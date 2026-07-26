"""
CPU inference runtime — exactly ONE model resident at a time.

Transformers loads full weights into RAM (float32 ≈ 4 bytes/param), so on a
CPU-only Container App we cannot hold several models at once. ModelRuntime keeps
at most one (model, tokenizer) loaded; selecting a different model unloads the
previous one first. It is a process-wide singleton — correct only at
min=max=1 replica.

Generation runs on a background thread feeding a TextIteratorStreamer, so the
event loop is never blocked and tokens stream out as they are produced.
"""
from __future__ import annotations

import gc
import logging
import threading
from collections.abc import Iterator

from app import config
from models_engine import registry

log = logging.getLogger(__name__)


class InferenceError(Exception):
    pass


class ModelRuntime:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._loaded_id: str | None = None
        self._model = None
        self._tokenizer = None

    @property
    def loaded_id(self) -> str | None:
        return self._loaded_id

    def unload(self) -> None:
        with self._lock:
            self._model = None
            self._tokenizer = None
            self._loaded_id = None
            gc.collect()

    def ensure_loaded(self, model_id: str) -> None:
        """Load model_id, unloading any other model first. No-op if already loaded."""
        with self._lock:
            if self._loaded_id == model_id and self._model is not None:
                return
            info = registry.get(model_id)
            if info is None or info.status != "ready":
                raise InferenceError(f"Model '{model_id}' is not downloaded/ready.")

            self.unload()
            import torch
            from transformers import AutoModelForCausalLM, AutoTokenizer

            path = info.path
            log.info("Loading model %s from %s (CPU, float32)", model_id, path)
            tokenizer = AutoTokenizer.from_pretrained(path, trust_remote_code=config.TRUST_REMOTE_CODE)
            model = AutoModelForCausalLM.from_pretrained(
                path,
                torch_dtype=torch.float32,
                low_cpu_mem_usage=True,
                trust_remote_code=config.TRUST_REMOTE_CODE,
            )
            model.to("cpu")
            model.eval()
            self._model = model
            self._tokenizer = tokenizer
            self._loaded_id = model_id
            log.info("Model %s loaded.", model_id)

    def _build_inputs(self, messages: list[dict], system_prompt: str):
        """Build model inputs, using the tokenizer chat template when available."""
        tok = self._tokenizer
        convo = []
        if system_prompt:
            convo.append({"role": "system", "content": system_prompt})
        convo.extend(messages)

        if getattr(tok, "chat_template", None):
            text = tok.apply_chat_template(convo, tokenize=False, add_generation_prompt=True)
        else:
            # Plain-concat fallback for base models with no chat template.
            parts = []
            for m in convo:
                parts.append(f"{m['role'].capitalize()}: {m['content']}")
            parts.append("Assistant:")
            text = "\n".join(parts)
        return tok(text, return_tensors="pt")

    def generate_stream(
        self,
        model_id: str,
        messages: list[dict],
        system_prompt: str,
        max_new_tokens: int | None = None,
    ) -> Iterator[str]:
        """Yield generated text chunks token-by-token. Loads the model if needed."""
        from transformers import TextIteratorStreamer

        self.ensure_loaded(model_id)
        with self._lock:
            tok = self._tokenizer
            model = self._model
            inputs = self._build_inputs(messages, system_prompt)

        streamer = TextIteratorStreamer(tok, skip_prompt=True, skip_special_tokens=True)
        gen_kwargs = dict(
            **inputs,
            streamer=streamer,
            max_new_tokens=max_new_tokens or config.MAX_NEW_TOKENS,
            do_sample=True,
            temperature=0.7,
            top_p=0.9,
            pad_token_id=tok.pad_token_id if tok.pad_token_id is not None else tok.eos_token_id,
        )

        thread = threading.Thread(target=model.generate, kwargs=gen_kwargs, daemon=True)
        thread.start()
        for chunk in streamer:
            if chunk:
                yield chunk
        thread.join()


# Process-wide singleton.
runtime = ModelRuntime()
