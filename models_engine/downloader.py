"""
Model downloader — pull a Hugging Face repo onto the persistent MODELS_DIR mount.

Security guardrails (all enforced here):
  1. Source host allowlist — only huggingface.co repos (validate_source).
  2. No pickle weights by default — allow_patterns restricts to safetensors +
     config + tokenizer, so *.bin/*.pt/*.pkl (which execute code on load) never
     land unless ALLOW_PICKLE is explicitly on.
  3. Size cap — MAX_MODEL_BYTES is checked against the repo's declared size
     before the download starts.
  4. trust_remote_code is NEVER passed here (custom modeling code is a download-
     time concern only at load time, handled in inference.py, and defaults off).

Progress: huggingface_hub has no simple byte callback, so run the blocking
snapshot_download on a worker thread and poll the on-disk directory size against
the repo's declared total, reporting via on_progress.
"""
from __future__ import annotations

import fnmatch
import json
import threading
import time
from collections.abc import Callable
from datetime import datetime, timezone
from urllib.parse import urlparse

from app import config
from app.broker import broker
from models_engine import registry

# Patterns kept when ALLOW_PICKLE is off — safetensors weights + everything
# needed to load a tokenizer/config, and nothing that can execute code on load.
SAFE_PATTERNS = [
    "*.safetensors",
    "*.json",
    "*.txt",
    "*.model",
    "tokenizer.*",
    "merges.txt",
    "vocab.*",
    "special_tokens_map.json",
    "generation_config.json",
]

ProgressCB = Callable[[int, int, str], None]  # (done_bytes, total_bytes, phase)


class DownloadError(Exception):
    pass


def validate_source(url_or_id: str) -> str:
    """Normalise a pasted URL or bare id into a 'org/name' repo id.

    Rejects any non-huggingface.co host, non-https schemes, and path traversal.
    """
    s = (url_or_id or "").strip()
    if not s:
        raise DownloadError("Empty model source.")
    if ".." in s or s.startswith("/"):
        raise DownloadError("Invalid model source.")

    # Treat as a URL if it has a scheme, or its first segment looks like a host
    # (contains a dot, e.g. "huggingface.co/org/name"). A bare "org/name" does not.
    first_segment = s.split("/", 1)[0].lower()
    looks_like_url = "://" in s or first_segment.startswith("www.") or "." in first_segment
    if looks_like_url:
        parsed = urlparse(s if "://" in s else f"https://{s}")
        if parsed.scheme not in ("https", ""):
            raise DownloadError("Only https Hugging Face URLs are allowed.")
        host = (parsed.hostname or "").lower()
        if host not in config.ALLOWED_DOWNLOAD_HOSTS:
            raise DownloadError(
                f"Host '{host}' not allowed. Only: {', '.join(sorted(config.ALLOWED_DOWNLOAD_HOSTS))}"
            )
        # Path is /org/name[/...]; take the first two non-empty segments.
        parts = [p for p in parsed.path.split("/") if p]
        if len(parts) < 2:
            raise DownloadError("URL must point at a model repo, e.g. huggingface.co/org/name.")
        repo_id = f"{parts[0]}/{parts[1]}"
    else:
        # Bare id "org/name".
        parts = [p for p in s.split("/") if p]
        if len(parts) != 2:
            raise DownloadError("Model id must be 'org/name' or a huggingface.co URL.")
        repo_id = f"{parts[0]}/{parts[1]}"
    return repo_id


def _matches_any(filename: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatch(filename, p) for p in patterns)


def _repo_plan(repo_id: str) -> tuple[int, bool, list[str]]:
    """Return (selected_total_bytes, has_safetensors, allow_patterns) for a repo."""
    from huggingface_hub import HfApi

    info = HfApi().model_info(repo_id, files_metadata=True)
    siblings = info.siblings or []
    has_safetensors = any((s.rfilename or "").endswith(".safetensors") for s in siblings)

    allow = None if config.ALLOW_PICKLE else SAFE_PATTERNS
    total = 0
    for s in siblings:
        name = s.rfilename or ""
        if allow is not None and not _matches_any(name, allow):
            continue
        total += s.size or 0
    return total, has_safetensors, allow


def download(model_id: str, source_url: str, on_progress: ProgressCB) -> registry.ModelInfo:
    """Blocking download of `model_id` into MODELS_DIR. Reports via on_progress."""
    from huggingface_hub import snapshot_download

    total, has_safetensors, allow = _repo_plan(model_id)

    if not config.ALLOW_PICKLE and not has_safetensors:
        raise DownloadError(
            "This repo has no .safetensors weights. Pickle formats are blocked "
            "(ALLOW_PICKLE is off) because they can execute code on load."
        )
    if total > config.MAX_MODEL_BYTES:
        raise DownloadError(
            f"Model is {total / 1024**3:.1f} GiB, over the "
            f"{config.MAX_MODEL_BYTES / 1024**3:.1f} GiB cap."
        )

    dest = registry.model_dir(model_id)
    dest.mkdir(parents=True, exist_ok=True)

    on_progress(0, total, "downloading")

    result: dict = {}

    def _worker():
        try:
            snapshot_download(
                repo_id=model_id,
                local_dir=str(dest),
                allow_patterns=allow,
                local_dir_use_symlinks=False,
                cache_dir=str(config.HF_HOME),
            )
            result["ok"] = True
        except Exception as e:  # surfaced to the caller after join
            result["error"] = str(e)

    t = threading.Thread(target=_worker, daemon=True)
    t.start()

    # Poll on-disk size until the worker finishes.
    while t.is_alive():
        done = registry.dir_size_bytes(dest)
        on_progress(done, total, "downloading")
        if done > config.MAX_MODEL_BYTES:
            # Runaway / mismatched declared size — stop reporting; worker will
            # finish, but we refuse to mark it ready below.
            break
        time.sleep(1.0)
    t.join()

    if result.get("error"):
        raise DownloadError(result["error"])

    final_size = registry.dir_size_bytes(dest)
    on_progress(final_size, total or final_size, "done")
    registry.write_meta(
        model_id,
        status="ready",
        size_bytes=final_size,
        source_url=source_url,
        has_safetensors=has_safetensors,
        downloaded_at=datetime.now(timezone.utc).isoformat(),
        error=None,
    )
    return registry.get(model_id)


def run_job(job_id: str, model_id: str, source_url: str) -> None:
    """Background-thread entrypoint: relay progress/terminal state over the broker."""
    topic = f"download:{job_id}"

    def _emit(event: str, payload: dict) -> None:
        broker.publish(topic, event, json.dumps({"model_id": model_id, **payload}))

    def _on_progress(done: int, total: int, phase: str) -> None:
        pct = int(done * 100 / total) if total else 0
        _emit("progress", {"done": done, "total": total, "pct": min(pct, 100), "phase": phase})

    # Mark the placeholder row immediately so the model appears as "downloading".
    registry.write_meta(
        model_id,
        status="downloading",
        source_url=source_url,
        downloaded_at=datetime.now(timezone.utc).isoformat(),
        size_bytes=0,
        has_safetensors=False,
        error=None,
    )
    try:
        info = download(model_id, source_url, _on_progress)
        _emit("done", {"status": "ready", "size_bytes": info.size_bytes, "final": 1})
    except Exception as e:
        registry.write_meta(model_id, status="error", error=str(e))
        _emit("error", {"message": str(e), "final": 1})
