"""
Model registry — the source of truth is the filesystem, not a database.

Each downloaded model lives at MODELS_DIR/<slug>/ with a sidecar meta.json.
scan() walks that directory and reconstructs the registry, so a restart (or a
freshly-mounted Azure Files share) needs no other state. Slugs are a reversible,
directory-safe encoding of the Hugging Face repo id ("org/name" -> "org__name").
"""
from __future__ import annotations

import json
import shutil
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path

from app import config

_META_NAME = "meta.json"
_SEP = "__"  # "org/name" <-> "org__name"


@dataclass(frozen=True)
class ModelInfo:
    model_id: str          # HF repo id, e.g. "HuggingFaceTB/SmolLM-360M-Instruct"
    path: str              # absolute path to the model dir on disk
    size_bytes: int
    status: str            # "downloading" | "ready" | "error" | "partial"
    source_url: str
    downloaded_at: str     # ISO8601, stamped by the caller
    has_safetensors: bool
    error: str | None = None


def slug(model_id: str) -> str:
    """Encode a repo id into a single directory-safe path segment."""
    if "/" in model_id.strip("/"):
        org, name = model_id.strip("/").split("/", 1)
        return f"{org}{_SEP}{name}".replace("/", _SEP)
    return model_id.strip("/")


def unslug(dirname: str) -> str:
    """Best-effort reverse of slug() for display."""
    return dirname.replace(_SEP, "/", 1)


def model_dir(model_id: str) -> Path:
    return config.MODELS_DIR / slug(model_id)


def _meta_path(model_id: str) -> Path:
    return model_dir(model_id) / _META_NAME


def dir_size_bytes(path: Path) -> int:
    total = 0
    for p in path.rglob("*"):
        if p.is_file():
            try:
                total += p.stat().st_size
            except OSError:
                pass
    return total


def _has_safetensors(path: Path) -> bool:
    return any(path.rglob("*.safetensors"))


def write_meta(model_id: str, **fields) -> None:
    """Atomically write/merge the sidecar meta.json for a model."""
    d = model_dir(model_id)
    d.mkdir(parents=True, exist_ok=True)
    meta = {}
    mp = d / _META_NAME
    if mp.exists():
        try:
            meta = json.loads(mp.read_text())
        except (json.JSONDecodeError, OSError):
            meta = {}
    meta.update({"model_id": model_id, **fields})
    # Atomic replace so a crash mid-write never leaves a truncated meta.json.
    fd, tmp = tempfile.mkstemp(dir=str(d), suffix=".tmp")
    try:
        with open(fd, "w") as f:
            json.dump(meta, f, indent=2)
        Path(tmp).replace(mp)
    finally:
        Path(tmp).unlink(missing_ok=True)


def _info_from_dir(d: Path) -> ModelInfo | None:
    mp = d / _META_NAME
    if not mp.exists():
        return None
    try:
        meta = json.loads(mp.read_text())
    except (json.JSONDecodeError, OSError):
        return None
    model_id = meta.get("model_id") or unslug(d.name)
    return ModelInfo(
        model_id=model_id,
        path=str(d),
        size_bytes=meta.get("size_bytes") or dir_size_bytes(d),
        status=meta.get("status", "partial"),
        source_url=meta.get("source_url", ""),
        downloaded_at=meta.get("downloaded_at", ""),
        has_safetensors=meta.get("has_safetensors", _has_safetensors(d)),
        error=meta.get("error"),
    )


def scan() -> list[ModelInfo]:
    """Return every model dir under MODELS_DIR that has a meta.json."""
    root = config.MODELS_DIR
    if not root.exists():
        return []
    out: list[ModelInfo] = []
    for d in sorted(root.iterdir()):
        if not d.is_dir() or d.name.startswith("."):
            continue
        info = _info_from_dir(d)
        if info is not None:
            out.append(info)
    return out


def get(model_id: str) -> ModelInfo | None:
    d = model_dir(model_id)
    return _info_from_dir(d) if d.exists() else None


def delete(model_id: str) -> None:
    """Remove a model directory. Guards against escaping MODELS_DIR."""
    d = model_dir(model_id).resolve()
    root = config.MODELS_DIR.resolve()
    if root not in d.parents:
        raise ValueError(f"refusing to delete path outside MODELS_DIR: {d}")
    shutil.rmtree(d, ignore_errors=True)
