"""Liveness probe for ACA. No auth (listed in auth.PUBLIC_PREFIXES)."""
from fastapi import APIRouter

from models_engine.inference import runtime

router = APIRouter()


@router.get("/healthz")
def healthz():
    return {"status": "ok", "loaded_model": runtime.loaded_id}
