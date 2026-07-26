"""
Scorecard — benchmark each downloaded model's tool-calling and show a comparable
table. Run is long-lived (each model loads + several generations), so results
stream over SSE; the latest run is persisted on the models mount.
"""
import json

from fastapi import APIRouter, Form, Request
from fastapi.responses import StreamingResponse
from fastapi.templating import Jinja2Templates

from agents import scorecard as sc
from app import config
from models_engine import registry

router = APIRouter()
templates = Jinja2Templates(directory=str(config.BASE_DIR / "web" / "templates"))


@router.get("/scorecard")
def scorecard_page(request: Request):
    ready = [m.model_id for m in registry.scan() if m.status == "ready"]
    return templates.TemplateResponse(
        request,
        "scorecard.html",
        {
            "app_name": config.APP_NAME,
            "nav": "scorecard",
            "models": ready,
            "cases": sc.CASES,
            "latest": sc.load_latest(),
        },
    )


def _sse(event: str, data: dict) -> str:
    return f"event: {event}\ndata: {json.dumps(data)}\n\n"


@router.post("/scorecard/run")
def scorecard_run(request: Request, models: list[str] = Form(default=[])):
    ready = {m.model_id for m in registry.scan() if m.status == "ready"}
    selected = [m for m in models if m in ready]  # ignore anything not actually ready

    def _gen():
        if not selected:
            yield _sse("error", {"message": "No ready models selected."})
            return
        for ev in sc.run_scorecard(selected):
            yield _sse(ev["event"], ev["data"])

    headers = {"Cache-Control": "no-cache", "X-Accel-Buffering": "no"}
    return StreamingResponse(_gen(), media_type="text/event-stream", headers=headers)
