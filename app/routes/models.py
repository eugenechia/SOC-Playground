"""
Model Manager — paste a Hugging Face URL/id to download a model, list what's on
disk, delete a model. The download runs on a background thread; the browser
follows progress over the SSE endpoint in events.py.
"""
import secrets as pysecrets
import threading

from fastapi import APIRouter, Form, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates

from app import config
from models_engine import downloader, registry
from models_engine.inference import runtime

router = APIRouter()
templates = Jinja2Templates(directory=str(config.BASE_DIR / "web" / "templates"))


def _ctx(**extra):
    base = {"app_name": config.APP_NAME, "nav": "models"}
    base.update(extra)
    return base


@router.get("/models")
def models_page(request: Request):
    models = registry.scan()
    return templates.TemplateResponse(
        request,
        "models.html",
        _ctx(models=models, ram_warn_b=config.RAM_WARN_PARAM_BILLIONS,
             allow_pickle=config.ALLOW_PICKLE),
    )


@router.post("/models/download")
def download_model(request: Request, source: str = Form(...)):
    try:
        model_id = downloader.validate_source(source)
    except downloader.DownloadError as e:
        return templates.TemplateResponse(
            request, "partials/download_error.html", {"error": str(e)}, status_code=400,
        )

    job_id = "job_" + pysecrets.token_hex(6)
    threading.Thread(
        target=downloader.run_job, args=(job_id, model_id, source), daemon=True
    ).start()

    return templates.TemplateResponse(
        request, "partials/download_progress.html",
        {"job_id": job_id, "model_id": model_id},
    )


@router.post("/models/{model_id:path}/delete")
def delete_model(model_id: str):
    if runtime.loaded_id == model_id:
        runtime.unload()
    try:
        registry.delete(model_id)
    except ValueError:
        pass
    return RedirectResponse(url="/models", status_code=303)
