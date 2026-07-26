"""Root/shared UI routes."""
from fastapi import APIRouter
from fastapi.responses import RedirectResponse

router = APIRouter()


@router.get("/")
def index():
    # The model manager is the natural landing page — you need a model first.
    return RedirectResponse(url="/models", status_code=303)
