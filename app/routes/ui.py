"""Root/home UI. The Entra callback lands here on login, so `/` is the overview
page that explains what SOC-Playground is and where to go next."""
from fastapi import APIRouter, Request
from fastapi.templating import Jinja2Templates

from app import config

router = APIRouter()
templates = Jinja2Templates(directory=str(config.BASE_DIR / "web" / "templates"))


@router.get("/")
def index(request: Request):
    return templates.TemplateResponse(
        request, "home.html", {"app_name": config.APP_NAME, "nav": "home"}
    )
