"""
Single-password auth via Starlette SessionMiddleware (Orbstack pattern) with
SOC-Copilot's DEV_AUTH_BYPASS for local dev.

Public routes: /login, /static/*, /healthz. Everything else requires a session
cookie with 'authed' = True. The password is resolved through secrets.get_secret
(env wins, then Key Vault) — never read from os.environ directly.
"""
from __future__ import annotations

import hmac

from fastapi import APIRouter, Form, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from starlette.middleware.base import BaseHTTPMiddleware

from app import config
from app.secrets import get_secret

PUBLIC_PREFIXES = ("/login", "/static", "/healthz")

templates = Jinja2Templates(directory=str(config.BASE_DIR / "web" / "templates"))


def password_matches(submitted: str) -> bool:
    """Constant-time compare against the configured APP_PASSWORD."""
    expected = get_secret("APP_PASSWORD")
    if not expected:
        # No password configured: refuse all logins rather than allowing any.
        return False
    return hmac.compare_digest(submitted.encode(), expected.encode())


class AuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        if any(path == p or path.startswith(p + "/") for p in PUBLIC_PREFIXES):
            return await call_next(request)
        if config.DEV_AUTH_BYPASS:
            request.session.setdefault("authed", True)
            return await call_next(request)
        if not request.session.get("authed"):
            return RedirectResponse(url="/login", status_code=303)
        return await call_next(request)


router = APIRouter()


@router.get("/login")
def login_form(request: Request, error: str | None = None):
    return templates.TemplateResponse(
        request, "login.html", {"error": error, "app_name": config.APP_NAME}
    )


@router.post("/login")
def login(request: Request, password: str = Form(...)):
    if password_matches(password):
        request.session["authed"] = True
        return RedirectResponse(url="/", status_code=303)
    return templates.TemplateResponse(
        request,
        "login.html",
        {"error": "Incorrect password.", "app_name": config.APP_NAME},
        status_code=401,
    )


@router.post("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse(url="/login", status_code=303)
