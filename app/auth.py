"""
Entra ID (Azure AD) SSO via MSAL authorization-code flow.

Ported by value from SOC-Copilot's app/auth.py. Unauthenticated requests are
auto-redirected to Microsoft; on callback we exchange the code (MSAL validates
state/nonce/PKCE/id_token) and store a `user` dict in the session. Access is
gated on membership of ENTRA_ALLOWED_GROUP_ID via the id_token `groups` claim —
no Graph call. DEV_AUTH_BYPASS injects a synthetic user for local dev.

Public routes: /auth/*, /static/*, /healthz. Everything else needs a session
user. Secrets resolve via app.secrets.get_secret (env wins, then Key Vault).
"""
from __future__ import annotations

import logging

import msal
from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from starlette.middleware.base import BaseHTTPMiddleware

from app import config
from app.secrets import get_secret

log = logging.getLogger(__name__)

router = APIRouter(prefix="/auth")

_SCOPES = ["User.Read"]

PUBLIC_PREFIXES = ("/auth", "/static", "/healthz")

_DENIED_HTML = """<!doctype html><html><head><meta charset="utf-8">
<title>Access denied</title></head>
<body style="font-family:sans-serif;background:#0e1117;color:#c9d1d9;padding:3rem">
<h2>Access denied</h2>
<p>Your account is not a member of the group allowed to use SOC-Playground.</p>
<p><a href="/auth/logout" style="color:#2f81f7">Sign out</a> and try a different account.</p>
</body></html>"""

_DEV_USER = {"name": "Dev User", "email": "dev@local", "oid": "", "groups": []}


def _msal_app() -> msal.ConfidentialClientApplication:
    """Built per-request: cheap (no network) and never holds stale credentials."""
    tenant_id = get_secret("ENTRA_TENANT_ID")
    return msal.ConfidentialClientApplication(
        get_secret("ENTRA_CLIENT_ID"),
        authority=f"https://login.microsoftonline.com/{tenant_id}",
        client_credential=get_secret("ENTRA_CLIENT_SECRET"),
    )


class AuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        if any(path == p or path.startswith(p + "/") for p in PUBLIC_PREFIXES):
            return await call_next(request)
        if config.DEV_AUTH_BYPASS:
            request.session.setdefault("user", dict(_DEV_USER))
            return await call_next(request)
        if not request.session.get("user"):
            return RedirectResponse(url="/auth/login", status_code=303)
        return await call_next(request)


@router.get("/login")
def login(request: Request):
    flow = _msal_app().initiate_auth_code_flow(
        _SCOPES, redirect_uri=get_secret("ENTRA_REDIRECT_URI")
    )
    request.session["auth_flow"] = flow
    return RedirectResponse(flow["auth_uri"], status_code=303)


@router.get("/callback")
def callback(request: Request):
    flow = request.session.pop("auth_flow", {})
    if not flow:
        return RedirectResponse("/auth/login", status_code=303)
    try:
        result = _msal_app().acquire_token_by_auth_code_flow(flow, dict(request.query_params))
    except ValueError as e:
        log.error("Entra auth_code_flow error: %s", e)
        return RedirectResponse("/auth/login", status_code=303)

    if "error" in result:
        log.error("Entra token error: %s", result)
        desc = result.get("error_description", result["error"])
        return HTMLResponse(f"Authentication failed: {desc}", status_code=400)

    claims = result.get("id_token_claims", {})

    allowed_group = get_secret("ENTRA_ALLOWED_GROUP_ID")
    if allowed_group and allowed_group not in (claims.get("groups") or []):
        log.warning("Access denied for %s — not in group %s",
                    claims.get("preferred_username"), allowed_group)
        return HTMLResponse(_DENIED_HTML, status_code=403)

    request.session["user"] = {
        "name": claims.get("name", ""),
        "email": claims.get("preferred_username", ""),
        "oid": claims.get("oid", ""),
        "groups": claims.get("groups", []),
    }
    log.info("Login: %s", request.session["user"]["email"])
    return RedirectResponse("/", status_code=303)


@router.get("/logout")
@router.post("/logout")
def logout(request: Request):
    request.session.clear()
    tenant_id = get_secret("ENTRA_TENANT_ID")
    post_logout = (get_secret("ENTRA_REDIRECT_URI") or "").replace("/auth/callback", "/")
    return RedirectResponse(
        f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/logout"
        f"?post_logout_redirect_uri={post_logout}",
        status_code=303,
    )


@router.get("/status")
def status(request: Request):
    user = request.session.get("user")
    return {"authenticated": bool(user), "email": (user or {}).get("email", ""),
            "name": (user or {}).get("name", "")}
