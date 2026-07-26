"""Auth gate (Entra SSO): unauthenticated requests redirect to /auth/login,
/healthz is public, /auth/status reports state, and DEV_AUTH_BYPASS lets local
dev through with a synthetic user."""
from fastapi.testclient import TestClient

from app import auth, config
from app.main import app

client = TestClient(app, base_url="https://testserver")


def test_healthz_is_public():
    r = client.get("/healthz")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_protected_redirects_to_entra_login():
    r = client.get("/models", follow_redirects=False)
    assert r.status_code == 303
    assert r.headers["location"] == "/auth/login"


def test_auth_status_unauthenticated():
    r = client.get("/auth/status")
    assert r.status_code == 200
    body = r.json()
    assert body["authenticated"] is False and body["email"] == ""


def test_dev_bypass_allows_access(monkeypatch):
    # With the bypass on, the middleware injects a synthetic user and skips Entra.
    monkeypatch.setattr(config, "DEV_AUTH_BYPASS", True)
    r = client.get("/models", follow_redirects=False)
    assert r.status_code == 200


def test_public_prefixes_cover_auth_static_health():
    assert auth.PUBLIC_PREFIXES == ("/auth", "/static", "/healthz")
