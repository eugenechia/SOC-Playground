"""Auth gate: unauthenticated requests redirect to /login; correct password lets
you in; /healthz is public."""
from fastapi.testclient import TestClient

from app.main import app

# https base_url so the Secure session cookie (https_only) is returned by the client.
client = TestClient(app, base_url="https://testserver")


def test_healthz_is_public():
    r = client.get("/healthz")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_protected_redirects_to_login():
    r = client.get("/models", follow_redirects=False)
    assert r.status_code == 303
    assert r.headers["location"] == "/login"


def test_login_rejects_wrong_password():
    r = client.post("/login", data={"password": "nope"}, follow_redirects=False)
    assert r.status_code == 401


def test_login_accepts_correct_password_and_grants_access():
    c = TestClient(app, base_url="https://testserver")
    r = c.post("/login", data={"password": "test-password"}, follow_redirects=False)
    assert r.status_code == 303
    # Session cookie now set; a protected page should resolve (302 to /models is fine).
    r2 = c.get("/models", follow_redirects=False)
    assert r2.status_code == 200
