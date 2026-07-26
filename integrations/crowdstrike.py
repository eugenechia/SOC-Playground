"""
CrowdStrike Falcon API client — READ-ONLY, SYNC. Copied by value from
SOC-Copilot's async client and adapted to sync httpx (SOC-Playground's agent
loop runs synchronously on the model-runtime thread).

The model never reaches this module directly; it calls the fixed templates in
integrations/fql_templates.py via the tools in agents/tools.py, and only those
tools call these functions.

Config:
  CROWDSTRIKE_BASE_URL       env, non-secret. Region base URL, default US-1.
  CROWDSTRIKE_CLIENT_ID      via get_secret (env in dev, Key Vault in prod).
  CROWDSTRIKE_CLIENT_SECRET  same pattern.

OAuth2 client-credentials; tokens ~30 min, cached with a 5-min refresh margin
behind a single-flight lock. 429s honor X-RateLimit-RetryAfter (bounded 30s).
Endpoints (all read-only):
  POST /oauth2/token
  GET  /devices/queries/devices/v1   POST /devices/entities/devices/v2
  GET  /alerts/queries/alerts/v2     POST /alerts/entities/alerts/v2
"""
import logging
import os
import threading
import time
from dataclasses import dataclass

import httpx

from app.secrets import get_secret
from integrations.retry import with_retry

log = logging.getLogger(__name__)

NOT_CONFIGURED_MSG = "CrowdStrike is not configured"
_DEFAULT_BASE = "https://api.crowdstrike.com"
_REFRESH_MARGIN = 300   # refresh when <5 min of token life remains
_MAX_429_WAIT = 30


@dataclass(frozen=True)
class FalconConfig:
    base_url: str
    client_id: str
    client_secret: str

    def _key(self) -> tuple[str, str]:
        return (self.base_url, self.client_id)


class _TokenEntry:
    __slots__ = ("token", "expiry", "lock")

    def __init__(self):
        self.token = ""
        self.expiry = 0.0            # time.monotonic() deadline
        self.lock = threading.Lock()


_client: httpx.Client | None = None
_client_lock = threading.Lock()
_entries: dict[tuple[str, str], _TokenEntry] = {}


def _http() -> httpx.Client:
    global _client
    with _client_lock:
        if _client is None or _client.is_closed:
            _client = httpx.Client(timeout=60)
        return _client


def close_client() -> None:
    global _client
    with _client_lock:
        if _client is not None and not _client.is_closed:
            _client.close()
        _client = None


def reset_token_caches() -> None:
    _entries.clear()


# ─── Env-derived default config ───────────────────────────────────────────────
def _env_base_url() -> str:
    return (os.environ.get("CROWDSTRIKE_BASE_URL", "").strip() or _DEFAULT_BASE).rstrip("/")


def env_cfg() -> FalconConfig:
    return FalconConfig(_env_base_url(),
                        get_secret("CROWDSTRIKE_CLIENT_ID"),
                        get_secret("CROWDSTRIKE_CLIENT_SECRET"))


def configured() -> bool:
    return bool(get_secret("CROWDSTRIKE_CLIENT_ID") and get_secret("CROWDSTRIKE_CLIENT_SECRET"))


# ─── Token + request machinery ────────────────────────────────────────────────
def _require(cfg: FalconConfig) -> None:
    if not (cfg.base_url and cfg.client_id and cfg.client_secret):
        raise RuntimeError(NOT_CONFIGURED_MSG)


def _get_token(cfg: FalconConfig) -> str:
    e = _entries.setdefault(cfg._key(), _TokenEntry())
    if e.token and time.monotonic() < e.expiry - _REFRESH_MARGIN:
        return e.token
    with e.lock:
        if e.token and time.monotonic() < e.expiry - _REFRESH_MARGIN:
            return e.token   # another thread refreshed while we waited
        r = with_retry(
            lambda: _http().post(
                f"{cfg.base_url}/oauth2/token",
                data={"client_id": cfg.client_id, "client_secret": cfg.client_secret},
                headers={"Content-Type": "application/x-www-form-urlencoded"}),
            label="crowdstrike.token")
        r.raise_for_status()
        j = r.json()
        e.token = j["access_token"]
        e.expiry = time.monotonic() + int(j.get("expires_in", 1800))
        return e.token


def _invalidate_token(cfg: FalconConfig) -> None:
    e = _entries.get(cfg._key())
    if e is not None:
        e.token, e.expiry = "", 0.0


def _request(cfg: FalconConfig, method: str, path: str, *,
             params: dict | None = None, json_body: dict | None = None,
             _retried: bool = False) -> dict:
    """One authenticated API call. 401 → invalidate + re-auth once. 429 → honor
    X-RateLimit-RetryAfter (bounded) once. Other failures propagate."""
    _require(cfg)
    token = _get_token(cfg)
    headers = {"Authorization": f"Bearer {token}"}

    def _do():
        if method == "GET":
            return _http().get(f"{cfg.base_url}{path}", params=params, headers=headers)
        return _http().post(f"{cfg.base_url}{path}", json=json_body, headers=headers)

    r = with_retry(_do, label=f"crowdstrike.{path.rsplit('/', 2)[-2]}")
    if r.status_code == 401 and not _retried:
        log.info("CrowdStrike 401 — refreshing token and retrying once")
        _invalidate_token(cfg)
        return _request(cfg, method, path, params=params, json_body=json_body, _retried=True)
    if r.status_code == 429 and not _retried:
        retry_at = r.headers.get("X-RateLimit-RetryAfter", "")
        try:
            wait = max(0, int(float(retry_at)) - int(time.time()))
        except ValueError:
            wait = 5
        wait = min(wait if wait > 0 else 5, _MAX_429_WAIT)
        log.warning("CrowdStrike 429 — waiting %ss", wait)
        time.sleep(wait)
        return _request(cfg, method, path, params=params, json_body=json_body, _retried=True)
    r.raise_for_status()
    return r.json()


# ─── Public read-only calls ───────────────────────────────────────────────────
def query_devices(cfg: FalconConfig, fql: str, limit: int = 20) -> list[str]:
    j = _request(cfg, "GET", "/devices/queries/devices/v1",
                 params={"filter": fql, "limit": limit})
    return j.get("resources", [])


def get_devices(cfg: FalconConfig, ids: list[str]) -> list[dict]:
    _require(cfg)
    if not ids:
        return []
    j = _request(cfg, "POST", "/devices/entities/devices/v2", json_body={"ids": ids})
    return j.get("resources", [])


def query_alerts(cfg: FalconConfig, fql: str, limit: int = 20) -> list[str]:
    j = _request(cfg, "GET", "/alerts/queries/alerts/v2",
                 params={"filter": fql, "limit": limit, "sort": "created_timestamp.desc"})
    return j.get("resources", [])


def get_alerts(cfg: FalconConfig, ids: list[str]) -> list[dict]:
    _require(cfg)
    if not ids:
        return []
    j = _request(cfg, "POST", "/alerts/entities/alerts/v2", json_body={"composite_ids": ids})
    return j.get("resources", [])
