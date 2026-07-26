"""
Microsoft Sentinel / Log Analytics client — READ-ONLY, SYNC.

Copied by value from SOC-Copilot's async client and adapted to sync httpx (our
agent loop is synchronous). The service principal is Log Analytics Reader; the
query API is read-only. The model never reaches this module directly — it calls
the fixed templates in integrations/kql_templates.py.

Config (all via app.secrets.get_secret; env wins in dev):
  SENTINEL_TENANT_ID, SENTINEL_CLIENT_ID, SENTINEL_WORKSPACE_ID,
  SENTINEL_CLIENT_SECRET
"""
import logging
import threading

import httpx

from app.secrets import get_secret
from integrations.retry import with_retry

log = logging.getLogger(__name__)

_LOG_ANALYTICS_SCOPE = "https://api.loganalytics.io/.default"

_client: httpx.Client | None = None
_client_lock = threading.Lock()


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


def configured() -> bool:
    return bool(
        get_secret("SENTINEL_TENANT_ID")
        and get_secret("SENTINEL_CLIENT_ID")
        and get_secret("SENTINEL_WORKSPACE_ID")
    )


def _get_token() -> str:
    tenant = get_secret("SENTINEL_TENANT_ID")
    client_id = get_secret("SENTINEL_CLIENT_ID")
    secret = get_secret("SENTINEL_CLIENT_SECRET")
    if not all([tenant, client_id, secret]):
        raise RuntimeError("Sentinel credentials not configured.")
    # Tokens last ~1h; we re-fetch per run rather than track expiry — a playground
    # query is short and infrequent, so simplicity wins.
    url = f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
    r = _http().post(url, data={
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": secret,
        "scope": _LOG_ANALYTICS_SCOPE,
    })
    r.raise_for_status()
    return r.json()["access_token"]


def run_kql(query: str, timespan: str | None = None, max_rows: int = 200) -> list[dict]:
    """Execute a KQL query against the configured workspace. Returns row dicts
    (capped at max_rows). Auth failures raise; 400/404 return [] so a missing
    table degrades to 'no evidence' rather than crashing."""
    workspace_id = get_secret("SENTINEL_WORKSPACE_ID")
    token = _get_token()
    url = f"https://api.loganalytics.io/v1/workspaces/{workspace_id}/query"
    body: dict = {"query": query}
    if timespan:
        body["timespan"] = timespan

    r = with_retry(
        lambda: _http().post(
            url,
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            json=body,
        ),
        label="sentinel.query",
    )
    if r.status_code in (401, 403):
        raise PermissionError(f"Sentinel auth denied ({r.status_code}): {r.text[:200]}")
    if r.status_code in (400, 404):
        log.warning("KQL %s: %s", r.status_code, r.text[:200])
        return []
    r.raise_for_status()

    tables = r.json().get("tables", [])
    if not tables:
        return []
    table = tables[0]
    columns = [c["name"] for c in table.get("columns", [])]
    rows = table.get("rows", [])[:max_rows]
    return [dict(zip(columns, row)) for row in rows]
