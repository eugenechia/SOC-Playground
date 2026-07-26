"""
Jira REST v3 client — READ-ONLY, SYNC.

Copied by value from SOC-Copilot's async client, trimmed to the two READ calls
(fetch issue, JQL search) and converted to sync httpx. No write/transition ops
exist in this module — a playground model can only read.

Safety: the model never composes raw JQL. Issue keys are regex-validated and
free-text search is escaped into a fixed `text ~ "<escaped>"` template
(jql_text_search), so a hostile parameter cannot inject JQL clauses.

Config (via app.secrets.get_secret): JIRA_URL, JIRA_EMAIL, JIRA_API_TOKEN.
"""
import base64
import logging
import re
import threading

import httpx

from app.secrets import get_secret

log = logging.getLogger(__name__)

_client: httpx.Client | None = None
_client_lock = threading.Lock()

_ISSUE_KEY_RE = re.compile(r"^[A-Z][A-Z0-9]+-\d+$")


class JiraParamError(ValueError):
    """A Jira parameter failed validation (bad key or unsafe search text)."""


def _base_url() -> str:
    return (get_secret("JIRA_URL") or "").rstrip("/")


def _headers() -> dict:
    email = get_secret("JIRA_EMAIL")
    token = get_secret("JIRA_API_TOKEN")
    creds = base64.b64encode(f"{email}:{token}".encode()).decode()
    return {"Authorization": f"Basic {creds}", "Accept": "application/json",
            "Content-Type": "application/json"}


def configured() -> bool:
    return bool(get_secret("JIRA_URL") and get_secret("JIRA_EMAIL") and get_secret("JIRA_API_TOKEN"))


def _http() -> httpx.Client:
    global _client
    with _client_lock:
        if _client is None or _client.is_closed:
            _client = httpx.Client(timeout=30)
        return _client


def close_client() -> None:
    global _client
    with _client_lock:
        if _client is not None and not _client.is_closed:
            _client.close()
        _client = None


def validate_issue_key(key: str) -> str:
    k = (key or "").strip().upper()
    if not _ISSUE_KEY_RE.match(k):
        raise JiraParamError("issue key must look like PROJ-123")
    return k


def jql_text_search(text: str) -> str:
    """Build a safe JQL text-search filter from free text. Rejects control chars
    and escapes quotes/backslashes so the value stays a single quoted literal."""
    t = (text or "").strip()
    if not t:
        raise JiraParamError("search text must be non-empty")
    if any(ord(c) < 0x20 for c in t):
        raise JiraParamError("search text contains control characters")
    if len(t) > 200:
        raise JiraParamError("search text is too long")
    esc = t.replace("\\", "\\\\").replace('"', '\\"')
    return f'text ~ "{esc}" ORDER BY created DESC'


# ─── Read operations ──────────────────────────────────────────────────────────
def fetch_issue_by_key(issue_key: str, fields: str = "*all") -> dict | None:
    base = _base_url()
    if not base:
        return None
    try:
        r = _http().get(f"{base}/rest/api/3/issue/{issue_key}",
                        headers=_headers(), params={"fields": fields})
        if r.status_code >= 400:
            log.error("fetch_issue_by_key %s HTTP %s: %s", issue_key, r.status_code, r.text[:300])
            return None
        return r.json()
    except Exception as e:  # noqa: BLE001
        log.error("fetch_issue_by_key %s exception: %s", issue_key, e)
        return None


def jql_search(jql: str, fields: str, max_results: int = 20) -> dict:
    base = _base_url()
    if not base:
        return {"error": "JIRA_URL not configured"}
    params = {"jql": jql, "maxResults": max_results, "fields": fields}
    try:
        r = _http().get(f"{base}/rest/api/3/search/jql", headers=_headers(), params=params)
        if r.status_code >= 400:
            log.error("jql_search HTTP %s: %s", r.status_code, r.text[:500])
            return {"error": f"HTTP {r.status_code}", "detail": r.text[:300]}
        return r.json()
    except Exception as e:  # noqa: BLE001
        log.error("jql_search exception: %s", e)
        return {"error": str(e)}
