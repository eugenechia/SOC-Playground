"""
Skill Library — a read-only, browsable reference of framework-mapped
cybersecurity SOPs from the open-source Anthropic-Cybersecurity-Skills repo
(Apache-2.0), fetched live from GitHub raw and cached in-process.

Design notes:
  * These SOPs are written for frontier agents, not the tiny local models this
    app runs — so the library is a reference/teaching surface, NOT wired into
    the model. (A future "load as a Workbench task framing" seam can build on
    `get_skill`, but nothing here touches inference.)
  * Fetching is SYNC httpx with the shared retry helper, mirroring the
    integrations/* read-only clients.
  * SSRF / path-traversal guard: `get_skill` only fetches slugs that exist in
    the fetched index — the model/user can never coerce an arbitrary raw URL.
  * Rendered markdown is sanitized with a bleach allowlist (third-party content).
"""
import logging
import threading
import time

import bleach
import httpx
import markdown as md
import yaml

from app import config
from integrations.retry import with_retry

log = logging.getLogger(__name__)


class SkillLibraryError(RuntimeError):
    """Raised when the index or a skill cannot be fetched/parsed. Routes catch
    this and render a friendly panel (fail-open — the page shell still loads)."""


# ─── HTTP client (sync, read-only) ────────────────────────────────────────────
_client: httpx.Client | None = None
_client_lock = threading.Lock()


def _http() -> httpx.Client:
    global _client
    with _client_lock:
        if _client is None or _client.is_closed:
            _client = httpx.Client(
                timeout=config.SKILLS_HTTP_TIMEOUT,
                headers={"User-Agent": "SOC-Playground-SkillLibrary"},
                follow_redirects=True,
            )
        return _client


def close_client() -> None:
    global _client
    with _client_lock:
        if _client is not None and not _client.is_closed:
            _client.close()
        _client = None


def _get_text(url: str, *, label: str) -> str:
    try:
        r = with_retry(lambda: _http().get(url), label=label)
        r.raise_for_status()
        return r.text
    except httpx.HTTPError as e:
        raise SkillLibraryError(f"Could not fetch {label} ({type(e).__name__}).") from e


# ─── In-process cache ─────────────────────────────────────────────────────────
# index: (fetched_at, list[dict]); details keyed by slug: (fetched_at, dict)
_index_cache: tuple[float, list[dict]] | None = None
_index_lock = threading.Lock()
_detail_cache: dict[str, tuple[float, dict]] = {}
_detail_lock = threading.Lock()


def _fresh(fetched_at: float) -> bool:
    return (time.time() - fetched_at) < config.SKILLS_CACHE_TTL_SECONDS


def _clear_caches() -> None:
    """Test/ops helper — drop all cached data."""
    global _index_cache
    with _index_lock:
        _index_cache = None
    with _detail_lock:
        _detail_cache.clear()


# ─── Index ────────────────────────────────────────────────────────────────────
def list_skills() -> list[dict]:
    """Return the skill index: a list of {name, description, domain, path},
    sorted by name. Cached for SKILLS_CACHE_TTL_SECONDS."""
    global _index_cache
    with _index_lock:
        if _index_cache is not None and _fresh(_index_cache[0]):
            return _index_cache[1]

    raw = _get_text(f"{config.SKILLS_REPO_RAW_BASE}/index.json", label="skill index")
    try:
        data = yaml.safe_load(raw)  # JSON is a subset of YAML; avoids a json import quirk
        skills = data["skills"] if isinstance(data, dict) else data
        clean = [
            {
                "name": s["name"],
                "description": s.get("description", ""),
                "domain": s.get("domain", ""),
                "path": s.get("path", f"skills/{s['name']}"),
            }
            for s in skills
            if isinstance(s, dict) and s.get("name")
        ]
    except (KeyError, TypeError, ValueError, yaml.YAMLError) as e:
        raise SkillLibraryError("The skill index was malformed.") from e

    clean.sort(key=lambda s: s["name"])
    with _index_lock:
        _index_cache = (time.time(), clean)
    return clean


def domains() -> list[str]:
    """Distinct domain values across the index, for the filter dropdown."""
    return sorted({s["domain"] for s in list_skills() if s["domain"]})


def _index_names() -> set[str]:
    return {s["name"] for s in list_skills()}


# ─── Detail ───────────────────────────────────────────────────────────────────
_ALLOWED_TAGS = [
    "h1", "h2", "h3", "h4", "h5", "h6",
    "p", "ul", "ol", "li", "pre", "code",
    "table", "thead", "tbody", "tr", "th", "td",
    "a", "strong", "em", "blockquote", "hr", "br", "span",
]
_ALLOWED_ATTRS = {"a": ["href", "title"], "span": ["class"], "code": ["class"]}


def _split_frontmatter(text: str) -> tuple[dict, str]:
    """Split a leading `---` YAML frontmatter block from the markdown body.
    Returns ({}, text) if there is no frontmatter."""
    if not text.startswith("---"):
        return {}, text
    # Split only at the FIRST closing fence so a later '---' (a horizontal rule
    # in the body) can't truncate the content. Leading '---' has no preceding
    # newline, so "\n---" first matches the closing fence.
    parts = text.split("\n---", 1)
    # text == "---\n<yaml>\n---\n<body>"; parts[0] == "---\n<yaml>"
    if len(parts) < 2:
        return {}, text
    yaml_block = parts[0][3:]  # drop leading '---'
    body = parts[1]
    if body.startswith("\n"):
        body = body[1:]
    try:
        fm = yaml.safe_load(yaml_block) or {}
        if not isinstance(fm, dict):
            fm = {}
    except yaml.YAMLError:
        fm = {}
    return fm, body


def _render_markdown(body: str) -> str:
    html = md.markdown(body, extensions=["fenced_code", "tables", "toc"])
    return bleach.clean(html, tags=_ALLOWED_TAGS, attributes=_ALLOWED_ATTRS, strip=True)


def get_skill(name: str) -> dict:
    """Fetch and render a single skill by slug.

    Guard: `name` must be a slug present in the index, so this can only ever
    resolve to `.../skills/<known-slug>/SKILL.md` — never an arbitrary URL.
    Returns {name, frontmatter, html, source_url}. Raises SkillLibraryError on
    fetch/parse failure; raises KeyError if the slug is unknown."""
    if name not in _index_names():
        raise KeyError(name)

    with _detail_lock:
        hit = _detail_cache.get(name)
        if hit is not None and _fresh(hit[0]):
            return hit[1]

    raw = _get_text(
        f"{config.SKILLS_REPO_RAW_BASE}/skills/{name}/SKILL.md",
        label=f"skill '{name}'",
    )
    fm, body = _split_frontmatter(raw)
    detail = {
        "name": name,
        "frontmatter": fm,
        "html": _render_markdown(body),
        "source_url": f"{config.SKILLS_REPO_HTML_BASE}/blob/main/skills/{name}/SKILL.md",
    }
    with _detail_lock:
        _detail_cache[name] = (time.time(), detail)
    return detail
