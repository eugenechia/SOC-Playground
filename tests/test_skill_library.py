"""
Skill Library: index parse + cache, frontmatter split (body '---' not truncated),
markdown render + sanitizer strips scripts, slug guard, network-error → panel,
and the two routes (list, unknown → 404, killswitch).
"""
import httpx
import pytest
from fastapi.testclient import TestClient

from app import config, skill_library
from app.main import app

client = TestClient(app, base_url="https://testserver")


# ─── Fakes for the sync httpx client ──────────────────────────────────────────
class _FakeResp:
    def __init__(self, text: str):
        self.text = text

    def raise_for_status(self):
        return None


class _FakeClient:
    """Serves canned bodies by URL; optionally raises to simulate an outage."""
    def __init__(self, bodies: dict[str, str], raise_exc: Exception | None = None):
        self._bodies = bodies
        self._raise = raise_exc

    def get(self, url):
        if self._raise is not None:
            raise self._raise
        for key, body in self._bodies.items():
            if url.endswith(key):
                return _FakeResp(body)
        raise httpx.HTTPStatusError("404", request=None, response=None)


_INDEX = """
{"version": "1", "total_skills": 2, "skills": [
  {"name": "b-hunt", "description": "Hunt for beacons", "domain": "threat-hunting", "path": "skills/b-hunt"},
  {"name": "a-malware", "description": "Analyze malware", "domain": "malware-analysis", "path": "skills/a-malware"}
]}
"""

_SKILL_MD = """---
name: b-hunt
description: Hunt for beacons
domain: cybersecurity
subdomain: threat-hunting
tags:
- beacon
- c2
mitre_attack:
- T1071.001
nist_csf:
- DE.AE-02
---
# Hunting Beacons

Intro text.

## Workflow

- step one
- step two

---

Trailing section after a horizontal rule.

<script>alert('xss')</script>
"""


@pytest.fixture(autouse=True)
def _clear():
    skill_library._clear_caches()
    yield
    skill_library._clear_caches()


def _install(monkeypatch, bodies, raise_exc=None):
    monkeypatch.setattr(skill_library, "_http", lambda: _FakeClient(bodies, raise_exc))
    # keep the network-error path fast (no real backoff sleeps)
    monkeypatch.setattr("integrations.retry.time.sleep", lambda *_: None)


# ─── Module: index ────────────────────────────────────────────────────────────
def test_list_skills_parses_and_sorts(monkeypatch):
    _install(monkeypatch, {"index.json": _INDEX})
    skills = skill_library.list_skills()
    assert [s["name"] for s in skills] == ["a-malware", "b-hunt"]  # sorted by name
    assert skills[1]["description"] == "Hunt for beacons"


def test_domains_distinct_sorted(monkeypatch):
    _install(monkeypatch, {"index.json": _INDEX})
    assert skill_library.domains() == ["malware-analysis", "threat-hunting"]


def test_index_is_cached(monkeypatch):
    _install(monkeypatch, {"index.json": _INDEX})
    skill_library.list_skills()
    # Second call must not hit the network — swap in a client that would error.
    monkeypatch.setattr(skill_library, "_http",
                        lambda: _FakeClient({}, httpx.ConnectError("down")))
    assert len(skill_library.list_skills()) == 2  # served from cache


def test_index_network_error_raises(monkeypatch):
    _install(monkeypatch, {}, raise_exc=httpx.ConnectError("down"))
    with pytest.raises(skill_library.SkillLibraryError):
        skill_library.list_skills()


# ─── Module: frontmatter + render ─────────────────────────────────────────────
def test_split_frontmatter_keeps_body_after_horizontal_rule():
    fm, body = skill_library._split_frontmatter(_SKILL_MD)
    assert fm["name"] == "b-hunt"
    assert fm["mitre_attack"] == ["T1071.001"]
    # A '---' hr appears in the body; it must NOT truncate the trailing section.
    assert "Trailing section after a horizontal rule." in body


def test_split_frontmatter_absent():
    fm, body = skill_library._split_frontmatter("# No frontmatter\n\nhi")
    assert fm == {} and body.startswith("# No frontmatter")


def test_get_skill_renders_and_sanitizes(monkeypatch):
    _install(monkeypatch, {"index.json": _INDEX, "skills/b-hunt/SKILL.md": _SKILL_MD})
    skill = skill_library.get_skill("b-hunt")
    assert skill["frontmatter"]["subdomain"] == "threat-hunting"
    assert "<h1>Hunting Beacons</h1>" in skill["html"]
    assert "<li>step one</li>" in skill["html"]
    # sanitizer must strip the executable script tag (leftover inner text is inert)
    assert "<script" not in skill["html"]
    assert skill["source_url"].endswith("/skills/b-hunt/SKILL.md")


def test_get_skill_unknown_slug_is_keyerror(monkeypatch):
    _install(monkeypatch, {"index.json": _INDEX})
    with pytest.raises(KeyError):
        skill_library.get_skill("does-not-exist")  # not in the index → guard trips


# ─── Routes ───────────────────────────────────────────────────────────────────
def test_route_list_renders(monkeypatch):
    monkeypatch.setattr(config, "DEV_AUTH_BYPASS", True)
    monkeypatch.setattr(config, "SKILLS_LIBRARY_ENABLED", True)
    monkeypatch.setattr(skill_library, "list_skills",
                        lambda: [{"name": "b-hunt", "description": "Hunt", "domain": "th", "path": "x"}])
    r = client.get("/skills")
    assert r.status_code == 200
    assert "b hunt" in r.text.lower() and "skill library" in r.text.lower()


def test_route_unknown_skill_404(monkeypatch):
    monkeypatch.setattr(config, "DEV_AUTH_BYPASS", True)
    monkeypatch.setattr(config, "SKILLS_LIBRARY_ENABLED", True)
    def _raise(_):
        raise KeyError("nope")
    monkeypatch.setattr(skill_library, "get_skill", _raise)
    r = client.get("/skills/nope")
    assert r.status_code == 404


def test_route_killswitch_off(monkeypatch):
    monkeypatch.setattr(config, "DEV_AUTH_BYPASS", True)
    monkeypatch.setattr(config, "SKILLS_LIBRARY_ENABLED", False)
    r = client.get("/skills")
    assert r.status_code == 200
    assert "turned off" in r.text.lower()
