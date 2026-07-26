"""Phase 4 integrations: Jira param safety, KQL param guards, tool registry, and
not-configured behaviour (no live creds in the test env)."""
import pytest

from agents.tools import ALL_TOOL_MAP
from integrations import jira, kql_templates
from integrations.jira import JiraParamError
from integrations.kql_templates import KqlParamError


# ── Jira param safety ────────────────────────────────────────────────
def test_jira_issue_key_validation():
    assert jira.validate_issue_key("soc-1234") == "SOC-1234"
    assert jira.validate_issue_key("ABC-1") == "ABC-1"
    for bad in ["", "1234", "SOC", "SOC 1", "SOC-", "'; DROP"]:
        with pytest.raises(JiraParamError):
            jira.validate_issue_key(bad)


def test_jira_text_search_escapes():
    jql = jira.jql_text_search('phishing "urgent"')
    assert jql.startswith('text ~ ')
    assert '\\"urgent\\"' in jql          # inner quotes escaped
    assert jql.endswith("ORDER BY created DESC")


def test_jira_text_search_rejects_bad():
    for bad in ["", "x" * 300, "line\nbreak"]:
        with pytest.raises(JiraParamError):
            jira.jql_text_search(bad)


# ── KQL template guards ──────────────────────────────────────────────
def test_kql_signins_ok():
    q, ts = kql_templates.signin_events_for_account("user@corp.com", 24)
    assert "SigninLogs" in q and ts == "PT24H"
    assert '"user@corp.com"' in q


def test_kql_string_escaping_blocks_injection():
    # A hostile value cannot break out of the quoted literal: the embedded quote
    # is escaped, so the whole payload stays a single string literal.
    q, _ = kql_templates.processes_on_host('host" | union SecretTable', 24)
    assert 'host\\" | union SecretTable' in q   # quote escaped -> payload is inert text
    # The only unescaped double-quotes are the literal's own delimiters (even count).
    assert q.replace('\\"', "").count('"') % 2 == 0


@pytest.mark.parametrize("bad_hours", [0, 999, "abc"])
def test_kql_hours_bounds(bad_hours):
    with pytest.raises(KqlParamError):
        kql_templates.signin_events_for_account("u@c.com", bad_hours)


# ── Tool registry ────────────────────────────────────────────────────
def test_registry_has_all_integrations():
    for name in ["falcon_device_lookup", "falcon_recent_alerts", "falcon_hash_sightings",
                 "sentinel_signins", "sentinel_host_processes", "sentinel_ip_connections",
                 "sentinel_alerts_for_entity", "sentinel_hash_events",
                 "ip_reputation", "hash_reputation", "domain_reputation",
                 "jira_get_issue", "jira_search"]:
        assert name in ALL_TOOL_MAP, name
        assert callable(ALL_TOOL_MAP[name].fn)


# ── Not-configured behaviour (no creds in test env) ──────────────────
def test_sentinel_tool_reports_not_configured():
    r = ALL_TOOL_MAP["sentinel_signins"].fn(upn="user@corp.com")
    assert r.get("error") == "Sentinel is not configured"


def test_jira_tool_reports_not_configured():
    # Valid key, but Jira has no creds in the test env.
    r = ALL_TOOL_MAP["jira_get_issue"].fn(issue_key="SOC-1")
    assert r.get("error") == "Jira is not configured"


def test_jira_tool_rejects_bad_key_before_config():
    r = ALL_TOOL_MAP["jira_get_issue"].fn(issue_key="not-a-key")
    assert "issue key" in r.get("error", "")


def test_tool_required_arg_missing():
    assert "required" in ALL_TOOL_MAP["ip_reputation"].fn().get("error", "")
