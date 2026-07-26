"""Task loading and the Phase-2 tool seam."""
from models_engine import tasks


def test_tasks_load():
    all_tasks = tasks.list_tasks()
    assert all_tasks, "expected at least one task in tasks.yaml"
    ids = {t.id for t in all_tasks}
    assert "crowdstrike-falcon" in ids


def test_get_task():
    t = tasks.get_task("crowdstrike-falcon")
    assert t is not None
    assert t.name == "CrowdStrike Falcon"
    assert t.system_prompt.strip()
    assert isinstance(t.starter_prompts, list) and t.starter_prompts


def test_crowdstrike_task_resolves_falcon_tools():
    # Phase 2: the CrowdStrike task wires the three read-only Falcon tools.
    t = tasks.get_task("crowdstrike-falcon")
    resolved = tasks.resolve_tools(t)
    names = {tool.name for tool in resolved}
    assert names == {"falcon_device_lookup", "falcon_recent_alerts", "falcon_hash_sightings"}


def test_non_tool_tasks_resolve_empty():
    # Tasks without tools stay pure single-shot chat.
    for tid in ("malware-analysis", "general-soc"):
        t = tasks.get_task(tid)
        assert t.tools == []
        assert tasks.resolve_tools(t) == []


def test_phase4_tasks_resolve_their_tools():
    expected = {
        "sentinel-hunt": {"sentinel_signins", "sentinel_host_processes", "sentinel_ip_connections",
                          "sentinel_alerts_for_entity", "sentinel_hash_events"},
        "threat-intel": {"ip_reputation", "hash_reputation", "domain_reputation"},
        "alert-triage": {"jira_get_issue", "jira_search"},
    }
    for tid, names in expected.items():
        t = tasks.get_task(tid)
        assert t is not None, tid
        assert {tool.name for tool in tasks.resolve_tools(t)} == names
