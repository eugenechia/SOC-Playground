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


def test_phase1_has_no_tools():
    # Phase 1 invariant: every task ships with an empty tools list and
    # resolve_tools returns nothing (no agent loop yet).
    for t in tasks.list_tasks():
        assert t.tools == []
        assert tasks.resolve_tools(t) == []
