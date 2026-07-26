"""
Model tool-calling scorecard — a reproducible benchmark of how well each local
model drives the agent's tools.

The whole point of the playground is "which model can actually do SOC work?" This
turns that into numbers. A fixed suite of cases (each with an expected tool +
expected params) is run against every selected model through the SAME agent loop
used in the Workbench, but with MOCK tools: the model's first tool call is
CAPTURED and scored, and a canned result is fed back so the run is deterministic
and offline (no live Falcon, no dependency on which hosts exist right now).

Scoring is deterministic and structural:
  - tool_correct : picked the expected tool (or correctly called none)
  - params       : fraction of expected params extracted correctly
  - completed    : produced a final answer with no error
  - overall      : weighted mean (tool 0.5, params 0.3, completed 0.2)
"""
from __future__ import annotations

import json
import logging
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from agents.loop import Tool, run_agent
from app import config
from models_engine.inference import runtime
from models_engine.tasks import get_task, resolve_tools

log = logging.getLogger(__name__)

_SCORECARD_DIR = config.MODELS_DIR / ".scorecards"
_LATEST = _SCORECARD_DIR / "latest.json"

# Weights for the overall score.
_W_TOOL, _W_PARAMS, _W_COMPLETED = 0.5, 0.3, 0.2

# A benign 64-hex sha256 (hash of the empty string) for the hash case.
_SAMPLE_SHA = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

# Canned tool results fed back during a benchmark run (never hits a live API).
_CANNED: dict[str, dict] = {
    "falcon_device_lookup": {"devices": [{"hostname": "MOCK-HOST", "platform_name": "Windows",
                             "os_version": "10 22H2", "status": "normal",
                             "local_ip": "10.0.0.5", "external_ip": "1.2.3.4"}], "count": 1},
    "falcon_recent_alerts": {"detections": [{"id": "mock1", "name": "Suspicious PowerShell",
                             "severity": 70, "tactic": "Execution", "technique": "T1059.001",
                             "status": "new", "hostname": "MOCK-HOST"}], "count": 1},
    "falcon_hash_sightings": {"detections": [{"id": "mock2", "name": "Known Malware",
                             "severity": 90, "tactic": "Execution", "technique": "T1204",
                             "status": "new", "hostname": "MOCK-HOST"}], "count": 1},
    "sentinel_signins": {"template": "signin_events_for_account", "row_count": 1,
                         "rows": [{"UserPrincipalName": "user@corp.com", "IPAddress": "1.2.3.4",
                                   "ResultType": "0"}]},
    "sentinel_host_processes": {"template": "processes_on_host", "row_count": 1, "rows": [{"FileName": "powershell.exe"}]},
    "sentinel_ip_connections": {"template": "network_connections_for_ip", "row_count": 1, "rows": [{"RemotePort": 443}]},
    "sentinel_alerts_for_entity": {"template": "security_alerts_for_entity", "row_count": 1, "rows": [{"AlertName": "Mock Alert"}]},
    "sentinel_hash_events": {"template": "device_events_for_hash", "row_count": 0, "rows": []},
    "ip_reputation": {"value": "45.83.220.5", "ioc_type": "ip", "verdict": "clean", "reasons": [], "sources": {}},
    "hash_reputation": {"ioc_type": "hash", "verdict": "unknown", "reasons": [], "sources": {}},
    "domain_reputation": {"ioc_type": "domain", "verdict": "clean", "reasons": [], "sources": {}},
    "jira_get_issue": {"issue": {"key": "SOC-1042", "summary": "Suspicious login", "status": "Open",
                                 "priority": "High"}},
    "jira_search": {"issues": [{"key": "SOC-1042", "summary": "Phishing report", "status": "Open"}], "count": 1},
}


@dataclass(frozen=True)
class Case:
    id: str
    task_id: str
    prompt: str
    expected_tool: str | None
    expected_args: dict = field(default_factory=dict)


# The benchmark suite. Prompts embed unambiguous values so param extraction is
# objectively checkable.
CASES: list[Case] = [
    Case("device_by_hostname", "crowdstrike-falcon",
         "Look up the CrowdStrike Falcon host named WORKSTATION-42 and report its OS and status.",
         "falcon_device_lookup", {"hostname_or_ip": "WORKSTATION-42"}),
    Case("device_by_ip", "crowdstrike-falcon",
         "Which Falcon host has the IP address 10.20.30.40? Give me its hostname and OS.",
         "falcon_device_lookup", {"hostname_or_ip": "10.20.30.40"}),
    Case("recent_alerts", "crowdstrike-falcon",
         "List the CrowdStrike Falcon detections for host DC-EAST-01 in the last 72 hours.",
         "falcon_recent_alerts", {"hostname": "DC-EAST-01"}),
    Case("hash_sightings", "crowdstrike-falcon",
         f"Are there any Falcon detections involving the file with SHA256 {_SAMPLE_SHA}?",
         "falcon_hash_sightings", {"sha256": _SAMPLE_SHA}),
    Case("sentinel_signins", "sentinel-hunt",
         "Show the Microsoft Sentinel sign-in events for user alice@corp.com over the last 24 hours.",
         "sentinel_signins", {"upn": "alice@corp.com"}),
    Case("ip_reputation", "threat-intel",
         "Check the external threat reputation of the IP address 8.8.8.8.",
         "ip_reputation", {"ip": "8.8.8.8"}),
    Case("jira_get_issue", "alert-triage",
         "Pull up the details of Jira issue SOC-1234 and summarise it.",
         "jira_get_issue", {"issue_key": "SOC-1234"}),
    Case("no_tool_control", "crowdstrike-falcon",
         "In one sentence, explain what credential dumping is. Do not use any tools.",
         None, {}),
]


def _mock_tools(task_id: str) -> list[Tool]:
    """The task's real tool specs, but with fns that return canned data."""
    task = get_task(task_id)
    out: list[Tool] = []
    for t in resolve_tools(task):
        canned = _CANNED.get(t.name, {"result": "ok"})
        out.append(Tool(name=t.name, description=t.description, params=t.params,
                        fn=(lambda _c=canned, **kw: dict(_c))))
    return out


def _arg_matches(expected: str, actual) -> bool:
    if not isinstance(actual, str):
        actual = str(actual)
    e, a = expected.strip().lower(), actual.strip().lower()
    return bool(a) and (e == a or e in a)


def _score_case(case: Case, called_tool: str | None, called_args: dict,
                completed: bool, errored: bool) -> dict:
    if case.expected_tool is None:
        tool_correct = 1.0 if called_tool is None else 0.0
        params = 1.0 if called_tool is None else 0.0
    else:
        tool_correct = 1.0 if called_tool == case.expected_tool else 0.0
        if tool_correct and case.expected_args:
            hits = sum(1 for k, v in case.expected_args.items()
                       if _arg_matches(v, called_args.get(k)))
            params = hits / len(case.expected_args)
        elif tool_correct:
            params = 1.0
        else:
            params = 0.0
    completed_s = 1.0 if (completed and not errored) else 0.0
    overall = _W_TOOL * tool_correct + _W_PARAMS * params + _W_COMPLETED * completed_s
    return {
        "case": case.id,
        "expected_tool": case.expected_tool,
        "called_tool": called_tool,
        "called_args": called_args,
        "tool_correct": tool_correct,
        "params": round(params, 3),
        "completed": completed_s,
        "overall": round(overall, 3),
    }


def _run_case(model_id: str, case: Case) -> dict:
    """Run one case through the agent loop with mock tools; capture + score."""
    tools = _mock_tools(case.task_id)
    task = get_task(case.task_id)
    system_prompt = task.system_prompt if task else ""

    def _generate(messages, sysp, max_new):
        return runtime.generate_text(model_id, messages, sysp, max_new)

    called_tool: str | None = None
    called_args: dict = {}
    completed = False
    errored = False

    for ev in run_agent(
        generate=_generate,
        base_system_prompt=system_prompt,
        tools=tools,
        user_message=case.prompt,
        max_steps=3,
        timeout_s=180,
        step_max_new_tokens=256,
    ):
        e, d = ev["event"], ev["data"]
        if e == "tool_call" and called_tool is None:
            called_tool = d.get("tool")
            called_args = d.get("args") or {}
        elif e == "error":
            errored = True
        elif e == "done":
            completed = True

    return _score_case(case, called_tool, called_args, completed, errored)


def _summarise(case_results: list[dict]) -> dict:
    n = len(case_results) or 1
    return {
        "tool": round(sum(r["tool_correct"] for r in case_results) / n, 3),
        "params": round(sum(r["params"] for r in case_results) / n, 3),
        "completed": round(sum(r["completed"] for r in case_results) / n, 3),
        "overall": round(sum(r["overall"] for r in case_results) / n, 3),
        "cases": len(case_results),
    }


def run_scorecard(model_ids: list[str]) -> Iterator[dict]:
    """Benchmark each model over the suite. Yields progress events and a final
    'result' + 'done'. Persists the latest scorecard to the models mount."""
    models_out: list[dict] = []
    for model_id in model_ids:
        yield {"event": "model_start", "data": {"model": model_id, "total": len(CASES)}}
        case_results: list[dict] = []
        for i, case in enumerate(CASES):
            try:
                r = _run_case(model_id, case)
            except Exception as e:  # noqa: BLE001 — one bad case shouldn't kill the run
                log.warning("scorecard case %s/%s failed: %s", model_id, case.id, e)
                r = _score_case(case, None, {}, completed=False, errored=True)
            case_results.append(r)
            yield {"event": "case_done",
                   "data": {"model": model_id, "index": i + 1, "total": len(CASES), "result": r}}
        summary = _summarise(case_results)
        models_out.append({"model": model_id, "summary": summary, "cases": case_results})
        yield {"event": "model_done", "data": {"model": model_id, "summary": summary}}

    scorecard = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "case_ids": [c.id for c in CASES],
        "models": models_out,
    }
    _save_latest(scorecard)
    yield {"event": "result", "data": scorecard}
    yield {"event": "done", "data": {}}


def _save_latest(scorecard: dict) -> None:
    try:
        _SCORECARD_DIR.mkdir(parents=True, exist_ok=True)
        _LATEST.write_text(json.dumps(scorecard, indent=2))
    except OSError as e:
        log.warning("could not persist scorecard: %s", e)


def load_latest() -> dict | None:
    if not _LATEST.exists():
        return None
    try:
        return json.loads(_LATEST.read_text())
    except (json.JSONDecodeError, OSError):
        return None
