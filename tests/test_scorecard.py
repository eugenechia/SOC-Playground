"""Scorecard scoring + a full run driven by a scripted fake model (no real
model, no network)."""
from agents import scorecard as sc
from models_engine.inference import runtime


# ── Pure scoring ─────────────────────────────────────────────────────
def _case(expected_tool, expected_args):
    return sc.Case("c", "crowdstrike-falcon", "p", expected_tool, expected_args)


def test_score_perfect_tool_case():
    c = _case("falcon_device_lookup", {"hostname_or_ip": "WORKSTATION-42"})
    r = sc._score_case(c, "falcon_device_lookup", {"hostname_or_ip": "WORKSTATION-42"},
                       completed=True, errored=False)
    assert r["tool_correct"] == 1.0 and r["params"] == 1.0 and r["completed"] == 1.0
    assert r["overall"] == 1.0


def test_score_wrong_tool_zeroes_params():
    c = _case("falcon_device_lookup", {"hostname_or_ip": "H"})
    r = sc._score_case(c, "falcon_recent_alerts", {"hostname": "H"}, completed=True, errored=False)
    assert r["tool_correct"] == 0.0 and r["params"] == 0.0


def test_score_partial_params():
    c = _case("falcon_recent_alerts", {"hostname": "DC-EAST-01", "sha256": "x"})
    r = sc._score_case(c, "falcon_recent_alerts", {"hostname": "DC-EAST-01"},
                       completed=True, errored=False)
    assert r["params"] == 0.5


def test_score_no_tool_control():
    c = _case(None, {})
    ok = sc._score_case(c, None, {}, completed=True, errored=False)
    assert ok["tool_correct"] == 1.0 and ok["params"] == 1.0
    spurious = sc._score_case(c, "falcon_device_lookup", {}, completed=True, errored=False)
    assert spurious["tool_correct"] == 0.0


def test_score_errored_not_completed():
    c = _case("falcon_device_lookup", {"hostname_or_ip": "H"})
    r = sc._score_case(c, "falcon_device_lookup", {"hostname_or_ip": "H"},
                       completed=False, errored=True)
    assert r["completed"] == 0.0


def test_arg_matches():
    assert sc._arg_matches("WORKSTATION-42", "workstation-42")
    assert sc._arg_matches("DC-EAST-01", "host DC-EAST-01")   # substring
    assert not sc._arg_matches("H1", "H2")
    assert not sc._arg_matches("H1", None)


# ── Full run with a scripted "perfect" model ─────────────────────────
# runtime.generate_text is invoked as runtime.generate_text(model_id, messages,
# system_prompt, max_new); monkeypatched as a plain function it receives all four.
def _perfect_generate(model_id, messages, system_prompt, max_new):
    last = messages[-1]["content"]
    if last.startswith("Observation"):
        return "Based on the tool result, here is my analysis."
    prompt = messages[0]["content"]
    if "WORKSTATION-42" in prompt:
        return '{"tool": "falcon_device_lookup", "args": {"hostname_or_ip": "WORKSTATION-42"}}'
    if "10.20.30.40" in prompt:
        return '{"tool": "falcon_device_lookup", "args": {"hostname_or_ip": "10.20.30.40"}}'
    if "DC-EAST-01" in prompt:
        return '{"tool": "falcon_recent_alerts", "args": {"hostname": "DC-EAST-01", "hours": 72}}'
    if "e3b0c442" in prompt:
        return ('{"tool": "falcon_hash_sightings", "args": {"sha256": '
                '"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}}')
    if "alice@corp.com" in prompt:
        return '{"tool": "sentinel_signins", "args": {"upn": "alice@corp.com"}}'
    if "8.8.8.8" in prompt:
        return '{"tool": "ip_reputation", "args": {"ip": "8.8.8.8"}}'
    if "SOC-1234" in prompt:
        return '{"tool": "jira_get_issue", "args": {"issue_key": "SOC-1234"}}'
    return "Credential dumping is stealing credentials from memory or storage."


def _never_tools_generate(model_id, messages, system_prompt, max_new):
    return "Here is a plain answer without calling any tools."


def test_run_scorecard_perfect_model(monkeypatch):
    monkeypatch.setattr(runtime, "generate_text", _perfect_generate)
    events = list(sc.run_scorecard(["perfect-model"]))
    kinds = [e["event"] for e in events]
    assert "model_done" in kinds and kinds[-1] == "done"
    summary = next(e["data"]["summary"] for e in events if e["event"] == "model_done")
    assert summary["tool"] == 1.0
    assert summary["params"] == 1.0
    assert summary["overall"] == 1.0
    # persisted and reloadable
    latest = sc.load_latest()
    assert latest is not None and latest["models"][0]["model"] == "perfect-model"


def test_run_scorecard_differentiates_models(monkeypatch):
    monkeypatch.setattr(runtime, "generate_text", _never_tools_generate)
    events = list(sc.run_scorecard(["lazy-model"]))
    summary = next(e["data"]["summary"] for e in events if e["event"] == "model_done")
    # Only the no-tool control scores on tool-selection (1 of 5 cases).
    assert summary["tool"] == round(1 / len(sc.CASES), 3)
    assert summary["overall"] < 0.5
