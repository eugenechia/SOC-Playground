"""Agent loop: tolerant tool-call parsing + the run_agent step generator.

No model and no network — `generate` is a scripted fake, tools are fakes. This
exercises the loop mechanics that matter for weak local models.
"""
from agents.loop import Tool, parse_tool_call, run_agent


# ── Parser ───────────────────────────────────────────────────────────
def test_parse_bare_object():
    name, args = parse_tool_call('{"tool": "falcon_recent_alerts", "args": {"hostname": "h1"}}')
    assert name == "falcon_recent_alerts"
    assert args == {"hostname": "h1"}


def test_parse_with_surrounding_prose():
    text = 'Sure, let me check.\n{"tool": "falcon_device_lookup", "args": {"hostname_or_ip": "10.0.0.1"}}\nThanks'
    name, args = parse_tool_call(text)
    assert name == "falcon_device_lookup"
    assert args == {"hostname_or_ip": "10.0.0.1"}


def test_parse_fenced_block():
    text = '```json\n{"tool": "falcon_hash_sightings", "args": {"sha256": "abc"}}\n```'
    name, args = parse_tool_call(text)
    assert name == "falcon_hash_sightings"


def test_parse_missing_args_defaults_empty():
    name, args = parse_tool_call('{"tool": "x"}')
    assert name == "x" and args == {}


def test_parse_no_tool_call_returns_none():
    assert parse_tool_call("Here is my final answer, no tools needed.") is None
    assert parse_tool_call('{"not_a_tool": true}') is None
    assert parse_tool_call("") is None


# ── run_agent ────────────────────────────────────────────────────────
def _events(gen):
    return [(e["event"], e["data"]) for e in gen]


def test_loop_runs_tool_then_answers():
    calls = {"n": 0}

    def fake_generate(messages, system_prompt, max_new):
        calls["n"] += 1
        if calls["n"] == 1:
            return '{"tool": "echo", "args": {"x": 1}}'
        return "Final answer based on the observation."

    echo = Tool(name="echo", description="echo", params={}, fn=lambda **kw: {"echoed": kw})
    events = _events(run_agent(
        generate=fake_generate, base_system_prompt="sys", tools=[echo],
        user_message="hi", max_steps=4,
    ))
    kinds = [e for e, _ in events]
    assert kinds == ["status", "tool_call", "tool_result", "status", "token", "done"] or \
           kinds == ["status", "tool_call", "tool_result", "token", "done"]
    # tool_call carries the parsed tool + args
    tc = next(d for e, d in events if e == "tool_call")
    assert tc["tool"] == "echo" and tc["args"] == {"x": 1}
    # tool_result carries the tool's return
    tr = next(d for e, d in events if e == "tool_result")
    assert tr["result"] == {"echoed": {"x": 1}}
    # final answer surfaced as a token
    tok = next(d for e, d in events if e == "token")
    assert "Final answer" in tok["text"]


def test_loop_direct_answer_no_tool():
    def fake_generate(messages, system_prompt, max_new):
        return "No tool needed — here's the answer."

    events = _events(run_agent(
        generate=fake_generate, base_system_prompt="sys", tools=[], user_message="hi",
    ))
    kinds = [e for e, _ in events]
    assert "tool_call" not in kinds
    assert kinds[-1] == "done"
    tok = next(d for e, d in events if e == "token")
    assert "answer" in tok["text"].lower()


def test_loop_unknown_tool_becomes_error_observation():
    calls = {"n": 0}

    def fake_generate(messages, system_prompt, max_new):
        calls["n"] += 1
        if calls["n"] == 1:
            return '{"tool": "does_not_exist", "args": {}}'
        return "Recovered and answered."

    events = _events(run_agent(
        generate=fake_generate, base_system_prompt="sys", tools=[], user_message="hi", max_steps=4,
    ))
    tr = next(d for e, d in events if e == "tool_result")
    assert "error" in tr["result"]
    assert "unknown tool" in tr["result"]["error"]


def test_loop_tool_exception_is_evidence_not_crash():
    def boom(**kwargs):
        raise ValueError("falcon exploded")

    calls = {"n": 0}

    def fake_generate(messages, system_prompt, max_new):
        calls["n"] += 1
        return '{"tool": "boom", "args": {}}' if calls["n"] == 1 else "Handled the error."

    boom_tool = Tool(name="boom", description="boom", params={}, fn=boom)
    events = _events(run_agent(
        generate=fake_generate, base_system_prompt="sys", tools=[boom_tool],
        user_message="hi", max_steps=4,
    ))
    tr = next(d for e, d in events if e == "tool_result")
    assert "error" in tr["result"] and "falcon exploded" in tr["result"]["error"]
