"""
Prompted-JSON agent loop for LOCAL models.

SOC-Copilot's loop relies on OpenAI native function-calling; our in-process
Transformers models don't emit `tool_calls`, and small models are unreliable at
structured output. So this loop uses a plain-JSON protocol with a TOLERANT
parser: the model is told to emit `{"tool": "...", "args": {...}}` to call a
tool; we extract it (fenced block or balanced-brace scan), run the tool, feed the
result back as an Observation, and loop. A turn with no valid tool JSON is the
final answer.

run_agent is a SYNC GENERATOR that yields step events (dicts). The route turns
each into an SSE frame, so the analyst watches the model reason, call tools, and
receive data — the whole point of the playground. Bounded by max_steps and a
wall-clock deadline.
"""
from __future__ import annotations

import json
import logging
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field

log = logging.getLogger(__name__)

_RESULT_DISPLAY_CAP = 4000   # chars of tool JSON shown/fed back


@dataclass(frozen=True)
class Tool:
    name: str
    description: str
    # {arg_name: {"type": "...", "description": "...", "required": bool}}
    params: dict[str, dict] = field(default_factory=dict)
    fn: Callable[..., dict] = None   # sync: fn(**args) -> JSON-serialisable dict


def _tool_signature(t: Tool) -> str:
    args = ", ".join(
        f"{n}: {spec.get('type', 'string')}"
        + ("" if spec.get("required") else "?")
        for n, spec in t.params.items()
    )
    return f"{t.name}({args}) — {t.description}"


def build_system_prompt(base_system_prompt: str, tools: list[Tool]) -> str:
    lines = [base_system_prompt.strip(), "", "You can call tools to fetch live data."]
    lines.append(
        "To call a tool, reply with ONLY a JSON object and nothing else:\n"
        '{"tool": "<name>", "args": {<arguments>}}'
    )
    lines.append("\nAvailable tools:")
    for t in tools:
        lines.append(f"- {_tool_signature(t)}")
        for n, spec in t.params.items():
            req = "required" if spec.get("required") else "optional"
            lines.append(f"    - {n} ({req}): {spec.get('description', '')}")
    lines.append(
        "\nRules:\n"
        "- Call a tool ONLY when you need live data. Use exact tool names above.\n"
        "- After a tool runs you receive an 'Observation'. Then either call another "
        "tool or give your FINAL answer in plain prose (no JSON).\n"
        "- If you already have enough information, answer directly without any JSON.\n"
        "- Never invent tool results; only use what an Observation returned."
    )
    return "\n".join(lines)


def parse_tool_call(text: str) -> tuple[str, dict] | None:
    """Extract the first valid {"tool":..., "args":{...}} object from model text.

    Tolerant: accepts a fenced ```json block or a bare object anywhere in the
    text, ignores surrounding prose, and scans for a balanced brace span.
    Returns (tool_name, args) or None if there's no valid tool call.
    """
    if not text:
        return None
    # Scan every '{' as a candidate start and try to json.loads a balanced span.
    for start in (i for i, c in enumerate(text) if c == "{"):
        depth = 0
        in_str = False
        esc = False
        for end in range(start, len(text)):
            c = text[end]
            if in_str:
                if esc:
                    esc = False
                elif c == "\\":
                    esc = True
                elif c == '"':
                    in_str = False
                continue
            if c == '"':
                in_str = True
            elif c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    candidate = text[start:end + 1]
                    try:
                        obj = json.loads(candidate)
                    except json.JSONDecodeError:
                        break  # not valid JSON from this start; try next '{'
                    if isinstance(obj, dict) and isinstance(obj.get("tool"), str):
                        args = obj.get("args")
                        return obj["tool"], (args if isinstance(args, dict) else {})
                    break
    return None


def _run_tool(tool: Tool, args: dict) -> dict:
    """Execute a tool, converting any exception into structured evidence."""
    try:
        result = tool.fn(**args)
        return result if isinstance(result, dict) else {"result": result}
    except TypeError as e:
        # Wrong/missing args from the model — surface so it can correct.
        return {"error": f"bad arguments for {tool.name}: {e}"}
    except Exception as e:  # noqa: BLE001 — evidence, not a crash
        return {"error": f"{type(e).__name__}: {e}"}


def run_agent(
    *,
    generate: Callable[[list[dict], str, int], str],
    base_system_prompt: str,
    tools: list[Tool],
    user_message: str,
    history: list[dict] | None = None,
    max_steps: int = 6,
    timeout_s: int = 300,
    step_max_new_tokens: int = 400,
) -> Iterator[dict]:
    """Drive the tool-calling loop. `generate(messages, system_prompt, max_new_tokens)
    -> str` is the model call (full turn). Yields event dicts:
      {"event": "status"|"tool_call"|"tool_result"|"token"|"error"|"done", "data": {...}}
    """
    tool_map = {t.name: t for t in tools}
    system_prompt = build_system_prompt(base_system_prompt, tools)
    messages: list[dict] = list(history or [])
    messages.append({"role": "user", "content": user_message})

    deadline = time.monotonic() + timeout_s
    final_text = ""

    for step in range(max_steps):
        if time.monotonic() > deadline:
            yield {"event": "error", "data": {"message": "Agent timed out."}}
            return

        yield {"event": "status", "data": {"message": f"Thinking (step {step + 1}/{max_steps})…"}}
        try:
            turn = generate(messages, system_prompt, step_max_new_tokens)
        except Exception as e:  # noqa: BLE001
            yield {"event": "error", "data": {"message": f"Generation failed: {e}"}}
            return

        call = parse_tool_call(turn)
        if call is None:
            final_text = turn.strip()
            break

        name, args = call
        messages.append({"role": "assistant", "content": turn})
        yield {"event": "tool_call", "data": {"tool": name, "args": args, "step": step + 1}}

        tool = tool_map.get(name)
        if tool is None:
            observation = {"error": f"unknown tool '{name}'. Available: {list(tool_map)}"}
        else:
            observation = _run_tool(tool, args)

        result_json = json.dumps(observation)[:_RESULT_DISPLAY_CAP]
        yield {"event": "tool_result", "data": {"tool": name, "result": observation, "step": step + 1}}
        messages.append({"role": "user", "content": f"Observation from {name}: {result_json}"})
    else:
        # Loop exhausted without a plain-prose answer — ask for a final synthesis.
        yield {"event": "status", "data": {"message": "Max steps reached — summarising…"}}
        try:
            final_text = generate(
                messages + [{"role": "user",
                             "content": "Give your final answer now in plain prose, no JSON."}],
                system_prompt, step_max_new_tokens,
            ).strip()
        except Exception as e:  # noqa: BLE001
            yield {"event": "error", "data": {"message": f"Generation failed: {e}"}}
            return

    if final_text:
        yield {"event": "token", "data": {"text": final_text}}
    else:
        yield {"event": "token", "data": {"text": "(no answer)"}}
    yield {"event": "done", "data": {}}
