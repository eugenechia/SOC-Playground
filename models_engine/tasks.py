"""
Task registry — loaded from tasks/tasks.yaml.

A task frames an experiment: a system prompt, starter prompts, and (Phase 2) a
set of tools. In Phase 1 every task's `tools` list is empty and resolve_tools()
returns [], so the workbench is a pure single-shot chat. The Tool Protocol and
resolve_tools() are declared now so the Phase-2 agent loop plugs in without
touching routes, templates, or the inference/registry layers — the only files
that change in Phase 2 are this one, tasks.yaml, and workbench.py's inner loop.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol, runtime_checkable

import yaml

from app import config


@dataclass(frozen=True)
class Task:
    id: str
    name: str
    description: str
    system_prompt: str
    starter_prompts: list[str] = field(default_factory=list)
    tools: list[str] = field(default_factory=list)  # Phase 1: always []


# ── Phase-2 seam (declared now, unused in Phase 1) ───────────────────
@runtime_checkable
class Tool(Protocol):
    name: str

    def spec(self) -> dict:
        """JSON-schema tool spec for function-calling."""
        ...

    def run(self, **kwargs) -> dict:
        """Execute the tool and return a JSON-serialisable result."""
        ...


# Phase 2 will populate this: {tool_id: Tool instance}.
TOOL_REGISTRY: dict[str, "Tool"] = {}


def resolve_tools(task: Task) -> list["Tool"]:
    """Map a task's tool ids to Tool instances. Phase 1 returns []."""
    return [TOOL_REGISTRY[t] for t in task.tools if t in TOOL_REGISTRY]


# ── Loading ──────────────────────────────────────────────────────────
def load_tasks(path: Path | None = None) -> dict[str, Task]:
    path = path or config.TASKS_FILE
    raw = yaml.safe_load(Path(path).read_text()) or {}
    items = raw.get("tasks", [])
    out: dict[str, Task] = {}
    for it in items:
        task = Task(
            id=it["id"],
            name=it["name"],
            description=it.get("description", ""),
            system_prompt=it.get("system_prompt", ""),
            starter_prompts=list(it.get("starter_prompts", [])),
            tools=list(it.get("tools", [])),
        )
        out[task.id] = task
    return out


# Load once at import; the file is baked into the image.
_TASKS: dict[str, Task] = load_tasks()


def list_tasks() -> list[Task]:
    return list(_TASKS.values())


def get_task(task_id: str) -> Task | None:
    return _TASKS.get(task_id)
