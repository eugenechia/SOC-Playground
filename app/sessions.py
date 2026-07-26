"""
Ephemeral, in-memory chat history — no database in Phase 1.

History is keyed by (session_id, task_id, model_id) so switching task or model
gives a fresh conversation. This is an in-process singleton: correct only at
min=max=1 replica, and intentionally lost on restart (a playground, not a
system of record).
"""
from __future__ import annotations

import threading
from collections import defaultdict

_lock = threading.Lock()
# key -> list of {"role": "user"|"assistant", "content": str}
_store: dict[tuple[str, str, str], list[dict]] = defaultdict(list)


def _key(session_id: str, task_id: str, model_id: str) -> tuple[str, str, str]:
    return (session_id, task_id, model_id)


def get_history(session_id: str, task_id: str, model_id: str) -> list[dict]:
    with _lock:
        # Return a copy so callers can't mutate the stored list in place.
        return list(_store[_key(session_id, task_id, model_id)])


def append(session_id: str, task_id: str, model_id: str, role: str, content: str) -> None:
    with _lock:
        _store[_key(session_id, task_id, model_id)].append({"role": role, "content": content})


def clear(session_id: str, task_id: str, model_id: str) -> None:
    with _lock:
        _store.pop(_key(session_id, task_id, model_id), None)
