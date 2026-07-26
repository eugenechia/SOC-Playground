"""
In-process SSE pub/sub. Correct (not just adequate) for a single-replica app:
the model runtime and this broker are both in-process singletons.

Topics used here: f"download:{job_id}" (one model-download job's progress).
Publishers push (event, data) tuples; subscribers are asyncio queues drained by
the SSE route in app/routes/events.py. A slow subscriber's queue fills and is
dropped — its browser reconnects, so nothing is permanently stuck.

Payloads are small JSON strings (progress) or pre-rendered HTML fragments, so
the browser JS stays a dumb EventSource / reader that appends nodes.
"""
import asyncio
import logging
from collections import defaultdict

log = logging.getLogger(__name__)

_QUEUE_MAX = 200


class Broker:
    def __init__(self) -> None:
        self._subs: dict[str, set[asyncio.Queue]] = defaultdict(set)

    def subscribe(self, topic: str) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=_QUEUE_MAX)
        self._subs[topic].add(q)
        return q

    def unsubscribe(self, topic: str, q: asyncio.Queue) -> None:
        self._subs[topic].discard(q)
        if not self._subs[topic]:
            self._subs.pop(topic, None)

    def publish(self, topic: str, event: str, html: str) -> None:
        for q in list(self._subs.get(topic, ())):
            try:
                q.put_nowait((event, html))
            except asyncio.QueueFull:
                # Drop the slow subscriber; its browser reconnects and re-renders.
                self._subs[topic].discard(q)
                log.debug("Dropped a full SSE subscriber on topic %s", topic)


# One process-wide broker instance.
broker = Broker()
