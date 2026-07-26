"""
SSE endpoint for model-download progress. Each connection subscribes to a
broker topic and relays JSON progress frames; a 15s keepalive stops the ACA
ingress idle-timeout from dropping a quiet connection.
"""
import asyncio
import json

from fastapi import APIRouter, Request
from fastapi.responses import StreamingResponse

from app.broker import broker

router = APIRouter()

_KEEPALIVE_S = 15
_HEADERS = {"Cache-Control": "no-cache", "X-Accel-Buffering": "no", "Connection": "keep-alive"}


def _sse(event: str, data: str) -> str:
    lines = "".join(f"data: {ln}\n" for ln in data.split("\n"))
    return f"event: {event}\n{lines}\n"


async def _stream(topic: str, request: Request):
    q = broker.subscribe(topic)
    try:
        yield _sse("ready", json.dumps({"topic": topic}))
        while True:
            if await request.is_disconnected():
                break
            try:
                event, data = await asyncio.wait_for(q.get(), timeout=_KEEPALIVE_S)
                yield _sse(event, data)
            except asyncio.TimeoutError:
                yield ": keepalive\n\n"
    finally:
        broker.unsubscribe(topic, q)


@router.get("/events/download/{job_id}")
async def events_download(request: Request, job_id: str):
    return StreamingResponse(
        _stream(f"download:{job_id}", request),
        media_type="text/event-stream",
        headers=_HEADERS,
    )
