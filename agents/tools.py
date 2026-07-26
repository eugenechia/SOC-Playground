"""
Read-only CrowdStrike Falcon tools for the agent loop.

The model supplies STRUCTURED params (hostname, ip, sha256, hours); we build the
FQL from the fixed templates in integrations/fql_templates.py — the model never
composes a query. Every tool is read-only and returns a JSON-serialisable dict
(errors as {"error": ...} evidence, never an exception). Registered into
models_engine.tasks.TOOL_REGISTRY so a task's `tools:` list resolves to these.
"""
from __future__ import annotations

import logging

from agents.loop import Tool
from integrations import crowdstrike, fql_templates
from integrations.fql_templates import FqlParamError

log = logging.getLogger(__name__)

_HOST_KEEP = ("device_id", "hostname", "platform_name", "os_version", "status",
              "last_seen", "local_ip", "external_ip", "machine_domain",
              "os_product_name", "agent_version")


def _shape_host(d: dict) -> dict:
    return {k: d.get(k) for k in _HOST_KEEP}


def _shape_detection(a: dict) -> dict:
    return {
        "id": a.get("composite_id"),
        "name": a.get("display_name") or a.get("name"),
        "severity": a.get("severity"),
        "status": a.get("status"),
        "tactic": a.get("tactic"),
        "technique": a.get("technique"),
        "created": a.get("created_timestamp"),
        "hostname": (a.get("device") or {}).get("hostname"),
    }


def _cfg() -> crowdstrike.FalconConfig:
    if not crowdstrike.configured():
        raise RuntimeError(crowdstrike.NOT_CONFIGURED_MSG)
    return crowdstrike.env_cfg()


# ─── Tool functions (sync, structured params → template → client) ─────────────
def falcon_device_lookup(hostname_or_ip: str = "") -> dict:
    s = (hostname_or_ip or "").strip()
    if not s:
        return {"error": "hostname_or_ip is required"}
    cfg = _cfg()
    try:
        # Try IP form first; fall back to hostname. Both go through validators.
        try:
            fql = fql_templates.device_by_ip(s)
        except FqlParamError:
            fql = fql_templates.device_by_hostname(s)
    except FqlParamError as e:
        return {"error": str(e)}
    ids = crowdstrike.query_devices(cfg, fql, limit=20)
    if not ids:
        return {"devices": [], "count": 0, "note": "no matching Falcon hosts"}
    hosts = [_shape_host(d) for d in crowdstrike.get_devices(cfg, ids)]
    return {"devices": hosts, "count": len(hosts)}


def falcon_recent_alerts(hostname: str = "", hours: int = 24) -> dict:
    if not (hostname or "").strip():
        return {"error": "hostname is required"}
    cfg = _cfg()
    try:
        fql = fql_templates.alerts_for_host(hostname, hours)
    except FqlParamError as e:
        return {"error": str(e)}
    ids = crowdstrike.query_alerts(cfg, fql, limit=20)
    if not ids:
        return {"detections": [], "count": 0, "note": "no matching Falcon detections"}
    dets = [_shape_detection(a) for a in crowdstrike.get_alerts(cfg, ids)]
    return {"detections": dets, "count": len(dets)}


def falcon_hash_sightings(sha256: str = "", hours: int = 168) -> dict:
    if not (sha256 or "").strip():
        return {"error": "sha256 is required"}
    cfg = _cfg()
    try:
        fql = fql_templates.alerts_for_hash(sha256, hours)
    except FqlParamError as e:
        return {"error": str(e)}
    ids = crowdstrike.query_alerts(cfg, fql, limit=20)
    if not ids:
        return {"detections": [], "count": 0, "note": "no detections for this hash"}
    dets = [_shape_detection(a) for a in crowdstrike.get_alerts(cfg, ids)]
    return {"detections": dets, "count": len(dets)}


# ─── Tool specs ───────────────────────────────────────────────────────────────
FALCON_TOOLS: list[Tool] = [
    Tool(
        name="falcon_device_lookup",
        description="Look up a CrowdStrike Falcon host by hostname or IP address. "
                    "Returns OS, containment status, last-seen, IPs, domain. Read-only.",
        params={"hostname_or_ip": {"type": "string", "required": True,
                                   "description": "A hostname or an IPv4/IPv6 address."}},
        fn=falcon_device_lookup,
    ),
    Tool(
        name="falcon_recent_alerts",
        description="List recent Falcon detections/alerts for a given host. "
                    "Returns name, severity, MITRE tactic/technique, status, timestamps. Read-only.",
        params={
            "hostname": {"type": "string", "required": True, "description": "The host to search."},
            "hours": {"type": "integer", "required": False,
                      "description": "Look-back window in hours (1-168, default 24)."},
        },
        fn=falcon_recent_alerts,
    ),
    Tool(
        name="falcon_hash_sightings",
        description="Find Falcon detections involving a specific file SHA256 hash. Read-only.",
        params={
            "sha256": {"type": "string", "required": True, "description": "64-hex-char SHA256."},
            "hours": {"type": "integer", "required": False,
                      "description": "Look-back window in hours (1-168, default 168)."},
        },
        fn=falcon_hash_sightings,
    ),
]

# {tool_name: Tool} for registration into the task tool registry.
FALCON_TOOL_MAP = {t.name: t for t in FALCON_TOOLS}
