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
from integrations import crowdstrike, fql_templates, jira, kql_templates, sentinel, threat_intel
from integrations.fql_templates import FqlParamError
from integrations.jira import JiraParamError
from integrations.kql_templates import KqlParamError

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

FALCON_TOOL_MAP = {t.name: t for t in FALCON_TOOLS}


# ─── Microsoft Sentinel (read-only KQL via templates) ─────────────────────────
_ROW_CAP = 30  # rows shown to the model per query


def _run_sentinel(template_name: str, **params) -> dict:
    if not sentinel.configured():
        return {"error": "Sentinel is not configured"}
    try:
        query, timespan = kql_templates.TEMPLATES[template_name](**params)
    except KqlParamError as e:
        return {"error": f"invalid parameter: {e}"}
    try:
        rows = sentinel.run_kql(query, timespan=timespan)
    except PermissionError as e:
        return {"error": str(e)}
    return {"template": template_name, "row_count": len(rows), "rows": rows[:_ROW_CAP]}


def sentinel_signins(upn: str = "", hours: int = 72) -> dict:
    if not (upn or "").strip():
        return {"error": "upn is required"}
    return _run_sentinel("signin_events_for_account", upn=upn, hours=hours)


def sentinel_host_processes(hostname: str = "", hours: int = 72) -> dict:
    if not (hostname or "").strip():
        return {"error": "hostname is required"}
    return _run_sentinel("processes_on_host", hostname=hostname, hours=hours)


def sentinel_ip_connections(ip: str = "", hours: int = 72) -> dict:
    if not (ip or "").strip():
        return {"error": "ip is required"}
    return _run_sentinel("network_connections_for_ip", ip=ip, hours=hours)


def sentinel_alerts_for_entity(value: str = "", hours: int = 168) -> dict:
    if not (value or "").strip():
        return {"error": "value is required"}
    return _run_sentinel("security_alerts_for_entity", value=value, hours=hours)


def sentinel_hash_events(sha256: str = "", hours: int = 168) -> dict:
    if not (sha256 or "").strip():
        return {"error": "sha256 is required"}
    return _run_sentinel("device_events_for_hash", sha=sha256, hours=hours)


_HOURS_PARAM = {"type": "integer", "required": False,
                "description": "Look-back window in hours (1-168)."}

SENTINEL_TOOLS: list[Tool] = [
    Tool(name="sentinel_signins", fn=sentinel_signins,
         description="Query Microsoft Sentinel SigninLogs for a user (UPN): times, IP, app, result. Read-only.",
         params={"upn": {"type": "string", "required": True, "description": "User principal name / email."},
                 "hours": _HOURS_PARAM}),
    Tool(name="sentinel_host_processes", fn=sentinel_host_processes,
         description="Query Sentinel DeviceProcessEvents for a host: command lines, parent process, SHA256. Read-only.",
         params={"hostname": {"type": "string", "required": True, "description": "Device/host name."},
                 "hours": _HOURS_PARAM}),
    Tool(name="sentinel_ip_connections", fn=sentinel_ip_connections,
         description="Query Sentinel DeviceNetworkEvents for connections to an IP. Read-only.",
         params={"ip": {"type": "string", "required": True, "description": "Remote IPv4/IPv6 address."},
                 "hours": _HOURS_PARAM}),
    Tool(name="sentinel_alerts_for_entity", fn=sentinel_alerts_for_entity,
         description="Query Sentinel SecurityAlert for any entity value (host, user, IP, hash). Read-only.",
         params={"value": {"type": "string", "required": True, "description": "Entity value to search for."},
                 "hours": _HOURS_PARAM}),
    Tool(name="sentinel_hash_events", fn=sentinel_hash_events,
         description="Query Sentinel DeviceFileEvents for a file hash (MD5/SHA1/SHA256). Read-only.",
         params={"sha256": {"type": "string", "required": True, "description": "File hash."},
                 "hours": _HOURS_PARAM}),
]
SENTINEL_TOOL_MAP = {t.name: t for t in SENTINEL_TOOLS}


# ─── Threat intel (IOC reputation) ────────────────────────────────────────────
def ip_reputation(ip: str = "") -> dict:
    if not (ip or "").strip():
        return {"error": "ip is required"}
    return threat_intel.check_reputation(ip, "ip")


def hash_reputation(sha256: str = "") -> dict:
    if not (sha256 or "").strip():
        return {"error": "sha256 is required"}
    return threat_intel.check_reputation(sha256, "hash")


def domain_reputation(domain: str = "") -> dict:
    if not (domain or "").strip():
        return {"error": "domain is required"}
    return threat_intel.check_reputation(domain, "domain")


THREAT_INTEL_TOOLS: list[Tool] = [
    Tool(name="ip_reputation", fn=ip_reputation,
         description="External reputation for an IP (VirusTotal/AbuseIPDB). Verdict malicious|clean|unknown. Read-only.",
         params={"ip": {"type": "string", "required": True, "description": "IPv4/IPv6 address."}}),
    Tool(name="hash_reputation", fn=hash_reputation,
         description="External reputation for a file hash via VirusTotal. Read-only.",
         params={"sha256": {"type": "string", "required": True, "description": "MD5/SHA1/SHA256 hash."}}),
    Tool(name="domain_reputation", fn=domain_reputation,
         description="External reputation for a domain via VirusTotal. Read-only.",
         params={"domain": {"type": "string", "required": True, "description": "Domain name."}}),
]
THREAT_INTEL_TOOL_MAP = {t.name: t for t in THREAT_INTEL_TOOLS}


# ─── Jira (read-only) ─────────────────────────────────────────────────────────
def _shape_issue(issue: dict) -> dict:
    f = issue.get("fields") or {}
    def _name(x):
        return (x or {}).get("displayName") or (x or {}).get("name") if isinstance(x, dict) else x
    desc = f.get("description")
    if isinstance(desc, dict):
        desc = "(rich text)"
    return {
        "key": issue.get("key"),
        "summary": f.get("summary"),
        "status": _name(f.get("status")),
        "priority": _name(f.get("priority")),
        "assignee": _name(f.get("assignee")),
        "type": _name(f.get("issuetype")),
        "created": f.get("created"),
        "description": (str(desc)[:500] if desc else None),
    }


def jira_get_issue(issue_key: str = "") -> dict:
    try:
        key = jira.validate_issue_key(issue_key)
    except JiraParamError as e:
        return {"error": str(e)}
    if not jira.configured():
        return {"error": "Jira is not configured"}
    issue = jira.fetch_issue_by_key(key)
    if issue is None:
        return {"error": f"issue {key} not found or unreadable"}
    return {"issue": _shape_issue(issue)}


def jira_search(text: str = "") -> dict:
    try:
        jql = jira.jql_text_search(text)
    except JiraParamError as e:
        return {"error": str(e)}
    if not jira.configured():
        return {"error": "Jira is not configured"}
    res = jira.jql_search(jql, fields="summary,status,priority,assignee,issuetype,created")
    if "error" in res:
        return res
    issues = [_shape_issue(i) for i in (res.get("issues") or [])]
    return {"issues": issues, "count": len(issues)}


JIRA_TOOLS: list[Tool] = [
    Tool(name="jira_get_issue", fn=jira_get_issue,
         description="Fetch a Jira issue/alert ticket by key (e.g. SOC-1234): summary, status, priority, assignee. Read-only.",
         params={"issue_key": {"type": "string", "required": True, "description": "Issue key like PROJ-123."}}),
    Tool(name="jira_search", fn=jira_search,
         description="Search Jira issues by free text (matched safely). Returns matching tickets. Read-only.",
         params={"text": {"type": "string", "required": True, "description": "Text to search for."}}),
]
JIRA_TOOL_MAP = {t.name: t for t in JIRA_TOOLS}


# ─── Combined registry (all integrations) ─────────────────────────────────────
ALL_TOOLS: list[Tool] = FALCON_TOOLS + SENTINEL_TOOLS + THREAT_INTEL_TOOLS + JIRA_TOOLS
ALL_TOOL_MAP: dict[str, Tool] = {t.name: t for t in ALL_TOOLS}
