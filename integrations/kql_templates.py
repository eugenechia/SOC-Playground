"""
Fixed, parameterized KQL templates — the ONLY way an agent touches Sentinel.

Why templates and not free-form LLM KQL (v1 decision): alert content is
attacker-influenced text sitting in the agent's prompt. Free-form query
generation would let a prompt-injection payload steer queries into arbitrary
tables or blow the cost/context budget. Here the agent may only pick a named
template and supply typed, validated parameters. Every value is escaped as a
KQL string literal, every query is row-capped, and the time window is bounded
server-side via the API timespan. Even a fully attacker-controlled parameter
cannot change which table is queried or inject a second statement.

Each template returns (query, timespan). The Investigation Agent's tools call
these, then sentinel.run_kql executes them.
"""
import ipaddress
import re

_TAKE = 200
_MAX_HOURS = 168  # 7 days


class KqlParamError(ValueError):
    """Raised when a template parameter fails validation. The agent sees this
    as a tool error and must correct the parameter — it can never bypass it."""


def _hours(h) -> int:
    try:
        h = int(h)
    except (TypeError, ValueError):
        raise KqlParamError("hours must be an integer")
    if h < 1 or h > _MAX_HOURS:
        raise KqlParamError(f"hours must be between 1 and {_MAX_HOURS}")
    return h


def _timespan(h: int) -> str:
    return f"PT{h}H"  # ISO-8601 duration; bounds the query server-side.


def _kql_str(s: str, *, field: str) -> str:
    """Escape a value as a safe KQL double-quoted string literal. Rejects
    control characters outright; escapes backslash and quote. The result can
    only ever be a single string literal — it cannot terminate the string and
    append KQL."""
    if not isinstance(s, str) or not s.strip():
        raise KqlParamError(f"{field} must be a non-empty string")
    if any(ord(c) < 0x20 for c in s):
        raise KqlParamError(f"{field} contains control characters")
    if len(s) > 512:
        raise KqlParamError(f"{field} is too long")
    escaped = s.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def _ip(s: str) -> str:
    try:
        ipaddress.ip_address(s)
    except ValueError:
        raise KqlParamError("value is not a valid IP address")
    return f'"{s}"'  # already validated to be an IP; no escaping needed


_HASH_RE = re.compile(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$")


def _hash(s: str) -> str:
    if not isinstance(s, str) or not _HASH_RE.match(s.strip()):
        raise KqlParamError("value is not an MD5/SHA1/SHA256 hex hash")
    return f'"{s.strip().lower()}"'


# ─── Templates ────────────────────────────────────────────────────────────────
# Each returns (query, timespan). Tables are fixed; only literals vary. Missing
# tables degrade to [] in sentinel.run_kql, so a workspace lacking a table just
# yields no evidence for that lens.

def signin_events_for_account(upn: str, hours: int = 72) -> tuple[str, str]:
    h = _hours(hours)
    u = _kql_str(upn, field="upn")
    q = f"""SigninLogs
| where UserPrincipalName =~ {u}
| project TimeGenerated, UserPrincipalName, IPAddress, AppDisplayName,
          ResultType, ResultDescription,
          City = tostring(LocationDetails.city),
          Country = tostring(LocationDetails.countryOrRegion)
| order by TimeGenerated desc
| take {_TAKE}"""
    return q, _timespan(h)


def processes_on_host(hostname: str, hours: int = 72) -> tuple[str, str]:
    h = _hours(hours)
    host = _kql_str(hostname, field="hostname")
    q = f"""DeviceProcessEvents
| where DeviceName =~ {host}
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, SHA256
| order by TimeGenerated desc
| take {_TAKE}"""
    return q, _timespan(h)


def network_connections_for_ip(ip: str, hours: int = 72) -> tuple[str, str]:
    h = _hours(hours)
    addr = _ip(ip)
    q = f"""DeviceNetworkEvents
| where RemoteIP == {addr}
| project TimeGenerated, DeviceName, RemoteIP, RemotePort, RemoteUrl,
          ActionType, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated desc
| take {_TAKE}"""
    return q, _timespan(h)


def security_alerts_for_entity(value: str, hours: int = 168) -> tuple[str, str]:
    h = _hours(hours)
    v = _kql_str(value, field="value")
    q = f"""SecurityAlert
| where Entities has {v} or ExtendedProperties has {v}
| project TimeGenerated, AlertName, AlertSeverity, Description,
          Status, ProviderName
| order by TimeGenerated desc
| take {_TAKE}"""
    return q, _timespan(h)


def device_events_for_hash(sha: str, hours: int = 168) -> tuple[str, str]:
    h = _hours(hours)
    hv = _hash(sha)
    q = f"""DeviceFileEvents
| where SHA256 == {hv} or SHA1 == {hv} or MD5 == {hv}
| project TimeGenerated, DeviceName, FileName, FolderPath, ActionType,
          InitiatingProcessAccountName, SHA256
| order by TimeGenerated desc
| take {_TAKE}"""
    return q, _timespan(h)


# Registry: template name → (callable, human description). The agent's tools are
# generated from this so adding a template is a one-line change here + one tool.
TEMPLATES = {
    "signin_events_for_account": signin_events_for_account,
    "processes_on_host": processes_on_host,
    "network_connections_for_ip": network_connections_for_ip,
    "security_alerts_for_entity": security_alerts_for_entity,
    "device_events_for_hash": device_events_for_hash,
}
