"""
Fixed, parameterized FQL (Falcon Query Language) templates — the ONLY way the
model touches the CrowdStrike API. Copied by value from SOC-Copilot.

Security model: the model picks a named tool and supplies typed, validated
parameters; it can NEVER compose FQL. Validation is allow-list and fail-closed.
FQL documents no escape sequence for quotes inside single-quoted values, so we
never escape — anything outside the allowed charset is rejected with
FqlParamError. A fully attacker-/model-controlled parameter cannot terminate the
quoted value, add operators, or change which fields are filtered.
"""
import ipaddress
import re
from datetime import datetime, timedelta, timezone

_MAX_HOURS = 168  # 7 days

# Alerts-v2 behavior field carrying the SHA256 of the triggering file.
# UNCONFIRMED against a live tenant; verify at first live run and fix HERE.
BEHAVIOR_HASH_FIELD = "behaviors.sha256"

_HOSTNAME_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,251}[A-Za-z0-9])?$")
_SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")


class FqlParamError(ValueError):
    """A template parameter failed validation. The model sees this as a tool
    error and must correct the parameter — it can never bypass it."""


def _hostname(s) -> str:
    # fullmatch, not match: re's $ anchor matches before a single trailing
    # newline, so match() would accept "host\n" and leak it into the FQL value.
    if not isinstance(s, str) or not _HOSTNAME_RE.fullmatch(s or ""):
        raise FqlParamError(
            "hostname must be 1-253 chars of letters/digits/._- and cannot "
            "start or end with a separator")
    return s


def _ip(s) -> str:
    if not isinstance(s, str):
        raise FqlParamError("ip must be a string")
    # Reject RFC 4007 zone suffixes outright: their charset is unrestricted and
    # could break out of the quoted FQL value.
    if "%" in s:
        raise FqlParamError("IP zone identifiers are not allowed")
    try:
        ipaddress.ip_address(s)
    except ValueError:
        raise FqlParamError("value is not a valid IP address")
    return s


def _sha256(s) -> str:
    if not isinstance(s, str) or not _SHA256_RE.fullmatch((s or "").strip()):
        raise FqlParamError("value is not a 64-hex-char SHA256")
    return s.strip().lower()


def _hours(h) -> int:
    try:
        h = int(h)
    except (TypeError, ValueError):
        raise FqlParamError("hours must be an integer")
    if h < 1 or h > _MAX_HOURS:
        raise FqlParamError(f"hours must be between 1 and {_MAX_HOURS}")
    return h


def _since(hours: int) -> str:
    ts = datetime.now(timezone.utc) - timedelta(hours=hours)
    return ts.strftime("%Y-%m-%dT%H:%M:%SZ")


# ─── Templates ────────────────────────────────────────────────────────────────
def device_by_hostname(hostname: str) -> str:
    return f"hostname:'{_hostname(hostname)}'"


def device_by_ip(ip: str) -> str:
    v = _ip(ip)
    return f"local_ip:'{v}',external_ip:'{v}'"   # , is FQL OR


def alerts_for_host(hostname: str, hours: int = 24) -> str:
    h = _hours(hours)
    return (f"device.hostname:'{_hostname(hostname)}'"
            f"+created_timestamp:>'{_since(h)}'")


def alerts_for_hash(sha256: str, hours: int = 168) -> str:
    h = _hours(hours)
    return (f"{BEHAVIOR_HASH_FIELD}:'{_sha256(sha256)}'"
            f"+created_timestamp:>'{_since(h)}'")
