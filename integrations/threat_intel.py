"""
External IOC reputation — VirusTotal + AbuseIPDB. READ-ONLY, SYNC.

Copied by value from SOC-Copilot and adapted to sync httpx. A fixed lookup keyed
by a validated IOC (never a free-form request). FAIL-OPEN: any missing key,
timeout or API error yields verdict "unknown". "unknown" NEVER means benign.

Keys (via app.secrets.get_secret; absent = that source contributes nothing):
  VT_API_KEY, ABUSEIPDB_API_KEY
"""
import ipaddress
import logging
import re

import httpx

from app.secrets import get_secret

log = logging.getLogger(__name__)

_VT_BASE = "https://www.virustotal.com/api/v3"
_ABUSE_BASE = "https://api.abuseipdb.com/api/v2"
_TIMEOUT = 15.0

_HASH_RE = re.compile(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$")
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-zA-Z0-9_](?:[a-zA-Z0-9_-]{0,61}[a-zA-Z0-9_])?\.)+[a-zA-Z]{2,}$")


def infer_type(value: str) -> str | None:
    v = (value or "").strip()
    try:
        ipaddress.ip_address(v)
        return "ip"
    except ValueError:
        pass
    if _HASH_RE.match(v):
        return "hash"
    if _DOMAIN_RE.match(v):
        return "domain"
    return None


def _is_private_ip(value: str) -> bool:
    try:
        return not ipaddress.ip_address(value).is_global
    except ValueError:
        return False


def _virustotal(client: httpx.Client, value: str, ioc_type: str) -> dict | None:
    key = get_secret("VT_API_KEY")
    if not key:
        return None
    endpoint = {"ip": f"ip_addresses/{value}", "domain": f"domains/{value}",
                "hash": f"files/{value}"}.get(ioc_type)
    if not endpoint:
        return None
    try:
        r = client.get(f"{_VT_BASE}/{endpoint}",
                       headers={"x-apikey": key, "Accept": "application/json"})
        if r.status_code == 404:
            return {"malicious_count": 0, "total_engines": 0, "reputation": 0}
        if r.status_code >= 400:
            log.warning("VirusTotal %s HTTP %s: %s", endpoint, r.status_code, r.text[:180])
            return None
        attrs = (r.json().get("data") or {}).get("attributes") or {}
        stats = attrs.get("last_analysis_stats") or {}
        out = {
            "malicious_count": int(stats.get("malicious", 0)),
            "total_engines": sum(int(v) for v in stats.values()) if stats else 0,
            "reputation": int(attrs.get("reputation", 0) or 0),
        }
        if ioc_type == "ip":
            out["country"] = (attrs.get("country") or "").strip()
            out["as_owner"] = (attrs.get("as_owner") or "").strip()
        return out
    except Exception as e:  # noqa: BLE001 — fail-open
        log.warning("VirusTotal check failed for %s (%s): %s", value, type(e).__name__, e)
        return None


def _abuseipdb(client: httpx.Client, ip: str) -> dict | None:
    key = get_secret("ABUSEIPDB_API_KEY")
    if not key:
        return None
    try:
        r = client.get(f"{_ABUSE_BASE}/check",
                       headers={"Key": key, "Accept": "application/json"},
                       params={"ipAddress": ip, "maxAgeInDays": 90})
        if r.status_code >= 400:
            log.warning("AbuseIPDB %s HTTP %s: %s", ip, r.status_code, r.text[:180])
            return None
        d = r.json().get("data") or {}
        return {
            "confidence_score": int(d.get("abuseConfidenceScore", 0)),
            "total_reports": int(d.get("totalReports", 0)),
            "country_code": (d.get("countryCode") or "").strip(),
            "isp": (d.get("isp") or "").strip(),
            "usage_type": (d.get("usageType") or "").strip(),
            "domain": (d.get("domain") or "").strip(),
        }
    except Exception as e:  # noqa: BLE001 — fail-open
        log.warning("AbuseIPDB check failed for %s (%s): %s", ip, type(e).__name__, e)
        return None


def check_reputation(value: str, ioc_type: str | None = None) -> dict:
    """Look up external reputation for one IOC. verdict is one of
    malicious | clean | unknown (unknown NEVER implies benign)."""
    value = (value or "").strip()
    ioc_type = ioc_type or infer_type(value)
    if not ioc_type:
        return {"value": value, "verdict": "unknown", "reasons": [],
                "note": "unrecognised IOC format — not an IP, hash or domain", "sources": {}}
    if ioc_type == "ip" and _is_private_ip(value):
        return {"value": value, "ioc_type": ioc_type, "verdict": "unknown", "reasons": [],
                "note": "private/internal IP — external reputation not applicable", "sources": {}}

    with httpx.Client(timeout=_TIMEOUT) as client:
        vt = _virustotal(client, value, ioc_type)
        abuse = _abuseipdb(client, value) if ioc_type == "ip" else None

    reasons: list[str] = []
    if vt and vt.get("malicious_count", 0) > 0:
        reasons.append(f"VirusTotal: {vt['malicious_count']}/{vt['total_engines']} engines flagged malicious")
    if abuse and abuse.get("confidence_score", 0) > 50:
        reasons.append(f"AbuseIPDB: {abuse['confidence_score']}% abuse confidence "
                       f"({abuse['total_reports']} reports)")

    all_none = vt is None and abuse is None
    verdict = "malicious" if reasons else ("unknown" if all_none else "clean")
    return {
        "value": value, "ioc_type": ioc_type, "verdict": verdict, "reasons": reasons,
        "sources": {"virustotal": vt, "abuseipdb": abuse},
        "note": ("no external source returned data — treat as UNKNOWN, not benign"
                 if all_none else None),
    }


def configured() -> bool:
    """True if at least one reputation source has a key."""
    return bool(get_secret("VT_API_KEY") or get_secret("ABUSEIPDB_API_KEY"))
