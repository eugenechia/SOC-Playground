"""FQL templates: valid params build correct filters; hostile params are rejected.

This is the injection-control boundary — the model supplies params, never FQL.
"""
import pytest

from integrations import fql_templates as fql
from integrations.fql_templates import FqlParamError


def test_device_by_hostname_ok():
    assert fql.device_by_hostname("DESKTOP-1") == "hostname:'DESKTOP-1'"


def test_device_by_ip_ok():
    out = fql.device_by_ip("10.0.0.5")
    assert "local_ip:'10.0.0.5'" in out and "external_ip:'10.0.0.5'" in out


def test_alerts_for_host_has_timestamp_bound():
    out = fql.alerts_for_host("host1", 24)
    assert "device.hostname:'host1'" in out
    assert "created_timestamp:>'" in out


def test_alerts_for_hash_ok():
    h = "a" * 64
    out = fql.alerts_for_hash(h, 48)
    assert h in out


@pytest.mark.parametrize("bad", [
    "host'+cid:'x",          # quote break-out attempt
    "host name",             # space
    "host\n",                # trailing newline
    "'; DROP",               # junk
    "",                      # empty
])
def test_hostname_rejects_injection(bad):
    with pytest.raises(FqlParamError):
        fql.device_by_hostname(bad)


@pytest.mark.parametrize("bad", [
    "notanip",
    "10.0.0.1%eth0'+x",      # zone-id break-out
    "999.1.1.1",
])
def test_ip_rejects_bad(bad):
    with pytest.raises(FqlParamError):
        fql.device_by_ip(bad)


@pytest.mark.parametrize("bad", ["xyz", "a" * 63, "g" * 64])
def test_sha256_rejects_bad(bad):
    with pytest.raises(FqlParamError):
        fql.alerts_for_hash(bad)


@pytest.mark.parametrize("bad", [0, -1, 999, "abc"])
def test_hours_bounds(bad):
    with pytest.raises(FqlParamError):
        fql.alerts_for_host("host1", bad)
