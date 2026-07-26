"""Registry: meta round-trip, scan, get, slug safety, delete guard."""
from app import config
from models_engine import registry


def test_slug_roundtrip():
    assert registry.slug("org/name") == "org__name"
    assert registry.unslug("org__name") == "org/name"


def test_write_scan_get_delete(monkeypatch, tmp_path):
    monkeypatch.setattr(config, "MODELS_DIR", tmp_path)

    registry.write_meta(
        "acme/tiny",
        status="ready",
        size_bytes=1234,
        source_url="acme/tiny",
        has_safetensors=True,
        downloaded_at="2026-01-01T00:00:00Z",
        error=None,
    )

    infos = registry.scan()
    assert len(infos) == 1
    assert infos[0].model_id == "acme/tiny"
    assert infos[0].status == "ready"
    assert infos[0].size_bytes == 1234

    got = registry.get("acme/tiny")
    assert got is not None and got.has_safetensors is True

    registry.delete("acme/tiny")
    assert registry.get("acme/tiny") is None
    assert registry.scan() == []


def test_delete_refuses_outside_models_dir(monkeypatch, tmp_path):
    monkeypatch.setattr(config, "MODELS_DIR", tmp_path)
    # A slug that resolves outside the root must be rejected, not deleted.
    import pytest

    with pytest.raises(ValueError):
        registry.delete("..")
