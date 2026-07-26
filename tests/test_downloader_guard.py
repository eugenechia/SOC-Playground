"""Downloader security guards — source validation and pickle exclusion.

These tests never hit the network: validate_source and the pattern list are
pure. Actual downloads are exercised in the end-to-end verification, not here.
"""
import pytest

from models_engine import downloader


@pytest.mark.parametrize("src,expected", [
    ("org/name", "org/name"),
    ("HuggingFaceTB/SmolLM-360M-Instruct", "HuggingFaceTB/SmolLM-360M-Instruct"),
    ("https://huggingface.co/org/name", "org/name"),
    ("https://huggingface.co/org/name/tree/main", "org/name"),
    ("huggingface.co/org/name", "org/name"),
])
def test_validate_source_accepts_hf(src, expected):
    assert downloader.validate_source(src) == expected


@pytest.mark.parametrize("src", [
    "",
    "not-a-repo",                                  # missing org/name
    "https://evil.com/org/name",                   # wrong host
    "http://huggingface.co/org/name",              # non-https
    "../etc/passwd",                               # traversal
    "org/name/../../x",                            # traversal in id
])
def test_validate_source_rejects_bad(src):
    with pytest.raises(downloader.DownloadError):
        downloader.validate_source(src)


def test_safe_patterns_exclude_pickles():
    # The default (ALLOW_PICKLE off) pattern set must never admit code-executing
    # weight formats.
    for bad in ["model.bin", "weights.pt", "arch.pkl", "pytorch_model.bin"]:
        assert not downloader._matches_any(bad, downloader.SAFE_PATTERNS)
    # ...and must admit safetensors + the config/tokenizer files we need.
    for good in ["model.safetensors", "config.json", "tokenizer.json", "tokenizer.model"]:
        assert downloader._matches_any(good, downloader.SAFE_PATTERNS)
