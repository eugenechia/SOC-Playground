"""
Non-secret configuration, parsed once at import from the environment.

The rule (mirrors SOC-Copilot invariant #5): NEVER read os.environ for a
credential here. Credentials live in app/secrets.py::get_secret. This module
holds only non-sensitive knobs, so it is safe to log any value in it.

All model weights live under MODELS_DIR, which on Azure is an Azure Files SMB
mount — the container filesystem is ephemeral and would otherwise re-download
gigabytes on every restart.
"""
import os
from pathlib import Path

APP_NAME = "SOC-Playground"

# ── Persistent model storage (Azure Files mount in prod) ─────────────
MODELS_DIR = Path(os.environ.get("MODELS_DIR", "/models")).resolve()
# Keep the Hugging Face cache under MODELS_DIR so it persists on the same mount.
HF_HOME = Path(os.environ.get("HF_HOME", str(MODELS_DIR / ".hf_cache"))).resolve()

# ── Download guardrails ──────────────────────────────────────────────
# Only repos on these hosts may be downloaded (SSRF / arbitrary-source guard).
ALLOWED_DOWNLOAD_HOSTS = frozenset({"huggingface.co"})
# Custom modeling code (trust_remote_code) is arbitrary code execution — off.
TRUST_REMOTE_CODE = os.environ.get("TRUST_REMOTE_CODE", "") == "1"
# When False, the downloader restricts patterns to safetensors/config/tokenizer
# and refuses pickle-format weights (*.bin/*.pt/*.pkl can execute code on load).
ALLOW_PICKLE = os.environ.get("ALLOW_PICKLE", "") == "1"
# Abuse guard on total snapshot size (default 8 GiB).
MAX_MODEL_BYTES = int(os.environ.get("MAX_MODEL_BYTES", str(8 * 1024 ** 3)))

# ── Inference bounds ─────────────────────────────────────────────────
MAX_NEW_TOKENS = int(os.environ.get("MAX_NEW_TOKENS", "512"))
# Advisory RAM ceiling for the UI warning; float32 ≈ 4 bytes/param.
RAM_WARN_PARAM_BILLIONS = float(os.environ.get("RAM_WARN_PARAM_BILLIONS", "1.5"))

# ── Phase 2: agent tool loop ─────────────────────────────────────────
# Fail-closed killswitch. When off, tasks with tools fall back to plain chat.
TOOLS_ENABLED = os.environ.get("TOOLS_ENABLED", "1") == "1"
AGENT_MAX_STEPS = int(os.environ.get("AGENT_MAX_STEPS", "6"))
AGENT_TIMEOUT_SECONDS = int(os.environ.get("AGENT_TIMEOUT_SECONDS", "300"))
# Per-step generation cap (tool-call turns are short; keep it tight).
AGENT_STEP_MAX_NEW_TOKENS = int(os.environ.get("AGENT_STEP_MAX_NEW_TOKENS", "400"))

# ── CrowdStrike Falcon (non-secret; creds via app.secrets.get_secret) ─
CROWDSTRIKE_BASE_URL = os.environ.get("CROWDSTRIKE_BASE_URL", "https://api.crowdstrike.com")

# ── Tasks ────────────────────────────────────────────────────────────
BASE_DIR = Path(__file__).resolve().parent.parent
TASKS_FILE = Path(os.environ.get("TASKS_FILE", str(BASE_DIR / "tasks" / "tasks.yaml")))

# ── Skill Library ────────────────────────────────────────────────────
# Browsable reference library of framework-mapped cybersecurity SOPs, fetched
# live from the open-source Anthropic-Cybersecurity-Skills repo (Apache-2.0) and
# cached in-process. Read-only; no model involvement. Fail-closed killswitch.
SKILLS_LIBRARY_ENABLED = os.environ.get("SKILLS_LIBRARY_ENABLED", "1") == "1"
# Raw base is the GitHub raw root for the repo at a pinned ref; the app only ever
# fetches `index.json` and `skills/<slug>/SKILL.md` under it (slug gated to the
# index — no arbitrary URL fetch).
SKILLS_REPO_RAW_BASE = os.environ.get(
    "SKILLS_REPO_RAW_BASE",
    "https://raw.githubusercontent.com/mukul975/Anthropic-Cybersecurity-Skills/main",
).rstrip("/")
# Human-facing source repo (attribution link on the pages).
SKILLS_REPO_HTML_BASE = os.environ.get(
    "SKILLS_REPO_HTML_BASE",
    "https://github.com/mukul975/Anthropic-Cybersecurity-Skills",
).rstrip("/")
SKILLS_CACHE_TTL_SECONDS = int(os.environ.get("SKILLS_CACHE_TTL_SECONDS", str(6 * 3600)))
SKILLS_HTTP_TIMEOUT = int(os.environ.get("SKILLS_HTTP_TIMEOUT", "20"))

# ── Local development ────────────────────────────────────────────────
# Skip the password gate with a synthetic session. NEVER set in Azure.
DEV_AUTH_BYPASS = os.environ.get("DEV_AUTH_BYPASS", "") == "1"
