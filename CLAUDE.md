# SOC-Playground — Agent Instructions

## What this is

A SOC analyst **playground** for local LLMs. Analysts paste a Hugging Face model
URL, the app downloads the weights onto a persistent volume, and they experiment
with the model on SOC work (threat hunting, malware analysis) in a Workbench that
pairs a **task** (framing) with a chosen **model**. The point is hands-on
evaluation — seeing how a given local model actually performs — not production
triage. Full plan: `~/.claude/plans/i-want-to-start-whimsical-castle.md`.

## Architecture (locked)

- FastAPI + Jinja2 + HTMX + SSE, hand-rolled dark CSS. No React, no CDN deps
  (htmx.min.js is vendored in `web/static/`).
- Single container, **exactly 1 replica** — the SSE broker (`app/broker.py`), the
  model runtime (`models_engine/inference.py`) and the chat session store
  (`app/sessions.py`) are in-process singletons. Never scale out without
  reworking them.
- **Hugging Face Transformers** for CPU inference; **`huggingface_hub`** for
  downloads. One model resident in RAM at a time (`ModelRuntime`).
- **No database in Phase 1.** The model registry is derived by scanning
  `MODELS_DIR` + per-model `meta.json` (`models_engine/registry.py`); tasks are
  defined in `tasks/tasks.yaml`; chat history is in-memory and ephemeral.
- Layout: `app/` (FastAPI, routes, auth, broker, sessions) · `models_engine/`
  (download + inference + registry + tasks) · `web/` (templates + static).

## Invariants — do not violate

1. **Persistent weights only on the mount.** Model weights MUST live under
   `MODELS_DIR` (the Azure Files mount in prod), never baked into the image or
   written to the ephemeral container FS. Startup fails fast if it isn't writable.
2. **Download guardrails** (`models_engine/downloader.py`): source host allowlist
   (`huggingface.co` only), safetensors-preferred (`ALLOW_PICKLE` off blocks
   pickle weights that execute code on load), size cap (`MAX_MODEL_BYTES`).
3. **`trust_remote_code` defaults OFF** everywhere (arbitrary code execution).
4. **Secrets only via `app/secrets.py::get_secret`.** Never `os.environ` for a
   credential, never hardcoded. Only `APP_PASSWORD` and `SESSION_SECRET` today.
5. **`DEV_AUTH_BYPASS` is local-only.** Never set it on the container app.
6. **One model in RAM.** Selecting a model unloads the previous one first — CPU
   RAM cannot hold several transformers models at once.

## Isolation from SOC-Copilot

SOC-Playground is a **pattern mirror** of SOC-Copilot with **zero linkage**. It
copies SOC-Copilot code by value (`app/broker.py`, `app/secrets.py`, the SSE /
auth patterns) but shares **no** infrastructure: its own ACR, its own Container
App, its own Azure Files storage, its own Key Vault / secrets. It may live in the
same resource group but references none of SOC-Copilot's resources, env vars, or
endpoints.

## Phase-2 seam (live tools — later)

The full vision is live tool/API wiring per task (agent tool-loop). The seam is
`models_engine/tasks.py` (`Tool` Protocol + `resolve_tools`) + `tasks.yaml`
(`tools: []`). Phase 2 populates `TOOL_REGISTRY`, maps task tool ids, and turns
the single `generate_stream` call in `app/routes/workbench.py` into an agent loop
over the existing SSE contract — no route/template/registry/inference changes.
Note: small local models are unreliable at structured tool-calling, so design the
tool protocol tolerant of that (parsing/retries, few tools per task).

## Deployment

Mac Studio → Docker build → **dedicated ACR** (e.g. `socplaygroundreg`) →
**dedicated Azure Container App** `soc-playground` (own Azure Files share mounted
at `/models`, own Key Vault / Container App secrets, `min=max=1`), optionally in
`rg-soc-platform`. GitHub: `git@github.com:eugenechia/SOC-Playground.git`
(private). See `azure/containerapp.md`.
