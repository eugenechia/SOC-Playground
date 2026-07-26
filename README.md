# SOC-Playground

A SOC analyst playground for **local** LLMs. Download a Hugging Face model into
the container, then experiment with it on SOC tasks (threat hunting, malware
analysis) — token-streamed, entirely on local weights.

Two screens:

- **Models** — paste a Hugging Face URL/id (e.g. `HuggingFaceTB/SmolLM-360M-Instruct`),
  watch it download with a live progress bar, list/delete downloaded models.
- **Workbench** — pick a **task** (framing) + a downloaded **model**, then chat.

Built on FastAPI + Jinja2 + HTMX + SSE, Hugging Face Transformers (CPU), single
container / single replica. It is a **pattern mirror** of SOC-Copilot with zero
shared infrastructure. See `CLAUDE.md` for the locked architecture and
`azure/containerapp.md` for deployment.

## Run locally

```bash
cp .env.example .env          # DEV_AUTH_BYPASS=1 is set for no-login local dev
docker compose up --build
```

Open http://localhost:8200 → you land on **Models** (login is bypassed in dev).

1. Paste `HuggingFaceTB/SmolLM-360M-Instruct` (small, safetensors, has a chat
   template) and click **Download**. The progress bar advances over SSE; the
   card flips to `ready`.
2. `docker compose restart app` — the model still lists (served from the `models`
   volume, not re-downloaded). This is the persistence guarantee.
3. Go to **Workbench**, pick *CrowdStrike Falcon* + the model, send a prompt.
   The reply streams token-by-token.

## Guardrails

- Downloads are restricted to `huggingface.co`.
- Only **safetensors** weights are pulled by default; pickle formats (`*.bin`,
  `*.pt`) are blocked because they can execute code on load. Override per-model
  with `ALLOW_PICKLE=1` only for a model you trust.
- `trust_remote_code` is **off** by default.
- One model is held in RAM at a time. On CPU, float32 ≈ 4 bytes/param
  (350M ≈ 1.4 GB, 1.3B ≈ 5 GB, 3B ≈ 12 GB) — stick to ≤ ~1.3B unless the replica
  has plenty of memory.

## Tests

```bash
pip install -r requirements.txt
pytest tests/          # registry, download guards, tasks, auth
```

## Configuration

All non-secret knobs are in `app/config.py` (env-driven, safe to log). Secrets
(`APP_PASSWORD`, `SESSION_SECRET`) resolve through `app/secrets.py`
(env → Key Vault). See `.env.example`.
