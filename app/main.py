"""
SOC-Playground — FastAPI entrypoint.

A single-container, single-replica app: the SSE broker, model runtime and chat
session store are all in-process singletons (never scale out without reworking
them). The lifespan hook fails fast if MODELS_DIR (the Azure Files mount in prod)
is not writable — otherwise every restart would silently re-download gigabytes
into an ephemeral container filesystem.
"""
import logging
import secrets as pysecrets
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware

from app import auth, config
from app.routes import events, health, models, scorecard, ui, workbench
from app.secrets import get_secret

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
log = logging.getLogger(__name__)


def _check_models_dir() -> None:
    config.MODELS_DIR.mkdir(parents=True, exist_ok=True)
    config.HF_HOME.mkdir(parents=True, exist_ok=True)
    probe = config.MODELS_DIR / ".write_probe"
    try:
        probe.write_text("ok")
        probe.unlink(missing_ok=True)
    except OSError as e:
        raise RuntimeError(
            f"MODELS_DIR {config.MODELS_DIR} is not writable ({e}). "
            "In Azure this must be an Azure Files mount."
        ) from e


@asynccontextmanager
async def lifespan(_: FastAPI):
    if config.DEV_AUTH_BYPASS:
        log.warning("DEV_AUTH_BYPASS is ON — the password gate is skipped. Local dev only.")
    _check_models_dir()
    from integrations import crowdstrike
    log.info("%s starting. MODELS_DIR=%s writable, tools=%s, falcon=%s",
             config.APP_NAME, config.MODELS_DIR,
             "on" if config.TOOLS_ENABLED else "off",
             "configured" if crowdstrike.configured() else "not-configured")
    yield
    crowdstrike.close_client()
    log.info("%s shut down.", config.APP_NAME)


app = FastAPI(title=config.APP_NAME, lifespan=lifespan)

# Middleware added last is outermost. SessionMiddleware (outer) must populate
# request.session before AuthMiddleware (inner) reads it.
_session_secret = get_secret("SESSION_SECRET") or pysecrets.token_hex(32)
app.add_middleware(auth.AuthMiddleware)
app.add_middleware(
    SessionMiddleware,
    secret_key=_session_secret,
    https_only=not config.DEV_AUTH_BYPASS,
    same_site="lax",
)

app.mount("/static", StaticFiles(directory=str(config.BASE_DIR / "web" / "static")), name="static")

app.include_router(auth.router)
app.include_router(health.router)
app.include_router(events.router)
app.include_router(models.router)
app.include_router(workbench.router)
app.include_router(scorecard.router)
app.include_router(ui.router)
