"""
Test setup. These env vars must be set BEFORE app.config is imported, because
config parses os.environ once at import time.
"""
import os
import tempfile

os.environ.setdefault("MODELS_DIR", tempfile.mkdtemp(prefix="soc-play-models-"))
os.environ["HF_HOME"] = os.path.join(os.environ["MODELS_DIR"], ".hf_cache")
os.environ["APP_PASSWORD"] = "test-password"
os.environ["SESSION_SECRET"] = "test-secret"
# Keep the password gate ON so the auth test is meaningful.
os.environ.pop("DEV_AUTH_BYPASS", None)
