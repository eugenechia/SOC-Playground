"""
Tiny SYNC retry helper for transient failures — no external dependency.

Copied by value from SOC-Copilot's async `integrations/retry.py` and adapted to
sync: SOC-Playground's agent loop and Falcon client run synchronously (the model
runtime is thread-based, not asyncio). Retries network errors and HTTP
429/5xx with exponential backoff; never retries other 4xx.
"""
import logging
import time

import httpx

log = logging.getLogger(__name__)

_RETRYABLE_STATUS = {429, 500, 502, 503, 504}


def _is_retryable(exc: Exception) -> bool:
    if isinstance(exc, (httpx.TimeoutException, httpx.NetworkError, httpx.RemoteProtocolError)):
        return True
    if isinstance(exc, httpx.HTTPStatusError):
        return exc.response.status_code in _RETRYABLE_STATUS
    return False


def with_retry(factory, *, attempts: int = 3, base_delay: float = 0.5, label: str = "op"):
    """Call a zero-arg callable with retries. Re-raises the last exception if all
    attempts fail or the error is not retryable."""
    last: Exception | None = None
    for attempt in range(attempts):
        try:
            return factory()
        except Exception as e:  # noqa: BLE001 — re-raised below when non-retryable
            last = e
            if not _is_retryable(e) or attempt == attempts - 1:
                raise
            delay = base_delay * (2 ** attempt) + 0.1 * attempt
            log.warning("%s failed (%s), retrying in %.1fs (attempt %d/%d)",
                        label, type(e).__name__, delay, attempt + 1, attempts)
            time.sleep(delay)
    raise last  # unreachable
