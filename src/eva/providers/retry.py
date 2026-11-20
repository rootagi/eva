from __future__ import annotations

import email.utils
import logging
import time
from collections.abc import Iterator
from typing import Any

import tenacity

logger = logging.getLogger(__name__)


def extract_retry_after(exc: BaseException | None) -> float | None:
    """Extract Retry-After duration in seconds from an exception or response headers."""
    if exc is None:
        return None

    # Check direct attribute
    if hasattr(exc, "retry_after") and isinstance(exc.retry_after, (int, float)):
        return float(exc.retry_after)

    # Check response headers (openai.APIStatusError, httpx.HTTPStatusError, etc.)
    response = getattr(exc, "response", None)
    if response is not None and hasattr(response, "headers"):
        headers = response.headers
        val = headers.get("retry-after") or headers.get("Retry-After")
        if val:
            val_str = str(val).strip()
            try:
                return float(val_str)
            except ValueError:
                pass
            try:
                parsed = email.utils.parsedate_to_datetime(val_str)
                delta = parsed.timestamp() - time.time()
                return max(delta, 0.0)
            except (ValueError, TypeError, OverflowError):
                pass
    return None


def is_transient_provider_error(exc: BaseException) -> bool:
    """Determine whether an exception represents a transient retryable error."""
    from eva.providers import AuthError, QuotaExhaustedError, RateLimitError, ServerError

    if isinstance(exc, (AuthError, QuotaExhaustedError)):
        return False

    status_code = getattr(exc, "status_code", None)
    if status_code is None:
        response = getattr(exc, "response", None)
        if response is not None and hasattr(response, "status_code"):
            status_code = response.status_code

    if status_code is not None:
        if status_code in (429, 500, 502, 503, 504):
            return True
        if 400 <= status_code < 500:
            return False

    code = getattr(exc, "code", None)
    if isinstance(code, int):
        if code in (429, 500, 502, 503, 504):
            return True
        if 400 <= code < 500:
            return False

    if isinstance(exc, (RateLimitError, ServerError, TimeoutError, ConnectionError)):
        return True

    try:
        import httpx

        if isinstance(
            exc,
            (
                httpx.TimeoutException,
                httpx.NetworkError,
                httpx.ConnectError,
                httpx.ReadTimeout,
                httpx.WriteTimeout,
                httpx.PoolTimeout,
            ),
        ):
            return True
    except ImportError:
        pass

    type_name = type(exc).__name__
    if type_name in (
        "RateLimitError",
        "ServerError",
        "APIConnectionError",
        "APITimeoutError",
        "InternalServerError",
        "ServiceUnavailableError",
        "BadGatewayError",
        "GatewayTimeoutError",
        "ConnectTimeout",
        "ReadTimeout",
        "WriteTimeout",
        "PoolTimeout",
        "NetworkError",
    ):
        return True

    if type_name in (
        "AuthenticationError",
        "PermissionDeniedError",
        "BadRequestError",
        "NotFoundError",
        "UnprocessableEntityError",
    ):
        return False

    return False


class wait_retry_after_or_exponential(tenacity.wait.wait_base):
    """Wait strategy that prefers Retry-After headers, falling back to exponential jitter."""

    def __init__(self, min_wait: float = 1.0, max_wait: float = 30.0):
        self.min_wait = min_wait
        self.max_wait = max_wait
        self.fallback = tenacity.wait_random_exponential(min=min_wait, max=max_wait)

    def __call__(self, retry_state: tenacity.RetryCallState) -> float:
        if retry_state.outcome and retry_state.outcome.failed:
            exc = retry_state.outcome.exception()
            ra = extract_retry_after(exc)
            if ra is not None and ra > 0:
                return min(max(ra, self.min_wait), self.max_wait)
        return float(self.fallback(retry_state))


class RetryingStream:
    """Wrapper that retries a generator function upon initiation failure using tenacity."""

    def __init__(
        self,
        func: Any,
        *args: Any,
        max_attempts: int = 5,
        min_wait: float = 1.0,
        max_wait: float = 30.0,
        **kwargs: Any,
    ):
        self.func = func
        self.args = args
        self.kwargs = kwargs
        self.max_attempts = max_attempts
        self.min_wait = min_wait
        self.max_wait = max_wait

    def __iter__(self) -> Iterator[Any]:
        retryer = tenacity.Retrying(
            stop=tenacity.stop_after_attempt(self.max_attempts),
            wait=wait_retry_after_or_exponential(min_wait=self.min_wait, max_wait=self.max_wait),
            retry=tenacity.retry_if_exception(is_transient_provider_error),
            reraise=True,
        )

        attempt_gen = None
        first_item = None
        has_first = False

        for attempt in retryer:
            with attempt:
                attempt_gen = iter(self.func(*self.args, **self.kwargs))
                try:
                    first_item = next(attempt_gen)
                    has_first = True
                except StopIteration:
                    has_first = False
                    return

        if has_first:
            yield first_item
            if attempt_gen is not None:
                yield from attempt_gen


def retry_provider_call(
    func: Any,
    *args: Any,
    max_attempts: int = 5,
    min_wait: float = 1.0,
    max_wait: float = 30.0,
    **kwargs: Any,
) -> Any:
    """Execute a callable with tenacity capped jittered retries for transient errors."""
    retryer = tenacity.Retrying(
        stop=tenacity.stop_after_attempt(max_attempts),
        wait=wait_retry_after_or_exponential(min_wait=min_wait, max_wait=max_wait),
        retry=tenacity.retry_if_exception(is_transient_provider_error),
        reraise=True,
    )
    for attempt in retryer:
        with attempt:
            res = func(*args, **kwargs)
            if hasattr(res, "__next__") and hasattr(res, "__iter__"):
                return res
            return res
