import httpx
import pytest

from eva.providers.retry import (
    RetryingStream,
    extract_retry_after,
    is_transient_provider_error,
    retry_provider_call,
)


def test_extract_retry_after_numeric():
    headers = {"retry-after": "5"}
    resp = httpx.Response(429, headers=headers, request=httpx.Request("POST", "https://api.test/v1"))
    err = httpx.HTTPStatusError("rate limit", request=resp.request, response=resp)
    assert extract_retry_after(err) == 5.0

    headers_float = {"retry-after": "1.5"}
    resp_f = httpx.Response(429, headers=headers_float, request=httpx.Request("POST", "https://api.test/v1"))
    err_f = httpx.HTTPStatusError("rate limit", request=resp_f.request, response=resp_f)
    assert extract_retry_after(err_f) == 1.5


def test_is_transient_provider_error():
    req = httpx.Request("POST", "https://api.test/v1")

    # 429 Rate limited -> Transient
    resp_429 = httpx.Response(429, request=req)
    assert is_transient_provider_error(httpx.HTTPStatusError("429", request=req, response=resp_429)) is True

    # 503 Service Unavailable -> Transient
    resp_503 = httpx.Response(503, request=req)
    assert is_transient_provider_error(httpx.HTTPStatusError("503", request=req, response=resp_503)) is True

    # Connection error -> Transient
    assert is_transient_provider_error(httpx.ConnectError("connection refused")) is True
    assert is_transient_provider_error(TimeoutError("timed out")) is True

    # 401 Unauthorized -> Permanent
    resp_401 = httpx.Response(401, request=req)
    assert is_transient_provider_error(httpx.HTTPStatusError("401", request=req, response=resp_401)) is False

    # 400 Bad Request -> Permanent
    resp_400 = httpx.Response(400, request=req)
    assert is_transient_provider_error(httpx.HTTPStatusError("400", request=req, response=resp_400)) is False


def test_retry_provider_call_success_after_failure():
    calls = 0

    def flaky_func():
        nonlocal calls
        calls += 1
        if calls < 2:
            req = httpx.Request("POST", "https://api.test")
            resp = httpx.Response(500, request=req)
            raise httpx.HTTPStatusError("server error", request=req, response=resp)
        return "success"

    result = retry_provider_call(flaky_func, max_attempts=3, min_wait=0.01, max_wait=0.05)
    assert result == "success"
    assert calls == 2


def test_retry_provider_call_aborts_on_permanent_error():
    calls = 0

    def failing_func():
        nonlocal calls
        calls += 1
        req = httpx.Request("POST", "https://api.test")
        resp = httpx.Response(401, request=req)
        raise httpx.HTTPStatusError("unauthorized", request=req, response=resp)

    with pytest.raises(httpx.HTTPStatusError):
        retry_provider_call(failing_func, max_attempts=4, min_wait=0.01, max_wait=0.05)

    assert calls == 1  # Should NOT retry 401


def test_retrying_stream_iteration_recovery():
    attempts = 0

    def stream_factory():
        nonlocal attempts
        attempts += 1
        if attempts < 2:
            req = httpx.Request("POST", "https://api.test")
            resp = httpx.Response(429, request=req)
            raise httpx.HTTPStatusError("rate limited", request=req, response=resp)
        yield "chunk1"
        yield "chunk2"

    stream = RetryingStream(stream_factory, max_attempts=3, min_wait=0.01, max_wait=0.05)
    chunks = list(stream)

    assert chunks == ["chunk1", "chunk2"]
    assert attempts == 2
