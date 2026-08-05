from unittest.mock import MagicMock, patch

import pytest

from eva.providers import (
    QuotaExhaustedError,
    call_provider,
    dispatch,
)
from eva.providers.gemini_provider import get_models as get_gemini_models


def test_call_provider_quota_exhausted(monkeypatch, mock_config):
    monkeypatch.setattr("eva.providers.check_and_increment", lambda *args, **kwargs: False)
    provider = MagicMock()
    provider.name = "groq"
    provider.max_rpm = 10
    provider.max_rpd = 100

    with pytest.raises(QuotaExhaustedError):
        list(call_provider(provider, "sys", "user", "", mock_config))


def test_dispatch_all_providers_fail(monkeypatch, mock_config):
    monkeypatch.setattr("eva.providers.check_and_increment", lambda *args, **kwargs: False)
    res = "".join(dispatch("sys", "user", "", mock_config))
    assert "[Eva Error] All available providers failed or exhausted their local budget" in res


def test_dispatch_pinned_quota_exhausted(monkeypatch, mock_config):
    monkeypatch.setattr("eva.providers.check_and_increment", lambda *args, **kwargs: False)
    res = "".join(dispatch("sys", "user", "", mock_config, pinned_provider="groq"))
    assert "[Eva Error] Local budget exhausted for groq" in res


def test_dispatch_pinned_provider_exception(monkeypatch, mock_config):
    provider = MagicMock()
    provider.name = "groq"
    provider.generate_stream.side_effect = RuntimeError("network glitch")

    with patch("eva.providers.get_provider", return_value=provider):
        monkeypatch.setattr("eva.providers.check_and_increment", lambda *args, **kwargs: True)
        res = "".join(dispatch("sys", "user", "", mock_config, pinned_provider="groq"))
        assert "[Eva Error] Pinned provider groq failed: network glitch" in res


def test_gemini_get_models_no_key(monkeypatch):
    monkeypatch.delenv("EVA_GEMINI_API_KEY", raising=False)
    with patch("eva.providers.gemini_provider.get_api_key", return_value=None):
        models = get_gemini_models()
        assert models == []
