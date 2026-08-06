from unittest.mock import MagicMock, patch

import pytest
import respx

from eva.providers import (
    AuthError,
    dispatch,
    get_provider,
)
from eva.providers.gemini_provider import GeminiProvider
from eva.providers.groq_provider import GroqProvider
from eva.providers.groq_provider import get_models as get_groq_models
from eva.providers.opencode_zen_provider import get_free_models as get_opencode_models
from eva.providers.openrouter_provider import get_free_models as get_openrouter_models


def test_get_registered_providers():
    assert get_provider("openrouter") is not None
    assert get_provider("groq") is not None
    assert get_provider("gemini") is not None
    assert get_provider("opencode_zen") is not None
    assert get_provider("nonexistent") is None


@respx.mock
def test_groq_get_models_mocked(monkeypatch):
    monkeypatch.setenv("EVA_GROQ_API_KEY", "test-key")
    respx.get("https://api.groq.com/openai/v1/models").respond(json={"data": [{"id": "llama-3.1-8b-instant"}]})

    models = get_groq_models()
    assert len(models) == 1
    assert models[0]["id"] == "llama-3.1-8b-instant"


@respx.mock
def test_openrouter_get_free_models_mocked():
    respx.get("https://openrouter.ai/api/v1/models").respond(
        json={
            "data": [
                {"id": "free-model-1", "pricing": {"prompt": "0"}},
                {"id": "paid-model-1", "pricing": {"prompt": "0.001"}},
            ]
        }
    )

    free_models = get_openrouter_models()
    assert len(free_models) == 1
    assert free_models[0]["id"] == "free-model-1"


@respx.mock
def test_opencode_zen_get_free_models_mocked():
    from eva.cache import get_cache
    from eva.providers.opencode_zen_provider import MODEL_CACHE_KEY
    with get_cache() as cache:
        cache.delete(MODEL_CACHE_KEY)

    respx.get("https://opencode.ai/zen/v1/models").respond(json={"data": [{"id": "big-pickle"}, {"id": "paid-model"}]})

    free_models = get_opencode_models()
    assert len(free_models) == 1
    assert free_models[0]["id"] == "big-pickle"



def test_gemini_provider_missing_key(monkeypatch, mock_config):
    monkeypatch.delenv("EVA_GEMINI_API_KEY", raising=False)
    with patch("eva.providers.gemini_provider.get_api_key", return_value=None):
        provider = GeminiProvider()
        with pytest.raises(AuthError):
            list(provider.generate_stream("sys", "user", "", mock_config))


def test_openai_compat_missing_key(monkeypatch, mock_config):
    monkeypatch.delenv("EVA_GROQ_API_KEY", raising=False)
    with patch("eva.providers.openai_compat.get_api_key", return_value=None):
        provider = GroqProvider()
        with pytest.raises(AuthError):
            list(provider.generate_stream("sys", "user", "", mock_config))


def test_dispatch_pinned_provider_not_found(mock_config):
    res = list(dispatch("sys", "user", "", mock_config, pinned_provider="unknown"))
    assert "Provider 'unknown' not found" in res[0]


def test_dispatch_fallback(monkeypatch, mock_config):
    # Mock budget check to pass
    monkeypatch.setattr("eva.providers.check_and_increment", lambda *args, **kwargs: True)

    fake_provider = MagicMock()
    fake_provider.name = "openrouter"
    fake_provider.generate_stream.return_value = iter(["Hello from mocked LLM"])

    with patch("eva.providers.get_provider", return_value=fake_provider):
        res = list(dispatch("sys", "user", "", mock_config))
        assert "".join(res) == "Hello from mocked LLM"
