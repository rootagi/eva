from unittest.mock import MagicMock, patch

import openai
import pytest
import respx

from eva.providers import AuthError, RateLimitError, ServerError, dispatch, get_provider
from eva.providers.llamacpp_provider import LlamaCppProvider, get_models as get_llamacpp_models
from eva.providers.ollama_provider import OllamaProvider, get_models as get_ollama_models


def test_ollama_provider_registered():
    provider = get_provider("ollama")
    assert provider is not None
    assert provider.name == "ollama"
    assert provider.max_rpm == 999


def test_llamacpp_provider_registered():
    provider = get_provider("llamacpp")
    assert provider is not None
    assert provider.name == "llamacpp"
    assert provider.max_rpm == 999


@respx.mock
def test_ollama_get_models_mocked():
    respx.get("http://localhost:11434/api/tags").respond(
        json={"models": [{"name": "gemma4:12b"}, {"name": "qwen2.5-coder:0.5b"}]}
    )
    models = get_ollama_models()
    assert len(models) == 2
    assert models[0]["id"] == "gemma4:12b"


@respx.mock
def test_llamacpp_get_models_mocked():
    respx.get("http://localhost:8080/v1/models").respond(
        json={"data": [{"id": "llama-3-8b-instruct.Q4_K_M.gguf"}]}
    )
    models = get_llamacpp_models()
    assert len(models) == 1
    assert models[0]["id"] == "llama-3-8b-instruct.Q4_K_M.gguf"


def test_ollama_provider_stream_success(mock_config):
    mock_chunk = MagicMock()
    mock_chunk.choices = [MagicMock()]
    mock_chunk.choices[0].delta.content = "local ollama response"

    mock_client = MagicMock()
    mock_client.chat.completions.create.return_value = [mock_chunk]

    with patch("openai.OpenAI", return_value=mock_client):
        provider = OllamaProvider()
        chunks = list(provider.generate_stream("sys", "user", "context text", mock_config))
        assert "".join(chunks) == "local ollama response"


def test_llamacpp_provider_stream_success(mock_config):
    mock_chunk = MagicMock()
    mock_chunk.choices = [MagicMock()]
    mock_chunk.choices[0].delta.content = "local llamacpp response"

    mock_client = MagicMock()
    mock_client.chat.completions.create.return_value = [mock_chunk]

    with patch("openai.OpenAI", return_value=mock_client):
        provider = LlamaCppProvider()
        chunks = list(provider.generate_stream("sys", "user", "context text", mock_config))
        assert "".join(chunks) == "local llamacpp response"


def test_ollama_provider_error_handling(mock_config):
    provider = OllamaProvider()

    with patch("openai.OpenAI") as mock_openai:
        mock_openai.return_value.chat.completions.create.side_effect = openai.AuthenticationError(
            message="auth err", response=MagicMock(status_code=401), body=None
        )
        with pytest.raises(AuthError):
            list(provider.generate_stream("sys", "user", "", mock_config))

    with patch("openai.OpenAI") as mock_openai:
        mock_openai.return_value.chat.completions.create.side_effect = openai.RateLimitError(
            message="rate limit", response=MagicMock(status_code=429), body=None
        )
        with pytest.raises(RateLimitError):
            list(provider.generate_stream("sys", "user", "", mock_config))

    with patch("openai.OpenAI") as mock_openai:
        mock_openai.return_value.chat.completions.create.side_effect = openai.APIConnectionError(
            request=MagicMock()
        )
        with pytest.raises(ServerError):
            list(provider.generate_stream("sys", "user", "", mock_config))


def test_llamacpp_provider_error_handling(mock_config):
    provider = LlamaCppProvider()

    with patch("openai.OpenAI") as mock_openai:
        mock_openai.return_value.chat.completions.create.side_effect = openai.AuthenticationError(
            message="auth err", response=MagicMock(status_code=401), body=None
        )
        with pytest.raises(AuthError):
            list(provider.generate_stream("sys", "user", "", mock_config))

    with patch("openai.OpenAI") as mock_openai:
        mock_openai.return_value.chat.completions.create.side_effect = openai.RateLimitError(
            message="rate limit", response=MagicMock(status_code=429), body=None
        )
        with pytest.raises(RateLimitError):
            list(provider.generate_stream("sys", "user", "", mock_config))

    with patch("openai.OpenAI") as mock_openai:
        mock_openai.return_value.chat.completions.create.side_effect = openai.APIConnectionError(
            request=MagicMock()
        )
        with pytest.raises(ServerError):
            list(provider.generate_stream("sys", "user", "", mock_config))


def test_offline_model_fallback_verified_with_mocked_network_failure(monkeypatch, mock_config):
    """Integration test: Offline model fallback verified with mocked network failure."""
    monkeypatch.setattr("eva.providers.check_and_increment", lambda *args, **kwargs: True)

    def mock_call_provider(provider, system_prompt, user_prompt, context, config):
        if provider.name in {"openrouter", "groq", "gemini", "opencode_zen"}:
            raise ServerError(f"Cloud provider {provider.name} network unreachable (mocked failure)")
        if provider.name == "ollama":
            yield "Offline fallback response from Ollama!"

    with patch("eva.providers.call_provider", side_effect=mock_call_provider):
        stream = dispatch("sys", "user", "", mock_config)
        output = "".join(stream)
        assert output == "Offline fallback response from Ollama!"
