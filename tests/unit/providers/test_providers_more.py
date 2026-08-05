from unittest.mock import MagicMock, patch

from eva.providers.gemini_provider import GeminiProvider
from eva.providers.opencode_zen_provider import OpenCodeZenProvider
from eva.providers.openrouter_provider import OpenRouterProvider


def test_gemini_provider_generate_stream_success(mock_config):
    mock_client = MagicMock()
    mock_chunk = MagicMock()
    mock_chunk.text = "Gemini response stream"
    mock_client.models.generate_content_stream.return_value = [mock_chunk]

    with (
        patch("google.genai.Client", return_value=mock_client),
        patch("eva.providers.gemini_provider.get_api_key", return_value="fake_key"),
    ):
        provider = GeminiProvider()
        output = list(provider.generate_stream("sys", "user", "context text", mock_config))
        assert "".join(output) == "Gemini response stream"


def test_openrouter_resolve_model_fallback(mock_config):
    provider = OpenRouterProvider()
    with patch("eva.providers.openrouter_provider.get_free_models", return_value=[]):
        resolved = provider._resolve_model("openrouter/free")
        assert resolved == "openrouter/auto"


def test_opencode_zen_resolve_model_fallback(mock_config):
    provider = OpenCodeZenProvider()
    with patch("eva.providers.opencode_zen_provider.get_free_models", return_value=[{"id": "free-1"}]):
        resolved = provider._resolve_model("custom-model")
        assert resolved == "free-1"
