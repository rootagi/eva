from unittest.mock import MagicMock, patch

import openai
import pytest
from google.genai import errors

from eva.providers import AuthError, RateLimitError, ServerError
from eva.providers.gemini_provider import GeminiProvider
from eva.providers.groq_provider import GroqProvider


def test_openai_compat_stream_success(mock_config):
    mock_chunk = MagicMock()
    mock_chunk.choices = [MagicMock()]
    mock_chunk.choices[0].delta.content = "openai chunk"

    mock_client = MagicMock()
    mock_client.chat.completions.create.return_value = [mock_chunk]

    with (
        patch("eva.providers.openai_compat.OpenAI", return_value=mock_client),
        patch("eva.providers.openai_compat.get_api_key", return_value="fake_key"),
    ):
        provider = GroqProvider()
        chunks = list(provider.generate_stream("sys", "user", "ctx", mock_config))
        assert "".join(chunks) == "openai chunk"


def test_openai_compat_errors(mock_config):
    with patch("eva.providers.openai_compat.get_api_key", return_value="fake_key"):
        provider = GroqProvider()

        # Auth error
        with patch("eva.providers.openai_compat.OpenAI") as mock_openai:
            mock_openai.return_value.chat.completions.create.side_effect = openai.AuthenticationError(
                message="bad key", response=MagicMock(status_code=401), body=None
            )
            with pytest.raises(AuthError):
                list(provider.generate_stream("sys", "user", "", mock_config))

        # Rate limit error
        with patch("eva.providers.openai_compat.OpenAI") as mock_openai:
            mock_openai.return_value.chat.completions.create.side_effect = openai.RateLimitError(
                message="rate limit", response=MagicMock(status_code=429), body=None
            )
            with pytest.raises(RateLimitError):
                list(provider.generate_stream("sys", "user", "", mock_config))

        # Server error 502
        with patch("eva.providers.openai_compat.OpenAI") as mock_openai:
            mock_openai.return_value.chat.completions.create.side_effect = openai.APIStatusError(
                message="502 error", response=MagicMock(status_code=502), body=None
            )
            with pytest.raises(ServerError):
                list(provider.generate_stream("sys", "user", "", mock_config))


def test_gemini_errors(mock_config):
    with patch("eva.providers.gemini_provider.get_api_key", return_value="fake_key"):
        provider = GeminiProvider()

        with patch("google.genai.Client") as mock_client:
            mock_client.return_value.models.generate_content_stream.side_effect = errors.APIError(
                401, {"message": "unauthorized"}
            )
            with pytest.raises(AuthError):
                list(provider.generate_stream("sys", "user", "", mock_config))

        with patch("google.genai.Client") as mock_client:
            mock_client.return_value.models.generate_content_stream.side_effect = errors.APIError(
                429, {"message": "rate limit"}
            )
            with pytest.raises(RateLimitError):
                list(provider.generate_stream("sys", "user", "", mock_config))

        with patch("google.genai.Client") as mock_client:
            mock_client.return_value.models.generate_content_stream.side_effect = errors.APIError(
                502, {"message": "bad gateway"}
            )
            with pytest.raises(ServerError):
                list(provider.generate_stream("sys", "user", "", mock_config))
