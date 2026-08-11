from unittest.mock import MagicMock, patch

from eva.config import AppConfig
from eva.providers import TextDelta, ToolCall, ToolSpec
from eva.providers.gemini_provider import GeminiProvider


def test_gemini_generate_with_tools_text_response():
    provider = GeminiProvider()
    config = AppConfig()

    mock_chunk = MagicMock()
    mock_chunk.function_calls = None
    mock_chunk.text = "Hello from Gemini!"

    mock_client = MagicMock()
    mock_client.models.generate_content_stream.return_value = [mock_chunk]

    with (
        patch("eva.providers.gemini_provider.get_api_key", return_value="fake-gemini-key"),
        patch("eva.providers.gemini_provider.genai.Client", return_value=mock_client),
    ):
        events = list(provider.generate_with_tools([{"role": "user", "content": "hi"}], [], config))

    assert len(events) == 1
    assert isinstance(events[0], TextDelta)
    assert events[0].content == "Hello from Gemini!"


def test_gemini_generate_with_tools_function_call_response():
    provider = GeminiProvider()
    config = AppConfig()

    mock_fn_call = MagicMock()
    mock_fn_call.id = "gemini_call_1"
    mock_fn_call.name = "list_directory"
    mock_fn_call.args = {"path": "src"}

    mock_chunk = MagicMock()
    mock_chunk.function_calls = [mock_fn_call]
    mock_chunk.text = None

    mock_client = MagicMock()
    mock_client.models.generate_content_stream.return_value = [mock_chunk]

    tools = [ToolSpec(name="list_directory", description="List directory", parameters={"type": "object"})]

    with (
        patch("eva.providers.gemini_provider.get_api_key", return_value="fake-gemini-key"),
        patch("eva.providers.gemini_provider.genai.Client", return_value=mock_client),
    ):
        events = list(provider.generate_with_tools([{"role": "user", "content": "list src"}], tools, config))

    assert len(events) == 1
    assert isinstance(events[0], ToolCall)
    assert events[0].call_id == "gemini_call_1"
    assert events[0].name == "list_directory"
    assert events[0].arguments == {"path": "src"}
