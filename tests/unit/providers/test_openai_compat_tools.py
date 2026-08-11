from unittest.mock import MagicMock, patch

from eva.config import AppConfig
from eva.providers import TextDelta, ToolCall, ToolSpec
from eva.providers.groq_provider import GroqProvider


def test_openai_compat_generate_with_tools_text_response():
    provider = GroqProvider()
    config = AppConfig()

    mock_chunk = MagicMock()
    mock_chunk.choices = [MagicMock()]
    mock_chunk.choices[0].delta.content = "Hello there!"
    mock_chunk.choices[0].delta.tool_calls = None

    mock_client = MagicMock()
    mock_client.chat.completions.create.return_value = [mock_chunk]

    with (
        patch("eva.providers.openai_compat.get_api_key", return_value="fake-key"),
        patch("eva.providers.openai_compat.OpenAI", return_value=mock_client),
    ):
        events = list(provider.generate_with_tools([{"role": "user", "content": "hi"}], [], config))

    assert len(events) == 1
    assert isinstance(events[0], TextDelta)
    assert events[0].content == "Hello there!"


def test_openai_compat_generate_with_tools_tool_call_response():
    provider = GroqProvider()
    config = AppConfig()

    mock_tool_call_delta1 = MagicMock()
    mock_tool_call_delta1.index = 0
    mock_tool_call_delta1.id = "call_abc123"
    mock_tool_call_delta1.function.name = "read_file"
    mock_tool_call_delta1.function.arguments = '{"path": "'

    mock_tool_call_delta2 = MagicMock()
    mock_tool_call_delta2.index = 0
    mock_tool_call_delta2.id = None
    mock_tool_call_delta2.function.name = None
    mock_tool_call_delta2.function.arguments = 'src/app.py"}'

    chunk1 = MagicMock()
    chunk1.choices = [MagicMock()]
    chunk1.choices[0].delta.content = None
    chunk1.choices[0].delta.tool_calls = [mock_tool_call_delta1]

    chunk2 = MagicMock()
    chunk2.choices = [MagicMock()]
    chunk2.choices[0].delta.content = None
    chunk2.choices[0].delta.tool_calls = [mock_tool_call_delta2]

    mock_client = MagicMock()
    mock_client.chat.completions.create.return_value = [chunk1, chunk2]

    tools = [ToolSpec(name="read_file", description="Read file", parameters={"type": "object"})]

    with (
        patch("eva.providers.openai_compat.get_api_key", return_value="fake-key"),
        patch("eva.providers.openai_compat.OpenAI", return_value=mock_client),
    ):
        events = list(provider.generate_with_tools([{"role": "user", "content": "read app"}], tools, config))

    assert len(events) == 1
    assert isinstance(events[0], ToolCall)
    assert events[0].call_id == "call_abc123"
    assert events[0].name == "read_file"
    assert events[0].arguments == {"path": "src/app.py"}
