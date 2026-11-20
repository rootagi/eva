from unittest.mock import MagicMock, patch

import pytest

from eva.config import AppConfig
from eva.providers import TextDelta, ToolCall, ToolSpec
from eva.providers.gemini_provider import GeminiProvider, format_gemini_contents


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


def test_gemini_multiturn_loop_tool_transcript():
    """Verify 3-turn multi-turn conversation with assistant tool_calls and role=='tool'."""
    provider = GeminiProvider()
    config = AppConfig()

    mock_chunk = MagicMock()
    mock_chunk.function_calls = None
    mock_chunk.text = "Files found: cache.py"

    mock_client = MagicMock()
    mock_client.models.generate_content_stream.return_value = [mock_chunk]

    messages = [
        {"role": "user", "content": "find files"},
        {
            "role": "assistant",
            "content": None,
            "tool_calls": [
                {
                    "id": "call_abc123",
                    "type": "function",
                    "function": {"name": "list_directory", "arguments": '{"path": "src"}'},
                }
            ],
        },
        {
            "role": "tool",
            "tool_call_id": "call_abc123",
            "name": "list_directory",
            "content": "cache.py\nproviders.py",
        },
    ]

    with (
        patch("eva.providers.gemini_provider.get_api_key", return_value="fake-gemini-key"),
        patch("eva.providers.gemini_provider.genai.Client", return_value=mock_client),
    ):
        events = list(provider.generate_with_tools(messages, [], config))

    assert len(events) == 1
    assert isinstance(events[0], TextDelta)
    assert events[0].content == "Files found: cache.py"

    call_args = mock_client.models.generate_content_stream.call_args
    assert call_args is not None
    _, kwargs = call_args
    contents = kwargs["contents"]
    assert len(contents) == 3

    # Turn 0: user message
    assert contents[0].role == "user"
    assert contents[0].parts[0].text == "find files"

    # Turn 1: model tool call
    assert contents[1].role == "model"
    assert contents[1].parts[0].function_call is not None
    assert contents[1].parts[0].function_call.name == "list_directory"
    assert contents[1].parts[0].function_call.args == {"path": "src"}
    assert contents[1].parts[0].function_call.id == "call_abc123"

    # Turn 2: tool response
    assert contents[2].role == "user"
    assert contents[2].parts[0].function_response is not None
    assert contents[2].parts[0].function_response.name == "list_directory"
    assert contents[2].parts[0].function_response.response == {"response": "cache.py\nproviders.py"}
    assert contents[2].parts[0].function_response.id == "call_abc123"


def test_gemini_multiturn_typed_tool_call():
    """Verify multi-turn conversion supporting typed ToolCall representations."""
    messages = [
        {"role": "user", "content": "read file"},
        {
            "role": "assistant",
            "content": "reading file now",
            "tool_calls": [ToolCall(call_id="call_read_1", name="read_file", arguments={"path": "test.txt"})],
        },
        {
            "role": "tool",
            "tool_call_id": "call_read_1",
            "name": "read_file",
            "content": '{"content": "hello world"}',
        },
    ]

    sys_inst, contents = format_gemini_contents(messages)
    assert sys_inst == ""
    assert len(contents) == 3

    assert contents[1].role == "model"
    assert len(contents[1].parts) == 2
    assert contents[1].parts[0].text == "reading file now"
    assert contents[1].parts[1].function_call.name == "read_file"
    assert contents[1].parts[1].function_call.args == {"path": "test.txt"}

    assert contents[2].role == "user"
    assert contents[2].parts[0].function_response.name == "read_file"
    assert contents[2].parts[0].function_response.response == {"content": "hello world"}


def test_gemini_multiturn_raw_dict():
    """Verify multi-turn conversion supporting raw dict formats."""
    messages = [
        {"role": "user", "content": "list files"},
        {"name": "list_dir", "args": {"path": "."}},
        {"name": "list_dir", "response": {"files": ["a", "b"]}},
    ]

    _, contents = format_gemini_contents(messages)
    assert len(contents) == 3
    assert contents[1].role == "model"
    assert contents[1].parts[0].function_call.name == "list_dir"
    assert contents[1].parts[0].function_call.args == {"path": "."}

    assert contents[2].role == "user"
    assert contents[2].parts[0].function_response.name == "list_dir"
    assert contents[2].parts[0].function_response.response == {"files": ["a", "b"]}


def test_gemini_missing_tool_call_id_raises_value_error():
    """Verify that role=='tool' missing tool_call_id raises ValueError, avoiding silent text coercion."""
    messages = [
        {"role": "user", "content": "hi"},
        {"role": "tool", "content": "orphaned result without tool_call_id"},
    ]

    with pytest.raises(ValueError, match="missing required 'tool_call_id'"):
        format_gemini_contents(messages)


def test_gemini_text_only_regression():
    """Verify text-only conversations remain green and preserve system instructions."""
    messages = [
        {"role": "system", "content": "You are a helpful coding assistant."},
        {"role": "user", "content": "How are you?"},
        {"role": "assistant", "content": "I am doing well, thank you!"},
    ]

    sys_inst, contents = format_gemini_contents(messages)
    assert sys_inst == "You are a helpful coding assistant."
    assert len(contents) == 2
    assert contents[0].role == "user"
    assert contents[0].parts[0].text == "How are you?"
    assert contents[1].role == "model"
    assert contents[1].parts[0].text == "I am doing well, thank you!"
