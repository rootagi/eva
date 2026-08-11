from eva.providers import (
    TextDelta,
    ToolCall,
    ToolSpec,
    get_tool_capable_providers,
    is_tool_capable,
)


class FakeUnsupportedProvider:
    name = "unsupported_fake"
    max_rpm = 10
    max_rpd = 100
    max_context_tokens = 4000
    # supports_tools defaults to False or is omitted


def test_unsupported_provider_reports_false():
    assert is_tool_capable("nonexistent_provider") is False
    assert is_tool_capable("unsupported_fake") is False
    assert "unsupported_fake" not in get_tool_capable_providers()


def test_local_providers_report_not_tool_capable():
    assert is_tool_capable("ollama") is False
    assert is_tool_capable("llamacpp") is False
    assert "ollama" not in get_tool_capable_providers()
    assert "llamacpp" not in get_tool_capable_providers()


def test_tool_event_dataclasses():
    delta = TextDelta(content="hello")
    assert delta.content == "hello"

    call = ToolCall(call_id="call_1", name="read_file", arguments={"path": "app.py"})
    assert call.call_id == "call_1"
    assert call.name == "read_file"
    assert call.arguments == {"path": "app.py"}

    spec = ToolSpec(name="read_file", description="Read file", parameters={"type": "object"})
    assert spec.name == "read_file"
    assert spec.parameters == {"type": "object"}
