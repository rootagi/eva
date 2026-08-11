from unittest.mock import patch

from eva.agent.loop import StoppedReason, run_investigation
from eva.config import AppConfig
from eva.providers import TextDelta, ToolCall, ToolSpec


class ScriptedFakeProvider:
    name = "fake_tool_provider"
    max_rpm = 100
    max_rpd = 1000
    supports_tools = True

    def __init__(self, turns_script: list[list[TextDelta | ToolCall]]):
        self.turns_script = turns_script
        self.call_count = 0

    def generate_with_tools(self, messages: list[dict], tools: list[ToolSpec], config: AppConfig):
        if self.call_count < len(self.turns_script):
            events = self.turns_script[self.call_count]
            self.call_count += 1
            yield from events
        else:
            yield TextDelta(content="Default final answer.")


def test_agent_loop_executes_tools_and_returns_final_answer(tmp_path):
    (tmp_path / "app.py").write_text("print('hello world')\n")

    turns_script = [
        # Turn 1: Call read_file
        [ToolCall(call_id="call_1", name="read_file", arguments={"path": "app.py"})],
        # Turn 2: Final text answer
        [TextDelta(content="The app prints hello world.")],
    ]
    provider = ScriptedFakeProvider(turns_script)
    config = AppConfig()

    with patch("eva.agent.loop.check_and_increment", return_value=True) as mock_budget:
        res = run_investigation(
            query="What does app.py do?",
            root=tmp_path,
            config=config,
            provider_name="fake_tool_provider",
            max_turns=5,
            provider_override=provider,
        )

    assert res.stopped_reason == StoppedReason.COMPLETED
    assert res.final_answer == "The app prints hello world."
    assert res.files_read == ["app.py"]
    assert res.turns_used == 2
    assert mock_budget.call_count == 2


def test_agent_loop_stops_at_max_turns(tmp_path):
    turns_script = [
        [ToolCall(call_id=f"call_{i}", name="list_directory", arguments={"path": f"dir_{i}"})]
        for i in range(10)
    ]
    provider = ScriptedFakeProvider(turns_script)
    config = AppConfig()

    with patch("eva.agent.loop.check_and_increment", return_value=True):
        res = run_investigation(
            query="Infinite loop test",
            root=tmp_path,
            config=config,
            provider_name="fake_tool_provider",
            max_turns=3,
            provider_override=provider,
        )

    assert res.stopped_reason == StoppedReason.MAX_TURNS
    assert res.turns_used == 3
    assert "maximum turn limit" in res.final_answer


def test_agent_loop_detects_repeated_identical_tool_call(tmp_path):
    turns_script = [
        [ToolCall(call_id="call_1", name="list_directory", arguments={"path": "."})],
        [ToolCall(call_id="call_2", name="list_directory", arguments={"path": "."})],
    ]
    provider = ScriptedFakeProvider(turns_script)
    config = AppConfig()

    with patch("eva.agent.loop.check_and_increment", return_value=True):
        res = run_investigation(
            query="Repeated call test",
            root=tmp_path,
            config=config,
            provider_name="fake_tool_provider",
            max_turns=5,
            provider_override=provider,
        )

    assert res.stopped_reason == StoppedReason.REPEATED_CALL_DETECTED
    assert res.turns_used == 2
    assert "repeated identical tool" in res.final_answer


def test_agent_loop_stops_on_budget_exhaustion(tmp_path):
    provider = ScriptedFakeProvider([])
    config = AppConfig()

    with patch("eva.agent.loop.check_and_increment", return_value=False):
        res = run_investigation(
            query="Budget test",
            root=tmp_path,
            config=config,
            provider_name="fake_tool_provider",
            max_turns=5,
            provider_override=provider,
        )

    assert res.stopped_reason == StoppedReason.BUDGET_EXHAUSTED
    assert "budget was exhausted" in res.final_answer
