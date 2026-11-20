from pathlib import Path
from unittest.mock import MagicMock, patch

from eva.agent.loop import StoppedReason, run_investigation
from eva.agent.tools import read_file, search_code
from eva.config import AppConfig


def test_read_file_line_and_byte_bounds(tmp_path: Path):
    target = tmp_path / "sample.txt"
    lines = [f"line {i}" for i in range(1, 101)]
    target.write_text("\n".join(lines))

    # Slice lines 10 to 15
    res = read_file(root=tmp_path, path="sample.txt", start_line=10, end_line=15)
    assert res.error is None
    content = str(res)
    assert "line 10" in content
    assert "line 15" in content
    assert "line 9\n" not in content
    assert "line 16" not in content

    # Byte bounding
    res_bytes = read_file(root=tmp_path, path="sample.txt", max_bytes=50)
    assert res_bytes.error is None
    assert "Content truncated at 50 bytes" in str(res_bytes)
    assert len(str(res_bytes).split("\n[Eva:")[0].encode("utf-8")) <= 50


def test_search_code_ripgrep_and_fallback(tmp_path: Path):
    target = tmp_path / "code.py"
    target.write_text(
        """
def compute_metrics():
    target_metric_value = 42
    return target_metric_value
"""
    )

    # Search for target_metric_value
    res = search_code(root=tmp_path, pattern="target_metric_value")
    assert isinstance(res, list)
    assert len(res) >= 1
    assert any("target_metric_value" in hit.get("text", "") for hit in res)


def test_search_code_sensitive_file_exclusion(tmp_path: Path):
    secret_file = tmp_path / ".env"
    secret_file.write_text("DATABASE_PASSWORD=supersecretpassword123")

    res = search_code(root=tmp_path, pattern="supersecretpassword123")
    assert isinstance(res, list)
    # Should exclude .env
    assert len(res) == 0


def test_investigation_cumulative_token_budget(tmp_path: Path):
    mock_provider = MagicMock()
    mock_provider.max_rpm = 100
    mock_provider.max_rpd = 1000

    # Returns chunks of content
    def mock_generate_with_tools(*args, **kwargs):
        yield "This is a detailed analysis that will consume multiple tokens each turn."

    mock_provider.generate_with_tools = mock_generate_with_tools

    config = AppConfig()

    with patch("eva.agent.loop.get_provider", return_value=mock_provider):
        result = run_investigation(
            query="Investigate repo",
            root=tmp_path,
            config=config,
            provider_name="mock_provider",
            max_turns=10,
            max_tokens_budget=15,  # Very small budget to force immediate exhaustion
        )

    assert result.stopped_reason == StoppedReason.TOKEN_BUDGET_EXHAUSTED
    assert result.tokens_used >= 15
