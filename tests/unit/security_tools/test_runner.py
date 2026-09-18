import subprocess
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

from eva.security_tools.runner import run_tool_argv, validate_argv
from eva.security_tools.utils import SecurityToolError, sha256_file, write_text_artifact


def test_validate_argv_rejects_shell_injection():
    with pytest.raises(SecurityToolError):
        validate_argv(["trivy", "fs", ".", "|", "sh"])
    with pytest.raises(SecurityToolError):
        validate_argv(["semgrep", "$(touch /tmp/nope)"])
    with pytest.raises(SecurityToolError):
        validate_argv(["gitleaks", "detect\nwhoami"])


def test_run_tool_uses_shell_false(tmp_path):
    mock_proc = MagicMock()
    mock_proc.communicate.return_value = ("ok", "")
    mock_proc.returncode = 0
    with patch("eva.security_tools.runner.subprocess.Popen", return_value=mock_proc) as mock_popen:
        result = run_tool_argv(
            adapter="demo",
            operation="scan",
            argv=["tool", "--json"],
            cwd=tmp_path,
            timeout=10,
            output_path=None,
            dry_run=False,
            run_id="run-1",
        )
    assert result.return_code == 0
    assert mock_popen.call_args.kwargs["shell"] is False
    assert mock_popen.call_args.kwargs["start_new_session"] is True


def test_run_tool_missing_binary(tmp_path):
    with patch("eva.security_tools.runner.subprocess.Popen", side_effect=FileNotFoundError):
        result = run_tool_argv(
            adapter="demo",
            operation="scan",
            argv=["missing-tool"],
            cwd=tmp_path,
            timeout=10,
            output_path=None,
            dry_run=False,
            run_id="run-1",
        )
    assert result.missing is True
    assert result.return_code == 127


def test_run_tool_timeout(tmp_path):
    mock_proc = MagicMock()
    mock_proc.pid = 99999
    mock_proc.communicate.side_effect = [
        subprocess.TimeoutExpired(["slow"], 1),
        ("partial", "err"),
    ]
    with (
        patch("eva.security_tools.runner.subprocess.Popen", return_value=mock_proc),
        patch("eva.security_tools.runner.os.killpg") as mock_killpg,
        patch("eva.security_tools.runner.os.getpgid", return_value=99999),
    ):
        result = run_tool_argv(
            adapter="demo",
            operation="scan",
            argv=["slow"],
            cwd=tmp_path,
            timeout=1,
            output_path=None,
            dry_run=False,
            run_id="run-1",
        )
    assert result.timed_out is True
    assert result.return_code == 124
    assert "timed out" in result.stderr
    mock_killpg.assert_called_once()


def test_artifact_hashing(tmp_path):
    record = write_text_artifact(tmp_path / "artifact.txt", "hello")
    assert record.sha256 == sha256_file(tmp_path / "artifact.txt")
    assert datetime.now(timezone.utc)
