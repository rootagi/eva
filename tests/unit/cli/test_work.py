from unittest.mock import MagicMock, patch

from typer.testing import CliRunner

from eva.cli.app import app


def test_work_failing_command_exits_without_prompt(monkeypatch):
    """When a command fails and allow_sudo is False, exits immediately with non-zero without prompting."""
    runner = CliRunner()

    with (
        patch("eva.cli.commands.work._resolve_app_attr") as mock_resolve,
        patch("subprocess.run") as mock_run,
        patch("typer.confirm") as mock_confirm,
    ):
        mock_config = MagicMock()
        mock_config.general.allowed_command_prefixes = []
        mock_config.general.sandbox_risky_commands = False

        def resolve_side_effect(name, default):
            if name == "load_config":
                return lambda: mock_config
            if name == "dispatch":
                return lambda *args, **kwargs: iter(["ls /nonexistent"])
            if name == "append_command_audit":
                return MagicMock()
            return default

        mock_resolve.side_effect = resolve_side_effect

        mock_proc = MagicMock()
        mock_proc.returncode = 2
        mock_proc.stdout = ""
        mock_proc.stderr = "ls: cannot access '/nonexistent': No such file or directory"
        mock_run.return_value = mock_proc

        result = runner.invoke(app, ["work", "--yes", "list files"])
        assert result.exit_code == 2
        mock_confirm.assert_not_called()


def test_work_allow_sudo_success(monkeypatch):
    """When --allow-sudo is given and command fails, retries with sudo if allowlisted."""
    runner = CliRunner()

    audit_records = []

    with (
        patch("eva.cli.commands.work._resolve_app_attr") as mock_resolve,
        patch("subprocess.run") as mock_run,
        patch("eva.replay.record_replay_event") as mock_replay,
    ):
        mock_config = MagicMock()
        mock_config.general.allowed_command_prefixes = ["cat", "sudo cat"]
        mock_config.general.sandbox_risky_commands = False

        def resolve_side_effect(name, default):
            if name == "load_config":
                return lambda: mock_config
            if name == "dispatch":
                return lambda *args, **kwargs: iter(["cat /etc/shadow"])
            if name == "append_command_audit":
                return audit_records.append
            return default

        mock_resolve.side_effect = resolve_side_effect

        # First run fails (code 1), escalated sudo run succeeds (code 0)
        proc_fail = MagicMock(returncode=1, stdout="", stderr="Permission denied")
        proc_success = MagicMock(returncode=0, stdout="root:...", stderr="")
        mock_run.side_effect = [proc_fail, proc_success]

        result = runner.invoke(app, ["work", "--yes", "--allow-sudo", "read shadow"])
        assert result.exit_code == 0
        assert mock_run.call_count == 2

        # Check that replay was recorded for the escalated command
        mock_replay.assert_called()

        # Check audit records include escalation
        escalated_records = [r for r in audit_records if r.get("escalated") is True]
        assert len(escalated_records) == 1
        assert escalated_records[0]["executed"] is True
        assert escalated_records[0]["command"] == "sudo cat /etc/shadow"


def test_work_allow_sudo_blocked_by_allowlist(monkeypatch):
    """When --allow-sudo is given but escalated command prefix is not allowed, escalation is blocked."""
    runner = CliRunner()
    audit_records = []

    with (
        patch("eva.cli.commands.work._resolve_app_attr") as mock_resolve,
        patch("subprocess.run") as mock_run,
    ):
        mock_config = MagicMock()
        mock_config.general.allowed_command_prefixes = ["cat"]
        mock_config.general.sandbox_risky_commands = False

        def resolve_side_effect(name, default):
            if name == "load_config":
                return lambda: mock_config
            if name == "dispatch":
                return lambda *args, **kwargs: iter(["cat /etc/shadow"])
            if name == "append_command_audit":
                return audit_records.append
            return default

        mock_resolve.side_effect = resolve_side_effect

        proc_fail = MagicMock(returncode=1, stdout="", stderr="Access denied")
        mock_run.return_value = proc_fail

        result = runner.invoke(app, ["work", "--yes", "--allow-sudo", "read shadow"])
        assert result.exit_code == 1

        blocked_records = [r for r in audit_records if r.get("escalated") is True]
        assert len(blocked_records) == 1
        assert blocked_records[0]["executed"] is False
        assert "escalation_safety_check_failed" in blocked_records[0]["blocked_reason"]
