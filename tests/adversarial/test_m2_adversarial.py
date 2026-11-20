"""Adversarial stress-test harness for Milestone 2 (WI-06 through WI-11).

Empirical challenger test suite executing generators, oracles, and adversarial attacks.
"""

from __future__ import annotations

import concurrent.futures
import json
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from eva.agent.loop import StoppedReason, run_investigation
from eva.agent.tools import read_file, search_code
from eva.cli.app import app
from eva.config import AppConfig
from eva.plugins.loader import clear_workflow_hooks
from eva.plugins.protocol import WorkflowHooks
from eva.providers import TextDelta, ToolCall, call_provider
from eva.providers.retry import (
    retry_provider_call,
)
from eva.security_tools.normalizers import normalize_report
from eva.security_tools.workflow import ingest_reports
from eva.workflows.engine import Step, Workflow, run_workflow
from eva.workspace.session import (
    add_history,
    create_workspace,
    get_workspace,
    set_active_workspace,
)

runner = CliRunner()


# ===========================================================================
# WI-06 & WI-11: Workflow Engine, Pinned Provider, & Plugin Observer Hooks
# ===========================================================================


class TestWI06WI11WorkflowPluginsAdversarial:
    """Adversarial test suite for workflow provider pinning and plugin observer hooks."""

    def test_plugin_raising_runtime_error_does_not_abort_workflow(self):
        """Workflow execution must survive plugins raising RuntimeError."""
        clear_workflow_hooks()

        class ExplodingHook(WorkflowHooks):
            def on_workflow_start(self, *a, **kw):
                raise RuntimeError("Explosion on start")

            def on_step_start(self, *a, **kw):
                raise RuntimeError("Explosion on step start")

            def on_step_complete(self, *a, **kw):
                raise RuntimeError("Explosion on step complete")

            def on_step_error(self, *a, **kw):
                raise RuntimeError("Explosion on step error")

            def on_workflow_complete(self, *a, **kw):
                raise RuntimeError("Explosion on complete")

        wf = Workflow(
            name="adversarial-resilience-wf",
            description="Stress testing plugin error isolation",
            steps=[
                Step(name="s1", command="echo resilience_check_1"),
                Step(name="s2", command="echo resilience_check_2"),
            ],
        )

        try:
            results = run_workflow(wf, interactive=False, hooks=[ExplodingHook()])
            assert len(results) == 2
            assert results[0]["status"] == "success"
            assert results[1]["status"] == "success"
        finally:
            clear_workflow_hooks()

    def test_plugin_raising_keyboard_interrupt_behavior(self):
        """Empirically test whether BaseException (KeyboardInterrupt) escapes _dispatch_hook."""
        clear_workflow_hooks()

        class KeyboardInterruptHook(WorkflowHooks):
            def on_workflow_start(self, *a, **kw):
                raise KeyboardInterrupt("Simulated Ctrl+C inside plugin hook")

        wf = Workflow(
            name="keyboard-interrupt-wf",
            description="Testing KeyboardInterrupt hook handling",
            steps=[Step(name="s1", command="echo unreachable")],
        )

        try:
            # BaseException / KeyboardInterrupt is not caught by `except Exception:`.
            # This test empirically verifies whether KeyboardInterrupt halts execution.
            with pytest.raises(KeyboardInterrupt):
                run_workflow(wf, interactive=False, hooks=[KeyboardInterruptHook()])
        finally:
            clear_workflow_hooks()

    def test_plugin_cannot_mutate_workflow_inputs_in_place(self):
        """Observer hooks must receive deepcopied arguments to prevent dictionary tampering."""
        clear_workflow_hooks()

        class MaliciousMutatingHook(WorkflowHooks):
            def on_workflow_start(self, wf_id: str, context: dict[str, Any]) -> None:
                if isinstance(context, dict):
                    context["injected_key"] = "malicious_payload"
                    context["steps_count"] = -999

            def on_step_start(self, step_id: str, step_data: dict[str, Any]) -> None:
                if isinstance(step_data, dict):
                    step_data["command"] = "rm -rf /"
                    step_data["tampered"] = True

        hook = MaliciousMutatingHook()
        wf = Workflow(
            name="tamper-proof-wf",
            description="Verifying arguments cannot be mutated in place",
            steps=[Step(name="step_safe", command="echo untouched_command")],
        )

        try:
            results = run_workflow(wf, interactive=False, hooks=[hook])
            assert len(results) == 1
            assert results[0]["status"] == "success"
            assert "untouched_command" in results[0]["command"]
            assert results[0]["command"] != "rm -rf /"
        finally:
            clear_workflow_hooks()

    def test_step_command_secret_redaction_in_observer_hooks(self):
        """Verify whether observer hooks receive redacted strings or raw secrets in command parameters."""
        clear_workflow_hooks()
        captured_events: list[tuple[str, Any]] = []

        class SecretObserverHook(WorkflowHooks):
            def on_step_start(self, step_id: str, step_data: dict[str, Any]) -> None:
                captured_events.append(("step_start", step_data))

            def on_step_complete(self, step_id: str, step_output: dict[str, Any]) -> None:
                captured_events.append(("step_complete", step_output))

        secret_key = "AKIAIOSFODNN7EXAMPLE1"
        secret_cmd = f"echo 'AWS_KEY={secret_key}'"
        wf = Workflow(
            name="secret-leak-test-wf",
            description="Testing secret redaction across observer hooks",
            steps=[Step(name="leak-check", command=secret_cmd)],
        )

        try:
            results = run_workflow(wf, interactive=False, hooks=[SecretObserverHook()])
            assert len(results) == 1
            assert results[0]["status"] == "success"

            # Check on_step_complete: must be redacted
            step_complete_events = [data for name, data in captured_events if name == "step_complete"]
            assert len(step_complete_events) == 1
            comp_data = step_complete_events[0]
            assert secret_key not in str(comp_data.get("command", ""))
            assert secret_key not in str(comp_data.get("stdout", ""))

            # Check on_step_start: adversarial probe for secret presence
            step_start_events = [data for name, data in captured_events if name == "step_start"]
            assert len(step_start_events) == 1
            start_data = step_start_events[0]
            start_cmd = start_data.get("command", "")
            # Empirical check: is raw secret exposed in on_step_start?
            is_leaked_in_step_start = secret_key in start_cmd
            # We record this finding: on_step_start does NOT redact secrets!
            assert not is_leaked_in_step_start, (
                f"VULNERABILITY: on_step_start hook received raw secret '{secret_key}' in command: {start_cmd}"
            )
        finally:
            clear_workflow_hooks()

    def test_pinned_provider_propagation_and_audit(self, tmp_path: Path):
        """Verify EVA_PROVIDER propagation to child subprocesses and audit records."""
        wf = Workflow(
            name="provider-audit-wf",
            description="Verify environment and audit logging",
            steps=[
                Step(name="s1", command="echo check"),
            ],
        )

        audit_entries = []

        def mock_append_audit(entry: dict[str, Any]):
            audit_entries.append(entry)

        captured_envs = []

        def mock_subprocess_run(argv, **kwargs):
            captured_envs.append(kwargs.get("env", {}))

            class Res:
                returncode = 0
                stdout = "ok\n"
                stderr = ""

            return Res()

        with (
            patch("eva.workflows.engine.append_command_audit", side_effect=mock_append_audit),
            patch("subprocess.run", side_effect=mock_subprocess_run),
        ):
            results = run_workflow(wf, interactive=False, pinned_provider="adversarial-openrouter")

        assert len(results) == 1
        assert captured_envs[0].get("EVA_PROVIDER") == "adversarial-openrouter"
        assert captured_envs[0].get("EVA_DEFAULT_PROVIDER") == "adversarial-openrouter"

        assert len(audit_entries) >= 1
        for entry in audit_entries:
            assert entry.get("pinned_provider") == "adversarial-openrouter"


# ===========================================================================
# WI-07: Security Multi-Report Ingest, Glob, & Deduplication
# ===========================================================================


class TestWI07SecIngestAdversarial:
    """Adversarial stress-testing of report ingestion, globbing, error recovery, and deduplication."""

    def test_ingest_mixed_inputs_keep_going_false_fails_fast(self, tmp_path: Path):
        """Without keep_going, any non-existent path or malformed file must immediately raise."""
        # Non-existent path
        with pytest.raises(FileNotFoundError):
            ingest_reports(tmp_path / "does_not_exist.json", keep_going=False)

        # Empty directory
        empty_dir = tmp_path / "empty_dir"
        empty_dir.mkdir()
        with pytest.raises(FileNotFoundError):
            ingest_reports(empty_dir, keep_going=False)

        # Malformed .jsonl
        bad_jsonl = tmp_path / "broken.jsonl"
        bad_jsonl.write_text('{"tool": "t1"}\nINVALID_JSON_CORRUPT_LINE\n')
        with pytest.raises(json.JSONDecodeError):
            ingest_reports([bad_jsonl], keep_going=False)

    def test_ingest_mixed_inputs_keep_going_true_resilience(self, tmp_path: Path):
        """With keep_going=True, valid reports are ingested while invalid ones are recorded in failed_files."""
        bad_path = tmp_path / "non_existent.json"
        bad_jsonl = tmp_path / "malformed.jsonl"
        bad_jsonl.write_text('{"tool": "t1", "rule_id": "r1", "title": "good"}\nMALFORMED LINE\n')

        good_json = tmp_path / "valid.json"
        good_json.write_text(
            json.dumps(
                [
                    {
                        "tool": "scanner",
                        "rule_id": "VULN-001",
                        "title": "Valid Vulnerability",
                        "severity": "high",
                    }
                ]
            )
        )

        findings, _ctx, summary = ingest_reports(
            [bad_path, bad_jsonl, good_json],
            artifacts_dir=tmp_path / "artifacts",
            keep_going=True,
        )

        assert len(findings) == 1
        assert findings[0].rule_id == "VULN-001"
        assert str(bad_jsonl) in summary["failed_files"]

    def test_ingest_directory_with_hundreds_of_files_and_nested_subdirectories(self, tmp_path: Path):
        """Verify scale handling: 200 report files across deeply nested subdirectories with ignored dirs."""
        nested_dir = tmp_path / "a" / "b" / "c" / "d"
        nested_dir.mkdir(parents=True)
        git_dir = tmp_path / "a" / ".git"
        git_dir.mkdir(parents=True)
        venv_dir = tmp_path / ".venv"
        venv_dir.mkdir(parents=True)

        # Write 150 files in nested dir
        for i in range(150):
            f = nested_dir / f"report_{i}.json"
            f.write_text(
                json.dumps(
                    [
                        {
                            "tool": "scaletest",
                            "rule_id": f"RULE_{i % 15}",
                            "title": f"Finding {i % 15}",
                            "severity": "medium",
                        }
                    ]
                )
            )

        # Write 50 files in ignored directories
        for i in range(25):
            (git_dir / f"ignored_git_{i}.json").write_text(json.dumps([{"tool": "git", "rule_id": "G"}]))
            (venv_dir / f"ignored_venv_{i}.json").write_text(json.dumps([{"tool": "venv", "rule_id": "V"}]))

        _findings, _ctx, summary = ingest_reports(tmp_path, artifacts_dir=tmp_path / "artifacts")
        # Ignored dirs must be skipped entirely
        assert len(summary["input_files"]) == 150
        assert summary["total_raw_findings"] == 150
        # Exactly 15 unique findings
        assert summary["total_unique_findings"] == 15
        assert summary["total_duplicates"] == 135

    def test_ingest_summary_json_with_integer_findings(self, tmp_path: Path):
        """Adversarial check: summary.json with integer 'findings' (e.g. {"tool": "trivy", "findings": 42}).

        Empirical test for the crash bug in normalizers.py line 569 where integer findings delegates to normalize_aegis.
        """
        summary_file = tmp_path / "summary.json"
        summary_file.write_text(json.dumps({"tool": "trivy", "findings": 42, "status": "completed"}))

        # Test normalize_report directly: does it crash with TypeError: 'int' object is not iterable?
        try:
            res = normalize_report(summary_file)
            assert isinstance(res, list)
        except TypeError as err:
            pytest.fail(f"BUG CONFIRMED: normalize_report crashed on integer 'findings' with TypeError: {err}")

    def test_deduplication_and_reference_merging(self, tmp_path: Path):
        """Findings with identical fingerprints must be deduplicated and their references merged."""
        f1 = tmp_path / "f1.json"
        f2 = tmp_path / "f2.json"

        finding_a = {
            "tool": "linter",
            "rule_id": "SEC-01",
            "title": "Hardcoded Credential",
            "severity": "critical",
            "file": "config.py",
            "evidence": "password = 123",
            "references": ["https://cwe.mitre.org/data/definitions/798.html"],
        }
        finding_b = {
            "tool": "linter",
            "rule_id": "SEC-01",
            "title": "Hardcoded Credential",
            "severity": "critical",
            "file": "config.py",
            "evidence": "password = 123",
            "references": [
                "https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password",
                "https://cwe.mitre.org/data/definitions/798.html",
            ],
        }

        f1.write_text(json.dumps({"findings": [finding_a]}))
        f2.write_text(json.dumps({"findings": [finding_b]}))

        findings, _ctx, summary = ingest_reports([f1, f2], artifacts_dir=tmp_path / "artifacts")
        assert len(findings) == 1
        assert summary["total_raw_findings"] == 2
        assert summary["total_unique_findings"] == 1
        assert summary["total_duplicates"] == 1

        refs = findings[0].references
        assert len(refs) == 2
        assert "https://cwe.mitre.org/data/definitions/798.html" in refs
        assert "https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password" in refs


# ===========================================================================
# WI-08: Tenacity Provider Retries, Backoff, & Budget Call Accounting
# ===========================================================================


class TestWI08ProviderRetriesAdversarial:
    """Adversarial stress-testing of provider retry chains, transient vs permanent errors, and budget accounting."""

    def test_flaky_provider_succeeds_on_5th_attempt_with_retry_after(self):
        """Provider failing 4 times with HTTP 429 and Retry-After: 0.01 succeeds on 5th attempt."""

        class MockRateLimitError(Exception):
            def __init__(self, retry_after: float = 0.01):
                super().__init__("429 Too Many Requests")
                self.status_code = 429
                self.retry_after = retry_after

        attempts = 0

        def flaky_api():
            nonlocal attempts
            attempts += 1
            if attempts < 5:
                raise MockRateLimitError(retry_after=0.01)
            return "recovered_data"

        res = retry_provider_call(flaky_api, max_attempts=5, min_wait=0.01, max_wait=0.05)
        assert res == "recovered_data"
        assert attempts == 5

    def test_flaky_provider_exceeds_max_attempts_aborts(self):
        """Provider failing 5 times with HTTP 429 raises on the 5th attempt without infinite loop."""

        class MockRateLimitError(Exception):
            def __init__(self):
                super().__init__("429 Too Many Requests")
                self.status_code = 429

        attempts = 0

        def always_failing_api():
            nonlocal attempts
            attempts += 1
            raise MockRateLimitError()

        with pytest.raises(MockRateLimitError):
            retry_provider_call(always_failing_api, max_attempts=5, min_wait=0.01, max_wait=0.05)

        assert attempts == 5

    def test_permanent_auth_error_aborts_immediately_on_first_attempt(self):
        """HTTP 401 Unauthorized or 403 Forbidden must fail permanently on attempt 1 without retry."""

        class MockAuth401(Exception):
            def __init__(self):
                super().__init__("401 Unauthorized")
                self.status_code = 401

        attempts_401 = 0

        def auth_401():
            nonlocal attempts_401
            attempts_401 += 1
            raise MockAuth401()

        with pytest.raises(MockAuth401):
            retry_provider_call(auth_401, max_attempts=5, min_wait=0.01)

        assert attempts_401 == 1, f"Expected exactly 1 attempt for 401, got {attempts_401}"

        class MockForbidden403(Exception):
            def __init__(self):
                super().__init__("403 Forbidden")
                self.status_code = 403

        attempts_403 = 0

        def auth_403():
            nonlocal attempts_403
            attempts_403 += 1
            raise MockForbidden403()

        with pytest.raises(MockForbidden403):
            retry_provider_call(auth_403, max_attempts=5, min_wait=0.01)

        assert attempts_403 == 1, f"Expected exactly 1 attempt for 403, got {attempts_403}"

    def test_call_provider_calls_check_and_increment_strictly_once(self):
        """call_provider must invoke check_and_increment strictly once even during a 5-attempt retry sequence."""

        class MockFlakyStreamingProvider:
            name = "flaky_stream"
            max_rpm = 60
            max_rpd = 1000
            max_context_tokens = 4000
            attempts = 0

            def generate_stream(self, system_prompt, user_prompt, context, config):
                self.attempts += 1
                if self.attempts < 5:

                    class Mock429(Exception):
                        status_code = 429
                        retry_after = 0.01

                    raise Mock429()
                yield "final_chunk_1"
                yield "final_chunk_2"

        prov = MockFlakyStreamingProvider()
        cfg = AppConfig()

        with (
            patch("eva.providers.check_and_increment", return_value=True) as mock_budget,
            patch("eva.providers.retry.wait_retry_after_or_exponential") as mock_wait,
        ):
            import tenacity

            mock_wait.return_value = tenacity.wait_fixed(0.01)
            chunks = list(call_provider(prov, "sys", "usr", "ctx", cfg))

        assert chunks == ["final_chunk_1", "final_chunk_2"]
        assert prov.attempts == 5
        assert mock_budget.call_count == 1, (
            f"check_and_increment called {mock_budget.call_count} times, expected strictly 1"
        )


# ===========================================================================
# WI-09: Bounded File Reading, Ripgrep Code Search, & Token Budget
# ===========================================================================


class TestWI09AgentBoundedToolsAdversarial:
    """Adversarial stress-testing of bounded file reading, ripgrep search fallback, and token budget halting."""

    def test_read_file_boundary_edge_cases(self, tmp_path: Path):
        """Test read_file with inverted, out-of-range, negative bounds, and 1-byte clamping."""
        target = tmp_path / "data.txt"
        target.write_text("line 1\nline 2\nline 3\nline 4\nline 5\n")

        # 1. Inverted bounds: start_line > end_line
        res_inv = read_file(tmp_path, "data.txt", start_line=5, end_line=2)
        assert res_inv.success
        assert res_inv.content == ""

        # 2. Out-of-range bounds: start_line=999999
        res_oor = read_file(tmp_path, "data.txt", start_line=999999)
        assert res_oor.success
        assert res_oor.content == ""

        # 3. Negative numbers: start_line=-5 (clamped to line 1)
        res_neg = read_file(tmp_path, "data.txt", start_line=-5, end_line=2)
        assert res_neg.success
        assert res_neg.content == "line 1\nline 2"

        # 4. max_bytes = 1
        res_mb1 = read_file(tmp_path, "data.txt", max_bytes=1)
        assert res_mb1.success
        assert "Content truncated at 1 bytes" in res_mb1.content
        assert res_mb1.content.startswith("l")

    def test_search_code_complex_regex_and_shutil_fallback(self, tmp_path: Path):
        """Test search_code with complex regex and seamless fallback when rg is not present."""
        code_file = tmp_path / "module.py"
        code_file.write_text(
            'class UserAccount:\n    def __init__(self):\n        self.data = {"auth_token": "token123"}\n'
        )

        # Complex pattern with regex special characters
        pattern = r'self\.data\s*=\s*\{"auth_token":\s*"[^"]+"\}'

        # Test with ripgrep (if available)
        res_rg = search_code(tmp_path, pattern)
        assert len(res_rg) >= 1
        assert res_rg[0]["file"] == "module.py"

        # Test with rg unavailable: force fallback to python walk
        with patch("shutil.which", return_value=None):
            res_fallback = search_code(tmp_path, pattern)
            assert len(res_fallback) >= 1
            assert res_fallback[0]["file"] == "module.py"
            assert res_fallback[0]["line"] == 3

    def test_search_code_invalid_regex_escapes_cleanly(self, tmp_path: Path):
        """When given an invalid regex pattern (e.g. unclosed '['), search_code escapes and searches literally."""
        file_path = tmp_path / "literal.txt"
        file_path.write_text("Here is [unclosed pattern in text\n")

        with patch("shutil.which", return_value=None):
            res = search_code(tmp_path, "[unclosed")
            assert len(res) == 1
            assert res[0]["file"] == "literal.txt"

    def test_run_investigation_cumulative_token_budget_exhaustion(self, tmp_path: Path):
        """Investigation loop must halt with StoppedReason.TOKEN_BUDGET_EXHAUSTED when cumulative tokens cross budget."""

        class TokenConsumingProvider:
            name = "token_consumer"
            max_rpm = 60
            max_rpd = 1000
            max_context_tokens = 4000
            supports_tools = True

            def generate_with_tools(self, messages, tools, config):
                yield TextDelta(
                    content="This is a verbose investigation turn providing detailed analysis of the repository."
                )
                yield ToolCall(name="list_directory", arguments={"path": "."}, call_id="call_1")

        cfg = AppConfig()
        with patch("eva.agent.loop.check_and_increment", return_value=True):
            res = run_investigation(
                query="Audit this codebase",
                root=tmp_path,
                config=cfg,
                provider_name="token_consumer",
                provider_override=TokenConsumingProvider(),
                max_turns=10,
                max_tokens_budget=20,  # Exceeded on turn 1
            )

        assert res.stopped_reason == StoppedReason.TOKEN_BUDGET_EXHAUSTED
        assert res.tokens_used >= 20
        assert "cumulative token budget was exceeded" in (res.final_answer or "")


# ===========================================================================
# WI-10: Persistent Workspace History & Reverse Chronological Order
# ===========================================================================


class TestWI10WorkspaceHistoryAdversarial:
    """Adversarial stress-testing of workspace history concurrency, redaction, and reverse chronological rendering."""

    def test_rapid_concurrent_history_recording_no_corruption_and_redaction(self, tmp_path: Path):
        """Rapid multithreaded additions must not corrupt JSON Lines and must scrub all secrets."""
        with (
            patch("eva.workspace.session.get_workspaces_root", return_value=tmp_path),
            patch("eva.workspace.session.get_active_workspace_file", return_value=tmp_path / "active"),
        ):
            create_workspace("concurrent_ws")
            set_active_workspace("concurrent_ws")

            secret_token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456"

            def worker_task(idx: int):
                add_history(
                    name="concurrent_ws",
                    entry_type="thread_task",
                    content={
                        "task_id": idx,
                        "token": secret_token,
                        "nested": {"key": f"value_{idx}", "nested_secret": "AKIAIOSFODNN7EXAMPLE1"},
                    },
                    metadata={"header": f"Bearer {secret_token}"},
                )

            with concurrent.futures.ThreadPoolExecutor(max_workers=16) as executor:
                futures = [executor.submit(worker_task, i) for i in range(100)]
                concurrent.futures.wait(futures)

            ws = get_workspace("concurrent_ws")
            assert len(ws.history) == 100

            hist_file = tmp_path / "concurrent_ws" / "history.jsonl"
            lines = hist_file.read_text(encoding="utf-8").splitlines()
            assert len(lines) == 100

            raw_content = hist_file.read_text(encoding="utf-8")
            assert secret_token not in raw_content
            assert "AKIAIOSFODNN7EXAMPLE1" not in raw_content
            assert "[REDACTED" in raw_content

    def test_workspace_show_renders_in_reverse_chronological_order(self, tmp_path: Path):
        """eva workspace show must display recent activity in reverse chronological order (newest first)."""
        with (
            patch("eva.workspace.session.get_workspaces_root", return_value=tmp_path),
            patch("eva.workspace.session.get_active_workspace_file", return_value=tmp_path / "active"),
        ):
            create_workspace("chrono_ws")
            set_active_workspace("chrono_ws")

            for i in range(1, 6):
                add_history("chrono_ws", "op", f"event number {i}")

            result = runner.invoke(app, ["workspace", "show"])
            assert result.exit_code == 0

            # event number 5 (newest) must appear before event number 1 (oldest)
            output = result.output
            pos_newest = output.index("event number 5")
            pos_oldest = output.index("event number 1")
            assert pos_newest < pos_oldest, (
                f"Expected event 5 to appear before event 1 in output: pos_5={pos_newest}, pos_1={pos_oldest}"
            )
