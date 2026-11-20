import email.utils
import json
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from eva.agent.tools import read_file, search_code
from eva.plugins.protocol import WorkflowHooks
from eva.providers.retry import (
    RetryingStream,
    extract_retry_after,
    wait_retry_after_or_exponential,
)
from eva.security_tools.cli import sec_app
from eva.security_tools.workflow import ingest_reports
from eva.workflows.engine import Step, Workflow, run_workflow
from eva.workspace.session import add_history, create_workspace, get_history

runner = CliRunner()


# ============================================================================
# 1. ADVERSARIAL STRESS TEST: WI-06 & WI-11 (Workflow Pinned Provider & Hooks)
# ============================================================================


def test_adversarial_workflow_step_failure_audit_pinned_provider_and_step_id(tmp_path: Path):
    """Stress test: Step failure audit records MUST contain both pinned_provider and step_id."""
    audit_log = tmp_path / "audit.jsonl"
    captured_entries = []

    def mock_append(entry):
        captured_entries.append(entry)
        with open(audit_log, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")

    wf = Workflow(
        name="adversarial_failure_wf",
        description="Workflow to verify audit fields on step failure",
        steps=[
            Step(
                id="sec_step_fail_999",
                name="failing_audit_step",
                command="false",
                description="Step that exits non-zero",
            )
        ],
    )

    with patch("eva.workflows.engine.append_command_audit", side_effect=mock_append):
        results = run_workflow(wf, interactive=False, pinned_provider="mock-llm-provider")

    assert len(results) == 1
    assert results[0]["status"] == "failed"
    assert len(captured_entries) >= 1

    failure_entry = captured_entries[0]

    # Verify pinned_provider is recorded
    assert failure_entry.get("pinned_provider") == "mock-llm-provider"

    # EMPIRICAL CHECK: Verify step_id is recorded in the audit entry
    # Note: If step_id is missing, this will fail and identify the defect.
    assert "step_id" in failure_entry, (
        f"Defect found: 'step_id' missing from workflow step failure audit record! "
        f"Keys present: {list(failure_entry.keys())}"
    )
    assert failure_entry["step_id"] == "sec_step_fail_999"


def test_adversarial_workflow_hooks_slow_callback_graceful():
    """Stress test: WorkflowHooks with slow callback executes gracefully."""

    class SlowHook(WorkflowHooks):
        def on_step_start(self, step_id, step_data=None):
            time.sleep(0.02)

        def on_step_complete(self, step_id, step_result=None):
            time.sleep(0.02)

    wf = Workflow(
        name="slow_hook_wf",
        description="Workflow with slow hooks",
        steps=[
            Step(name="s1", command="echo slow_test_passed"),
        ],
    )

    t0 = time.time()
    results = run_workflow(wf, interactive=False, hooks=[SlowHook()])
    elapsed = time.time() - t0

    assert len(results) == 1
    assert results[0]["status"] == "success"
    assert elapsed >= 0.04


def test_adversarial_workflow_hooks_base_exception_isolation():
    """Stress test: WorkflowHooks raising BaseException (SystemExit) MUST NOT crash the workflow runner."""

    class ExitHook(WorkflowHooks):
        def on_step_start(self, step_id, step_data=None):
            raise SystemExit(42)

    wf = Workflow(
        name="exit_hook_wf",
        description="Workflow testing hook exception isolation against BaseException",
        steps=[
            Step(name="safe_step", command="echo hook_isolated"),
        ],
    )

    # In a hardened system, plugin hooks should never crash the core runner,
    # even when attempting to raise SystemExit or other BaseExceptions.
    try:
        results = run_workflow(wf, interactive=False, hooks=[ExitHook()])
        assert len(results) == 1
        assert results[0]["status"] == "success"
    except BaseException as exc:  # noqa: BLE001
        pytest.fail(
            f"Defect found: Workflow runner crashed on hook BaseException ({type(exc).__name__}: {exc})! "
            f"Hooks are not safely isolated against BaseException (e.g. SystemExit)."
        )


# ============================================================================
# 2. ADVERSARIAL STRESS TEST: WI-07 (Security Ingest Dedup & Fault Tolerance)
# ============================================================================


def test_adversarial_sec_ingest_dedup_1000_colliding_findings(tmp_path: Path):
    """Stress test: Ingest 1,000 synthetic findings with overlapping fingerprints across SARIF and JSON."""
    sarif_file = tmp_path / "colliding_sarif.sarif"
    json_file = tmp_path / "colliding_json.json"

    # SARIF report: 500 findings (50 unique findings repeated 10 times)
    sarif_results = []
    for i in range(500):
        idx = i % 50
        sarif_results.append(
            {
                "ruleId": f"SEC_RULE_{idx:03d}",
                "message": {"text": f"Vulnerability description {idx:03d}"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": f"src/module_{idx:03d}.py"},
                            "region": {"startLine": idx + 10, "endLine": idx + 10},
                        }
                    }
                ],
                "level": "error",
            }
        )
    sarif_file.write_text(
        json.dumps({"runs": [{"tool": {"driver": {"name": "sarif-synth"}}, "results": sarif_results}]})
    )

    # JSON report: 500 findings:
    # - 250 findings that duplicate the first 25 SARIF findings (indexes 0..24)
    # - 250 findings that define 75 NEW unique findings (indexes 50..124)
    json_findings = []
    for i in range(250):
        idx = i % 25
        json_findings.append(
            {
                "tool": "sarif-synth",
                "rule_id": f"SEC_RULE_{idx:03d}",
                "title": f"Vulnerability description {idx:03d}",
                "file": f"src/module_{idx:03d}.py",
                "line": idx + 10,
                "evidence": f"Vulnerability description {idx:03d}",
                "references": [f"https://sec.example.com/ref_{idx}_{i}"],
            }
        )
    for i in range(250):
        idx = 50 + (i % 75)
        json_findings.append(
            {
                "tool": "sarif-synth",
                "rule_id": f"SEC_RULE_{idx:03d}",
                "title": f"Vulnerability description {idx:03d}",
                "file": f"src/module_{idx:03d}.py",
                "line": idx + 10,
                "evidence": f"Vulnerability description {idx:03d}",
                "references": [f"https://sec.example.com/ref_{idx}"],
            }
        )
    json_file.write_text(json.dumps({"findings": json_findings}))

    t_start = time.time()
    findings, _ctx, stats = ingest_reports(
        [sarif_file, json_file],
        artifacts_dir=tmp_path / "artifacts",
    )
    t_elapsed = time.time() - t_start

    # Performance constraint: 1,000 items should process in < 2 seconds
    assert t_elapsed < 2.0, f"Deduplication took too long: {t_elapsed:.2f}s"

    # Exact count assertions:
    # Total raw: 500 (SARIF) + 500 (JSON) = 1,000 findings
    assert stats["total_raw_findings"] == 1000
    # Expected unique: 50 (from SARIF) + 75 (new from JSON) = 125 unique findings
    assert len(findings) == 125
    assert stats["total_unique_findings"] == 125
    assert stats["total_duplicates"] == 875

    # References merging assertion
    colliding_sample = next(f for f in findings if f.rule_id == "SEC_RULE_001")
    assert len(colliding_sample.references) > 1


def test_adversarial_sec_ingest_permission_and_keep_going(tmp_path: Path):
    """Stress test: Unreadable file halts when keep_going=False, but is bypassed when keep_going=True."""
    valid_file_1 = tmp_path / "report_1.json"
    valid_file_1.write_text(json.dumps({"findings": [{"tool": "t1", "rule_id": "r1", "title": "t1"}]}))

    unreadable_file = tmp_path / "unreadable_report.json"
    unreadable_file.write_text(json.dumps({"findings": [{"tool": "t2", "rule_id": "r2", "title": "t2"}]}))
    unreadable_file.chmod(0o000)

    valid_file_2 = tmp_path / "report_2.json"
    valid_file_2.write_text(json.dumps({"findings": [{"tool": "t3", "rule_id": "r3", "title": "t3"}]}))

    try:
        # Case 1: keep_going=False -> MUST raise PermissionError
        with pytest.raises(PermissionError):
            ingest_reports([valid_file_1, unreadable_file, valid_file_2], keep_going=False)

        # Case 2: keep_going=True -> MUST succeed, ingest remaining, record failure
        findings, _ctx, stats = ingest_reports(
            [valid_file_1, unreadable_file, valid_file_2],
            artifacts_dir=tmp_path / "artifacts",
            keep_going=True,
        )

        assert len(findings) == 2
        assert stats["total_unique_findings"] == 2
        assert str(unreadable_file.resolve()) in stats["failed_files"]

        # Case 3: CLI with --keep-going
        cli_res = runner.invoke(
            sec_app,
            [
                "ingest",
                str(valid_file_1),
                str(unreadable_file),
                str(valid_file_2),
                "--keep-going",
                "--artifacts-dir",
                str(tmp_path / "cli_artifacts"),
            ],
        )
        assert cli_res.exit_code == 0
        assert "Ingested 2 findings" in cli_res.output

    finally:
        unreadable_file.chmod(0o644)


# ============================================================================
# 3. ADVERSARIAL STRESS TEST: WI-08 (Tenacity Stream Retry & Retry-After)
# ============================================================================


def test_adversarial_retry_after_formats():
    """Verify Retry-After extraction handles integer seconds and HTTP RFC date formats."""

    class MockResp:
        def __init__(self, headers):
            self.headers = headers

    class MockHttpError(Exception):
        def __init__(self, headers):
            self.response = MockResp(headers)

    # 1. Integer format: "3"
    err_int = MockHttpError({"retry-after": "3"})
    assert extract_retry_after(err_int) == 3.0

    # 2. HTTP RFC date format in future (e.g. 120s from now)
    future_dt = datetime.now(timezone.utc) + timedelta(seconds=120)
    rfc_date_str = email.utils.format_datetime(future_dt)
    err_date = MockHttpError({"Retry-After": rfc_date_str})
    extracted = extract_retry_after(err_date)
    assert extracted is not None
    assert 115.0 <= extracted <= 125.0

    # 3. Wait strategy clamping
    wait_strat = wait_retry_after_or_exponential(min_wait=1.0, max_wait=30.0)

    # Mock retry state with retry-after=60 -> clamped to max_wait=30.0
    class MockOutcome:
        failed = True

        def exception(self):
            return MockHttpError({"retry-after": "60"})

    class MockRetryState:
        outcome = MockOutcome()

    wait_time = wait_strat(MockRetryState())
    assert wait_time == 30.0


def test_adversarial_retrying_stream_0_vs_100_bytes_yielded():
    """Stress test: Generator stream connection reset after 0 bytes vs after 100 bytes."""
    # Scenario A: Connection reset after 0 bytes yielded -> RetryingStream must retry and recover
    attempt_a = 0

    def generator_fail_at_0_bytes():
        nonlocal attempt_a
        attempt_a += 1
        if attempt_a == 1:
            raise ConnectionError("Connection reset before any data yielded (0 bytes)")
        yield "packet_1"
        yield "packet_2"

    stream_a = RetryingStream(generator_fail_at_0_bytes, min_wait=0.001, max_wait=0.01)
    items_a = list(stream_a)
    assert attempt_a == 2
    assert items_a == ["packet_1", "packet_2"]

    # Scenario B: Connection reset after 100 bytes yielded -> MUST NOT blindly retry and corrupt/duplicate data!
    # Exception must surface properly to the caller midstream.
    attempt_b = 0

    def generator_fail_after_100_bytes():
        nonlocal attempt_b
        attempt_b += 1
        yield "X" * 60
        yield "Y" * 40  # 100 bytes total yielded
        raise ConnectionError("Connection reset midstream after 100 bytes")

    stream_b = RetryingStream(generator_fail_after_100_bytes, min_wait=0.001, max_wait=0.01)

    collected_b = []
    with pytest.raises(ConnectionError) as exc_info:
        for chunk in stream_b:
            collected_b.append(chunk)  # noqa: PERF402

    assert "Connection reset midstream after 100 bytes" in str(exc_info.value)
    assert len("".join(collected_b)) == 100
    assert attempt_b == 1  # Did not attempt unsafe blind restart after yielding


# ============================================================================
# 4. ADVERSARIAL STRESS TEST: WI-09 (Safe File/Search Boundaries & Containment)
# ============================================================================


def test_adversarial_read_file_multibyte_utf8_and_binary(tmp_path: Path):
    """Stress test: max_bytes slicing through 4-byte UTF-8 character and binary files."""
    # 4-byte character: 🌟 (U+1F31F, UTF-8: \xf0\x9f\x8c\x9f)
    # File has 8 ASCII characters + 4-byte emoji + more text
    content = "12345678" + "\U0001f31f" + "ABCDEFGH"
    utf_file = tmp_path / "multibyte.txt"
    utf_file.write_text(content, encoding="utf-8")

    # Byte 8 is start of emoji; bytes 9, 10, 11 are continuation bytes.
    # Slicing at 9, 10, 11 cuts directly through the 4-byte character.
    for cut_point in [9, 10, 11]:
        res = read_file(tmp_path, "multibyte.txt", max_bytes=cut_point)
        assert res.success is True
        assert "[Eva: Content truncated at" in str(res.output)
        # Content decoded without unhandled UnicodeDecodeError
        assert str(res.output).startswith("12345678")

    # Binary file with null bytes
    bin_file = tmp_path / "firmware.bin"
    bin_file.write_bytes(b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00")
    res_bin = read_file(tmp_path, "firmware.bin")
    assert res_bin.success is False
    assert "binary" in res_bin.error.lower()


def test_adversarial_search_code_special_paths_and_traversal(tmp_path: Path):
    """Stress test: search_code with spaces/non-ASCII and path containment rejection."""
    # Special directory name with spaces and non-ASCII chars
    complex_dir = tmp_path / "src directory with spaces" / "тест_ünicöde"
    complex_dir.mkdir(parents=True)
    source_file = complex_dir / "target.py"
    source_file.write_text("def find_adversarial_secret():\n    return 'flag_xyz'\n", encoding="utf-8")

    # 1. Search in complex path
    results = search_code(
        tmp_path,
        "find_adversarial_secret",
        path="src directory with spaces/тест_ünicöde",
    )
    assert len(results) == 1
    assert "find_adversarial_secret" in results[0]["text"]

    # 2. Path containment rejection on ../../etc
    traversal_results = search_code(tmp_path, "root", path="../../etc")
    assert traversal_results == []

    # 3. Traversal on read_file
    res_trav = read_file(tmp_path, "../../etc/shadow")
    assert res_trav.success is False
    assert "traversal" in res_trav.error.lower()


# ============================================================================
# 5. ADVERSARIAL STRESS TEST: WI-10 (Workspace History Deep Redaction)
# ============================================================================


def test_adversarial_workspace_history_deeply_nested_redaction(tmp_path: Path):
    """Stress test: add_history with dict depth > 10 containing diverse API keys."""
    with patch("eva.workspace.session.get_config_dir", return_value=tmp_path):
        create_workspace("deep_sec_ws")

        # Build deeply nested structure with depth 15
        nested_data = {
            "openai_sk": "sk-proj-987654321098765432109876543210",
            "dummy_entropy": "FakeTestToken1234567890AaBbCcDdEeFfGg",
            "anthropic_sk": "sk-ant-api03-abcdefghijklmnopqrstuv123456",
            "bearer_auth": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.t-IDcSemACt8x4iTMCda8Yhe3iZaWbvV5XKSTbuAn0M",
            "aws_access": "AKIAIOSFODNN7EXAMPLE",
            "nested_list": [
                "sk-listkey12345678901234567890",
                {"in_list_dict": "sk-inlistdict12345678901234567890"},
            ],
        }

        for depth in range(15):
            nested_data = {"depth_level": depth, "child": nested_data}

        metadata = {
            "meta_secret": "sk-metasecret12345678901234567890",
            "meta_token": "FakeTestToken1234567890AaBbCcDdEeFfGg",
        }

        add_history(
            "deep_sec_ws",
            "investigate",
            content=nested_data,
            metadata=metadata,
        )

        history = get_history("deep_sec_ws")
        assert len(history) == 1
        entry_str = json.dumps(history[0])

        # Assert zero plaintext secrets in saved history
        raw_secrets = [
            "sk-proj-987654321098765432109876543210",
            "FakeTestToken1234567890AaBbCcDdEeFfGg",
            "sk-ant-api03-abcdefghijklmnopqrstuv123456",
            "AKIAIOSFODNN7EXAMPLE",
            "sk-listkey12345678901234567890",
            "sk-inlistdict12345678901234567890",
            "sk-metasecret12345678901234567890",
        ]

        for s in raw_secrets:
            assert s not in entry_str, f"Defect: Raw secret leaked in deep history: {s}"

        # Assert nesting depth is preserved
        curr = history[0]["content"]
        measured_depth = 0
        while isinstance(curr, dict) and "child" in curr:
            measured_depth += 1
            curr = curr["child"]
        assert measured_depth == 15
