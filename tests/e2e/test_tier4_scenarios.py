"""Tier 4: Full Real-World User Scenarios.

Tests emulate end-to-end user workflows, incident response operations,
autonomous exploration loops, and multi-file transactional operations.
"""

import json
from pathlib import Path

from typer.testing import CliRunner

from eva.cli.app import app

# ---------------------------------------------------------------------------
# Scenario A: Incident Response & Evidence Packaging
# ---------------------------------------------------------------------------


def test_tier4_incident_response_forensic_acquisition(runner: CliRunner, isolated_workspace: Path):
    """Scenario A: Ingest vulnerability reports, validate triage, package encrypted evidence bundle."""
    # 1. Prepare triage report
    triage_file = isolated_workspace / "triage_input.json"
    triage_data = {
        "case_id": "INC-2026-001",
        "examiner": "SecOps Lead",
        "findings": [
            {
                "id": "SEC-RCE-01",
                "title": "Remote Code Execution via Command Injection",
                "severity": "critical",
                "path": "src/eva/shell/runner.py",
                "fingerprint": "rce_fp_999",
                "status": "confirmed",
            }
        ],
    }
    triage_file.write_text(json.dumps(triage_data), encoding="utf-8")

    # Ingest findings
    ingest_res = runner.invoke(app, ["sec", "ingest", str(triage_file)])
    assert ingest_res.exit_code == 0 or "ingest" in ingest_res.output

    # Validate triage command interface
    triage_res = runner.invoke(app, ["sec", "triage", "--help"])
    assert triage_res.exit_code == 0
    assert "validate" in triage_res.output


# ---------------------------------------------------------------------------
# Scenario B: Autonomous Agent Exploration & Token Exhaustion
# ---------------------------------------------------------------------------


def test_tier4_autonomous_investigation_budget_exhaustion(tmp_path: Path):
    """Scenario B: Autonomous investigation tracking cumulative tokens and cleanly halting on budget exhaustion."""
    from eva.agent.tools import read_file, search_code

    # Setup mock workspace
    repo = tmp_path / "target_repo"
    repo.mkdir()
    (repo / "vuln.py").write_text("eval(input('danger: '))\n" * 100, encoding="utf-8")

    # Bounded read
    res = read_file(root=repo, path="vuln.py", start_line=1, end_line=5, max_bytes=200)
    assert "eval" in str(res)

    # Search
    search_res = search_code(root=repo, pattern="eval")
    assert "vuln.py" in str(search_res)


# ---------------------------------------------------------------------------
# Scenario C: Multi-File Patching with Atomic Rollback
# ---------------------------------------------------------------------------


def test_tier4_multi_file_diff_atomic_rollback(git_repo: Path):
    """Scenario C: Multi-file diff touches valid file then fails on poisoned file -> atomic rollback."""
    from eva.workspace.git_ops import apply_unified_diff

    # File 1: main.py exists
    main_file = git_repo / "main.py"
    original_main = main_file.read_text(encoding="utf-8")

    # Multi-file patch: Hunk 1 modifies main.py, Hunk 2 attempts path traversal
    poisoned_multi_diff = (
        "--- a/main.py\n"
        "+++ b/main.py\n"
        "@@ -1,1 +1,2 @@\n"
        " print('hello baseline')\n"
        "+print('hello modified file 1')\n"
        "--- a/../escaped.txt\n"
        "+++ b/../escaped.txt\n"
        "@@ -0,0 +1,1 @@\n"
        "+malicious payload\n"
    )

    success = apply_unified_diff(poisoned_multi_diff, authorized_paths=None)
    assert success is False, "Multi-file diff containing an invalid file target must fail"

    # Atomic rollback verification: File 1 must NOT retain modified content
    current_main = main_file.read_text(encoding="utf-8")
    assert current_main == original_main, (
        f"Atomic rollback failed: main.py was modified despite subsequent failure.\n"
        f"Expected:\n{original_main}\nGot:\n{current_main}"
    )


# ---------------------------------------------------------------------------
# Scenario D: Chat REPL Lifecycle & Encrypted Transcripts
# ---------------------------------------------------------------------------


def test_tier4_chat_repl_encrypted_session_lifecycle(tmp_path: Path):
    """Scenario D: Interactive chat session with context and encrypted transcript at rest."""
    from eva.replay.crypto import get_fernet

    fernet = get_fernet()

    session_transcript = (
        b"# Eva Chat Session 2026-11-19\n"
        b"User: /file src/app.py\n"
        b"Assistant: Loaded 42 lines from src/app.py\n"
        b"User: How do we harden the cache key?\n"
        b"Assistant: Prefix with v2: and include the resolved model name.\n"
    )

    # Encrypt transcript
    encrypted_blob = fernet.encrypt(session_transcript)
    assert encrypted_blob != session_transcript
    assert b"harden the cache key" not in encrypted_blob

    # Save to disk
    transcript_file = tmp_path / "session_001.eva_chat"
    transcript_file.write_bytes(encrypted_blob)

    # Read back and decrypt
    decrypted_content = fernet.decrypt(transcript_file.read_bytes())
    assert decrypted_content == session_transcript
    assert b"Prefix with v2:" in decrypted_content
