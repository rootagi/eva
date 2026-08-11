import json

from eva.security.audit import append_investigation_audit, verify_audit_chain


def test_append_investigation_audit_creates_valid_chain(tmp_path):
    log_file = tmp_path / "audit.jsonl"

    append_investigation_audit(
        provider="groq",
        query="What is app.py?",
        files_read=["src/app.py"],
        turns_used=3,
        stopped_reason="completed",
        log_file=log_file,
    )

    assert log_file.exists()
    lines = [json.loads(line) for line in log_file.read_text().splitlines() if line.strip()]
    assert len(lines) == 1
    assert lines[0]["command"] == "investigate"
    assert lines[0]["provider"] == "groq"
    assert lines[0]["files_read"] == ["src/app.py"]
    assert lines[0]["turns_used"] == 3
    assert lines[0]["stopped_reason"] == "completed"

    is_valid, count, _msg = verify_audit_chain(log_file)
    assert is_valid
    assert count == 1
