import json

from eva.security.audit import (
    append_command_audit,
    verify_audit_chain,
)


def test_audit_chain_validity(tmp_path):
    log_file = tmp_path / "command_audit.jsonl"

    entries = [
        {"query": "ls -la", "executed": True},
        {"query": "git status", "executed": True},
        {"query": "rm -rf /", "executed": False, "blocked_reason": "unsafe_command"},
    ]

    for entry in entries:
        append_command_audit(entry, log_file=log_file)

    is_valid, count, msg = verify_audit_chain(log_file)
    assert is_valid is True
    assert count == 3
    assert "verified successfully" in msg


def test_audit_chain_tampering_detection(tmp_path):
    log_file = tmp_path / "command_audit.jsonl"

    entries = [
        {"query": "ls -la", "executed": True},
        {"query": "cat secret.txt", "executed": True},
        {"query": "echo hello", "executed": True},
    ]

    for entry in entries:
        append_command_audit(entry, log_file=log_file)

    # Mutate the second line (tamper with content)
    lines = log_file.read_text(encoding="utf-8").splitlines()
    data = json.loads(lines[1])
    data["query"] = "cat modified_secret.txt"  # Tampered
    lines[1] = json.dumps(data)
    log_file.write_text("\n".join(lines) + "\n", encoding="utf-8")

    # Verify that tampering is detected
    is_valid, count, msg = verify_audit_chain(log_file)
    assert is_valid is False
    assert count == 1  # Only sequence 1 was valid
    assert "Hash signature mismatch" in msg or "Previous hash mismatch" in msg


def test_audit_chain_redacts_secrets(tmp_path):
    log_file = tmp_path / "command_audit.jsonl"

    entry = {"query": "echo sk-1234567890123456789012345678901234567890", "executed": True}
    append_command_audit(entry, log_file=log_file)

    content = log_file.read_text(encoding="utf-8")
    assert "sk-1234567890123456789012345678901234567890" not in content
    assert "REDACTED" in content

    is_valid, count, _ = verify_audit_chain(log_file)
    assert is_valid is True
    assert count == 1
