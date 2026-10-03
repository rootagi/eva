from typing import Any

__all__ = [
    "BLAST_RADIUS_PATTERNS",
    "DENYLIST_PATTERNS",
    "AllowlistViolationError",
    "CommandExtractionError",
    "ParsedCommand",
    "UnsafeCommandError",
    "append_command_audit",
    "check_command_allowlist",
    "compute_entry_hash",
    "explain_safety_checks",
    "extract_single_command",
    "get_command_audit_log",
    "get_sandboxed_env",
    "is_sensitive_file",
    "parse_safe_command",
    "redact_secrets",
    "run_sandboxed",
    "verify_audit_chain",
]

_LAZY_IMPORTS: dict[str, tuple[str, str]] = {
    "compute_entry_hash": ("eva.security.audit", "compute_entry_hash"),
    "verify_audit_chain": ("eva.security.audit", "verify_audit_chain"),
    "redact_secrets": ("eva.security.redaction", "redact_secrets"),
    "get_sandboxed_env": ("eva.security.sandbox", "get_sandboxed_env"),
    "run_sandboxed": ("eva.security.sandbox", "run_sandboxed"),
    "DENYLIST_PATTERNS": ("eva.security.sensitive_files", "DENYLIST_PATTERNS"),
    "is_sensitive_file": ("eva.security.sensitive_files", "is_sensitive_file"),
    "BLAST_RADIUS_PATTERNS": ("eva.security.work_safety", "BLAST_RADIUS_PATTERNS"),
    "AllowlistViolationError": ("eva.security.work_safety", "AllowlistViolationError"),
    "CommandExtractionError": ("eva.security.work_safety", "CommandExtractionError"),
    "ParsedCommand": ("eva.security.work_safety", "ParsedCommand"),
    "UnsafeCommandError": ("eva.security.work_safety", "UnsafeCommandError"),
    "append_command_audit": ("eva.security.work_safety", "append_command_audit"),
    "check_command_allowlist": ("eva.security.work_safety", "check_command_allowlist"),
    "explain_safety_checks": ("eva.security.work_safety", "explain_safety_checks"),
    "extract_single_command": ("eva.security.work_safety", "extract_single_command"),
    "get_command_audit_log": ("eva.security.work_safety", "get_command_audit_log"),
    "parse_safe_command": ("eva.security.work_safety", "parse_safe_command"),
}


def __getattr__(name: str) -> Any:
    if name in _LAZY_IMPORTS:
        import importlib

        mod_name, attr_name = _LAZY_IMPORTS[name]
        mod = importlib.import_module(mod_name)
        return getattr(mod, attr_name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
