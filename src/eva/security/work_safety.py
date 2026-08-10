import re
import shlex
import sys
from dataclasses import dataclass
from typing import Any

from eva.security.audit import append_command_audit, get_command_audit_log

__all__ = [
    "AllowlistViolationError",
    "CommandExtractionError",
    "ParsedCommand",
    "UnsafeCommandError",
    "append_command_audit",
    "check_command_allowlist",
    "explain_safety_checks",
    "extract_single_command",
    "get_command_audit_log",
    "parse_safe_command",
]


@dataclass(frozen=True)
class ParsedCommand:
    command: str
    argv: list[str]


class CommandExtractionError(ValueError):
    pass


class UnsafeCommandError(ValueError):
    pass


class AllowlistViolationError(UnsafeCommandError):
    pass


# Irreversible / blast-radius patterns (hard-blocked by default)
BLAST_RADIUS_PATTERNS = [
    # Recursive delete on system paths
    r"\brm\s+-[a-zA-Z]*r[a-zA-Z]*\s+(/|/\*|/bin|/sbin|/usr|/etc|/var|/home|/root|/boot|/sys|/proc|/dev)(\s+|$)",
    r"\brm\s+-[a-zA-Z]*\s+-[a-zA-Z]*\s+(/|/\*|/bin|/sbin|/usr|/etc|/var|/home|/root|/boot|/sys|/proc|/dev)(\s+|$)",
    r"\brm\s+-[a-zA-Z]*r[a-zA-Z]*f?\s+--no-preserve-root\b",
    # Disk formatting
    r"\bmkfs(\.[a-zA-Z0-9]+)?\b",
    r"\bmke2fs\b",
    # Direct writes to block devices
    r"\bdd\s+.*of=/dev/(sd[a-z][0-9]?|nvme[0-9]n[0-9](p[0-9])?|hd[a-z][0-9]?|vd[a-z][0-9]?|loop[0-9]+)\b",
    # Piping a remote script straight into a shell (curl|bash, wget|sh, etc.)
    r"\b(curl|wget|fetch)\b.*\|\s*(sudo\s+)?(bash|sh|zsh|dash|ksh)\b",
    # Fork bombs
    r":\(\)\s*\{\s*:\|:&\s*\};:",
    r":\(\)\{:\|\:&?\};:",
    # Recursive chown/chmod on system paths
    r"\b(chmod|chown)\s+(-[a-zA-Z]*R[a-zA-Z]*)\s+.*\s+(/|/\*|/bin|/sbin|/usr|/etc|/var|/home|/root|/boot|/sys|/proc|/dev)(\s+|$)",
]

COMPILED_BLAST_PATTERNS = [re.compile(pattern, re.IGNORECASE) for pattern in BLAST_RADIUS_PATTERNS]


def extract_single_command(model_output: str) -> str:
    text = model_output.strip()
    if not text:
        raise CommandExtractionError("model returned an empty command")

    if text.startswith("```"):
        match = re.fullmatch(r"```(?:[A-Za-z0-9_-]+)?\s*\n(?P<body>.*?)\n```", text, flags=re.DOTALL)
        if not match:
            raise CommandExtractionError("model output contained a malformed or trailing fenced block")
        text = match.group("body").strip()
    elif "```" in text:
        raise CommandExtractionError("model output contained an inline or malformed code block")

    return text


def check_command_allowlist(command: str, allowed_prefixes: list[str] | None) -> None:
    """Validate that command starts with one of the allowed prefixes if allowlist is active."""
    if not allowed_prefixes:
        return

    cmd = command.strip()
    if not any(cmd.startswith(prefix) for prefix in allowed_prefixes):
        raise AllowlistViolationError(f"Command '{cmd}' does not match any allowed prefix in {allowed_prefixes}")


def parse_safe_command(model_output: str, allowed_prefixes: list[str] | None = None) -> ParsedCommand:
    command = extract_single_command(model_output)

    # Check for irreversible/blast-radius patterns
    for pattern in COMPILED_BLAST_PATTERNS:
        if pattern.search(command):
            raise UnsafeCommandError(f"Command matches blast-radius pattern: {command}")

    # Check allowlist if configured
    if allowed_prefixes:
        check_command_allowlist(command, allowed_prefixes)

    # Parse argv via shlex for validation
    try:
        argv = shlex.split(command, posix=(sys.platform != "win32"))
    except ValueError as exc:
        raise CommandExtractionError(f"Failed to parse command arguments: {exc}") from exc

    return ParsedCommand(command=command, argv=argv)


def explain_safety_checks(model_output: str, allowed_prefixes: list[str] | None = None) -> list[dict[str, Any]]:
    """Perform transparency inspection of all safety checks on model output."""
    checks = []

    # 1. Extraction
    try:
        command = extract_single_command(model_output)
        checks.append({"check": "Command Extraction", "passed": True, "detail": f"Extracted command: {command}"})
    except CommandExtractionError as exc:
        checks.append({"check": "Command Extraction", "passed": False, "detail": str(exc)})
        return checks

    # 2. Blast-radius denylist
    matched_pattern = None
    for pattern in COMPILED_BLAST_PATTERNS:
        if pattern.search(command):
            matched_pattern = pattern.pattern
            break
    if matched_pattern:
        checks.append(
            {"check": "Blast-Radius Denylist", "passed": False, "detail": f"Matched pattern: {matched_pattern}"}
        )
    else:
        checks.append({"check": "Blast-Radius Denylist", "passed": True, "detail": "No blast-radius patterns matched."})

    # 3. Allowlist
    if not allowed_prefixes:
        checks.append(
            {"check": "Command Allowlist", "passed": True, "detail": "Allowlist disabled (no prefixes configured)."}
        )
    else:
        cmd_str = command.strip()
        matched_prefix = next((p for p in allowed_prefixes if cmd_str.startswith(p)), None)
        if matched_prefix:
            checks.append(
                {"check": "Command Allowlist", "passed": True, "detail": f"Matched allowed prefix: '{matched_prefix}'"}
            )
        else:
            checks.append(
                {
                    "check": "Command Allowlist",
                    "passed": False,
                    "detail": f"Command '{cmd_str}' does not match any allowed prefix in {allowed_prefixes}",
                }
            )

    # 4. shlex argument parsing
    try:
        argv = shlex.split(command, posix=(sys.platform != "win32"))
        checks.append(
            {"check": "Argv Syntax Parsing", "passed": True, "detail": f"Parsed argv ({len(argv)} tokens): {argv}"}
        )
    except ValueError as exc:
        checks.append({"check": "Argv Syntax Parsing", "passed": False, "detail": f"shlex split failed: {exc}"})

    return checks
