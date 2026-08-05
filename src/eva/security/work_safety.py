import re
import shlex
from dataclasses import dataclass

from eva.security.audit import append_command_audit, get_command_audit_log

__all__ = [
    "CommandExtractionError",
    "ParsedCommand",
    "UnsafeCommandError",
    "append_command_audit",
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


def parse_safe_command(model_output: str) -> ParsedCommand:
    command = extract_single_command(model_output)

    # Check for irreversible/blast-radius patterns
    for pattern in COMPILED_BLAST_PATTERNS:
        if pattern.search(command):
            raise UnsafeCommandError(f"Command matches blast-radius pattern: {command}")

    # Parse argv via shlex for validation
    try:
        shlex.split(command)
    except ValueError as exc:
        raise CommandExtractionError(f"Failed to parse command arguments: {exc}") from exc

    return ParsedCommand(command=command, argv=[])
