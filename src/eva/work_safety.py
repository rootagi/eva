import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from eva.config import get_config_dir


@dataclass(frozen=True)
class ParsedCommand:
    command: str
    argv: list[str]


class CommandExtractionError(ValueError):
    pass


class UnsafeCommandError(ValueError):
    pass


def extract_single_command(model_output: str) -> str:
    text = model_output.strip()
    if not text:
        raise CommandExtractionError("model returned an empty command")

    if text.startswith("```"):
        match = re.fullmatch(r"```(?:[A-Za-z0-9_-]+)?\s*\n(?P<body>.*?)\n```", text, flags=re.DOTALL)
        if not match:
            raise CommandExtractionError("model output contained a malformed or trailing fenced block")
        text = match.group("body").strip()

    return text


def parse_safe_command(model_output: str) -> ParsedCommand:
    command = extract_single_command(model_output)
    return ParsedCommand(command=command, argv=[])


def get_command_audit_log() -> Path:
    return get_config_dir() / "command_audit.jsonl"


def append_command_audit(entry: dict[str, Any]):
    log_file = get_command_audit_log()
    log_file.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        **entry,
    }
    with open(log_file, "a", encoding="utf-8") as f:
        f.write(json.dumps(payload, sort_keys=True) + "\n")
