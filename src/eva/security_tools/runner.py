from __future__ import annotations

import os
import signal
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

from eva.security.audit import append_command_audit
from eva.security.redaction import redact_secrets
from eva.security_tools.models import ToolExecutionResult
from eva.security_tools.utils import COMMAND_SUBSTITUTION_PATTERNS, SHELL_CONTROL_TOKENS, SecurityToolError


def validate_argv(argv: list[str]) -> None:
    if not argv or not all(isinstance(arg, str) and arg for arg in argv):
        raise SecurityToolError("adapter produced an empty or invalid argv")
    for arg in argv:
        if "\n" in arg or "\r" in arg:
            raise SecurityToolError("argv contains newline characters")
        if arg in SHELL_CONTROL_TOKENS:
            raise SecurityToolError(f"argv contains shell control token: {arg}")
        if any(pattern in arg for pattern in COMMAND_SUBSTITUTION_PATTERNS):
            raise SecurityToolError("argv contains command substitution syntax")


def run_tool_argv(
    *,
    adapter: str,
    operation: str,
    argv: list[str],
    cwd: Path | str,
    timeout: int,
    output_path: Path | str | None,
    dry_run: bool,
    run_id: str,
    scope_id: str | None = None,
) -> ToolExecutionResult:
    validate_argv(argv)
    started = datetime.now(timezone.utc)
    start = time.time()
    result = ToolExecutionResult(
        adapter=adapter,
        operation=operation,
        argv=argv,
        dry_run=dry_run,
        output_path=str(output_path) if output_path else None,
        started_at=started,
        finished_at=started,
        duration_s=0.0,
    )

    if dry_run:
        finished = datetime.now(timezone.utc)
        result.finished_at = finished
        result.duration_s = round(time.time() - start, 3)
        append_command_audit(
            {
                "command": "eva sec",
                "run_id": run_id,
                "scope_id": scope_id,
                "adapter": adapter,
                "operation": operation,
                "argv": argv,
                "executed": False,
                "dry_run": True,
                "timestamp": finished.isoformat(),
            }
        )
        return result

    try:
        proc = subprocess.Popen(
            argv,
            shell=False,
            cwd=str(cwd),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=(os.name == "posix"),
        )
        try:
            stdout_str, stderr_str = proc.communicate(timeout=timeout)
            finished = datetime.now(timezone.utc)
            result.return_code = proc.returncode
            result.stdout = redact_secrets(stdout_str or "")
            result.stderr = redact_secrets(stderr_str or "")
            result.finished_at = finished
            result.duration_s = round(time.time() - start, 3)
        except subprocess.TimeoutExpired:
            if os.name == "posix":
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                except OSError:
                    pass
            else:
                proc.kill()
            stdout_str, stderr_str = proc.communicate()
            finished = datetime.now(timezone.utc)
            result.timed_out = True
            result.return_code = 124
            result.stdout = redact_secrets(stdout_str or "")
            result.stderr = redact_secrets(
                f"{(stderr_str or '').strip()}\nExecution timed out after {timeout} seconds.".strip()
            )
            result.finished_at = finished
            result.duration_s = round(time.time() - start, 3)
    except FileNotFoundError:
        finished = datetime.now(timezone.utc)
        result.skipped = True
        result.missing = True
        result.return_code = 127
        result.stderr = f"{argv[0]} is not installed or not on PATH."
        result.finished_at = finished
        result.duration_s = round(time.time() - start, 3)

    append_command_audit(
        {
            "command": "eva sec",
            "run_id": run_id,
            "scope_id": scope_id,
            "adapter": adapter,
            "operation": operation,
            "argv": argv,
            "executed": not result.dry_run and not result.missing,
            "exit_status": result.return_code,
            "timed_out": result.timed_out,
            "missing": result.missing,
            "started_at": result.started_at.isoformat(),
            "finished_at": result.finished_at.isoformat(),
            "duration_s": result.duration_s,
            "artifact_path": result.output_path,
        }
    )
    return result
