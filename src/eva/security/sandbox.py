import os
import subprocess
import tempfile
from pathlib import Path

SAFE_ENV_VARS = {"PATH", "HOME", "USER", "LANG", "LC_ALL", "TERM", "TMPDIR", "PWD"}


def get_sandboxed_env() -> dict[str, str]:
    """Construct a stripped, restricted environment dictionary."""
    env = {}
    for var in SAFE_ENV_VARS:
        val = os.getenv(var)
        if val is not None:
            env[var] = val
    env["EVA_SANDBOX"] = "1"
    return env


def run_sandboxed(
    command: str,
    *,
    cwd: Path | str | None = None,
    timeout: float = 30.0,
) -> subprocess.CompletedProcess[str]:
    """Execute a command in a restricted sandboxed subprocess environment.

    Restricts environment variables, closes stdin, enforces timeout, and isolates execution.
    """
    env = get_sandboxed_env()
    work_dir = Path(cwd) if cwd else Path.cwd()

    try:
        result = subprocess.run(
            command,
            shell=True,
            cwd=str(work_dir),
            env=env,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return result
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout.decode("utf-8", errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        stderr = (
            exc.stderr.decode("utf-8", errors="replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        ) + f"\n[Eva Sandbox] Execution timed out after {timeout} seconds."
        return subprocess.CompletedProcess(
            args=command,
            returncode=124,
            stdout=stdout,
            stderr=stderr,
        )
