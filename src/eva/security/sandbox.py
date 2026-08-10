import os
import shlex
import subprocess
import sys
from pathlib import Path

SAFE_ENV_VARS = {"PATH", "HOME", "USER", "LANG", "LC_ALL", "TERM", "TMPDIR", "PWD"}
if sys.platform == "win32":
    SAFE_ENV_VARS.update(
        {
            "SystemRoot",
            "WINDIR",
            "PATHEXT",
            "COMSPEC",
            "TEMP",
            "TMP",
            "USERPROFILE",
            "USERNAME",
            "LOCALAPPDATA",
            "APPDATA",
        }
    )


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
    allow_shell_features: bool = False,
) -> subprocess.CompletedProcess[str]:
    """Execute a command in a restricted sandboxed subprocess environment.

    Restricts environment variables, closes stdin, enforces timeout, and isolates execution.
    By default, executes via argv (shlex.split, shell=False). If allow_shell_features=True,
    executes via shell=True.
    """
    env = get_sandboxed_env()
    work_dir = Path(cwd) if cwd else Path.cwd()

    if allow_shell_features:
        cmd_args: str | list[str] = command
        use_shell = True
    else:
        try:
            cmd_args = shlex.split(command, posix=(sys.platform != "win32"))
            use_shell = False
        except ValueError:
            cmd_args = command
            use_shell = True

    try:
        result = subprocess.run(
            cmd_args,
            shell=use_shell,
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
