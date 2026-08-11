import subprocess
from pathlib import Path

from eva.security.sandbox import run_sandboxed


def execute_shell_command(
    command: str, cwd: Path | str | None = None, timeout: float = 30.0
) -> subprocess.CompletedProcess[str]:
    """Execute a single shell command inside a sandboxed environment."""
    return run_sandboxed(command, cwd=cwd, timeout=timeout, allow_shell_features=True)
