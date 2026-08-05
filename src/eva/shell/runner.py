import subprocess


def execute_shell_command(command: str) -> subprocess.CompletedProcess[str]:
    """Execute a single shell command."""
    return subprocess.run(command, shell=True, check=False, capture_output=True, text=True)
