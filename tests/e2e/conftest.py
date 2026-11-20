import os
import subprocess
from collections.abc import Generator
from pathlib import Path

import pytest
from typer.testing import CliRunner


@pytest.fixture
def runner() -> CliRunner:
    """Typer CLI test runner."""
    return CliRunner()


@pytest.fixture
def isolated_workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Generator[Path, None, None]:
    """Isolated environment with dedicated config, data, and workspace directories."""
    config_dir = tmp_path / "config"
    data_dir = tmp_path / "data"
    workspace_dir = tmp_path / "workspace"

    config_dir.mkdir(parents=True, exist_ok=True)
    data_dir.mkdir(parents=True, exist_ok=True)
    workspace_dir.mkdir(parents=True, exist_ok=True)

    monkeypatch.setenv("EVA_CONFIG_DIR", str(config_dir))
    monkeypatch.setenv("EVA_CACHE_DIR", str(data_dir / "cache"))
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(config_dir))
    monkeypatch.setenv("XDG_DATA_HOME", str(data_dir))
    monkeypatch.setenv("EVA_OPENROUTER_API_KEY", "test-key-mock")
    monkeypatch.setenv("EVA_GROQ_API_KEY", "test-groq-mock")
    monkeypatch.setenv("EVA_GEMINI_API_KEY", "test-gemini-mock")

    cwd = os.getcwd()
    os.chdir(str(workspace_dir))
    try:
        yield workspace_dir
    finally:
        os.chdir(cwd)


@pytest.fixture
def git_repo(tmp_path: Path) -> Generator[Path, None, None]:
    """Initializes a real git repository in a temp directory."""
    repo_dir = tmp_path / "git_repo"
    repo_dir.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init"], cwd=str(repo_dir), check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["git", "config", "user.name", "Eva Tester"], cwd=str(repo_dir), check=True)
    subprocess.run(["git", "config", "user.email", "tester@eva.local"], cwd=str(repo_dir), check=True)

    test_file = repo_dir / "main.py"
    test_file.write_text("print('hello baseline')\n", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=str(repo_dir), check=True)
    subprocess.run(["git", "commit", "-m", "initial commit"], cwd=str(repo_dir), check=True, stdout=subprocess.DEVNULL)

    cwd = os.getcwd()
    os.chdir(str(repo_dir))
    try:
        yield repo_dir
    finally:
        os.chdir(cwd)
