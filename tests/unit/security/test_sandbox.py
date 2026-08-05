from eva.config import AppConfig
from eva.security.sandbox import get_sandboxed_env, run_sandboxed


def test_sandbox_env_stripping(monkeypatch):
    monkeypatch.setenv("SECRET_TOKEN", "super_secret_123")
    monkeypatch.setenv("PATH", "/usr/bin:/bin")

    env = get_sandboxed_env()

    assert "SECRET_TOKEN" not in env
    assert "PATH" in env
    assert env["EVA_SANDBOX"] == "1"


def test_run_sandboxed_basic_command(tmp_path):
    res = run_sandboxed("echo 'hello sandbox'", cwd=tmp_path)
    assert res.returncode == 0
    assert "hello sandbox" in res.stdout


def test_run_sandboxed_timeout(tmp_path):
    res = run_sandboxed("sleep 2", cwd=tmp_path, timeout=0.1)
    assert res.returncode == 124
    assert "timed out" in res.stderr


def test_sandbox_opt_in_config_default():
    config = AppConfig()
    # Verified opt-in: False by default
    assert config.general.sandbox_risky_commands is False
