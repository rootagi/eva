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


def test_run_sandboxed_argv_vs_shell(tmp_path):
    # Without allow_shell_features, pipes are literal arguments to echo (not evaluated by shell)
    res_argv = run_sandboxed("echo hello | grep hello", cwd=tmp_path, allow_shell_features=False)
    assert res_argv.returncode == 0
    assert "|" in res_argv.stdout  # argv echo receives '|', 'grep', 'hello' as string args

    # With allow_shell_features, shell evaluates the pipe
    res_shell = run_sandboxed("echo hello | grep hello", cwd=tmp_path, allow_shell_features=True)
    assert res_shell.returncode == 0
    assert res_shell.stdout.strip() == "hello"


def test_run_sandboxed_timeout(tmp_path):
    res = run_sandboxed("sleep 2", cwd=tmp_path, timeout=0.1)
    assert res.returncode == 124
    assert "timed out" in res.stderr


def test_sandbox_opt_in_config_default():
    config = AppConfig()
    # Verified opt-in: False by default
    assert config.general.sandbox_risky_commands is False
