from typer.testing import CliRunner

from eva.cli.app import app
from eva.config import load_config

runner = CliRunner()


def test_cli_allow_and_disallow_command(monkeypatch, tmp_path):
    cfg_file = tmp_path / "config.toml"
    monkeypatch.setattr("eva.config.config.get_config_file", lambda: cfg_file)

    # 1. allow-command
    res1 = runner.invoke(app, ["config", "allow-command", "git"])
    assert res1.exit_code == 0
    assert "Added 'git' to allowed command prefixes" in res1.output

    cfg = load_config()
    assert cfg.general.allowed_command_prefixes == ["git"]

    # 2. allow-command duplicate
    res1_dup = runner.invoke(app, ["config", "allow-command", "git"])
    assert res1_dup.exit_code == 0
    assert "already in the allowlist" in res1_dup.output

    # 3. show config includes allowlist
    res_show = runner.invoke(app, ["config", "show"])
    assert res_show.exit_code == 0
    assert "Allowed Command Prefixes" in res_show.output
    assert "git" in res_show.output

    # 4. disallow-command
    res2 = runner.invoke(app, ["config", "disallow-command", "git"])
    assert res2.exit_code == 0
    assert "Removed 'git' from allowed command prefixes" in res2.output

    cfg_after = load_config()
    assert cfg_after.general.allowed_command_prefixes == []

    # 5. disallow-command non-existent
    res2_bad = runner.invoke(app, ["config", "disallow-command", "nonexistent"])
    assert res2_bad.exit_code == 1
    assert "not in the allowlist" in res2_bad.output


def test_cli_import_allowlist(monkeypatch, tmp_path):
    cfg_file = tmp_path / "config.toml"
    monkeypatch.setattr("eva.config.config.get_config_file", lambda: cfg_file)

    import_file = tmp_path / "allowlist.txt"
    import_file.write_text("# Comment\ngit\n\nnpm\nls\n", encoding="utf-8")

    res = runner.invoke(app, ["config", "import-allowlist", str(import_file)])
    assert res.exit_code == 0
    assert "Imported 3 new allowed command prefix(es)" in res.output

    cfg = load_config()
    assert cfg.general.allowed_command_prefixes == ["git", "npm", "ls"]


def test_work_dry_run_explain(monkeypatch, tmp_path):
    cfg_file = tmp_path / "config.toml"
    monkeypatch.setattr("eva.config.config.get_config_file", lambda: cfg_file)

    # Mock dispatch imported in app module
    import eva.providers

    monkeypatch.setattr(eva.providers, "dispatch", lambda *args, **kwargs: iter(["git status"]))

    res = runner.invoke(app, ["work", "check status", "--dry-run-explain"])
    assert res.exit_code == 0
    assert "Command Safety Checks Summary" in res.output
    assert "Command Extraction" in res.output
    assert "Blast-Radius Denylist" in res.output
    assert "Command Allowlist" in res.output
    assert "Argv Syntax Parsing" in res.output
