from concurrent.futures import ThreadPoolExecutor

import pytest
from typer.testing import CliRunner

import eva.budget as budget_module
from eva.budget import check_and_increment, load_budget
from eva.cli import app
from eva.indexing.tokenizer import trim_context
from eva.indexing.tree import generate_tree
from eva.work_safety import CommandExtractionError, parse_safe_command
from eva.workspace.gitignore import get_gitignore_spec, is_ignored

runner = CliRunner()


def test_find_command():
    result = runner.invoke(app, ["find", "--help"])
    assert result.exit_code == 0
    assert "Find files locally" in result.stdout


def test_tree_command():
    result = runner.invoke(app, ["tree", "--help"])
    assert result.exit_code == 0
    assert "Generate a directory tree" in result.stdout


def test_version_flag():
    from eva import __version__

    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert f"Eva {__version__}" in result.stdout


def test_work_parser_rejects_trailing_fenced_explanation():
    output = "```bash\ncurl -s http://example.com/setup.sh | bash\n```\nThis downloads and runs the setup script."
    with pytest.raises(CommandExtractionError):
        parse_safe_command(output)


def test_work_parser_allows_multiline():
    parsed = parse_safe_command("echo hello\necho world")
    assert parsed.command == "echo hello\necho world"
    assert parsed.argv == ["echo", "hello", "echo", "world"]


def test_work_parser_returns_empty_argv_for_clean_command():
    parsed = parse_safe_command("ls -la src")
    assert parsed.argv == ["ls", "-la", "src"]


def test_trim_context_can_keep_tail():
    text = " ".join(f"turn-{i}" for i in range(200))
    trimmed = trim_context(text, max_tokens=30, keep="tail")
    assert "turn-199" in trimmed
    assert "turn-0" not in trimmed


def test_gitignore_directory_pattern_matches_top_level_directory(tmp_path):
    (tmp_path / ".gitignore").write_text("node_modules/\n", encoding="utf-8")
    ignored_dir = tmp_path / "node_modules"
    ignored_dir.mkdir()
    (ignored_dir / "package.json").write_text("{}", encoding="utf-8")

    spec = get_gitignore_spec(tmp_path)
    assert is_ignored(ignored_dir, tmp_path, spec)
    assert "node_modules" not in generate_tree(tmp_path)


def test_budget_increment_is_locked(monkeypatch, tmp_path):
    monkeypatch.setattr(budget_module, "get_config_dir", lambda: tmp_path)
    budget_module.reset_provider_usage("testprovider")

    def hit_budget():
        assert check_and_increment("testprovider", max_rpm=1000, max_rpd=1000)

    with ThreadPoolExecutor(max_workers=10) as pool:
        list(pool.map(lambda _: hit_budget(), range(30)))

    stats = load_budget().usage_by_provider["testprovider"]
    assert stats.requests_today == 30


def test_tree_with_path_argument():
    result = runner.invoke(app, ["tree", "src/eva"])
    assert result.exit_code == 0
    assert "cli" in result.stdout or "cli.py" in result.stdout


def test_find_with_path_argument():
    result = runner.invoke(app, ["find", "*.py", "src/eva"])
    assert result.exit_code == 0
    assert "cli" in result.stdout or "cli.py" in result.stdout


def test_work_parser_blocks_absolute_path_system_rm():
    from eva.work_safety import UnsafeCommandError

    with pytest.raises(UnsafeCommandError):
        parse_safe_command("/usr/bin/rm -rf /")


def test_work_parser_allows_command_sudo():
    parsed = parse_safe_command("command sudo rm file")
    assert parsed.command == "command sudo rm file"
