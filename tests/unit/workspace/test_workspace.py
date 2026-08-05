from eva.workspace.git_ops import run_git
from eva.workspace.gitignore import get_gitignore_spec, is_ignored


def test_git_ops_run_git():
    res = run_git(["version"])
    assert res.returncode == 0
    assert "git version" in res.stdout


def test_workspace_gitignore(tmp_path):
    (tmp_path / ".gitignore").write_text("build/\n*.log\n", encoding="utf-8")
    spec = get_gitignore_spec(tmp_path)

    log_file = tmp_path / "app.log"
    assert is_ignored(log_file, tmp_path, spec) is True

    src_file = tmp_path / "main.py"
    assert is_ignored(src_file, tmp_path, spec) is False
