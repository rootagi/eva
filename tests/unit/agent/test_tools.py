from eva.agent.tools import list_directory, read_file, search_code


def test_list_directory_excludes_denylisted_and_gitignored_files(tmp_path):
    (tmp_path / ".gitignore").write_text("ignored.txt\n")
    (tmp_path / "app.py").write_text("print('hello')\n")
    (tmp_path / ".env").write_text("SECRET=123\n")
    (tmp_path / "ignored.txt").write_text("should be ignored\n")

    entries = list_directory(tmp_path)
    entry_names = [e["name"] for e in entries]

    assert "app.py" in entry_names
    assert ".env" not in entry_names
    assert "ignored.txt" not in entry_names


def test_read_file_rejects_path_traversal_outside_root(tmp_path):
    (tmp_path / "app.py").write_text("print('hello')\n")

    res_rel = read_file(tmp_path, "../../etc/passwd")
    assert not res_rel.success
    assert "Path traversal" in res_rel.error

    res_abs = read_file(tmp_path, "/etc/passwd")
    assert not res_abs.success
    assert "Path traversal" in res_abs.error


def test_read_file_rejects_denylisted_file(tmp_path):
    (tmp_path / ".env").write_text("SECRET=123\n")

    res = read_file(tmp_path, ".env")
    assert not res.success
    assert "excluded for security reasons" in res.error


def test_read_file_redacts_secrets_in_content(tmp_path):
    secret_key = "sk-123456789012345678901234567890"
    (tmp_path / "config.py").write_text(f"API_KEY = '{secret_key}'\n")

    res = read_file(tmp_path, "config.py")
    assert res.success
    assert secret_key not in res.content
    assert "[REDACTED_" in res.content


def test_search_code_respects_result_cap(tmp_path):
    lines = "\n".join([f"target_token_line_{i}" for i in range(100)])
    (tmp_path / "large.py").write_text(lines)

    results = search_code(tmp_path, "target_token", max_results=10)
    assert len(results) == 10
