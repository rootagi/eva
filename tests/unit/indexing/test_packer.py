from eva.indexing.packer import pack_repository
from eva.indexing.tokenizer import count_tokens


def test_pack_repository_includes_small_repository_under_budget(tmp_path):
    (tmp_path / "README.md").write_text("# Example\n")
    (tmp_path / "app.py").write_text("def greet():\n    return 'hello'\n")

    result = pack_repository(tmp_path, max_tokens=10_000)

    assert result.included_files == ["README.md", "app.py"]
    assert result.excluded_files == []
    assert result.total_files_scanned == 2
    assert "--- app.py ---" in result.packed_context


def test_pack_repository_excludes_files_when_budget_is_exceeded(tmp_path):
    (tmp_path / "first.py").write_text("first_token " * 500)
    (tmp_path / "second.py").write_text("second_token " * 500)

    result = pack_repository(tmp_path, max_tokens=100)

    assert any(reason == "budget_exceeded" for _, reason in result.excluded_files)
    assert count_tokens(result.packed_context) <= 100
    assert "Repository packing omitted" in result.packed_context


def test_pack_repository_excludes_binary_files(tmp_path):
    (tmp_path / "app.py").write_text("print('hello')\n")
    (tmp_path / "asset.bin").write_bytes(b"\x00\x01\x02")

    result = pack_repository(tmp_path, max_tokens=10_000)

    assert ("asset.bin", "binary") in result.excluded_files
    assert result.included_files == ["app.py"]


def test_pack_repository_excludes_denylisted_files(tmp_path):
    (tmp_path / "app.py").write_text("print('hello')\n")
    (tmp_path / "credentials.json").write_text('{"api_key": "should-not-be-packed"}\n')

    result = pack_repository(tmp_path, max_tokens=10_000)

    assert ("credentials.json", "denylisted") in result.excluded_files
    assert "should-not-be-packed" not in result.packed_context


def test_pack_repository_keeps_tree_when_budget_excludes_files(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").write_text("application_token " * 500)
    (tmp_path / "src" / "worker.py").write_text("worker_token " * 500)

    result = pack_repository(tmp_path, max_tokens=120)

    assert "# Repository tree" in result.packed_context
    assert "src" in result.packed_context
    assert any(reason == "budget_exceeded" for _, reason in result.excluded_files)
