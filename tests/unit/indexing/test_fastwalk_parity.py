from pathlib import Path

from eva.indexing.finder import find_files_python_fallback
from eva.indexing.tree import generate_tree

try:
    import eva_fastwalk

    HAS_RUST = True
except ImportError:
    HAS_RUST = False


def _setup_test_repo(tmp_path: Path):
    (tmp_path / "README.md").write_text("# Project", encoding="utf-8")
    src = tmp_path / "src"
    src.mkdir()
    (src / "main.py").write_text("print('main')", encoding="utf-8")
    (src / "utils.py").write_text("print('utils')", encoding="utf-8")

    git = tmp_path / ".git"
    git.mkdir()
    (git / "config").write_text("[core]", encoding="utf-8")

    node = tmp_path / "node_modules" / "pkg"
    node.mkdir(parents=True)
    (node / "index.js").write_text("module.exports = {}", encoding="utf-8")

    target = tmp_path / "target" / "debug"
    target.mkdir(parents=True)
    (target / "app.bin").write_text("bin", encoding="utf-8")
    (target / "output.txt").write_text("txt", encoding="utf-8")

    docs = tmp_path / "docs"
    docs.mkdir()
    (docs / "guide.md").write_text("# Guide", encoding="utf-8")

    eva = tmp_path / ".eva"
    eva.mkdir()
    (eva / "context.md").write_text("# Context", encoding="utf-8")


def test_parity_defaults(tmp_path: Path):
    _setup_test_repo(tmp_path)
    py_files = {p.relative_to(tmp_path).as_posix() for p in find_files_python_fallback(tmp_path, "*")}
    expected = {"README.md", "src/main.py", "src/utils.py", "docs/guide.md"}
    assert py_files == expected

    if HAS_RUST:
        rust_raw = eva_fastwalk.fast_find_files(str(tmp_path), "*")
        rust_files = {Path(p).relative_to(tmp_path).as_posix() for p in rust_raw}
        assert rust_files == py_files


def test_parity_unignore(tmp_path: Path):
    _setup_test_repo(tmp_path)
    py_files = {
        p.relative_to(tmp_path).as_posix() for p in find_files_python_fallback(tmp_path, "*", unignore=["target"])
    }
    assert "target/debug/app.bin" in py_files
    assert "target/debug/output.txt" in py_files
    assert "node_modules/pkg/index.js" not in py_files
    assert ".git/config" not in py_files

    if HAS_RUST:
        rust_raw = eva_fastwalk.fast_find_files(str(tmp_path), "*", unignore=["target"])
        rust_files = {Path(p).relative_to(tmp_path).as_posix() for p in rust_raw}
        assert rust_files == py_files


def test_parity_extra_ignored(tmp_path: Path):
    _setup_test_repo(tmp_path)
    py_files = {
        p.relative_to(tmp_path).as_posix() for p in find_files_python_fallback(tmp_path, "*", extra_ignored=["docs"])
    }
    assert "docs/guide.md" not in py_files
    assert "src/main.py" in py_files

    if HAS_RUST:
        rust_raw = eva_fastwalk.fast_find_files(str(tmp_path), "*", extra_ignored=["docs"])
        rust_files = {Path(p).relative_to(tmp_path).as_posix() for p in rust_raw}
        assert rust_files == py_files


def test_parity_pattern_filter(tmp_path: Path):
    _setup_test_repo(tmp_path)
    py_files = {p.relative_to(tmp_path).as_posix() for p in find_files_python_fallback(tmp_path, "*.py")}
    assert py_files == {"src/main.py", "src/utils.py"}

    if HAS_RUST:
        rust_raw = eva_fastwalk.fast_find_files(str(tmp_path), "*.py")
        rust_files = {Path(p).relative_to(tmp_path).as_posix() for p in rust_raw}
        assert rust_files == py_files


def test_parity_tree_generation(tmp_path: Path):
    _setup_test_repo(tmp_path)
    tree_default = generate_tree(tmp_path)
    assert "src" in tree_default
    assert "main.py" in tree_default
    assert "target" not in tree_default
    assert "node_modules" not in tree_default

    tree_unignored = generate_tree(tmp_path, unignore=["target"])
    assert "target" in tree_unignored
    assert "app.bin" in tree_unignored
