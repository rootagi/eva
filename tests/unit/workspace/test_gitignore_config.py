from pathlib import Path

from eva.indexing.finder import find_files
from eva.indexing.packer import pack_repository
from eva.indexing.tree import generate_tree
from eva.workspace.gitignore import (
    configure_ignored_dirs,
    is_ignored,
)


def test_gitignore_config_defaults(tmp_path: Path):
    try:
        configure_ignored_dirs(extra=[], unignore=[])
        target_file = tmp_path / "target" / "output.bin"
        target_file.parent.mkdir()
        target_file.write_text("data", encoding="utf-8")

        assert is_ignored(target_file, tmp_path, None) is True
    finally:
        configure_ignored_dirs(extra=[], unignore=[])


def test_gitignore_config_unignore(tmp_path: Path):
    try:
        configure_ignored_dirs(extra=[], unignore=["target"])
        target_file = tmp_path / "target" / "output.txt"
        target_file.parent.mkdir(parents=True, exist_ok=True)
        target_file.write_text("unignored text", encoding="utf-8")

        assert is_ignored(target_file, tmp_path, None) is False

        found = list(find_files(tmp_path, "*.txt"))
        assert any(f.name == "output.txt" for f in found)

        pack_res = pack_repository(tmp_path, max_tokens=1000)
        assert any("target/output.txt" in f for f in pack_res.included_files)
    finally:
        configure_ignored_dirs(extra=[], unignore=[])


def test_gitignore_config_extra_ignore(tmp_path: Path):
    try:
        scratch_dir = tmp_path / "scratch"
        scratch_dir.mkdir(parents=True, exist_ok=True)
        scratch_file = scratch_dir / "temp.txt"
        scratch_file.write_text("temp", encoding="utf-8")

        configure_ignored_dirs(extra=["scratch"], unignore=[])
        assert is_ignored(scratch_file, tmp_path, None) is True

        tree = generate_tree(tmp_path)
        assert "scratch" not in tree
    finally:
        configure_ignored_dirs(extra=[], unignore=[])


def test_eva_dir_ignored_by_default(tmp_path: Path):
    try:
        configure_ignored_dirs(extra=[], unignore=[])
        eva_dir = tmp_path / ".eva"
        eva_dir.mkdir(parents=True, exist_ok=True)
        ctx_file = eva_dir / "context.md"
        ctx_file.write_text("# Context", encoding="utf-8")

        assert is_ignored(ctx_file, tmp_path, None) is True

        pack_res = pack_repository(tmp_path, max_tokens=1000)
        assert not any(".eva" in f for f in pack_res.included_files)
    finally:
        configure_ignored_dirs(extra=[], unignore=[])
