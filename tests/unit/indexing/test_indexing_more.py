import pytest

from eva.indexing.io import ContextReadError, read_text_file_for_context
from eva.indexing.tokenizer import trim_context


def test_io_errors(tmp_path):
    nonexistent = tmp_path / "does_not_exist.txt"
    with pytest.raises(ContextReadError, match="does not exist"):
        read_text_file_for_context(nonexistent)

    directory = tmp_path / "somedir"
    directory.mkdir()
    with pytest.raises(ContextReadError, match="not a regular file"):
        read_text_file_for_context(directory)

    binary_file = tmp_path / "binary.bin"
    binary_file.write_bytes(b"hello \x00 world")
    with pytest.raises(ContextReadError, match="binary"):
        read_text_file_for_context(binary_file)

    large_file = tmp_path / "large.txt"
    large_file.write_text("A" * 50, encoding="utf-8")
    text, warnings = read_text_file_for_context(large_file, max_bytes=10)
    assert len(text) == 10
    assert len(warnings) == 1


def test_trim_context_tail(tmp_path):
    text = "line1\nline2\nline3\nline4\n"
    trimmed = trim_context(text, max_tokens=2, keep="tail")
    assert "...[Context Trimmed]..." in trimmed

    with pytest.raises(ValueError, match="keep must be 'head' or 'tail'"):
        trim_context(text, max_tokens=2, keep="invalid")
