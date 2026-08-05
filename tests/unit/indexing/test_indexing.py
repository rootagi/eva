from eva.indexing.finder import find_files
from eva.indexing.io import read_text_file_for_context
from eva.indexing.tokenizer import count_tokens, trim_context
from eva.indexing.tree import generate_tree


def test_indexing_tree_and_finder(tmp_path):
    (tmp_path / "a.py").write_text("print(1)\n", encoding="utf-8")
    (tmp_path / "b.txt").write_text("hello\n", encoding="utf-8")

    tree = generate_tree(tmp_path)
    assert "a.py" in tree
    assert "b.txt" in tree

    py_files = list(find_files(tmp_path, "*.py"))
    assert len(py_files) == 1
    assert py_files[0].name == "a.py"


def test_indexing_io_and_tokenizer(tmp_path):
    f = tmp_path / "sample.py"
    f.write_text("def foo(): pass\n", encoding="utf-8")

    text, warnings = read_text_file_for_context(f)
    assert "def foo" in text
    assert len(warnings) == 0

    tokens = count_tokens(text)
    assert tokens > 0

    trimmed = trim_context("long text string" * 50, max_tokens=5, keep="head")
    assert "[Context Trimmed]" in trimmed
