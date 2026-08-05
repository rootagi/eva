from eva.ui.formatter import is_ai_error, print_error, print_info, print_markdown, print_success, print_warning
from eva.ui.streaming import stream_response


def test_is_ai_error():
    assert is_ai_error("[Eva Error] Failed") is True
    assert is_ai_error("Error: invalid provider") is True
    assert is_ai_error("Regular response text") is False


def test_stream_response():
    chunks = iter(["Hello ", "world!"])
    res = stream_response(chunks)
    assert res == "Hello world!"


def test_formatter_prints(capsys):
    print_info("info msg")
    print_success("success msg")
    print_error("error msg")
    print_warning("warning msg")
    print_markdown("# Markdown Title", title="Test")

    captured = capsys.readouterr()
    assert captured is not None
