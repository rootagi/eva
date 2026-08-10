import logging
from unittest.mock import patch

import pytest

from eva.indexing.tokenizer import (
    count_tokens,
    reset_encoding_cache,
    trim_context,
)


@pytest.fixture(autouse=True)
def _clear_encoding_cache():
    """Reset the module-level encoding cache before and after each test."""
    reset_encoding_cache()
    yield
    reset_encoding_cache()


class TestOfflineFallback:
    """Verify graceful degradation when tiktoken cannot download the encoding."""

    def test_count_tokens_falls_back_to_approximation(self):
        text = "hello world, this is a test"
        with patch("eva.indexing.tokenizer.tiktoken.get_encoding", side_effect=Exception("network down")):
            result = count_tokens(text)
        assert result == len(text) // 4

    def test_trim_context_head_falls_back(self):
        text = "a" * 100
        with patch("eva.indexing.tokenizer.tiktoken.get_encoding", side_effect=Exception("network down")):
            trimmed = trim_context(text, max_tokens=5, keep="head")
        # 5 tokens * 4 chars = 20 chars kept, plus the trimmed marker
        assert trimmed.startswith("a" * 20)
        assert "...[Context Trimmed]..." in trimmed

    def test_trim_context_tail_falls_back(self):
        text = "b" * 100
        with patch("eva.indexing.tokenizer.tiktoken.get_encoding", side_effect=Exception("network down")):
            trimmed = trim_context(text, max_tokens=5, keep="tail")
        assert "...[Context Trimmed]..." in trimmed
        # Tail portion should be 20 chars
        tail_part = trimmed.split("...[Context Trimmed]...\n")[1]
        assert len(tail_part) == 20

    def test_short_text_not_trimmed_in_fallback(self):
        text = "short"
        with patch("eva.indexing.tokenizer.tiktoken.get_encoding", side_effect=Exception("network down")):
            trimmed = trim_context(text, max_tokens=100, keep="head")
        assert trimmed == text

    def test_no_crash_on_any_exception_type(self):
        """Ensure we handle all exception types, not just a narrow set."""
        exceptions = [
            ConnectionError("refused"),
            OSError("DNS failure"),
            RuntimeError("SSL handshake failed"),
            Exception("unexpected"),
        ]
        for exc in exceptions:
            reset_encoding_cache()
            with patch("eva.indexing.tokenizer.tiktoken.get_encoding", side_effect=exc):
                result = count_tokens("test text")
            assert isinstance(result, int)


class TestWarningLogging:
    """Verify the degradation warning is logged exactly once."""

    def test_warning_logged_once(self, caplog):
        with (
            patch("eva.indexing.tokenizer.tiktoken.get_encoding", side_effect=Exception("offline")),
            caplog.at_level(logging.WARNING, logger="eva.indexing.tokenizer"),
        ):
            count_tokens("first call")
            count_tokens("second call")
            count_tokens("third call")

        warning_messages = [r for r in caplog.records if r.levelno == logging.WARNING]
        assert len(warning_messages) == 1
        assert "approximate" in warning_messages[0].message.lower()


class TestCustomEncodingPath:
    """Verify EVA_TIKTOKEN_ENCODING_PATH is respected."""

    def test_custom_path_used(self, tmp_path, monkeypatch):
        """When EVA_TIKTOKEN_ENCODING_PATH is set and valid, tiktoken.get_encoding is not called."""
        import base64

        fake_encoding = tmp_path / "fake.tiktoken"
        # Build a minimal BPE vocab covering individual bytes so any
        # ASCII input can be encoded (one token per byte).
        lines = []
        for i in range(256):
            b64 = base64.b64encode(bytes([i])).decode()
            lines.append(f"{b64} {i}")
        fake_encoding.write_text("\n".join(lines), encoding="utf-8")

        monkeypatch.setenv("EVA_TIKTOKEN_ENCODING_PATH", str(fake_encoding))

        with patch("eva.indexing.tokenizer.tiktoken.get_encoding") as mock_get:
            # Should load from file, not call get_encoding
            result = count_tokens("hello world")
            mock_get.assert_not_called()
        assert isinstance(result, int)
        assert result > 0

    def test_bad_custom_path_falls_through(self, monkeypatch):
        """A bad path should fall through to tiktoken.get_encoding."""
        monkeypatch.setenv("EVA_TIKTOKEN_ENCODING_PATH", "/nonexistent/path.tiktoken")

        with patch("eva.indexing.tokenizer.tiktoken.get_encoding", side_effect=Exception("offline")):
            # Should degrade to approximation without crashing
            result = count_tokens("test")
        assert result == len("test") // 4
