"""Tests for disk-backed response caching integration in dispatch()."""

from importlib import import_module
from unittest.mock import patch

from typer.testing import CliRunner

from eva.cli.app import app
from eva.config import AppConfig
from eva.providers import dispatch

app_module = import_module("eva.cli.app")
runner = CliRunner()


def _make_config() -> AppConfig:
    return AppConfig()


class TestDispatchCaching:
    """Test caching integration in dispatch()."""

    def test_dispatch_caches_response_second_call_skips_provider(self):
        """Calling dispatch() twice with identical args only invokes the provider once."""
        config = _make_config()
        call_count = 0

        def counting_call_provider(provider, system_prompt, user_prompt, context, config):
            nonlocal call_count
            call_count += 1
            yield "cached answer"

        with patch("eva.providers.call_provider", side_effect=counting_call_provider):
            # First call — should invoke the provider
            result1 = "".join(dispatch("sys", "user", "ctx", config, use_cache=True))
            assert result1 == "cached answer"
            assert call_count == 1

            # Second call — should come from cache
            result2 = "".join(dispatch("sys", "user", "ctx", config, use_cache=True))
            assert result2 == "cached answer"
            assert call_count == 1  # Provider NOT called again

    def test_dispatch_no_cache_always_calls_provider(self):
        """use_cache=False always invokes the provider, even on a repeated call."""
        config = _make_config()
        call_count = 0

        def counting_call_provider(provider, system_prompt, user_prompt, context, config):
            nonlocal call_count
            call_count += 1
            yield "uncached answer"

        with patch("eva.providers.call_provider", side_effect=counting_call_provider):
            result1 = "".join(dispatch("sys", "user", "ctx", config, use_cache=False))
            assert result1 == "uncached answer"
            assert call_count == 1

            result2 = "".join(dispatch("sys", "user", "ctx", config, use_cache=False))
            assert result2 == "uncached answer"
            assert call_count == 2  # Provider called again

    def test_dispatch_error_response_not_cached(self):
        """A response satisfying is_ai_error() is never written to the cache."""
        config = _make_config()
        call_count = 0

        def error_call_provider(provider, system_prompt, user_prompt, context, config):
            nonlocal call_count
            call_count += 1
            yield "[Eva Error] Something went wrong"

        with patch("eva.providers.call_provider", side_effect=error_call_provider):
            result1 = "".join(dispatch("sys", "user", "ctx", config, use_cache=True))
            assert "[Eva Error]" in result1
            assert call_count == 1

            # Second call should NOT be cached — provider called again
            result2 = "".join(dispatch("sys", "user", "ctx", config, use_cache=True))
            assert "[Eva Error]" in result2
            assert call_count == 2


class TestAskNoCacheFlag:
    """Test --no-cache flag on the ask CLI command."""

    def test_ask_no_cache_flag(self):
        """--no-cache passes use_cache=False to dispatch."""
        with patch.object(app_module, "dispatch", return_value=iter(["answer"])) as mock_dispatch:
            res = runner.invoke(app, ["ask", "hello", "--no-cache"])
            assert res.exit_code == 0
            # Verify use_cache=False was passed
            _, kwargs = mock_dispatch.call_args
            assert kwargs.get("use_cache") is False

    def test_ask_default_uses_cache(self):
        """Without --no-cache, use_cache defaults to True."""
        with patch.object(app_module, "dispatch", return_value=iter(["answer"])) as mock_dispatch:
            res = runner.invoke(app, ["ask", "hello"])
            assert res.exit_code == 0
            _, kwargs = mock_dispatch.call_args
            assert kwargs.get("use_cache") is True
