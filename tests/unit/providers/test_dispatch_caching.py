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

    def test_dispatch_cache_diverges_across_models_under_same_provider(self):
        """Switching models under the same provider must produce different cache keys and not return stale cache."""
        config1 = _make_config()
        config1.general.default_provider = "groq"
        config1.providers["groq"].model = "llama-3.1-8b-instant"

        config2 = _make_config()
        config2.general.default_provider = "groq"
        config2.providers["groq"].model = "llama-3.3-70b-versatile"

        call_history: list[str] = []

        def tracking_call_provider(provider, system_prompt, user_prompt, context, config):
            call_history.append(config.providers[provider.name].model)
            yield f"answer-from-{config.providers[provider.name].model}"

        with patch("eva.providers.call_provider", side_effect=tracking_call_provider):
            res1 = "".join(dispatch("sys", "user", "ctx", config1, use_cache=True))
            assert res1 == "answer-from-llama-3.1-8b-instant"
            assert call_history == ["llama-3.1-8b-instant"]

            # Same provider, different model: must NOT return cached answer from first model
            res2 = "".join(dispatch("sys", "user", "ctx", config2, use_cache=True))
            assert res2 == "answer-from-llama-3.3-70b-versatile"
            assert call_history == ["llama-3.1-8b-instant", "llama-3.3-70b-versatile"]

            # Same provider, same model: hits cache
            res3 = "".join(dispatch("sys", "user", "ctx", config1, use_cache=True))
            assert res3 == "answer-from-llama-3.1-8b-instant"
            assert len(call_history) == 2  # Cached, no new call

    def test_dispatch_cache_fallback_cached_under_actual_provider(self):
        """When fallback occurs, result is cached under the provider actually used, not the initial one."""
        config = _make_config()
        config.general.default_provider = "groq"
        config.general.fallback_enabled = True
        config.general.fallback_order = ["gemini"]

        from eva.providers import QuotaExhaustedError

        call_count = 0

        def fallback_call_provider(provider, system_prompt, user_prompt, context, config):
            nonlocal call_count
            call_count += 1
            if provider.name == "groq":
                raise QuotaExhaustedError("Groq quota exceeded")
            yield "fallback-gemini-answer"

        with patch("eva.providers.call_provider", side_effect=fallback_call_provider):
            res = "".join(dispatch("sys", "user", "ctx", config, use_cache=True))
            assert res == "fallback-gemini-answer"
            assert call_count == 2  # groq attempted then gemini

            # Now pinned dispatch directly to gemini should hit the cache written by the fallback path
            call_count_before = call_count
            res_pinned = "".join(dispatch("sys", "user", "ctx", config, pinned_provider="gemini", use_cache=True))
            assert res_pinned == "fallback-gemini-answer"
            assert call_count == call_count_before  # Cache hit!


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
