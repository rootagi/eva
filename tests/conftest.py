import pytest

from eva.config import AppConfig, ProviderConfig


@pytest.fixture(autouse=True)
def _isolate_cache(monkeypatch, tmp_path):
    """Redirect the disk cache to a temp directory so tests never share cached responses."""
    monkeypatch.setattr("eva.cache.cache.get_cache_dir", lambda: tmp_path / "test_cache")


@pytest.fixture
def mock_config(monkeypatch, tmp_path):
    monkeypatch.setenv("EVA_OPENROUTER_API_KEY", "test-or-key")
    monkeypatch.setenv("EVA_GROQ_API_KEY", "test-groq-key")
    monkeypatch.setenv("EVA_GEMINI_API_KEY", "test-gemini-key")
    monkeypatch.setenv("EVA_OPENCODE_ZEN_API_KEY", "test-opencode-key")
    config = AppConfig(
        providers={
            "openrouter": ProviderConfig(model="openrouter/free"),
            "groq": ProviderConfig(model="llama-3.1-8b-instant"),
            "gemini": ProviderConfig(model="gemini-3-flash"),
            "opencode_zen": ProviderConfig(model="big-pickle"),
        }
    )
    return config


def pytest_configure(config):
    args = [str(a) for a in config.args]
    if any("e2e" in a for a in args) and not any("unit" in a for a in args):
        if hasattr(config.option, "cov_fail_under"):
            config.option.cov_fail_under = None
        cov_plugin = config.pluginmanager.get_plugin("_cov")
        if cov_plugin and hasattr(cov_plugin, "options"):
            cov_plugin.options.cov_fail_under = None
