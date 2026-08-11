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
