from eva.config import (
    AppConfig,
    get_api_key_env_var,
    load_config,
    save_config,
)


def test_config_defaults():
    cfg = AppConfig()
    assert cfg.general.default_provider == "openrouter"
    assert "openrouter" in cfg.providers
    assert "groq" in cfg.providers
    assert "gemini" in cfg.providers


def test_get_api_key_env_var():
    assert get_api_key_env_var("openrouter") == "EVA_OPENROUTER_API_KEY"
    assert get_api_key_env_var("opencode-zen") == "EVA_OPENCODE_ZEN_API_KEY"


def test_save_and_load_config(monkeypatch, tmp_path):
    monkeypatch.setattr("eva.config.config.get_config_file", lambda: tmp_path / "config.toml")
    cfg = AppConfig()
    cfg.general.default_provider = "groq"
    save_config(cfg)

    loaded = load_config()
    assert loaded.general.default_provider == "groq"
