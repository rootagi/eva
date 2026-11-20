from eva.config import load_config
from eva.providers import DEFAULT_CONTEXT_BUDGET, get_context_budget
from eva.providers.groq_provider import GroqProvider


def test_get_context_budget_known_provider():
    config = load_config()
    budget = get_context_budget("groq", config)
    assert budget == GroqProvider.max_context_tokens
    assert budget == 7000


def test_get_context_budget_unknown_provider_fallback():
    config = load_config()
    budget = get_context_budget("nonexistent_provider", config)
    assert budget == DEFAULT_CONTEXT_BUDGET
    assert budget == 4000


def test_get_context_budget_config_override():
    from eva.config.config import AppConfig, ProviderConfig

    config = AppConfig()
    config.providers["opencode_zen"] = ProviderConfig(model="big-pickle", max_context_tokens=32000)
    budget = get_context_budget("opencode_zen", config)
    assert budget == 32000


def test_get_context_budget_precedence_matrix():
    from eva.config.config import AppConfig, GeneralConfig, ProviderConfig

    # Level 1: context_token_limit beats provider_cfg and provider default
    cfg1 = AppConfig(
        general=GeneralConfig(context_token_limit=16000),
        providers={"groq": ProviderConfig(model="llama-3.1", max_context_tokens=8000)},
    )
    assert get_context_budget("groq", cfg1) == 16000

    # Level 2: provider_cfg beats provider default when context_token_limit is None or <=0
    cfg2 = AppConfig(
        general=GeneralConfig(context_token_limit=0),
        providers={"groq": ProviderConfig(model="llama-3.1", max_context_tokens=8000)},
    )
    assert get_context_budget("groq", cfg2) == 8000

    # Level 3: provider default when neither config limit nor provider_cfg is set
    cfg3 = AppConfig(providers={"groq": ProviderConfig(model="llama-3.1")})
    assert get_context_budget("groq", cfg3) == 7000

    # Level 4: fallback when provider is unknown or None
    assert get_context_budget("unknown", cfg3) == DEFAULT_CONTEXT_BUDGET
    assert get_context_budget(None, cfg3) == DEFAULT_CONTEXT_BUDGET
    assert get_context_budget("groq", None) == 7000
    assert get_context_budget(None, None) == DEFAULT_CONTEXT_BUDGET
