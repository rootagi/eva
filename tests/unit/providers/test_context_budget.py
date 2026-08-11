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
