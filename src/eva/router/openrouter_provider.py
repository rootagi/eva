import logging

import httpx

from eva.cache import get_cache
from eva.router import register_provider
from eva.router.openai_compat import OpenAICompatibleProvider

logger = logging.getLogger(__name__)
MODEL_CACHE_KEY = "models:openrouter:free"


def get_free_models() -> list[dict]:
    with get_cache() as cache:
        cached = cache.get(MODEL_CACHE_KEY)
        if cached:
            return cached

    try:
        resp = httpx.get("https://openrouter.ai/api/v1/models", timeout=5.0)
        if resp.status_code == 200:
            data = resp.json().get("data", [])
            # Filter prompt pricing = 0
            free_models = [m for m in data if m.get("pricing", {}).get("prompt") in ("0", "0.0", 0, 0.0)]
            if free_models:
                with get_cache() as cache:
                    cache.set(MODEL_CACHE_KEY, free_models, expire=12 * 3600)
            return free_models
        logger.warning("OpenRouter model list fetch failed with HTTP %s", resp.status_code)
    except (httpx.HTTPError, KeyError, ValueError, RuntimeError) as exc:
        logger.warning("OpenRouter model list fetch failed: %s", exc)
    return []


class OpenRouterProvider(OpenAICompatibleProvider):
    name = "openrouter"
    base_url = "https://openrouter.ai/api/v1"
    max_rpm = 20
    max_rpd = 50
    default_model = "openrouter/free"
    max_context_tokens = 4000

    def _resolve_model(self, config_model: str) -> str:
        if config_model != "openrouter/free":
            return config_model

        free_models = get_free_models()
        if free_models:
            return free_models[0]["id"]

        logger.warning("No OpenRouter free model list available; falling back to openrouter/auto")
        return "openrouter/auto"


register_provider(OpenRouterProvider())
