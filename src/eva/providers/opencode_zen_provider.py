import logging

import httpx

from eva.cache import get_cache
from eva.providers import register_provider
from eva.providers.openai_compat import OpenAICompatibleProvider

logger = logging.getLogger(__name__)
MODEL_CACHE_KEY = "models:opencode_zen:free"


def get_free_models() -> list[dict]:
    with get_cache() as cache:
        cached = cache.get(MODEL_CACHE_KEY)
        if cached:
            return cached

    try:
        resp = httpx.get("https://opencode.ai/zen/v1/models", timeout=5.0)
        if resp.status_code == 200:
            data = resp.json().get("data", [])
            free_models = [m for m in data if "free" in m.get("id", "").lower() or m.get("id") == "big-pickle"]
            if free_models:
                with get_cache() as cache:
                    cache.set(MODEL_CACHE_KEY, free_models, expire=12 * 3600)
            return free_models
        logger.warning("OpenCode Zen model list fetch failed with HTTP %s", resp.status_code)
    except (httpx.HTTPError, KeyError, ValueError, RuntimeError) as exc:
        logger.warning("OpenCode Zen model list fetch failed: %s", exc)
    return []


class OpenCodeZenProvider(OpenAICompatibleProvider):
    name = "opencode_zen"
    base_url = "https://opencode.ai/zen/v1"
    max_rpm = 10
    max_rpd = 100
    default_model = "big-pickle"
    max_context_tokens = 4000

    def _resolve_model(self, config_model: str) -> str:
        free_models = get_free_models()
        if free_models:
            # check if config_model is in the free models
            for m in free_models:
                if m["id"] == config_model:
                    return config_model
            return free_models[0]["id"]
        return config_model


register_provider(OpenCodeZenProvider())
