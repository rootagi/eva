import logging

from eva.config import get_api_key
from eva.router import register_provider
from eva.router.openai_compat import OpenAICompatibleProvider

logger = logging.getLogger(__name__)


def get_models() -> list[dict]:
    api_key = get_api_key("groq")
    if not api_key:
        return []
    import httpx

    try:
        resp = httpx.get(
            "https://api.groq.com/openai/v1/models", headers={"Authorization": f"Bearer {api_key}"}, timeout=5.0
        )
        if resp.status_code == 200:
            return resp.json().get("data", [])
        logger.warning("Groq model list fetch failed with HTTP %s", resp.status_code)
    except (httpx.HTTPError, KeyError, ValueError, RuntimeError) as exc:
        logger.warning("Groq model list fetch failed: %s", exc)
    return []


class GroqProvider(OpenAICompatibleProvider):
    name = "groq"
    base_url = "https://api.groq.com/openai/v1"
    max_rpm = 30
    max_rpd = 1000
    default_model = "llama-3.1-8b-instant"
    max_context_tokens = 7000


register_provider(GroqProvider())
