import logging
import os
from collections.abc import Iterator

from eva.config import AppConfig, get_api_key
from eva.providers import register_provider
from eva.providers.openai_compat import OpenAICompatibleProvider

logger = logging.getLogger(__name__)


def get_models() -> list[dict]:
    import httpx

    host = os.getenv("OLLAMA_HOST", "http://localhost:11434")
    try:
        resp = httpx.get(f"{host}/api/tags", timeout=5.0)
        if resp.status_code == 200:
            models_raw = resp.json().get("models", [])
            return [{"id": m.get("name"), "name": m.get("name")} for m in models_raw if m.get("name")]
    except (httpx.HTTPError, KeyError, ValueError, RuntimeError) as exc:
        logger.warning("Ollama model list fetch failed: %s", exc)
    return []


class OllamaProvider(OpenAICompatibleProvider):
    name = "ollama"
    base_url = os.getenv("OLLAMA_HOST", "http://localhost:11434") + "/v1"
    max_rpm = 999
    max_rpd = 9999
    default_model = "gemma4:12b"
    max_context_tokens = 8000

    def generate_stream(self, system_prompt: str, user_prompt: str, context: str, config: AppConfig) -> Iterator[str]:
        api_key = get_api_key(self.name) or "ollama"
        import openai
        from openai import OpenAI

        from eva.indexing.tokenizer import trim_context
        from eva.providers import AuthError, RateLimitError, ServerError

        base_url = os.getenv("OLLAMA_HOST", "http://localhost:11434").rstrip("/") + "/v1"
        client = OpenAI(base_url=base_url, api_key=api_key)

        provider_config = config.providers.get(self.name)
        model = self._resolve_model(provider_config.model if provider_config else self.default_model)

        trimmed_context = trim_context(context, max_tokens=self.max_context_tokens) if context else ""

        messages = [{"role": "system", "content": system_prompt}]
        if trimmed_context:
            messages.append({"role": "user", "content": f"Context:\n{trimmed_context}"})
        messages.append({"role": "user", "content": user_prompt})

        try:
            stream = client.chat.completions.create(model=model, messages=messages, stream=True)
            for chunk in stream:
                if chunk.choices and chunk.choices[0].delta.content:
                    yield chunk.choices[0].delta.content
        except openai.AuthenticationError:
            raise AuthError(f"Invalid API key for {self.name}.")
        except openai.RateLimitError:
            raise RateLimitError(f"Rate limited by {self.name}.")
        except openai.APIConnectionError as e:
            raise ServerError(f"Ollama server unavailable at {base_url}: {e}")
        except openai.APIStatusError as e:
            raise ServerError(f"Ollama server error: {e}")


register_provider(OllamaProvider())
