from collections.abc import Iterator

from google import genai
from google.genai import errors

from eva.config import AppConfig, get_api_key
from eva.indexing.tokenizer import trim_context
from eva.providers import AuthError, Provider, RateLimitError, ServerError, register_provider


class GeminiProvider(Provider):
    name = "gemini"
    max_rpm = 15
    max_rpd = 1500

    def generate_stream(self, system_prompt: str, user_prompt: str, context: str, config: AppConfig) -> Iterator[str]:
        api_key = get_api_key(self.name)
        if not api_key:
            raise AuthError(f"Missing API key for {self.name}. Use: eva config set-key {self.name}")

        client = genai.Client(api_key=api_key)

        provider_config = config.providers.get(self.name)
        model = provider_config.model if provider_config else "gemini-3-flash"

        trimmed_context = trim_context(context, max_tokens=1000000) if context else ""

        prompt = ""
        if trimmed_context:
            prompt += f"Context:\n{trimmed_context}\n\n"
        prompt += user_prompt

        try:
            response = client.models.generate_content_stream(
                model=model,
                contents=prompt,
                config=genai.types.GenerateContentConfig(
                    system_instruction=system_prompt,
                ),
            )
            for chunk in response:
                if chunk.text:
                    yield chunk.text
        except errors.APIError as e:
            if e.code == 401 or e.code == 403:
                raise AuthError("Invalid API key for Gemini.")
            if e.code == 429:
                raise RateLimitError("Rate limited by Gemini.")
            if e.code in [502, 503]:
                raise ServerError("Gemini server error.")
            raise


def get_models() -> list[dict]:
    api_key = get_api_key("gemini")
    if not api_key:
        return []

    try:
        client = genai.Client(api_key=api_key)
        models = []
        for model in client.models.list():
            name = getattr(model, "name", "")
            display_name = getattr(model, "display_name", name)
            if name:
                models.append({"id": name, "name": display_name})
        return models
    except (errors.APIError, AttributeError, KeyError, ValueError, RuntimeError):
        return []


register_provider(GeminiProvider())
