import logging
from collections.abc import Iterator

import openai
from openai import OpenAI

from eva.config import AppConfig, get_api_key
from eva.indexing.tokenizer import trim_context
from eva.providers import AuthError, Provider, RateLimitError, ServerError

logger = logging.getLogger(__name__)


class OpenAICompatibleProvider(Provider):
    """Base for providers that expose an OpenAI-compatible chat completions API."""

    name: str
    base_url: str
    max_rpm: int
    max_rpd: int
    default_model: str
    max_context_tokens: int = 4000

    def generate_stream(self, system_prompt: str, user_prompt: str, context: str, config: AppConfig) -> Iterator[str]:
        api_key = get_api_key(self.name)
        if not api_key:
            raise AuthError(f"Missing API key for {self.name}. Use: eva config set-key {self.name}")

        client = OpenAI(base_url=self.base_url, api_key=api_key)

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
        except openai.APIStatusError as e:
            if e.status_code in [502, 503]:
                raise ServerError(f"{self.name} server error.")
            raise

    def _resolve_model(self, config_model: str) -> str:
        """Override in subclasses to implement dynamic model resolution."""
        return config_model
