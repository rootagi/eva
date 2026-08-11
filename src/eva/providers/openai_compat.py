import json
import logging
from collections.abc import Iterator

import openai
from openai import OpenAI

from eva.config import AppConfig, get_api_key
from eva.indexing.tokenizer import trim_context
from eva.providers import (
    AuthError,
    Provider,
    RateLimitError,
    ServerError,
    TextDelta,
    ToolCall,
    ToolSpec,
    get_effective_context_tokens,
)

logger = logging.getLogger(__name__)


class OpenAICompatibleProvider(Provider):
    """Base for providers that expose an OpenAI-compatible chat completions API."""

    name: str
    base_url: str
    max_rpm: int
    max_rpd: int
    default_model: str
    max_context_tokens: int = 4000
    supports_tools: bool = True

    def generate_stream(self, system_prompt: str, user_prompt: str, context: str, config: AppConfig) -> Iterator[str]:
        api_key = get_api_key(self.name)
        if not api_key:
            raise AuthError(f"Missing API key for {self.name}. Use: eva config set-key {self.name}")

        client = OpenAI(base_url=self.base_url, api_key=api_key)

        provider_config = config.providers.get(self.name)
        model = self._resolve_model(provider_config.model if provider_config else self.default_model)

        max_tokens = get_effective_context_tokens(self.name, config)
        trimmed_context = trim_context(context, max_tokens=max_tokens) if context else ""

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

    def generate_with_tools(
        self, messages: list[dict], tools: list[ToolSpec], config: AppConfig
    ) -> Iterator[TextDelta | ToolCall]:
        api_key = get_api_key(self.name)
        if not api_key:
            raise AuthError(f"Missing API key for {self.name}. Use: eva config set-key {self.name}")

        client = OpenAI(base_url=self.base_url, api_key=api_key)
        provider_config = config.providers.get(self.name)
        model = self._resolve_model(provider_config.model if provider_config else self.default_model)

        openai_tools = [
            {
                "type": "function",
                "function": {
                    "name": tool.name,
                    "description": tool.description,
                    "parameters": tool.parameters,
                },
            }
            for tool in tools
        ]

        try:
            stream = client.chat.completions.create(model=model, messages=messages, tools=openai_tools, stream=True)

            accumulated_tool_calls: dict[int, dict] = {}

            for chunk in stream:
                if not chunk.choices:
                    continue
                delta = chunk.choices[0].delta

                if delta.content:
                    yield TextDelta(content=delta.content)

                if delta.tool_calls:
                    for tc in delta.tool_calls:
                        idx = tc.index
                        if idx not in accumulated_tool_calls:
                            accumulated_tool_calls[idx] = {
                                "call_id": tc.id or f"call_{idx}",
                                "name": tc.function.name if tc.function and tc.function.name else "",
                                "arguments_str": "",
                            }
                        if tc.id:
                            accumulated_tool_calls[idx]["call_id"] = tc.id
                        if tc.function and tc.function.name:
                            accumulated_tool_calls[idx]["name"] = tc.function.name
                        if tc.function and tc.function.arguments:
                            accumulated_tool_calls[idx]["arguments_str"] += tc.function.arguments

            for call_data in accumulated_tool_calls.values():
                args_str = call_data["arguments_str"].strip()
                parsed_args = {}
                if args_str:
                    try:
                        parsed_args = json.loads(args_str)
                    except json.JSONDecodeError:
                        logger.warning("Failed to parse tool call arguments JSON: %s", args_str)
                        parsed_args = {"raw": args_str}

                yield ToolCall(
                    call_id=call_data["call_id"],
                    name=call_data["name"],
                    arguments=parsed_args,
                )

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
