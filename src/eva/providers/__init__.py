import logging
import time
from collections.abc import Iterator
from typing import Protocol

from eva.config import AppConfig
from eva.security.redaction import redact_secrets
from eva.telemetry.metrics import record_provider_metric

logger = logging.getLogger(__name__)


class RateLimitError(Exception):
    pass


class ServerError(Exception):
    pass


class AuthError(Exception):
    pass


class QuotaExhaustedError(Exception):
    pass


from dataclasses import dataclass, field
from typing import Any


@dataclass
class TextDelta:
    content: str


@dataclass
class ToolCall:
    call_id: str
    name: str
    arguments: dict[str, Any] = field(default_factory=dict)


@dataclass
class ToolSpec:
    name: str
    description: str
    parameters: dict[str, Any] = field(default_factory=dict)


class Provider(Protocol):
    name: str
    max_rpm: int
    max_rpd: int
    max_context_tokens: int
    supports_tools: bool = False

    def generate_stream(
        self, system_prompt: str, user_prompt: str, context: str, config: AppConfig
    ) -> Iterator[str]: ...

    def generate_with_tools(
        self, messages: list[dict], tools: list[ToolSpec], config: AppConfig
    ) -> Iterator[TextDelta | ToolCall]: ...


# Provider registry
_PROVIDERS: dict[str, Provider] = {}
DEFAULT_CONTEXT_BUDGET = 4000


def register_provider(provider: Provider):
    _PROVIDERS[provider.name] = provider


def get_provider(name: str) -> Provider | None:
    return _PROVIDERS.get(name)


def is_tool_capable(provider_name: str) -> bool:
    """Return True if the specified provider exists and supports tool calling."""
    provider = get_provider(provider_name)
    if provider is None:
        return False
    return getattr(provider, "supports_tools", False) is True


def get_tool_capable_providers() -> list[str]:
    """Return list of names of registered providers supporting tool calling."""
    return [name for name, p in _PROVIDERS.items() if getattr(p, "supports_tools", False) is True]


def get_context_budget(provider_name: str, config: AppConfig) -> int:
    """Return effective max context tokens for provider: config > provider class default > 4000."""
    if config and hasattr(config, "providers"):
        provider_cfg = config.providers.get(provider_name)
        if provider_cfg:
            cfg_budget = getattr(provider_cfg, "max_context_tokens", None)
            if isinstance(cfg_budget, int) and cfg_budget > 0:
                return cfg_budget

    provider = get_provider(provider_name)
    if provider is not None:
        budget = getattr(provider, "max_context_tokens", None)
        if isinstance(budget, int) and budget > 0:
            return budget

    return DEFAULT_CONTEXT_BUDGET


def get_effective_context_tokens(provider_name: str, config: AppConfig) -> int:
    """Return effective max context tokens for provider at generation time."""
    return get_context_budget(provider_name, config)


def _resolve_provider_name(config: AppConfig, pinned_provider: str | None = None) -> str:
    """Return the provider name that dispatch will actually use."""
    if pinned_provider:
        return pinned_provider
    return config.general.default_provider


def dispatch(
    system_prompt: str,
    user_prompt: str,
    context: str,
    config: AppConfig,
    pinned_provider: str | None = None,
    use_cache: bool = True,
) -> Iterator[str]:
    from eva.cache import generate_cache_key, get_cached_response, set_cached_response
    from eva.ui.formatter import is_ai_error

    # Determine the provider name for the cache key
    provider_name = _resolve_provider_name(config, pinned_provider)

    # Check cache before calling the provider
    cache_key = generate_cache_key(provider_name, system_prompt, user_prompt, context) if use_cache else None
    if use_cache and cache_key:
        cached = get_cached_response(cache_key)
        if cached is not None:
            logger.debug("Cache hit for provider %s", provider_name)
            yield cached
            return

    # Delegate to the uncached dispatch and collect the full response
    chunks: list[str] = []
    for chunk in _dispatch_uncached(system_prompt, user_prompt, context, config, pinned_provider):
        chunks.append(chunk)
        yield chunk

    # Cache the result if caching is enabled and the response is not an error
    if use_cache and cache_key:
        full_response = "".join(chunks)
        if not is_ai_error(full_response):
            set_cached_response(cache_key, full_response)
        else:
            logger.debug("Skipping cache for error response")


def _dispatch_uncached(
    system_prompt: str, user_prompt: str, context: str, config: AppConfig, pinned_provider: str | None = None
) -> Iterator[str]:
    if pinned_provider:
        provider = get_provider(pinned_provider)
        if not provider:
            yield f"Error: Provider '{pinned_provider}' not found."
            return

        try:
            logger.debug("Dispatching to pinned provider %s", pinned_provider)
            yield from call_provider(provider, system_prompt, user_prompt, context, config)
        except QuotaExhaustedError as e:
            logger.warning("Pinned provider %s exhausted: %s", pinned_provider, e)
            yield f"\n[Eva Error] {e!s}"
        except Exception as e:
            logger.exception("Pinned provider %s failed", pinned_provider)
            yield f"\n[Eva Error] Pinned provider {pinned_provider} failed: {e!s}"
        return

    # Unpinned: try default, then fallback
    order = [config.general.default_provider]
    if config.general.fallback_enabled:
        for p in config.general.fallback_order:
            if p not in order:
                order.append(p)

    failures: list[str] = []

    for i, p_name in enumerate(order):
        provider = get_provider(p_name)
        if not provider:
            failures.append(f"{p_name}: provider not registered")
            logger.warning("Provider %s is configured but not registered", p_name)
            continue

        try:
            logger.debug("Dispatching to provider %s", p_name)
            yielded_any = False
            for chunk in call_provider(provider, system_prompt, user_prompt, context, config):
                yielded_any = True
                yield chunk
            return  # Success
        except QuotaExhaustedError as e:
            if yielded_any:
                yield f"\n[Eva Error] Provider {p_name} failed mid-stream: {e!s}"
                return
            failures.append(f"{p_name}: {type(e).__name__}: {e}")
            logger.info("Provider %s skipped: %s", p_name, e)
            continue
        except AuthError as e:
            if yielded_any:
                yield f"\n[Eva Error] Provider {p_name} failed mid-stream: {e!s}"
                return
            failures.append(f"{p_name}: {type(e).__name__}: {e}")
            logger.warning("Provider %s auth failed: %s", p_name, e)
        except Exception as e:
            if yielded_any:
                yield f"\n[Eva Error] Provider {p_name} failed mid-stream: {e!s}"
                return
            failures.append(f"{p_name}: {type(e).__name__}: {e}")
            logger.exception("Provider %s failed", p_name)

    detail = "; ".join(failures) if failures else "no providers were available"
    yield f"\n[Eva Error] All available providers failed or exhausted their local budget. Failures: {detail}"


# Import budget quota check after dispatch is defined so circular imports are avoided
from eva.workflows.budget import check_and_increment


def call_provider(
    provider: Provider, system_prompt: str, user_prompt: str, context: str, config: AppConfig
) -> Iterator[str]:
    if not check_and_increment(provider.name, provider.max_rpm, provider.max_rpd):
        logger.info("Local budget exhausted for provider %s", provider.name)
        record_provider_metric(provider.name, 0.0, False, error_type="QuotaExhaustedError", config=config)
        raise QuotaExhaustedError(
            f"Local budget exhausted for {provider.name}. RPM: {provider.max_rpm}, RPD: {provider.max_rpd}"
        )
    safe_user_prompt = redact_secrets(user_prompt)
    safe_context = redact_secrets(context)
    start_t = time.time()
    try:
        yield from provider.generate_stream(system_prompt, safe_user_prompt, safe_context, config)
        duration = time.time() - start_t
        record_provider_metric(provider.name, duration, True, config=config)
    except Exception as exc:
        duration = time.time() - start_t
        record_provider_metric(provider.name, duration, False, error_type=type(exc).__name__, config=config)
        raise


# Auto-register providers
import eva.providers.gemini_provider
import eva.providers.groq_provider
import eva.providers.llamacpp_provider
import eva.providers.ollama_provider
import eva.providers.opencode_zen_provider
import eva.providers.openrouter_provider  # noqa: F401
