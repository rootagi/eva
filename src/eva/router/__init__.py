import logging
from collections.abc import Iterator
from typing import Protocol

from eva.budget import check_and_increment
from eva.config import AppConfig

logger = logging.getLogger(__name__)


class RateLimitError(Exception):
    pass


class ServerError(Exception):
    pass


class AuthError(Exception):
    pass


class QuotaExhaustedError(Exception):
    pass


class Provider(Protocol):
    name: str
    max_rpm: int
    max_rpd: int

    def generate_stream(
        self, system_prompt: str, user_prompt: str, context: str, config: AppConfig
    ) -> Iterator[str]: ...


# Provider registry
_PROVIDERS = {}


def register_provider(provider: Provider):
    _PROVIDERS[provider.name] = provider


def get_provider(name: str) -> Provider | None:
    return _PROVIDERS.get(name)


def call_provider(
    provider: Provider, system_prompt: str, user_prompt: str, context: str, config: AppConfig
) -> Iterator[str]:
    if not check_and_increment(provider.name, provider.max_rpm, provider.max_rpd):
        logger.info("Local budget exhausted for provider %s", provider.name)
        raise QuotaExhaustedError(
            f"Local budget exhausted for {provider.name}. RPM: {provider.max_rpm}, RPD: {provider.max_rpd}"
        )
    yield from provider.generate_stream(system_prompt, user_prompt, context, config)


def dispatch(
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


# Import providers to auto-register them
import eva.router.gemini_provider
import eva.router.groq_provider
import eva.router.opencode_zen_provider
import eva.router.openrouter_provider  # noqa: F401
