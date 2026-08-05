"""Compatibility re-exports for router."""

from eva.providers import (
    AuthError,
    Provider,
    QuotaExhaustedError,
    RateLimitError,
    ServerError,
    call_provider,
    dispatch,
    get_provider,
    register_provider,
)

__all__ = [
    "AuthError",
    "Provider",
    "QuotaExhaustedError",
    "RateLimitError",
    "ServerError",
    "call_provider",
    "dispatch",
    "get_provider",
    "register_provider",
]
