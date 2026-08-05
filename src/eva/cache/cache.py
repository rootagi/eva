import hashlib
import json

from diskcache import Cache

from eva.config import get_config_dir


def get_cache_dir():
    return get_config_dir() / "cache"


def get_cache() -> Cache:
    return Cache(get_cache_dir())


def generate_cache_key(model: str, system_prompt: str, user_prompt: str, context: str) -> str:
    key_data = {
        "model": model,
        "system_prompt": system_prompt,
        "user_prompt": user_prompt,
        "context_hash": hashlib.sha256(context.encode("utf-8")).hexdigest() if context else "",
    }
    key_str = json.dumps(key_data, sort_keys=True)
    return hashlib.sha256(key_str.encode("utf-8")).hexdigest()


def get_cached_response(key: str) -> str | None:
    with get_cache() as cache:
        return cache.get(key)


def set_cached_response(key: str, response: str, ttl_hours: int = 24):
    with get_cache() as cache:
        cache.set(key, response, expire=ttl_hours * 3600)


def clear_cache():
    with get_cache() as cache:
        cache.clear()
