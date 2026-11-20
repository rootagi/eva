import pytest

from eva.cache import Cache, clear_cache, generate_cache_key, get_cached_response, set_cached_response


def test_cache_key_generation():
    key1 = generate_cache_key("model1", "sys", "user", "ctx")
    key2 = generate_cache_key("model1", "sys", "user", "ctx")
    key3 = generate_cache_key("model2", "sys", "user", "ctx")
    key4 = generate_cache_key("model1", "sys", "user", "ctx", namespace="v1")

    assert key1 == key2
    assert key1 != key3
    assert key1 != key4  # Namespace separation prevents collisions
    assert key1.startswith("v2:")
    assert key4.startswith("v1:")


def test_cache_key_provider_model_namespace():
    key_groq_llama8b = generate_cache_key("groq:llama-3.1-8b-instant", "sys", "user", "ctx")
    key_groq_llama70b = generate_cache_key("groq:llama-3.3-70b-versatile", "sys", "user", "ctx")
    assert key_groq_llama8b != key_groq_llama70b


def test_cache_set_get_clear(monkeypatch, tmp_path):
    monkeypatch.setattr("eva.cache.cache.get_cache_dir", lambda: tmp_path / "cache")
    key = generate_cache_key("m", "s", "u", "c")

    assert get_cached_response(key) is None
    set_cached_response(key, "response_val")
    assert get_cached_response(key) == "response_val"

    clear_cache()
    assert get_cached_response(key) is None


def test_cache_dict_protocol_and_delete(tmp_path):
    cache = Cache(tmp_path / "custom_cache")
    cache["k1"] = {"models": ["m1", "m2"]}
    assert "k1" in cache
    assert "k2" not in cache
    assert cache["k1"] == {"models": ["m1", "m2"]}
    assert cache.get("k2", "default") == "default"

    with pytest.raises(KeyError):
        _ = cache["k2"]

    del cache["k1"]
    assert "k1" not in cache
    assert cache.get("k1") is None

    # Delete non-existent key should not error
    cache.delete("non_existent")


def test_cache_ttl_expiration(tmp_path, monkeypatch):
    current_time = 1000.0
    monkeypatch.setattr("eva.cache.cache.time.time", lambda: current_time)

    cache = Cache(tmp_path / "ttl_cache")
    cache.set("ephemeral", "data", expire=60.0)
    assert cache.get("ephemeral") == "data"

    # Advance time past expiration
    current_time = 1061.0
    assert cache.get("ephemeral") is None


def test_cache_corrupted_payload(tmp_path):
    cache = Cache(tmp_path / "corrupt_cache")
    with cache._get_conn() as conn:
        conn.execute(
            "INSERT INTO cache_entries (key, value, expires_at) VALUES (?, ?, ?)",
            ("bad_json", "not a valid json string {", None),
        )
    assert cache.get("bad_json") is None
