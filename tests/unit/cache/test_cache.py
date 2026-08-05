from eva.cache import clear_cache, generate_cache_key, get_cached_response, set_cached_response


def test_cache_key_generation():
    key1 = generate_cache_key("model1", "sys", "user", "ctx")
    key2 = generate_cache_key("model1", "sys", "user", "ctx")
    key3 = generate_cache_key("model2", "sys", "user", "ctx")

    assert key1 == key2
    assert key1 != key3


def test_cache_set_get_clear(monkeypatch, tmp_path):
    monkeypatch.setattr("eva.cache.cache.get_cache_dir", lambda: tmp_path / "cache")
    key = generate_cache_key("m", "s", "u", "c")

    assert get_cached_response(key) is None
    set_cached_response(key, "response_val")
    assert get_cached_response(key) == "response_val"

    clear_cache()
    assert get_cached_response(key) is None
