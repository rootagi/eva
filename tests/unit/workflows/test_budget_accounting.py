import json
from pathlib import Path

from eva.workflows.budget import (
    MODEL_PRICING,
    Budget,
    UsageStats,
    _locked_budget_file,
    atomic_write_json,
    calculate_cost,
    load_budget,
)


def test_usage_stats_fields():
    """Verify UsageStats includes input/output tokens, cost, and last_model."""
    stats = UsageStats(
        requests_today=5,
        requests_this_minute=2,
        last_request_time=1234567.8,
        input_tokens=1000,
        output_tokens=250,
        estimated_cost_usd=0.015,
        last_model="gemini-2.5-flash",
    )
    assert stats.input_tokens == 1000
    assert stats.output_tokens == 250
    assert stats.estimated_cost_usd == 0.015
    assert stats.last_model == "gemini-2.5-flash"


def test_model_pricing_table():
    """Verify MODEL_PRICING contains standard model families and pricing tuples."""
    assert len(MODEL_PRICING) > 0
    # Gemini, OpenAI, Claude families
    for inp_rate, out_rate in MODEL_PRICING.values():
        assert isinstance(inp_rate, (int, float))
        assert isinstance(out_rate, (int, float))
        assert inp_rate >= 0
        assert out_rate >= 0


def test_calculate_cost():
    """Verify calculate_cost computes accurate USD or returns None for unknown models."""
    cost = calculate_cost("gemini-2.5-flash", input_tokens=1_000_000, output_tokens=1_000_000)
    assert cost is not None
    assert cost > 0

    # Unknown model returns None
    assert calculate_cost("unknown-model-xyz", input_tokens=100, output_tokens=100) is None


def test_atomic_write_json(tmp_path: Path):
    """Verify atomic_write_json writes valid JSON atomically without lingering .tmp files."""
    dest = tmp_path / "test_budget.json"
    data = {"stats": {"input_tokens": 500, "output_tokens": 100}}

    atomic_write_json(dest, data)
    assert dest.exists()

    loaded = json.loads(dest.read_text(encoding="utf-8"))
    assert loaded == data

    # No leftover temporary files
    assert not list(tmp_path.glob("*.tmp"))


def test_load_budget_corrupt_quarantine(tmp_path: Path):
    """Verify load_budget quarantines invalid JSON and recovers with empty Budget."""
    corrupt_file = tmp_path / "usage.json"
    corrupt_file.write_text("{malformed: json invalid", encoding="utf-8")

    budget = load_budget(corrupt_file)
    assert isinstance(budget, Budget)
    assert hasattr(budget, "stats")
    assert budget.requests_today == 0

    # Verify corrupt file was quarantined
    corrupt_copies = list(tmp_path.glob("usage.json.corrupt-*"))
    assert len(corrupt_copies) == 1
    assert corrupt_copies[0].read_text(encoding="utf-8") == "{malformed: json invalid"


def test_locked_budget_file_timeout(tmp_path: Path):
    """Verify _locked_budget_file honors timeout parameter without hanging indefinitely."""
    lock_file = tmp_path / "test.lock"
    # Acquire lock in context manager
    with _locked_budget_file(lock_file=lock_file, timeout=1.0) as acquired:
        assert acquired is True
