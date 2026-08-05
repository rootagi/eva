from datetime import datetime, timezone

from eva.workflows.budget import (
    UsageStats,
    check_and_increment,
    normalize_usage_stats,
    remaining_budget,
)


def test_budget_stats_normalization():
    stats = UsageStats(requests_today=10, requests_this_minute=5, last_request_time=100.0)
    now = datetime.now(timezone.utc)
    norm = normalize_usage_stats(stats, now=now)
    assert norm.requests_this_minute == 0


def test_budget_check_increment(monkeypatch, tmp_path):
    monkeypatch.setattr("eva.workflows.budget.get_config_dir", lambda: tmp_path)
    ok = check_and_increment("test_prov", max_rpm=2, max_rpd=10)
    assert ok is True

    ok2 = check_and_increment("test_prov", max_rpm=2, max_rpd=10)
    assert ok2 is True

    ok3 = check_and_increment("test_prov", max_rpm=2, max_rpd=10)
    assert ok3 is False

    rpd_rem, rpm_rem = remaining_budget("test_prov", max_rpm=2, max_rpd=10)
    assert rpm_rem == 0
    assert rpd_rem == 8
