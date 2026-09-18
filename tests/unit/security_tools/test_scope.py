from datetime import datetime, timedelta, timezone

import pytest

from eva.security_tools.scope import ScopeError, ScopeFile, assert_target_in_scope, assert_zap_authorized


def make_scope(**overrides):
    data = {
        "engagement_id": "local-dev-001",
        "expires_at": datetime.now(timezone.utc) + timedelta(days=1),
        "paths": ["."],
        "web_targets": ["https://staging.example.internal/app"],
        "allowed_ports": [443],
        "max_requests_per_second": 2,
        "max_concurrency": 2,
        "allow_active_scanning": False,
    }
    data.update(overrides)
    return ScopeFile.model_validate(data)


def test_scope_rejects_expiry():
    scope = make_scope(expires_at=datetime.now(timezone.utc) - timedelta(seconds=1))
    with pytest.raises(ScopeError, match="expired"):
        scope.assert_not_expired()


def test_scope_allows_host_and_path_prefix():
    scope = make_scope()
    assert_target_in_scope("https://staging.example.internal/app/login", scope)


def test_scope_rejects_outside_host_path_and_port():
    scope = make_scope()
    with pytest.raises(ScopeError):
        assert_target_in_scope("https://evil.example.internal/app/login", scope)
    with pytest.raises(ScopeError):
        assert_target_in_scope("https://staging.example.internal/admin", scope)
    with pytest.raises(ScopeError):
        assert_target_in_scope("http://staging.example.internal:8080/app", scope)


def test_active_scan_requires_scope_flag_and_cli_flag():
    scope = make_scope()
    assert_zap_authorized("https://staging.example.internal/app", scope, active=False)
    with pytest.raises(ScopeError, match="active scanning"):
        assert_zap_authorized("https://staging.example.internal/app", scope, active=True)
    active_scope = make_scope(allow_active_scanning=True)
    assert_zap_authorized("https://staging.example.internal/app", active_scope, active=True)


def test_zap_requires_scope():
    with pytest.raises(ScopeError, match="scope file"):
        assert_zap_authorized("https://staging.example.internal/app", None, active=False)
