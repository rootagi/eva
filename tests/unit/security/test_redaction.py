import pytest

from eva.security.redaction import redact_secrets, shannon_entropy


@pytest.fixture
def fake_secrets():
    return [
        "sk-proj-1234567890123456789012345678901234567890",
        "ghp_1234567890abcdefghijklmnopqrstuvwxyz12",
        "glpat-1234567890abcdefghij",
        "AKIAIOSFODNN7EXAMPLE",
        "xoxb-123456789012-1234567890123-abcdefghijklmnopqrstuvwx",
        "EVA_OPENROUTER_API_KEY=sk-or-v1-1234567890abcdef",
        "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.secret",
        "Basic dXNlcm5hbWU6cGFzc3dvcmQ=",
        "api_key: 'super_secret_api_key_12345'",
        "password = 'my_super_secret_password_123'",
        'auth_token: "token_abc1234567890"',
        "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0Z3\n-----END RSA PRIVATE KEY-----",
        "a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a1b0",  # High-entropy hex/token string
    ]


def test_redact_secrets_fixtures(fake_secrets):
    for secret in fake_secrets:
        redacted = redact_secrets(secret)
        assert secret not in redacted
        assert "REDACTED" in redacted


def test_redact_secrets_preserves_normal_text():
    normal_text = "The quick brown fox jumps over the lazy dog."
    assert redact_secrets(normal_text) == normal_text


def test_redact_secrets_empty_string():
    assert redact_secrets("") == ""


def test_shannon_entropy():
    assert shannon_entropy("") == 0.0
    # Repeating character has 0 entropy
    assert shannon_entropy("aaaaaaaaaaaaaaaa") == 0.0
    # High entropy string
    high_ent = shannon_entropy("a8Z9#kL2!pXq7$vM")
    assert high_ent > 3.5


def test_high_entropy_token_redaction():
    text = "User token is 9xK#2mP$7vL!4qZ&1wY*5nJ."
    redacted = redact_secrets(text)
    assert "9xK#2mP$7vL!4qZ&1wY*5nJ" not in redacted


def test_path_aware_entropy_preserves_filesystem_paths():
    path_text = "Icon=/home/ultron/.local/share/Antigravity/icon.png"
    redacted = redact_secrets(path_text)
    assert redacted == path_text


def test_path_with_embedded_secret_redacts_secret_pattern():
    secret_line = "Authorization: Bearer sk-proj-1234567890123456789012345678901234567890"
    redacted = redact_secrets(secret_line)
    assert "sk-proj" not in redacted
    assert "[REDACTED" in redacted


def test_configure_redaction_threshold_override():
    from eva.security.redaction import configure_redaction

    token_text = "Key is 9xK#2mP$7vL!4qZ&1wY*5nJ"
    try:
        configure_redaction(entropy_threshold=8.0, ignore_patterns=[])
        res = redact_secrets(token_text)
        assert "9xK#2mP$7vL!4qZ&1wY*5nJ" in res
    finally:
        configure_redaction(entropy_threshold=3.5, ignore_patterns=[])


def test_configure_redaction_ignore_patterns():
    from eva.security.redaction import configure_redaction

    token_text = "User identifier is ultron_custom_token_here123456"
    try:
        configure_redaction(entropy_threshold=2.0, ignore_patterns=[r"^ultron.*"])
        res = redact_secrets(token_text)
        assert "ultron_custom_token_here123456" in res
    finally:
        configure_redaction(entropy_threshold=3.5, ignore_patterns=[])


def test_redact_secrets_without_configure_call_uses_default_behavior():
    # Calling redact_secrets with a typical high-entropy token redacts by default
    text = "Secret token: 9xK#2mP$7vL!4qZ&1wY*5nJ"
    redacted = redact_secrets(text)
    assert "9xK#2mP$7vL!4qZ&1wY*5nJ" not in redacted
    assert "[REDACTED_HIGH_ENTROPY]" in redacted
