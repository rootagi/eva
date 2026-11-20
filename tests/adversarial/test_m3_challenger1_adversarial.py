"""Adversarial stress-test harness for Milestone 3 (WI-12 and WI-13).

Challenger M3-1 empirical verification test suite.
Stress-tests:
1. Context budget precedence matrix, non-integer types, zero/negative bounds, unregistered providers.
2. Chat REPL ergonomics, multi-line blocks, slash commands, file permissions, and Fernet encryption at rest.
"""

from __future__ import annotations

import stat
from typing import ClassVar
from unittest.mock import MagicMock, patch

import pytest
import typer
from cryptography.fernet import InvalidToken
from typer.testing import CliRunner

from eva.config import AppConfig, GeneralConfig, ProviderConfig
from eva.providers import DEFAULT_CONTEXT_BUDGET, get_context_budget
from eva.providers.groq_provider import GroqProvider
from eva.security.sensitive_files import is_sensitive_file
from eva.workflows.chat_session import (
    ChatSession,
    dispatch_slash_command,
    load_session_transcript,
    save_session_transcript,
)

runner = CliRunner()


# ===========================================================================
# WI-13: Context Budget Precedence Matrix & Adversarial Edge Cases
# ===========================================================================


class TestWI13ContextBudgetPrecedenceAdversarial:
    """Adversarial tests for WI-13 context budget resolution ladder and boundaries."""

    def test_precedence_ladder_level1_context_token_limit_overrides_all(self):
        """config.general.context_token_limit must override provider_cfg and provider metadata."""
        config = AppConfig(
            general=GeneralConfig(context_token_limit=12000),
            providers={"groq": ProviderConfig(model="llama-3.1", max_context_tokens=6000)},
        )
        assert get_context_budget("groq", config) == 12000

    def test_precedence_ladder_level2_provider_cfg_overrides_provider_default(self):
        """When general limit is unset (None), provider_cfg.max_context_tokens overrides provider metadata."""
        config = AppConfig(
            general=GeneralConfig(context_token_limit=None),
            providers={"groq": ProviderConfig(model="llama-3.1", max_context_tokens=9500)},
        )
        assert get_context_budget("groq", config) == 9500

    def test_precedence_ladder_level3_provider_metadata_used_when_no_cfg(self):
        """When neither general limit nor provider_cfg budget is set, provider.max_context_tokens is used."""
        config = AppConfig(
            general=GeneralConfig(context_token_limit=None),
            providers={"groq": ProviderConfig(model="llama-3.1")},
        )
        assert get_context_budget("groq", config) == GroqProvider.max_context_tokens
        assert get_context_budget("groq", config) == 7000

    def test_precedence_ladder_level4_fallback_default_context_budget(self):
        """When provider is unregistered or None, falls back to DEFAULT_CONTEXT_BUDGET (4000)."""
        config = AppConfig()
        assert get_context_budget("completely_unknown_provider_xyz", config) == DEFAULT_CONTEXT_BUDGET
        assert get_context_budget("", config) == DEFAULT_CONTEXT_BUDGET
        assert get_context_budget(None, config) == DEFAULT_CONTEXT_BUDGET
        assert get_context_budget("unknown", None) == DEFAULT_CONTEXT_BUDGET
        assert get_context_budget(None, None) == DEFAULT_CONTEXT_BUDGET

    @pytest.mark.parametrize("invalid_val", [0, -1, -500, -999999])
    def test_zero_and_negative_context_token_limit_bypassed(self, invalid_val):
        """Zero or negative context_token_limit must be ignored and fall back to lower precedence levels."""
        config = AppConfig(
            general=GeneralConfig(context_token_limit=invalid_val),
            providers={"groq": ProviderConfig(model="llama-3.1", max_context_tokens=8500)},
        )
        assert get_context_budget("groq", config) == 8500

    @pytest.mark.parametrize("invalid_val", [0, -1, -500])
    def test_zero_and_negative_provider_cfg_bypassed(self, invalid_val):
        """Zero or negative provider_cfg.max_context_tokens must fall back to provider metadata or default."""
        config = AppConfig(
            general=GeneralConfig(context_token_limit=None),
            providers={"groq": ProviderConfig(model="llama-3.1", max_context_tokens=invalid_val)},
        )
        assert get_context_budget("groq", config) == GroqProvider.max_context_tokens

    def test_non_integer_type_resilience(self):
        """Non-integer types (string, float) on limit must be safely bypassed without crashing."""

        class FakeGeneral:
            context_token_limit = "8000"  # string instead of int

        class FakeConfig:
            general = FakeGeneral()
            providers: ClassVar[dict[str, ProviderConfig]] = {
                "groq": ProviderConfig(model="llama-3.1", max_context_tokens=6500)
            }

        budget = get_context_budget("groq", FakeConfig())
        assert budget == 6500

    def test_boolean_type_not_mistaken_for_integer_token_limit(self):
        """In Python bool is a subclass of int. If limit=True, it must NOT return 1 token."""

        class FakeGeneral:
            context_token_limit = True

        class FakeConfig:
            general = FakeGeneral()
            providers: ClassVar[dict[str, ProviderConfig]] = {
                "groq": ProviderConfig(model="llama-3.1", max_context_tokens=6500)
            }

        budget = get_context_budget("groq", FakeConfig())
        assert budget != 1, "Boolean True was improperly accepted as a valid 1-token budget"
        assert budget == 6500

    def test_ask_command_respects_context_budget(self, tmp_path, monkeypatch):
        """eva ask must use get_context_budget when trimming context."""
        from eva.cli.commands.ask import ask

        mock_dispatch = MagicMock(return_value=iter(["mock response"]))
        monkeypatch.setattr("eva.providers.dispatch", mock_dispatch)

        config = AppConfig(general=GeneralConfig(context_token_limit=1500))
        monkeypatch.setattr("eva.config.load_config", lambda: config)

        test_file = tmp_path / "test.txt"
        test_file.write_text("Hello " * 1000)

        with patch("eva.indexing.tokenizer.trim_context") as mock_trim:
            mock_trim.return_value = "trimmed content"
            with patch("eva.ui.streaming.stream_response", return_value="mock response"):
                try:
                    ask(
                        query=["test question"],
                        files=[test_file],
                        dirs=None,
                        repo=None,
                        dry_run=False,
                        yes=True,
                        provider="groq",
                        no_cache=True,
                        output_format="text",
                        no_project_context=True,
                        force_include=None,
                    )
                except typer.Exit:
                    pass
                assert mock_trim.called
                assert mock_trim.call_args[1].get("max_tokens") == 1500

    def test_chat_session_respects_context_budget(self):
        """ChatSession.get_budget() must strictly respect centralized get_context_budget."""
        config = AppConfig(general=GeneralConfig(context_token_limit=2500))
        session = ChatSession(config=config, provider="groq")
        assert session.get_budget() == 2500


# ===========================================================================
# WI-12: Chat REPL Ergonomics & Encrypted Transcripts Adversarial
# ===========================================================================


class TestWI12ChatREPLEncryptedTranscriptsAdversarial:
    """Adversarial stress-test suite for Chat REPL ergonomics, encryption, and slash commands."""

    def test_transcript_ciphertext_at_rest_on_disk(self, tmp_path):
        """Session transcript file saved with encrypt=True MUST contain Fernet ciphertext and no plaintext."""
        secret_payload = "USER_SECRET_TOKEN=xyz987654321_CLASSIFIED"
        transcript_file = tmp_path / "session.eva_chat"

        save_session_transcript(transcript_file, secret_payload, encrypt=True)
        assert transcript_file.exists()

        raw_bytes = transcript_file.read_bytes()
        assert raw_bytes.startswith(b"gAAAAA"), "Fernet token must start with gAAAAA"
        assert secret_payload.encode("utf-8") not in raw_bytes, "Plaintext secret leaked in ciphertext file"

    def test_transcript_decryption_roundtrip(self, tmp_path):
        """Encrypted transcript must decrypt cleanly to original plaintext."""
        secret_payload = "Conversation line 1\nLine 2 with special chars: 🤖 <test> & 'quotes'"
        transcript_file = tmp_path / "roundtrip.eva_chat"

        save_session_transcript(transcript_file, secret_payload, encrypt=True)
        decrypted = load_session_transcript(transcript_file)
        assert decrypted == secret_payload

    def test_backward_compatible_plaintext_md_loading(self, tmp_path):
        """Existing legacy unencrypted .md transcripts must load without error."""
        legacy_payload = "# Legacy Plaintext Chat Session\nUser: hello\nEva: hi"
        legacy_file = tmp_path / "legacy.md"
        legacy_file.write_text(legacy_payload, encoding="utf-8")

        loaded = load_session_transcript(legacy_file)
        assert loaded == legacy_payload

    def test_adversarial_plaintext_starting_with_gaaaaa_does_not_crash_with_invalid_token(self, tmp_path):
        """A plaintext markdown file that happens to start with 'gAAAA' must not crash with InvalidToken."""
        raw_text = "gAAAAA_this_is_a_plaintext_note_not_fernet_token"
        note_file = tmp_path / "notes.md"
        note_file.write_text(raw_text, encoding="utf-8")

        try:
            loaded = load_session_transcript(note_file)
            assert loaded == raw_text
        except InvalidToken:
            pytest.fail("load_session_transcript raised unhandled InvalidToken on plaintext file starting with gAAAA")

    def test_adversarial_session_persistence_does_not_leak_plaintext_md_when_encrypted(self, tmp_path, monkeypatch):
        """When encrypt_sessions=True, persist_session must NOT leave an unencrypted .md file on disk."""
        monkeypatch.setattr("eva.workflows.chat_session.get_config_dir", lambda: tmp_path)
        config = AppConfig(general=GeneralConfig(encrypt_sessions=True))
        session = ChatSession(config=config, session="classified_ops")
        session.context_history = "TOP_SECRET_RECON_DATA_CLEARANCE_REQUIRED"

        session.persist_session()

        sess_dir = tmp_path / "sessions"
        plaintext_md = sess_dir / "classified_ops.md"
        encrypted_chat = sess_dir / "classified_ops.eva_chat"

        assert encrypted_chat.exists(), "Encrypted .eva_chat file was not created"
        if plaintext_md.exists():
            content = plaintext_md.read_text(encoding="utf-8")
            assert "TOP_SECRET_RECON_DATA_CLEARANCE_REQUIRED" not in content, (
                "CRITICAL: persist_session leaked raw plaintext transcript in .md file while encrypt_sessions is True!"
            )

    def test_multiline_block_triple_quotes_parsing(self):
        """Single-line and multi-line triple-quote blocks must parse cleanly."""
        config = AppConfig()
        session = ChatSession(config=config)

        # Single-line triple quotes
        with patch("builtins.input", return_value='"""inline code block"""'):
            res = session.read_user_input()
            assert res == "inline code block"

        with patch("builtins.input", return_value="'''inline single quotes'''"):
            res = session.read_user_input()
            assert res == "inline single quotes"

        # Multi-turn triple quotes
        inputs = iter(['"""multi-line', "def foo():", "    return 42", '"""'])
        with patch("builtins.input", side_effect=lambda *_: next(inputs)):
            res = session.read_user_input()
            assert "def foo():" in res
            assert "return 42" in res

    def test_multiline_mode_ctrl_d_eof_submits_accumulated_input(self):
        """When multiline_mode is enabled, Ctrl-D (EOF) must submit accumulated lines, NOT abort session."""
        config = AppConfig()
        session = ChatSession(config=config)
        session.multiline_mode = True

        inputs = iter(["first line of script", "second line of script"])

        def mock_input(prompt=""):
            try:
                return next(inputs)
            except StopIteration:
                raise EOFError()

        with patch("builtins.input", side_effect=mock_input):
            try:
                res = session.read_user_input()
                assert "first line of script" in res
                assert "second line of script" in res
            except EOFError:
                pytest.fail("Ctrl-D in multiline_mode raised unhandled EOFError instead of submitting lines")

    def test_multiline_mode_empty_line_submits_accumulated_input(self):
        """When multiline_mode is enabled, an empty line submits accumulated lines."""
        config = AppConfig()
        session = ChatSession(config=config)
        session.multiline_mode = True

        inputs = iter(["line 1", "line 2", ""])
        with patch("builtins.input", side_effect=lambda *_: next(inputs)):
            res = session.read_user_input()
            assert res == "line 1\nline 2"

    def test_slash_file_sensitive_file_denylisting(self, tmp_path):
        """Slash command /file MUST reject sensitive files (.env, id_rsa, *.pem, credentials.json)."""
        config = AppConfig()
        session = ChatSession(config=config)

        sensitive_file = tmp_path / ".env"
        sensitive_file.write_text("AWS_SECRET_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE", encoding="utf-8")

        assert is_sensitive_file(sensitive_file) is True

        dispatch_slash_command(session, f"/file {sensitive_file}")
        assert "AWS_SECRET_ACCESS_KEY" not in session.context_history, (
            "CRITICAL: /file attached sensitive file (.env) to conversation context!"
        )

    def test_slash_file_directory_path_handling(self, tmp_path):
        """Slash command /file on a directory must fail gracefully and not attach directory."""
        config = AppConfig()
        session = ChatSession(config=config)
        test_dir = tmp_path / "testdir"
        test_dir.mkdir()

        dispatch_slash_command(session, f"/file {test_dir}")
        assert str(test_dir) not in session.context_history

    def test_slash_file_missing_file_handling(self):
        """Slash command /file on non-existent file reports error cleanly without crash."""
        config = AppConfig()
        session = ChatSession(config=config)
        handled = dispatch_slash_command(session, "/file /nonexistent/file/path/here.py")
        assert handled is True
        assert "/nonexistent" not in session.context_history

    def test_slash_commands_suite(self):
        """Test full suite of slash commands: /tree, /model, /provider, /clear, /help, unknown."""
        config = AppConfig()
        session = ChatSession(config=config)

        # /help
        assert dispatch_slash_command(session, "/help") is True

        # /tree
        assert dispatch_slash_command(session, "/tree") is True
        assert "workspace directory structure" in session.context_history

        # /model without arg and with arg
        assert dispatch_slash_command(session, "/model") is True
        assert dispatch_slash_command(session, "/model test-model-custom") is True
        assert session.get_current_model() == "test-model-custom"

        # /provider without arg and with arg
        assert dispatch_slash_command(session, "/provider") is True
        assert dispatch_slash_command(session, "/provider groq") is True
        assert session.provider == "groq"

        # /clear
        session.context_history = "some accumulated conversation"
        session.turns_count = 10
        assert dispatch_slash_command(session, "/clear") is True
        assert session.context_history == ""
        assert session.turns_count == 0

        # Unknown slash command
        assert dispatch_slash_command(session, "/foobar_invalid") is True

    def test_slash_save_command_honors_encryption(self, tmp_path):
        """/save command must produce an encrypted transcript when encrypt_sessions is True."""
        config = AppConfig(general=GeneralConfig(encrypt_sessions=True))
        session = ChatSession(config=config)
        session.context_history = "Secret transcript to save: ConfidentialToken42"

        save_target = tmp_path / "saved_session.eva_chat"
        handled = dispatch_slash_command(session, f"/save {save_target}")
        assert handled is True
        assert save_target.exists()

        raw = save_target.read_bytes()
        assert raw.startswith(b"gAAAAA")
        assert b"ConfidentialToken42" not in raw

    def test_transcript_file_permissions_0600(self, tmp_path):
        """Transcript files saved to disk must have restricted file permissions (0600)."""
        transcript_file = tmp_path / "secure_session.eva_chat"
        save_session_transcript(transcript_file, "data", encrypt=True)

        mode = stat.S_IMODE(transcript_file.stat().st_mode)
        # 0o600 means readable and writable only by the owner
        assert mode == 0o600, f"Expected file mode 0o600, got {oct(mode)}"

    def test_history_file_creation_and_permissions_0600(self, tmp_path):
        """Readline history file must be created and have restricted 0600 permissions."""
        config = AppConfig()
        session = ChatSession(config=config)
        hist_path = tmp_path / "test_history"
        session.history_file = hist_path

        session._save_history()
        assert hist_path.exists()
        mode = stat.S_IMODE(hist_path.stat().st_mode)
        assert mode == 0o600, f"Expected history file mode 0o600, got {oct(mode)}"
