from unittest.mock import MagicMock, patch

from eva.config import AppConfig
from eva.workflows.chat_session import (
    SLASH_COMMANDS,
    ChatSession,
    dispatch_slash_command,
    handle_url_command,
    load_session_transcript,
    run_chat_session,
)


def test_run_chat_session_exit(monkeypatch, tmp_path):
    monkeypatch.setattr("builtins.input", lambda prompt="": "exit")
    config = AppConfig()
    run_chat_session(config)


def test_run_chat_session_interaction(monkeypatch, tmp_path):
    monkeypatch.setattr("eva.workflows.chat_session.get_config_dir", lambda: tmp_path)
    inputs = iter(["hello", "quit"])
    monkeypatch.setattr("builtins.input", lambda prompt="": next(inputs))

    with patch("eva.workflows.chat_session.dispatch", return_value=iter(["Hi there!"])):
        config = AppConfig()
        run_chat_session(config, session="test_sess", resume=False)

    session_file = tmp_path / "sessions" / "test_sess.eva_chat"
    if not session_file.exists():
        session_file = tmp_path / "sessions" / "test_sess.md"
    assert session_file.exists()
    content = load_session_transcript(session_file)
    assert "User: hello" in content
    assert "Eva: Hi there!" in content


def test_chat_session_slash_file(tmp_path):
    config = AppConfig()
    session = ChatSession(config=config)
    sample_file = tmp_path / "sample.py"
    sample_file.write_text("print('hello world')\nprint('second line')\n", encoding="utf-8")

    handled = dispatch_slash_command(session, f"/file {sample_file}")
    assert handled is True
    assert "Loaded 2 lines from" in session.context_history
    assert "print('hello world')" in session.context_history


def test_chat_session_slash_tree(tmp_path):
    config = AppConfig()
    session = ChatSession(config=config)
    handled = dispatch_slash_command(session, "/tree")
    assert handled is True
    assert "directory structure" in session.context_history


def test_chat_session_slash_model_and_provider():
    config = AppConfig()
    session = ChatSession(config=config)

    # Provider switch
    dispatch_slash_command(session, "/provider groq")
    assert session.provider == "groq"

    # Model switch
    dispatch_slash_command(session, "/model llama-3.3-70b-versatile")
    assert session.get_current_model() == "llama-3.3-70b-versatile"

    # Inspect model & provider without args
    assert dispatch_slash_command(session, "/model") is True
    assert dispatch_slash_command(session, "/provider") is True


def test_chat_session_slash_clear():
    config = AppConfig()
    session = ChatSession(config=config)
    session.context_history = "some past conversation"
    session.turns_count = 5

    handled = dispatch_slash_command(session, "/clear")
    assert handled is True
    assert session.context_history == ""
    assert session.turns_count == 0


def test_chat_session_slash_save_and_encryption(tmp_path):
    config = AppConfig()
    session = ChatSession(config=config)
    session.context_history = "Secret user message: 12345"

    save_path = tmp_path / "custom.eva_chat"
    handled = dispatch_slash_command(session, f"/save {save_path}")
    assert handled is True
    assert save_path.exists()

    raw_bytes = save_path.read_bytes()
    assert b"12345" not in raw_bytes  # Encrypted with Fernet
    assert raw_bytes.startswith(b"gAAAA")

    # Load and verify transparent decryption
    decrypted = load_session_transcript(save_path)
    assert decrypted == "Secret user message: 12345"


def test_chat_session_slash_multiline_toggle():
    config = AppConfig()
    session = ChatSession(config=config)
    assert session.multiline_mode is False

    dispatch_slash_command(session, "/multiline")
    assert session.multiline_mode is True

    dispatch_slash_command(session, "/multiline")
    assert session.multiline_mode is False


def test_chat_session_slash_help_and_unknown():
    config = AppConfig()
    session = ChatSession(config=config)
    assert dispatch_slash_command(session, "/help") is True
    assert dispatch_slash_command(session, "/unknown_cmd") is True
    assert "/url" in SLASH_COMMANDS
    assert "/file" in SLASH_COMMANDS


def test_chat_session_project_context(tmp_path, monkeypatch):
    eva_dir = tmp_path / ".eva"
    eva_dir.mkdir(parents=True, exist_ok=True)
    (eva_dir / "context.md").write_text("# Project Architecture: Security Core\n", encoding="utf-8")

    monkeypatch.chdir(tmp_path)
    config = AppConfig()

    # Loaded with project context
    sess = ChatSession(config=config, no_project_context=False)
    assert "Security Core" in sess.project_context
    assert "Security Core" in sess.get_system_prompt()

    # Disabled with flag
    sess_no_ctx = ChatSession(config=config, no_project_context=True)
    assert sess_no_ctx.project_context == ""
    assert "Security Core" not in sess_no_ctx.get_system_prompt()


def test_handle_url_command():
    mock_resp = MagicMock()
    mock_resp.headers.get_content_charset.return_value = "utf-8"
    mock_resp.read.return_value = b"<html><body><h1>Title</h1><p>Test paragraph content</p></body></html>"
    mock_resp.__enter__.return_value = mock_resp
    mock_resp.__exit__.return_value = False

    with patch("urllib.request.urlopen", return_value=mock_resp):
        text = handle_url_command("https://example.com/sec-advisory")
        assert "Title" in text
        assert "Test paragraph content" in text
        assert "<html>" not in text
