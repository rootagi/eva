from unittest.mock import patch

from eva.config import AppConfig
from eva.workflows.chat_session import run_chat_session


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

    session_file = tmp_path / "sessions" / "test_sess.md"
    assert session_file.exists()
    content = session_file.read_text(encoding="utf-8")
    assert "User: hello" in content
    assert "Eva: Hi there!" in content
