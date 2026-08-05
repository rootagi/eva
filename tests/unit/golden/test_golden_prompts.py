from pathlib import Path

from eva.prompts import (
    ANALYZE_SYSTEM_PROMPT,
    ASK_SYSTEM_PROMPT,
    COMMIT_SYSTEM_PROMPT,
    EDIT_SYSTEM_PROMPT,
    EXPLAIN_SYSTEM_PROMPT,
    WORK_SYSTEM_PROMPT,
)

GOLDEN_DIR = Path(__file__).parents[2] / "fixtures" / "golden" / "prompts"


def test_golden_ask_system_prompt():
    golden_file = GOLDEN_DIR / "ask_system_prompt.txt"
    assert ASK_SYSTEM_PROMPT == golden_file.read_text(encoding="utf-8")


def test_golden_explain_system_prompt():
    golden_file = GOLDEN_DIR / "explain_system_prompt.txt"
    assert EXPLAIN_SYSTEM_PROMPT == golden_file.read_text(encoding="utf-8")


def test_golden_chat_system_prompt():
    from eva.prompts import CHAT_SYSTEM_PROMPT

    golden_file = GOLDEN_DIR / "chat_system_prompt.txt"
    assert CHAT_SYSTEM_PROMPT == golden_file.read_text(encoding="utf-8")


def test_golden_analyze_system_prompt():
    golden_file = GOLDEN_DIR / "analyze_system_prompt.txt"
    assert ANALYZE_SYSTEM_PROMPT == golden_file.read_text(encoding="utf-8")


def test_golden_work_system_prompt():
    golden_file = GOLDEN_DIR / "work_system_prompt.txt"
    assert WORK_SYSTEM_PROMPT == golden_file.read_text(encoding="utf-8")


def test_golden_edit_system_prompt():
    golden_file = GOLDEN_DIR / "edit_system_prompt.txt"
    assert EDIT_SYSTEM_PROMPT == golden_file.read_text(encoding="utf-8")


def test_golden_commit_system_prompt():
    golden_file = GOLDEN_DIR / "commit_system_prompt.txt"
    assert COMMIT_SYSTEM_PROMPT == golden_file.read_text(encoding="utf-8")
