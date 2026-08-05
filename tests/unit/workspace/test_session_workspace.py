from typer.testing import CliRunner

from eva.cli.app import app
from eva.workspace.session import (
    add_bookmark,
    add_history,
    add_note,
    create_workspace,
    get_active_workspace,
    get_workspace,
    list_workspaces,
    redact_secrets,
    set_active_workspace,
)

runner = CliRunner()


def test_redact_secrets():
    raw_key = "my key is sk-123456789012345678901234"
    redacted = redact_secrets(raw_key)
    assert "sk-" not in redacted or "[REDACTED_SECRET_KEY]" in redacted

    env_str = "export EVA_GROQ_API_KEY=secret_key_12345678"
    assert "[REDACTED_API_KEY]" in redact_secrets(env_str)

    bearer_str = "Authorization: Bearer abcdef123456789"
    assert "[REDACTED_BEARER_TOKEN]" in redact_secrets(bearer_str)


def test_workspace_isolation_no_state_leak(tmp_path, monkeypatch):
    """Verify eva workspace commands don't leak state between different workspace names."""
    monkeypatch.setattr("eva.workspace.session.get_config_dir", lambda: tmp_path)

    ws_a = create_workspace("proj_alpha")
    ws_b = create_workspace("proj_beta")

    add_note("proj_alpha", "Alpha secret notes")
    add_bookmark("proj_alpha", "/path/to/alpha.py")
    add_history("proj_alpha", "command", "git status in alpha")

    add_note("proj_beta", "Beta confidential notes")
    add_bookmark("proj_beta", "/path/to/beta.py")

    loaded_a = get_workspace("proj_alpha")
    loaded_b = get_workspace("proj_beta")

    # Verify no state leaked from Alpha to Beta
    assert any("Alpha secret notes" in n for n in loaded_a.notes)
    assert not any("Alpha secret notes" in n for n in loaded_b.notes)

    assert "/path/to/alpha.py" in loaded_a.bookmarks
    assert "/path/to/alpha.py" not in loaded_b.bookmarks

    assert "/path/to/beta.py" in loaded_b.bookmarks
    assert "/path/to/beta.py" not in loaded_a.bookmarks

    assert len(loaded_a.history) == 1
    assert len(loaded_b.history) == 0


def test_active_workspace_switch(tmp_path, monkeypatch):
    monkeypatch.setattr("eva.workspace.session.get_config_dir", lambda: tmp_path)

    set_active_workspace("workspace_one")
    assert get_active_workspace() == "workspace_one"

    set_active_workspace("workspace_two")
    assert get_active_workspace() == "workspace_two"

    all_ws = list_workspaces()
    assert "workspace_one" in all_ws
    assert "workspace_two" in all_ws


def test_workspace_cli_commands(tmp_path, monkeypatch):
    monkeypatch.setattr("eva.workspace.session.get_config_dir", lambda: tmp_path)

    res_create = runner.invoke(app, ["workspace", "create", "my_cli_ws"])
    assert res_create.exit_code == 0
    assert "Created and activated workspace 'my_cli_ws'" in res_create.output

    res_switch = runner.invoke(app, ["workspace", "switch", "my_cli_ws"])
    assert res_switch.exit_code == 0
    assert "Switched active workspace to 'my_cli_ws'" in res_switch.output

    res_note = runner.invoke(app, ["workspace", "note", "Important", "meeting", "notes"])
    assert res_note.exit_code == 0
    assert "Added note to workspace 'my_cli_ws'" in res_note.output

    res_bm = runner.invoke(app, ["workspace", "bookmark", "src/eva/cli/app.py"])
    assert res_bm.exit_code == 0
    assert "Bookmarked" in res_bm.output

    res_show = runner.invoke(app, ["workspace", "show"])
    assert res_show.exit_code == 0
    assert "Important meeting notes" in res_show.output
    assert "src/eva/cli/app.py" in res_show.output

    res_list = runner.invoke(app, ["workspace", "list"])
    assert res_list.exit_code == 0
    assert "my_cli_ws" in res_list.output
