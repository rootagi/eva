import typer

from eva.cli.helpers import _resolve_app_attr


def chat(
    provider: str | None = typer.Option(None, "--provider", "-p", help="Pin to a specific provider"),
    session: str | None = typer.Option(None, "--session", "-s", help="Save chat transcript under this session name"),
    resume: bool = typer.Option(False, "--resume", help="Resume the named session"),
):
    """Interactive REPL."""
    from eva.config import load_config as _load_config
    from eva.workflows.chat_session import run_chat_session as _run_chat_session

    load_config = _resolve_app_attr("load_config", _load_config)
    run_chat_session = _resolve_app_attr("run_chat_session", _run_chat_session)

    config = load_config()
    run_chat_session(config=config, provider=provider, session=session, resume=resume)
