"""Base plugin protocol and classes for Eva CLI plugins."""

import logging
from abc import ABC

import typer

logger = logging.getLogger(__name__)


class PluginError(Exception):
    """Base exception raised for plugin load or execution errors."""


class EvaPlugin(ABC):
    """Abstract base class for all Eva CLI plugins.

    Plugins should subclass this class and override methods as needed.
    """

    name: str
    version: str

    def register_commands(self, app: typer.Typer) -> None:
        """Register CLI commands or sub-typer applications with Eva's main Typer app.

        Args:
            app: The main root Typer application.
        """

    def register_providers(self) -> None:
        """Register custom LLM providers with Eva's provider registry."""

    def register_workflow_hooks(self) -> None:
        """Register workflow hooks for step execution.

        Note: Workflow step hook dispatch is not yet wired up in this version of Eva.
        Future versions will support read-only observer hooks (e.g. on_step_start,
        on_step_complete) for logging and notifications.
        """
        logger.warning(
            "Plugin '%s' registered workflow hooks, but workflow hook registration "
            "is not wired up in this version of Eva; hooks will not fire.",
            getattr(self, "name", self.__class__.__name__),
        )
