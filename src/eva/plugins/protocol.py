"""Base plugin protocol and classes for Eva CLI plugins."""

import logging
from abc import ABC
from typing import Any

import typer

logger = logging.getLogger(__name__)


class PluginError(Exception):
    """Base exception raised for plugin load or execution errors."""


class WorkflowHooks:
    """Read-only observer hooks for workflow execution lifecycle."""

    def on_workflow_start(self, workflow_id: str, context: dict[str, Any] | None = None) -> None:
        """Called when workflow execution begins."""

    def on_step_start(self, step_id: str, step_data: dict[str, Any] | None = None) -> None:
        """Called immediately before a workflow step executes."""

    def on_step_complete(self, step_id: str, step_result: dict[str, Any] | None = None) -> None:
        """Called immediately after a workflow step successfully executes."""

    def on_step_error(self, step_id: str, error: dict[str, Any] | None = None) -> None:
        """Called when a workflow step fails, is declined, or is blocked by safety checks."""

    def on_workflow_complete(self, workflow_id: str, summary: dict[str, Any] | None = None) -> None:
        """Called after all steps finish or workflow halts early."""


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

    def register_workflow_hooks(self) -> WorkflowHooks | list[WorkflowHooks] | None:
        """Register workflow hooks for step execution.

        Plugins may override this method to return a WorkflowHooks instance
        (or list of instances), or register hooks with register_workflow_hook().
        """
        logger.warning(
            "Plugin '%s' registered workflow hooks, but workflow hook registration "
            "is not wired up in this version of Eva; hooks will not fire.",
            getattr(self, "name", self.__class__.__name__),
        )
        return None
