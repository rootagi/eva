"""Discovery and loading of Eva plugins via Python entry points."""

import importlib.metadata
import logging

import typer

from eva.plugins.protocol import EvaPlugin

logger = logging.getLogger(__name__)

ENTRY_POINT_GROUP = "eva.plugins"


def discover_entry_points():
    """Discover registered entry points for Eva plugins."""
    try:
        eps = importlib.metadata.entry_points(group=ENTRY_POINT_GROUP)
        return list(eps)
    except TypeError:
        # Fallback for older importlib_metadata interface if present
        all_eps = importlib.metadata.entry_points()
        if hasattr(all_eps, "select"):
            return list(all_eps.select(group=ENTRY_POINT_GROUP))
        elif isinstance(all_eps, dict):
            return list(all_eps.get(ENTRY_POINT_GROUP, []))
        return []


def load_plugins(app: typer.Typer) -> list[EvaPlugin]:
    """Discover, load, and register all installed Eva plugins.

    Fails soft: if a plugin fails to load, instantiate, or register, a warning is
    logged and the plugin is skipped.

    Args:
        app: Main Typer app instance to pass to plugin command registration.

    Returns:
        List of successfully loaded and initialized EvaPlugin instances.
    """
    entry_points = discover_entry_points()
    loaded_plugins: list[EvaPlugin] = []

    for ep in entry_points:
        plugin_name = ep.name
        try:
            plugin_obj = ep.load()
        except Exception as exc:
            logger.warning("Failed to load plugin entry point '%s': %s", plugin_name, exc, exc_info=True)
            continue

        try:
            if isinstance(plugin_obj, type):
                if issubclass(plugin_obj, EvaPlugin):
                    plugin_instance = plugin_obj()
                else:
                    logger.warning(
                        "Plugin entry point '%s' resolved to class %r, which is not an EvaPlugin subclass.",
                        plugin_name,
                        plugin_obj,
                    )
                    continue
            elif isinstance(plugin_obj, EvaPlugin):
                plugin_instance = plugin_obj
            elif callable(plugin_obj):
                candidate = plugin_obj()
                if isinstance(candidate, EvaPlugin):
                    plugin_instance = candidate
                else:
                    logger.warning(
                        "Factory entry point '%s' returned %r, which is not an EvaPlugin instance.",
                        plugin_name,
                        candidate,
                    )
                    continue
            else:
                logger.warning(
                    "Plugin entry point '%s' resolved to %r, which is not an EvaPlugin subclass or instance.",
                    plugin_name,
                    plugin_obj,
                )
                continue

            # Run registration lifecycle
            plugin_instance.register_providers()
            plugin_instance.register_commands(app)

            # Check if subclass overrode register_workflow_hooks
            if type(plugin_instance).register_workflow_hooks != EvaPlugin.register_workflow_hooks:
                plugin_instance.register_workflow_hooks()

            loaded_plugins.append(plugin_instance)
            logger.debug(
                "Successfully loaded plugin '%s' (%s)", getattr(plugin_instance, "name", plugin_name), ep.value
            )

        except Exception as exc:
            logger.warning("Failed to initialize or register plugin '%s': %s", plugin_name, exc, exc_info=True)
            continue

    return loaded_plugins
