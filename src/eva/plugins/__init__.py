"""Plugin subsystem package for Eva CLI."""

from eva.plugins.loader import discover_entry_points, load_plugins
from eva.plugins.protocol import EvaPlugin, PluginError

__all__ = [
    "EvaPlugin",
    "PluginError",
    "discover_entry_points",
    "load_plugins",
]
