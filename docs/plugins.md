# Plugin System

Eva CLI features an extensible plugin architecture. Third-party packages can register CLI commands, contribute custom AI providers, or register workflow step hooks by creating standard Python packages with entry points.

---

## Architecture Overview

The plugin subsystem (`src/eva/plugins/`) consists of:

| Module | Purpose |
| --- | --- |
| `protocol.py` | Defines `EvaPlugin` abstract base class and `PluginError` exception. |
| `loader.py` | Automatic discovery via `importlib.metadata.entry_points` under the `"eva.plugins"` group. |
| `__init__.py` | Re-exports `EvaPlugin` and `PluginError` for public API. |

---

## Writing a Plugin

### 1. Create the Plugin Class

Subclass `EvaPlugin` and override the lifecycle hooks you need:

```python
import typer
from eva.plugins import EvaPlugin


class MyPlugin(EvaPlugin):
    name = "my-plugin"
    version = "0.1.0"

    def register_commands(self, app: typer.Typer) -> None:
        @app.command("my-command")
        def my_command():
            """Custom command contributed by plugin."""
            typer.echo("Hello from my plugin!")

    def register_providers(self) -> None:
        # Register custom LLM provider implementations here
        pass
```

### 2. Register the Entry Point

Expose the plugin in your package's `pyproject.toml`:

```toml
[project.entry-points."eva.plugins"]
my_plugin = "my_package.module:MyPlugin"
```

### 3. Install the Package

Install your plugin package into the same environment as Eva:

```bash
pip install .
# or for development:
pip install -e .
```

Eva automatically discovers installed plugins via `importlib.metadata.entry_points` on startup.

---

## Plugin Lifecycle Hooks

| Method | Purpose | Status |
| --- | --- | --- |
| `register_commands(app)` | Add custom CLI commands or sub-Typer apps to Eva's main Typer app. | ✅ Active |
| `register_providers()` | Register custom LLM provider implementations with Eva's provider registry. | ✅ Active |
| `register_workflow_hooks()` | Register workflow step observer hooks (e.g., `on_step_start`, `on_step_complete`). | ⏳ Future |

---

## Fail-Soft Safety

If an installed plugin fails to load or raises an exception during initialization, Eva logs a warning and skips the broken plugin without interrupting CLI operation:

```text
WARNING: Plugin 'broken-plugin' failed to load: ModuleNotFoundError: No module named 'missing_dep'
```

This ensures that a single broken plugin never takes down the entire CLI.

---

## Example Plugin

See [`examples/eva-plugin-hello`](../examples/eva-plugin-hello) for a complete reference plugin package that adds a `hello` command.
