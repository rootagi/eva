"""Unit tests for plugin discovery, loading, fail-soft handling, and command dispatch."""

import logging
from unittest.mock import MagicMock, patch

import typer
from typer.testing import CliRunner

from eva.plugins import EvaPlugin, PluginError, discover_entry_points, load_plugins


class DummyPlugin(EvaPlugin):
    name = "dummy-plugin"
    version = "1.0.0"

    def __init__(self):
        self.commands_registered = False
        self.providers_registered = False
        self.hooks_registered = False

    def register_commands(self, app: typer.Typer) -> None:
        self.commands_registered = True

        @app.command("dummy-cmd")
        def dummy_cmd():
            typer.echo("Dummy output")

    def register_providers(self) -> None:
        self.providers_registered = True

    def register_workflow_hooks(self) -> None:
        super().register_workflow_hooks()
        self.hooks_registered = True


class MinimalPlugin(EvaPlugin):
    name = "minimal-plugin"
    version = "1.0.0"


class BrokenLoadEntryPoint:
    name = "broken-load"
    value = "dummy:broken"

    def load(self):
        raise ImportError("Plugin module missing")


class BrokenInitPlugin(EvaPlugin):
    name = "broken-init"
    version = "1.0.0"

    def __init__(self):
        raise RuntimeError("Initialization error")


class NonPluginClass:
    pass


def test_discover_entry_points():
    mock_ep = MagicMock()
    mock_ep.name = "test-ep"
    with patch("importlib.metadata.entry_points") as mock_entry_points:
        mock_entry_points.return_value = [mock_ep]
        eps = discover_entry_points()
        assert len(eps) == 1
        assert eps[0].name == "test-ep"


def test_discover_entry_points_type_error_fallback():
    mock_ep = MagicMock()
    mock_ep.name = "fallback-ep"

    class SelectableList(list):
        def select(self, group=None):
            return [mock_ep]

    with patch("importlib.metadata.entry_points") as mock_entry_points:
        mock_entry_points.side_effect = [TypeError("group not supported"), SelectableList([mock_ep])]
        eps = discover_entry_points()
        assert len(eps) == 1
        assert eps[0].name == "fallback-ep"


def test_discover_entry_points_dict_fallback():
    mock_ep = MagicMock()
    mock_ep.name = "dict-ep"

    with patch("importlib.metadata.entry_points") as mock_entry_points:
        mock_entry_points.side_effect = [TypeError("group not supported"), {"eva.plugins": [mock_ep]}]
        eps = discover_entry_points()
        assert len(eps) == 1
        assert eps[0].name == "dict-ep"


def test_discover_entry_points_empty_fallback():
    with patch("importlib.metadata.entry_points") as mock_entry_points:
        mock_entry_points.side_effect = [TypeError("group not supported"), None]
        eps = discover_entry_points()
        assert eps == []


def test_successful_plugin_registration():
    test_app = typer.Typer()
    mock_ep = MagicMock()
    mock_ep.name = "dummy"
    mock_ep.value = "dummy:DummyPlugin"
    mock_ep.load.return_value = DummyPlugin

    with patch("eva.plugins.loader.discover_entry_points", return_value=[mock_ep]):
        plugins = load_plugins(test_app)

    assert len(plugins) == 1
    plugin = plugins[0]
    assert isinstance(plugin, DummyPlugin)
    assert plugin.commands_registered is True
    assert plugin.providers_registered is True


def test_already_instantiated_plugin_entry_point():
    test_app = typer.Typer()
    instance = DummyPlugin()
    mock_ep = MagicMock()
    mock_ep.name = "instance_dummy"
    mock_ep.value = "dummy:instance"
    mock_ep.load.return_value = instance

    with patch("eva.plugins.loader.discover_entry_points", return_value=[mock_ep]):
        plugins = load_plugins(test_app)

    assert len(plugins) == 1
    assert plugins[0] is instance


def test_minimal_plugin_defaults():
    test_app = typer.Typer()
    mock_ep = MagicMock()
    mock_ep.name = "minimal"
    mock_ep.value = "dummy:MinimalPlugin"
    mock_ep.load.return_value = MinimalPlugin

    with patch("eva.plugins.loader.discover_entry_points", return_value=[mock_ep]):
        plugins = load_plugins(test_app)

    assert len(plugins) == 1
    p = plugins[0]
    p.register_commands(test_app)
    p.register_providers()


def test_factory_plugin_registration():
    test_app = typer.Typer()
    instance = DummyPlugin()
    factory = lambda: instance

    mock_ep = MagicMock()
    mock_ep.name = "factory_dummy"
    mock_ep.value = "dummy:factory"
    mock_ep.load.return_value = factory

    with patch("eva.plugins.loader.discover_entry_points", return_value=[mock_ep]):
        plugins = load_plugins(test_app)

    assert len(plugins) == 1
    assert plugins[0] is instance


def test_factory_plugin_returns_invalid_instance(caplog):
    test_app = typer.Typer()
    factory = lambda: "not a plugin"

    mock_ep = MagicMock()
    mock_ep.name = "invalid_factory"
    mock_ep.value = "dummy:factory"
    mock_ep.load.return_value = factory

    with patch("eva.plugins.loader.discover_entry_points", return_value=[mock_ep]), caplog.at_level(logging.WARNING):
        plugins = load_plugins(test_app)

    assert plugins == []
    assert "returned 'not a plugin', which is not an EvaPlugin instance" in caplog.text


def test_plugin_raises_on_load(caplog):
    test_app = typer.Typer()
    broken_ep = BrokenLoadEntryPoint()

    with patch("eva.plugins.loader.discover_entry_points", return_value=[broken_ep]), caplog.at_level(logging.WARNING):
        plugins = load_plugins(test_app)

    assert plugins == []
    assert "Failed to load plugin entry point 'broken-load'" in caplog.text


def test_plugin_raises_on_init(caplog):
    test_app = typer.Typer()
    mock_ep = MagicMock()
    mock_ep.name = "broken-init-ep"
    mock_ep.value = "dummy:BrokenInitPlugin"
    mock_ep.load.return_value = BrokenInitPlugin

    with patch("eva.plugins.loader.discover_entry_points", return_value=[mock_ep]), caplog.at_level(logging.WARNING):
        plugins = load_plugins(test_app)

    assert plugins == []
    assert "Failed to initialize or register plugin 'broken-init-ep'" in caplog.text


def test_plugin_invalid_type(caplog):
    test_app = typer.Typer()
    mock_ep = MagicMock()
    mock_ep.name = "invalid-type"
    mock_ep.value = "dummy:NonPluginClass"
    mock_ep.load.return_value = NonPluginClass

    with patch("eva.plugins.loader.discover_entry_points", return_value=[mock_ep]), caplog.at_level(logging.WARNING):
        plugins = load_plugins(test_app)

    assert plugins == []
    assert "is not an EvaPlugin subclass" in caplog.text


def test_plugin_non_callable_non_class_object(caplog):
    test_app = typer.Typer()
    mock_ep = MagicMock()
    mock_ep.name = "raw-int"
    mock_ep.value = "dummy:int_val"
    mock_ep.load.return_value = 12345

    with patch("eva.plugins.loader.discover_entry_points", return_value=[mock_ep]), caplog.at_level(logging.WARNING):
        plugins = load_plugins(test_app)

    assert plugins == []
    assert "resolved to 12345, which is not an EvaPlugin subclass or instance" in caplog.text


def test_workflow_hooks_warning_logged(caplog):
    test_app = typer.Typer()
    mock_ep = MagicMock()
    mock_ep.name = "dummy-hooks"
    mock_ep.value = "dummy:DummyPlugin"
    mock_ep.load.return_value = DummyPlugin

    with patch("eva.plugins.loader.discover_entry_points", return_value=[mock_ep]), caplog.at_level(logging.WARNING):
        plugins = load_plugins(test_app)

    assert len(plugins) == 1
    assert plugins[0].hooks_registered is True
    assert "workflow hook registration is not wired up in this version of Eva" in caplog.text


def test_command_dispatch_through_plugin():
    from eva.cli.app import app

    mock_ep = MagicMock()
    mock_ep.name = "dummy"
    mock_ep.value = "dummy:DummyPlugin"
    mock_ep.load.return_value = DummyPlugin

    with patch("eva.plugins.loader.discover_entry_points", return_value=[mock_ep]):
        load_plugins(app)

    runner = CliRunner()
    result = runner.invoke(app, ["dummy-cmd"])
    assert result.exit_code == 0
    assert "Dummy output" in result.stdout


def test_plugin_error_exception():
    exc = PluginError("Test plugin error")
    assert str(exc) == "Test plugin error"
