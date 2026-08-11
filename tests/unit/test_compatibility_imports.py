import importlib

import pytest


def test_router_shim_removed():
    """Guard: eva.router must not exist — use eva.providers instead."""
    with pytest.raises(ModuleNotFoundError):
        importlib.import_module("eva.router")


def test_context_shim_removed():
    """Guard: eva.context must not exist — use eva.indexing / eva.workspace instead."""
    with pytest.raises(ModuleNotFoundError):
        importlib.import_module("eva.context")


@pytest.mark.parametrize(
    "mod_name",
    [
        "eva.budget",
        "eva.work_safety",
        "eva.git_ops",
        "eva.chat_session",
        "eva.diagnostics",
    ],
)
def test_legacy_shims_removed(mod_name):
    """Guard: legacy flat shim modules must be removed."""
    with pytest.raises(ModuleNotFoundError):
        importlib.import_module(mod_name)
