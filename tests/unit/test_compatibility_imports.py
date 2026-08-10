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
