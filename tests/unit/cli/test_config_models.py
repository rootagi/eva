"""Unit tests for eva config models discovery and set-model validation."""

import json
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from eva.cli.app import app


@pytest.fixture
def runner():
    return CliRunner()


def test_models_discovery_with_cache(runner: CliRunner, tmp_path):
    mock_models = [
        {"id": "test-provider/model-1", "name": "Model One"},
        {"id": "test-provider/model-2", "name": "Model Two"},
    ]

    with (
        patch("eva.config.get_config_dir", return_value=tmp_path),
        patch("eva.providers.groq_provider.get_models", return_value=mock_models) as mock_get,
    ):
        # 1. First fetch - hits provider
        res1 = runner.invoke(app, ["config", "models", "groq"])
        assert res1.exit_code == 0
        assert "test-provider/model-1" in res1.output
        assert mock_get.call_count == 1

        # Check cache file exists
        cache_file = tmp_path / "models_cache.json"
        assert cache_file.exists()
        data = json.loads(cache_file.read_text(encoding="utf-8"))
        assert "groq" in data["providers"]

        # 2. Second fetch - hits disk cache (mock_get call_count remains 1)
        res2 = runner.invoke(app, ["config", "models", "groq"])
        assert res2.exit_code == 0
        assert "test-provider/model-1" in res2.output
        assert mock_get.call_count == 1

        # 3. Third fetch with --refresh - bypasses cache
        res3 = runner.invoke(app, ["config", "models", "groq", "--refresh"])
        assert res3.exit_code == 0
        assert mock_get.call_count == 2


def test_models_json_output(runner: CliRunner, tmp_path):
    mock_models = [{"id": "llama-3.1", "name": "Llama 3.1"}]

    with (
        patch("eva.config.get_config_dir", return_value=tmp_path),
        patch("eva.providers.groq_provider.get_models", return_value=mock_models),
    ):
        res = runner.invoke(app, ["config", "models", "groq", "--json"])
        assert res.exit_code == 0
        data = json.loads(res.output)
        assert "groq" in data
        assert data["groq"][0]["id"] == "llama-3.1"


def test_models_unknown_provider(runner: CliRunner, tmp_path):
    with patch("eva.config.get_config_dir", return_value=tmp_path):
        res = runner.invoke(app, ["config", "models", "nonexistent_provider"])
        assert res.exit_code == 1
        assert "Unknown provider" in res.output


def test_set_model_validation_and_force(runner: CliRunner, tmp_path):
    from eva.config import load_config

    mock_models = [{"id": "llama-3.1-8b-instant", "name": "Llama 8B"}]

    with (
        patch("eva.config.get_config_dir", return_value=tmp_path),
        patch("eva.providers.groq_provider.get_models", return_value=mock_models),
    ):
        # 1. Valid model succeeds
        res_valid = runner.invoke(app, ["config", "set-model", "groq", "llama-3.1-8b-instant"])
        assert res_valid.exit_code == 0
        assert "set to 'llama-3.1-8b-instant'" in res_valid.output

        # 2. Invalid model rejected without --force
        res_invalid = runner.invoke(app, ["config", "set-model", "groq", "unknown-model-xyz"])
        assert res_invalid.exit_code == 1
        assert "not a recognized model" in res_invalid.output
        assert "--force" in res_invalid.output

        # 3. Invalid model accepted with --force
        res_forced = runner.invoke(app, ["config", "set-model", "groq", "unknown-model-xyz", "--force"])
        assert res_forced.exit_code == 0
        assert "set to 'unknown-model-xyz'" in res_forced.output
        cfg = load_config()
        assert cfg.providers["groq"].model == "unknown-model-xyz"
