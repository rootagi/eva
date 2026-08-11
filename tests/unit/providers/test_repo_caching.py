from unittest.mock import patch

from typer.testing import CliRunner

from eva.cli.app import app

runner = CliRunner()


def test_repo_packed_context_participates_in_response_caching(tmp_path):
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    (repo_dir / "main.py").write_text("def main(): pass\n")

    call_count = 0

    def mock_call_provider(provider, system_prompt, user_prompt, context, config):
        nonlocal call_count
        call_count += 1
        yield "Cached response for repo context"

    with patch("eva.providers.call_provider", side_effect=mock_call_provider):
        # First call: cache miss, invokes call_provider
        res1 = runner.invoke(app, ["ask", "Explain codebase", "--repo", str(repo_dir), "--yes"])
        assert res1.exit_code == 0
        assert "Cached response for repo context" in res1.output
        assert call_count == 1

        # Second identical call: cache hit, does not invoke call_provider again
        res2 = runner.invoke(app, ["ask", "Explain codebase", "--repo", str(repo_dir), "--yes"])
        assert res2.exit_code == 0
        assert "Cached response for repo context" in res2.output
        assert call_count == 1
