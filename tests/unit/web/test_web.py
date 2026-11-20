import io
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from PIL import Image
from typer.testing import CliRunner

from eva.cli.app import app
from eva.web import SearXNGClient, SSRFSafeFetcher, TerminalImageRenderer, WebIndex
from eva.web.fetcher import (
    SimpleHTMLToMarkdown,
    SSRFSecurityError,
    fetch_url,
    is_ip_blocked,
    validate_url_ssrf_safe,
)
from eva.web.imaging import TerminalImageRenderer as ImageRenderer
from eva.web.imaging import detect_image_format, render_image


def test_web_init_getattr():
    """Verify eva.web lazy attribute access and error on unknown."""
    import eva.web

    assert eva.web.SearXNGClient is SearXNGClient
    assert eva.web.WebIndex is WebIndex
    assert eva.web.SSRFSafeFetcher is SSRFSafeFetcher
    assert eva.web.TerminalImageRenderer is TerminalImageRenderer

    with pytest.raises(AttributeError):
        _ = eva.web.NonExistentClass


def test_ssrf_validator_blocks_private():
    """Verify validate_url_ssrf_safe blocks loopback, private IPs, and cloud metadata."""
    assert validate_url_ssrf_safe("http://127.0.0.1:8080/search") is False
    assert validate_url_ssrf_safe("http://localhost:3000") is False
    assert validate_url_ssrf_safe("http://169.254.169.254/latest/meta-data") is False
    assert validate_url_ssrf_safe("http://10.0.0.5/api") is False
    assert validate_url_ssrf_safe("http://192.168.1.1/admin") is False
    assert validate_url_ssrf_safe("http://172.16.0.1/status") is False
    assert validate_url_ssrf_safe("http://[::1]/secret") is False
    assert validate_url_ssrf_safe("ftp://example.com/file") is False
    assert validate_url_ssrf_safe("") is False
    assert validate_url_ssrf_safe("not-a-url") is False


def test_is_ip_blocked():
    """Verify is_ip_blocked checks for private, loopback, multicast, and ULA IPs."""
    assert is_ip_blocked("127.0.0.1") is True
    assert is_ip_blocked("10.0.1.2") is True
    assert is_ip_blocked("172.16.0.5") is True
    assert is_ip_blocked("192.168.1.1") is True
    assert is_ip_blocked("169.254.1.1") is True
    assert is_ip_blocked("::1") is True
    assert is_ip_blocked("fc00::1") is True
    assert is_ip_blocked("fe80::1") is True
    assert is_ip_blocked("invalid-ip") is True
    assert is_ip_blocked("8.8.8.8") is False
    assert is_ip_blocked("1.1.1.1") is False
    # RFC 6052 NAT64 IPv4-Embedded IPv6 translation checks
    assert is_ip_blocked("64:ff9b::a752:398c") is False  # Public 167.82.57.140
    assert is_ip_blocked("64:ff9b::7f00:0001") is True  # Loopback 127.0.0.1
    assert is_ip_blocked("64:ff9b::0a00:0001") is True  # Private 10.0.0.1


def test_ssrf_validator_allows_searxng_exemption():
    """Verify local SearXNG URL is allowed when explicitly in allowed_searxng_urls."""
    searx_url = "http://127.0.0.1:8080"
    assert validate_url_ssrf_safe("http://127.0.0.1:8080/search", allowed_searxng_urls=[searx_url]) is True


def test_ssrf_fetcher_exception():
    """Verify SSRFSafeFetcher raises SSRFSecurityError for blocked IPs."""
    fetcher = SSRFSafeFetcher()
    with pytest.raises((SSRFSecurityError, ValueError)):
        fetcher.fetch_url("http://169.254.169.254/latest/meta-data")


def test_html_to_markdown_parser():
    """Verify SimpleHTMLToMarkdown handles headings, paragraphs, pre, links, images, and ignores script."""
    html_doc = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Test Page Title</title>
        <meta name="description" content="A sample meta description.">
        <style>body { color: red; }</style>
        <script>console.log("ignore me");</script>
    </head>
    <body>
        <h1>Main Heading</h1>
        <p>This is a paragraph with <a href="https://example.com/link">link text</a> and <br> a line break.</p>
        <pre><code>def test(): pass</code></pre>
        <ul>
            <li>First bullet</li>
            <li>Second bullet</li>
        </ul>
        <img src="https://example.com/img.png" alt="example alt">
    </body>
    </html>
    """
    parser = SimpleHTMLToMarkdown()
    parser.feed(html_doc)
    parser.close()

    assert parser.title == "Test Page Title"
    assert parser.description == "A sample meta description."
    assert len(parser.links) == 1
    assert parser.links[0]["url"] == "https://example.com/link"
    assert len(parser.images) == 1
    assert "https://example.com/img.png" in parser.images

    md = parser.get_markdown()
    assert "# Main Heading" in md
    assert "[link text](https://example.com/link)" in md
    assert "```" in md
    assert "First bullet" in md
    assert "ignore me" not in md


def test_fetch_url_mocked():
    """Verify fetch_url follows redirects and returns markdown dict."""
    with patch("eva.web.fetcher.validate_url_ssrf_safe", return_value=True):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.content = b"<html><head><title>Mocked</title></head><body><p>Mocked body</p></body></html>"
        mock_response.encoding = "utf-8"
        mock_response.headers = {}

        mock_client = MagicMock()
        mock_client.get.return_value = mock_response
        mock_client.__enter__.return_value = mock_client

        with patch("httpx.Client", return_value=mock_client):
            doc = fetch_url("https://example.com")
            assert doc["title"] == "Mocked"
            assert "Mocked body" in doc["body_markdown"]


def test_web_index_sqlite_fts5(tmp_path: Path):
    """Verify WebIndex table creation, indexing, BM25 searching, and retrieval."""
    db_file = tmp_path / "test_web.db"
    idx = WebIndex(db_path=db_file)

    doc_id = idx.index_document(
        url="https://sec.example.com/advisory",
        title="Security Vulnerability Advisory",
        description="Buffer overflow in parser",
        body_markdown="# Advisory\n\nA critical buffer overflow vulnerability was identified.",
    )
    assert doc_id is not None

    hits = idx.search("Vulnerability")
    assert len(hits) >= 1
    assert hits[0]["title"] == "Security Vulnerability Advisory"

    doc_by_id = idx.get_document(doc_id)
    assert doc_by_id is not None
    assert doc_by_id["url"] == "https://sec.example.com/advisory"

    doc_by_url = idx.get_document("https://sec.example.com/advisory")
    assert doc_by_url is not None
    assert doc_by_url["id"] == doc_id

    hist = idx.list_history()
    assert len(hist) >= 1

    # Empty query returns empty list
    assert idx.search("") == []


def test_detect_image_format():
    """Verify magic byte detection correctly recognizes formats and rejects SVGs."""
    assert detect_image_format(b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR") == "png"
    assert detect_image_format(b"\xff\xd8\xff\xe0\x00\x10JFIF") == "jpeg"
    assert detect_image_format(b"GIF89a\x01\x00\x01\x00") == "gif"
    assert detect_image_format(b"<svg xmlns='http://www.w3.org/2000/svg'></svg>") is None
    assert detect_image_format(b"<?xml version='1.0'?><svg></svg>") is None
    assert detect_image_format(b"") is None


def test_terminal_image_renderer_protocols(tmp_path: Path):
    """Verify TerminalImageRenderer renders kitty, iterm2, and halfblock protocols."""
    renderer = ImageRenderer()

    # Create dummy PNG in memory
    img = Image.new("RGB", (10, 10), color="blue")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    png_bytes = buf.getvalue()

    # Kitty protocol
    kitty_out = renderer.render_image(png_bytes, protocol="kitty")
    assert "\033_G" in kitty_out

    # iTerm2 protocol
    iterm_out = renderer.render_image(png_bytes, protocol="iterm2")
    assert "\033]1337;File=" in iterm_out

    # Halfblock protocol
    half_out = renderer.render_image(png_bytes, protocol="halfblock", width=10)
    assert "▀" in half_out

    # Test file path input
    img_file = tmp_path / "sample.png"
    img_file.write_bytes(png_bytes)
    file_out = render_image(img_file, protocol="halfblock", width=5)
    assert "▀" in file_out

    # Test oversized bytes rejection
    small_renderer = ImageRenderer(max_bytes=10)
    with pytest.raises(ValueError):
        small_renderer.render_image(png_bytes)


def test_searxng_client_mocked():
    """Verify SearXNGClient live search parses JSON response and formats results."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "results": [
            {
                "url": "https://example.com/cve-1234",
                "title": "CVE-1234 Analysis",
                "content": "Advisory text details",
                "score": 0.9,
            }
        ]
    }

    mock_client = MagicMock()
    mock_client.get.return_value = mock_resp
    mock_client.__enter__.return_value = mock_client

    with patch("httpx.Client", return_value=mock_client):
        client = SearXNGClient(base_urls=["http://127.0.0.1:8080"], passive_index=False)
        results = client.search("CVE-1234")
        assert len(results) == 1
        assert results[0]["title"] == "CVE-1234 Analysis"


def test_web_cli_subcommands(tmp_path: Path):
    """Verify eva web search, open, history, and image CLI subcommands."""
    runner = CliRunner()

    # Create test indexed document
    db_file = tmp_path / "cli_web.db"
    idx = WebIndex(db_path=db_file)
    doc_id = idx.index_document(
        url="https://test.local/doc",
        title="Test Local Doc",
        description="Description for local doc",
        body_markdown="# Local Doc\nContent here",
    )

    with patch("eva.web.index.get_default_web_db_path", return_value=db_file):
        # web search --offline (JSON)
        res_search_json = runner.invoke(app, ["web", "search", "Local", "--offline", "--format", "json"])
        assert res_search_json.exit_code == 0
        assert "Test Local Doc" in res_search_json.output

        # web search --offline (Text table)
        res_search_text = runner.invoke(app, ["web", "search", "Local", "--offline", "--format", "text"])
        assert res_search_text.exit_code == 0
        assert "Test Local Doc" in res_search_text.output

        # web history (JSON)
        res_hist_json = runner.invoke(app, ["web", "history", "--format", "json"])
        assert res_hist_json.exit_code == 0
        assert "https://test.local/doc" in res_hist_json.output

        # web history (Text)
        res_hist_text = runner.invoke(app, ["web", "history", "--format", "text"])
        assert res_hist_text.exit_code == 0
        assert "Test Local Doc" in res_hist_text.output

        # web open by ID
        res_open = runner.invoke(app, ["web", "open", str(doc_id)])
        assert res_open.exit_code == 0
        assert "Local Doc" in res_open.output

    # Create dummy PNG and test web image
    img = Image.new("RGB", (4, 4), color="red")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    img_file = tmp_path / "red.png"
    img_file.write_bytes(buf.getvalue())

    res_img = runner.invoke(app, ["web", "image", str(img_file), "--protocol", "halfblock", "--width", "4"])
    assert res_img.exit_code == 0


def test_explorer_functions(monkeypatch):
    """Verify explorer is_interactive_tty and explore_web behaviour."""
    from eva.web.explorer import explore_web, is_interactive_tty

    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    assert is_interactive_tty() is False

    with pytest.raises(SystemExit) as exc_info:
        explore_web("sample query")
    assert exc_info.value.code == 1


def test_imaging_detect_terminal_protocol(monkeypatch):
    """Verify protocol detection from TERM and TERM_PROGRAM environment variables."""
    renderer = ImageRenderer()

    monkeypatch.setenv("TERM", "xterm-kitty")
    assert renderer.detect_terminal_protocol() == "kitty"

    monkeypatch.setenv("TERM", "xterm")
    monkeypatch.setenv("TERM_PROGRAM", "iTerm.app")
    assert renderer.detect_terminal_protocol() == "iterm2"

    monkeypatch.setenv("TERM", "xterm")
    monkeypatch.setenv("TERM_PROGRAM", "")
    assert renderer.detect_terminal_protocol() == "halfblock"


def test_searxng_env_url_and_empty(monkeypatch):
    """Verify SearXNGClient respects EVA_SEARXNG_URL and returns empty for blank queries."""
    monkeypatch.setenv("EVA_SEARXNG_URL", "http://searxng.internal:8080")
    client = SearXNGClient()
    assert client.base_urls == ["http://searxng.internal:8080"]

    assert client.search("   ") == []


def test_create_image_grid():
    """Verify create_image_grid creates composite image with badges."""
    from eva.web.imaging import create_image_grid

    items = [{"title": f"Test {i + 1}", "img_src": ""} for i in range(4)]
    grid_bytes, loaded = create_image_grid(items, cols=2, cell_width=60, cell_height=40)
    assert len(grid_bytes) > 0
    assert len(loaded) == 4
    assert grid_bytes[:8] == b"\x89PNG\r\n\x1a\n"


def test_web_index_last_search_tracking(tmp_path: Path):
    """Verify WebIndex correctly persists, overwrites, and retrieves last search items."""
    db_file = tmp_path / "last_search_test.db"
    idx = WebIndex(db_path=db_file)

    # Initial search session
    items_query1 = [
        {"url": f"https://query1.com/item-{i}", "title": f"Q1 Title {i}", "description": f"Desc {i}"}
        for i in range(1, 11)
    ]
    idx.save_last_search(items_query1, query="first query")

    last_items = idx.get_last_search()
    assert len(last_items) == 10
    assert last_items[0]["url"] == "https://query1.com/item-1"
    assert last_items[9]["url"] == "https://query1.com/item-10"

    item_10 = idx.get_last_search_item(10)
    assert item_10 is not None
    assert item_10["url"] == "https://query1.com/item-10"
    assert item_10["title"] == "Q1 Title 10"

    # Out of range index
    assert idx.get_last_search_item(11) is None
    assert idx.get_last_search_item(0) is None

    # Overwrite with second search session
    items_query2 = [
        {"url": f"https://query2.com/item-{i}", "title": f"Q2 Title {i}", "description": f"Desc {i}"}
        for i in range(1, 6)
    ]
    idx.save_last_search(items_query2, query="second query")

    new_last_items = idx.get_last_search()
    assert len(new_last_items) == 5
    assert new_last_items[0]["url"] == "https://query2.com/item-1"
    # Item 10 from old search should no longer be in last search
    assert idx.get_last_search_item(10) is None
    assert idx.get_last_search_item(5)["url"] == "https://query2.com/item-5"


def test_web_cli_open_resolves_last_search_result(tmp_path: Path):
    """Verify 'eva web open <N>' opens the Nth result from the user's latest search."""
    runner = CliRunner()
    db_file = tmp_path / "cli_open_test.db"
    idx = WebIndex(db_path=db_file)

    # Passive documents indexed from query 1 (doc IDs 1..10 in SQLite)
    for i in range(1, 11):
        idx.index_document(
            url=f"https://old-query.com/doc-{i}",
            title=f"Old Query Doc {i}",
            description=f"Old Description {i}",
            body_markdown=f"# Old Doc {i}\nBody from old query",
        )

    # Verify doc 10 in SQLite is old doc 10
    doc_10_db = idx.get_document(10)
    assert doc_10_db is not None
    assert doc_10_db["title"] == "Old Query Doc 10"

    with patch("eva.web.index.get_default_web_db_path", return_value=db_file):
        # Now user searches query 2
        mock_results_q2 = [
            {
                "url": f"https://new-search.com/result-{i}",
                "title": f"New Search Result {i}",
                "description": f"New Snippet {i}",
                "score": 0.9,
            }
            for i in range(1, 11)
        ]
        with patch("eva.web.searxng.search", return_value=mock_results_q2):
            res_search = runner.invoke(app, ["web", "search", "Sydney Sweeney", "--limit", "10"])
            assert res_search.exit_code == 0
            assert "New Search Result 10" in res_search.output

        # Mock fetch_url for when open_cmd fetches live content for the new URL
        def mock_fetch(url: str):
            return {
                "url": url,
                "title": f"Fetched: {url}",
                "description": "Fetched description",
                "body_markdown": f"# Live Fetched Content\nContent for {url}",
                "images": [],
                "links": [],
            }

        with patch("eva.web.fetcher.fetch_url", side_effect=mock_fetch):
            # User runs 'eva web open 10'
            res_open_10 = runner.invoke(app, ["web", "open", "10"])
            assert res_open_10.exit_code == 0
            # Must open result 10 of query 2 (https://new-search.com/result-10), NOT old query doc 10!
            assert "https://new-search.com/result-10" in res_open_10.output
            assert "Old Query Doc 10" not in res_open_10.output

            # User runs 'eva web open #1'
            res_open_hash1 = runner.invoke(app, ["web", "open", "#1"])
            assert res_open_hash1.exit_code == 0
            assert "https://new-search.com/result-1" in res_open_hash1.output

        # Browser flag test
        with patch("webbrowser.open") as mock_browser_open:
            res_browser = runner.invoke(app, ["web", "open", "2", "--browser"])
            assert res_browser.exit_code == 0
            mock_browser_open.assert_called_once_with("https://new-search.com/result-2")

        # Image index resolution test
        with patch("eva.web.imaging.render_image") as mock_render_image:
            mock_render_image.return_value = "rendered"
            res_image = runner.invoke(app, ["web", "image", "1", "--protocol", "halfblock"])
            assert res_image.exit_code == 0
            mock_render_image.assert_called_once_with("https://new-search.com/result-1", protocol="halfblock", width=80)
