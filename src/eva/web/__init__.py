"""Eva Web Search, Offline FTS5 Indexing, and Terminal Visuals."""

__all__ = [
    "SSRFSafeFetcher",
    "SearXNGClient",
    "TerminalImageRenderer",
    "WebIndex",
]


def __getattr__(name: str):
    if name == "SearXNGClient":
        from eva.web.searxng import SearXNGClient

        return SearXNGClient
    if name == "WebIndex":
        from eva.web.index import WebIndex

        return WebIndex
    if name == "SSRFSafeFetcher":
        from eva.web.fetcher import SSRFSafeFetcher

        return SSRFSafeFetcher
    if name == "TerminalImageRenderer":
        from eva.web.imaging import TerminalImageRenderer

        return TerminalImageRenderer
    raise AttributeError(f"module 'eva.web' has no attribute '{name}'")
