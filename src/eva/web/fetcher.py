"""SSRF-Safe HTTP Fetcher with HTML-to-Markdown Extraction."""

from __future__ import annotations

import html
import ipaddress
import re
import socket
import urllib.parse
from html.parser import HTMLParser
from typing import Any


class SSRFSecurityError(ValueError):
    """Raised when an outbound URL targets a forbidden private, loopback, or metadata network."""


BLOCKED_IP_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("192.88.99.0/24"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("240.0.0.0/4"),
    ipaddress.ip_network("255.255.255.255/32"),
    # IPv6 blocked ranges
    ipaddress.ip_network("::/128"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),  # IPv6 ULA
    ipaddress.ip_network("fe80::/10"),  # IPv6 link-local
    ipaddress.ip_network("ff00::/8"),  # IPv6 multicast
]

NAT64_WKP = ipaddress.ip_network("64:ff9b::/96")


def is_ip_blocked(ip_str: str) -> bool:
    """Check if an IP address belongs to any blocked network range."""
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return True

    # Support RFC 6052 NAT64 IPv4-Embedded IPv6 addresses by inspecting the translated IPv4
    if ip.version == 6 and ip in NAT64_WKP:
        embedded_v4 = ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
        return is_ip_blocked(str(embedded_v4))

    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast or ip.is_unspecified:
        return True

    for net in BLOCKED_IP_NETWORKS:
        if ip in net:
            return True
    return False


def validate_url_ssrf_safe(url: str, allowed_searxng_urls: list[str] | None = None) -> bool:
    """Validate whether an outbound URL is safe from SSRF vulnerabilities."""
    if not url:
        return False

    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return False

    hostname = parsed.hostname
    if not hostname:
        return False

    hostname_lower = hostname.lower()
    if hostname_lower in ("localhost", "localhost.localdomain", "127.0.0.1", "[::1]", "::1"):
        # Check if explicitly exempted (e.g. SearXNG local development instance)
        if allowed_searxng_urls:
            for allowed in allowed_searxng_urls:
                allowed_parsed = urllib.parse.urlparse(allowed)
                if (
                    allowed_parsed.scheme == parsed.scheme
                    and allowed_parsed.hostname == hostname
                    and allowed_parsed.port == parsed.port
                ):
                    return True
        return False

    # Check for direct cloud metadata address
    if "169.254.169.254" in hostname_lower or "169.254." in hostname_lower:
        return False

    # Resolve hostname to IP addresses
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    try:
        addrinfo = socket.getaddrinfo(hostname, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        # Cannot resolve hostname
        return False

    if not addrinfo:
        return False

    for item in addrinfo:
        sockaddr = item[4]
        ip_addr = sockaddr[0]
        if is_ip_blocked(ip_addr):
            # Check exemption
            if allowed_searxng_urls:
                for allowed in allowed_searxng_urls:
                    allowed_parsed = urllib.parse.urlparse(allowed)
                    if (
                        allowed_parsed.scheme == parsed.scheme
                        and allowed_parsed.hostname == hostname
                        and allowed_parsed.port == parsed.port
                    ):
                        return True
            return False

    return True


class SimpleHTMLToMarkdown(HTMLParser):
    """Converts HTML text to clean Markdown without third-party dependencies."""

    def __init__(self) -> None:
        super().__init__()
        self.output: list[str] = []
        self.title: str = ""
        self.description: str = ""
        self.links: list[dict[str, str]] = []
        self.images: list[str] = []
        self._in_title = False
        self._in_script_or_style = False
        self._in_pre = False
        self._current_tag = ""
        self._link_href = ""
        self._link_text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr_dict = {k.lower(): v or "" for k, v in attrs}
        self._current_tag = tag.lower()

        if self._current_tag in ("script", "style", "noscript", "svg"):
            self._in_script_or_style = True
            return

        if self._current_tag == "title":
            self._in_title = True
            return

        if self._current_tag == "meta":
            if attr_dict.get("name", "").lower() == "description":
                self.description = attr_dict.get("content", "").strip()
            return

        if self._in_script_or_style:
            return

        if self._current_tag == "pre":
            self._in_pre = True
            self.output.append("\n```\n")
        elif self._current_tag in ("h1", "h2", "h3", "h4", "h5", "h6"):
            level = int(self._current_tag[1])
            self.output.append(f"\n\n{'#' * level} ")
        elif self._current_tag == "p":
            self.output.append("\n\n")
        elif self._current_tag == "br":
            self.output.append("\n")
        elif self._current_tag == "li":
            self.output.append("\n- ")
        elif self._current_tag == "a":
            self._link_href = attr_dict.get("href", "")
            self._link_text = []
        elif self._current_tag == "img":
            src = attr_dict.get("src", "")
            alt = attr_dict.get("alt", "image")
            if src:
                self.images.append(src)
                self.output.append(f"![{alt}]({src})")

    def handle_endtag(self, tag: str) -> None:
        tag_lower = tag.lower()
        if tag_lower in ("script", "style", "noscript", "svg"):
            self._in_script_or_style = False
            return

        if tag_lower == "title":
            self._in_title = False
            return

        if self._in_script_or_style:
            return

        if tag_lower == "pre":
            self._in_pre = False
            self.output.append("\n```\n")
        elif tag_lower == "a" and self._link_href:
            anchor_text = "".join(self._link_text).strip() or self._link_href
            self.links.append({"text": anchor_text, "url": self._link_href})
            self.output.append(f"[{anchor_text}]({self._link_href})")
            self._link_href = ""
            self._link_text = []
        elif tag_lower in ("p", "div", "h1", "h2", "h3", "h4", "h5", "h6"):
            self.output.append("\n")

    def handle_data(self, data: str) -> None:
        if self._in_script_or_style:
            return

        if self._in_title:
            self.title += data.strip()
            return

        if self._link_href:
            self._link_text.append(data)
            return

        if self._in_pre:
            self.output.append(data)
        else:
            cleaned = re.sub(r"[ \t]+", " ", data)
            self.output.append(cleaned)

    def get_markdown(self) -> str:
        text = "".join(self.output)
        text = html.unescape(text)
        text = re.sub(r"\n{3,}", "\n\n", text)
        return text.strip()


class SSRFSafeFetcher:
    """Safe HTTP web fetcher providing SSRF defense and HTML to Markdown conversion."""

    def __init__(self, allowed_searxng_urls: list[str] | None = None) -> None:
        self.allowed_searxng_urls = allowed_searxng_urls or []

    def validate_url(self, url: str) -> bool:
        return validate_url_ssrf_safe(url, allowed_searxng_urls=self.allowed_searxng_urls)

    def fetch_url(
        self,
        url: str,
        max_bytes: int = 2 * 1024 * 1024,
        timeout: float = 10.0,
    ) -> dict[str, Any]:
        """Fetch URL with SSRF validation across initial request and redirects."""
        if not self.validate_url(url):
            raise SSRFSecurityError(f"SSRF security check failed: blocked dangerous or private URL: {url}")

        import httpx

        headers = {
            "User-Agent": (
                "Eva/5.0 (https://github.com/eva-cli/eva; contact@eva.local) "
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/124.0.0.0 Safari/537.36"
            ),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        }

        current_url = url
        redirects = 0
        max_redirects = 5

        with httpx.Client(timeout=timeout, follow_redirects=False, headers=headers) as client:
            while True:
                response = client.get(current_url)

                # Check redirect
                if 300 <= response.status_code < 400:
                    redirects += 1
                    if redirects > max_redirects:
                        raise SSRFSecurityError("SSRF error: maximum redirects exceeded")

                    location = response.headers.get("location")
                    if not location:
                        break
                    next_url = urllib.parse.urljoin(current_url, location)
                    if not self.validate_url(next_url):
                        raise SSRFSecurityError(
                            f"SSRF security check failed: redirect to blocked/metadata destination: {next_url}"
                        )
                    current_url = next_url
                    continue

                response.raise_for_status()
                break

            content_bytes = response.content[:max_bytes]
            text = content_bytes.decode(response.encoding or "utf-8", errors="replace")

        # Parse HTML to Markdown
        parser = SimpleHTMLToMarkdown()
        parser.feed(text)
        parser.close()

        return {
            "url": current_url,
            "title": parser.title or current_url,
            "description": parser.description,
            "body_markdown": parser.get_markdown(),
            "links": parser.links,
            "images": parser.images,
        }


def fetch_url(
    url: str,
    max_bytes: int = 2 * 1024 * 1024,
    timeout: float = 10.0,
    allowed_searxng_urls: list[str] | None = None,
) -> dict[str, Any]:
    """Top-level convenience fetcher with SSRF guards."""
    fetcher = SSRFSafeFetcher(allowed_searxng_urls=allowed_searxng_urls)
    return fetcher.fetch_url(url, max_bytes=max_bytes, timeout=timeout)
