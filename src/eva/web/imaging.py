"""Multi-Protocol Terminal Image Renderer with SSRF Guards and Decompression Protection."""

from __future__ import annotations

import base64
import io
import logging
import os
from pathlib import Path
from typing import Any

from eva.security_tools.deps import missing_extra_exit
from eva.web.fetcher import SSRFSecurityError, validate_url_ssrf_safe

logger = logging.getLogger(__name__)

MAGIC_SIGNATURES = {
    b"\x89PNG\r\n\x1a\n": "png",
    b"\xff\xd8\xff": "jpeg",
    b"GIF87a": "gif",
    b"GIF89a": "gif",
    b"RIFF": "webp",
}


def detect_image_format(data: bytes) -> str | None:
    """Identify image format from magic header bytes, explicitly rejecting SVGs."""
    if not data or len(data) < 8:
        return None

    # Check for SVG or XML
    prefix = data[:128].lower()
    if b"<svg" in prefix or b"<?xml" in prefix:
        return None

    for magic, fmt in MAGIC_SIGNATURES.items():
        if data.startswith(magic):
            if fmt == "webp" and data[8:12] != b"WEBP":
                continue
            return fmt
    return None


class TerminalImageRenderer:
    """Renders images directly in terminal via Kitty, Sixel, iTerm2, or TrueColor half-blocks."""

    def __init__(
        self,
        max_pixels: int = 100_000_000,
        max_bytes: int = 5 * 1024 * 1024,
    ) -> None:
        self.max_pixels = max_pixels
        self.max_bytes = max_bytes

    def detect_terminal_protocol(self) -> str:
        """Auto-detect the best graphics protocol supported by the current terminal."""
        term = os.environ.get("TERM", "").lower()
        term_program = os.environ.get("TERM_PROGRAM", "").lower()

        if "kitty" in term or "kitty" in term_program:
            return "kitty"
        if "iterm" in term_program or "wezterm" in term_program:
            return "iterm2"
        if "foot" in term or "sixel" in term:
            return "sixel"
        return "halfblock"

    def render_image(
        self,
        image_source: str | bytes | Path,
        protocol: str = "auto",
        width: int = 80,
        height: int | None = None,
    ) -> str:
        """Render image into terminal control sequences."""
        # Load image bytes
        if isinstance(image_source, bytes):
            raw_bytes = image_source
        elif isinstance(image_source, Path) or (
            isinstance(image_source, str) and not image_source.startswith(("http://", "https://"))
        ):
            path = Path(image_source)
            if not path.is_file():
                raise FileNotFoundError(f"Image file not found: {path}")
            raw_bytes = path.read_bytes()
        else:
            # Remote URL: enforce SSRF check and byte limit
            url = str(image_source)
            if not validate_url_ssrf_safe(url):
                raise SSRFSecurityError(f"SSRF blocked: image URL {url} targets private network")

            import httpx

            with httpx.Client(timeout=10.0) as client:
                resp = client.get(url)
                resp.raise_for_status()
                raw_bytes = resp.content[: self.max_bytes]

        if len(raw_bytes) > self.max_bytes:
            raise ValueError(f"Image size exceeds maximum limit of {self.max_bytes} bytes")

        fmt = detect_image_format(raw_bytes)
        if not fmt:
            raise ValueError("Unsupported or invalid image format (SVGs and non-image binaries are rejected)")

        # Verify Pillow availability
        try:
            from PIL import Image
        except ImportError:
            missing_extra_exit("web-images", "Pillow is required for terminal image rendering.")
            return ""

        Image.MAX_IMAGE_PIXELS = self.max_pixels

        try:
            img = Image.open(io.BytesIO(raw_bytes))
            img.verify()
            img = Image.open(io.BytesIO(raw_bytes))
        except (OSError, ValueError, RuntimeError) as exc:
            raise ValueError(f"Invalid or corrupted image: {exc}") from exc

        if (img.width * img.height) > self.max_pixels:
            raise ValueError(f"Decompression bomb detected: image exceeds {self.max_pixels} pixels")

        if protocol == "auto":
            protocol = self.detect_terminal_protocol()

        if protocol == "kitty":
            return self._render_kitty(raw_bytes, fmt, img=img, width=width)
        if protocol == "iterm2":
            return self._render_iterm2(raw_bytes)
        if protocol == "halfblock":
            return self._render_halfblock(img, width=width, height=height)

        # Fallback to halfblock
        return self._render_halfblock(img, width=width, height=height)

    def _render_kitty(
        self,
        raw_bytes: bytes,
        fmt: str,
        img: Any = None,
        width: int | None = None,
    ) -> str:
        """Format image using Kitty Graphics Protocol APC chunking."""
        # Kitty f=100 strictly requires valid PNG payload. Convert non-PNG images.
        if fmt != "png" and img is not None:
            buf = io.BytesIO()
            img.save(buf, format="PNG")
            raw_bytes = buf.getvalue()

        b64 = base64.b64encode(raw_bytes).decode("ascii")
        chunks = [b64[i : i + 4096] for i in range(0, len(b64), 4096)]
        lines = []
        cols_param = f",c={width}" if width else ""
        for i, chunk in enumerate(chunks):
            m = 1 if i < len(chunks) - 1 else 0
            if i == 0:
                lines.append(f"\033_Ga=T,f=100{cols_param},m={m};{chunk}\033\\")
            else:
                lines.append(f"\033_Gm={m};{chunk}\033\\")
        return "".join(lines) + "\n"

    def _render_iterm2(self, raw_bytes: bytes) -> str:
        """Format image using iTerm2 inline image OSC 1337 sequence."""
        b64 = base64.b64encode(raw_bytes).decode("ascii")
        return f"\033]1337;File=inline=1;width=auto;height=auto:{b64}\a\n"

    def _render_halfblock(self, img: Any, width: int = 80, height: int | None = None) -> str:
        """Universal TrueColor ANSI rendering using unicode upper half block character."""
        # Calculate aspect ratio
        orig_w, orig_h = img.size
        target_w = min(width, orig_w)
        target_h = height if height else max(1, int(orig_h * (target_w / orig_w) * 0.5))

        # Two vertical pixels per character
        resized = img.convert("RGB").resize((target_w, target_h * 2))
        if hasattr(resized, "get_flattened_data"):
            pixels = list(resized.get_flattened_data())
        else:
            pixels = list(resized.getdata())

        lines = []
        for y in range(0, target_h * 2, 2):
            line_parts = []
            for x in range(target_w):
                top = pixels[y * target_w + x]
                bottom_idx = (y + 1) * target_w + x
                bottom = pixels[bottom_idx] if (y + 1) < target_h * 2 else top
                # Top pixel is foreground, bottom is background
                line_parts.append(
                    f"\033[38;2;{top[0]};{top[1]};{top[2]}m\033[48;2;{bottom[0]};{bottom[1]};{bottom[2]}m▀\033[0m"
                )
            lines.append("".join(line_parts))
        return "\n".join(lines) + "\n"


def render_image(
    image_source: str | bytes | Path,
    protocol: str = "auto",
    width: int = 80,
) -> str:
    """Convenience function to render image to ANSI string."""
    renderer = TerminalImageRenderer()
    return renderer.render_image(image_source, protocol=protocol, width=width)


def create_image_grid(
    image_items: list[dict[str, Any]],
    cols: int = 3,
    cell_width: int = 240,
    cell_height: int = 180,
    pad: int = 8,
) -> tuple[bytes, list[dict[str, Any]]]:
    """Fetch images in parallel and compile a composite grid with numeric badges.

    Returns (composite_png_bytes, loaded_items).
    """
    import concurrent.futures

    import httpx
    from PIL import Image, ImageDraw

    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/124.0.0.0 Safari/537.36"
        )
    }

    def _fetch_single(item: dict[str, Any]) -> tuple[dict[str, Any], Any]:
        url = item.get("img_src") or item.get("thumbnail_src") or item.get("url")
        if not url or not url.startswith(("http://", "https://")):
            return item, None
        try:
            with httpx.Client(timeout=5.0, headers=headers, follow_redirects=True) as client:
                resp = client.get(url)
                if resp.status_code == 200:
                    img = Image.open(io.BytesIO(resp.content))
                    img.load()
                    return item, img.convert("RGB")
        except (httpx.HTTPError, OSError, ValueError) as exc:
            logger.debug("Failed to fetch image grid item: %s", exc)
        return item, None

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        valid_cells = list(pool.map(_fetch_single, image_items))

    if not valid_cells:
        return b"", []

    num_items = len(valid_cells)
    cols = max(1, min(cols, num_items))
    rows = (num_items + cols - 1) // cols

    total_w = cols * cell_width + (cols + 1) * pad
    total_h = rows * cell_height + (rows + 1) * pad

    canvas = Image.new("RGB", (total_w, total_h), color=(24, 24, 28))
    draw = ImageDraw.Draw(canvas)

    for idx, (item, img) in enumerate(valid_cells):
        c = idx % cols
        r = idx // cols
        x = pad + c * (cell_width + pad)
        y = pad + r * (cell_height + pad)

        if img is not None:
            # Scale to fit cell aspect ratio while preserving original bounds
            img_copy = img.copy()
            img_copy.thumbnail((cell_width, cell_height), Image.Resampling.LANCZOS)
            offset_x = x + (cell_width - img_copy.width) // 2
            offset_y = y + (cell_height - img_copy.height) // 2
            draw.rectangle([x, y, x + cell_width, y + cell_height], fill=(35, 35, 42))
            canvas.paste(img_copy, (offset_x, offset_y))
        else:
            draw.rectangle([x, y, x + cell_width, y + cell_height], fill=(45, 45, 55))
            draw.text((x + cell_width // 4, y + cell_height // 2 - 5), "[Image Unavailable]", fill=(160, 160, 170))

        # Draw number badge
        badge_num = str(idx + 1)
        badge_w = 22 + len(badge_num) * 8
        badge_h = 22
        draw.rectangle([x + 4, y + 4, x + 4 + badge_w, y + 4 + badge_h], fill=(10, 10, 12))
        draw.text((x + 8, y + 6), f"#{badge_num}", fill=(0, 220, 255))

    buf = io.BytesIO()
    canvas.save(buf, format="PNG")
    return buf.getvalue(), [item for item, _ in valid_cells]
