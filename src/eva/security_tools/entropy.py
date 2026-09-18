from __future__ import annotations

import math
from collections import Counter
from pathlib import Path
from typing import Any

from eva.security_tools.models import Finding
from eva.security_tools.normalizers import make_finding


def calculate_shannon_entropy(data: bytes) -> float:
    """Calculate the Shannon entropy of raw byte data in bits per byte (0.0 to 8.0)."""
    if not data:
        return 0.0
    length = len(data)
    counts = Counter(data)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def compute_sliding_window_entropy(data: bytes, window_size: int = 1024, step_size: int = 512) -> list[dict[str, Any]]:
    """Compute Shannon entropy across data using a sliding window."""
    if not data:
        return []
    windows = []
    data_len = len(data)
    for offset in range(0, data_len, step_size):
        chunk = data[offset : offset + window_size]
        if not chunk:
            break
        ent = round(calculate_shannon_entropy(chunk), 4)
        windows.append(
            {
                "offset": offset,
                "size": len(chunk),
                "entropy": ent,
            }
        )
        if offset + window_size >= data_len:
            break
    return windows


def analyze_file_entropy(
    file_path: Path | str,
    block_size: int = 1024,
    artifact_path: str | None = None,
) -> tuple[dict[str, Any], list[Finding]]:
    """Compute block and sliding window Shannon entropy for a file, identifying

    packed/encrypted regions and padding.
    """
    path = Path(file_path).resolve()
    if not path.exists() or not path.is_file():
        raise FileNotFoundError(f"File not found: {path}")

    file_size = path.stat().st_size
    findings: list[Finding] = []

    if file_size == 0:
        return {
            "file": str(path),
            "file_size": 0,
            "overall_entropy": 0.0,
            "blocks": [],
            "summary": {"min": 0.0, "max": 0.0, "mean": 0.0, "stddev": 0.0},
        }, findings

    data = path.read_bytes()
    overall_entropy = round(calculate_shannon_entropy(data), 4)

    # Block entropy
    blocks: list[dict[str, Any]] = []
    block_entropies: list[float] = []
    high_entropy_blocks: list[tuple[int, int, float]] = []

    for idx, offset in enumerate(range(0, file_size, block_size)):
        chunk = data[offset : offset + block_size]
        ent = round(calculate_shannon_entropy(chunk), 4)
        block_info = {
            "block_index": idx,
            "offset": offset,
            "size": len(chunk),
            "entropy": ent,
        }
        blocks.append(block_info)
        block_entropies.append(ent)

        if ent >= 7.2 and len(chunk) >= 512:
            high_entropy_blocks.append((offset, len(chunk), ent))

    # Calculate statistics
    min_ent = round(min(block_entropies), 4) if block_entropies else 0.0
    max_ent = round(max(block_entropies), 4) if block_entropies else 0.0
    mean_ent = round(sum(block_entropies) / len(block_entropies), 4) if block_entropies else 0.0
    variance = sum((x - mean_ent) ** 2 for x in block_entropies) / len(block_entropies) if block_entropies else 0.0
    stddev_ent = round(math.sqrt(variance), 4)

    # Sliding window analysis (useful for granular inspection)
    sliding_windows = compute_sliding_window_entropy(data, window_size=block_size, step_size=max(1, block_size // 2))

    # Consolidate contiguous high entropy blocks into findings
    if high_entropy_blocks:
        # Group adjacent blocks
        ranges: list[dict[str, Any]] = []
        current_start, current_len, max_block_ent = high_entropy_blocks[0]

        for offset, length, ent in high_entropy_blocks[1:]:
            if offset == current_start + current_len:
                current_len += length
                max_block_ent = max(max_block_ent, ent)
            else:
                ranges.append({"start": current_start, "size": current_len, "peak_entropy": max_block_ent})
                current_start, current_len, max_block_ent = offset, length, ent
        ranges.append({"start": current_start, "size": current_len, "peak_entropy": max_block_ent})

        for r in ranges:
            start_off = r["start"]
            size = r["size"]
            peak = r["peak_entropy"]
            severity = "high" if peak >= 7.6 else "medium"
            findings.append(
                make_finding(
                    tool="binary-entropy",
                    rule_id="entropy.high_density_payload",
                    title=f"High entropy region (0x{start_off:x}-0x{start_off + size:x}, peak={peak:.2f} bits/byte)",
                    severity=severity,
                    confidence="high",
                    category="packer_or_encryption",
                    file=str(path),
                    line_start=start_off,
                    evidence=f"Region of {size} bytes at offset 0x{start_off:x} has peak entropy {peak:.2f} bits/byte, indicating packed code, encrypted payload, or compressed data.",
                    remediation="Extract region bytes and check for headers, packers, or decryption stubs.",
                    artifact_path=artifact_path,
                )
            )

    # If overall file entropy is exceptionally high
    if overall_entropy >= 7.5 and file_size >= 4096:
        findings.append(
            make_finding(
                tool="binary-entropy",
                rule_id="entropy.file.overall_packed",
                title=f"Entire file has high entropy ({overall_entropy:.2f} bits/byte)",
                severity="medium",
                confidence="medium",
                category="packer_or_encryption",
                file=str(path),
                evidence=f"File entropy is {overall_entropy:.2f}/8.0; whole file is likely encrypted or packed.",
                remediation="Perform dynamic unpacking or memory dump capture during process initialization.",
                artifact_path=artifact_path,
            )
        )

    metadata = {
        "file": str(path),
        "file_size": file_size,
        "block_size": block_size,
        "overall_entropy": overall_entropy,
        "summary": {
            "min": min_ent,
            "max": max_ent,
            "mean": mean_ent,
            "stddev": stddev_ent,
        },
        "blocks_count": len(blocks),
        "blocks": blocks[:100],  # Sample first 100 blocks for concise reporting
        "sliding_windows_sample": sliding_windows[:50],
        "high_entropy_regions_count": len(high_entropy_blocks),
    }

    return metadata, findings
