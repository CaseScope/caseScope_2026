"""Shared report normalization and chunking helpers for IOC extraction."""

from __future__ import annotations

import re
from typing import Any, Dict, List, Tuple

SECTION_HEADER_PATTERN = re.compile(r"^[A-Za-z0-9 /()\[\]_-]+:?$")
DEFAULT_CHUNK_OVERLAP_CHARS = 400


def prepare_ioc_report_text(report_text: str) -> str:
    """Trim pathological report fragments that are expensive and low-value."""
    prepared_text = report_text or ""
    if '-filemask="' in prepared_text:
        idx = prepared_text.find('-filemask="')
        end = prepared_text.find('"', idx + 100)
        if end > idx:
            prepared_text = (
                prepared_text[:idx + 50]
                + "...[FILEMASK TRUNCATED]..."
                + prepared_text[end:]
            )
    return prepared_text


def split_report_sections(report_text: str) -> List[Tuple[str, str]]:
    """Split a Huntress-style report into section title and body pairs."""
    lines = (report_text or "").splitlines()
    sections: List[Tuple[str, str]] = []
    current_name = "Full Report"
    current_body: List[str] = []
    idx = 0

    while idx < len(lines):
        line = lines[idx].rstrip()
        next_line = lines[idx + 1].rstrip() if idx + 1 < len(lines) else ""
        if (
            line
            and SECTION_HEADER_PATTERN.match(line)
            and next_line
            and set(next_line) <= {"-"}
            and len(next_line) >= 3
        ):
            body = "\n".join(current_body).strip()
            if body:
                sections.append((current_name, body))
            current_name = line.strip().rstrip(":").strip()
            current_body = []
            idx += 2
            continue
        current_body.append(lines[idx])
        idx += 1

    body = "\n".join(current_body).strip()
    if body:
        sections.append((current_name, body))
    return sections


def split_large_section_blocks(
    section_name: str,
    section_text: str,
    max_chars: int,
    overlap_chars: int = DEFAULT_CHUNK_OVERLAP_CHARS,
) -> List[Dict[str, Any]]:
    """Split oversized sections into paragraph-aware blocks with overlap."""
    header = f"{section_name}\n{'-' * min(max(len(section_name), 3), 32)}\n"
    paragraphs = [
        paragraph.strip()
        for paragraph in re.split(r"\n\s*\n", section_text or "")
        if paragraph.strip()
    ] or [section_text.strip()]

    blocks: List[Dict[str, Any]] = []
    current = ""
    for paragraph in paragraphs:
        paragraph_block = f"{header}{paragraph}"
        if len(paragraph_block) > max_chars:
            overlap = min(overlap_chars, max(120, (max_chars - len(header)) // 5))
            usable = max(1000, max_chars - len(header) - overlap)
            start = 0
            while start < len(paragraph):
                piece_start = max(0, start - overlap) if start else 0
                piece = paragraph[piece_start:start + usable].strip()
                if piece:
                    blocks.append(
                        {
                            "text": f"{header}{piece}",
                            "section_name": section_name,
                            "overlap_applied": piece_start < start,
                        }
                    )
                start += usable
            continue

        if current and len(current) + 2 + len(paragraph) > max_chars:
            blocks.append(
                {
                    "text": current,
                    "section_name": section_name,
                    "overlap_applied": False,
                }
            )
            current = paragraph_block
        elif current:
            current = f"{current}\n\n{paragraph}"
        else:
            current = paragraph_block

    if current:
        blocks.append(
            {
                "text": current,
                "section_name": section_name,
                "overlap_applied": False,
            }
        )
    return blocks


def chunk_report_for_ai_with_metadata(report_text: str, max_chars: int) -> List[Dict[str, Any]]:
    """Chunk a report for AI extraction and preserve section provenance."""
    text = (report_text or "").strip()
    if not text:
        return []
    if len(text) <= max_chars:
        return [
            {
                "text": text,
                "sections": ["Full Report"],
                "overlap_applied": False,
                "chunk_index": 1,
                "chunk_count": 1,
            }
        ]

    sections = split_report_sections(text) or [("Full Report", text)]
    chunks: List[Dict[str, Any]] = []
    current_parts: List[str] = []
    current_sections: List[str] = []
    current_len = 0
    current_overlap = False

    for section_name, section_text in sections:
        section_block = (
            f"{section_name}\n{'-' * min(max(len(section_name), 3), 32)}\n{section_text}"
        ).strip()
        candidate_blocks = (
            [
                {
                    "text": section_block,
                    "section_name": section_name,
                    "overlap_applied": False,
                }
            ]
            if len(section_block) <= max_chars
            else split_large_section_blocks(section_name, section_text, max_chars)
        )

        for block in candidate_blocks:
            block_text = block["text"]
            projected_len = current_len + (2 if current_parts else 0) + len(block_text)
            if current_parts and projected_len > max_chars:
                chunks.append(
                    {
                        "text": "\n\n".join(current_parts),
                        "sections": list(current_sections),
                        "overlap_applied": current_overlap,
                    }
                )
                current_parts = [block_text]
                current_sections = [section_name]
                current_len = len(block_text)
                current_overlap = bool(block.get("overlap_applied"))
            else:
                current_parts.append(block_text)
                if section_name not in current_sections:
                    current_sections.append(section_name)
                current_len = projected_len if current_parts[:-1] else len(block_text)
                current_overlap = current_overlap or bool(block.get("overlap_applied"))

    if current_parts:
        chunks.append(
            {
                "text": "\n\n".join(current_parts),
                "sections": list(current_sections),
                "overlap_applied": current_overlap,
            }
        )

    total = len(chunks)
    for idx, chunk in enumerate(chunks, start=1):
        chunk["chunk_index"] = idx
        chunk["chunk_count"] = total
    return chunks or [
        {
            "text": text[:max_chars],
            "sections": ["Full Report"],
            "overlap_applied": False,
            "chunk_index": 1,
            "chunk_count": 1,
        }
    ]


def chunk_report_for_ai(report_text: str, max_chars: int) -> List[str]:
    """Backward-compatible chunk output without metadata."""
    return [chunk["text"] for chunk in chunk_report_for_ai_with_metadata(report_text, max_chars)]


def split_edr_reports(edr_report_text: str) -> List[str]:
    """Split EDR report text by the standard report separator."""
    if not edr_report_text:
        return []
    return [r.strip() for r in edr_report_text.split("*** NEW REPORT ***") if r.strip()]


def get_report_preview(report_text: str, max_length: int = 200) -> str:
    """Return the first non-empty line of a report for display."""
    if not report_text:
        return ""

    lines = [line.strip() for line in report_text.split("\n") if line.strip()]
    if not lines:
        return report_text[:max_length]

    preview = lines[0]
    if len(preview) > max_length:
        return preview[:max_length] + "..."
    return preview
