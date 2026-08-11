"""Shared report normalization and chunking helpers for IOC extraction."""

from __future__ import annotations

import importlib.util
import os
import re
import sys
from typing import Any, Dict, List, Optional, Tuple

SECTION_HEADER_PATTERN = re.compile(r"^[A-Za-z0-9 /()\[\]_-]+:?$")
DEFAULT_CHUNK_OVERLAP_CHARS = 400


def _load_source_module(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(
        name,
        os.path.join(os.path.dirname(__file__), "ioc_sources", filename),
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


_ioc_sources_base = _load_source_module("ioc_sources_base_shared", "base.py")
_ioc_sources_generic = _load_source_module("ioc_sources_generic_shared", "generic.py")
_ioc_sources_huntress = _load_source_module("ioc_sources_huntress_shared", "huntress.py")

CanonicalReport = _ioc_sources_base.CanonicalReport
CanonicalReportSection = _ioc_sources_base.CanonicalReportSection
GenericReportAdapter = _ioc_sources_generic.GenericReportAdapter
HuntressReportAdapter = _ioc_sources_huntress.HuntressReportAdapter


def _source_adapters() -> List[Any]:
    return [HuntressReportAdapter(), GenericReportAdapter()]


def is_canonical_report(report_input: Any) -> bool:
    """Return True when the input already crossed the source-adapter boundary."""
    return (
        hasattr(report_input, "sections")
        and hasattr(report_input, "text_for_extraction")
        and hasattr(report_input, "provenance_summary")
    )


def normalize_report_source(report_input: Any, metadata: Optional[Dict[str, Any]] = None) -> Any:
    """Normalize raw or structured source data to a canonical report."""
    if is_canonical_report(report_input):
        return report_input
    metadata = dict(metadata or {})
    for adapter in _source_adapters():
        if adapter.matches(report_input, metadata):
            return adapter.normalize(report_input, metadata)
    return GenericReportAdapter().normalize(report_input, metadata)


def render_canonical_report_text(canonical_report: Any) -> str:
    """Render canonical sections into the existing text-based extraction boundary."""
    if hasattr(canonical_report, "text_for_extraction"):
        return canonical_report.text_for_extraction()
    return str(canonical_report or "")


def prepare_ioc_report_text(report_text: Any, metadata: Optional[Dict[str, Any]] = None) -> str:
    """Trim pathological report fragments that are expensive and low-value."""
    canonical_report = normalize_report_source(report_text, metadata=metadata)
    prepared_text = render_canonical_report_text(canonical_report)
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


def split_report_sections(report_text: Any, metadata: Optional[Dict[str, Any]] = None) -> List[Tuple[str, str]]:
    """Split a report into canonicalized section title and body pairs."""
    canonical_report = normalize_report_source(report_text, metadata=metadata)
    return [
        (section.source_section_name or "Full Report", section.text_for_extraction())
        for section in canonical_report.sections
        if section.text_for_extraction()
    ]


def canonical_sections_for_report(
    report_text: Any,
    metadata: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    """Return canonical section dictionaries for callers that need provenance."""
    canonical_report = normalize_report_source(report_text, metadata=metadata)
    return [
        {
            "name": section.source_section_name or "Full Report",
            "body": section.text_for_extraction(),
            "canonical_type": section.canonical_type,
            "evidence_classes": list(getattr(section, "evidence_classes", []) or []),
            "source_section_name": section.source_section_name,
            "raw_text": section.raw_text,
            "source_type": canonical_report.source_type,
            "source_product": canonical_report.source_product,
            "source_report_id": canonical_report.source_report_id,
        }
        for section in canonical_report.sections
        if section.text_for_extraction()
    ]


def split_large_section_blocks(
    section_name: str,
    section_text: str,
    max_chars: int,
    overlap_chars: int = DEFAULT_CHUNK_OVERLAP_CHARS,
    canonical_type: str = "raw",
    evidence_classes: Optional[List[str]] = None,
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
                            "canonical_type": canonical_type,
                            "evidence_classes": list(evidence_classes or []),
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
                    "canonical_type": canonical_type,
                    "evidence_classes": list(evidence_classes or []),
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
                "canonical_type": canonical_type,
                "evidence_classes": list(evidence_classes or []),
                "overlap_applied": False,
            }
        )
    return blocks


def chunk_canonical_report_for_ai(canonical_report: Any, max_chars: int) -> List[Dict[str, Any]]:
    """Chunk a canonical report for AI extraction without re-normalizing."""
    text = render_canonical_report_text(canonical_report).strip()
    if not text:
        return []
    if len(text) <= max_chars:
        return [
            {
                "text": text,
                "sections": [
                    section.source_section_name or "Full Report"
                    for section in canonical_report.sections
                ] or ["Full Report"],
                "canonical_sections": [
                    section.canonical_type
                    for section in canonical_report.sections
                ],
                "evidence_classes": sorted(
                    {
                        evidence_class
                        for section in canonical_report.sections
                        for evidence_class in (getattr(section, "evidence_classes", []) or [])
                    }
                ),
                "source_type": canonical_report.source_type,
                "source_product": canonical_report.source_product,
                "source_report_id": canonical_report.source_report_id,
                "overlap_applied": False,
                "chunk_index": 1,
                "chunk_count": 1,
            }
        ]

    sections = [
        (
            section.source_section_name or "Full Report",
            section.text_for_extraction(),
            section.canonical_type,
            list(getattr(section, "evidence_classes", []) or []),
        )
        for section in canonical_report.sections
        if section.text_for_extraction()
    ] or [("Full Report", text, "raw", [])]
    chunks: List[Dict[str, Any]] = []
    current_parts: List[str] = []
    current_sections: List[str] = []
    current_canonical_sections: List[str] = []
    current_evidence_classes: List[str] = []
    current_len = 0
    current_overlap = False

    for section_name, section_text, canonical_type, evidence_classes in sections:
        section_block = (
            f"{section_name}\n{'-' * min(max(len(section_name), 3), 32)}\n{section_text}"
        ).strip()
        candidate_blocks = (
            [
                {
                    "text": section_block,
                    "section_name": section_name,
                    "canonical_type": canonical_type,
                    "evidence_classes": list(evidence_classes or []),
                    "overlap_applied": False,
                }
            ]
            if len(section_block) <= max_chars
            else split_large_section_blocks(
                section_name,
                section_text,
                max_chars,
                canonical_type=canonical_type,
                evidence_classes=list(evidence_classes or []),
            )
        )

        for block in candidate_blocks:
            block_text = block["text"]
            projected_len = current_len + (2 if current_parts else 0) + len(block_text)
            if current_parts and projected_len > max_chars:
                chunks.append(
                    {
                        "text": "\n\n".join(current_parts),
                        "sections": list(current_sections),
                        "canonical_sections": list(current_canonical_sections),
                        "evidence_classes": list(current_evidence_classes),
                        "source_type": canonical_report.source_type,
                        "source_product": canonical_report.source_product,
                        "source_report_id": canonical_report.source_report_id,
                        "overlap_applied": current_overlap,
                    }
                )
                current_parts = [block_text]
                current_sections = [section_name]
                current_canonical_sections = [canonical_type]
                current_evidence_classes = list(block.get("evidence_classes") or [])
                current_len = len(block_text)
                current_overlap = bool(block.get("overlap_applied"))
            else:
                current_parts.append(block_text)
                if section_name not in current_sections:
                    current_sections.append(section_name)
                if canonical_type not in current_canonical_sections:
                    current_canonical_sections.append(canonical_type)
                for evidence_class in block.get("evidence_classes") or []:
                    if evidence_class not in current_evidence_classes:
                        current_evidence_classes.append(evidence_class)
                current_len = projected_len if current_parts[:-1] else len(block_text)
                current_overlap = current_overlap or bool(block.get("overlap_applied"))

    if current_parts:
        chunks.append(
            {
                "text": "\n\n".join(current_parts),
                "sections": list(current_sections),
                "canonical_sections": list(current_canonical_sections),
                "evidence_classes": list(current_evidence_classes),
                "source_type": canonical_report.source_type,
                "source_product": canonical_report.source_product,
                "source_report_id": canonical_report.source_report_id,
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
            "canonical_sections": ["raw"],
            "evidence_classes": [],
            "source_type": canonical_report.source_type,
            "source_product": canonical_report.source_product,
            "source_report_id": canonical_report.source_report_id,
            "overlap_applied": False,
            "chunk_index": 1,
            "chunk_count": 1,
        }
    ]


def chunk_report_for_ai_with_metadata(report_text: Any, max_chars: int) -> List[Dict[str, Any]]:
    """Chunk a report for AI extraction and preserve section provenance."""
    return chunk_canonical_report_for_ai(normalize_report_source(report_text), max_chars)


def chunk_sections_for_ai_with_metadata(
    sections: List[Dict[str, Any]],
    max_chars: int,
    *,
    source_type: str = "",
    source_product: str = "",
    source_report_id: str = "",
) -> List[Dict[str, Any]]:
    """Chunk already-selected canonical section dictionaries."""
    pseudo_report = CanonicalReport(
        source_type=source_type or "",
        source_product=source_product or None,
        source_report_id=source_report_id or None,
        raw_text="",
        sections=[
            CanonicalReportSection(
                canonical_type=str(section.get("canonical_type") or "raw"),
                source_section_name=str(section.get("source_section_name") or section.get("name") or "Full Report"),
                raw_text=str(section.get("raw_text") or section.get("body") or ""),
                normalized_text=str(section.get("body") or section.get("raw_text") or ""),
                evidence_classes=list(section.get("evidence_classes") or []),
            )
            for section in sections or []
        ],
        adapter_name="selected_sections",
    )
    return chunk_canonical_report_for_ai(pseudo_report, max_chars)


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
