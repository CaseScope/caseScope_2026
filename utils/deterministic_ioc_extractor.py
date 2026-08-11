"""Deterministic IOC extraction stage helpers."""

from __future__ import annotations

import importlib.util
import os
from typing import Any, Dict, List, Optional, Type


def _load_local_module(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(
        name,
        os.path.join(os.path.dirname(__file__), filename),
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


_ioc_schema = _load_local_module("deterministic_ioc_schema_shared", "ioc_schema.py")
_ioc_merge = _load_local_module("deterministic_ioc_merge_shared", "ioc_merge.py")


def _section_provenance(canonical_report: Any, section: Any) -> Dict[str, Any]:
    return {
        "source_type": getattr(canonical_report, "source_type", ""),
        "source_product": getattr(canonical_report, "source_product", ""),
        "source_report_id": getattr(canonical_report, "source_report_id", ""),
        "adapter": getattr(canonical_report, "adapter_name", ""),
        "raw_text_preserved": True,
        "sections": [
            {
                "source_section": getattr(section, "source_section_name", "") or "Full Report",
                "canonical_section": getattr(section, "canonical_type", "") or "raw",
                "evidence_classes": list(getattr(section, "evidence_classes", []) or []),
            }
        ],
    }


def _merge_section_extractions(extractions: List[Dict[str, Any]]) -> Dict[str, Any]:
    merged: Dict[str, Any] = {}
    for extraction in extractions:
        if not merged:
            merged = extraction
            continue
        merged = _ioc_merge.merge_extractions(merged, extraction)
        merged["extraction_summary"] = _ioc_merge.merge_extraction_summaries(
            merged.get("extraction_summary", {}),
            extraction.get("extraction_summary", {}),
        )
    return merged or {}


def run_deterministic_stage(
    report_text: str,
    extractor_cls: Type[Any],
    *,
    source_provenance: Optional[Dict[str, Any]] = None,
    canonical_report: Any = None,
) -> Dict[str, Any]:
    """Run the deterministic extraction stage and attach internal records."""
    extractor = extractor_cls()
    if canonical_report is not None and getattr(canonical_report, "sections", None):
        section_extractions: List[Dict[str, Any]] = []
        section_records: List[Dict[str, Any]] = []
        for section in canonical_report.sections:
            section_text = section.text_for_extraction()
            if not section_text:
                continue
            section_extraction = extractor.extract(section_text)
            section_extraction.setdefault("extraction_summary", {})
            section_extraction["extraction_summary"]["source_provenance"] = _section_provenance(
                canonical_report,
                section,
            )
            section_records = _ioc_merge.merge_record_lists(
                section_records,
                _ioc_schema.records_from_extraction(
                    section_extraction,
                    source="regex",
                    trust_tier=_ioc_schema.TRUST_HIGH,
                ),
            )
            section_extractions.append(section_extraction)
        extraction = _merge_section_extractions(section_extractions) or extractor.extract(report_text)
        extraction.setdefault("extraction_summary", {})
        if source_provenance:
            extraction["extraction_summary"]["source_provenance"] = source_provenance
        extraction["_ioc_records"] = section_records or _ioc_schema.records_from_extraction(
            extraction,
            source="regex",
            trust_tier=_ioc_schema.TRUST_HIGH,
        )
        return extraction

    extraction = extractor.extract(report_text)
    if source_provenance:
        extraction.setdefault("extraction_summary", {})
        extraction["extraction_summary"]["source_provenance"] = source_provenance
    extraction["_ioc_records"] = _ioc_schema.records_from_extraction(
        extraction,
        source="regex",
        trust_tier=_ioc_schema.TRUST_HIGH,
    )
    return extraction
