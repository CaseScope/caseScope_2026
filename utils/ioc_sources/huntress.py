"""Huntress report adapter for canonical IOC ingestion."""

from __future__ import annotations

import os
import re
import sys
import importlib.util
from typing import Any, Dict, Optional

try:
    from .base import CanonicalReport, CanonicalReportSection, ReportSourceAdapter
    from .generic import classify_evidence_classes, classify_section, source_text, split_underlined_sections
except ImportError:
    _base_path = os.path.join(os.path.dirname(__file__), "base.py")
    _base_spec = importlib.util.spec_from_file_location("ioc_sources_base_fallback", _base_path)
    _base = importlib.util.module_from_spec(_base_spec)
    assert _base_spec.loader is not None
    sys.modules["ioc_sources_base_fallback"] = _base
    _base_spec.loader.exec_module(_base)
    CanonicalReport = _base.CanonicalReport
    CanonicalReportSection = _base.CanonicalReportSection
    ReportSourceAdapter = _base.ReportSourceAdapter

    _generic_path = os.path.join(os.path.dirname(__file__), "generic.py")
    _generic_spec = importlib.util.spec_from_file_location("ioc_sources_generic_fallback", _generic_path)
    _generic = importlib.util.module_from_spec(_generic_spec)
    assert _generic_spec.loader is not None
    sys.modules["ioc_sources_generic_fallback"] = _generic
    _generic_spec.loader.exec_module(_generic)
    classify_section = _generic.classify_section
    classify_evidence_classes = _generic.classify_evidence_classes
    source_text = _generic.source_text
    split_underlined_sections = _generic.split_underlined_sections


HUNTRESS_SECTION_TYPES = {
    "lead signal information": "detection",
    "investigative summary": "summary",
    "affected endpoint": "host",
    "affected endpoints": "host",
    "affected user": "identity",
    "affected users": "identity",
    "process tree": "process",
    "process evidence": "process",
    "file system": "file",
    "network": "network",
    "network indicators": "network",
    "remediation": "remediation",
    "recommended actions": "remediation",
    "response actions": "remediation",
    "threat description": "threat_description",
}

HUNTRESS_REPORT_ID_PATTERNS = (
    re.compile(r"huntress\.io/(?:org/\d+/)?infection_reports/(\d+)", re.I),
    re.compile(r"\b(?:Report|Case|Incident)\s+ID\s*[:#]\s*([A-Za-z0-9_-]+)", re.I),
)


class HuntressReportAdapter(ReportSourceAdapter):
    source_type = "huntress"
    source_product = "Huntress"

    def matches(self, report_input: Any, metadata: Optional[Dict[str, Any]] = None) -> bool:
        metadata = dict(metadata or {})
        declared = str(metadata.get("source_type") or metadata.get("vendor") or "").lower()
        if declared == "huntress":
            return True
        text = source_text(report_input).lower()
        return any(
            marker in text
            for marker in (
                "huntress.io",
                "huntress reported",
                "lead signal information",
                "infection_reports",
            )
        )

    def normalize(self, report_input: Any, metadata: Optional[Dict[str, Any]] = None) -> CanonicalReport:
        metadata = dict(metadata or {})
        raw_text = source_text(report_input).strip()
        pairs = split_underlined_sections(raw_text) or [("Full Report", raw_text)]
        sections = []
        for name, body in pairs:
            source_name = name or "Full Report"
            canonical_type = self._canonical_type(source_name, body)
            normalized_text = self._normalize_section_text(canonical_type, body)
            sections.append(
                CanonicalReportSection(
                    canonical_type=canonical_type,
                    source_section_name=source_name,
                    raw_text=body,
                    normalized_text=normalized_text,
                    evidence_classes=classify_evidence_classes(source_name, normalized_text),
                    metadata={"adapter": self.__class__.__name__},
                )
            )
        return CanonicalReport(
            source_type=self.source_type,
            source_product=self.source_product,
            source_report_id=metadata.get("source_report_id") or self._extract_report_id(raw_text),
            raw_text=raw_text,
            sections=sections,
            adapter_name=self.__class__.__name__,
            metadata=metadata,
        )

    def _canonical_type(self, section_name: str, section_text: str) -> str:
        lowered = (section_name or "").strip().lower()
        if lowered in HUNTRESS_SECTION_TYPES:
            return HUNTRESS_SECTION_TYPES[lowered]
        return classify_section(section_name, section_text)

    def _extract_report_id(self, report_text: str) -> Optional[str]:
        for pattern in HUNTRESS_REPORT_ID_PATTERNS:
            match = pattern.search(report_text or "")
            if match:
                return match.group(1)
        return None

    def _normalize_section_text(self, canonical_type: str, section_text: str) -> str:
        lines = []
        scheduled_task_context = "scheduled task" in (section_text or "").lower()
        for line in (section_text or "").splitlines():
            stripped = line.strip()
            if not stripped:
                lines.append(line)
                continue
            if "huntress.io" in stripped.lower():
                continue
            if re.search(r":\s*not on endpoint\s*$", stripped, re.I):
                label = stripped.split(":", 1)[0].strip()
                lines.append(f"{label}: [source placeholder omitted: Not on endpoint]")
                continue
            if scheduled_task_context:
                line = re.sub(r"^(\s*)Service Path\s*:", r"\1Scheduled Task Executable Path:", line, flags=re.I)
                line = re.sub(r"^(\s*)Name\s*:", r"\1Scheduled Task:", line, flags=re.I)
                line = re.sub(r"^(\s*)Parameters\s*:", r"\1Scheduled Task Command:", line, flags=re.I)
            lines.append(line)
        return "\n".join(lines).strip()
