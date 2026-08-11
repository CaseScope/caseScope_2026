"""Generic report adapter used when no known source matches."""

from __future__ import annotations

import json
import os
import re
import sys
import importlib.util
from typing import Any, Dict, List, Optional, Tuple

try:
    from .base import CanonicalReport, CanonicalReportSection, ReportSourceAdapter
except ImportError:
    _base_path = os.path.join(os.path.dirname(__file__), "base.py")
    _spec = importlib.util.spec_from_file_location("ioc_sources_base_fallback", _base_path)
    _base = importlib.util.module_from_spec(_spec)
    assert _spec.loader is not None
    sys.modules["ioc_sources_base_fallback"] = _base
    _spec.loader.exec_module(_base)
    CanonicalReport = _base.CanonicalReport
    CanonicalReportSection = _base.CanonicalReportSection
    ReportSourceAdapter = _base.ReportSourceAdapter


SECTION_HEADER_PATTERN = re.compile(r"^[A-Za-z0-9 /()\[\]_.-]+:?$")


def source_text(report_input: Any) -> str:
    """Return a text representation without blocking future structured adapters."""
    if report_input is None:
        return ""
    if isinstance(report_input, str):
        return report_input
    try:
        return json.dumps(report_input, indent=2, sort_keys=True, default=str)
    except Exception:
        return str(report_input)


def split_underlined_sections(report_text: str) -> List[Tuple[str, str]]:
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


def classify_section(section_name: str, section_text: str) -> str:
    name = (section_name or "").lower()
    text = (section_text or "").lower()
    haystack = f"{name}\n{text}"

    if any(token in haystack for token in ("scheduled task", "scheduledtask", "taskname")):
        return "process"
    if any(token in haystack for token in ("process", "command", "powershell", "parent process", "execution chain")):
        return "process"
    if any(token in name for token in ("host", "endpoint", "device")):
        return "host"
    if any(token in haystack for token in ("sid", "user account", "affected user", "credential", "password")):
        return "identity"
    if any(token in haystack for token in ("domain", "url", "ip address", "network", "c2", "callback")):
        return "network"
    if any(token in haystack for token in ("sha256", "sha1", "md5", "file path", "filename", "file system")):
        return "file"
    if any(token in haystack for token in ("registry", "runonce", "run key", "hkcu", "hklm", "web shell", "webshell")):
        return "persistence"
    if any(token in haystack for token in ("lsass", "sam database", "ntds.dit", "credential theft")):
        return "persistence"
    if any(token in name for token in ("remediation", "response action", "recommended action")):
        return "remediation"
    if any(token in name for token in ("detection", "alert", "lead signal")):
        return "detection"
    if any(token in name for token in ("summary", "overview", "description")):
        return "summary"
    return "raw"


class GenericReportAdapter(ReportSourceAdapter):
    source_type = "generic"
    source_product = None

    def matches(self, report_input: Any, metadata: Optional[Dict[str, Any]] = None) -> bool:
        return True

    def normalize(self, report_input: Any, metadata: Optional[Dict[str, Any]] = None) -> CanonicalReport:
        metadata = dict(metadata or {})
        raw_text = source_text(report_input).strip()
        pairs = split_underlined_sections(raw_text) or [("Full Report", raw_text)]
        sections = [
            CanonicalReportSection(
                canonical_type=classify_section(name, body),
                source_section_name=name or "Full Report",
                raw_text=body,
                normalized_text=body,
            )
            for name, body in pairs
            if body.strip()
        ]
        if not sections and raw_text:
            sections = [
                CanonicalReportSection(
                    canonical_type="raw",
                    source_section_name="Full Report",
                    raw_text=raw_text,
                    normalized_text=raw_text,
                )
            ]
        return CanonicalReport(
            source_type="generic",
            source_product=metadata.get("source_product"),
            source_report_id=metadata.get("source_report_id"),
            raw_text=raw_text,
            sections=sections,
            adapter_name=self.__class__.__name__,
            metadata=metadata,
        )
