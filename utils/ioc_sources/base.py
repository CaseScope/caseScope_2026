"""Source adapter contracts for IOC report ingestion."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class CanonicalReportSection:
    """Normalized report section with original source provenance retained."""

    canonical_type: str
    source_section_name: str
    raw_text: str
    normalized_text: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def text_for_extraction(self) -> str:
        return (self.normalized_text or self.raw_text or "").strip()


@dataclass
class CanonicalReport:
    """Canonical report representation between raw source input and IOC extraction."""

    source_type: str
    source_product: Optional[str]
    source_report_id: Optional[str]
    raw_text: str
    sections: List[CanonicalReportSection]
    adapter_name: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    structured_evidence: Dict[str, Any] = field(default_factory=dict)

    def text_for_extraction(self) -> str:
        blocks: List[str] = []
        for section in self.sections:
            text = section.text_for_extraction()
            if not text:
                continue
            name = section.source_section_name or section.canonical_type or "Full Report"
            blocks.append(f"{name}\n{'-' * min(max(len(name), 3), 32)}\n{text}")
        return "\n\n".join(blocks).strip() or (self.raw_text or "").strip()

    def provenance_summary(self) -> Dict[str, Any]:
        return {
            "source_type": self.source_type,
            "source_product": self.source_product,
            "source_report_id": self.source_report_id,
            "adapter": self.adapter_name,
            "raw_text_preserved": True,
            "sections": [
                {
                    "source_section": section.source_section_name,
                    "canonical_section": section.canonical_type,
                }
                for section in self.sections
            ],
        }


class ReportSourceAdapter:
    """Base class for source-specific report normalizers."""

    source_type = "generic"
    source_product: Optional[str] = None

    def matches(self, report_input: Any, metadata: Optional[Dict[str, Any]] = None) -> bool:
        return False

    def normalize(self, report_input: Any, metadata: Optional[Dict[str, Any]] = None) -> CanonicalReport:
        raise NotImplementedError
