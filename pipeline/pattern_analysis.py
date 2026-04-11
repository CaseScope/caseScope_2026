"""Minimal Phase 1 wrappers around the existing pattern-analysis stack."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from utils.candidate_extractor import CandidateExtractor
from utils.deterministic_evidence_engine import DeterministicEvidenceEngine


def create_candidate_extractor(case_id: int, analysis_id: Optional[str] = None) -> CandidateExtractor:
    """Create the candidate-extraction stage wrapper."""
    return CandidateExtractor(case_id=case_id, analysis_id=analysis_id)


def create_evidence_engine(
    case_id: int,
    analysis_id: str,
    *,
    census: Optional[Dict[str, int]] = None,
    gap_findings: Optional[List[Any]] = None,
) -> DeterministicEvidenceEngine:
    """Create the deterministic-evidence stage wrapper."""
    return DeterministicEvidenceEngine(
        case_id=case_id,
        analysis_id=analysis_id,
        census=census,
        gap_findings=gap_findings,
    )


def evaluate_pattern_packages(
    *,
    case_id: int,
    analysis_id: str,
    pattern_id: str,
    pattern_config: Dict[str, Any],
    anchor_events: List[Dict[str, Any]],
    time_window_minutes: int = 60,
    census: Optional[Dict[str, int]] = None,
    gap_findings: Optional[List[Any]] = None,
):
    """Evaluate one pattern through the existing deterministic evidence engine."""
    engine = create_evidence_engine(
        case_id,
        analysis_id,
        census=census,
        gap_findings=gap_findings,
    )
    return engine.evaluate_pattern(
        pattern_id=pattern_id,
        pattern_config=pattern_config,
        anchor_events=anchor_events,
        time_window_minutes=time_window_minutes,
    )
