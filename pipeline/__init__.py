"""Thin pipeline entry points for additive Phase 1 wiring."""

from pipeline.pattern_analysis import (
    create_candidate_extractor,
    create_evidence_engine,
    evaluate_pattern_packages,
)

__all__ = [
    "create_candidate_extractor",
    "create_evidence_engine",
    "evaluate_pattern_packages",
]
