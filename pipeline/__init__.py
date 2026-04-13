"""Thin pipeline entry points for additive Phase 1 wiring."""

from pipeline.baselines import (
    run_behavioral_profiling,
    run_build_baselines,
    run_peer_clustering,
)
from pipeline.detect_anomalies import run_detect_anomalies
from pipeline.detect import run_hayabusa_correlation
from pipeline.pattern_analysis import (
    create_candidate_extractor,
    create_evidence_engine,
    evaluate_pattern_packages,
)

__all__ = [
    "create_candidate_extractor",
    "create_evidence_engine",
    "evaluate_pattern_packages",
    "run_behavioral_profiling",
    "run_build_baselines",
    "run_detect_anomalies",
    "run_peer_clustering",
    "run_hayabusa_correlation",
]
