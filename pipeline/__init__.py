"""Thin pipeline entry points for additive Phase 1 wiring."""

from pipeline.baselines import (
    run_behavioral_profiling,
    run_build_baselines,
    run_peer_clustering,
)
from pipeline.detect_anomalies import run_detect_anomalies
from pipeline.detect import run_hayabusa_correlation
from pipeline.pattern_analysis import (
    apply_pattern_suppression,
    create_candidate_extractor,
    create_evidence_engine,
    evaluate_ai_pattern,
    evaluate_pattern_packages,
    load_pattern_configs,
    materialize_pattern_package,
    prepare_pattern_analysis,
    process_ai_pattern_packages,
    run_pattern_census,
    select_highest_scoring_packages,
    should_run_pattern,
)

__all__ = [
    "apply_pattern_suppression",
    "create_candidate_extractor",
    "create_evidence_engine",
    "evaluate_ai_pattern",
    "evaluate_pattern_packages",
    "load_pattern_configs",
    "materialize_pattern_package",
    "prepare_pattern_analysis",
    "process_ai_pattern_packages",
    "run_behavioral_profiling",
    "run_build_baselines",
    "run_detect_anomalies",
    "run_pattern_census",
    "run_peer_clustering",
    "run_hayabusa_correlation",
    "select_highest_scoring_packages",
    "should_run_pattern",
]
