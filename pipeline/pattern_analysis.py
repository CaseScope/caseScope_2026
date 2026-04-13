"""Shared pattern-analysis stage helpers."""

from __future__ import annotations

import logging
from typing import Any, Callable, Dict, List, Optional, Tuple

from utils.pattern_suppression import (
    PATTERN_SUPPRESSION_PRIORITY,
    get_pattern_suppression_matches,
)
from utils.candidate_extractor import CandidateExtractor
from utils.deterministic_evidence_engine import DeterministicEvidenceEngine

logger = logging.getLogger(__name__)


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


def load_pattern_configs() -> Dict[str, Dict[str, Any]]:
    """Load the configured pattern definitions for analysis."""
    try:
        from utils.pattern_event_mappings import PATTERN_EVENT_MAPPINGS

        return dict(PATTERN_EVENT_MAPPINGS)
    except ImportError:
        logger.warning("[PatternAnalysis] No patterns configured for analysis")
        return {}


def run_pattern_census(case_id: int) -> Dict[str, int]:
    """Get the event-id census used to prefilter pattern analysis."""
    from utils.clickhouse import get_fresh_client

    try:
        client = get_fresh_client()
        result = client.query(
            "SELECT event_id, count() as cnt FROM events "
            "WHERE case_id = {case_id:UInt32} "
            "AND (noise_matched = false OR noise_matched IS NULL) "
            "GROUP BY event_id",
            parameters={"case_id": case_id},
        )
        census = {str(row[0]): row[1] for row in result.result_rows}
        logger.info("[PatternAnalysis] Census: %s distinct event IDs in case %s", len(census), case_id)
        return census
    except Exception as exc:
        logger.warning("[PatternAnalysis] Census query failed, running all patterns: %s", exc)
        return {}


def should_run_pattern(pattern_config: Dict[str, Any], census: Dict[str, int]) -> bool:
    """Check whether a pattern is eligible given the case census."""
    if not census:
        return True

    anchor_events = pattern_config.get("anchor_events", [])
    if not anchor_events:
        return True

    return any(str(event_id) in census for event_id in anchor_events)


def prepare_pattern_analysis(case_id: int) -> Dict[str, Any]:
    """Load pattern configs, run census, and order eligible patterns."""
    patterns = load_pattern_configs()
    census = run_pattern_census(case_id)
    runnable_patterns = {
        pattern_id: pattern_config
        for pattern_id, pattern_config in patterns.items()
        if should_run_pattern(pattern_config, census)
    }
    ordered_patterns: List[Tuple[str, Dict[str, Any]]] = sorted(
        runnable_patterns.items(),
        key=lambda item: (
            PATTERN_SUPPRESSION_PRIORITY.get(item[0], 999),
            item[1].get("name", item[0]),
        ),
    )
    return {
        "patterns": patterns,
        "census": census,
        "runnable_patterns": runnable_patterns,
        "ordered_patterns": ordered_patterns,
        "skipped_count": len(patterns) - len(runnable_patterns),
    }


def select_highest_scoring_packages(evidence_packages: List[Any]) -> List[Any]:
    """Keep only the highest-scoring package per correlation key."""
    best_by_key: Dict[str, Any] = {}
    for package in evidence_packages:
        existing = best_by_key.get(package.correlation_key)
        if existing is None or package.deterministic_score > existing.deterministic_score:
            best_by_key[package.correlation_key] = package
    return list(best_by_key.values())


def apply_pattern_suppression(
    pattern_id: str,
    package: Any,
    confirmed_patterns: Dict[str, List[Dict[str, Any]]],
) -> Dict[str, Any]:
    """Evaluate whether a package should be suppressed or down-ranked."""
    suppression_matches = get_pattern_suppression_matches(
        pattern_id,
        package.anchor,
        confirmed_patterns,
    )
    hard_match = next(
        (match for match in suppression_matches if match["mode"] == "hard"),
        None,
    )
    if hard_match:
        return {
            "suppressed": True,
            "suppressor": hard_match["suppressor"],
            "soft_adjustment": 0,
            "package": package,
        }

    soft_adjustment = max(
        [match["adjustment"] for match in suppression_matches if match["mode"] == "soft"],
        default=0,
    )
    if soft_adjustment:
        package.deterministic_score = max(0, package.deterministic_score - soft_adjustment)

    return {
        "suppressed": False,
        "suppressor": None,
        "soft_adjustment": soft_adjustment,
        "package": package,
    }


def materialize_pattern_package(
    *,
    case_id: int,
    analysis_id: str,
    pattern_id: str,
    pattern_name: str,
    pattern_config: Dict[str, Any],
    package: Any,
    extraction_result: Dict[str, Any],
    ai_full_threshold: int,
    ai_gray_threshold: int,
    run_full_analysis: Callable[[], Any],
    run_light_analysis: Callable[[], Any],
    model_name: Optional[str] = None,
    extra_finding_fields: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Finalize a surviving package into artifacts, a result record, and tracking metadata."""
    from models.rag import AIAnalysisResult
    from utils.analysis_summary import severity_from_confidence
    from utils.finding_contract import (
        build_deterministic_analysis_artifacts,
        finalize_deterministic_package,
    )
    from utils.pattern_suppression import build_confirmed_pattern_entry

    finalized = finalize_deterministic_package(
        package,
        ai_full_threshold=ai_full_threshold,
        ai_gray_threshold=ai_gray_threshold,
        run_full_analysis=run_full_analysis,
        run_light_analysis=run_light_analysis,
    )
    final_score = finalized["final_score"]
    artifacts = build_deterministic_analysis_artifacts(
        case_id=case_id,
        analysis_id=analysis_id,
        source_system="ai_correlation",
        pattern_id=pattern_id,
        pattern_name=pattern_name,
        correlation_key=package.correlation_key,
        confidence=final_score,
        summary=f"Pattern match: {pattern_name} ({package.correlation_key})",
        evidence_package=finalized["evidence_package"],
        severity=severity_from_confidence(final_score),
        events_analyzed=extraction_result.get("anchor_count", 0),
        deterministic_score=package.deterministic_score,
        coverage_quality=package.coverage.coverage_score if package.coverage else None,
        ai_adjustment=finalized["ai_adjustment"],
        ai_escalated=package.ai_escalated,
        ai_reasoning=finalized["ai_reasoning"],
        ai_false_positive_assessment=finalized["ai_false_positive_assessment"],
        mitre_techniques=pattern_config.get("mitre_techniques", []),
        extra_finding_fields=extra_finding_fields,
        rule_based_confidence=extraction_result.get("base_confidence", 50),
        model_used=model_name if package.ai_judgment else "deterministic",
        window_start=package.coverage.window_start if package.coverage else None,
        window_end=package.coverage.window_end if package.coverage else None,
    )
    return {
        "result_record": AIAnalysisResult(**artifacts["analysis_result_payload"]),
        "finding": artifacts["finding"],
        "should_emit_finding": finalized["should_emit_finding"],
        "confirmed_pattern_entry": build_confirmed_pattern_entry(
            correlation_key=package.correlation_key,
            score=final_score,
            anchor=package.anchor,
        ),
    }
