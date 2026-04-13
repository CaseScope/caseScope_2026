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


def build_pattern_threat_intel_context(
    opencti_provider: Any,
    pattern_config: Dict[str, Any],
    *,
    max_chars: int = 500,
) -> str:
    """Build concise threat-intel prompt context for one pattern."""
    if opencti_provider is None:
        return ""

    try:
        mitre_ids = pattern_config.get("mitre_techniques", [])
        ti_parts = []
        for mitre_id in mitre_ids[:2]:
            context = opencti_provider.get_attack_pattern_context(mitre_id)
            if not context.get("technique_name"):
                continue

            actors = [
                actor["name"]
                for actor in context.get("threat_actors", [])[:3]
                if actor.get("name")
            ]
            if actors:
                ti_parts.append(
                    f"THREAT INTEL: {mitre_id} is used by {', '.join(actors)}."
                )

            detection_guidance = context.get("detection_guidance")
            if detection_guidance:
                ti_parts.append(f"Detection guidance: {detection_guidance[:150]}")

        if not ti_parts:
            return ""

        ti_context = "\n".join(ti_parts)[:max_chars]
        ti_context += (
            "\nNote: use 'consistent with' language, "
            "not definitive attribution."
        )
        return ti_context
    except Exception:
        return ""


def prepare_task_ai_pattern_inputs(
    *,
    extractor: Any,
    pattern_config: Dict[str, Any],
    time_start: Optional[Any] = None,
    time_end: Optional[Any] = None,
) -> Dict[str, Any]:
    """Extract one task-driven AI pattern run and shape the task inputs."""
    extraction_result = extractor.extract_pattern_candidates(
        pattern_config=pattern_config,
        time_start=time_start,
        time_end=time_end,
    )
    extraction_stats = {
        "anchor_count": extraction_result["anchor_count"],
        "supporting_count": extraction_result["supporting_count"],
        "total_stored": extraction_result["total_stored"],
    }
    return {
        "extraction_result": extraction_result,
        "extraction_stats": extraction_stats,
        "should_skip": extraction_result["total_stored"] == 0,
        "anchor_events": extraction_result.get("anchors", []),
    }


def execute_task_ai_pattern(
    *,
    case_id: int,
    analysis_id: str,
    pattern_id: str,
    pattern_config: Dict[str, Any],
    extraction_result: Dict[str, Any],
    anchor_events: List[Any],
    opencti_provider: Any,
    evidence_engine: Any,
    confirmed_patterns: Dict[str, List[Dict[str, Any]]],
    findings_output: List[Any],
    run_full_analysis_for_package: Callable[[Any], Any],
    run_light_analysis_for_package: Callable[[Any], Any],
    model_name: Optional[str] = None,
    event_callback: Optional[Callable[[str, Any, Any], None]] = None,
    ai_gray_threshold_default: int = 20,
) -> Dict[str, Any]:
    """Run one task-driven AI pattern through TI context, evaluation, and persistence."""
    ti_context = build_pattern_threat_intel_context(opencti_provider, pattern_config)
    processed = evaluate_ai_pattern(
        case_id=case_id,
        analysis_id=analysis_id,
        pattern_id=pattern_id,
        pattern_name=pattern_config["name"],
        pattern_config=pattern_config,
        extraction_result=extraction_result,
        anchor_events=anchor_events,
        evidence_engine=evidence_engine,
        confirmed_patterns=confirmed_patterns,
        run_full_analysis_for_package=lambda package: run_full_analysis_for_package(
            package, ti_context
        ),
        run_light_analysis_for_package=run_light_analysis_for_package,
        model_name=model_name,
        event_callback=event_callback,
        ai_gray_threshold_default=ai_gray_threshold_default,
    )
    confirmed_entries = persist_ai_pattern_results(
        pattern_id=pattern_id,
        processed=processed,
        findings_output=findings_output,
        confirmed_patterns=confirmed_patterns,
    )
    return {
        "processed": processed,
        "confirmed_pattern_entries": confirmed_entries,
        "threat_intel_context": ti_context,
    }


def annotate_task_pattern_overlaps(
    findings: List[Dict[str, Any]],
    overlap_pairs: Optional[List[Tuple[str, str]]] = None,
) -> List[Dict[str, Any]]:
    """Annotate task findings with known overlapping pattern relationships."""
    pairs = overlap_pairs or [
        ("lsass_memory_dump", "process_injection"),
        ("lsass_memory_dump", "powershell_credential_dump"),
    ]
    detected_ids = {finding["pattern_id"] for finding in findings}
    for finding in findings:
        overlaps = []
        for pattern_a, pattern_b in pairs:
            if finding["pattern_id"] == pattern_a and pattern_b in detected_ids:
                overlaps.append(pattern_b)
            elif finding["pattern_id"] == pattern_b and pattern_a in detected_ids:
                overlaps.append(pattern_a)
        if overlaps:
            finding["overlapping_patterns"] = overlaps
    return findings


def finalize_task_ai_pattern_results(
    *,
    case_id: int,
    case_uuid: str,
    analysis_id: str,
    pattern_configs: Dict[str, Dict[str, Any]],
    all_results: List[Dict[str, Any]],
    extraction_stats: Dict[str, Any],
    errors: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Sort, annotate, and package the final task response payload."""
    all_results.sort(key=lambda finding: finding["confidence"], reverse=True)
    annotate_task_pattern_overlaps(all_results)
    return {
        "success": True,
        "case_id": case_id,
        "case_uuid": case_uuid,
        "analysis_id": analysis_id,
        "patterns_analyzed": len(pattern_configs),
        "results_count": len(all_results),
        "high_confidence_count": len(
            [finding for finding in all_results if finding["confidence"] >= 70]
        ),
        "results": all_results[:100],
        "extraction_stats": extraction_stats,
        "errors": errors if errors else None,
    }


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


def process_ai_pattern_packages(
    *,
    case_id: int,
    analysis_id: str,
    pattern_id: str,
    pattern_name: str,
    pattern_config: Dict[str, Any],
    extraction_result: Dict[str, Any],
    evidence_packages: List[Any],
    confirmed_patterns: Dict[str, List[Dict[str, Any]]],
    ai_full_threshold: int,
    ai_gray_threshold: int,
    run_full_analysis_for_package: Callable[[Any], Any],
    run_light_analysis_for_package: Callable[[Any], Any],
    model_name: Optional[str] = None,
    extra_finding_fields_for_package: Optional[Callable[[Any], Optional[Dict[str, Any]]]] = None,
    event_callback: Optional[Callable[[str, Any, Any], None]] = None,
) -> Dict[str, Any]:
    """Process AI-mode evidence packages through suppression and materialization."""
    result_records = []
    findings = []
    confirmed_pattern_entries = []

    for package in evidence_packages:
        suppression_result = apply_pattern_suppression(
            pattern_id,
            package,
            confirmed_patterns,
        )
        if suppression_result["suppressed"]:
            if event_callback is not None:
                event_callback("suppressed", package, suppression_result["suppressor"])
            continue

        soft_adjustment = suppression_result["soft_adjustment"]
        if soft_adjustment and event_callback is not None:
            event_callback("downranked", package, soft_adjustment)

        extra_finding_fields = None
        if extra_finding_fields_for_package is not None:
            extra_finding_fields = extra_finding_fields_for_package(package)

        materialized = materialize_pattern_package(
            case_id=case_id,
            analysis_id=analysis_id,
            pattern_id=pattern_id,
            pattern_name=pattern_name,
            pattern_config=pattern_config,
            package=package,
            extraction_result=extraction_result,
            ai_full_threshold=ai_full_threshold,
            ai_gray_threshold=ai_gray_threshold,
            run_full_analysis=lambda: run_full_analysis_for_package(package),
            run_light_analysis=lambda: run_light_analysis_for_package(package),
            model_name=model_name,
            extra_finding_fields=extra_finding_fields,
        )
        result_records.append(materialized["result_record"])
        if materialized["should_emit_finding"]:
            findings.append(materialized["finding"])
        confirmed_pattern_entries.append(materialized["confirmed_pattern_entry"])

    return {
        "result_records": result_records,
        "findings": findings,
        "confirmed_pattern_entries": confirmed_pattern_entries,
    }


def evaluate_ai_pattern(
    *,
    case_id: int,
    analysis_id: str,
    pattern_id: str,
    pattern_name: str,
    pattern_config: Dict[str, Any],
    extraction_result: Dict[str, Any],
    anchor_events: List[Any],
    evidence_engine: Any,
    confirmed_patterns: Dict[str, List[Dict[str, Any]]],
    run_full_analysis_for_package: Callable[[Any], Any],
    run_light_analysis_for_package: Callable[[Any], Any],
    model_name: Optional[str] = None,
    extra_finding_fields_for_package: Optional[Callable[[Any], Optional[Dict[str, Any]]]] = None,
    event_callback: Optional[Callable[[str, Any, Any], None]] = None,
    ai_full_threshold_default: int = 40,
    ai_gray_threshold_default: int = 30,
) -> Dict[str, Any]:
    """Evaluate one AI-mode pattern and process its surviving packages."""
    time_window = pattern_config.get("time_window_minutes", 60)
    evidence_packages = evidence_engine.evaluate_pattern(
        pattern_id,
        pattern_config,
        anchor_events,
        time_window,
    )
    evidence_packages = select_highest_scoring_packages(evidence_packages)
    return process_ai_pattern_packages(
        case_id=case_id,
        analysis_id=analysis_id,
        pattern_id=pattern_id,
        pattern_name=pattern_name,
        pattern_config=pattern_config,
        extraction_result=extraction_result,
        evidence_packages=evidence_packages,
        confirmed_patterns=confirmed_patterns,
        ai_full_threshold=pattern_config.get("ai_full_threshold", ai_full_threshold_default),
        ai_gray_threshold=pattern_config.get("ai_gray_threshold", ai_gray_threshold_default),
        run_full_analysis_for_package=run_full_analysis_for_package,
        run_light_analysis_for_package=run_light_analysis_for_package,
        model_name=model_name,
        extra_finding_fields_for_package=extra_finding_fields_for_package,
        event_callback=event_callback,
    )


def persist_ai_pattern_results(
    *,
    pattern_id: str,
    processed: Dict[str, Any],
    findings_output: List[Any],
    confirmed_patterns: Dict[str, List[Dict[str, Any]]],
) -> List[Dict[str, Any]]:
    """Persist processed AI-mode results and update suppression tracking."""
    from models.database import db
    from utils.pattern_suppression import should_track_pattern_for_suppression

    for result_record in processed["result_records"]:
        db.session.add(result_record)

    findings_output.extend(processed["findings"])
    confirmed_entries = processed["confirmed_pattern_entries"]
    db.session.commit()

    if should_track_pattern_for_suppression(pattern_id):
        confirmed_patterns[pattern_id] = confirmed_entries

    return confirmed_entries


def evaluate_rule_based_pattern(
    *,
    extractor: Any,
    rule_analyzer: Any,
    pattern_id: str,
    pattern_config: Dict[str, Any],
) -> List[Dict[str, Any]]:
    """Evaluate one non-AI pattern across its correlation keys."""
    pattern_results = []
    for key in extractor.get_correlation_keys(pattern_id):
        key_candidates = extractor.get_candidates_for_key(pattern_id, key)
        behavioral_context = key_candidates[0].get("behavioral_context") if key_candidates else None
        result = rule_analyzer.analyze_without_ai(
            candidates=key_candidates,
            pattern_config=pattern_config,
            behavioral_context=behavioral_context,
        )
        result["correlation_key"] = key
        result["pattern_id"] = pattern_id
        pattern_results.append(result)
    return pattern_results
