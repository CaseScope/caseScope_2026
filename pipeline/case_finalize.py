"""Case-analysis finalization helpers."""

from datetime import datetime
from typing import Any, Callable, Dict, List, Optional

from models.behavioral_profiles import AnalysisStatus
from models.database import db
from utils.analysis_summary import summarize_findings


def finalize_case_analysis_run(
    analysis_run: Any,
    *,
    case_id: int,
    analysis_id: str,
    all_findings: List[Any],
    profiling_stats: Dict[str, Any],
    pattern_results: List[Any],
    gap_findings: List[Any],
    hayabusa_findings: List[Any],
    attack_chains: List[Any],
    census: Dict[str, int],
    ioc_timeline: Dict[str, Any],
    storyline_results: Dict[str, Any],
    triage_result: Dict[str, Any],
    synthesis_result: Dict[str, Any],
    phase_outcomes: Dict[str, Dict[str, Any]],
    degraded_reasons: List[str],
    final_status: str = AnalysisStatus.COMPLETE,
    phase_message: Optional[str] = None,
    progress_percent: int = 100,
    error_message: Optional[str] = None,
    partial_results_available: bool = False,
    start_time: Optional[datetime] = None,
    make_json_safe: Optional[Callable[[Any], Any]] = None,
    record_phase_outcome: Optional[Callable[..., None]] = None,
) -> bool:
    """Persist terminal analysis state, summary metrics, and findings-store sync."""
    if not analysis_run:
        return False

    make_json_safe = make_json_safe or (lambda value: value)
    finding_summary = summarize_findings(all_findings)
    total_findings = finding_summary["total_findings"]
    now = datetime.utcnow()

    db.session.commit()

    analysis_run.status = final_status
    analysis_run.completed_at = now
    analysis_run.last_progress_at = now
    analysis_run.progress_percent = min(100, max(0, progress_percent))
    analysis_run.current_phase = phase_message or (
        "Analysis complete" if final_status == AnalysisStatus.COMPLETE
        else "Partial results saved" if final_status == AnalysisStatus.PARTIAL
        else "Analysis failed"
    )
    analysis_run.partial_results_available = partial_results_available
    analysis_run.error_message = error_message[:500] if error_message else None

    analysis_run.findings_generated = total_findings
    analysis_run.high_confidence_findings = finding_summary["high_confidence_findings"]
    analysis_run.users_profiled = profiling_stats.get("users_profiled", 0)
    analysis_run.systems_profiled = profiling_stats.get("systems_profiled", 0)
    analysis_run.peer_groups_created = (
        profiling_stats.get("user_groups", 0) + profiling_stats.get("system_groups", 0)
    )
    analysis_run.patterns_evaluated = len(pattern_results)
    analysis_run.gap_findings = len(gap_findings)
    analysis_run.attack_chains_found = len(attack_chains)
    analysis_run.patterns_analyzed = len(pattern_results)

    summary = {
        "total_findings": total_findings,
        "critical_findings": finding_summary["critical_findings"],
        "high_findings": finding_summary["high_findings"],
        "medium_findings": finding_summary["medium_findings"],
        "low_findings": finding_summary["low_findings"],
        "gap_findings": len(gap_findings),
        "hayabusa_findings": len(hayabusa_findings),
        "attack_chains": len(attack_chains),
        "patterns_analyzed": len(pattern_results),
        "storyline_findings": len(storyline_results.get("storylines", [])),
        "users_profiled": profiling_stats.get("users_profiled", 0),
        "systems_profiled": profiling_stats.get("systems_profiled", 0),
        "high_confidence_findings": finding_summary["high_confidence_findings"],
        "severity_breakdown": finding_summary["severity_breakdown"],
        "top_findings": finding_summary["top_findings"],
        "mode": getattr(analysis_run, "mode", None),
        "duration_seconds": (now - start_time).total_seconds() if start_time else 0,
        "census_distinct_event_ids": len(census),
        "census_total_events": sum(census.values()) if census else 0,
        "ioc_timeline_entries": len(ioc_timeline.get("entries", [])) if ioc_timeline else 0,
        "ioc_timeline_cross_host_links": len(ioc_timeline.get("cross_host_links", [])) if ioc_timeline else 0,
        "incident_storylines": storyline_results.get("storylines", []),
        "ai_triage": triage_result if triage_result else None,
        "ai_synthesis": synthesis_result if synthesis_result else None,
        "phase_outcomes": phase_outcomes,
        "degraded_reasons": degraded_reasons,
        "partial_results_available": partial_results_available,
        "final_status": final_status,
    }
    analysis_run.summary = make_json_safe(summary)
    db.session.commit()

    try:
        from utils.unified_findings_store import sync_case_findings

        mirrored_count = sync_case_findings(case_id, analysis_id, all_findings)
        if record_phase_outcome:
            record_phase_outcome(
                "finding_storage_sync",
                True,
                details={"mirrored_findings": mirrored_count},
                message="Unified findings mirrored to ClickHouse",
            )
    except Exception as exc:
        if record_phase_outcome:
            record_phase_outcome(
                "finding_storage_sync",
                False,
                details={"error": str(exc)},
                message="Unified findings mirror unavailable",
            )

    summary["phase_outcomes"] = phase_outcomes
    analysis_run.summary = make_json_safe(summary)
    db.session.commit()
    return True
