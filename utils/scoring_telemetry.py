"""Structured scoring telemetry for deterministic pattern analysis."""

import json
import logging
from typing import Any, Callable, Dict, Optional

from config import Config

logger = logging.getLogger(__name__)

_BENIGN_RATIONALE_TAGS = {
    "machine_account": ("machine account", "computer account"),
    "dc_replication": ("dc replication", "directory replication", "domain controller"),
    "admin_workflow": (
        "administrative workflow",
        "admin workflow",
        "legitimate administrative",
        "known administrative workflow",
    ),
    "expected_system_behavior": ("expected system behavior",),
    "missing_telemetry": ("missing telemetry", "coverage gap", "telemetry gap"),
}


def resolve_effective_scoring_version(pattern_config: Optional[Dict[str, Any]]) -> str:
    """Return the scoring version that should be used at runtime."""
    requested = str((pattern_config or {}).get("scoring_version") or "1.0")
    if getattr(Config, "RAG_FORCE_LEGACY_SCORING", False):
        return "1.0"
    return requested


def extract_ai_rationale_tags(ai_judgment: Optional[Dict[str, Any]]) -> list[str]:
    """Project stable benign rationale tags from AI reasoning text."""
    if not isinstance(ai_judgment, dict):
        return []

    text = " ".join(
        str(ai_judgment.get(key, "") or "")
        for key in ("reasoning", "false_positive_assessment")
    ).lower()
    tags = [
        tag
        for tag, markers in _BENIGN_RATIONALE_TAGS.items()
        if any(marker in text for marker in markers)
    ]
    return sorted(tags)


def build_scoring_telemetry(
    *,
    case_id: int,
    analysis_id: str,
    pattern_id: str,
    pattern_name: str,
    pattern_config: Optional[Dict[str, Any]],
    package: Any,
    finalized: Optional[Dict[str, Any]] = None,
    outcome: str = "materialized",
    suppression_detail: Optional[Any] = None,
    soft_suppression_adjustment: float = 0.0,
) -> Dict[str, Any]:
    """Build the structured scoring telemetry payload for one package event."""
    requested_version = str((pattern_config or {}).get("scoring_version") or "1.0")
    effective_version = (
        str(getattr(package, "scoring_version", "") or "")
        or resolve_effective_scoring_version(pattern_config)
    )
    finalized = finalized or {}
    ai_judgment = getattr(package, "ai_judgment", None) if isinstance(getattr(package, "ai_judgment", None), dict) else {}
    eligible_to_emit = finalized.get(
        "should_emit_finding",
        getattr(package, "eligible_to_emit", False),
    )
    emit_block_reasons = finalized.get(
        "emit_block_reasons",
        getattr(package, "emit_block_reasons", []) or [],
    )
    telemetry = {
        "event": "scoring_telemetry",
        "telemetry_contract_version": "scoring_2_0_phase1",
        "case_id": case_id,
        "analysis_id": analysis_id,
        "pattern_id": pattern_id,
        "pattern_name": pattern_name,
        "correlation_key": getattr(package, "correlation_key", ""),
        "outcome": outcome,
        "requested_scoring_version": requested_version,
        "effective_scoring_version": effective_version,
        "legacy_forced": requested_version != effective_version,
        "scoring_changes": list(getattr(package, "scoring_changes", []) or []),
        "deterministic_score": float(getattr(package, "deterministic_score", 0) or 0),
        "final_score": finalized.get("final_score"),
        "ai_adjustment": finalized.get("ai_adjustment"),
        "ai_analyzed": bool(finalized.get("ai_analyzed")),
        "ai_escalated": bool(getattr(package, "ai_escalated", False)),
        "eligible_to_emit": bool(eligible_to_emit),
        "emit_block_reasons": list(emit_block_reasons),
        "evaluable_weight": float(getattr(package, "evaluable_weight", 0) or 0),
        "excluded_weight": float(getattr(package, "excluded_weight", 0) or 0),
        "raw_total_weight": float(getattr(package, "raw_total_weight", 0) or 0),
        "coverage_gap_present": bool(getattr(package, "coverage_gap_present", False)),
        "overlay_score_adjustment": float(getattr(package, "overlay_score_adjustment", 0) or 0),
        "suppression_detail": suppression_detail,
        "soft_suppression_adjustment": float(soft_suppression_adjustment or 0),
        "ai_rationale_tags": extract_ai_rationale_tags(ai_judgment),
    }
    if ai_judgment:
        telemetry["ai_reasoning_present"] = bool(ai_judgment.get("reasoning"))
        telemetry["ai_false_positive_assessment_present"] = bool(
            ai_judgment.get("false_positive_assessment")
        )
    return telemetry


def emit_scoring_telemetry(
    payload: Dict[str, Any],
    *,
    writer: Optional[Callable[[str], None]] = None,
    logger_obj: Optional[logging.Logger] = None,
) -> None:
    """Emit one structured scoring telemetry payload as JSON."""
    line = json.dumps(payload, sort_keys=True, default=str)
    if writer is not None:
        writer(line)
        return
    (logger_obj or logger).info(line)
