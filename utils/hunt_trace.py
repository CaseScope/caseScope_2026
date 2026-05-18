"""Single write path for hunt ledger trace records."""
from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional, Tuple

from dateutil import parser as date_parser
from sqlalchemy import func

from models.database import db
from models.hunt import (
    HuntChecklistCheck,
    HuntChecklistCheckStatus,
    HuntChecklistDefinition,
    HuntChecklistRun,
    HuntChecklistRunStatus,
    HuntCoverageStatus,
    HuntCreatedByType,
    HuntDecision,
    HuntDecisionClassification,
    HuntDecisionEvidenceLink,
    HuntDecisionEvidenceRole,
    HuntDecisionScope,
    HuntDecisionState,
    HuntEvidenceRef,
    HuntHypothesis,
    HuntNegativeFinding,
    HuntNegativeFindingState,
    HuntNegativeFindingType,
    HuntRun,
    HuntSourceAvailabilityStatus,
    HuntStep,
    HuntStepStatus,
)

logger = logging.getLogger(__name__)

SCHEMA_VERSION = "hunt-ledger-v1"
DECISION_SCHEMA_VERSION = "hunt-decision-v1"
NEGATIVE_FINDING_SCHEMA_VERSION = "hunt-negative-finding-v1"
MAX_SUMMARY_CHARS = 1200
MAX_FIELD_CHARS = 2000

EVIDENCE_LIST_KEYS = (
    "events",
    "artifacts",
    "downloads",
    "processes",
    "process_tree",
    "memory_results",
    "network_logs",
    "connections",
    "results",
    "findings",
    "iocs",
)


def _utcnow() -> datetime:
    return datetime.utcnow()


def _json_safe(value: Any) -> Any:
    """Return a JSON-serializable copy with deterministic primitive values."""
    try:
        return json.loads(json.dumps(value, default=str, sort_keys=True))
    except Exception:
        return str(value)


def _stable_hash(payload: Any) -> str:
    serialized = json.dumps(_json_safe(payload), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def _truncate(value: Any, limit: int = MAX_FIELD_CHARS) -> Optional[str]:
    if value is None:
        return None
    text = str(value)
    if not text:
        return None
    return text[:limit]


def _parse_timestamp(value: Any) -> Optional[datetime]:
    if value in (None, ""):
        return None
    if isinstance(value, datetime):
        return value.replace(tzinfo=None) if value.tzinfo else value
    try:
        parsed = date_parser.parse(str(value))
        return parsed.replace(tzinfo=None) if parsed.tzinfo else parsed
    except Exception:
        return None


def _normalize_created_by_type(value: Optional[str]) -> str:
    normalized = str(value or HuntCreatedByType.SYSTEM).strip().lower()
    return normalized if normalized in HuntCreatedByType.all() else HuntCreatedByType.SYSTEM


def normalize_coverage_status(value: Optional[str]) -> str:
    normalized = str(value or HuntCoverageStatus.UNKNOWN).strip().lower()
    return normalized if normalized in HuntCoverageStatus.all() else HuntCoverageStatus.UNKNOWN


def _normalize_required_choice(value: Any, allowed: List[str], field_name: str) -> str:
    normalized = str(value or "").strip().lower()
    if normalized not in allowed:
        raise ValueError(f"{field_name} must be one of: {', '.join(allowed)}")
    return normalized


def _normalize_decision_state(value: Any) -> str:
    return _normalize_required_choice(value or HuntDecisionState.DRAFT, HuntDecisionState.all(), "decision_state")


def _normalize_decision_classification(value: Any) -> str:
    return _normalize_required_choice(value, HuntDecisionClassification.all(), "classification")


def _normalize_decision_scope(value: Any) -> str:
    return _normalize_required_choice(value or HuntDecisionScope.CASE, HuntDecisionScope.all(), "decision_scope")


def _normalize_evidence_role(value: Any) -> str:
    return _normalize_required_choice(value or HuntDecisionEvidenceRole.SUPPORTING, HuntDecisionEvidenceRole.all(), "support_role")


def _normalize_checklist_run_status(value: Any) -> str:
    return _normalize_required_choice(value or HuntChecklistRunStatus.DRAFT, HuntChecklistRunStatus.all(), "checklist_run_status")


def _normalize_check_status(value: Any) -> str:
    return _normalize_required_choice(value or HuntChecklistCheckStatus.PENDING, HuntChecklistCheckStatus.all(), "check_status")


def _normalize_source_availability_status(value: Any) -> str:
    return _normalize_required_choice(
        value or HuntSourceAvailabilityStatus.UNKNOWN,
        HuntSourceAvailabilityStatus.all(),
        "source_availability_status",
    )


def _normalize_negative_finding_state(value: Any) -> str:
    return _normalize_required_choice(value or HuntNegativeFindingState.DRAFT, HuntNegativeFindingState.all(), "finding_state")


def _normalize_negative_finding_type(value: Any) -> str:
    return _normalize_required_choice(value, HuntNegativeFindingType.all(), "finding_type")


def _normalize_confidence(value: Any) -> Optional[float]:
    if value in (None, ""):
        return None
    try:
        confidence = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("confidence must be numeric") from exc
    if confidence < 0 or confidence > 1:
        raise ValueError("confidence must be between 0 and 1")
    return confidence


def _next_step_number(hunt_run_id: int) -> int:
    current = db.session.query(func.max(HuntStep.step_number)).filter_by(
        hunt_run_id=int(hunt_run_id)
    ).scalar()
    return int(current or 0) + 1


def create_hunt_run(
    *,
    case_id: int,
    objective: str,
    created_by: str = "system",
    status: str = "active",
    model_provider: Optional[str] = None,
    model_name: Optional[str] = None,
    source_scope: Optional[Dict[str, Any]] = None,
    time_scope_start: Any = None,
    time_scope_end: Any = None,
) -> HuntRun:
    """Create a hunt run objective."""
    run = HuntRun(
        case_id=int(case_id),
        objective=str(objective or "").strip(),
        status=str(status or "active").strip() or "active",
        created_by=str(created_by or "system"),
        model_provider=_truncate(model_provider, 80),
        model_name=_truncate(model_name, 255),
        source_scope=_json_safe(source_scope or {}),
        time_scope_start=_parse_timestamp(time_scope_start),
        time_scope_end=_parse_timestamp(time_scope_end),
    )
    db.session.add(run)
    db.session.commit()
    return run


def add_hypothesis(
    *,
    hunt_run_id: int,
    hypothesis: str,
    status: str = "open",
    confidence: Optional[float] = None,
    rationale: Optional[str] = None,
) -> HuntHypothesis:
    """Append a hypothesis to a hunt run."""
    item = HuntHypothesis(
        hunt_run_id=int(hunt_run_id),
        hypothesis=str(hypothesis or "").strip(),
        status=str(status or "open").strip() or "open",
        confidence=confidence,
        rationale=rationale,
    )
    db.session.add(item)
    db.session.commit()
    return item


def _get_run(hunt_run_id: int) -> HuntRun:
    run = HuntRun.query.get(int(hunt_run_id))
    if run is None:
        raise ValueError("hunt_run_id not found")
    return run


def _get_decision(decision_or_id: HuntDecision | int) -> Optional[HuntDecision]:
    if isinstance(decision_or_id, HuntDecision):
        return decision_or_id
    try:
        return HuntDecision.query.get(int(decision_or_id))
    except Exception:
        return None


def _validate_hypothesis(hunt_run_id: int, hypothesis_id: Any) -> Optional[int]:
    if not hypothesis_id:
        return None
    hypothesis = HuntHypothesis.query.get(int(hypothesis_id))
    if hypothesis is None or int(hypothesis.hunt_run_id) != int(hunt_run_id):
        raise ValueError("hypothesis_id does not belong to hunt_run_id")
    return int(hypothesis_id)


def _validate_source_decision(hunt_run_id: int, source_decision_id: Any) -> Optional[int]:
    if not source_decision_id:
        return None
    source = HuntDecision.query.get(int(source_decision_id))
    if source is None or int(source.hunt_run_id) != int(hunt_run_id):
        raise ValueError("source_decision_id does not belong to hunt_run_id")
    if source.created_by_type != HuntCreatedByType.AI:
        raise ValueError("source_decision_id must reference an AI draft decision")
    return int(source_decision_id)


def _validate_superseded_decision(hunt_run_id: int, supersedes_decision_id: Any) -> Optional[HuntDecision]:
    if not supersedes_decision_id:
        return None
    prior = HuntDecision.query.get(int(supersedes_decision_id))
    if prior is None or int(prior.hunt_run_id) != int(hunt_run_id):
        raise ValueError("supersedes_decision_id does not belong to hunt_run_id")
    if prior.decision_state != HuntDecisionState.ACCEPTED or prior.created_by_type != HuntCreatedByType.ANALYST:
        raise ValueError("supersedes_decision_id must reference an analyst accepted decision")
    if prior.superseded_by_decision_id is not None:
        raise ValueError("supersedes_decision_id already has a superseding decision")
    return prior


def _target_value_for_scope(
    decision_scope: str,
    *,
    target_host: Optional[str] = None,
    target_user: Optional[str] = None,
    target_ioc: Optional[str] = None,
    target_artifact_path: Optional[str] = None,
    target_process: Optional[str] = None,
) -> Optional[str]:
    if decision_scope == HuntDecisionScope.CASE:
        return "case"
    if decision_scope == HuntDecisionScope.HOST:
        return target_host
    if decision_scope == HuntDecisionScope.USER:
        return target_user
    if decision_scope in (HuntDecisionScope.IOC, HuntDecisionScope.NETWORK):
        return target_ioc
    if decision_scope == HuntDecisionScope.ARTIFACT:
        return target_artifact_path
    if decision_scope in (HuntDecisionScope.PROCESS, HuntDecisionScope.SERVICE):
        return target_process
    return None


def _validate_decision_target(
    decision_scope: str,
    *,
    target_host: Optional[str] = None,
    target_user: Optional[str] = None,
    target_ioc: Optional[str] = None,
    target_artifact_path: Optional[str] = None,
    target_process: Optional[str] = None,
) -> None:
    if decision_scope != HuntDecisionScope.CASE and not _target_value_for_scope(
        decision_scope,
        target_host=target_host,
        target_user=target_user,
        target_ioc=target_ioc,
        target_artifact_path=target_artifact_path,
        target_process=target_process,
    ):
        raise ValueError("target field required for non-case decision_scope")


def _resolve_decision_evidence_links(
    *,
    hunt_run_id: int,
    case_id: int,
    evidence_links: Optional[List[Dict[str, Any]]],
) -> List[Dict[str, Any]]:
    resolved = []
    for raw_link in evidence_links or []:
        if not isinstance(raw_link, dict):
            raise ValueError("evidence_links entries must be objects")
        step_id = raw_link.get("hunt_step_id")
        evidence_ref_id = raw_link.get("hunt_evidence_ref_id")
        if not step_id and not evidence_ref_id:
            raise ValueError("evidence link requires hunt_step_id or hunt_evidence_ref_id")

        step = None
        evidence_ref = None
        if step_id:
            step = HuntStep.query.get(int(step_id))
            if step is None or int(step.hunt_run_id) != int(hunt_run_id):
                raise ValueError("hunt_step_id does not belong to hunt_run_id")
        if evidence_ref_id:
            evidence_ref = HuntEvidenceRef.query.get(int(evidence_ref_id))
            if evidence_ref is None or int(evidence_ref.case_id) != int(case_id):
                raise ValueError("hunt_evidence_ref_id does not belong to case_id")
            if int(evidence_ref.step.hunt_run_id) != int(hunt_run_id):
                raise ValueError("hunt_evidence_ref_id does not belong to hunt_run_id")
            if step is not None and int(evidence_ref.hunt_step_id) != int(step.id):
                raise ValueError("hunt_evidence_ref_id does not belong to hunt_step_id")

        resolved.append({
            "hunt_step_id": int(step.id) if step is not None else None,
            "hunt_evidence_ref_id": int(evidence_ref.id) if evidence_ref is not None else None,
            "support_role": _normalize_evidence_role(raw_link.get("support_role")),
            "note": _truncate(raw_link.get("note"), MAX_FIELD_CHARS),
            "step": step,
            "evidence_ref": evidence_ref,
        })
    return resolved


def fingerprint_decision_evidence(resolved_links: List[Dict[str, Any]]) -> str:
    """Create an order-stable fingerprint for decision evidence support."""
    selector_hashes = sorted(
        link["evidence_ref"].selector_hash
        for link in resolved_links
        if link.get("evidence_ref") is not None and link["evidence_ref"].selector_hash
    )
    step_fingerprints = sorted(
        link["step"].result_fingerprint
        for link in resolved_links
        if link.get("step") is not None and link["step"].result_fingerprint
    )
    stable_payload = {
        "selector_hashes": selector_hashes,
        "step_fingerprints": step_fingerprints,
    }
    return _stable_hash(stable_payload)


def _store_decision_evidence_links(decision: HuntDecision, resolved_links: List[Dict[str, Any]]) -> None:
    for link in resolved_links:
        db.session.add(HuntDecisionEvidenceLink(
            hunt_decision_id=decision.id,
            hunt_step_id=link.get("hunt_step_id"),
            hunt_evidence_ref_id=link.get("hunt_evidence_ref_id"),
            support_role=link.get("support_role") or HuntDecisionEvidenceRole.SUPPORTING,
            note=link.get("note"),
        ))


def create_decision(
    *,
    hunt_run_id: int,
    classification: str,
    decision_state: str = HuntDecisionState.DRAFT,
    decision_scope: str = HuntDecisionScope.CASE,
    created_by_type: str = HuntCreatedByType.SYSTEM,
    created_by: str = "system",
    hypothesis_id: Optional[int] = None,
    source_decision_id: Optional[int] = None,
    supersedes_decision_id: Optional[int] = None,
    target_host: Optional[str] = None,
    target_user: Optional[str] = None,
    target_ioc: Optional[str] = None,
    target_artifact_path: Optional[str] = None,
    target_process: Optional[str] = None,
    confidence: Any = None,
    rationale: Optional[str] = None,
    ai_rationale: Optional[str] = None,
    evidence_links: Optional[List[Dict[str, Any]]] = None,
    reviewed_by: Optional[str] = None,
    review_note: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None,
    schema_version: str = DECISION_SCHEMA_VERSION,
) -> HuntDecision:
    """Create an evidence-backed hunt decision."""
    run = _get_run(hunt_run_id)
    normalized_state = _normalize_decision_state(decision_state)
    normalized_classification = _normalize_decision_classification(classification)
    normalized_scope = _normalize_decision_scope(decision_scope)
    normalized_actor_type = _normalize_created_by_type(created_by_type)
    _validate_decision_target(
        normalized_scope,
        target_host=target_host,
        target_user=target_user,
        target_ioc=target_ioc,
        target_artifact_path=target_artifact_path,
        target_process=target_process,
    )
    normalized_hypothesis_id = _validate_hypothesis(run.id, hypothesis_id)
    normalized_source_id = _validate_source_decision(run.id, source_decision_id)
    superseded_decision = _validate_superseded_decision(run.id, supersedes_decision_id)
    resolved_links = _resolve_decision_evidence_links(
        hunt_run_id=run.id,
        case_id=run.case_id,
        evidence_links=evidence_links,
    )
    if normalized_state == HuntDecisionState.ACCEPTED and not resolved_links:
        raise ValueError("accepted decisions require at least one evidence link")

    now = _utcnow()
    decision = HuntDecision(
        hunt_run_id=run.id,
        hypothesis_id=normalized_hypothesis_id,
        case_id=run.case_id,
        source_decision_id=normalized_source_id,
        supersedes_decision_id=int(supersedes_decision_id) if superseded_decision else None,
        decision_state=normalized_state,
        classification=normalized_classification,
        decision_scope=normalized_scope,
        target_host=_truncate(target_host, 255),
        target_user=_truncate(target_user, 255),
        target_ioc=_truncate(target_ioc, MAX_FIELD_CHARS),
        target_artifact_path=_truncate(target_artifact_path, MAX_FIELD_CHARS),
        target_process=_truncate(target_process, MAX_FIELD_CHARS),
        confidence=_normalize_confidence(confidence),
        rationale=rationale,
        ai_rationale=ai_rationale,
        evidence_fingerprint=fingerprint_decision_evidence(resolved_links),
        created_by_type=normalized_actor_type,
        created_by=str(created_by or "system")[:80],
        reviewed_by=_truncate(reviewed_by, 80),
        reviewed_at=now if reviewed_by else None,
        review_note=review_note,
        accepted_at=now if normalized_state == HuntDecisionState.ACCEPTED else None,
        metadata_json=_json_safe(metadata or {}),
        schema_version=schema_version or DECISION_SCHEMA_VERSION,
    )
    db.session.add(decision)
    db.session.flush()
    _store_decision_evidence_links(decision, resolved_links)
    if superseded_decision is not None:
        superseded_decision.decision_state = HuntDecisionState.SUPERSEDED
        superseded_decision.superseded_by_decision_id = decision.id
        superseded_decision.superseded_at = now
    run.updated_at = now
    db.session.commit()
    return decision


def accept_decision(
    decision_or_id: HuntDecision | int,
    *,
    reviewed_by: str,
    classification: Optional[str] = None,
    rationale: Optional[str] = None,
    confidence: Any = None,
    evidence_links: Optional[List[Dict[str, Any]]] = None,
    review_note: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> HuntDecision:
    """Create an analyst-authored accepted decision from an AI draft."""
    source = _get_decision(decision_or_id)
    if source is None:
        raise ValueError("decision not found")
    if source.created_by_type != HuntCreatedByType.AI or source.decision_state != HuntDecisionState.DRAFT:
        raise ValueError("only AI draft decisions can be accepted")
    links = evidence_links if evidence_links is not None else [
        {
            "hunt_step_id": link.hunt_step_id,
            "hunt_evidence_ref_id": link.hunt_evidence_ref_id,
            "support_role": link.support_role,
            "note": link.note,
        }
        for link in source.evidence_links.order_by(HuntDecisionEvidenceLink.id.asc()).all()
    ]
    now = _utcnow()
    source.reviewed_by = str(reviewed_by or "system")[:80]
    source.reviewed_at = now
    source.review_note = review_note
    accepted = create_decision(
        hunt_run_id=source.hunt_run_id,
        hypothesis_id=source.hypothesis_id,
        source_decision_id=source.id,
        decision_state=HuntDecisionState.ACCEPTED,
        classification=classification or source.classification,
        decision_scope=source.decision_scope,
        target_host=source.target_host,
        target_user=source.target_user,
        target_ioc=source.target_ioc,
        target_artifact_path=source.target_artifact_path,
        target_process=source.target_process,
        confidence=confidence if confidence not in (None, "") else source.confidence,
        rationale=rationale if rationale is not None else source.rationale,
        ai_rationale=source.ai_rationale,
        evidence_links=links,
        created_by_type=HuntCreatedByType.ANALYST,
        created_by=reviewed_by,
        reviewed_by=reviewed_by,
        review_note=review_note,
        metadata=metadata or {},
    )
    return accepted


def reject_decision(
    decision_or_id: HuntDecision | int,
    *,
    reviewed_by: str,
    review_note: Optional[str] = None,
) -> HuntDecision:
    """Reject a non-authoritative draft decision while preserving it."""
    decision = _get_decision(decision_or_id)
    if decision is None:
        raise ValueError("decision not found")
    if decision.decision_state != HuntDecisionState.DRAFT:
        raise ValueError("only draft decisions can be rejected")
    decision.decision_state = HuntDecisionState.REJECTED
    decision.reviewed_by = str(reviewed_by or "system")[:80]
    decision.reviewed_at = _utcnow()
    decision.review_note = review_note
    decision.hunt_run.updated_at = _utcnow()
    db.session.commit()
    return decision


def supersede_decision(
    decision_or_id: HuntDecision | int,
    *,
    created_by: str,
    classification: str,
    rationale: str,
    evidence_links: List[Dict[str, Any]],
    confidence: Any = None,
    review_note: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> HuntDecision:
    """Create a replacement accepted decision for a prior accepted decision."""
    prior = _get_decision(decision_or_id)
    if prior is None:
        raise ValueError("decision not found")
    return create_decision(
        hunt_run_id=prior.hunt_run_id,
        hypothesis_id=prior.hypothesis_id,
        supersedes_decision_id=prior.id,
        decision_state=HuntDecisionState.ACCEPTED,
        classification=classification,
        decision_scope=prior.decision_scope,
        target_host=prior.target_host,
        target_user=prior.target_user,
        target_ioc=prior.target_ioc,
        target_artifact_path=prior.target_artifact_path,
        target_process=prior.target_process,
        confidence=confidence,
        rationale=rationale,
        evidence_links=evidence_links,
        created_by_type=HuntCreatedByType.ANALYST,
        created_by=created_by,
        reviewed_by=created_by,
        review_note=review_note,
        metadata=metadata or {},
    )


def active_authoritative_decisions(
    *,
    hunt_run_id: Optional[int] = None,
    case_id: Optional[int] = None,
    decision_scope: Optional[str] = None,
    target_filters: Optional[Dict[str, Any]] = None,
) -> List[HuntDecision]:
    """Return the shared active authoritative decision set."""
    query = HuntDecision.query.filter_by(
        decision_state=HuntDecisionState.ACCEPTED,
        created_by_type=HuntCreatedByType.ANALYST,
        superseded_by_decision_id=None,
    )
    if hunt_run_id is not None:
        query = query.filter_by(hunt_run_id=int(hunt_run_id))
    if case_id is not None:
        query = query.filter_by(case_id=int(case_id))
    if decision_scope:
        query = query.filter_by(decision_scope=_normalize_decision_scope(decision_scope))
    for field, value in (target_filters or {}).items():
        if value not in (None, "") and field in {
            "target_host",
            "target_user",
            "target_ioc",
            "target_artifact_path",
            "target_process",
        }:
            query = query.filter(getattr(HuntDecision, field) == str(value))
    return query.order_by(HuntDecision.created_at.desc(), HuntDecision.id.desc()).all()


def _get_checklist_definition(slug: str, version: str = "1.0") -> HuntChecklistDefinition:
    definition = HuntChecklistDefinition.query.filter_by(
        slug=str(slug or "").strip(),
        version=str(version or "1.0").strip(),
    ).first()
    if definition is None or not definition.is_active:
        raise ValueError("checklist definition not found or inactive")
    return definition


def _get_checklist_run(checklist_run_or_id: HuntChecklistRun | int) -> Optional[HuntChecklistRun]:
    if isinstance(checklist_run_or_id, HuntChecklistRun):
        return checklist_run_or_id
    try:
        return HuntChecklistRun.query.get(int(checklist_run_or_id))
    except Exception:
        return None


def _get_checklist_check(checklist_run_id: int, check_key: str) -> HuntChecklistCheck:
    check = HuntChecklistCheck.query.filter_by(
        checklist_run_id=int(checklist_run_id),
        check_key=str(check_key or "").strip(),
    ).first()
    if check is None:
        raise ValueError("check_key not found for checklist_run_id")
    return check


def _get_negative_finding(finding_or_id: HuntNegativeFinding | int) -> Optional[HuntNegativeFinding]:
    if isinstance(finding_or_id, HuntNegativeFinding):
        return finding_or_id
    try:
        return HuntNegativeFinding.query.get(int(finding_or_id))
    except Exception:
        return None


def _definition_checks(definition_snapshot: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    return {
        str(check.get("key")): check
        for check in (definition_snapshot or {}).get("required_checks", [])
        if check.get("key")
    }


def _checks_for_run(checklist_run_id: int) -> List[HuntChecklistCheck]:
    return HuntChecklistCheck.query.filter_by(checklist_run_id=int(checklist_run_id)).all()


def _allowed_language_templates(definition_snapshot: Dict[str, Any], coverage_status: str) -> List[Dict[str, Any]]:
    return list(
        (definition_snapshot or {})
        .get("allowed_language_by_coverage", {})
        .get(coverage_status, [])
    )


def _statement_template_key(definition_snapshot: Dict[str, Any], coverage_status: str, statement: str) -> Optional[str]:
    normalized_statement = str(statement or "").strip()
    for template in _allowed_language_templates(definition_snapshot, coverage_status):
        if normalized_statement == str(template.get("statement") or "").strip():
            return str(template.get("key") or "")
    return None


def _blocked_absence_phrases(definition_snapshot: Dict[str, Any]) -> List[str]:
    return [
        str(item or "").strip().lower()
        for item in (definition_snapshot or {}).get("blocked_language", [])
        if str(item or "").strip()
    ]


def _validate_negative_statement(
    checklist_run: HuntChecklistRun,
    statement: str,
) -> str:
    coverage_status = normalize_coverage_status(checklist_run.coverage_status)
    if coverage_status in {
        HuntCoverageStatus.INSUFFICIENT,
        HuntCoverageStatus.NOT_AVAILABLE,
        HuntCoverageStatus.UNKNOWN,
    }:
        raise ValueError(f"{coverage_status} coverage cannot produce a negative finding")

    lowered_statement = str(statement or "").strip().lower()
    for phrase in _blocked_absence_phrases(checklist_run.definition_snapshot_json or {}):
        if phrase and phrase in lowered_statement:
            raise ValueError("statement contains blocked absence language")

    template_key = _statement_template_key(
        checklist_run.definition_snapshot_json or {},
        coverage_status,
        statement,
    )
    if not template_key:
        raise ValueError("statement must match an approved language template for coverage_status")

    if coverage_status == HuntCoverageStatus.PARTIAL and not checklist_run.limitations_json:
        raise ValueError("partial coverage requires limitation text before a negative finding can be generated")
    return template_key


def create_checklist_run(
    *,
    hunt_run_id: int,
    checklist_slug: str,
    checklist_version: str = "1.0",
    decision_scope: str = HuntDecisionScope.CASE,
    target_metadata: Optional[Dict[str, Any]] = None,
    created_by_type: str = HuntCreatedByType.SYSTEM,
    created_by: str = "system",
    metadata: Optional[Dict[str, Any]] = None,
) -> HuntChecklistRun:
    """Create a checklist run and pending checks from a versioned definition."""
    run = _get_run(hunt_run_id)
    definition = _get_checklist_definition(checklist_slug, checklist_version)
    snapshot = _json_safe(definition.definition_json or {})
    normalized_scope = _normalize_decision_scope(decision_scope)
    supported_scopes = set(snapshot.get("supported_scopes") or [])
    if normalized_scope not in supported_scopes:
        raise ValueError("decision_scope is not supported by checklist definition")

    now = _utcnow()
    normalized_target_metadata = dict(target_metadata or {})
    normalized_target_metadata.setdefault("decision_scope", normalized_scope)
    checklist_run = HuntChecklistRun(
        case_id=run.case_id,
        hunt_run_id=run.id,
        checklist_definition_id=definition.id,
        checklist_slug=definition.slug,
        checklist_version=definition.version,
        definition_snapshot_json=snapshot,
        status=HuntChecklistRunStatus.DRAFT,
        coverage_status=HuntCoverageStatus.UNKNOWN,
        finding_eligible=False,
        finding_block_reasons_json=[],
        missing_sources_json=[],
        limitations_json=[],
        target_metadata_json=_json_safe(normalized_target_metadata),
        created_by_type=_normalize_created_by_type(created_by_type),
        created_by=str(created_by or "system")[:80],
        created_at=now,
        updated_at=now,
        metadata_json=_json_safe(metadata or {}),
    )
    db.session.add(checklist_run)
    db.session.flush()

    for check_definition in snapshot.get("required_checks", []):
        db.session.add(HuntChecklistCheck(
            case_id=run.case_id,
            hunt_run_id=run.id,
            checklist_run_id=checklist_run.id,
            check_key=str(check_definition.get("key") or "").strip(),
            check_name=str(check_definition.get("name") or check_definition.get("key") or "").strip(),
            check_status=HuntChecklistCheckStatus.PENDING,
            coverage_status=HuntCoverageStatus.UNKNOWN,
            source_availability_status=HuntSourceAvailabilityStatus.UNKNOWN,
            metadata_json=_json_safe({"definition": check_definition}),
        ))

    run.updated_at = now
    db.session.commit()
    return checklist_run


def list_checklist_runs(*, hunt_run_id: Optional[int] = None, case_id: Optional[int] = None) -> List[HuntChecklistRun]:
    """List checklist runs by hunt run or case."""
    query = HuntChecklistRun.query
    if hunt_run_id is not None:
        query = query.filter_by(hunt_run_id=int(hunt_run_id))
    if case_id is not None:
        query = query.filter_by(case_id=int(case_id))
    return query.order_by(HuntChecklistRun.created_at.desc(), HuntChecklistRun.id.desc()).all()


def get_checklist_run(checklist_run_id: int) -> HuntChecklistRun:
    """Return one checklist run or raise."""
    checklist_run = _get_checklist_run(checklist_run_id)
    if checklist_run is None:
        raise ValueError("checklist_run_id not found")
    return checklist_run


def attach_step_to_check(
    *,
    checklist_run_id: int,
    check_key: str,
    hunt_step_id: int,
    result_summary: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> HuntChecklistCheck:
    """Mark a traced-tool checklist check completed by linking a HuntStep."""
    check = _get_checklist_check(checklist_run_id, check_key)
    step = HuntStep.query.get(int(hunt_step_id))
    if step is None:
        raise ValueError("hunt_step_id not found")
    if int(step.case_id if hasattr(step, "case_id") else step.hunt_run.case_id) != int(check.case_id):
        raise ValueError("hunt_step_id does not belong to checklist case_id")
    if int(step.hunt_run_id) != int(check.hunt_run_id):
        raise ValueError("hunt_step_id does not belong to checklist hunt_run_id")

    checklist_run = get_checklist_run(check.checklist_run_id)
    check_definition = _definition_checks(checklist_run.definition_snapshot_json or {}).get(check.check_key, {})
    approved_tools = set(check_definition.get("approved_tools") or [])
    if check_definition.get("type") == "source_metadata":
        raise ValueError("source metadata checks must be completed with source metadata")
    if approved_tools and step.tool_name not in approved_tools:
        raise ValueError("hunt_step tool_name is not approved for check_key")

    now = _utcnow()
    check.hunt_step_id = step.id
    check.check_status = HuntChecklistCheckStatus.COMPLETED
    check.coverage_status = normalize_coverage_status(step.coverage_status)
    check.source_availability_status = HuntSourceAvailabilityStatus.AVAILABLE
    check.result_count = step.result_count
    check.result_summary = _truncate(result_summary if result_summary is not None else step.result_summary, MAX_FIELD_CHARS)
    check.completed_at = now
    check.updated_at = now
    check.metadata_json = _json_safe(metadata or check.metadata_json or {})
    checklist_run.status = HuntChecklistRunStatus.IN_PROGRESS
    checklist_run.updated_at = now
    db.session.commit()
    return check


def record_check_source_metadata(
    *,
    checklist_run_id: int,
    check_key: str,
    source_metadata: Dict[str, Any],
    source_availability_status: str = HuntSourceAvailabilityStatus.AVAILABLE,
    limitations: Optional[List[Any]] = None,
    result_summary: Optional[str] = None,
) -> HuntChecklistCheck:
    """Complete a source-driven checklist check with documented source metadata."""
    if not isinstance(source_metadata, dict) or not source_metadata:
        raise ValueError("source_metadata_json required")
    check = _get_checklist_check(checklist_run_id, check_key)
    checklist_run = get_checklist_run(check.checklist_run_id)
    check_definition = _definition_checks(checklist_run.definition_snapshot_json or {}).get(check.check_key, {})
    if check_definition.get("type") != "source_metadata":
        raise ValueError("source metadata can only be recorded for source_metadata checks")

    now = _utcnow()
    check.check_status = HuntChecklistCheckStatus.COMPLETED
    check.coverage_status = normalize_coverage_status(source_metadata.get("coverage_status") or checklist_run.coverage_status)
    check.source_availability_status = _normalize_source_availability_status(source_availability_status)
    check.source_metadata_json = _json_safe(source_metadata)
    check.limitations_json = _json_safe(limitations or source_metadata.get("limitations") or [])
    check.result_summary = _truncate(result_summary or source_metadata.get("review_summary"), MAX_FIELD_CHARS)
    check.completed_at = now
    check.updated_at = now
    checklist_run.status = HuntChecklistRunStatus.IN_PROGRESS
    checklist_run.updated_at = now
    db.session.commit()
    return check


def mark_check_not_applicable(
    *,
    checklist_run_id: int,
    check_key: str,
    reason: str,
    metadata: Optional[Dict[str, Any]] = None,
) -> HuntChecklistCheck:
    """Mark a checklist check not applicable with a required reason."""
    if not str(reason or "").strip():
        raise ValueError("not_applicable_reason required")
    check = _get_checklist_check(checklist_run_id, check_key)
    now = _utcnow()
    check.check_status = HuntChecklistCheckStatus.NOT_APPLICABLE
    check.source_availability_status = HuntSourceAvailabilityStatus.NOT_APPLICABLE
    check.not_applicable_reason = str(reason).strip()
    check.metadata_json = _json_safe(metadata or {})
    check.completed_at = now
    check.updated_at = now
    checklist_run = get_checklist_run(check.checklist_run_id)
    checklist_run.status = HuntChecklistRunStatus.IN_PROGRESS
    checklist_run.updated_at = now
    db.session.commit()
    return check


def recalculate_checklist_coverage(
    checklist_run_or_id: HuntChecklistRun | int,
    *,
    coverage_status: Optional[str] = None,
    missing_sources: Optional[List[Any]] = None,
    limitations: Optional[List[Any]] = None,
) -> HuntChecklistRun:
    """Set checklist coverage metadata before eligibility is calculated."""
    checklist_run = get_checklist_run(checklist_run_or_id) if not isinstance(checklist_run_or_id, HuntChecklistRun) else checklist_run_or_id
    if coverage_status is not None:
        checklist_run.coverage_status = normalize_coverage_status(coverage_status)
    checklist_run.missing_sources_json = _json_safe(missing_sources or checklist_run.missing_sources_json or [])
    checklist_run.limitations_json = _json_safe(limitations or checklist_run.limitations_json or [])
    checklist_run.updated_at = _utcnow()
    db.session.commit()
    return checklist_run


def calculate_finding_eligibility(
    checklist_run_or_id: HuntChecklistRun | int,
    *,
    statement: Optional[str] = None,
) -> Dict[str, Any]:
    """Calculate whether a checklist run can support a negative finding."""
    checklist_run = get_checklist_run(checklist_run_or_id) if not isinstance(checklist_run_or_id, HuntChecklistRun) else checklist_run_or_id
    coverage_status = normalize_coverage_status(checklist_run.coverage_status)
    block_reasons: List[Dict[str, str]] = []

    def block(code: str, message: str) -> None:
        block_reasons.append({"code": code, "severity": "blocking", "message": message})

    if checklist_run.status != HuntChecklistRunStatus.COMPLETED:
        block("checklist_not_completed", "Checklist run must be operationally completed.")
    if coverage_status == HuntCoverageStatus.INSUFFICIENT:
        block("coverage_insufficient", "Coverage is insufficient for a negative finding.")
    elif coverage_status == HuntCoverageStatus.NOT_AVAILABLE:
        block("coverage_not_available", "Required coverage is not available.")
    elif coverage_status == HuntCoverageStatus.UNKNOWN:
        block("coverage_unknown", "Coverage status is unknown.")
    elif coverage_status == HuntCoverageStatus.PARTIAL and not checklist_run.limitations_json:
        block("mandatory_limitation_missing", "Partial coverage requires limitation text.")

    required_checks = _definition_checks(checklist_run.definition_snapshot_json or {})
    checks = {check.check_key: check for check in _checks_for_run(checklist_run.id)}
    for check_key, check_definition in required_checks.items():
        check = checks.get(check_key)
        if check is None:
            block("required_check_not_completed", f"Required check {check_key} is missing.")
            continue
        if check.check_status == HuntChecklistCheckStatus.PENDING:
            block("required_check_not_completed", f"Required check {check_key} is pending.")
            continue
        if check.check_status in {HuntChecklistCheckStatus.FAILED, HuntChecklistCheckStatus.SKIPPED}:
            block("required_check_not_completed", f"Required check {check_key} is {check.check_status}.")
            continue
        if check.check_status == HuntChecklistCheckStatus.NOT_APPLICABLE and not check.not_applicable_reason:
            block("not_applicable_reason_missing", f"Check {check_key} needs a not_applicable reason.")
            continue
        if check.check_status == HuntChecklistCheckStatus.COMPLETED:
            if check_definition.get("type") == "source_metadata":
                if not check.source_metadata_json:
                    block("source_metadata_not_documented", f"Source metadata check {check_key} lacks source metadata.")
            elif not check.hunt_step_id:
                block("check_not_linked_to_hunt_step", f"Check {check_key} lacks a HuntStep link.")

    if statement is not None:
        try:
            _validate_negative_statement(checklist_run, statement)
        except ValueError as exc:
            code = "unapproved_absence_language"
            if "partial coverage requires" in str(exc):
                code = "mandatory_limitation_missing"
            elif "coverage cannot produce" in str(exc):
                code = f"coverage_{coverage_status}"
            block(code, str(exc))

    eligible = not block_reasons
    return {"finding_eligible": eligible, "block_reasons": block_reasons}


def complete_checklist_run(
    checklist_run_or_id: HuntChecklistRun | int,
    *,
    coverage_status: Optional[str] = None,
    missing_sources: Optional[List[Any]] = None,
    limitations: Optional[List[Any]] = None,
) -> HuntChecklistRun:
    """Operationally complete a checklist run and calculate eligibility."""
    checklist_run = get_checklist_run(checklist_run_or_id) if not isinstance(checklist_run_or_id, HuntChecklistRun) else checklist_run_or_id
    recalculate_checklist_coverage(
        checklist_run,
        coverage_status=coverage_status,
        missing_sources=missing_sources,
        limitations=limitations,
    )
    checklist_run.status = HuntChecklistRunStatus.COMPLETED
    checklist_run.completed_at = _utcnow()
    eligibility = calculate_finding_eligibility(checklist_run)
    checklist_run.finding_eligible = bool(eligibility["finding_eligible"])
    checklist_run.finding_block_reasons_json = _json_safe(eligibility["block_reasons"])
    checklist_run.updated_at = _utcnow()
    db.session.commit()
    return checklist_run


def create_negative_finding_draft(
    *,
    checklist_run_id: int,
    finding_type: str,
    statement: str,
    created_by_type: str = HuntCreatedByType.AI,
    created_by: str = "system",
    confidence: Any = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> HuntNegativeFinding:
    """Create a non-reportable draft negative finding from an eligible checklist."""
    checklist_run = get_checklist_run(checklist_run_id)
    eligibility = calculate_finding_eligibility(checklist_run, statement=statement)
    if not eligibility["finding_eligible"]:
        checklist_run.finding_eligible = False
        checklist_run.finding_block_reasons_json = _json_safe(eligibility["block_reasons"])
        db.session.commit()
        raise ValueError("checklist_run is not eligible for a negative finding")
    template_key = _validate_negative_statement(checklist_run, statement)

    now = _utcnow()
    finding = HuntNegativeFinding(
        case_id=checklist_run.case_id,
        hunt_run_id=checklist_run.hunt_run_id,
        checklist_run_id=checklist_run.id,
        finding_state=HuntNegativeFindingState.DRAFT,
        finding_type=_normalize_negative_finding_type(finding_type),
        statement=str(statement or "").strip(),
        coverage_status=normalize_coverage_status(checklist_run.coverage_status),
        confidence=_normalize_confidence(confidence),
        decision_scope=str((checklist_run.target_metadata_json or {}).get("decision_scope") or HuntDecisionScope.CASE),
        target_metadata_json=_json_safe(checklist_run.target_metadata_json or {}),
        created_by_type=_normalize_created_by_type(created_by_type),
        created_by=str(created_by or "system")[:80],
        language_template_key=template_key,
        limitations_json=_json_safe(checklist_run.limitations_json or []),
        missing_sources_json=_json_safe(checklist_run.missing_sources_json or []),
        metadata_json=_json_safe(metadata or {}),
        schema_version=NEGATIVE_FINDING_SCHEMA_VERSION,
        created_at=now,
        updated_at=now,
    )
    finding.checklist_run = checklist_run
    checklist_run.finding_eligible = True
    checklist_run.finding_block_reasons_json = []
    db.session.add(finding)
    db.session.commit()
    return finding


def accept_negative_finding(
    finding_or_id: HuntNegativeFinding | int,
    *,
    reviewed_by: str,
    review_note: Optional[str] = None,
) -> HuntNegativeFinding:
    """Create an analyst-owned accepted finding from a draft."""
    source = _get_negative_finding(finding_or_id)
    if source is None:
        raise ValueError("negative finding not found")
    if source.finding_state != HuntNegativeFindingState.DRAFT:
        raise ValueError("only draft negative findings can be accepted")
    checklist_run = get_checklist_run(source.checklist_run_id)
    eligibility = calculate_finding_eligibility(checklist_run, statement=source.statement)
    if not eligibility["finding_eligible"]:
        checklist_run.finding_eligible = False
        checklist_run.finding_block_reasons_json = _json_safe(eligibility["block_reasons"])
        db.session.commit()
        raise ValueError("checklist_run is not eligible for a negative finding")

    now = _utcnow()
    source.reviewed_by = str(reviewed_by or "system")[:80]
    source.reviewed_at = now
    source.review_note = review_note
    accepted = HuntNegativeFinding(
        case_id=source.case_id,
        hunt_run_id=source.hunt_run_id,
        checklist_run_id=source.checklist_run_id,
        source_finding_id=source.id,
        finding_state=HuntNegativeFindingState.ACCEPTED,
        finding_type=source.finding_type,
        statement=source.statement,
        coverage_status=source.coverage_status,
        confidence=source.confidence,
        decision_scope=source.decision_scope,
        target_metadata_json=_json_safe(source.target_metadata_json or {}),
        created_by_type=HuntCreatedByType.ANALYST,
        created_by=str(reviewed_by or "system")[:80],
        reviewed_by=str(reviewed_by or "system")[:80],
        reviewed_at=now,
        review_note=review_note,
        accepted_at=now,
        evidence_fingerprint=source.evidence_fingerprint,
        language_template_key=source.language_template_key,
        limitations_json=_json_safe(source.limitations_json or []),
        missing_sources_json=_json_safe(source.missing_sources_json or []),
        metadata_json=_json_safe(source.metadata_json or {}),
        schema_version=source.schema_version or NEGATIVE_FINDING_SCHEMA_VERSION,
        created_at=now,
        updated_at=now,
    )
    accepted.checklist_run = checklist_run
    db.session.add(accepted)
    checklist_run.updated_at = now
    db.session.commit()
    return accepted


def reject_negative_finding(
    finding_or_id: HuntNegativeFinding | int,
    *,
    reviewed_by: str,
    review_note: Optional[str] = None,
) -> HuntNegativeFinding:
    """Reject a draft negative finding while preserving history."""
    finding = _get_negative_finding(finding_or_id)
    if finding is None:
        raise ValueError("negative finding not found")
    if finding.finding_state != HuntNegativeFindingState.DRAFT:
        raise ValueError("only draft negative findings can be rejected")
    finding.finding_state = HuntNegativeFindingState.REJECTED
    finding.reviewed_by = str(reviewed_by or "system")[:80]
    finding.reviewed_at = _utcnow()
    finding.rejected_at = finding.reviewed_at
    finding.review_note = review_note
    finding.updated_at = finding.reviewed_at
    db.session.commit()
    return finding


def supersede_negative_finding(
    finding_or_id: HuntNegativeFinding | int,
    *,
    created_by: str,
    statement: str,
    review_note: Optional[str] = None,
    confidence: Any = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> HuntNegativeFinding:
    """Create an analyst-owned accepted replacement for an active finding."""
    prior = _get_negative_finding(finding_or_id)
    if prior is None:
        raise ValueError("negative finding not found")
    if not prior.is_active:
        raise ValueError("only active negative findings can be superseded")
    checklist_run = get_checklist_run(prior.checklist_run_id)
    eligibility = calculate_finding_eligibility(checklist_run, statement=statement)
    if not eligibility["finding_eligible"]:
        checklist_run.finding_eligible = False
        checklist_run.finding_block_reasons_json = _json_safe(eligibility["block_reasons"])
        db.session.commit()
        raise ValueError("checklist_run is not eligible for a negative finding")
    template_key = _validate_negative_statement(checklist_run, statement)

    now = _utcnow()
    replacement = HuntNegativeFinding(
        case_id=prior.case_id,
        hunt_run_id=prior.hunt_run_id,
        checklist_run_id=prior.checklist_run_id,
        supersedes_finding_id=prior.id,
        finding_state=HuntNegativeFindingState.ACCEPTED,
        finding_type=prior.finding_type,
        statement=str(statement or "").strip(),
        coverage_status=checklist_run.coverage_status,
        confidence=_normalize_confidence(confidence),
        decision_scope=prior.decision_scope,
        target_metadata_json=_json_safe(prior.target_metadata_json or {}),
        created_by_type=HuntCreatedByType.ANALYST,
        created_by=str(created_by or "system")[:80],
        reviewed_by=str(created_by or "system")[:80],
        reviewed_at=now,
        review_note=review_note,
        accepted_at=now,
        language_template_key=template_key,
        limitations_json=_json_safe(checklist_run.limitations_json or []),
        missing_sources_json=_json_safe(checklist_run.missing_sources_json or []),
        metadata_json=_json_safe(metadata or {}),
        schema_version=prior.schema_version or NEGATIVE_FINDING_SCHEMA_VERSION,
        created_at=now,
        updated_at=now,
    )
    replacement.checklist_run = checklist_run
    db.session.add(replacement)
    db.session.flush()
    prior.finding_state = HuntNegativeFindingState.SUPERSEDED
    prior.superseded_by_finding_id = replacement.id
    prior.superseded_at = now
    prior.updated_at = now
    db.session.commit()
    return replacement


def get_active_negative_findings(
    *,
    hunt_run_id: Optional[int] = None,
    case_id: Optional[int] = None,
    finding_type: Optional[str] = None,
    decision_scope: Optional[str] = None,
) -> List[HuntNegativeFinding]:
    """Return active analyst-accepted negative findings."""
    query = HuntNegativeFinding.query.filter_by(
        finding_state=HuntNegativeFindingState.ACCEPTED,
        created_by_type=HuntCreatedByType.ANALYST,
        superseded_by_finding_id=None,
    )
    if hunt_run_id is not None:
        query = query.filter_by(hunt_run_id=int(hunt_run_id))
    if case_id is not None:
        query = query.filter_by(case_id=int(case_id))
    if finding_type:
        query = query.filter_by(finding_type=_normalize_negative_finding_type(finding_type))
    if decision_scope:
        query = query.filter_by(decision_scope=_normalize_decision_scope(decision_scope))
    return query.order_by(HuntNegativeFinding.created_at.desc(), HuntNegativeFinding.id.desc()).all()


def start_step(
    *,
    hunt_run_id: int,
    tool_name: str,
    tool_params: Optional[Dict[str, Any]] = None,
    case_id: Optional[int] = None,
    hypothesis_id: Optional[int] = None,
    query_summary: Optional[str] = None,
    created_by_type: str = HuntCreatedByType.SYSTEM,
    created_by: str = "system",
    model_provider: Optional[str] = None,
    model_name: Optional[str] = None,
    prompt_version: Optional[str] = None,
    schema_version: str = SCHEMA_VERSION,
) -> HuntStep:
    """Start a traced tool step."""
    run = HuntRun.query.get(int(hunt_run_id))
    if run is None:
        raise ValueError("hunt_run_id not found")
    if case_id is not None and int(case_id) != int(run.case_id):
        raise ValueError("hunt_run_id does not belong to case_id")
    step = HuntStep(
        hunt_run_id=int(hunt_run_id),
        hypothesis_id=int(hypothesis_id) if hypothesis_id else None,
        step_number=_next_step_number(int(hunt_run_id)),
        tool_name=str(tool_name or "unknown")[:120],
        tool_parameters_json=_json_safe(tool_params or {}),
        query_summary=query_summary,
        started_at=_utcnow(),
        status=HuntStepStatus.STARTED,
        coverage_status=HuntCoverageStatus.UNKNOWN,
        created_by_type=_normalize_created_by_type(created_by_type),
        created_by=str(created_by or "system")[:80],
        model_provider=_truncate(model_provider, 80),
        model_name=_truncate(model_name, 255),
        prompt_version=_truncate(prompt_version, 80),
        schema_version=schema_version or SCHEMA_VERSION,
    )
    db.session.add(step)
    db.session.commit()
    return step


def _get_step(step_or_id: HuntStep | int) -> Optional[HuntStep]:
    if isinstance(step_or_id, HuntStep):
        return step_or_id
    try:
        return HuntStep.query.get(int(step_or_id))
    except Exception:
        return None


def _infer_source_table(tool_name: str, key_path: str, row: Dict[str, Any]) -> str:
    lowered = f"{tool_name} {key_path} {row.get('source_table', '')}".lower()
    if "network" in lowered or row.get("log_type"):
        return "network_logs"
    if "memory" in lowered:
        return "memory"
    if "finding" in lowered:
        return "case_unified_findings"
    return str(row.get("source_table") or "events")


def _first_value(row: Dict[str, Any], keys: Iterable[str]) -> Any:
    for key in keys:
        value = row.get(key)
        if value not in (None, "", []):
            return value
    return None


def normalize_evidence_selector(
    *,
    case_id: int,
    row: Dict[str, Any],
    tool_name: str = "",
    key_path: str = "",
) -> Dict[str, Any]:
    """Normalize a returned row into a durable evidence selector."""
    source_table = _infer_source_table(tool_name, key_path, row)
    timestamp_value = _first_value(row, ("timestamp_utc", "timestamp", "time", "ts", "event_timestamp", "first_seen"))
    host = _first_value(row, ("source_host", "host", "hostname", "computer", "sensor", "id_orig_h"))
    username = _first_value(row, ("username", "user", "account", "target_user"))
    artifact_path = _first_value(row, ("artifact_path", "target_path", "file_path", "path", "process_path", "download_path"))
    selector = {
        "case_id": int(case_id),
        "source_table": source_table,
        "source_file": _truncate(_first_value(row, ("source_file", "file", "filename")), 1024),
        "artifact_type": _truncate(_first_value(row, ("artifact_type", "_artifact_type", "type", "log_type")), 120),
        "timestamp_utc": str(timestamp_value) if timestamp_value not in (None, "") else None,
        "event_id": _truncate(_first_value(row, ("event_id", "eventid")), 80),
        "record_id": _truncate(_first_value(row, ("record_id", "event_record_id", "record_number")), 120),
        "source_host": _truncate(host, 255),
        "username": _truncate(username, 255),
        "ioc_value": _truncate(_first_value(row, ("ioc_value", "value", "indicator")), MAX_FIELD_CHARS),
        "artifact_path": _truncate(artifact_path, MAX_FIELD_CHARS),
        "row_uuid": _truncate(_first_value(row, ("row_uuid", "uuid", "event_uuid")), 120),
        "source_id": _truncate(_first_value(row, ("source_id", "id", "uid")), 255),
    }
    selector["selector_hash"] = hash_selector(selector)
    return selector


def hash_selector(selector: Dict[str, Any]) -> str:
    """Hash normalized selector fields, excluding any existing hash."""
    normalized = {
        key: selector.get(key)
        for key in sorted(selector.keys())
        if key != "selector_hash" and selector.get(key) not in ("", [], {})
    }
    return _stable_hash(normalized)


def _iter_candidate_rows(payload: Any, key_path: str = "") -> Iterable[Tuple[str, Dict[str, Any]]]:
    if isinstance(payload, list):
        for item in payload:
            if isinstance(item, dict):
                yield key_path, item
        return
    if not isinstance(payload, dict):
        return
    for key, value in payload.items():
        next_path = f"{key_path}.{key}" if key_path else key
        if key in EVIDENCE_LIST_KEYS and isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    yield next_path, item
            continue
        if isinstance(value, dict):
            yield from _iter_candidate_rows(value, next_path)


def _row_has_evidence_shape(row: Dict[str, Any]) -> bool:
    fields = {
        "timestamp", "timestamp_utc", "event_id", "source_host", "host",
        "username", "user", "artifact_type", "_artifact_type", "source_file",
        "target_path", "file_path", "path", "process_name", "command_line",
        "ioc_value", "value", "rule", "rule_title", "summary",
    }
    return any(row.get(field) not in (None, "", []) for field in fields)


def extract_evidence_refs(
    *,
    case_id: int,
    tool_name: str,
    result_payload: Dict[str, Any],
) -> Tuple[List[Dict[str, Any]], List[str]]:
    """Extract normalized evidence selectors without raising on partial failures."""
    refs: List[Dict[str, Any]] = []
    warnings: List[str] = []
    seen = set()
    for key_path, row in _iter_candidate_rows(result_payload):
        if not _row_has_evidence_shape(row):
            continue
        try:
            selector = normalize_evidence_selector(
                case_id=case_id,
                row=row,
                tool_name=tool_name,
                key_path=key_path,
            )
            selector_hash = selector["selector_hash"]
            if selector_hash in seen:
                continue
            seen.add(selector_hash)
            refs.append({
                "selector": selector,
                "row": _json_safe(row),
                "key_path": key_path,
            })
        except Exception as exc:  # noqa: BLE001
            warnings.append(f"{key_path or 'row'}: {exc}")
    return refs, warnings


def _result_count(payload: Dict[str, Any], evidence_refs: List[Dict[str, Any]]) -> int:
    for key in ("event_count", "result_count", "total_matches", "count", "download_count", "process_count"):
        value = payload.get(key)
        if isinstance(value, int) and value >= 0:
            return value
    return len(evidence_refs)


def _summarize_result(payload: Dict[str, Any], result_count: int) -> str:
    if payload.get("error"):
        return _truncate(payload.get("error"), MAX_SUMMARY_CHARS) or ""
    summary_parts = [f"result_count={result_count}"]
    for key in ("query_filters", "search", "artifact_types", "artifact_filter", "group_by"):
        if key in payload:
            summary_parts.append(f"{key}={json.dumps(_json_safe(payload.get(key)), sort_keys=True)[:300]}")
    for key in ("summary", "result_summary", "message"):
        if payload.get(key):
            summary_parts.append(str(payload.get(key))[:500])
            break
    return _truncate("; ".join(summary_parts), MAX_SUMMARY_CHARS) or ""


def fingerprint_result(
    *,
    tool_name: str,
    tool_params: Dict[str, Any],
    result_summary: str,
    evidence_refs: List[Dict[str, Any]],
) -> str:
    """Create an order-stable result fingerprint."""
    selector_hashes = sorted(
        ref.get("selector", {}).get("selector_hash", "")
        for ref in evidence_refs
        if ref.get("selector", {}).get("selector_hash")
    )
    stable_payload = {
        "tool_name": tool_name,
        "tool_params": _json_safe(tool_params or {}),
        "result_summary": result_summary or "",
        "selector_hashes": selector_hashes,
    }
    return _stable_hash(stable_payload)


def _store_evidence_refs(step: HuntStep, refs: List[Dict[str, Any]]) -> None:
    for ref in refs:
        selector = ref.get("selector") or {}
        row = ref.get("row") if isinstance(ref.get("row"), dict) else {}
        evidence = HuntEvidenceRef(
            hunt_step_id=step.id,
            case_id=step.hunt_run.case_id,
            source_type=_truncate(ref.get("key_path"), 80),
            source_table=_truncate(selector.get("source_table"), 80),
            source_id=_truncate(selector.get("source_id"), 255),
            source_file=_truncate(selector.get("source_file"), 1024),
            artifact_type=_truncate(selector.get("artifact_type"), 120),
            timestamp=_parse_timestamp(selector.get("timestamp_utc")),
            host=_truncate(selector.get("source_host"), 255),
            username=_truncate(selector.get("username"), 255),
            artifact_path=_truncate(selector.get("artifact_path"), MAX_FIELD_CHARS),
            event_id=_truncate(selector.get("event_id"), 80),
            record_id=_truncate(selector.get("record_id"), 120),
            ioc_value=_truncate(selector.get("ioc_value"), MAX_FIELD_CHARS),
            row_uuid=_truncate(selector.get("row_uuid"), 120),
            summary=_truncate(_first_value(row, ("summary", "rule", "rule_title", "command_line", "process_name")), MAX_FIELD_CHARS),
            provenance=_truncate(row.get("emitted_provenance") or row.get("provenance"), 80),
            selector_json=_json_safe(selector),
            selector_hash=selector.get("selector_hash") or hash_selector(selector),
        )
        db.session.add(evidence)


def complete_step(
    step_or_id: HuntStep | int,
    *,
    result_payload: Optional[Dict[str, Any]] = None,
    coverage_status: Optional[str] = None,
    coverage_detail: Optional[Dict[str, Any]] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> Optional[HuntStep]:
    """Complete a step; partial evidence extraction never fails the step."""
    step = _get_step(step_or_id)
    if step is None:
        return None
    payload = result_payload if isinstance(result_payload, dict) else {"result": result_payload}
    extraction_warnings: List[str] = []
    evidence_refs: List[Dict[str, Any]] = []
    try:
        evidence_refs, extraction_warnings = extract_evidence_refs(
            case_id=step.hunt_run.case_id,
            tool_name=step.tool_name,
            result_payload=payload,
        )
    except Exception as exc:  # noqa: BLE001
        extraction_warnings.append(f"evidence extraction failed: {exc}")
        evidence_refs = []

    result_count = _result_count(payload, evidence_refs)
    result_summary = _summarize_result(payload, result_count)
    normalized_coverage = normalize_coverage_status(coverage_status or payload.get("coverage_status"))
    if extraction_warnings and normalized_coverage == HuntCoverageStatus.COMPLETE:
        normalized_coverage = HuntCoverageStatus.PARTIAL

    step.status = HuntStepStatus.COMPLETED
    step.completed_at = _utcnow()
    step.result_count = result_count
    step.result_summary = result_summary
    step.coverage_status = normalized_coverage
    step.coverage_detail_json = _json_safe(coverage_detail or payload.get("coverage_detail") or {})
    step.result_fingerprint = fingerprint_result(
        tool_name=step.tool_name,
        tool_params=step.tool_parameters_json or {},
        result_summary=result_summary,
        evidence_refs=evidence_refs,
    )
    step_metadata = dict(metadata or {})
    if extraction_warnings:
        step_metadata["extraction_warnings"] = extraction_warnings
    step.metadata_json = _json_safe(step_metadata)
    _store_evidence_refs(step, evidence_refs)
    step.hunt_run.updated_at = _utcnow()
    db.session.commit()
    return step


def fail_step(
    step_or_id: HuntStep | int,
    *,
    error_message: str,
    result_payload: Optional[Dict[str, Any]] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> Optional[HuntStep]:
    """Mark a traced step as failed."""
    step = _get_step(step_or_id)
    if step is None:
        return None
    payload = result_payload if isinstance(result_payload, dict) else {}
    step.status = HuntStepStatus.FAILED
    step.completed_at = _utcnow()
    step.error_message = str(error_message or "tool execution failed")
    step.result_count = 0
    step.result_summary = _truncate(payload.get("error") or error_message, MAX_SUMMARY_CHARS)
    step.coverage_status = HuntCoverageStatus.UNKNOWN
    step.metadata_json = _json_safe(metadata or {})
    step.result_fingerprint = fingerprint_result(
        tool_name=step.tool_name,
        tool_params=step.tool_parameters_json or {},
        result_summary=step.result_summary or "",
        evidence_refs=[],
    )
    step.hunt_run.updated_at = _utcnow()
    db.session.commit()
    return step


def skip_step(
    step_or_id: HuntStep | int,
    *,
    reason: str,
    metadata: Optional[Dict[str, Any]] = None,
) -> Optional[HuntStep]:
    """Mark a traced step as skipped without executing the tool."""
    step = _get_step(step_or_id)
    if step is None:
        return None
    step.status = HuntStepStatus.SKIPPED
    step.completed_at = _utcnow()
    step.error_message = str(reason or "tool skipped")
    step.result_count = 0
    step.result_summary = _truncate(reason, MAX_SUMMARY_CHARS)
    step.coverage_status = HuntCoverageStatus.NOT_AVAILABLE
    step.metadata_json = _json_safe(metadata or {})
    step.result_fingerprint = fingerprint_result(
        tool_name=step.tool_name,
        tool_params=step.tool_parameters_json or {},
        result_summary=step.result_summary or "",
        evidence_refs=[],
    )
    step.hunt_run.updated_at = _utcnow()
    db.session.commit()
    return step


def get_hunt_run_ledger(hunt_run_id: int) -> Optional[Dict[str, Any]]:
    run = HuntRun.query.get(int(hunt_run_id))
    return run.to_dict(include_children=True) if run else None
