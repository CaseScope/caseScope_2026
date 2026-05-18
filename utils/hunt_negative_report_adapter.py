"""Report-safe adapter for checklist-backed HuntNegativeFinding records."""
from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional

from models.hunt import (
    HuntChecklistCheck,
    HuntCoverageStatus,
    HuntCreatedByType,
    HuntNegativeFinding,
    HuntNegativeFindingState,
)


SECTION_TITLE = "Reviewed Artifacts With No Matching Evidence Identified"
BLOCKED_REPORT_LANGUAGE = (
    "host is clean",
    "network is clean",
    "no compromise",
    "no breach",
    "nothing found",
    "no malicious activity occurred",
    "no data was exfiltrated",
    "no lateral movement occurred",
)


def normalize_selected_finding_ids(selected_finding_ids: Optional[Iterable[Any]]) -> Optional[List[int]]:
    """Normalize an explicit per-report include selection."""
    if selected_finding_ids is None:
        return None
    normalized: List[int] = []
    for raw_id in selected_finding_ids:
        if raw_id in (None, ""):
            continue
        try:
            finding_id = int(raw_id)
        except (TypeError, ValueError):
            continue
        if finding_id not in normalized:
            normalized.append(finding_id)
    return normalized


def get_reportable_negative_findings_for_case(
    case_id: int,
    selected_finding_ids: Optional[Iterable[Any]] = None,
) -> List[HuntNegativeFinding]:
    """Return reportable negative findings, optionally limited to an explicit selection."""
    selected_ids = normalize_selected_finding_ids(selected_finding_ids)
    if selected_ids == []:
        return []

    candidates = (
        HuntNegativeFinding.query
        .filter_by(
            case_id=int(case_id),
            finding_state=HuntNegativeFindingState.ACCEPTED,
            created_by_type=HuntCreatedByType.ANALYST,
            superseded_by_finding_id=None,
        )
        .order_by(HuntNegativeFinding.accepted_at.asc(), HuntNegativeFinding.id.asc())
        .all()
    )
    reportable = [finding for finding in candidates if finding.is_reportable]

    if selected_ids is None:
        return reportable

    by_id = {int(finding.id): finding for finding in reportable if finding.id is not None}
    return [by_id[finding_id] for finding_id in selected_ids if finding_id in by_id]


def serialize_reportable_negative_finding(finding: HuntNegativeFinding) -> Dict[str, Any]:
    """Serialize a single finding for deterministic report consumption."""
    if not finding.is_reportable:
        raise ValueError("HuntNegativeFinding is not reportable")

    checklist_run = finding.checklist_run
    limitations = finding.limitations_json or checklist_run.limitations_json or []
    _validate_report_statement(finding.statement, finding.coverage_status, limitations)
    definition = checklist_run.definition_snapshot_json or {}
    checks = _list_checklist_checks(checklist_run)
    linked_steps = _linked_hunt_steps(checks)
    linked_evidence_refs = _linked_evidence_refs(checks)

    return {
        "negative_finding_id": finding.id,
        "finding_type": finding.finding_type,
        "checklist_definition_key": checklist_run.checklist_slug,
        "checklist_definition_name": definition.get("display_name") or checklist_run.checklist_slug,
        "checklist_run_id": checklist_run.id,
        "hunt_run_id": finding.hunt_run_id,
        "statement": finding.statement,
        "coverage_status": finding.coverage_status,
        "limitations": limitations,
        "missing_sources": finding.missing_sources_json or checklist_run.missing_sources_json or [],
        "reviewed_checks_summary": _reviewed_checks_summary(checks),
        "reviewed_sources_summary": _reviewed_sources_summary(checks),
        "target_scope": finding.decision_scope,
        "target_metadata": finding.target_metadata_json or checklist_run.target_metadata_json or {},
        "accepted_by": finding.reviewed_by or finding.created_by,
        "accepted_at": finding.accepted_at.isoformat() if finding.accepted_at else None,
        "source_finding_id": finding.source_finding_id,
        "supersession_status": "active",
        "linked_hunt_steps": linked_steps,
        "linked_evidence_refs": linked_evidence_refs,
        "audit_references": {
            "negative_finding_id": finding.id,
            "checklist_run_id": checklist_run.id,
            "hunt_run_id": finding.hunt_run_id,
            "language_template_key": finding.language_template_key,
            "evidence_fingerprint": finding.evidence_fingerprint,
        },
    }


def _validate_report_statement(statement: str, coverage_status: str, limitations: List[Any]) -> None:
    normalized = str(statement or "").strip().lower()
    if not normalized:
        raise ValueError("Negative finding statement is required")
    for blocked in BLOCKED_REPORT_LANGUAGE:
        if blocked in normalized:
            raise ValueError("Negative finding statement contains report-blocked language")
    if coverage_status == HuntCoverageStatus.PARTIAL and not limitations:
        raise ValueError("Partial coverage negative findings require visible limitations")


def build_negative_findings_report_section(
    case_id: int,
    selected_finding_ids: Optional[Iterable[Any]] = None,
) -> str:
    """Build deterministic report prose for an explicit finding selection."""
    findings = [
        serialize_reportable_negative_finding(finding)
        for finding in get_reportable_negative_findings_for_case(case_id, selected_finding_ids)
    ]
    if not findings:
        return ""

    blocks = [SECTION_TITLE]
    for item in findings:
        blocks.append(_render_finding_block(item))
    return "\n\n".join(blocks)


def build_negative_findings_report_context(
    case_id: int,
    selected_finding_ids: Optional[Iterable[Any]] = None,
) -> Dict[str, Any]:
    """Return template context for deterministic negative-finding report sections."""
    findings = [
        serialize_reportable_negative_finding(finding)
        for finding in get_reportable_negative_findings_for_case(case_id, selected_finding_ids)
    ]
    return {
        "negative_findings": findings,
        "negative_findings_section": _render_section(findings),
        "negative_findings_section_title": SECTION_TITLE,
        "negative_findings_included": len(findings),
    }


def _list_checklist_checks(checklist_run) -> List[HuntChecklistCheck]:
    checks = getattr(checklist_run, "checks", None)
    if checks is None:
        return []
    if hasattr(checks, "order_by"):
        return checks.order_by(HuntChecklistCheck.id.asc()).all()
    if isinstance(checks, list):
        return checks
    return list(checks)


def _linked_hunt_steps(checks: List[HuntChecklistCheck]) -> List[Dict[str, Any]]:
    steps: List[Dict[str, Any]] = []
    seen_ids = set()
    for check in checks:
        step = getattr(check, "hunt_step", None)
        if step is None or getattr(step, "id", None) in seen_ids:
            continue
        seen_ids.add(step.id)
        steps.append({
            "hunt_step_id": step.id,
            "check_key": check.check_key,
            "tool_name": step.tool_name,
            "result_count": step.result_count,
            "result_summary": step.result_summary,
            "coverage_status": step.coverage_status,
            "result_fingerprint": step.result_fingerprint,
        })
    return steps


def _linked_evidence_refs(checks: List[HuntChecklistCheck]) -> List[Dict[str, Any]]:
    refs: List[Dict[str, Any]] = []
    seen_keys = set()
    for check in checks:
        step = getattr(check, "hunt_step", None)
        evidence_refs = getattr(step, "evidence_refs", None) if step is not None else None
        if evidence_refs is None:
            continue
        if hasattr(evidence_refs, "all"):
            step_refs = evidence_refs.all()
        else:
            step_refs = list(evidence_refs)
        for ref in step_refs:
            payload = ref.to_dict() if hasattr(ref, "to_dict") else dict(ref)
            key = payload.get("selector_hash") or (payload.get("hunt_step_id"), payload.get("id"))
            if key in seen_keys:
                continue
            seen_keys.add(key)
            refs.append(payload)
    return refs


def _reviewed_checks_summary(checks: List[HuntChecklistCheck]) -> List[Dict[str, Any]]:
    return [
        {
            "check_key": check.check_key,
            "check_name": check.check_name,
            "check_status": check.check_status,
            "coverage_status": check.coverage_status,
            "source_availability_status": check.source_availability_status,
            "hunt_step_id": check.hunt_step_id,
            "result_count": check.result_count,
            "result_summary": check.result_summary,
            "not_applicable_reason": check.not_applicable_reason,
        }
        for check in checks
    ]


def _reviewed_sources_summary(checks: List[HuntChecklistCheck]) -> List[Dict[str, Any]]:
    sources: List[Dict[str, Any]] = []
    for check in checks:
        metadata = check.source_metadata_json or {}
        if metadata:
            sources.append({
                "check_key": check.check_key,
                "source_availability_status": check.source_availability_status,
                "source_metadata": metadata,
                "limitations": check.limitations_json or [],
            })
    return sources


def _render_section(findings: List[Dict[str, Any]]) -> str:
    if not findings:
        return ""
    blocks = [SECTION_TITLE]
    for item in findings:
        blocks.append(_render_finding_block(item))
    return "\n\n".join(blocks)


def _render_finding_block(item: Dict[str, Any]) -> str:
    lines = [
        item["statement"],
        f"Checklist: {item['checklist_definition_name']} (run {item['checklist_run_id']})",
        f"Coverage: {item['coverage_status']}",
    ]
    limitations = item.get("limitations") or []
    if limitations:
        lines.append("Limitations: " + "; ".join(str(value) for value in limitations))
    missing_sources = item.get("missing_sources") or []
    if missing_sources:
        lines.append("Missing or incomplete sources: " + "; ".join(str(value) for value in missing_sources))
    lines.append(f"Audit reference: HuntRun {item['hunt_run_id']}, NegativeFinding {item['negative_finding_id']}")
    return "\n".join(lines)
