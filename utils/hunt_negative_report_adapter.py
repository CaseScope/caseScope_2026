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
AUDIT_APPENDIX_TITLE = "Negative Finding Audit Appendix"
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
        "negative_findings_audit_appendix": _render_audit_appendix(findings),
        "negative_findings_audit_appendix_title": AUDIT_APPENDIX_TITLE,
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


def _render_audit_appendix(findings: List[Dict[str, Any]]) -> str:
    if not findings:
        return ""
    blocks = [AUDIT_APPENDIX_TITLE]
    for item in findings:
        blocks.append(_render_audit_appendix_block(item))
    return "\n\n".join(blocks)


def _render_audit_appendix_block(item: Dict[str, Any]) -> str:
    lines = [
        f"Negative Finding {item['negative_finding_id']}",
        f"Statement: {item['statement']}",
        f"Checklist: {item['checklist_definition_name']} ({item['checklist_definition_key']})",
        f"Checklist Run ID: {item['checklist_run_id']}",
        f"HuntRun ID: {item['hunt_run_id']}",
        f"Coverage Status: {item['coverage_status']}",
        f"Target Scope: {item['target_scope']}",
        f"Accepted By: {item['accepted_by']}",
        f"Accepted At: {item['accepted_at'] or 'not recorded'}",
        f"Source Finding ID: {item['source_finding_id'] or 'none'}",
        f"Supersession Status: {item['supersession_status']}",
    ]
    _append_list(lines, "Limitations", item.get("limitations"))
    _append_list(lines, "Missing Sources", item.get("missing_sources"))
    _append_mapping(lines, "Target Metadata", item.get("target_metadata"))
    _append_check_summaries(lines, item.get("reviewed_checks_summary") or [])
    _append_source_summaries(lines, item.get("reviewed_sources_summary") or [])
    _append_step_summaries(lines, item.get("linked_hunt_steps") or [])
    _append_evidence_summaries(lines, item.get("linked_evidence_refs") or [])
    _append_mapping(lines, "Audit References", item.get("audit_references"))
    return "\n".join(lines)


def _append_list(lines: List[str], label: str, values: Any) -> None:
    items = values if isinstance(values, list) else []
    if not items:
        lines.append(f"{label}: none documented")
        return
    lines.append(f"{label}:")
    for value in items:
        lines.append(f"- {value}")


def _append_mapping(lines: List[str], label: str, mapping: Any) -> None:
    data = mapping if isinstance(mapping, dict) else {}
    if not data:
        lines.append(f"{label}: none documented")
        return
    lines.append(f"{label}:")
    for key in sorted(data):
        lines.append(f"- {key}: {data[key]}")


def _append_check_summaries(lines: List[str], checks: List[Dict[str, Any]]) -> None:
    if not checks:
        lines.append("Reviewed Checks: none linked")
        return
    lines.append("Reviewed Checks:")
    for check in checks:
        lines.append(
            "- "
            f"{check.get('check_name') or check.get('check_key')} "
            f"(key={check.get('check_key')}, status={check.get('check_status')}, "
            f"coverage={check.get('coverage_status')}, source_availability={check.get('source_availability_status')}, "
            f"hunt_step_id={check.get('hunt_step_id') or 'none'}, result_count={check.get('result_count')})"
        )
        if check.get("result_summary"):
            lines.append(f"  Result Summary: {check['result_summary']}")
        if check.get("not_applicable_reason"):
            lines.append(f"  Not Applicable Reason: {check['not_applicable_reason']}")


def _append_source_summaries(lines: List[str], sources: List[Dict[str, Any]]) -> None:
    if not sources:
        lines.append("Reviewed Source Metadata: none documented")
        return
    lines.append("Reviewed Source Metadata:")
    for source in sources:
        lines.append(
            "- "
            f"{source.get('check_key')} "
            f"(availability={source.get('source_availability_status')})"
        )
        metadata = source.get("source_metadata") if isinstance(source.get("source_metadata"), dict) else {}
        for key in sorted(metadata):
            lines.append(f"  {key}: {metadata[key]}")
        for limitation in source.get("limitations") or []:
            lines.append(f"  Limitation: {limitation}")


def _append_step_summaries(lines: List[str], steps: List[Dict[str, Any]]) -> None:
    if not steps:
        lines.append("Linked HuntSteps: none linked")
        return
    lines.append("Linked HuntSteps:")
    for step in steps:
        lines.append(
            "- "
            f"HuntStep {step.get('hunt_step_id')} "
            f"(check={step.get('check_key')}, tool={step.get('tool_name')}, coverage={step.get('coverage_status')}, "
            f"result_count={step.get('result_count')}, fingerprint={step.get('result_fingerprint') or 'none'})"
        )
        if step.get("result_summary"):
            lines.append(f"  Result Summary: {step['result_summary']}")


def _append_evidence_summaries(lines: List[str], refs: List[Dict[str, Any]]) -> None:
    if not refs:
        lines.append("Evidence References: none extracted")
        return
    lines.append("Evidence References:")
    for ref in refs:
        lines.append(
            "- "
            f"EvidenceRef {ref.get('id') or 'unknown'} "
            f"(hunt_step_id={ref.get('hunt_step_id')}, selector_hash={ref.get('selector_hash')}, "
            f"source_table={ref.get('source_table') or 'none'}, source_id={ref.get('source_id') or 'none'}, "
            f"artifact_type={ref.get('artifact_type') or 'none'})"
        )
        if ref.get("summary"):
            lines.append(f"  Summary: {ref['summary']}")
        selector = ref.get("selector_json") if isinstance(ref.get("selector_json"), dict) else {}
        if selector:
            lines.append("  Selector:")
            for key in sorted(selector):
                lines.append(f"  - {key}: {selector[key]}")
