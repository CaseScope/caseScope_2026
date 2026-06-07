"""Hunt ledger API routes."""
from __future__ import annotations

import logging
from datetime import datetime
from urllib.parse import urlparse

from flask import Blueprint, jsonify, request
from flask_login import current_user, login_required
from sqlalchemy import func

from models.case import Case
from models.case_work import CaseWorkActivityType
from models.database import db
from models.hunt import (
    HuntChecklistDefinition,
    HuntChecklistRun,
    HuntCreatedByType,
    HuntDecision,
    HuntDecisionState,
    HuntNegativeFinding,
    HuntNegativeFindingState,
    HuntRun,
    HuntStep,
)
from models.ioc import IOC
from utils import hunt_trace
from utils.case_work import safe_log_case_work_activity
from utils.chat_tools import lookup_ioc
from utils.forensic_chat_sources import search_network_logs_for_case

logger = logging.getLogger(__name__)

hunt_bp = Blueprint("hunt", __name__, url_prefix="/api")

NETWORK_IOC_TYPES = {
    "IP Address (IPv4)",
    "IP Address (IPv6)",
    "Hostname",
    "FQDN",
    "Domain",
    "URL",
    "User-Agent",
    "JA3 Hash",
    "JA3S Hash",
    "SSL Certificate Hash",
}


def _load_case_or_404(case_id: int):
    case = Case.get_by_id(case_id)
    if not case:
        return None, (jsonify({"success": False, "error": "Case not found"}), 404)
    return case, None


def _load_run_or_404(hunt_run_id: int):
    run = HuntRun.query.get(hunt_run_id)
    if not run:
        return None, (jsonify({"success": False, "error": "Hunt run not found"}), 404)
    _, error = _load_case_or_404(run.case_id)
    if error:
        return None, error
    return run, None


def _load_decision_or_404(decision_id: int):
    decision = HuntDecision.query.get(decision_id)
    if not decision:
        return None, (jsonify({"success": False, "error": "Hunt decision not found"}), 404)
    _, error = _load_case_or_404(decision.case_id)
    if error:
        return None, error
    return decision, None


def _load_checklist_run_or_404(checklist_run_id: int):
    checklist_run = HuntChecklistRun.query.get(checklist_run_id)
    if not checklist_run:
        return None, (jsonify({"success": False, "error": "Hunt checklist run not found"}), 404)
    _, error = _load_case_or_404(checklist_run.case_id)
    if error:
        return None, error
    return checklist_run, None


def _load_negative_finding_or_404(finding_id: int):
    finding = HuntNegativeFinding.query.get(finding_id)
    if not finding:
        return None, (jsonify({"success": False, "error": "Hunt negative finding not found"}), 404)
    _, error = _load_case_or_404(finding.case_id)
    if error:
        return None, error
    return finding, None


def _decision_payload(data):
    return {
        "hypothesis_id": data.get("hypothesis_id"),
        "classification": data.get("classification"),
        "decision_scope": data.get("decision_scope") or "case",
        "target_host": data.get("target_host"),
        "target_user": data.get("target_user"),
        "target_ioc": data.get("target_ioc"),
        "target_artifact_path": data.get("target_artifact_path"),
        "target_process": data.get("target_process"),
        "confidence": data.get("confidence"),
        "rationale": data.get("rationale"),
        "ai_rationale": data.get("ai_rationale"),
        "evidence_links": data.get("evidence_links") if isinstance(data.get("evidence_links"), list) else [],
        "metadata": data.get("metadata") if isinstance(data.get("metadata"), dict) else {},
    }


def _negative_finding_history_payload(findings, active_findings):
    active_ids = {finding.id for finding in active_findings}
    drafts = []
    rejected = []
    superseded = []
    other_history = []
    for finding in findings:
        if finding.id in active_ids:
            continue
        if finding.finding_state == HuntNegativeFindingState.DRAFT:
            drafts.append(finding)
        elif finding.finding_state == HuntNegativeFindingState.REJECTED:
            rejected.append(finding)
        elif finding.finding_state == HuntNegativeFindingState.SUPERSEDED:
            superseded.append(finding)
        else:
            other_history.append(finding)
    return {
        "active_findings": [finding.to_dict() for finding in active_findings],
        "draft_findings": [finding.to_dict() for finding in drafts],
        "rejected_findings": [finding.to_dict() for finding in rejected],
        "superseded_findings": [finding.to_dict() for finding in superseded],
        "other_history": [finding.to_dict() for finding in other_history],
    }


def _normalize_ioc_review_time(value):
    """Normalize browser datetime-local input into the DB/tool timestamp format."""
    raw = str(value or "").strip()
    if not raw:
        return None
    normalized = raw.replace("T", " ")
    if normalized.endswith("Z"):
        normalized = normalized[:-1].strip()
    if len(normalized) == 16:
        normalized = f"{normalized}:00"
    try:
        datetime.fromisoformat(normalized)
    except ValueError:
        return None
    return normalized


def _network_search_value(ioc: IOC) -> str:
    value = str(ioc.value or "").strip()
    if ioc.ioc_type == "URL":
        parsed = urlparse(value)
        return parsed.hostname or value
    return value


def _is_network_ioc(ioc: IOC) -> bool:
    return ioc.category == "Network" or ioc.ioc_type in NETWORK_IOC_TYPES


def _load_iocs_for_review(case_id: int, ioc_ids) -> list[IOC]:
    query = IOC.query.filter_by(case_id=case_id, hidden=False)
    if isinstance(ioc_ids, list) and ioc_ids:
        normalized_ids = []
        for raw_id in ioc_ids:
            try:
                normalized_ids.append(int(raw_id))
            except (TypeError, ValueError):
                continue
        if not normalized_ids:
            return []
        query = query.filter(IOC.id.in_(normalized_ids))
    return query.order_by(IOC.category.asc(), IOC.ioc_type.asc(), IOC.value.asc()).limit(100).all()


def _trace_tool_result(run: HuntRun, *, tool_name: str, tool_params: dict, result_payload: dict, created_by: str):
    step = hunt_trace.start_step(
        hunt_run_id=run.id,
        case_id=run.case_id,
        tool_name=tool_name,
        tool_params=tool_params,
        query_summary=tool_params.get("value") or tool_params.get("search"),
        created_by_type=HuntCreatedByType.ANALYST,
        created_by=created_by,
    )
    if result_payload.get("error"):
        return hunt_trace.fail_step(
            step,
            error_message=result_payload.get("error"),
            result_payload=result_payload,
            metadata={"ioc_review": True},
        )
    return hunt_trace.complete_step(
        step,
        result_payload=result_payload,
        coverage_status=result_payload.get("coverage_status") or "complete",
        coverage_detail=result_payload.get("coverage_detail"),
        metadata={"ioc_review": True},
    )


@hunt_bp.route("/hunt-runs", methods=["POST"])
@login_required
def create_hunt_run():
    """Create a hunt ledger run for a case objective."""
    data = request.get_json(silent=True) or {}
    case_id = data.get("case_id")
    objective = str(data.get("objective") or "").strip()
    if not case_id:
        return jsonify({"success": False, "error": "case_id required"}), 400
    if not objective:
        return jsonify({"success": False, "error": "objective required"}), 400

    try:
        case_id = int(case_id)
    except (TypeError, ValueError):
        return jsonify({"success": False, "error": "case_id must be an integer"}), 400

    _, error = _load_case_or_404(case_id)
    if error:
        return error

    try:
        run = hunt_trace.create_hunt_run(
            case_id=case_id,
            objective=objective,
            created_by=current_user.username,
            status=data.get("status") or "active",
            model_provider=data.get("model_provider"),
            model_name=data.get("model_name"),
            source_scope=data.get("source_scope") if isinstance(data.get("source_scope"), dict) else {},
            time_scope_start=data.get("time_scope_start"),
            time_scope_end=data.get("time_scope_end"),
        )
        return jsonify({"success": True, "hunt_run": run.to_dict()}), 201
    except Exception as exc:
        logger.exception("Failed to create hunt run: %s", exc)
        return jsonify({"success": False, "error": str(exc)}), 500


@hunt_bp.route("/hunt-runs", methods=["GET"])
@login_required
def list_hunt_runs():
    """List hunt runs for a case."""
    case_id = request.args.get("case_id", type=int)
    if not case_id:
        return jsonify({"success": False, "error": "case_id required"}), 400
    _, error = _load_case_or_404(case_id)
    if error:
        return error

    runs = HuntRun.query.filter_by(case_id=case_id).order_by(
        HuntRun.created_at.desc()
    ).limit(100).all()
    run_payloads = []
    for run in runs:
        payload = run.to_dict()
        payload["step_count"] = run.steps.count()
        latest_activity = db_latest_step_activity(run.id)
        payload["latest_activity"] = latest_activity.isoformat() if latest_activity else payload.get("updated_at")
        run_payloads.append(payload)
    return jsonify({
        "success": True,
        "hunt_runs": run_payloads,
    })


@hunt_bp.route("/hunt-runs/ioc-review", methods=["POST"])
@login_required
def create_ioc_hunt_review():
    """Run IOC-backed hunting checks and persist analyst-reviewable HuntSteps."""
    data = request.get_json(silent=True) or {}
    case_id = data.get("case_id")
    if not case_id:
        return jsonify({"success": False, "error": "case_id required"}), 400
    try:
        case_id = int(case_id)
    except (TypeError, ValueError):
        return jsonify({"success": False, "error": "case_id must be an integer"}), 400

    case, error = _load_case_or_404(case_id)
    if error:
        return error

    time_start = _normalize_ioc_review_time(data.get("time_start"))
    time_end = _normalize_ioc_review_time(data.get("time_end"))
    if not time_start or not time_end:
        return jsonify({
            "success": False,
            "error": "Explicit time_start and time_end are required for IOC-backed hunting review",
        }), 400

    iocs = _load_iocs_for_review(case_id, data.get("ioc_ids"))
    if not iocs:
        return jsonify({"success": False, "error": "No stored IOCs are available for this case"}), 400

    try:
        limit = int(data.get("limit") or 25)
    except (TypeError, ValueError):
        limit = 25
    limit = max(1, min(limit, 100))
    include_network = data.get("include_network") is not False

    try:
        run = hunt_trace.create_hunt_run(
            case_id=case_id,
            objective=f"IOC-backed hunting review ({len(iocs)} IOCs)",
            created_by=current_user.username,
            status="active",
            source_scope={
                "workflow": "ioc_backed_hunting_review",
                "ioc_count": len(iocs),
                "ioc_ids": [ioc.id for ioc in iocs],
            },
            time_scope_start=time_start,
            time_scope_end=time_end,
        )

        reviewed = []
        network_searches = 0
        lookup_matches = 0
        network_matches = 0
        errors = []

        for ioc in iocs:
            ioc_payload = {
                "id": ioc.id,
                "value": ioc.value,
                "ioc_type": ioc.ioc_type,
                "category": ioc.category,
            }
            try:
                lookup_payload = lookup_ioc(case_id=case_id, value=ioc.value)
            except Exception as exc:  # noqa: BLE001
                lookup_payload = {"error": str(exc), "ioc": ioc_payload}
            lookup_payload["ioc"] = ioc_payload
            lookup_payload["result_count"] = lookup_payload.get("event_matches", 0)
            lookup_step = _trace_tool_result(
                run,
                tool_name="lookup_ioc",
                tool_params={"value": ioc.value, "ioc_id": ioc.id},
                result_payload=lookup_payload,
                created_by=current_user.username,
            )
            lookup_count = int(lookup_payload.get("event_matches") or 0)
            lookup_matches += lookup_count

            network_result = None
            network_step = None
            if include_network and _is_network_ioc(ioc):
                network_searches += 1
                search_value = _network_search_value(ioc)
                network_params = {
                    "search": search_value,
                    "time_start": time_start,
                    "time_end": time_end,
                    "limit": limit,
                    "ioc_id": ioc.id,
                    "ioc_type": ioc.ioc_type,
                }
                try:
                    network_result = search_network_logs_for_case(
                        case_id=case_id,
                        search=search_value,
                        log_type="",
                        pcap_id=None,
                        src_ip="",
                        dst_ip="",
                        time_start=time_start,
                        time_end=time_end,
                        limit=limit,
                    )
                except Exception as exc:  # noqa: BLE001
                    network_result = {"error": str(exc), "network_query": network_params, "ioc": ioc_payload}
                network_result["ioc"] = ioc_payload
                network_step = _trace_tool_result(
                    run,
                    tool_name="search_network_logs",
                    tool_params=network_result.get("network_query") or network_params,
                    result_payload=network_result,
                    created_by=current_user.username,
                )
                network_matches += int(network_result.get("total") or network_result.get("result_count") or 0)

            if lookup_payload.get("error"):
                errors.append({"ioc": ioc.value, "tool": "lookup_ioc", "error": lookup_payload["error"]})
            if network_result and network_result.get("error"):
                errors.append({"ioc": ioc.value, "tool": "search_network_logs", "error": network_result["error"]})

            reviewed.append({
                "ioc_id": ioc.id,
                "value": ioc.value,
                "ioc_type": ioc.ioc_type,
                "category": ioc.category,
                "lookup_step_id": lookup_step.id if lookup_step else None,
                "lookup_matches": lookup_count,
                "network_step_id": network_step.id if network_step else None,
                "network_total": (network_result or {}).get("total") if network_result else None,
                "network_returned_count": (network_result or {}).get("returned_count") if network_result else None,
                "network_truncated": (network_result or {}).get("truncated") if network_result else None,
            })

        run.final_summary = (
            f"Reviewed {len(iocs)} stored IOCs from {time_start} to {time_end}; "
            f"lookup matches={lookup_matches}; network searches={network_searches}; "
            f"network matches={network_matches}; errors={len(errors)}."
        )
        run.status = "completed" if not errors else "completed_with_errors"
        db.session.commit()
        safe_log_case_work_activity(
            case.uuid,
            CaseWorkActivityType.IOC_ACTION,
            "Ran stored IOC hunting review",
            details={
                "hunt_run_id": run.id,
                "ioc_count": len(iocs),
                "time_start": time_start,
                "time_end": time_end,
                "lookup_matches": lookup_matches,
                "network_searches": network_searches,
                "network_matches": network_matches,
                "errors": errors,
            },
            user_id=current_user.id,
            username=current_user.username,
        )

        return jsonify({
            "success": True,
            "hunt_run": run.to_dict(),
            "summary": {
                "case_id": case.id,
                "case_uuid": case.uuid,
                "ioc_count": len(iocs),
                "time_start": time_start,
                "time_end": time_end,
                "lookup_matches": lookup_matches,
                "network_searches": network_searches,
                "network_matches": network_matches,
                "errors": errors,
            },
            "reviewed_iocs": reviewed,
        }), 201
    except Exception as exc:
        logger.exception("Failed to create IOC-backed hunt review: %s", exc)
        return jsonify({"success": False, "error": str(exc)}), 500


def db_latest_step_activity(hunt_run_id: int):
    """Return latest known step activity timestamp for a hunt run."""
    return db.session.query(
        func.max(func.coalesce(HuntStep.completed_at, HuntStep.started_at))
    ).filter_by(hunt_run_id=hunt_run_id).scalar()


@hunt_bp.route("/hunt-checklists", methods=["GET"])
@login_required
def list_hunt_checklists():
    """List active checklist definitions."""
    definitions = HuntChecklistDefinition.query.filter_by(is_active=True).order_by(
        HuntChecklistDefinition.slug.asc(),
        HuntChecklistDefinition.version.asc(),
    ).all()
    return jsonify({
        "success": True,
        "checklists": [definition.to_dict() for definition in definitions],
    })


@hunt_bp.route("/hunt-checklists/<string:slug>", methods=["GET"])
@login_required
def get_hunt_checklist(slug: str):
    """Read one active checklist definition."""
    definition = HuntChecklistDefinition.query.filter_by(
        slug=slug,
        is_active=True,
    ).order_by(HuntChecklistDefinition.version.desc()).first()
    if not definition:
        return jsonify({"success": False, "error": "Hunt checklist definition not found"}), 404
    return jsonify({
        "success": True,
        "checklist": definition.to_dict(),
    })


@hunt_bp.route("/hunt-runs/<int:hunt_run_id>", methods=["GET"])
@login_required
def get_hunt_run(hunt_run_id: int):
    """Read back a hunt run ledger with hypotheses, steps, and evidence refs."""
    run, error = _load_run_or_404(hunt_run_id)
    if error:
        return error
    return jsonify({
        "success": True,
        "hunt_run": run.to_dict(include_children=True),
    })


@hunt_bp.route("/hunt-runs/<int:hunt_run_id>/checklists", methods=["POST"])
@login_required
def create_hunt_checklist_run(hunt_run_id: int):
    """Create a checklist run inside a hunt run."""
    run, error = _load_run_or_404(hunt_run_id)
    if error:
        return error
    data = request.get_json(silent=True) or {}
    checklist_slug = str(data.get("checklist_slug") or "").strip()
    if not checklist_slug:
        return jsonify({"success": False, "error": "checklist_slug required"}), 400

    try:
        checklist_run = hunt_trace.create_checklist_run(
            hunt_run_id=run.id,
            checklist_slug=checklist_slug,
            checklist_version=data.get("checklist_version") or "1.0",
            decision_scope=data.get("decision_scope") or "case",
            target_metadata=data.get("target_metadata") if isinstance(data.get("target_metadata"), dict) else {},
            created_by_type=HuntCreatedByType.ANALYST,
            created_by=current_user.username,
            metadata=data.get("metadata") if isinstance(data.get("metadata"), dict) else {},
        )
        return jsonify({"success": True, "checklist_run": checklist_run.to_dict(include_children=True)}), 201
    except ValueError as exc:
        return jsonify({"success": False, "error": str(exc)}), 400
    except Exception as exc:
        logger.exception("Failed to create hunt checklist run: %s", exc)
        return jsonify({"success": False, "error": str(exc)}), 500


@hunt_bp.route("/hunt-runs/<int:hunt_run_id>/checklists", methods=["GET"])
@login_required
def list_hunt_checklist_runs(hunt_run_id: int):
    """List checklist runs for a hunt run."""
    run, error = _load_run_or_404(hunt_run_id)
    if error:
        return error
    checklist_runs = hunt_trace.list_checklist_runs(hunt_run_id=run.id)
    return jsonify({
        "success": True,
        "checklist_runs": [item.to_dict(include_children=True) for item in checklist_runs],
    })


@hunt_bp.route("/hunt-checklist-runs/<int:checklist_run_id>", methods=["GET"])
@login_required
def get_hunt_checklist_run(checklist_run_id: int):
    """Read one checklist run with checks and finding history."""
    checklist_run, error = _load_checklist_run_or_404(checklist_run_id)
    if error:
        return error
    return jsonify({
        "success": True,
        "checklist_run": checklist_run.to_dict(include_children=True),
    })


@hunt_bp.route("/hunt-checklist-runs/<int:checklist_run_id>/checks/<string:check_key>/attach-step", methods=["POST"])
@login_required
def attach_hunt_check_step(checklist_run_id: int, check_key: str):
    """Attach a traced HuntStep to a checklist check."""
    _, error = _load_checklist_run_or_404(checklist_run_id)
    if error:
        return error
    data = request.get_json(silent=True) or {}
    if not data.get("hunt_step_id"):
        return jsonify({"success": False, "error": "hunt_step_id required"}), 400

    try:
        check = hunt_trace.attach_step_to_check(
            checklist_run_id=checklist_run_id,
            check_key=check_key,
            hunt_step_id=data.get("hunt_step_id"),
            result_summary=data.get("result_summary"),
            metadata=data.get("metadata") if isinstance(data.get("metadata"), dict) else {},
        )
        return jsonify({"success": True, "check": check.to_dict()})
    except ValueError as exc:
        return jsonify({"success": False, "error": str(exc)}), 400
    except Exception as exc:
        logger.exception("Failed to attach hunt checklist step: %s", exc)
        return jsonify({"success": False, "error": str(exc)}), 500


@hunt_bp.route("/hunt-checklist-runs/<int:checklist_run_id>/checks/<string:check_key>/source-metadata", methods=["POST"])
@login_required
def record_hunt_check_source_metadata(checklist_run_id: int, check_key: str):
    """Record source-driven metadata for a checklist check."""
    _, error = _load_checklist_run_or_404(checklist_run_id)
    if error:
        return error
    data = request.get_json(silent=True) or {}
    source_metadata = data.get("source_metadata") if isinstance(data.get("source_metadata"), dict) else None
    if not source_metadata:
        return jsonify({"success": False, "error": "source_metadata required"}), 400

    try:
        check = hunt_trace.record_check_source_metadata(
            checklist_run_id=checklist_run_id,
            check_key=check_key,
            source_metadata=source_metadata,
            source_availability_status=data.get("source_availability_status") or "available",
            limitations=data.get("limitations") if isinstance(data.get("limitations"), list) else None,
            result_summary=data.get("result_summary"),
        )
        return jsonify({"success": True, "check": check.to_dict()})
    except ValueError as exc:
        return jsonify({"success": False, "error": str(exc)}), 400
    except Exception as exc:
        logger.exception("Failed to record hunt checklist source metadata: %s", exc)
        return jsonify({"success": False, "error": str(exc)}), 500


@hunt_bp.route("/hunt-checklist-runs/<int:checklist_run_id>/checks/<string:check_key>/not-applicable", methods=["POST"])
@login_required
def mark_hunt_check_not_applicable(checklist_run_id: int, check_key: str):
    """Mark a checklist check not applicable."""
    _, error = _load_checklist_run_or_404(checklist_run_id)
    if error:
        return error
    data = request.get_json(silent=True) or {}
    reason = str(data.get("reason") or data.get("not_applicable_reason") or "").strip()
    if not reason:
        return jsonify({"success": False, "error": "reason required"}), 400

    try:
        check = hunt_trace.mark_check_not_applicable(
            checklist_run_id=checklist_run_id,
            check_key=check_key,
            reason=reason,
            metadata=data.get("metadata") if isinstance(data.get("metadata"), dict) else {},
        )
        return jsonify({"success": True, "check": check.to_dict()})
    except ValueError as exc:
        return jsonify({"success": False, "error": str(exc)}), 400
    except Exception as exc:
        logger.exception("Failed to mark hunt checklist check not applicable: %s", exc)
        return jsonify({"success": False, "error": str(exc)}), 500


@hunt_bp.route("/hunt-checklist-runs/<int:checklist_run_id>/complete", methods=["POST"])
@login_required
def complete_hunt_checklist_run(checklist_run_id: int):
    """Complete a checklist run and recalculate finding eligibility."""
    checklist_run, error = _load_checklist_run_or_404(checklist_run_id)
    if error:
        return error
    data = request.get_json(silent=True) or {}

    try:
        completed = hunt_trace.complete_checklist_run(
            checklist_run,
            coverage_status=data.get("coverage_status"),
            missing_sources=data.get("missing_sources") if isinstance(data.get("missing_sources"), list) else None,
            limitations=data.get("limitations") if isinstance(data.get("limitations"), list) else None,
        )
        return jsonify({"success": True, "checklist_run": completed.to_dict(include_children=True)})
    except ValueError as exc:
        return jsonify({"success": False, "error": str(exc)}), 400
    except Exception as exc:
        logger.exception("Failed to complete hunt checklist run: %s", exc)
        return jsonify({"success": False, "error": str(exc)}), 500


@hunt_bp.route("/hunt-runs/<int:hunt_run_id>/hypotheses", methods=["POST"])
@login_required
def add_hunt_hypothesis(hunt_run_id: int):
    """Append a hypothesis to an existing hunt run."""
    run = HuntRun.query.get(hunt_run_id)
    if not run:
        return jsonify({"success": False, "error": "Hunt run not found"}), 404
    _, error = _load_case_or_404(run.case_id)
    if error:
        return error

    data = request.get_json(silent=True) or {}
    hypothesis_text = str(data.get("hypothesis") or "").strip()
    if not hypothesis_text:
        return jsonify({"success": False, "error": "hypothesis required"}), 400

    try:
        hypothesis = hunt_trace.add_hypothesis(
            hunt_run_id=hunt_run_id,
            hypothesis=hypothesis_text,
            status=data.get("status") or "open",
            confidence=data.get("confidence"),
            rationale=data.get("rationale"),
        )
        return jsonify({"success": True, "hypothesis": hypothesis.to_dict()}), 201
    except Exception as exc:
        logger.exception("Failed to add hunt hypothesis: %s", exc)
        return jsonify({"success": False, "error": str(exc)}), 500


@hunt_bp.route("/hunt-runs/<int:hunt_run_id>/decisions", methods=["GET"])
@login_required
def list_hunt_decisions(hunt_run_id: int):
    """List active and historical decisions for a hunt run."""
    run, error = _load_run_or_404(hunt_run_id)
    if error:
        return error

    decisions = run.decisions.order_by(HuntDecision.created_at.asc(), HuntDecision.id.asc()).all()
    target_filters = {
        "target_host": request.args.get("target_host"),
        "target_user": request.args.get("target_user"),
        "target_ioc": request.args.get("target_ioc"),
        "target_artifact_path": request.args.get("target_artifact_path"),
        "target_process": request.args.get("target_process"),
    }
    active_decisions = hunt_trace.active_authoritative_decisions(
        hunt_run_id=run.id,
        case_id=run.case_id,
        decision_scope=request.args.get("decision_scope"),
        target_filters=target_filters,
    )
    return jsonify({
        "success": True,
        "decisions": [decision.to_dict(include_evidence=True) for decision in decisions],
        "active_decisions": [decision.to_dict(include_evidence=True) for decision in active_decisions],
        "active_rule": {
            "decision_state": HuntDecisionState.ACCEPTED,
            "created_by_type": HuntCreatedByType.ANALYST,
            "superseded_by_decision_id": None,
        },
    })


@hunt_bp.route("/hunt-checklist-runs/<int:checklist_run_id>/negative-findings/drafts", methods=["POST"])
@login_required
def create_hunt_negative_finding_draft(checklist_run_id: int):
    """Create a non-reportable negative finding draft from a checklist run."""
    _, error = _load_checklist_run_or_404(checklist_run_id)
    if error:
        return error
    data = request.get_json(silent=True) or {}
    if not data.get("finding_type"):
        return jsonify({"success": False, "error": "finding_type required"}), 400
    if not str(data.get("statement") or "").strip():
        return jsonify({"success": False, "error": "statement required"}), 400

    try:
        finding = hunt_trace.create_negative_finding_draft(
            checklist_run_id=checklist_run_id,
            finding_type=data.get("finding_type"),
            statement=data.get("statement"),
            created_by_type=data.get("created_by_type") or HuntCreatedByType.AI,
            created_by=data.get("created_by") or current_user.username,
            confidence=data.get("confidence"),
            metadata=data.get("metadata") if isinstance(data.get("metadata"), dict) else {},
        )
        return jsonify({"success": True, "negative_finding": finding.to_dict()}), 201
    except ValueError as exc:
        return jsonify({"success": False, "error": str(exc)}), 400
    except Exception as exc:
        logger.exception("Failed to create hunt negative finding draft: %s", exc)
        return jsonify({"success": False, "error": str(exc)}), 500


@hunt_bp.route("/hunt-negative-findings/<int:finding_id>/accept", methods=["POST"])
@login_required
def accept_hunt_negative_finding(finding_id: int):
    """Accept a negative finding draft as an analyst-owned accepted finding."""
    finding, error = _load_negative_finding_or_404(finding_id)
    if error:
        return error
    data = request.get_json(silent=True) or {}

    try:
        accepted = hunt_trace.accept_negative_finding(
            finding,
            reviewed_by=current_user.username,
            review_note=data.get("review_note"),
        )
        return jsonify({"success": True, "negative_finding": accepted.to_dict()}), 201
    except ValueError as exc:
        return jsonify({"success": False, "error": str(exc)}), 400
    except Exception as exc:
        logger.exception("Failed to accept hunt negative finding: %s", exc)
        return jsonify({"success": False, "error": str(exc)}), 500


@hunt_bp.route("/hunt-negative-findings/<int:finding_id>/reject", methods=["POST"])
@login_required
def reject_hunt_negative_finding(finding_id: int):
    """Reject a negative finding draft."""
    finding, error = _load_negative_finding_or_404(finding_id)
    if error:
        return error
    data = request.get_json(silent=True) or {}

    try:
        rejected = hunt_trace.reject_negative_finding(
            finding,
            reviewed_by=current_user.username,
            review_note=data.get("review_note"),
        )
        return jsonify({"success": True, "negative_finding": rejected.to_dict()})
    except ValueError as exc:
        return jsonify({"success": False, "error": str(exc)}), 400
    except Exception as exc:
        logger.exception("Failed to reject hunt negative finding: %s", exc)
        return jsonify({"success": False, "error": str(exc)}), 500


@hunt_bp.route("/hunt-negative-findings/<int:finding_id>/supersede", methods=["POST"])
@login_required
def supersede_hunt_negative_finding(finding_id: int):
    """Supersede an active negative finding with a replacement."""
    finding, error = _load_negative_finding_or_404(finding_id)
    if error:
        return error
    data = request.get_json(silent=True) or {}
    if not str(data.get("statement") or "").strip():
        return jsonify({"success": False, "error": "statement required"}), 400

    try:
        replacement = hunt_trace.supersede_negative_finding(
            finding,
            created_by=current_user.username,
            statement=data.get("statement"),
            review_note=data.get("review_note"),
            confidence=data.get("confidence"),
            metadata=data.get("metadata") if isinstance(data.get("metadata"), dict) else {},
        )
        return jsonify({"success": True, "negative_finding": replacement.to_dict()}), 201
    except ValueError as exc:
        return jsonify({"success": False, "error": str(exc)}), 400
    except Exception as exc:
        logger.exception("Failed to supersede hunt negative finding: %s", exc)
        return jsonify({"success": False, "error": str(exc)}), 500


@hunt_bp.route("/hunt-runs/<int:hunt_run_id>/negative-findings", methods=["GET"])
@login_required
def list_hunt_negative_findings(hunt_run_id: int):
    """List active and historical negative findings for a hunt run."""
    run, error = _load_run_or_404(hunt_run_id)
    if error:
        return error
    findings = run.negative_findings.order_by(
        HuntNegativeFinding.created_at.asc(),
        HuntNegativeFinding.id.asc(),
    ).all()
    active_findings = hunt_trace.get_active_negative_findings(
        hunt_run_id=run.id,
        case_id=run.case_id,
        finding_type=request.args.get("finding_type"),
        decision_scope=request.args.get("decision_scope"),
    )
    payload = _negative_finding_history_payload(findings, active_findings)
    payload["success"] = True
    payload["active_rule"] = {
        "finding_state": HuntNegativeFindingState.ACCEPTED,
        "created_by_type": HuntCreatedByType.ANALYST,
        "superseded_by_finding_id": None,
        "checklist_run_status": "completed",
        "finding_eligible": True,
    }
    return jsonify(payload)


@hunt_bp.route("/hunt-runs/<int:hunt_run_id>/decisions/drafts", methods=["POST"])
@login_required
def create_hunt_decision_draft(hunt_run_id: int):
    """Create a non-authoritative AI or system decision draft."""
    run, error = _load_run_or_404(hunt_run_id)
    if error:
        return error
    data = request.get_json(silent=True) or {}

    try:
        decision = hunt_trace.create_decision(
            hunt_run_id=run.id,
            decision_state=HuntDecisionState.DRAFT,
            created_by_type=data.get("created_by_type") or HuntCreatedByType.AI,
            created_by=data.get("created_by") or current_user.username,
            **_decision_payload(data),
        )
        return jsonify({"success": True, "decision": decision.to_dict(include_evidence=True)}), 201
    except ValueError as exc:
        return jsonify({"success": False, "error": str(exc)}), 400
    except Exception as exc:
        logger.exception("Failed to create hunt decision draft: %s", exc)
        return jsonify({"success": False, "error": str(exc)}), 500


@hunt_bp.route("/hunt-runs/<int:hunt_run_id>/decisions", methods=["POST"])
@login_required
def create_hunt_decision(hunt_run_id: int):
    """Create an analyst-authored accepted decision."""
    run, error = _load_run_or_404(hunt_run_id)
    if error:
        return error
    data = request.get_json(silent=True) or {}

    try:
        decision = hunt_trace.create_decision(
            hunt_run_id=run.id,
            decision_state=HuntDecisionState.ACCEPTED,
            created_by_type=HuntCreatedByType.ANALYST,
            created_by=current_user.username,
            source_decision_id=data.get("source_decision_id"),
            supersedes_decision_id=data.get("supersedes_decision_id"),
            reviewed_by=current_user.username,
            review_note=data.get("review_note"),
            **_decision_payload(data),
        )
        return jsonify({"success": True, "decision": decision.to_dict(include_evidence=True)}), 201
    except ValueError as exc:
        return jsonify({"success": False, "error": str(exc)}), 400
    except Exception as exc:
        logger.exception("Failed to create hunt decision: %s", exc)
        return jsonify({"success": False, "error": str(exc)}), 500


@hunt_bp.route("/hunt-decisions/<int:decision_id>/accept", methods=["POST"])
@login_required
def accept_hunt_decision(decision_id: int):
    """Accept an AI draft by creating a new analyst-authored decision."""
    decision, error = _load_decision_or_404(decision_id)
    if error:
        return error
    data = request.get_json(silent=True) or {}

    try:
        accepted = hunt_trace.accept_decision(
            decision,
            reviewed_by=current_user.username,
            classification=data.get("classification"),
            rationale=data.get("rationale"),
            confidence=data.get("confidence"),
            evidence_links=data.get("evidence_links") if isinstance(data.get("evidence_links"), list) else None,
            review_note=data.get("review_note"),
            metadata=data.get("metadata") if isinstance(data.get("metadata"), dict) else {},
        )
        return jsonify({"success": True, "decision": accepted.to_dict(include_evidence=True)}), 201
    except ValueError as exc:
        return jsonify({"success": False, "error": str(exc)}), 400
    except Exception as exc:
        logger.exception("Failed to accept hunt decision: %s", exc)
        return jsonify({"success": False, "error": str(exc)}), 500


@hunt_bp.route("/hunt-decisions/<int:decision_id>/reject", methods=["POST"])
@login_required
def reject_hunt_decision(decision_id: int):
    """Reject an AI draft decision."""
    decision, error = _load_decision_or_404(decision_id)
    if error:
        return error
    data = request.get_json(silent=True) or {}

    try:
        rejected = hunt_trace.reject_decision(
            decision,
            reviewed_by=current_user.username,
            review_note=data.get("review_note"),
        )
        return jsonify({"success": True, "decision": rejected.to_dict(include_evidence=True)})
    except ValueError as exc:
        return jsonify({"success": False, "error": str(exc)}), 400
    except Exception as exc:
        logger.exception("Failed to reject hunt decision: %s", exc)
        return jsonify({"success": False, "error": str(exc)}), 500


@hunt_bp.route("/hunt-decisions/<int:decision_id>/supersede", methods=["POST"])
@login_required
def supersede_hunt_decision(decision_id: int):
    """Create a replacement analyst decision and preserve the prior record."""
    decision, error = _load_decision_or_404(decision_id)
    if error:
        return error
    data = request.get_json(silent=True) or {}

    try:
        replacement = hunt_trace.supersede_decision(
            decision,
            created_by=current_user.username,
            classification=data.get("classification"),
            rationale=data.get("rationale"),
            confidence=data.get("confidence"),
            evidence_links=data.get("evidence_links") if isinstance(data.get("evidence_links"), list) else [],
            review_note=data.get("review_note"),
            metadata=data.get("metadata") if isinstance(data.get("metadata"), dict) else {},
        )
        return jsonify({"success": True, "decision": replacement.to_dict(include_evidence=True)}), 201
    except ValueError as exc:
        return jsonify({"success": False, "error": str(exc)}), 400
    except Exception as exc:
        logger.exception("Failed to supersede hunt decision: %s", exc)
        return jsonify({"success": False, "error": str(exc)}), 500
