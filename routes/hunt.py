"""Hunt ledger API routes."""
from __future__ import annotations

import logging

from flask import Blueprint, jsonify, request
from flask_login import current_user, login_required
from sqlalchemy import func

from models.case import Case
from models.database import db
from models.hunt import HuntCreatedByType, HuntDecision, HuntDecisionState, HuntRun, HuntStep
from utils import hunt_trace

logger = logging.getLogger(__name__)

hunt_bp = Blueprint("hunt", __name__, url_prefix="/api")


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


def db_latest_step_activity(hunt_run_id: int):
    """Return latest known step activity timestamp for a hunt run."""
    return db.session.query(
        func.max(func.coalesce(HuntStep.completed_at, HuntStep.started_at))
    ).filter_by(hunt_run_id=hunt_run_id).scalar()


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
