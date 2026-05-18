"""Hunt ledger API routes."""
from __future__ import annotations

import logging

from flask import Blueprint, jsonify, request
from flask_login import current_user, login_required
from sqlalchemy import func

from models.case import Case
from models.database import db
from models.hunt import HuntRun, HuntStep
from utils import hunt_trace

logger = logging.getLogger(__name__)

hunt_bp = Blueprint("hunt", __name__, url_prefix="/api")


def _load_case_or_404(case_id: int):
    case = Case.get_by_id(case_id)
    if not case:
        return None, (jsonify({"success": False, "error": "Case not found"}), 404)
    return case, None


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
    run = HuntRun.query.get(hunt_run_id)
    if not run:
        return jsonify({"success": False, "error": "Hunt run not found"}), 404
    _, error = _load_case_or_404(run.case_id)
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
