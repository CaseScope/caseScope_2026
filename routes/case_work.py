"""Case work time tracking API routes."""

from flask import Blueprint, jsonify, request
from flask_login import current_user, login_required

from models.case import Case
from models.case_work import CaseWorkSession
from routes.route_helpers import _require_case_write_access
from utils.case_work import begin_work_session, end_work_session, get_active_work_session


case_work_bp = Blueprint("case_work", __name__, url_prefix="/api/case-work")


def _load_case(case_uuid):
    case = Case.get_by_uuid(case_uuid)
    if not case:
        return None, (jsonify({"success": False, "error": "Case not found"}), 404)
    return case, None


@case_work_bp.route("/active/<case_uuid>")
@login_required
def active_case_work_session(case_uuid):
    """Return the current user's active work session state."""
    case, error = _load_case(case_uuid)
    if error:
        return error

    active_session = get_active_work_session(current_user.id)
    if not active_session:
        return jsonify({"success": True, "case_uuid": case.uuid, "active_session": None, "active_other_case": None})

    if active_session.case_uuid == case.uuid:
        return jsonify(
            {
                "success": True,
                "case_uuid": case.uuid,
                "active_session": active_session.to_summary_dict(),
                "active_other_case": None,
            }
        )

    return jsonify(
        {
            "success": True,
            "case_uuid": case.uuid,
            "active_session": None,
            "active_other_case": active_session.to_summary_dict(),
        }
    )


@case_work_bp.route("/begin/<case_uuid>", methods=["POST"])
@login_required
def begin_case_work(case_uuid):
    """Begin a case work session for the current analyst."""
    viewer_error = _require_case_write_access(current_user, "Viewers cannot start case work sessions")
    if viewer_error:
        return viewer_error

    case, error = _load_case(case_uuid)
    if error:
        return error

    payload = request.get_json(silent=True) or {}
    try:
        session, created = begin_work_session(case, current_user, start_note=payload.get("note"))
    except ValueError as exc:
        return jsonify({"success": False, "error": str(exc)}), 409

    return jsonify({"success": True, "created": created, "session": session.to_summary_dict()})


@case_work_bp.route("/end/<case_uuid>", methods=["POST"])
@login_required
def end_case_work(case_uuid):
    """End the current analyst's active work session for this case."""
    viewer_error = _require_case_write_access(current_user, "Viewers cannot end case work sessions")
    if viewer_error:
        return viewer_error

    case, error = _load_case(case_uuid)
    if error:
        return error

    payload = request.get_json(silent=True) or {}
    try:
        session = end_work_session(current_user, case_uuid=case.uuid, end_note=payload.get("note"))
    except ValueError as exc:
        return jsonify({"success": False, "error": str(exc)}), 409

    if not session:
        return jsonify({"success": False, "error": "No active work session found"}), 404

    return jsonify({"success": True, "session": session.to_summary_dict()})


@case_work_bp.route("/sessions/<case_uuid>")
@login_required
def list_case_work_sessions(case_uuid):
    """List work sessions for a case."""
    case, error = _load_case(case_uuid)
    if error:
        return error

    limit = max(1, min(request.args.get("limit", 100, type=int), 500))
    sessions = (
        CaseWorkSession.query.filter_by(case_uuid=case.uuid)
        .order_by(CaseWorkSession.started_at.desc())
        .limit(limit)
        .all()
    )

    return jsonify({"success": True, "case_uuid": case.uuid, "sessions": [session.to_summary_dict() for session in sessions]})


@case_work_bp.route("/session/<session_uuid>")
@login_required
def get_case_work_session(session_uuid):
    """Return a work session and its detailed activity entries."""
    session = CaseWorkSession.query.filter_by(uuid=session_uuid).first()
    if not session:
        return jsonify({"success": False, "error": "Work session not found"}), 404

    case = Case.get_by_uuid(session.case_uuid)
    if not case:
        return jsonify({"success": False, "error": "Case not found"}), 404

    return jsonify({"success": True, "session": session.to_detail_dict()})
