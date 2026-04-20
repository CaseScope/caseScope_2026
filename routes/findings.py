"""Canonical findings API routes."""

from flask import Blueprint, jsonify, request
from flask_login import login_required

from models.case import Case

findings_bp = Blueprint("findings", __name__, url_prefix="/api")


def _build_unified_findings_payload(case_id: int):
    """Build the canonical unified findings payload for a case."""
    from utils.unified_findings import get_unified_findings

    severity = request.args.get("severity")
    category = request.args.get("category")
    min_confidence = request.args.get("min_confidence", 0, type=int)
    limit = request.args.get("limit", 200, type=int)

    result = get_unified_findings(
        case_id=case_id,
        min_confidence=min_confidence,
        severity=severity,
        category=category,
        limit=limit,
    )
    return {"success": True, **result}


@findings_bp.route("/findings/list/<case_uuid>", methods=["GET"])
@login_required
def get_case_findings(case_uuid):
    """Return unified findings for one case through the canonical findings surface."""
    case = Case.get_by_uuid(case_uuid)
    if not case:
        return jsonify({"success": False, "error": "Case not found"}), 404

    return jsonify(_build_unified_findings_payload(case.id))
