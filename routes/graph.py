"""Read-only Phase 0C investigation graph API routes."""
from __future__ import annotations

import logging

from flask import Blueprint, jsonify, request
from flask_login import login_required

from models.case import Case
from utils.graph_query import GraphNotFoundError, GraphQueryError, GraphQueryService


logger = logging.getLogger(__name__)
graph_bp = Blueprint("graph", __name__, url_prefix="/api")


def _load_case(case_uuid: str):
    case = Case.get_by_uuid(case_uuid)
    if not case:
        return None, (jsonify({"success": False, "error": "Case not found"}), 404)
    return case, None


def _error_response(exc: Exception):
    if isinstance(exc, GraphNotFoundError):
        return jsonify({"success": False, "error": str(exc)}), 404
    if isinstance(exc, GraphQueryError):
        return jsonify({"success": False, "error": str(exc)}), 400
    logger.exception("Unexpected graph API error")
    return jsonify({"success": False, "error": "Graph query failed"}), 500


def _service() -> GraphQueryService:
    return GraphQueryService()


@graph_bp.route("/graph/<case_uuid>/summary")
@login_required
def graph_summary(case_uuid):
    case, error = _load_case(case_uuid)
    if error:
        return error
    try:
        return jsonify({"success": True, **_service().graph_summary(case.id)})
    except Exception as exc:
        return _error_response(exc)


@graph_bp.route("/graph/<case_uuid>/entities/search")
@login_required
def graph_entity_search(case_uuid):
    case, error = _load_case(case_uuid)
    if error:
        return error
    try:
        payload = _service().search_entities(
            case.id,
            q=request.args.get("q", ""),
            entity_types=request.args.getlist("type") or request.args.get("type", ""),
            limit=request.args.get("limit", ""),
        )
        return jsonify({"success": True, **payload})
    except Exception as exc:
        return _error_response(exc)


@graph_bp.route("/graph/<case_uuid>/entities/<int:entity_id>")
@login_required
def graph_entity_detail(case_uuid, entity_id):
    case, error = _load_case(case_uuid)
    if error:
        return error
    try:
        return jsonify({"success": True, "entity": _service().entity_detail(case.id, entity_id)})
    except Exception as exc:
        return _error_response(exc)


@graph_bp.route("/graph/<case_uuid>/entities/<int:entity_id>/neighbors")
@login_required
def graph_entity_neighbors(case_uuid, entity_id):
    case, error = _load_case(case_uuid)
    if error:
        return error
    try:
        include_invalidated = (request.args.get("include_invalidated") or "").strip().lower() == "true"
        payload = _service().neighborhood(
            case.id,
            entity_id,
            direction=request.args.get("direction", "both"),
            relationship_types=request.args.getlist("relationship_type") or request.args.get("relationship_type", ""),
            entity_types=request.args.getlist("entity_type") or request.args.get("entity_type", ""),
            cursor=request.args.get("cursor", ""),
            limit=request.args.get("limit", ""),
            include_invalidated=include_invalidated,
        )
        return jsonify({"success": True, **payload})
    except Exception as exc:
        return _error_response(exc)


@graph_bp.route("/graph/<case_uuid>/relationships/<int:relationship_id>")
@login_required
def graph_relationship_detail(case_uuid, relationship_id):
    case, error = _load_case(case_uuid)
    if error:
        return error
    try:
        return jsonify({"success": True, "relationship": _service().relationship_detail(case.id, relationship_id)})
    except Exception as exc:
        return _error_response(exc)


@graph_bp.route("/graph/<case_uuid>/relationships/<int:relationship_id>/evidence")
@login_required
def graph_relationship_evidence(case_uuid, relationship_id):
    case, error = _load_case(case_uuid)
    if error:
        return error
    try:
        payload = _service().relationship_evidence(
            case.id,
            relationship_id,
            cursor=request.args.get("cursor", ""),
            offset=request.args.get("offset", ""),
            limit=request.args.get("limit", ""),
        )
        return jsonify({"success": True, **payload})
    except Exception as exc:
        return _error_response(exc)


@graph_bp.route("/graph/<case_uuid>/evidence/<path:evidence_record_key>")
@login_required
def graph_evidence_detail(case_uuid, evidence_record_key):
    case, error = _load_case(case_uuid)
    if error:
        return error
    try:
        return jsonify({"success": True, **_service().exact_evidence(case.id, evidence_record_key)})
    except Exception as exc:
        return _error_response(exc)


@graph_bp.route("/graph/<case_uuid>/paths", methods=["POST"])
@login_required
def graph_paths(case_uuid):
    case, error = _load_case(case_uuid)
    if error:
        return error
    try:
        data = request.get_json(silent=True) or {}
        payload = _service().path_search(
            case.id,
            source_entity_id=data.get("source_entity_id"),
            target_entity_id=data.get("target_entity_id"),
            direction=data.get("direction", "both"),
            max_depth=data.get("max_depth", 3),
            max_paths=data.get("max_paths", 3),
            relationship_types=data.get("relationship_types") or [],
        )
        return jsonify({"success": True, **payload})
    except Exception as exc:
        return _error_response(exc)

