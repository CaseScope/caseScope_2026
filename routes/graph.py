"""Investigation graph API routes (Phase 0C read + Phase 0D saved views)."""
from __future__ import annotations

import logging

from flask import Blueprint, jsonify, request
from flask_login import current_user, login_required

from models.case import Case
from routes.route_helpers import _require_case_write_access
from utils.graph_query import GraphNotFoundError, GraphQueryError, GraphQueryService
from utils.graph_saved_views import (
    GraphSavedViewConflictError,
    GraphSavedViewError,
    GraphSavedViewNotFoundError,
    GraphSavedViewService,
)
from utils.investigation_references import InvestigationReferenceError


logger = logging.getLogger(__name__)
graph_bp = Blueprint("graph", __name__, url_prefix="/api")


def _load_case(case_uuid: str):
    case = Case.get_by_uuid(case_uuid)
    if not case:
        return None, (jsonify({"success": False, "error": "Case not found"}), 404)
    return case, None


def _error_response(exc: Exception):
    if isinstance(exc, GraphSavedViewConflictError):
        return jsonify({
            "success": False,
            "error": str(exc),
            "stale_version": True,
            "current_version": exc.current_version,
        }), 409
    if isinstance(exc, (GraphSavedViewNotFoundError, GraphNotFoundError)):
        return jsonify({"success": False, "error": str(exc)}), 404
    if isinstance(exc, (GraphSavedViewError, GraphQueryError, InvestigationReferenceError)):
        return jsonify({"success": False, "error": str(exc)}), 400
    logger.exception("Unexpected graph API error")
    return jsonify({"success": False, "error": "Graph query failed"}), 500


def _service() -> GraphQueryService:
    return GraphQueryService()


def _view_service() -> GraphSavedViewService:
    return GraphSavedViewService()


def _actor():
    return {
        "user_id": getattr(current_user, "id", None),
        "username": getattr(current_user, "username", None),
        "actor_type": "analyst",
        "is_ai": False,
    }

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


@graph_bp.route("/graph/<case_uuid>/views", methods=["GET"])
@login_required
def list_saved_views(case_uuid):
    case, error = _load_case(case_uuid)
    if error:
        return error
    try:
        payload = _view_service().list_views(
            case.id,
            limit=request.args.get("limit", 50),
            offset=request.args.get("offset", 0),
        )
        return jsonify({"success": True, **payload})
    except Exception as exc:
        return _error_response(exc)


@graph_bp.route("/graph/<case_uuid>/views", methods=["POST"])
@login_required
def create_saved_view(case_uuid):
    case, error = _load_case(case_uuid)
    if error:
        return error
    denied = _require_case_write_access(current_user)
    if denied:
        return denied
    payload = request.get_json(silent=True) or {}
    try:
        view = _view_service().create_view(
            case.id,
            title=payload.get("title"),
            description=payload.get("description"),
            view_payload=payload.get("view") or payload,
            actor=_actor(),
        )
        return jsonify({"success": True, **view}), 201
    except Exception as exc:
        return _error_response(exc)


@graph_bp.route("/graph/<case_uuid>/views/<view_uuid>", methods=["GET"])
@login_required
def get_saved_view(case_uuid, view_uuid):
    case, error = _load_case(case_uuid)
    if error:
        return error
    try:
        resolve_live = (request.args.get("resolve_live") or "true").strip().lower() != "false"
        restore = (request.args.get("restore") or "").strip().lower() == "true"
        if restore:
            payload = _view_service().restore_payload(case.id, view_uuid)
            return jsonify({"success": True, **payload})
        payload = _view_service().get_view(case.id, view_uuid, resolve_live=resolve_live)
        return jsonify({"success": True, **payload})
    except Exception as exc:
        return _error_response(exc)


@graph_bp.route("/graph/<case_uuid>/views/<view_uuid>", methods=["PUT"])
@login_required
def update_saved_view(case_uuid, view_uuid):
    case, error = _load_case(case_uuid)
    if error:
        return error
    denied = _require_case_write_access(current_user)
    if denied:
        return denied
    payload = request.get_json(silent=True) or {}
    try:
        expected_version = payload.get("expected_version", payload.get("version"))
        view_payload = payload.get("view") if "view" in payload else None
        if view_payload is None and any(
            key in payload
            for key in (
                "root_entity_ids",
                "root_entity_references",
                "expanded_entity_ids",
                "expanded_entity_references",
                "visible_relationship_ids",
                "visible_relationship_references",
                "filters_json",
                "filters",
                "node_coordinates_json",
                "node_coordinates",
                "pinned_node_ids",
                "hidden_node_ids",
                "selected_entity_id",
                "selected_relationship_id",
            )
        ):
            view_payload = payload
        view = _view_service().update_view(
            case.id,
            view_uuid,
            expected_version=expected_version,
            actor=_actor(),
            title=payload.get("title") if "title" in payload else None,
            description=payload.get("description") if "description" in payload else None,
            view_payload=view_payload,
        )
        return jsonify({"success": True, **view})
    except Exception as exc:
        return _error_response(exc)


@graph_bp.route("/graph/<case_uuid>/views/<view_uuid>", methods=["DELETE"])
@login_required
def delete_saved_view(case_uuid, view_uuid):
    case, error = _load_case(case_uuid)
    if error:
        return error
    denied = _require_case_write_access(current_user)
    if denied:
        return denied
    payload = request.get_json(silent=True) or {}
    try:
        expected_version = payload.get("expected_version", payload.get("version"))
        if expected_version is None:
            expected_version = request.args.get("expected_version") or request.args.get("version")
        result = _view_service().delete_view(
            case.id,
            view_uuid,
            expected_version=expected_version,
            actor=_actor(),
        )
        return jsonify({"success": True, **result})
    except Exception as exc:
        return _error_response(exc)

