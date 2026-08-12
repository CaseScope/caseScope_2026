"""Investigation Thread API routes (Phase 0D)."""
from __future__ import annotations

import logging

from flask import Blueprint, jsonify, request
from flask_login import current_user, login_required

from models.case import Case
from routes.route_helpers import _require_case_write_access
from utils.graph_query import GraphNotFoundError, GraphQueryError
from utils.investigation_references import InvestigationReferenceError
from utils.investigation_threads import (
    InvestigationThreadConflictError,
    InvestigationThreadError,
    InvestigationThreadNotFoundError,
    InvestigationThreadService,
)


logger = logging.getLogger(__name__)
investigation_threads_bp = Blueprint("investigation_threads", __name__, url_prefix="/api")


def _load_case(case_uuid: str):
    case = Case.get_by_uuid(case_uuid)
    if not case:
        return None, (jsonify({"success": False, "error": "Case not found"}), 404)
    return case, None


def _actor():
    return {
        "user_id": getattr(current_user, "id", None),
        "username": getattr(current_user, "username", None),
        "actor_type": "analyst",
        "is_ai": False,
    }


def _service() -> InvestigationThreadService:
    return InvestigationThreadService()


def _error_response(exc: Exception):
    if isinstance(exc, InvestigationThreadConflictError):
        return jsonify({
            "success": False,
            "error": str(exc),
            "stale_version": True,
            "current_version": exc.current_version,
        }), 409
    if isinstance(exc, InvestigationThreadNotFoundError):
        return jsonify({"success": False, "error": str(exc)}), 404
    if isinstance(exc, (InvestigationThreadError, InvestigationReferenceError, GraphQueryError)):
        return jsonify({"success": False, "error": str(exc)}), 400
    if isinstance(exc, GraphNotFoundError):
        return jsonify({"success": False, "error": str(exc)}), 404
    logger.exception("Unexpected investigation thread API error")
    return jsonify({"success": False, "error": "Investigation thread operation failed"}), 500


def _expected_version_from_payload(payload: dict):
    if "expected_version" in payload:
        return payload.get("expected_version")
    return payload.get("version")


@investigation_threads_bp.route("/investigation-threads/<case_uuid>", methods=["GET"])
@login_required
def list_threads(case_uuid):
    case, error = _load_case(case_uuid)
    if error:
        return error
    try:
        payload = _service().list_threads(
            case.id,
            limit=request.args.get("limit", 50),
            offset=request.args.get("offset", 0),
            status=request.args.get("status"),
        )
        return jsonify({"success": True, **payload})
    except Exception as exc:
        return _error_response(exc)


@investigation_threads_bp.route("/investigation-threads/<case_uuid>", methods=["POST"])
@login_required
def create_thread(case_uuid):
    case, error = _load_case(case_uuid)
    if error:
        return error
    denied = _require_case_write_access(current_user)
    if denied:
        return denied
    payload = request.get_json(silent=True) or {}
    try:
        thread = _service().create_thread(
            case.id,
            title=payload.get("title"),
            description=payload.get("description"),
            status=payload.get("status", "draft"),
            owner_user_id=payload.get("owner_user_id", getattr(current_user, "id", None)),
            owner_username=payload.get("owner_username", getattr(current_user, "username", None)),
            time_start=payload.get("time_start"),
            time_end=payload.get("time_end"),
            include_in_report=payload.get("include_in_report", False),
            actor=_actor(),
        )
        return jsonify({"success": True, "thread": thread}), 201
    except Exception as exc:
        return _error_response(exc)


@investigation_threads_bp.route("/investigation-threads/<case_uuid>/from-selection", methods=["POST"])
@login_required
def create_thread_from_selection(case_uuid):
    case, error = _load_case(case_uuid)
    if error:
        return error
    denied = _require_case_write_access(current_user)
    if denied:
        return denied
    payload = request.get_json(silent=True) or {}
    try:
        result = _service().create_from_selection(
            case.id,
            title=payload.get("title"),
            description=payload.get("description"),
            entity_ids=payload.get("entity_ids"),
            relationship_ids=payload.get("relationship_ids"),
            evidence_record_keys=payload.get("evidence_record_keys"),
            actor=_actor(),
        )
        return jsonify({"success": True, **result}), 201
    except Exception as exc:
        return _error_response(exc)


@investigation_threads_bp.route("/investigation-threads/<case_uuid>/<thread_uuid>", methods=["GET"])
@login_required
def get_thread(case_uuid, thread_uuid):
    case, error = _load_case(case_uuid)
    if error:
        return error
    try:
        include_memberships = (request.args.get("include_memberships") or "true").strip().lower() != "false"
        payload = _service().get_thread(case.id, thread_uuid, include_memberships=include_memberships)
        return jsonify({"success": True, **payload})
    except Exception as exc:
        return _error_response(exc)


@investigation_threads_bp.route("/investigation-threads/<case_uuid>/<thread_uuid>", methods=["PATCH"])
@login_required
def update_thread(case_uuid, thread_uuid):
    case, error = _load_case(case_uuid)
    if error:
        return error
    denied = _require_case_write_access(current_user)
    if denied:
        return denied
    payload = request.get_json(silent=True) or {}
    try:
        expected_version = _expected_version_from_payload(payload)
        fields = {
            key: payload[key]
            for key in (
                "title",
                "description",
                "analyst_conclusion",
                "status",
                "owner_user_id",
                "owner_username",
                "time_start",
                "time_end",
                "include_in_report",
                "current_saved_view_uuid",
            )
            if key in payload
        }
        thread = _service().update_thread(
            case.id,
            thread_uuid,
            expected_version=expected_version,
            actor=_actor(),
            **fields,
        )
        return jsonify({"success": True, "thread": thread})
    except Exception as exc:
        return _error_response(exc)


@investigation_threads_bp.route("/investigation-threads/<case_uuid>/<thread_uuid>/selection", methods=["POST"])
@login_required
def add_selection(case_uuid, thread_uuid):
    case, error = _load_case(case_uuid)
    if error:
        return error
    denied = _require_case_write_access(current_user)
    if denied:
        return denied
    payload = request.get_json(silent=True) or {}
    try:
        result = _service().add_selection(
            case.id,
            thread_uuid,
            expected_version=_expected_version_from_payload(payload),
            entity_ids=payload.get("entity_ids"),
            relationship_ids=payload.get("relationship_ids"),
            evidence_record_keys=payload.get("evidence_record_keys"),
            actor=_actor(),
        )
        return jsonify({"success": True, **result})
    except Exception as exc:
        return _error_response(exc)


@investigation_threads_bp.route("/investigation-threads/<case_uuid>/<thread_uuid>/entities", methods=["POST"])
@login_required
def link_entity(case_uuid, thread_uuid):
    case, error = _load_case(case_uuid)
    if error:
        return error
    denied = _require_case_write_access(current_user)
    if denied:
        return denied
    payload = request.get_json(silent=True) or {}
    try:
        result = _service().link_entity(
            case.id,
            thread_uuid,
            expected_version=_expected_version_from_payload(payload),
            entity_id=payload.get("entity_id"),
            analyst_rationale=payload.get("analyst_rationale"),
            actor=_actor(),
        )
        return jsonify({"success": True, **result})
    except Exception as exc:
        return _error_response(exc)


@investigation_threads_bp.route(
    "/investigation-threads/<case_uuid>/<thread_uuid>/entities/<path:stable_ref>",
    methods=["DELETE"],
)
@login_required
def unlink_entity(case_uuid, thread_uuid, stable_ref):
    case, error = _load_case(case_uuid)
    if error:
        return error
    denied = _require_case_write_access(current_user)
    if denied:
        return denied
    payload = request.get_json(silent=True) or {}
    try:
        result = _service().unlink_entity(
            case.id,
            thread_uuid,
            expected_version=_expected_version_from_payload(payload),
            stable_reference_key=stable_ref,
            actor=_actor(),
        )
        return jsonify({"success": True, **result})
    except Exception as exc:
        return _error_response(exc)


@investigation_threads_bp.route("/investigation-threads/<case_uuid>/<thread_uuid>/relationships", methods=["POST"])
@login_required
def link_relationship(case_uuid, thread_uuid):
    case, error = _load_case(case_uuid)
    if error:
        return error
    denied = _require_case_write_access(current_user)
    if denied:
        return denied
    payload = request.get_json(silent=True) or {}
    try:
        result = _service().link_relationship(
            case.id,
            thread_uuid,
            expected_version=_expected_version_from_payload(payload),
            relationship_id=payload.get("relationship_id"),
            analyst_rationale=payload.get("analyst_rationale"),
            actor=_actor(),
        )
        return jsonify({"success": True, **result})
    except Exception as exc:
        return _error_response(exc)


@investigation_threads_bp.route(
    "/investigation-threads/<case_uuid>/<thread_uuid>/relationships/<path:stable_ref>",
    methods=["DELETE"],
)
@login_required
def unlink_relationship(case_uuid, thread_uuid, stable_ref):
    case, error = _load_case(case_uuid)
    if error:
        return error
    denied = _require_case_write_access(current_user)
    if denied:
        return denied
    payload = request.get_json(silent=True) or {}
    try:
        result = _service().unlink_relationship(
            case.id,
            thread_uuid,
            expected_version=_expected_version_from_payload(payload),
            stable_reference_key=stable_ref,
            actor=_actor(),
        )
        return jsonify({"success": True, **result})
    except Exception as exc:
        return _error_response(exc)


@investigation_threads_bp.route("/investigation-threads/<case_uuid>/<thread_uuid>/evidence", methods=["POST"])
@login_required
def link_evidence(case_uuid, thread_uuid):
    case, error = _load_case(case_uuid)
    if error:
        return error
    denied = _require_case_write_access(current_user)
    if denied:
        return denied
    payload = request.get_json(silent=True) or {}
    try:
        result = _service().link_evidence(
            case.id,
            thread_uuid,
            expected_version=_expected_version_from_payload(payload),
            evidence_record_key=payload.get("evidence_record_key"),
            originating_relationship_id=payload.get("originating_relationship_id"),
            analyst_rationale=payload.get("analyst_rationale"),
            actor=_actor(),
        )
        return jsonify({"success": True, **result})
    except Exception as exc:
        return _error_response(exc)


@investigation_threads_bp.route(
    "/investigation-threads/<case_uuid>/<thread_uuid>/evidence/<snapshot_uuid>",
    methods=["DELETE"],
)
@login_required
def unlink_evidence(case_uuid, thread_uuid, snapshot_uuid):
    case, error = _load_case(case_uuid)
    if error:
        return error
    denied = _require_case_write_access(current_user)
    if denied:
        return denied
    payload = request.get_json(silent=True) or {}
    try:
        result = _service().unlink_evidence(
            case.id,
            thread_uuid,
            expected_version=_expected_version_from_payload(payload),
            snapshot_uuid=snapshot_uuid,
            actor=_actor(),
        )
        return jsonify({"success": True, **result})
    except Exception as exc:
        return _error_response(exc)


@investigation_threads_bp.route("/investigation-threads/<case_uuid>/<thread_uuid>/iocs", methods=["POST"])
@login_required
def link_ioc(case_uuid, thread_uuid):
    case, error = _load_case(case_uuid)
    if error:
        return error
    denied = _require_case_write_access(current_user)
    if denied:
        return denied
    payload = request.get_json(silent=True) or {}
    try:
        result = _service().link_ioc(
            case.id,
            thread_uuid,
            expected_version=_expected_version_from_payload(payload),
            ioc_uuid=payload.get("ioc_uuid"),
            analyst_rationale=payload.get("analyst_rationale"),
            actor=_actor(),
        )
        return jsonify({"success": True, **result})
    except Exception as exc:
        return _error_response(exc)


@investigation_threads_bp.route(
    "/investigation-threads/<case_uuid>/<thread_uuid>/iocs/<ioc_ref>",
    methods=["DELETE"],
)
@login_required
def unlink_ioc(case_uuid, thread_uuid, ioc_ref):
    case, error = _load_case(case_uuid)
    if error:
        return error
    denied = _require_case_write_access(current_user)
    if denied:
        return denied
    payload = request.get_json(silent=True) or {}
    try:
        result = _service().unlink_ioc(
            case.id,
            thread_uuid,
            expected_version=_expected_version_from_payload(payload),
            ioc_uuid=ioc_ref,
            actor=_actor(),
        )
        return jsonify({"success": True, **result})
    except Exception as exc:
        return _error_response(exc)


@investigation_threads_bp.route("/investigation-threads/<case_uuid>/<thread_uuid>/findings", methods=["POST"])
@login_required
def link_finding(case_uuid, thread_uuid):
    case, error = _load_case(case_uuid)
    if error:
        return error
    denied = _require_case_write_access(current_user)
    if denied:
        return denied
    payload = request.get_json(silent=True) or {}
    try:
        result = _service().link_finding(
            case.id,
            thread_uuid,
            expected_version=_expected_version_from_payload(payload),
            finding_kind=payload.get("finding_kind", "unified_finding"),
            analysis_id=payload.get("analysis_id"),
            source_system=payload.get("source_system"),
            dedup_key=payload.get("dedup_key"),
            finding_id=payload.get("finding_id"),
            pattern_match_id=payload.get("pattern_match_id"),
            analyst_rationale=payload.get("analyst_rationale"),
            actor=_actor(),
        )
        return jsonify({"success": True, **result})
    except Exception as exc:
        return _error_response(exc)


@investigation_threads_bp.route(
    "/investigation-threads/<case_uuid>/<thread_uuid>/findings/<path:finding_ref>",
    methods=["DELETE"],
)
@login_required
def unlink_finding(case_uuid, thread_uuid, finding_ref):
    case, error = _load_case(case_uuid)
    if error:
        return error
    denied = _require_case_write_access(current_user)
    if denied:
        return denied
    payload = request.get_json(silent=True) or {}
    try:
        result = _service().unlink_finding(
            case.id,
            thread_uuid,
            expected_version=_expected_version_from_payload(payload),
            stable_reference_key=finding_ref,
            actor=_actor(),
        )
        return jsonify({"success": True, **result})
    except Exception as exc:
        return _error_response(exc)


@investigation_threads_bp.route("/investigation-threads/<case_uuid>/<thread_uuid>/notes", methods=["POST"])
@login_required
def add_note(case_uuid, thread_uuid):
    case, error = _load_case(case_uuid)
    if error:
        return error
    denied = _require_case_write_access(current_user)
    if denied:
        return denied
    payload = request.get_json(silent=True) or {}
    try:
        result = _service().add_note(
            case.id,
            thread_uuid,
            expected_version=_expected_version_from_payload(payload),
            body=payload.get("body"),
            actor=_actor(),
        )
        return jsonify({"success": True, **result}), 201
    except Exception as exc:
        return _error_response(exc)


@investigation_threads_bp.route(
    "/investigation-threads/<case_uuid>/<thread_uuid>/notes/<note_uuid>",
    methods=["PATCH"],
)
@login_required
def update_note(case_uuid, thread_uuid, note_uuid):
    case, error = _load_case(case_uuid)
    if error:
        return error
    denied = _require_case_write_access(current_user)
    if denied:
        return denied
    payload = request.get_json(silent=True) or {}
    try:
        result = _service().update_note(
            case.id,
            thread_uuid,
            note_uuid=note_uuid,
            expected_version=_expected_version_from_payload(payload),
            body=payload.get("body"),
            actor=_actor(),
        )
        return jsonify({"success": True, **result})
    except Exception as exc:
        return _error_response(exc)


@investigation_threads_bp.route(
    "/investigation-threads/<case_uuid>/<thread_uuid>/notes/<note_uuid>",
    methods=["DELETE"],
)
@login_required
def remove_note(case_uuid, thread_uuid, note_uuid):
    case, error = _load_case(case_uuid)
    if error:
        return error
    denied = _require_case_write_access(current_user)
    if denied:
        return denied
    payload = request.get_json(silent=True) or {}
    try:
        result = _service().remove_note(
            case.id,
            thread_uuid,
            note_uuid=note_uuid,
            expected_version=_expected_version_from_payload(payload),
            actor=_actor(),
        )
        return jsonify({"success": True, **result})
    except Exception as exc:
        return _error_response(exc)
