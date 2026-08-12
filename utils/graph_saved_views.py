"""Service layer for durable graph saved views.

Saved views persist analyst workspace state with stable graph references so a
layout can be restored after graph rebuilds that replace transient row IDs.
"""
from __future__ import annotations

import math
import re
from datetime import datetime, timezone
from typing import Any

from models.audit_log import AuditAction, AuditEntityType, AuditLog
from models.database import db
from models.graph_saved_view import GraphSavedView
from utils.graph_query import GraphNotFoundError, GraphQueryError
from utils.investigation_references import (
    InvestigationReferenceError,
    build_entity_reference,
    build_relationship_reference,
    canonical_json,
    entity_reference_from_graph_entity,
    evidence_set_fingerprint,
    membership_fingerprint_entry,
    relationship_reference_from_graph_relationship,
    require_graph_entity,
    require_graph_relationship,
    resolve_entity_reference,
    resolve_relationship_reference,
    snapshot_sha256,
)


TITLE_MAX = 255
DESCRIPTION_MAX = 20000
MAX_ENTITY_REFS = 500
MAX_RELATIONSHIP_REFS = 1000
MAX_VIEW_STATE_BYTES = 1 * 1024 * 1024
LIST_DEFAULT = 50
LIST_MAX = 200
PROJECTION_CONTRACT_VERSION = "graph-view:v1"

AUDIT_ENTITY_TYPE = AuditEntityType.GRAPH_SAVED_VIEW
_THREADREF_RE = re.compile(r"^threadref:v1:[0-9a-f]{64}$")


class GraphSavedViewError(ValueError):
    """Client-correctable saved-view error."""


class GraphSavedViewConflictError(GraphSavedViewError):
    """Raised when optimistic concurrency detects a stale write."""

    def __init__(self, message, *, current_version, details=None):
        super().__init__(message)
        self.current_version = current_version
        self.details = details or {}


class GraphSavedViewNotFoundError(GraphSavedViewError):
    """Raised when a saved graph view does not exist in the case scope."""


class GraphSavedViewService:
    """Repository-testable service for saved graph workspace arrangements."""

    def create_view(self, case_id, *, title, description=None, view_payload, actor):
        case_id = _case_id(case_id)
        normalized_title = _validate_title(title)
        normalized_description = _validate_description(description)
        normalized = _normalize_view_payload(case_id, view_payload)
        actor_info = _actor_info(actor)

        view = GraphSavedView(
            case_id=case_id,
            title=normalized_title,
            description=normalized_description,
            root_entity_references=normalized["root_entity_references"],
            expanded_entity_references=normalized["expanded_entity_references"],
            visible_relationship_references=normalized["visible_relationship_references"],
            filters_json=normalized["filters_json"],
            time_start=normalized["time_start"],
            time_end=normalized["time_end"],
            pinned_node_references=normalized["pinned_node_references"],
            hidden_node_references=normalized["hidden_node_references"],
            hidden_group_state=normalized["hidden_group_state"],
            node_coordinates_json=normalized["node_coordinates_json"],
            selected_entity_reference=normalized["selected_entity_reference"],
            selected_relationship_reference=normalized["selected_relationship_reference"],
            projection_contract_version=PROJECTION_CONTRACT_VERSION,
            evidence_set_fingerprint=normalized["evidence_set_fingerprint"],
            view_state_json=normalized["view_state_json"],
            view_state_sha256=normalized["view_state_sha256"],
            created_by_user_id=actor_info["user_id"],
            created_by_username=actor_info["username"],
            updated_by_user_id=actor_info["user_id"],
            updated_by_username=actor_info["username"],
        )

        db.session.add(view)
        db.session.flush()
        AuditLog.log(
            entity_type=AUDIT_ENTITY_TYPE,
            entity_id=view.uuid,
            entity_name=view.title,
            action=AuditAction.CREATED,
            username=actor_info["username"],
            user_id=actor_info["user_id"],
            case_uuid=_case_uuid(case_id),
            details=_audit_details(view, action="created"),
        )
        return self.get_view(case_id, view.uuid, resolve_live=True)

    def list_views(self, case_id, limit=LIST_DEFAULT, offset=0):
        case_id = _case_id(case_id)
        effective_limit = _limit(limit, default=LIST_DEFAULT, maximum=LIST_MAX)
        effective_offset = _offset(offset)
        query = GraphSavedView.query.filter_by(case_id=case_id)
        total = query.count()
        rows = (
            query.order_by(GraphSavedView.updated_at.desc(), GraphSavedView.id.desc())
            .offset(effective_offset)
            .limit(effective_limit)
            .all()
        )
        return {
            "views": [_view_dict(row, include_state=False) for row in rows],
            "pagination": {
                "limit": effective_limit,
                "offset": effective_offset,
                "total": total,
                "has_more": effective_offset + len(rows) < total,
            },
        }

    def get_view(self, case_id, view_uuid, *, resolve_live=True):
        case_id = _case_id(case_id)
        view = _get_view_or_404(case_id, view_uuid)
        payload = {"view": _view_dict(view, include_state=True)}
        if resolve_live:
            payload.update(_live_resolution(case_id, view.view_state_json or {}))
        else:
            payload.update(
                {
                    "live_resolution": {"entities": {}, "relationships": {}},
                    "unresolved_entity_references": [],
                    "unresolved_relationship_references": [],
                }
            )
        return payload

    def update_view(
        self,
        case_id,
        view_uuid,
        *,
        expected_version,
        actor,
        title=None,
        description=None,
        view_payload=None,
    ):
        case_id = _case_id(case_id)
        expected_version = _expected_version(expected_version)
        current = _get_view_or_404(case_id, view_uuid)
        actor_info = _actor_info(actor)

        updates: dict[str, Any] = {
            "updated_by_user_id": actor_info["user_id"],
            "updated_by_username": actor_info["username"],
            "updated_at": datetime.utcnow(),
            "version": GraphSavedView.version + 1,
        }
        changes: dict[str, Any] = {"version": {"old": current.version, "new": current.version + 1}}

        if title is not None:
            normalized_title = _validate_title(title)
            updates["title"] = normalized_title
            changes["title"] = {"old": current.title, "new": normalized_title}
        if description is not None:
            normalized_description = _validate_description(description)
            updates["description"] = normalized_description
            changes["description"] = {"old": current.description, "new": normalized_description}
        if view_payload is not None:
            normalized = _normalize_view_payload(case_id, view_payload)
            updates.update(
                {
                    "root_entity_references": normalized["root_entity_references"],
                    "expanded_entity_references": normalized["expanded_entity_references"],
                    "visible_relationship_references": normalized["visible_relationship_references"],
                    "filters_json": normalized["filters_json"],
                    "time_start": normalized["time_start"],
                    "time_end": normalized["time_end"],
                    "pinned_node_references": normalized["pinned_node_references"],
                    "hidden_node_references": normalized["hidden_node_references"],
                    "hidden_group_state": normalized["hidden_group_state"],
                    "node_coordinates_json": normalized["node_coordinates_json"],
                    "selected_entity_reference": normalized["selected_entity_reference"],
                    "selected_relationship_reference": normalized["selected_relationship_reference"],
                    "projection_contract_version": PROJECTION_CONTRACT_VERSION,
                    "evidence_set_fingerprint": normalized["evidence_set_fingerprint"],
                    "view_state_json": normalized["view_state_json"],
                    "view_state_sha256": normalized["view_state_sha256"],
                }
            )
            changes["view_state_sha256"] = {
                "old": current.view_state_sha256,
                "new": normalized["view_state_sha256"],
            }
            changes["evidence_set_fingerprint"] = {
                "old": current.evidence_set_fingerprint,
                "new": normalized["evidence_set_fingerprint"],
            }

        matched = (
            GraphSavedView.query.filter(
                GraphSavedView.case_id == case_id,
                GraphSavedView.uuid == str(view_uuid),
                GraphSavedView.version == expected_version,
            ).update(updates, synchronize_session=False)
        )
        if matched != 1:
            db.session.rollback()
            latest = GraphSavedView.query.filter_by(case_id=case_id, uuid=str(view_uuid)).first()
            if latest is None:
                raise GraphSavedViewNotFoundError("Saved graph view not found")
            raise GraphSavedViewConflictError(
                "Saved graph view was modified by another user",
                current_version=latest.version,
            )

        db.session.flush()
        db.session.expire_all()
        updated = _get_view_or_404(case_id, view_uuid)
        AuditLog.log(
            entity_type=AUDIT_ENTITY_TYPE,
            entity_id=updated.uuid,
            entity_name=updated.title,
            action=AuditAction.UPDATED,
            username=actor_info["username"],
            user_id=actor_info["user_id"],
            case_uuid=_case_uuid(case_id),
            details={
                "action": "updated",
                "case_id": case_id,
                "changes": changes,
                "view_state_sha256": updated.view_state_sha256,
                "evidence_set_fingerprint": updated.evidence_set_fingerprint,
            },
        )
        return self.get_view(case_id, view_uuid, resolve_live=True)

    def delete_view(self, case_id, view_uuid, *, expected_version, actor):
        case_id = _case_id(case_id)
        expected_version = _expected_version(expected_version)
        view = _get_view_or_404(case_id, view_uuid)

        actor_info = _actor_info(actor)
        final_state = _view_dict(view, include_state=True)

        from models.investigation_thread import InvestigationThread

        affected_threads = (
            InvestigationThread.query.filter(
                InvestigationThread.case_id == case_id,
                InvestigationThread.current_saved_view_id == view.id,
            )
            .order_by(InvestigationThread.id.asc())
            .all()
        )
        affected_thread_uuids = [thread.uuid for thread in affected_threads]
        if affected_thread_uuids:
            raise GraphSavedViewConflictError(
                "Saved graph view is currently referenced by investigation threads",
                current_version=view.version,
                details={"referencing_thread_uuids": affected_thread_uuids},
            )

        deleted = (
            GraphSavedView.query.filter(
                GraphSavedView.case_id == case_id,
                GraphSavedView.uuid == str(view_uuid),
                GraphSavedView.version == expected_version,
            ).delete(synchronize_session=False)
        )
        if deleted != 1:
            db.session.rollback()
            latest = GraphSavedView.query.filter_by(case_id=case_id, uuid=str(view_uuid)).first()
            if latest is None:
                raise GraphSavedViewNotFoundError("Saved graph view not found")
            raise GraphSavedViewConflictError(
                "Saved graph view was modified by another user",
                current_version=latest.version,
            )
        db.session.flush()
        AuditLog.log(
            entity_type=AUDIT_ENTITY_TYPE,
            entity_id=view_uuid,
            entity_name=final_state["title"],
            action=AuditAction.DELETED,
            username=actor_info["username"],
            user_id=actor_info["user_id"],
            case_uuid=_case_uuid(case_id),
            details={
                "action": "deleted",
                "case_id": case_id,
                "final_state": final_state,
            },
        )
        return {
            "deleted": True,
            "view_uuid": str(view_uuid),
        }

    def restore_payload(self, case_id, view_uuid):
        resolved_view = self.get_view(case_id, view_uuid, resolve_live=True)
        view = resolved_view["view"]
        state = view.get("view_state_json") or {}
        live_entities = resolved_view["live_resolution"]["entities"]
        live_relationships = resolved_view["live_resolution"]["relationships"]

        node_coordinates = {}
        for stable_key, coords in (state.get("node_coordinates") or {}).items():
            entity_id = live_entities.get(stable_key)
            if entity_id is not None:
                node_coordinates[str(entity_id)] = coords

        selected_entity_id = None
        selected_entity_ref = state.get("selected_entity_reference")
        if selected_entity_ref:
            selected_entity_id = live_entities.get(selected_entity_ref.get("stable_reference_key"))

        selected_relationship_id = None
        selected_relationship_ref = state.get("selected_relationship_reference")
        if selected_relationship_ref:
            selected_relationship_id = live_relationships.get(selected_relationship_ref.get("stable_reference_key"))

        return {
            "view": view,
            "resolved": {
                "root_entity_ids": _resolved_ids(state.get("root_entity_references"), live_entities),
                "expanded_entity_ids": _resolved_ids(state.get("expanded_entity_references"), live_entities),
                "visible_relationship_ids": _resolved_ids(
                    state.get("visible_relationship_references"),
                    live_relationships,
                ),
                "pinned_node_ids": _resolved_ids(state.get("pinned_node_references"), live_entities),
                "hidden_node_ids": _resolved_ids(state.get("hidden_node_references"), live_entities),
                "node_coordinates": node_coordinates,
                "selected_entity_id": selected_entity_id,
                "selected_relationship_id": selected_relationship_id,
                "filters": state.get("filters") or {},
                "time_start": state.get("time_start"),
                "time_end": state.get("time_end"),
                "unresolved_entity_references": resolved_view["unresolved_entity_references"],
                "unresolved_relationship_references": resolved_view["unresolved_relationship_references"],
            },
        }


def _normalize_view_payload(case_id: int, payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise GraphSavedViewError("view_payload must be an object")

    root_entity_refs = _entity_ref_list(
        case_id,
        ids=payload.get("root_entity_ids"),
        references=payload.get("root_entity_references"),
        field_name="root_entity",
    )
    expanded_entity_refs = _entity_ref_list(
        case_id,
        ids=payload.get("expanded_entity_ids"),
        references=payload.get("expanded_entity_references"),
        field_name="expanded_entity",
    )
    visible_relationship_refs = _relationship_ref_list(
        case_id,
        ids=payload.get("visible_relationship_ids"),
        references=payload.get("visible_relationship_references"),
        field_name="visible_relationship",
    )
    pinned_node_refs = _entity_ref_list(
        case_id,
        ids=payload.get("pinned_node_ids"),
        references=payload.get("pinned_node_references"),
        field_name="pinned_node",
    )
    hidden_node_refs = _entity_ref_list(
        case_id,
        ids=payload.get("hidden_node_ids"),
        references=payload.get("hidden_node_references"),
        field_name="hidden_node",
    )
    selected_entity_ref = _entity_ref_single(
        case_id,
        entity_id=payload.get("selected_entity_id"),
        reference=payload.get("selected_entity_reference"),
        field_name="selected_entity",
    )
    selected_relationship_ref = _relationship_ref_single(
        case_id,
        relationship_id=payload.get("selected_relationship_id"),
        reference=payload.get("selected_relationship_reference"),
        field_name="selected_relationship",
    )

    filters_json = _json_value(payload.get("filters_json"), default={})
    hidden_group_state = _json_value(payload.get("hidden_group_state"), default={})
    time_start = _parse_datetime(payload.get("time_start"), "time_start")
    time_end = _parse_datetime(payload.get("time_end"), "time_end")
    if time_start and time_end and time_start > time_end:
        raise GraphSavedViewError("time_start must be before time_end")

    known_entity_refs = _unique_refs(
        [
            *root_entity_refs,
            *expanded_entity_refs,
            *pinned_node_refs,
            *hidden_node_refs,
            *([selected_entity_ref] if selected_entity_ref else []),
        ]
    )
    node_coordinates = _normalize_node_coordinates(
        case_id,
        payload.get("node_coordinates_json"),
        known_entity_refs=known_entity_refs,
    )

    entity_refs_for_limits = _unique_refs([*known_entity_refs])
    relationship_refs_for_limits = _unique_refs(
        [
            *visible_relationship_refs,
            *([selected_relationship_ref] if selected_relationship_ref else []),
        ]
    )
    if len(entity_refs_for_limits) > MAX_ENTITY_REFS:
        raise GraphSavedViewError(f"Saved view cannot reference more than {MAX_ENTITY_REFS} entities")
    if len(relationship_refs_for_limits) > MAX_RELATIONSHIP_REFS:
        raise GraphSavedViewError(
            f"Saved view cannot reference more than {MAX_RELATIONSHIP_REFS} relationships"
        )

    view_state = {
        "projection_contract_version": PROJECTION_CONTRACT_VERSION,
        "root_entity_references": root_entity_refs,
        "expanded_entity_references": expanded_entity_refs,
        "visible_relationship_references": visible_relationship_refs,
        "filters": filters_json,
        "time_start": time_start.isoformat() if time_start else None,
        "time_end": time_end.isoformat() if time_end else None,
        "pinned_node_references": pinned_node_refs,
        "hidden_node_references": hidden_node_refs,
        "hidden_group_state": hidden_group_state,
        "node_coordinates": node_coordinates,
        "selected_entity_reference": selected_entity_ref,
        "selected_relationship_reference": selected_relationship_ref,
    }
    canonical_state = canonical_json(view_state)
    if len(canonical_state.encode("utf-8")) > MAX_VIEW_STATE_BYTES:
        raise GraphSavedViewError("Saved view state exceeds 1 MiB")

    fingerprint_entries = []
    for ref in _unique_refs([*known_entity_refs]):
        fingerprint_entries.append(
            membership_fingerprint_entry(
                kind="entity",
                stable_reference_key=ref["stable_reference_key"],
            )
        )
    for ref in relationship_refs_for_limits:
        fingerprint_entries.append(
            membership_fingerprint_entry(
                kind="relationship",
                stable_reference_key=ref["stable_reference_key"],
            )
        )

    return {
        "root_entity_references": root_entity_refs,
        "expanded_entity_references": expanded_entity_refs,
        "visible_relationship_references": visible_relationship_refs,
        "filters_json": filters_json,
        "time_start": time_start,
        "time_end": time_end,
        "pinned_node_references": pinned_node_refs,
        "hidden_node_references": hidden_node_refs,
        "hidden_group_state": hidden_group_state,
        "node_coordinates_json": node_coordinates,
        "selected_entity_reference": selected_entity_ref,
        "selected_relationship_reference": selected_relationship_ref,
        "evidence_set_fingerprint": evidence_set_fingerprint(fingerprint_entries),
        "view_state_json": view_state,
        "view_state_sha256": snapshot_sha256(view_state),
    }


def _entity_ref_list(case_id: int, *, ids: Any, references: Any, field_name: str) -> list[dict[str, Any]]:
    refs: list[dict[str, Any]] = []
    if ids not in (None, ""):
        for entity_id in _as_list(ids, field_name=f"{field_name}_ids"):
            entity = require_graph_entity(case_id, entity_id)
            refs.append(entity_reference_from_graph_entity(entity))
    if references not in (None, ""):
        for reference in _as_list(references, field_name=f"{field_name}_references"):
            refs.append(_normalize_entity_reference(case_id, reference))
    return _unique_refs(refs)


def _relationship_ref_list(case_id: int, *, ids: Any, references: Any, field_name: str) -> list[dict[str, Any]]:
    refs: list[dict[str, Any]] = []
    if ids not in (None, ""):
        for relationship_id in _as_list(ids, field_name=f"{field_name}_ids"):
            relationship, source, target = require_graph_relationship(case_id, relationship_id)
            refs.append(
                relationship_reference_from_graph_relationship(
                    relationship,
                    source_entity=source,
                    target_entity=target,
                )
            )
    if references not in (None, ""):
        for reference in _as_list(references, field_name=f"{field_name}_references"):
            refs.append(_normalize_relationship_reference(case_id, reference))
    return _unique_refs(refs)


def _entity_ref_single(case_id: int, *, entity_id: Any, reference: Any, field_name: str) -> dict[str, Any] | None:
    if entity_id not in (None, ""):
        entity = require_graph_entity(case_id, entity_id)
        return entity_reference_from_graph_entity(entity)
    if reference not in (None, ""):
        return _normalize_entity_reference(case_id, reference)
    return None


def _relationship_ref_single(
    case_id: int,
    *,
    relationship_id: Any,
    reference: Any,
    field_name: str,
) -> dict[str, Any] | None:
    if relationship_id not in (None, ""):
        relationship, source, target = require_graph_relationship(case_id, relationship_id)
        return relationship_reference_from_graph_relationship(
            relationship,
            source_entity=source,
            target_entity=target,
        )
    if reference not in (None, ""):
        return _normalize_relationship_reference(case_id, reference)
    return None


def _normalize_entity_reference(case_id: int, reference: Any) -> dict[str, Any]:
    if not isinstance(reference, dict):
        raise InvestigationReferenceError("Entity reference must be an object")
    _validate_reference_case(case_id, reference)
    return build_entity_reference(
        case_id=case_id,
        entity_type=reference.get("entity_type"),
        entity_key=reference.get("entity_key"),
    )


def _normalize_relationship_reference(case_id: int, reference: Any) -> dict[str, Any]:
    if not isinstance(reference, dict):
        raise InvestigationReferenceError("Relationship reference must be an object")
    _validate_reference_case(case_id, reference)
    return build_relationship_reference(
        case_id=case_id,
        source_entity_type=reference.get("source_entity_type"),
        source_entity_key=reference.get("source_entity_key"),
        relationship_type=reference.get("relationship_type"),
        target_entity_type=reference.get("target_entity_type"),
        target_entity_key=reference.get("target_entity_key"),
        derivation_type=reference.get("derivation_type"),
    )


def _normalize_node_coordinates(
    case_id: int,
    value: Any,
    *,
    known_entity_refs: list[dict[str, Any]],
) -> dict[str, dict[str, float]]:
    if value in (None, ""):
        return {}
    if not isinstance(value, dict):
        raise GraphSavedViewError("node_coordinates_json must be an object")

    known_keys = {ref["stable_reference_key"] for ref in known_entity_refs}
    coordinates: dict[str, dict[str, float]] = {}
    for raw_key, raw_coords in value.items():
        stable_key = _coordinate_stable_key(case_id, raw_key, known_keys)
        if not isinstance(raw_coords, dict):
            raise GraphSavedViewError("node coordinate values must be objects")
        coordinates[stable_key] = {
            "x": _finite_number(raw_coords.get("x"), "node coordinate x"),
            "y": _finite_number(raw_coords.get("y"), "node coordinate y"),
        }
    return dict(sorted(coordinates.items(), key=lambda item: item[0]))


def _coordinate_stable_key(case_id: int, raw_key: Any, known_keys: set[str]) -> str:
    key = str(raw_key or "").strip()
    if not key:
        raise GraphSavedViewError("node coordinate key is required")
    if _is_int_like(key):
        entity = require_graph_entity(case_id, int(key))
        stable_key = entity_reference_from_graph_entity(entity)["stable_reference_key"]
        if stable_key not in known_keys:
            raise GraphSavedViewError("node coordinate entity must also be present in saved entity references")
        return stable_key
    if key in known_keys:
        return key
    if _THREADREF_RE.fullmatch(key):
        raise GraphSavedViewError("node coordinate stable keys must also be present in saved entity references")
    raise GraphSavedViewError("node coordinate keys must be entity IDs or stable reference keys")


def _live_resolution(case_id: int, state: dict[str, Any]) -> dict[str, Any]:
    entity_refs = _state_entity_references(state)
    relationship_refs = _state_relationship_references(state)
    entity_resolution: dict[str, int | None] = {}
    relationship_resolution: dict[str, int | None] = {}
    unresolved_entities: list[dict[str, Any]] = []
    unresolved_relationships: list[dict[str, Any]] = []

    for ref in entity_refs:
        stable_key = ref["stable_reference_key"]
        if stable_key in entity_resolution:
            continue
        entity, live_available = resolve_entity_reference(case_id, ref)
        entity_resolution[stable_key] = entity.id if live_available and entity is not None else None
        if not live_available:
            unresolved_entities.append(ref)

    for ref in relationship_refs:
        stable_key = ref["stable_reference_key"]
        if stable_key in relationship_resolution:
            continue
        relationship, live_available, _source, _target = resolve_relationship_reference(case_id, ref)
        relationship_resolution[stable_key] = (
            relationship.id if live_available and relationship is not None else None
        )
        if not live_available:
            unresolved_relationships.append(ref)

    return {
        "live_resolution": {
            "entities": entity_resolution,
            "relationships": relationship_resolution,
        },
        "unresolved_entity_references": unresolved_entities,
        "unresolved_relationship_references": unresolved_relationships,
    }


def _state_entity_references(state: dict[str, Any]) -> list[dict[str, Any]]:
    refs = []
    for key in (
        "root_entity_references",
        "expanded_entity_references",
        "pinned_node_references",
        "hidden_node_references",
    ):
        refs.extend(ref for ref in state.get(key) or [] if isinstance(ref, dict))
    selected = state.get("selected_entity_reference")
    if isinstance(selected, dict):
        refs.append(selected)
    return _unique_refs(refs)


def _state_relationship_references(state: dict[str, Any]) -> list[dict[str, Any]]:
    refs = [ref for ref in state.get("visible_relationship_references") or [] if isinstance(ref, dict)]
    selected = state.get("selected_relationship_reference")
    if isinstance(selected, dict):
        refs.append(selected)
    return _unique_refs(refs)


def _view_dict(view: GraphSavedView, *, include_state: bool) -> dict[str, Any]:
    payload = {
        "id": view.id,
        "uuid": view.uuid,
        "case_id": view.case_id,
        "title": view.title,
        "description": view.description,
        "projection_contract_version": view.projection_contract_version,
        "evidence_set_fingerprint": view.evidence_set_fingerprint,
        "view_state_sha256": view.view_state_sha256,
        "version": view.version,
        "created_by_user_id": view.created_by_user_id,
        "created_by_username": view.created_by_username,
        "created_at": view.created_at.isoformat() if view.created_at else None,
        "updated_by_user_id": view.updated_by_user_id,
        "updated_by_username": view.updated_by_username,
        "updated_at": view.updated_at.isoformat() if view.updated_at else None,
    }
    if include_state:
        payload.update(
            {
                "root_entity_references": view.root_entity_references or [],
                "expanded_entity_references": view.expanded_entity_references or [],
                "visible_relationship_references": view.visible_relationship_references or [],
                "filters_json": view.filters_json or {},
                "time_start": view.time_start.isoformat() if view.time_start else None,
                "time_end": view.time_end.isoformat() if view.time_end else None,
                "pinned_node_references": view.pinned_node_references or [],
                "hidden_node_references": view.hidden_node_references or [],
                "hidden_group_state": view.hidden_group_state or {},
                "node_coordinates_json": view.node_coordinates_json or {},
                "selected_entity_reference": view.selected_entity_reference,
                "selected_relationship_reference": view.selected_relationship_reference,
                "view_state_json": view.view_state_json or {},
            }
        )
    return payload


def _audit_details(view: GraphSavedView, *, action: str) -> dict[str, Any]:
    return {
        "action": action,
        "case_id": view.case_id,
        "view_uuid": view.uuid,
        "version": view.version,
        "view_state_sha256": view.view_state_sha256,
        "evidence_set_fingerprint": view.evidence_set_fingerprint,
        "entity_reference_count": len(_state_entity_references(view.view_state_json or {})),
        "relationship_reference_count": len(_state_relationship_references(view.view_state_json or {})),
    }


def _get_view_or_404(case_id: int, view_uuid: Any) -> GraphSavedView:
    view = GraphSavedView.query.filter_by(case_id=case_id, uuid=str(view_uuid or "").strip()).first()
    if view is None:
        raise GraphSavedViewNotFoundError("Saved graph view not found")
    return view


def _case_uuid(case_id: int) -> str | None:
    from models.case import Case

    case_uuid = db.session.query(Case.uuid).filter(Case.id == case_id).scalar()
    return str(case_uuid) if case_uuid else None


def _actor_info(actor: Any) -> dict[str, Any]:
    if actor is None:
        return {"user_id": None, "username": "system"}
    if isinstance(actor, dict):
        username = actor.get("username") or actor.get("name") or actor.get("email")
        user_id = actor.get("id") or actor.get("user_id")
    else:
        username = getattr(actor, "username", None) or getattr(actor, "name", None) or getattr(actor, "email", None)
        user_id = getattr(actor, "id", None) or getattr(actor, "user_id", None)
    username = str(username or "system").strip() or "system"
    try:
        user_id = int(user_id) if user_id not in (None, "") else None
    except (TypeError, ValueError):
        user_id = None
    return {"user_id": user_id, "username": username[:80]}


def _validate_title(title: Any) -> str:
    value = str(title or "").strip()
    if not value:
        raise GraphSavedViewError("title is required")
    if len(value) > TITLE_MAX:
        raise GraphSavedViewError(f"title cannot exceed {TITLE_MAX} characters")
    return value


def _validate_description(description: Any) -> str | None:
    if description is None:
        return None
    value = str(description)
    if len(value) > DESCRIPTION_MAX:
        raise GraphSavedViewError(f"description cannot exceed {DESCRIPTION_MAX} characters")
    return value


def _case_id(value: Any) -> int:
    try:
        case_id = int(value)
    except (TypeError, ValueError) as exc:
        raise GraphSavedViewError("Invalid case_id") from exc
    if case_id < 1:
        raise GraphSavedViewError("Invalid case_id")
    return case_id


def _expected_version(value: Any) -> int:
    try:
        version = int(value)
    except (TypeError, ValueError) as exc:
        raise GraphSavedViewError("expected_version is required") from exc
    if version < 1:
        raise GraphSavedViewError("expected_version must be positive")
    return version


def _limit(value: Any, *, default: int, maximum: int) -> int:
    if value in (None, ""):
        return default
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise GraphSavedViewError("Invalid limit") from exc
    if parsed < 1:
        raise GraphSavedViewError("Limit must be positive")
    return min(parsed, maximum)


def _offset(value: Any) -> int:
    if value in (None, ""):
        return 0
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise GraphSavedViewError("Invalid offset") from exc
    if parsed < 0:
        raise GraphSavedViewError("offset must be non-negative")
    return parsed


def _as_list(value: Any, *, field_name: str) -> list[Any]:
    if value in (None, ""):
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    raise GraphSavedViewError(f"{field_name} must be a list")


def _unique_refs(refs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen = set()
    unique = []
    for ref in refs:
        stable_key = ref.get("stable_reference_key")
        if not stable_key or stable_key in seen:
            continue
        seen.add(stable_key)
        unique.append(ref)
    return unique


def _validate_reference_case(case_id: int, reference: dict[str, Any]) -> None:
    reference_case_id = reference.get("case_id")
    if reference_case_id in (None, ""):
        return
    try:
        parsed = int(reference_case_id)
    except (TypeError, ValueError) as exc:
        raise InvestigationReferenceError("Invalid reference case_id") from exc
    if parsed != int(case_id):
        raise InvestigationReferenceError("Reference case_id mismatch")


def _json_value(value: Any, *, default: Any) -> Any:
    if value is None:
        return default.copy() if isinstance(default, dict) else list(default)
    canonical_json(value)
    return value


def _parse_datetime(value: Any, field_name: str) -> datetime | None:
    if value in (None, ""):
        return None
    if isinstance(value, datetime):
        return value
    if not isinstance(value, str):
        raise GraphSavedViewError(f"{field_name} must be an ISO datetime string")
    raw = value.strip()
    if raw.endswith("Z"):
        raw = f"{raw[:-1]}+00:00"
    try:
        parsed = datetime.fromisoformat(raw)
    except ValueError as exc:
        raise GraphSavedViewError(f"{field_name} must be an ISO datetime string") from exc
    if parsed.tzinfo is not None:
        return parsed.astimezone(timezone.utc).replace(tzinfo=None)
    return parsed


def _finite_number(value: Any, field_name: str) -> float:
    try:
        parsed = float(value)
    except (TypeError, ValueError) as exc:
        raise GraphSavedViewError(f"{field_name} must be a finite number") from exc
    if not math.isfinite(parsed):
        raise GraphSavedViewError(f"{field_name} must be a finite number")
    return parsed


def _is_int_like(value: str) -> bool:
    return bool(re.fullmatch(r"[0-9]+", value))


def _resolved_ids(refs: Any, resolution: dict[str, int | None]) -> list[int]:
    ids = []
    for ref in refs or []:
        if not isinstance(ref, dict):
            continue
        resolved_id = resolution.get(ref.get("stable_reference_key"))
        if resolved_id is not None:
            ids.append(resolved_id)
    return ids


__all__ = [
    "DESCRIPTION_MAX",
    "LIST_DEFAULT",
    "LIST_MAX",
    "MAX_ENTITY_REFS",
    "MAX_RELATIONSHIP_REFS",
    "MAX_VIEW_STATE_BYTES",
    "PROJECTION_CONTRACT_VERSION",
    "TITLE_MAX",
    "GraphSavedViewConflictError",
    "GraphSavedViewError",
    "GraphSavedViewNotFoundError",
    "GraphSavedViewService",
    "GraphNotFoundError",
    "GraphQueryError",
]
