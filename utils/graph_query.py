"""Bounded read/query service for the canonical investigation graph."""
from __future__ import annotations

import json
import re
from collections import deque
from datetime import date, datetime
from typing import Any, Iterable

from sqlalchemy import and_, case, func, or_
from sqlalchemy.orm import aliased

from models.database import db
from models.graph import GraphEntity, GraphEntityObservation, GraphRelationship, GraphRelationshipEvidence
from utils.graph_identity import GraphEntityType, GraphRelationshipType, GraphValidationState


EVIDENCE_RECORD_KEY_RE = re.compile(r"^erk:v2:[0-9a-f]{64}$")

DEFAULT_SEARCH_LIMIT = 25
MAX_SEARCH_LIMIT = 50
DEFAULT_NEIGHBOR_LIMIT = 100
MAX_NEIGHBOR_LIMIT = 200
DEFAULT_EVIDENCE_LIMIT = 50
MAX_EVIDENCE_LIMIT = 200
MAX_PATH_DEPTH = 4
MAX_PATHS = 10
MAX_VISITED_NODES = 2000
MAX_PATH_FRONTIER = 500
MAX_PATH_EDGES_PER_NODE = 250

EVIDENCE_EVENT_COLUMNS = (
    "timestamp",
    "timestamp_utc",
    "selector_key",
    "artifact_type",
    "source_file",
    "source_path",
    "source_host",
    "event_id",
    "channel",
    "provider",
    "record_id",
    "level",
    "username",
    "domain",
    "sid",
    "logon_type",
    "process_name",
    "process_path",
    "process_id",
    "parent_process",
    "parent_pid",
    "command_line",
    "target_path",
    "file_hash_md5",
    "file_hash_sha1",
    "file_hash_sha256",
    "file_size",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "reg_key",
    "reg_value",
    "reg_data",
    "raw_json",
    "extra_fields",
    "search_blob",
    "parser_version",
    "evidence_record_key",
    "evidence_identity_version",
    "evidence_identity_quality",
)


class GraphQueryError(ValueError):
    """Raised for client-correctable graph query errors."""


class GraphNotFoundError(GraphQueryError):
    """Raised when a case-scoped graph object is absent."""


def _json_safe(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    if hasattr(value, "packed"):
        return str(value)
    if isinstance(value, tuple):
        return [_json_safe(item) for item in value]
    if isinstance(value, list):
        return [_json_safe(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}
    return value


def _metadata(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    return {}


def _limit(value: Any, *, default: int, maximum: int) -> int:
    if value in (None, ""):
        return default
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        raise GraphQueryError("Invalid limit")
    if parsed < 1:
        raise GraphQueryError("Limit must be positive")
    return min(parsed, maximum)


def _non_negative_int(value: Any, *, name: str) -> int:
    if value in (None, ""):
        return 0
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        raise GraphQueryError(f"Invalid {name}")
    if parsed < 0:
        raise GraphQueryError(f"{name} must be non-negative")
    return parsed


def _bounded_int(value: Any, *, name: str, default: int, minimum: int, maximum: int) -> int:
    if value in (None, ""):
        return default
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        raise GraphQueryError(f"Invalid {name}")
    if parsed < minimum or parsed > maximum:
        raise GraphQueryError(f"{name} must be between {minimum} and {maximum}")
    return parsed


def _split_filter_values(values: Any) -> list[str]:
    if values in (None, ""):
        return []
    if isinstance(values, str):
        raw_values = values.split(",")
    else:
        raw_values = []
        for value in values:
            raw_values.extend(str(value or "").split(","))
    return [value.strip() for value in raw_values if value and value.strip()]


def _validate_entity_types(values: Any) -> list[str]:
    entity_types = _split_filter_values(values)
    invalid = [value for value in entity_types if value not in GraphEntityType.ALL]
    if invalid:
        raise GraphQueryError(f"Invalid entity type: {invalid[0]}")
    return sorted(set(entity_types))


def _validate_relationship_types(values: Any) -> list[str]:
    relationship_types = _split_filter_values(values)
    invalid = [value for value in relationship_types if value not in GraphRelationshipType.ALL]
    if invalid:
        raise GraphQueryError(f"Invalid relationship type: {invalid[0]}")
    return sorted(set(relationship_types))


def _validate_direction(direction: Any) -> str:
    value = str(direction or "both").strip().lower()
    if value not in {"both", "in", "out"}:
        raise GraphQueryError("Invalid direction")
    return value


def _like_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _entity_dict(entity: GraphEntity) -> dict[str, Any]:
    return {
        "id": entity.id,
        "entity_type": entity.entity_type,
        "entity_key": entity.entity_key,
        "display_value": entity.display_value,
        "canonical_value": entity.canonical_value,
        "first_seen_at": _json_safe(entity.first_seen_at),
        "last_seen_at": _json_safe(entity.last_seen_at),
        "metadata": _metadata(entity.metadata_json),
    }


def _relationship_dict(relationship: GraphRelationship, support_count: int | None = None) -> dict[str, Any]:
    payload = {
        "id": relationship.id,
        "source_entity_id": relationship.source_entity_id,
        "target_entity_id": relationship.target_entity_id,
        "relationship_type": relationship.relationship_type,
        "derivation_type": relationship.derivation_type,
        "validation_state": relationship.validation_state,
        "confidence": relationship.confidence,
        "first_seen_at": _json_safe(relationship.first_seen_at),
        "last_seen_at": _json_safe(relationship.last_seen_at),
        "metadata": _metadata(relationship.metadata_json),
    }
    if support_count is not None:
        payload["support_count"] = int(support_count or 0)
    return payload


def _evidence_dict(evidence: GraphRelationshipEvidence) -> dict[str, Any]:
    return {
        "id": evidence.id,
        "relationship_id": evidence.relationship_id,
        "evidence_record_key": evidence.evidence_record_key,
        "observed_at": _json_safe(evidence.observed_at),
        "source_table": evidence.source_table,
        "evidence_role": evidence.evidence_role,
        "extractor_name": evidence.extractor_name,
        "extractor_version": evidence.extractor_version,
        "metadata": _metadata(evidence.metadata_json),
    }


class GraphQueryService:
    """Repository-testable read service for Phase 0C graph APIs."""

    def graph_summary(self, case_id: int) -> dict[str, Any]:
        entity_rows = (
            db.session.query(GraphEntity.entity_type, func.count(GraphEntity.id))
            .filter(GraphEntity.case_id == case_id)
            .group_by(GraphEntity.entity_type)
            .order_by(GraphEntity.entity_type.asc())
            .all()
        )
        relationship_rows = (
            db.session.query(GraphRelationship.relationship_type, func.count(GraphRelationship.id))
            .filter(GraphRelationship.case_id == case_id)
            .group_by(GraphRelationship.relationship_type)
            .order_by(GraphRelationship.relationship_type.asc())
            .all()
        )
        validation_rows = (
            db.session.query(GraphRelationship.validation_state, func.count(GraphRelationship.id))
            .filter(GraphRelationship.case_id == case_id)
            .group_by(GraphRelationship.validation_state)
            .order_by(GraphRelationship.validation_state.asc())
            .all()
        )
        entity_counts = {row[0]: int(row[1]) for row in entity_rows}
        relationship_counts = {row[0]: int(row[1]) for row in relationship_rows}
        validation_counts = {row[0]: int(row[1]) for row in validation_rows}
        return {
            "total_entities": sum(entity_counts.values()),
            "entity_counts": entity_counts,
            "total_relationships": sum(relationship_counts.values()),
            "relationship_counts": relationship_counts,
            "validation_counts": validation_counts,
            "active_relationships": validation_counts.get(GraphValidationState.ACTIVE, 0),
            "invalidated_relationships": validation_counts.get(GraphValidationState.INVALIDATED, 0),
        }

    def search_entities(
        self,
        case_id: int,
        *,
        q: str = "",
        entity_types: Any = None,
        limit: Any = None,
    ) -> dict[str, Any]:
        effective_limit = _limit(limit, default=DEFAULT_SEARCH_LIMIT, maximum=MAX_SEARCH_LIMIT)
        entity_type_values = _validate_entity_types(entity_types)
        query_text = str(q or "").strip()
        if len(query_text) > 200:
            raise GraphQueryError("Search query is too long")
        if not query_text:
            return {"entities": [], "limit": effective_limit, "has_more": False}

        normalized = query_text.lower()
        escaped = _like_escape(normalized)
        canonical_lower = func.lower(func.coalesce(GraphEntity.canonical_value, ""))
        display_lower = func.lower(func.coalesce(GraphEntity.display_value, ""))
        key_lower = func.lower(func.coalesce(GraphEntity.entity_key, ""))
        rank_expr = case(
            (
                or_(canonical_lower == normalized, display_lower == normalized, key_lower == normalized),
                0,
            ),
            (
                or_(
                    canonical_lower.like(f"{escaped}%", escape="\\"),
                    display_lower.like(f"{escaped}%", escape="\\"),
                    key_lower.like(f"{escaped}%", escape="\\"),
                ),
                1,
            ),
            else_=2,
        )

        query = GraphEntity.query.filter(GraphEntity.case_id == case_id)
        if entity_type_values:
            query = query.filter(GraphEntity.entity_type.in_(entity_type_values))
        query = query.filter(
            or_(
                canonical_lower.like(f"%{escaped}%", escape="\\"),
                display_lower.like(f"%{escaped}%", escape="\\"),
                key_lower.like(f"%{escaped}%", escape="\\"),
            )
        )
        rows = (
            query.order_by(rank_expr.asc(), GraphEntity.entity_type.asc(), GraphEntity.canonical_value.asc(), GraphEntity.id.asc())
            .limit(effective_limit + 1)
            .all()
        )
        return {
            "entities": [_entity_dict(entity) for entity in rows[:effective_limit]],
            "limit": effective_limit,
            "has_more": len(rows) > effective_limit,
        }

    def entity_detail(self, case_id: int, entity_id: int) -> dict[str, Any]:
        entity = self._get_entity(case_id, entity_id)
        active_filter = GraphRelationship.validation_state == GraphValidationState.ACTIVE
        outgoing = GraphRelationship.query.filter(
            GraphRelationship.case_id == case_id,
            GraphRelationship.source_entity_id == entity.id,
            active_filter,
        ).count()
        incoming = GraphRelationship.query.filter(
            GraphRelationship.case_id == case_id,
            GraphRelationship.target_entity_id == entity.id,
            active_filter,
        ).count()
        observation_count = GraphEntityObservation.query.filter_by(case_id=case_id, entity_id=entity.id).count()
        payload = _entity_dict(entity)
        payload["relationship_counts"] = {
            "incoming": incoming,
            "outgoing": outgoing,
            "total": incoming + outgoing,
        }
        payload["observation_count"] = observation_count
        return payload

    def neighborhood(
        self,
        case_id: int,
        entity_id: int,
        *,
        direction: str = "both",
        relationship_types: Any = None,
        entity_types: Any = None,
        cursor: Any = None,
        limit: Any = None,
        include_invalidated: bool = False,
    ) -> dict[str, Any]:
        root = self._get_entity(case_id, entity_id)
        effective_direction = _validate_direction(direction)
        effective_limit = _limit(limit, default=DEFAULT_NEIGHBOR_LIMIT, maximum=MAX_NEIGHBOR_LIMIT)
        relationship_type_values = _validate_relationship_types(relationship_types)
        entity_type_values = _validate_entity_types(entity_types)
        cursor_id = _non_negative_int(cursor, name="cursor")

        query = GraphRelationship.query.filter(GraphRelationship.case_id == case_id, GraphRelationship.id > cursor_id)
        if not include_invalidated:
            query = query.filter(GraphRelationship.validation_state == GraphValidationState.ACTIVE)
        if relationship_type_values:
            query = query.filter(GraphRelationship.relationship_type.in_(relationship_type_values))
        if effective_direction == "out":
            query = query.filter(GraphRelationship.source_entity_id == entity_id)
        elif effective_direction == "in":
            query = query.filter(GraphRelationship.target_entity_id == entity_id)
        else:
            query = query.filter(or_(GraphRelationship.source_entity_id == entity_id, GraphRelationship.target_entity_id == entity_id))

        if entity_type_values:
            source_alias = aliased(GraphEntity)
            target_alias = aliased(GraphEntity)
            query = query.join(source_alias, GraphRelationship.source_entity_id == source_alias.id)
            query = query.join(target_alias, GraphRelationship.target_entity_id == target_alias.id)
            if effective_direction == "out":
                query = query.filter(target_alias.entity_type.in_(entity_type_values))
            elif effective_direction == "in":
                query = query.filter(source_alias.entity_type.in_(entity_type_values))
            else:
                query = query.filter(
                    or_(
                        and_(GraphRelationship.source_entity_id == entity_id, target_alias.entity_type.in_(entity_type_values)),
                        and_(GraphRelationship.target_entity_id == entity_id, source_alias.entity_type.in_(entity_type_values)),
                    )
                )

        relationships = query.order_by(GraphRelationship.id.asc()).limit(effective_limit + 1).all()
        page_relationships = relationships[:effective_limit]
        has_more = len(relationships) > effective_limit
        nodes = self._entities_for_relationships(case_id, page_relationships, root)
        support_counts = self._support_counts(case_id, [relationship.id for relationship in page_relationships])
        return {
            "root": _entity_dict(root),
            "nodes": [_entity_dict(entity) for entity in nodes],
            "edges": [_relationship_dict(relationship, support_counts.get(relationship.id, 0)) for relationship in page_relationships],
            "pagination": {
                "limit": effective_limit,
                "has_more": has_more,
                "next_cursor": str(page_relationships[-1].id) if has_more and page_relationships else None,
            },
            "truncated": has_more,
        }

    def relationship_detail(self, case_id: int, relationship_id: int) -> dict[str, Any]:
        relationship = self._get_relationship(case_id, relationship_id)
        support_count = GraphRelationshipEvidence.query.filter_by(
            case_id=case_id,
            relationship_id=relationship.id,
        ).count()
        return {
            **_relationship_dict(relationship, support_count),
            "source_entity": _entity_dict(relationship.source_entity),
            "target_entity": _entity_dict(relationship.target_entity),
        }

    def relationship_evidence(
        self,
        case_id: int,
        relationship_id: int,
        *,
        cursor: Any = None,
        offset: Any = None,
        limit: Any = None,
    ) -> dict[str, Any]:
        self._get_relationship(case_id, relationship_id)
        effective_limit = _limit(limit, default=DEFAULT_EVIDENCE_LIMIT, maximum=MAX_EVIDENCE_LIMIT)
        cursor_id = _non_negative_int(cursor, name="cursor")
        offset_count = _non_negative_int(offset, name="offset")
        query = GraphRelationshipEvidence.query.filter_by(case_id=case_id, relationship_id=relationship_id)
        if cursor_id:
            query = query.filter(GraphRelationshipEvidence.id > cursor_id)
        rows = (
            query.order_by(GraphRelationshipEvidence.id.asc())
            .offset(offset_count if not cursor_id else 0)
            .limit(effective_limit + 1)
            .all()
        )
        page_rows = rows[:effective_limit]
        has_more = len(rows) > effective_limit
        return {
            "evidence": [_evidence_dict(row) for row in page_rows],
            "pagination": {
                "limit": effective_limit,
                "has_more": has_more,
                "next_cursor": str(page_rows[-1].id) if has_more and page_rows else None,
                "offset": offset_count,
            },
            "truncated": has_more,
        }

    def exact_evidence(self, case_id: int, evidence_record_key: str, *, client=None) -> dict[str, Any]:
        if not EVIDENCE_RECORD_KEY_RE.fullmatch(str(evidence_record_key or "")):
            raise GraphQueryError("Invalid evidence record key")
        if client is None:
            from utils.clickhouse import get_client

            client = get_client()
        sql = f"""
            SELECT {', '.join(EVIDENCE_EVENT_COLUMNS)}
            FROM events
            WHERE case_id = {{case_id:UInt32}}
              AND evidence_record_key = {{evidence_record_key:String}}
            ORDER BY COALESCE(timestamp_utc, timestamp) ASC, selector_key ASC
            LIMIT 2
        """
        result = client.query(
            sql,
            parameters={"case_id": int(case_id), "evidence_record_key": evidence_record_key},
        )
        rows = list(getattr(result, "result_rows", []) or [])
        if not rows:
            raise GraphNotFoundError("Evidence not found")
        column_names = list(getattr(result, "column_names", []) or EVIDENCE_EVENT_COLUMNS)
        records = [self._event_row_to_dict(row, column_names) for row in rows]
        primary = records[0]
        return {
            "evidence_record_key": evidence_record_key,
            "event": primary,
            "selector_key": primary.get("selector_key") or "",
            "duplicates_detected": len(records) > 1,
            "duplicate_rows_returned": len(records),
            "duplicate_policy": "ERK identifies one evidence record; duplicate physical rows are reported, not treated as distinct graph evidence.",
            "records": records,
        }

    def path_search(
        self,
        case_id: int,
        *,
        source_entity_id: Any,
        target_entity_id: Any,
        direction: str = "both",
        max_depth: Any = 3,
        max_paths: Any = 3,
        relationship_types: Any = None,
    ) -> dict[str, Any]:
        try:
            source_id = int(source_entity_id)
            target_id = int(target_entity_id)
        except (TypeError, ValueError):
            raise GraphQueryError("Invalid source or target entity")
        self._get_entity(case_id, source_id)
        self._get_entity(case_id, target_id)
        effective_direction = _validate_direction(direction)
        requested_depth = _bounded_int(max_depth, name="max_depth", default=3, minimum=1, maximum=MAX_PATH_DEPTH)
        requested_paths = _bounded_int(max_paths, name="max_paths", default=3, minimum=1, maximum=MAX_PATHS)
        relationship_type_values = _validate_relationship_types(relationship_types)

        if source_id == target_id:
            node = self._get_entity(case_id, source_id)
            return {
                "paths": [{"node_ids": [source_id], "edge_ids": []}],
                "nodes": [_entity_dict(node)],
                "edges": [],
                "effective_limits": self._path_limits(requested_depth, requested_paths),
                "visited_node_count": 1,
                "examined_edge_count": 0,
                "truncated": False,
                "truncation_reason": None,
                "result_statement": "Graph path from entity to itself.",
            }

        paths: list[dict[str, list[int]]] = []
        visited_nodes: set[int] = {source_id}
        frontier = deque([(source_id, [source_id], [])])
        truncated = False
        truncation_reason = None
        examined_edge_count = 0

        while frontier and not truncated:
            if len(paths) >= requested_paths:
                truncated = bool(frontier)
                truncation_reason = "max_paths reached" if truncated else None
                break
            current_id, path_node_ids, path_edge_ids = frontier.popleft()
            current_depth = len(path_edge_ids)
            if current_depth >= requested_depth:
                continue
            if len(frontier) > MAX_PATH_FRONTIER:
                truncated = True
                truncation_reason = "frontier limit reached"
                break
            relationships, node_truncated = self._path_neighbor_edges(
                case_id,
                current_id,
                direction=effective_direction,
                relationship_types=relationship_type_values,
            )
            if node_truncated:
                truncated = True
                truncation_reason = "per-node expansion limit reached"
            examined_edge_count += len(relationships)
            for relationship in relationships:
                next_id = self._next_node_for_path(current_id, relationship, effective_direction)
                if next_id is None or next_id in path_node_ids:
                    continue
                next_node_path = path_node_ids + [next_id]
                next_edge_path = path_edge_ids + [relationship.id]
                if next_id == target_id:
                    paths.append({"node_ids": next_node_path, "edge_ids": next_edge_path})
                    if len(paths) >= requested_paths:
                        break
                elif len(next_edge_path) < requested_depth:
                    frontier.append((next_id, next_node_path, next_edge_path))
                    visited_nodes.add(next_id)
                    if len(visited_nodes) > MAX_VISITED_NODES:
                        truncated = True
                        truncation_reason = "visited node limit reached"
                        break

        result_node_ids: set[int] = set()
        result_edge_ids: set[int] = set()
        for path in paths:
            result_node_ids.update(path["node_ids"])
            result_edge_ids.update(path["edge_ids"])
        if not paths:
            result_node_ids.update({source_id, target_id})

        entities = GraphEntity.query.filter(GraphEntity.case_id == case_id, GraphEntity.id.in_(result_node_ids)).all()
        relationships = GraphRelationship.query.filter(
            GraphRelationship.case_id == case_id,
            GraphRelationship.id.in_(result_edge_ids),
        ).all() if result_edge_ids else []
        support_counts = self._support_counts(case_id, [relationship.id for relationship in relationships])
        statement = (
            f"Found {len(paths)} graph path(s) within depth {requested_depth}."
            if paths
            else f"No path found within depth {requested_depth}."
        )
        if truncated and not paths:
            statement = f"No path found within depth {requested_depth} before traversal limits were reached."
        return {
            "paths": paths,
            "nodes": [_entity_dict(entity) for entity in sorted(entities, key=lambda item: item.id)],
            "edges": [_relationship_dict(relationship, support_counts.get(relationship.id, 0)) for relationship in sorted(relationships, key=lambda item: item.id)],
            "effective_limits": self._path_limits(requested_depth, requested_paths),
            "visited_node_count": len(visited_nodes),
            "examined_edge_count": examined_edge_count,
            "truncated": truncated,
            "truncation_reason": truncation_reason,
            "result_statement": statement,
        }

    def _get_entity(self, case_id: int, entity_id: int) -> GraphEntity:
        entity = GraphEntity.query.filter_by(case_id=case_id, id=entity_id).first()
        if entity is None:
            raise GraphNotFoundError("Entity not found")
        return entity

    def _get_relationship(self, case_id: int, relationship_id: int) -> GraphRelationship:
        relationship = GraphRelationship.query.filter_by(case_id=case_id, id=relationship_id).first()
        if relationship is None:
            raise GraphNotFoundError("Relationship not found")
        return relationship

    def _entities_for_relationships(
        self,
        case_id: int,
        relationships: Iterable[GraphRelationship],
        root: GraphEntity,
    ) -> list[GraphEntity]:
        ids = {root.id}
        for relationship in relationships:
            ids.add(relationship.source_entity_id)
            ids.add(relationship.target_entity_id)
        return (
            GraphEntity.query.filter(GraphEntity.case_id == case_id, GraphEntity.id.in_(ids))
            .order_by(GraphEntity.id.asc())
            .all()
        )

    def _support_counts(self, case_id: int, relationship_ids: list[int]) -> dict[int, int]:
        if not relationship_ids:
            return {}
        rows = (
            db.session.query(GraphRelationshipEvidence.relationship_id, func.count(GraphRelationshipEvidence.id))
            .filter(
                GraphRelationshipEvidence.case_id == case_id,
                GraphRelationshipEvidence.relationship_id.in_(relationship_ids),
            )
            .group_by(GraphRelationshipEvidence.relationship_id)
            .all()
        )
        return {int(row[0]): int(row[1]) for row in rows}

    def _path_neighbor_edges(
        self,
        case_id: int,
        entity_id: int,
        *,
        direction: str,
        relationship_types: list[str],
    ) -> tuple[list[GraphRelationship], bool]:
        query = GraphRelationship.query.filter(
            GraphRelationship.case_id == case_id,
            GraphRelationship.validation_state == GraphValidationState.ACTIVE,
        )
        if relationship_types:
            query = query.filter(GraphRelationship.relationship_type.in_(relationship_types))
        if direction == "out":
            query = query.filter(GraphRelationship.source_entity_id == entity_id)
        elif direction == "in":
            query = query.filter(GraphRelationship.target_entity_id == entity_id)
        else:
            query = query.filter(or_(GraphRelationship.source_entity_id == entity_id, GraphRelationship.target_entity_id == entity_id))
        rows = query.order_by(GraphRelationship.id.asc()).limit(MAX_PATH_EDGES_PER_NODE + 1).all()
        return rows[:MAX_PATH_EDGES_PER_NODE], len(rows) > MAX_PATH_EDGES_PER_NODE

    def _next_node_for_path(self, current_id: int, relationship: GraphRelationship, direction: str) -> int | None:
        if direction == "out":
            return relationship.target_entity_id if relationship.source_entity_id == current_id else None
        if direction == "in":
            return relationship.source_entity_id if relationship.target_entity_id == current_id else None
        if relationship.source_entity_id == current_id:
            return relationship.target_entity_id
        if relationship.target_entity_id == current_id:
            return relationship.source_entity_id
        return None

    def _path_limits(self, max_depth: int, max_paths: int) -> dict[str, int]:
        return {
            "max_depth": max_depth,
            "max_paths": max_paths,
            "max_visited_nodes": MAX_VISITED_NODES,
            "max_frontier": MAX_PATH_FRONTIER,
            "max_edges_per_node": MAX_PATH_EDGES_PER_NODE,
        }

    def _event_row_to_dict(self, row: Any, column_names: list[str]) -> dict[str, Any]:
        event = {column_names[index]: _json_safe(value) for index, value in enumerate(row)}
        for json_field in ("raw_json", "extra_fields"):
            value = event.get(json_field)
            if isinstance(value, str) and value:
                try:
                    event[json_field] = json.loads(value)
                except (TypeError, ValueError, json.JSONDecodeError):
                    pass
        return event

