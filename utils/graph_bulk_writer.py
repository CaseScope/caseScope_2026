"""PostgreSQL COPY/set-based writer for high-volume event graph projection."""
from __future__ import annotations

import csv
import io
import json
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, Iterable, Optional

from models.database import db
from utils.graph_extractors import GraphRelationshipCandidate
from utils.graph_identity import (
    GraphDerivationType,
    GraphSupportState,
    GraphValidationState,
)
from utils.graph_materializer import GraphMaterializer, _coerce_datetime, _merge_metadata
from utils.graph_support_locator import validate_support_provenance

logger = logging.getLogger(__name__)


@dataclass
class BulkGraphWriteStats:
    """Per-batch counters and timings for graph bulk projection."""

    events_read: int = 0
    candidate_relationships: int = 0
    entities_staged: int = 0
    observations_staged: int = 0
    relationships_staged: int = 0
    support_staged: int = 0
    extraction_seconds: float = 0.0
    canonicalization_seconds: float = 0.0
    copy_entities_seconds: float = 0.0
    copy_observations_seconds: float = 0.0
    copy_relationships_seconds: float = 0.0
    copy_support_seconds: float = 0.0
    merge_entities_seconds: float = 0.0
    merge_observations_seconds: float = 0.0
    merge_relationships_seconds: float = 0.0
    merge_support_seconds: float = 0.0
    commit_seconds: float = 0.0
    total_batch_seconds: float = 0.0

    @property
    def events_per_second(self) -> float:
        return self.events_read / self.total_batch_seconds if self.total_batch_seconds else 0.0

    @property
    def supports_per_second(self) -> float:
        return self.support_staged / self.total_batch_seconds if self.total_batch_seconds else 0.0

    def as_dict(self) -> Dict[str, Any]:
        return {
            'events_read': self.events_read,
            'candidate_relationships': self.candidate_relationships,
            'unique_entities_staged': self.entities_staged,
            'observations_staged': self.observations_staged,
            'unique_relationships_staged': self.relationships_staged,
            'support_rows_staged': self.support_staged,
            'extraction_seconds': round(self.extraction_seconds, 6),
            'canonicalization_seconds': round(self.canonicalization_seconds, 6),
            'copy_entities_seconds': round(self.copy_entities_seconds, 6),
            'copy_observations_seconds': round(self.copy_observations_seconds, 6),
            'copy_relationships_seconds': round(self.copy_relationships_seconds, 6),
            'copy_support_seconds': round(self.copy_support_seconds, 6),
            'merge_entities_seconds': round(self.merge_entities_seconds, 6),
            'merge_observations_seconds': round(self.merge_observations_seconds, 6),
            'merge_relationships_seconds': round(self.merge_relationships_seconds, 6),
            'merge_support_seconds': round(self.merge_support_seconds, 6),
            'commit_seconds': round(self.commit_seconds, 6),
            'total_batch_seconds': round(self.total_batch_seconds, 6),
            'events_per_second': round(self.events_per_second, 3),
            'supports_per_second': round(self.supports_per_second, 3),
        }


@dataclass
class _EntityRow:
    case_id: int
    entity_type: str
    entity_key: str
    display_value: str
    canonical_value: str
    first_seen_at: Optional[datetime]
    last_seen_at: Optional[datetime]
    metadata_json: Dict[str, Any] = field(default_factory=dict)


@dataclass
class _ObservationRow:
    case_id: int
    entity_type: str
    entity_key: str
    evidence_record_key: str
    observation_role: str
    observed_value: str
    observed_at: Optional[datetime]
    source_table: str


@dataclass
class _RelationshipRow:
    case_id: int
    source_entity_type: str
    source_entity_key: str
    relationship_type: str
    target_entity_type: str
    target_entity_key: str
    derivation_type: str
    extractor_name: str
    extractor_version: str
    first_seen_at: Optional[datetime]
    last_seen_at: Optional[datetime]
    metadata_json: Dict[str, Any] = field(default_factory=dict)


@dataclass
class _SupportRow:
    case_id: int
    source_entity_type: str
    source_entity_key: str
    relationship_type: str
    target_entity_type: str
    target_entity_key: str
    derivation_type: str
    evidence_record_key: str
    source_table: str
    evidence_role: str
    extractor_name: str
    extractor_version: str
    observed_at: Optional[datetime]
    metadata_json: Dict[str, Any] = field(default_factory=dict)
    source_ref_type: Optional[str] = None
    source_ref_id: Optional[int] = None
    support_locator_json: Optional[Dict[str, Any]] = None


class GraphBulkWriter:
    """Bulk persists event-derived graph facts using PostgreSQL staging tables."""

    def __init__(self, *, materializer: Optional[GraphMaterializer] = None):
        self.materializer = materializer or GraphMaterializer()
        self.last_stats: Optional[BulkGraphWriteStats] = None

    def materialize_candidates(
        self,
        case_id: int,
        candidates: Iterable[GraphRelationshipCandidate],
        *,
        events_read: int = 0,
        extraction_seconds: float = 0.0,
    ) -> BulkGraphWriteStats:
        if getattr(db.engine.dialect, 'name', '') != 'postgresql':
            return self._legacy_materialize_candidates(
                case_id,
                candidates,
                events_read=events_read,
                extraction_seconds=extraction_seconds,
            )

        started = time.monotonic()
        stats = BulkGraphWriteStats(events_read=int(events_read), extraction_seconds=extraction_seconds)
        entities: Dict[tuple, _EntityRow] = {}
        observations: Dict[tuple, _ObservationRow] = {}
        relationships: Dict[tuple, _RelationshipRow] = {}
        support: Dict[tuple, _SupportRow] = {}

        canonical_started = time.monotonic()
        for candidate in candidates:
            self._stage_candidate(case_id, candidate, entities, observations, relationships, support)
            stats.candidate_relationships += 1
        stats.canonicalization_seconds = time.monotonic() - canonical_started
        stats.entities_staged = len(entities)
        stats.observations_staged = len(observations)
        stats.relationships_staged = len(relationships)
        stats.support_staged = len(support)

        if not (entities or observations or relationships or support):
            stats.total_batch_seconds = time.monotonic() - started
            self.last_stats = stats
            return stats

        raw = db.engine.raw_connection()
        try:
            cursor = raw.cursor()
            self._create_temp_tables(cursor)
            stats.copy_entities_seconds = self._copy_rows(cursor, 'tmp_graph_entities', _ENTITY_COLUMNS, entities.values())
            stats.copy_observations_seconds = self._copy_rows(
                cursor,
                'tmp_graph_entity_observations',
                _OBSERVATION_COLUMNS,
                observations.values(),
            )
            stats.copy_relationships_seconds = self._copy_rows(
                cursor,
                'tmp_graph_relationships',
                _RELATIONSHIP_COLUMNS,
                relationships.values(),
            )
            stats.copy_support_seconds = self._copy_rows(
                cursor,
                'tmp_graph_relationship_evidence',
                _SUPPORT_COLUMNS,
                support.values(),
            )
            stats.merge_entities_seconds = self._execute_timed(cursor, _MERGE_ENTITIES_SQL)
            stats.merge_observations_seconds = self._execute_timed(cursor, _MERGE_OBSERVATIONS_SQL)
            stats.merge_relationships_seconds = self._execute_timed(cursor, _MERGE_RELATIONSHIPS_SQL)
            stats.merge_support_seconds = self._execute_timed(cursor, _MERGE_SUPPORT_SQL)
            commit_started = time.monotonic()
            raw.commit()
            stats.commit_seconds = time.monotonic() - commit_started
        except Exception:
            raw.rollback()
            raise
        finally:
            raw.close()

        stats.total_batch_seconds = time.monotonic() - started
        self.last_stats = stats
        logger.info('Graph bulk batch materialized stats=%s', stats.as_dict())
        return stats

    def _legacy_materialize_candidates(
        self,
        case_id: int,
        candidates: Iterable[GraphRelationshipCandidate],
        *,
        events_read: int,
        extraction_seconds: float,
    ) -> BulkGraphWriteStats:
        started = time.monotonic()
        count = self.materializer.materialize_candidates(case_id, candidates)
        db.session.commit()
        stats = BulkGraphWriteStats(
            events_read=int(events_read),
            candidate_relationships=count,
            support_staged=count,
            extraction_seconds=extraction_seconds,
            total_batch_seconds=time.monotonic() - started,
        )
        self.last_stats = stats
        return stats

    def _stage_candidate(
        self,
        case_id: int,
        candidate: GraphRelationshipCandidate,
        entities: Dict[tuple, _EntityRow],
        observations: Dict[tuple, _ObservationRow],
        relationships: Dict[tuple, _RelationshipRow],
        support: Dict[tuple, _SupportRow],
    ) -> None:
        if candidate.case_id != int(case_id):
            raise ValueError('Graph relationship candidate case_id does not match materialization case')
        if candidate.derivation_type not in GraphDerivationType.AUTHORITATIVE_EXTRACTOR_TYPES:
            raise ValueError(f'Authoritative extractor cannot materialize {candidate.derivation_type}')

        support_locator = dict(candidate.support_locator or {})
        validate_support_provenance(
            evidence_record_key=candidate.evidence_record_key,
            source_table=candidate.source_table,
            support_locator=support_locator or None,
        )
        observed_at = _coerce_datetime(candidate.observed_at)
        source_ref_type, source_ref_id = self.materializer._resolve_source_ref(candidate, support_locator)

        source_identity = self.materializer.canonicalize_entity_spec(case_id, candidate.source)
        target_identity = self.materializer.canonicalize_entity_spec(case_id, candidate.target)
        source_key = (case_id, source_identity.entity_type, source_identity.entity_key)
        target_key = (case_id, target_identity.entity_type, target_identity.entity_key)
        self._merge_entity(entities, source_key, source_identity, observed_at)
        self._merge_entity(entities, target_key, target_identity, observed_at)

        self._add_observation(
            observations,
            source_key,
            evidence_record_key=candidate.evidence_record_key,
            observation_role='relationship_source',
            source_table=candidate.source_table,
            observed_at=observed_at,
            observed_value=candidate.source.raw_value,
        )
        self._add_observation(
            observations,
            target_key,
            evidence_record_key=candidate.evidence_record_key,
            observation_role='relationship_target',
            source_table=candidate.source_table,
            observed_at=observed_at,
            observed_value=candidate.target.raw_value,
        )

        relationship_key = (
            case_id,
            source_identity.entity_type,
            source_identity.entity_key,
            candidate.relationship_type,
            target_identity.entity_type,
            target_identity.entity_key,
            candidate.derivation_type,
        )
        self._merge_relationship(
            relationships,
            relationship_key,
            candidate,
            source_identity,
            target_identity,
            observed_at,
        )

        support_key = (
            *relationship_key,
            candidate.evidence_record_key,
            candidate.evidence_role,
            candidate.extractor_name,
            candidate.extractor_version,
        )
        existing = support.get(support_key)
        metadata = _merge_metadata({}, candidate.metadata)
        if existing is None:
            support[support_key] = _SupportRow(
                case_id=case_id,
                source_entity_type=source_identity.entity_type,
                source_entity_key=source_identity.entity_key,
                relationship_type=candidate.relationship_type,
                target_entity_type=target_identity.entity_type,
                target_entity_key=target_identity.entity_key,
                derivation_type=candidate.derivation_type,
                evidence_record_key=candidate.evidence_record_key,
                source_table=candidate.source_table,
                evidence_role=candidate.evidence_role,
                extractor_name=candidate.extractor_name,
                extractor_version=candidate.extractor_version,
                observed_at=observed_at,
                metadata_json=metadata,
                source_ref_type=source_ref_type or None,
                source_ref_id=source_ref_id,
                support_locator_json=support_locator or None,
            )
        else:
            existing.metadata_json = _merge_metadata(existing.metadata_json, metadata)
            if source_ref_type:
                existing.source_ref_type = source_ref_type
                existing.source_ref_id = source_ref_id
            if support_locator:
                existing.support_locator_json = support_locator
            if existing.observed_at is None:
                existing.observed_at = observed_at

    def _merge_entity(self, rows: Dict[tuple, _EntityRow], key: tuple, identity, observed_at: Optional[datetime]) -> None:
        existing = rows.get(key)
        if existing is None:
            rows[key] = _EntityRow(
                case_id=key[0],
                entity_type=identity.entity_type,
                entity_key=identity.entity_key,
                display_value=identity.display_value,
                canonical_value=identity.canonical_value,
                first_seen_at=observed_at,
                last_seen_at=observed_at,
                metadata_json=_merge_metadata({}, identity.metadata),
            )
            return
        existing.metadata_json = _merge_metadata(existing.metadata_json, identity.metadata)
        existing.first_seen_at = _earliest(existing.first_seen_at, observed_at)
        existing.last_seen_at = _latest(existing.last_seen_at, observed_at)

    def _add_observation(
        self,
        rows: Dict[tuple, _ObservationRow],
        entity_key: tuple,
        *,
        evidence_record_key: str,
        observation_role: str,
        source_table: str,
        observed_at: Optional[datetime],
        observed_value: str,
    ) -> None:
        key = (*entity_key, evidence_record_key, observation_role, source_table)
        if key in rows:
            return
        rows[key] = _ObservationRow(
            case_id=entity_key[0],
            entity_type=entity_key[1],
            entity_key=entity_key[2],
            evidence_record_key=evidence_record_key,
            observation_role=observation_role,
            observed_value=observed_value,
            observed_at=observed_at,
            source_table=source_table,
        )

    def _merge_relationship(
        self,
        rows: Dict[tuple, _RelationshipRow],
        key: tuple,
        candidate: GraphRelationshipCandidate,
        source_identity,
        target_identity,
        observed_at: Optional[datetime],
    ) -> None:
        existing = rows.get(key)
        if existing is None:
            rows[key] = _RelationshipRow(
                case_id=key[0],
                source_entity_type=source_identity.entity_type,
                source_entity_key=source_identity.entity_key,
                relationship_type=candidate.relationship_type,
                target_entity_type=target_identity.entity_type,
                target_entity_key=target_identity.entity_key,
                derivation_type=candidate.derivation_type,
                extractor_name=candidate.extractor_name,
                extractor_version=candidate.extractor_version,
                first_seen_at=observed_at,
                last_seen_at=observed_at,
                metadata_json=_merge_metadata({}, candidate.metadata),
            )
            return
        existing.metadata_json = _merge_metadata(existing.metadata_json, candidate.metadata)
        existing.first_seen_at = _earliest(existing.first_seen_at, observed_at)
        existing.last_seen_at = _latest(existing.last_seen_at, observed_at)

    def _create_temp_tables(self, cursor) -> None:
        cursor.execute(_CREATE_TEMP_TABLES_SQL)

    def _copy_rows(self, cursor, table: str, columns: tuple[str, ...], rows: Iterable[Any]) -> float:
        started = time.monotonic()
        buffer = io.StringIO()
        writer = csv.writer(buffer, lineterminator='\n')
        count = 0
        for row in rows:
            writer.writerow([_copy_value(getattr(row, column)) for column in columns])
            count += 1
        if count:
            buffer.seek(0)
            cols = ', '.join(columns)
            cursor.copy_expert(f"COPY {table} ({cols}) FROM STDIN WITH (FORMAT CSV, NULL '\\N')", buffer)
        return time.monotonic() - started

    def _execute_timed(self, cursor, sql: str) -> float:
        started = time.monotonic()
        cursor.execute(sql)
        return time.monotonic() - started


def _earliest(current: Optional[datetime], value: Optional[datetime]) -> Optional[datetime]:
    if value is None:
        return current
    if current is None or value < current:
        return value
    return current


def _latest(current: Optional[datetime], value: Optional[datetime]) -> Optional[datetime]:
    if value is None:
        return current
    if current is None or value > current:
        return value
    return current


def _copy_value(value: Any) -> Any:
    if value is None:
        return r'\N'
    if isinstance(value, datetime):
        return value.isoformat(sep=' ')
    if isinstance(value, (dict, list)):
        return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False)
    return value


_ENTITY_COLUMNS = (
    'case_id',
    'entity_type',
    'entity_key',
    'display_value',
    'canonical_value',
    'first_seen_at',
    'last_seen_at',
    'metadata_json',
)

_OBSERVATION_COLUMNS = (
    'case_id',
    'entity_type',
    'entity_key',
    'evidence_record_key',
    'observation_role',
    'observed_value',
    'observed_at',
    'source_table',
)

_RELATIONSHIP_COLUMNS = (
    'case_id',
    'source_entity_type',
    'source_entity_key',
    'relationship_type',
    'target_entity_type',
    'target_entity_key',
    'derivation_type',
    'extractor_name',
    'extractor_version',
    'first_seen_at',
    'last_seen_at',
    'metadata_json',
)

_SUPPORT_COLUMNS = (
    'case_id',
    'source_entity_type',
    'source_entity_key',
    'relationship_type',
    'target_entity_type',
    'target_entity_key',
    'derivation_type',
    'evidence_record_key',
    'source_table',
    'evidence_role',
    'extractor_name',
    'extractor_version',
    'observed_at',
    'metadata_json',
    'source_ref_type',
    'source_ref_id',
    'support_locator_json',
)


_CREATE_TEMP_TABLES_SQL = """
CREATE TEMP TABLE IF NOT EXISTS tmp_graph_entities (
    case_id integer NOT NULL,
    entity_type text NOT NULL,
    entity_key text NOT NULL,
    display_value text NOT NULL,
    canonical_value text,
    first_seen_at timestamp,
    last_seen_at timestamp,
    metadata_json jsonb NOT NULL DEFAULT '{}'::jsonb
) ON COMMIT DELETE ROWS;

CREATE TEMP TABLE IF NOT EXISTS tmp_graph_entity_observations (
    case_id integer NOT NULL,
    entity_type text NOT NULL,
    entity_key text NOT NULL,
    evidence_record_key text NOT NULL,
    observation_role text NOT NULL,
    observed_value text,
    observed_at timestamp,
    source_table text NOT NULL
) ON COMMIT DELETE ROWS;

CREATE TEMP TABLE IF NOT EXISTS tmp_graph_relationships (
    case_id integer NOT NULL,
    source_entity_type text NOT NULL,
    source_entity_key text NOT NULL,
    relationship_type text NOT NULL,
    target_entity_type text NOT NULL,
    target_entity_key text NOT NULL,
    derivation_type text NOT NULL,
    extractor_name text NOT NULL,
    extractor_version text NOT NULL,
    first_seen_at timestamp,
    last_seen_at timestamp,
    metadata_json jsonb NOT NULL DEFAULT '{}'::jsonb
) ON COMMIT DELETE ROWS;

CREATE TEMP TABLE IF NOT EXISTS tmp_graph_relationship_evidence (
    case_id integer NOT NULL,
    source_entity_type text NOT NULL,
    source_entity_key text NOT NULL,
    relationship_type text NOT NULL,
    target_entity_type text NOT NULL,
    target_entity_key text NOT NULL,
    derivation_type text NOT NULL,
    evidence_record_key text NOT NULL,
    source_table text NOT NULL,
    evidence_role text NOT NULL,
    extractor_name text NOT NULL,
    extractor_version text NOT NULL,
    observed_at timestamp,
    metadata_json jsonb NOT NULL DEFAULT '{}'::jsonb,
    source_ref_type text,
    source_ref_id integer,
    support_locator_json jsonb
) ON COMMIT DELETE ROWS;
"""


_MERGE_ENTITIES_SQL = """
INSERT INTO graph_entities (
    case_id, entity_type, entity_key, display_value, canonical_value,
    first_seen_at, last_seen_at, metadata_json, created_at, updated_at
)
SELECT
    case_id, entity_type, entity_key, display_value, canonical_value,
    first_seen_at, last_seen_at, metadata_json::json, NOW(), NOW()
FROM tmp_graph_entities
ON CONFLICT (case_id, entity_type, entity_key)
DO UPDATE SET
    first_seen_at = CASE
        WHEN graph_entities.first_seen_at IS NULL THEN EXCLUDED.first_seen_at
        WHEN EXCLUDED.first_seen_at IS NULL THEN graph_entities.first_seen_at
        ELSE LEAST(graph_entities.first_seen_at, EXCLUDED.first_seen_at)
    END,
    last_seen_at = CASE
        WHEN graph_entities.last_seen_at IS NULL THEN EXCLUDED.last_seen_at
        WHEN EXCLUDED.last_seen_at IS NULL THEN graph_entities.last_seen_at
        ELSE GREATEST(graph_entities.last_seen_at, EXCLUDED.last_seen_at)
    END,
    metadata_json = (COALESCE(graph_entities.metadata_json, '{}'::json)::jsonb || COALESCE(EXCLUDED.metadata_json, '{}'::json)::jsonb)::json,
    updated_at = NOW();
"""


_MERGE_OBSERVATIONS_SQL = """
INSERT INTO graph_entity_observations (
    case_id, entity_id, evidence_record_key, observation_role,
    observed_value, observed_at, source_table, created_at, metadata_json
)
SELECT
    o.case_id,
    e.id,
    o.evidence_record_key,
    o.observation_role,
    o.observed_value,
    o.observed_at,
    o.source_table,
    NOW(),
    '{}'::json
FROM tmp_graph_entity_observations o
JOIN graph_entities e
  ON e.case_id = o.case_id
 AND e.entity_type = o.entity_type
 AND e.entity_key = o.entity_key
ON CONFLICT (entity_id, evidence_record_key, observation_role, source_table) DO NOTHING;
"""


_MERGE_RELATIONSHIPS_SQL = """
INSERT INTO graph_relationships (
    case_id, source_entity_id, relationship_type, target_entity_id,
    first_seen_at, last_seen_at, confidence, derivation_type,
    extractor_name, extractor_version, validation_state,
    created_at, updated_at, metadata_json
)
SELECT
    r.case_id,
    source_entity.id,
    r.relationship_type,
    target_entity.id,
    r.first_seen_at,
    r.last_seen_at,
    1.0,
    r.derivation_type,
    r.extractor_name,
    r.extractor_version,
    'ACTIVE',
    NOW(),
    NOW(),
    r.metadata_json::json
FROM tmp_graph_relationships r
JOIN graph_entities source_entity
  ON source_entity.case_id = r.case_id
 AND source_entity.entity_type = r.source_entity_type
 AND source_entity.entity_key = r.source_entity_key
JOIN graph_entities target_entity
  ON target_entity.case_id = r.case_id
 AND target_entity.entity_type = r.target_entity_type
 AND target_entity.entity_key = r.target_entity_key
ON CONFLICT (case_id, source_entity_id, relationship_type, target_entity_id, derivation_type)
DO UPDATE SET
    first_seen_at = CASE
        WHEN graph_relationships.first_seen_at IS NULL THEN EXCLUDED.first_seen_at
        WHEN EXCLUDED.first_seen_at IS NULL THEN graph_relationships.first_seen_at
        ELSE LEAST(graph_relationships.first_seen_at, EXCLUDED.first_seen_at)
    END,
    last_seen_at = CASE
        WHEN graph_relationships.last_seen_at IS NULL THEN EXCLUDED.last_seen_at
        WHEN EXCLUDED.last_seen_at IS NULL THEN graph_relationships.last_seen_at
        ELSE GREATEST(graph_relationships.last_seen_at, EXCLUDED.last_seen_at)
    END,
    validation_state = 'ACTIVE',
    metadata_json = (COALESCE(graph_relationships.metadata_json, '{}'::json)::jsonb || COALESCE(EXCLUDED.metadata_json, '{}'::json)::jsonb)::json,
    updated_at = NOW();
"""


_MERGE_SUPPORT_SQL = """
WITH resolved AS (
    SELECT
        s.case_id,
        rel.id AS relationship_id,
        s.evidence_record_key,
        s.source_table,
        s.evidence_role,
        s.extractor_name,
        s.extractor_version,
        s.observed_at,
        s.metadata_json,
        s.source_ref_type,
        s.source_ref_id,
        s.support_locator_json
    FROM tmp_graph_relationship_evidence s
    JOIN graph_entities source_entity
      ON source_entity.case_id = s.case_id
     AND source_entity.entity_type = s.source_entity_type
     AND source_entity.entity_key = s.source_entity_key
    JOIN graph_entities target_entity
      ON target_entity.case_id = s.case_id
     AND target_entity.entity_type = s.target_entity_type
     AND target_entity.entity_key = s.target_entity_key
    JOIN graph_relationships rel
      ON rel.case_id = s.case_id
     AND rel.source_entity_id = source_entity.id
     AND rel.relationship_type = s.relationship_type
     AND rel.target_entity_id = target_entity.id
     AND rel.derivation_type = s.derivation_type
)
INSERT INTO graph_relationship_evidence (
    case_id, relationship_id, evidence_record_key, source_table, evidence_role,
    extractor_name, extractor_version, observed_at, created_at, metadata_json,
    support_state, source_ref_type, source_ref_id, support_locator_json,
    support_state_changed_at
)
SELECT
    case_id,
    relationship_id,
    evidence_record_key,
    source_table,
    evidence_role,
    extractor_name,
    extractor_version,
    observed_at,
    NOW(),
    metadata_json::json,
    'ACTIVE',
    source_ref_type,
    source_ref_id,
    support_locator_json::json,
    NOW()
FROM resolved
ON CONFLICT (relationship_id, evidence_record_key, evidence_role, extractor_name, extractor_version)
DO UPDATE SET
    support_state = 'ACTIVE',
    support_state_reason = CASE
        WHEN graph_relationship_evidence.support_state <> 'ACTIVE' THEN 'rematerialized'
        ELSE graph_relationship_evidence.support_state_reason
    END,
    support_state_changed_at = CASE
        WHEN graph_relationship_evidence.support_state <> 'ACTIVE' THEN NOW()
        ELSE graph_relationship_evidence.support_state_changed_at
    END,
    source_ref_type = COALESCE(EXCLUDED.source_ref_type, graph_relationship_evidence.source_ref_type),
    source_ref_id = CASE
        WHEN EXCLUDED.source_ref_type IS NOT NULL THEN EXCLUDED.source_ref_id
        ELSE graph_relationship_evidence.source_ref_id
    END,
    support_locator_json = COALESCE(EXCLUDED.support_locator_json, graph_relationship_evidence.support_locator_json),
    metadata_json = (COALESCE(graph_relationship_evidence.metadata_json, '{}'::json)::jsonb || COALESCE(EXCLUDED.metadata_json, '{}'::json)::jsonb)::json
WHERE graph_relationship_evidence.support_state <> 'ACTIVE'
   OR (
        EXCLUDED.source_ref_type IS NOT NULL
        AND (
            graph_relationship_evidence.source_ref_type IS DISTINCT FROM EXCLUDED.source_ref_type
            OR graph_relationship_evidence.source_ref_id IS DISTINCT FROM EXCLUDED.source_ref_id
        )
   )
   OR (
        EXCLUDED.support_locator_json IS NOT NULL
        AND COALESCE(graph_relationship_evidence.support_locator_json::jsonb, '{}'::jsonb) IS DISTINCT FROM COALESCE(EXCLUDED.support_locator_json::jsonb, '{}'::jsonb)
   )
   OR (
        COALESCE(graph_relationship_evidence.metadata_json, '{}'::json)::jsonb
        IS DISTINCT FROM
        (COALESCE(graph_relationship_evidence.metadata_json, '{}'::json)::jsonb || COALESCE(EXCLUDED.metadata_json, '{}'::json)::jsonb)
   );
"""
