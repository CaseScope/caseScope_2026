"""Materialization service for deterministic investigative graph facts."""
from __future__ import annotations

import logging
import json
import re
import time
from datetime import datetime, timedelta
from typing import Any, Dict, Iterable, Optional

from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from models.database import db
from models.graph import (
    GraphEntity,
    GraphEntityObservation,
    GraphRelationship,
    GraphRelationshipEvidence,
)
from utils.graph_extractors import (
    GRAPH_ELIGIBLE_EVENT_PREDICATE,
    GRAPH_EXTRACTOR_EVENT_COLUMNS,
    GraphRelationshipCandidate,
    event_from_clickhouse_row,
    extract_event_relationships,
)
from utils.graph_identity import (
    EntityIdentity,
    EntitySpec,
    GraphDerivationType,
    GraphEntityType,
    GraphSourceRefType,
    GraphSupportState,
    GraphValidationState,
    build_domain_entity,
    build_file_hash_entity,
    build_file_path_entity,
    build_host_entity,
    build_ip_entity,
    build_logon_session_entity,
    build_process_entity,
    build_registry_key_entity,
    build_service_entity,
    build_url_entity,
    build_user_entity,
)
from utils.graph_support_locator import validate_support_provenance

logger = logging.getLogger(__name__)
EVIDENCE_RECORD_KEY_RE = re.compile(r'^erk:v2:[0-9a-f]{64}$')
GRAPH_PROJECTION_VERSION = 'graph_events_v2_windowed'
GRAPH_PROJECTION_PREVIOUS_VERSION = 'graph_events_v1'
DEFAULT_GRAPH_WINDOW_SECONDS = 900


def _clean(value: Any) -> str:
    return str(value or '').strip()


def _coerce_datetime(value: Any) -> Optional[datetime]:
    if value is None or value == '':
        return None
    if isinstance(value, datetime):
        return value.replace(tzinfo=None)
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        try:
            return datetime.fromisoformat(text.replace('Z', '+00:00')).replace(tzinfo=None)
        except ValueError:
            return None
    return None


def _merge_metadata(existing: Dict[str, Any] | None, additions: Dict[str, Any] | None) -> Dict[str, Any]:
    merged = dict(existing or {})
    for key, value in (additions or {}).items():
        if value not in (None, '', [], {}):
            merged[key] = value
    return merged


class GraphMaterializer:
    """Idempotently persists canonical graph facts and provenance."""

    def __init__(self, session=None):
        self.session = session or db.session
        self._known_system_cache: Dict[tuple[int, str], Optional[int]] = {}
        self._entity_identity_cache: Dict[str, EntityIdentity] = {}

    def canonicalize_entity_spec(self, case_id: int, spec: EntitySpec) -> EntityIdentity:
        cache_key = self._entity_cache_key(case_id, spec)
        cached = self._entity_identity_cache.get(cache_key)
        if cached is not None:
            return cached
        identity = self._canonicalize_entity_spec_uncached(case_id, spec)
        if len(self._entity_identity_cache) < 100000:
            self._entity_identity_cache[cache_key] = identity
        return identity

    def _canonicalize_entity_spec_uncached(self, case_id: int, spec: EntitySpec) -> EntityIdentity:
        entity_type = spec.entity_type
        hints = spec.hints or {}

        if entity_type == GraphEntityType.HOST:
            known_system_id = hints.get('known_system_id')
            if not known_system_id and hints.get('prefer_known_system', True):
                known_system_id = self._lookup_known_system_id(case_id, spec.raw_value)
            return build_host_entity(
                spec.raw_value,
                known_system_id=known_system_id,
                source_context=hints.get('source_context'),
            )

        if entity_type == GraphEntityType.USER:
            host_identity = None
            if hints.get('host'):
                host_identity = self.canonicalize_entity_spec(case_id, hints['host'])
            return build_user_entity(
                hints.get('username') or spec.raw_value,
                sid=hints.get('sid'),
                domain=hints.get('domain'),
                host_key=host_identity.entity_key if host_identity else '',
            )

        if entity_type == GraphEntityType.PROCESS:
            host_identity = self.canonicalize_entity_spec(case_id, hints['host'])
            return build_process_entity(
                host_key=host_identity.entity_key,
                pid=hints.get('pid'),
                start_time=hints.get('start_time'),
                evidence_record_key=hints.get('evidence_record_key'),
                process_name=hints.get('process_name') or spec.raw_value,
                process_path=hints.get('process_path'),
            )

        if entity_type == GraphEntityType.FILE_PATH:
            host_key = ''
            if hints.get('host'):
                host_key = self.canonicalize_entity_spec(case_id, hints['host']).entity_key
            return build_file_path_entity(hints.get('path') or spec.raw_value, host_key=host_key)

        if entity_type == GraphEntityType.FILE_HASH:
            return build_file_hash_entity(hints.get('algorithm'), hints.get('hash_value') or spec.raw_value)

        if entity_type == GraphEntityType.IP_ADDRESS:
            return build_ip_entity(spec.raw_value)

        if entity_type == GraphEntityType.DOMAIN:
            return build_domain_entity(spec.raw_value)

        if entity_type == GraphEntityType.URL:
            return build_url_entity(spec.raw_value)

        if entity_type == GraphEntityType.REGISTRY_KEY:
            host_key = ''
            if hints.get('host'):
                host_key = self.canonicalize_entity_spec(case_id, hints['host']).entity_key
            return build_registry_key_entity(spec.raw_value, host_key=host_key)

        if entity_type == GraphEntityType.SERVICE:
            host_key = ''
            if hints.get('host'):
                host_key = self.canonicalize_entity_spec(case_id, hints['host']).entity_key
            return build_service_entity(spec.raw_value, host_key=host_key)

        if entity_type == GraphEntityType.LOGON_SESSION:
            host_identity = self.canonicalize_entity_spec(case_id, hints['host'])
            user_identity = None
            if hints.get('user'):
                user_identity = self.canonicalize_entity_spec(case_id, hints['user'])
            return build_logon_session_entity(
                hints.get('logon_id') or spec.raw_value,
                host_key=host_identity.entity_key,
                user_key=user_identity.entity_key if user_identity else '',
            )

        raise ValueError(f'Unsupported graph entity type: {entity_type}')

    def _entity_cache_key(self, case_id: int, spec: EntitySpec) -> str:
        def normalize(value: Any):
            if isinstance(value, EntitySpec):
                return {
                    'entity_type': value.entity_type,
                    'raw_value': value.raw_value,
                    'display_value': value.display_value,
                    'hints': normalize(value.hints or {}),
                }
            if isinstance(value, dict):
                return {str(key): normalize(val) for key, val in sorted(value.items(), key=lambda item: str(item[0]))}
            if isinstance(value, (list, tuple)):
                return [normalize(item) for item in value]
            if isinstance(value, datetime):
                return value.isoformat()
            return value

        return json.dumps(
            {
                'case_id': int(case_id),
                'entity_type': spec.entity_type,
                'raw_value': spec.raw_value,
                'display_value': spec.display_value,
                'hints': normalize(spec.hints or {}),
            },
            sort_keys=True,
            default=str,
            separators=(',', ':'),
        )

    def _lookup_known_system_id(self, case_id: int, hostname: Any) -> Optional[int]:
        """Resolve KnownSystem identity. Fail closed on infrastructure errors.

        A legitimate miss (no matching KnownSystem) returns None and allows the
        accepted observed-host fallback. Database/query/infrastructure failures
        must propagate so per-record savepoints can isolate the bad event
        without silently minting a second host identity.
        """
        if not _clean(hostname):
            return None
        cache_key = (int(case_id), _clean(hostname).upper())
        if cache_key in self._known_system_cache:
            return self._known_system_cache[cache_key]
        from models.known_system import KnownSystem

        system, _match_type = KnownSystem.find_by_hostname_or_alias(hostname, case_id=case_id)
        known_system_id = system.id if system else None
        if len(self._known_system_cache) < 100000:
            self._known_system_cache[cache_key] = known_system_id
        return known_system_id

    def materialize_candidate(self, case_id: int, candidate: GraphRelationshipCandidate) -> GraphRelationship:
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
        source_ref_type, source_ref_id = self._resolve_source_ref(candidate, support_locator)
        source_entity = self._get_or_create_entity(
            case_id,
            self.canonicalize_entity_spec(case_id, candidate.source),
            observed_at=observed_at,
            evidence_record_key=candidate.evidence_record_key,
            source_table=candidate.source_table,
            observation_role='relationship_source',
            observed_value=candidate.source.raw_value,
        )
        target_entity = self._get_or_create_entity(
            case_id,
            self.canonicalize_entity_spec(case_id, candidate.target),
            observed_at=observed_at,
            evidence_record_key=candidate.evidence_record_key,
            source_table=candidate.source_table,
            observation_role='relationship_target',
            observed_value=candidate.target.raw_value,
        )
        if source_entity.case_id != case_id or target_entity.case_id != case_id:
            raise ValueError('Graph relationship endpoints must belong to the same case')

        relationship = self._get_or_create_relationship(
            case_id=case_id,
            source_entity_id=source_entity.id,
            relationship_type=candidate.relationship_type,
            target_entity_id=target_entity.id,
            derivation_type=candidate.derivation_type,
            extractor_name=candidate.extractor_name,
            extractor_version=candidate.extractor_version,
            observed_at=observed_at,
            metadata=candidate.metadata,
        )
        # Reprocessing that recreates equivalent support reactivates the edge.
        if relationship.validation_state != GraphValidationState.ACTIVE:
            relationship.validation_state = GraphValidationState.ACTIVE
        self._get_or_create_relationship_evidence(
            case_id=case_id,
            relationship_id=relationship.id,
            evidence_record_key=candidate.evidence_record_key,
            source_table=candidate.source_table,
            evidence_role=candidate.evidence_role,
            extractor_name=candidate.extractor_name,
            extractor_version=candidate.extractor_version,
            observed_at=observed_at,
            metadata=candidate.metadata,
            source_ref_type=source_ref_type,
            source_ref_id=source_ref_id,
            support_locator=support_locator,
        )
        return relationship

    def _resolve_source_ref(
        self,
        candidate: GraphRelationshipCandidate,
        support_locator: Dict[str, Any],
    ) -> tuple[Optional[str], Optional[int]]:
        if candidate.source_ref_type and candidate.source_ref_id is not None:
            return str(candidate.source_ref_type), int(candidate.source_ref_id)
        meta = candidate.metadata or {}
        if meta.get('case_file_id') not in (None, ''):
            try:
                return GraphSourceRefType.CASE_FILE, int(meta['case_file_id'])
            except (TypeError, ValueError):
                pass
        if _clean(candidate.source_table) == 'events':
            # Events always prefer CaseFile when present on the candidate/event.
            raw_case_file = getattr(candidate, 'case_file_id', None)
            if raw_case_file not in (None, ''):
                try:
                    return GraphSourceRefType.CASE_FILE, int(raw_case_file)
                except (TypeError, ValueError):
                    pass
        if support_locator:
            from utils.graph_support_locator import source_ref_from_locator

            try:
                return source_ref_from_locator(support_locator)
            except Exception:
                return None, None
        return None, None

    def materialize_candidates(self, case_id: int, candidates: Iterable[GraphRelationshipCandidate]) -> int:
        count = 0
        for candidate in candidates:
            self.materialize_candidate(case_id, candidate)
            count += 1
        return count

    def _get_or_create_entity(
        self,
        case_id: int,
        identity: EntityIdentity,
        *,
        observed_at: Optional[datetime],
        evidence_record_key: str,
        source_table: str,
        observation_role: str,
        observed_value: str,
    ) -> GraphEntity:
        entity = GraphEntity.query.filter_by(
            case_id=case_id,
            entity_type=identity.entity_type,
            entity_key=identity.entity_key,
        ).first()
        if entity is None:
            entity = GraphEntity(
                case_id=case_id,
                entity_type=identity.entity_type,
                entity_key=identity.entity_key,
                display_value=identity.display_value,
                canonical_value=identity.canonical_value,
                first_seen_at=observed_at,
                last_seen_at=observed_at,
                metadata_json=identity.metadata,
            )
            try:
                with self.session.begin_nested():
                    self.session.add(entity)
                    self.session.flush()
            except IntegrityError:
                entity = GraphEntity.query.filter_by(
                    case_id=case_id,
                    entity_type=identity.entity_type,
                    entity_key=identity.entity_key,
                ).first()
                if entity is None:
                    raise
        else:
            self._update_seen_window(entity, observed_at)
            entity.metadata_json = _merge_metadata(entity.metadata_json, identity.metadata)
        self._get_or_create_entity_observation(
            case_id=case_id,
            entity_id=entity.id,
            evidence_record_key=evidence_record_key,
            observation_role=observation_role,
            source_table=source_table,
            observed_at=observed_at,
            observed_value=observed_value,
        )
        return entity

    def _get_or_create_entity_observation(
        self,
        *,
        case_id: int,
        entity_id: int,
        evidence_record_key: str,
        observation_role: str,
        source_table: str,
        observed_at: Optional[datetime],
        observed_value: str,
    ) -> GraphEntityObservation:
        observation = GraphEntityObservation.query.filter_by(
            entity_id=entity_id,
            evidence_record_key=evidence_record_key,
            observation_role=observation_role,
            source_table=source_table,
        ).first()
        if observation:
            return observation
        observation = GraphEntityObservation(
            case_id=case_id,
            entity_id=entity_id,
            evidence_record_key=evidence_record_key,
            observation_role=observation_role,
            observed_value=observed_value,
            observed_at=observed_at,
            source_table=source_table,
        )
        try:
            with self.session.begin_nested():
                self.session.add(observation)
                self.session.flush()
        except IntegrityError:
            observation = GraphEntityObservation.query.filter_by(
                entity_id=entity_id,
                evidence_record_key=evidence_record_key,
                observation_role=observation_role,
                source_table=source_table,
            ).first()
            if observation is None:
                raise
        return observation

    def _get_or_create_relationship(
        self,
        *,
        case_id: int,
        source_entity_id: int,
        relationship_type: str,
        target_entity_id: int,
        derivation_type: str,
        extractor_name: str,
        extractor_version: str,
        observed_at: Optional[datetime],
        metadata: Dict[str, Any],
    ) -> GraphRelationship:
        relationship = GraphRelationship.query.filter_by(
            case_id=case_id,
            source_entity_id=source_entity_id,
            relationship_type=relationship_type,
            target_entity_id=target_entity_id,
            derivation_type=derivation_type,
        ).first()
        if relationship is None:
            relationship = GraphRelationship(
                case_id=case_id,
                source_entity_id=source_entity_id,
                relationship_type=relationship_type,
                target_entity_id=target_entity_id,
                first_seen_at=observed_at,
                last_seen_at=observed_at,
                derivation_type=derivation_type,
                extractor_name=extractor_name,
                extractor_version=extractor_version,
                validation_state=GraphValidationState.ACTIVE,
                metadata_json=metadata or {},
            )
            try:
                with self.session.begin_nested():
                    self.session.add(relationship)
                    self.session.flush()
            except IntegrityError:
                relationship = GraphRelationship.query.filter_by(
                    case_id=case_id,
                    source_entity_id=source_entity_id,
                    relationship_type=relationship_type,
                    target_entity_id=target_entity_id,
                    derivation_type=derivation_type,
                ).first()
                if relationship is None:
                    raise
        else:
            self._update_seen_window(relationship, observed_at)
            relationship.metadata_json = _merge_metadata(relationship.metadata_json, metadata)
        return relationship

    def _get_or_create_relationship_evidence(
        self,
        *,
        case_id: int,
        relationship_id: int,
        evidence_record_key: str,
        source_table: str,
        evidence_role: str,
        extractor_name: str,
        extractor_version: str,
        observed_at: Optional[datetime],
        metadata: Dict[str, Any],
        source_ref_type: Optional[str] = None,
        source_ref_id: Optional[int] = None,
        support_locator: Optional[Dict[str, Any]] = None,
    ) -> GraphRelationshipEvidence:
        evidence = GraphRelationshipEvidence.query.filter_by(
            relationship_id=relationship_id,
            evidence_record_key=evidence_record_key,
            evidence_role=evidence_role,
            extractor_name=extractor_name,
            extractor_version=extractor_version,
        ).first()
        if evidence:
            # Reactivate previously invalidated/unavailable support when equivalent
            # canonical evidence is rematerialized (reprocess path).
            if evidence.support_state != GraphSupportState.ACTIVE:
                evidence.support_state = GraphSupportState.ACTIVE
                evidence.support_state_reason = 'rematerialized'
                evidence.support_state_changed_at = datetime.utcnow()
            if source_ref_type:
                evidence.source_ref_type = source_ref_type
                evidence.source_ref_id = source_ref_id
            if support_locator:
                evidence.support_locator_json = support_locator
            evidence.metadata_json = _merge_metadata(evidence.metadata_json, metadata)
            return evidence
        # Prefer attaching CaseFile from event metadata when present.
        if not source_ref_type and metadata and metadata.get('case_file_id') not in (None, ''):
            try:
                source_ref_type = GraphSourceRefType.CASE_FILE
                source_ref_id = int(metadata['case_file_id'])
            except (TypeError, ValueError):
                pass
        evidence = GraphRelationshipEvidence(
            case_id=case_id,
            relationship_id=relationship_id,
            evidence_record_key=evidence_record_key,
            source_table=source_table,
            evidence_role=evidence_role,
            extractor_name=extractor_name,
            extractor_version=extractor_version,
            observed_at=observed_at,
            metadata_json=metadata or {},
            support_state=GraphSupportState.ACTIVE,
            source_ref_type=source_ref_type,
            source_ref_id=source_ref_id,
            support_locator_json=support_locator or None,
            support_state_changed_at=datetime.utcnow(),
        )
        try:
            with self.session.begin_nested():
                self.session.add(evidence)
                self.session.flush()
        except IntegrityError:
            evidence = GraphRelationshipEvidence.query.filter_by(
                relationship_id=relationship_id,
                evidence_record_key=evidence_record_key,
                evidence_role=evidence_role,
                extractor_name=extractor_name,
                extractor_version=extractor_version,
            ).first()
            if evidence is None:
                raise
        return evidence

    def _update_seen_window(self, obj, observed_at: Optional[datetime]) -> None:
        if observed_at is None:
            return
        if getattr(obj, 'first_seen_at', None) is None or observed_at < obj.first_seen_at:
            obj.first_seen_at = observed_at
        if getattr(obj, 'last_seen_at', None) is None or observed_at > obj.last_seen_at:
            obj.last_seen_at = observed_at


def clear_case_graph(case_id: int, *, session=None) -> Dict[str, int]:
    session = session or db.session
    summary = {
        'relationship_evidence': GraphRelationshipEvidence.query.filter_by(case_id=case_id).delete(synchronize_session=False),
        'entity_observations': GraphEntityObservation.query.filter_by(case_id=case_id).delete(synchronize_session=False),
        'relationships': GraphRelationship.query.filter_by(case_id=case_id).delete(synchronize_session=False),
        'entities': GraphEntity.query.filter_by(case_id=case_id).delete(synchronize_session=False),
    }
    session.flush()
    return summary


def _projection_state_id(projection_state: Any) -> Optional[int]:
    if projection_state is None:
        return None
    if isinstance(projection_state, int):
        return int(projection_state)
    return getattr(projection_state, 'id', None)


def _load_projection_state(projection_state: Any):
    state_id = _projection_state_id(projection_state)
    if state_id is None:
        return None
    from models.graph import GraphProjectionState

    return GraphProjectionState.query.get(int(state_id))


def _projection_lock_key(case_id: int) -> int:
    return 4183000000 + int(case_id)


def _try_acquire_projection_lock(case_id: int) -> bool:
    if getattr(db.engine.dialect, 'name', '') != 'postgresql':
        return False
    acquired = db.session.execute(
        text('SELECT pg_try_advisory_lock(:lock_key)'),
        {'lock_key': _projection_lock_key(case_id)},
    ).scalar()
    if not acquired:
        raise RuntimeError(f'Graph projection already running for case {case_id}')
    return True


def _release_projection_lock(case_id: int, acquired: bool) -> None:
    if not acquired:
        return
    try:
        db.session.execute(
            text('SELECT pg_advisory_unlock(:lock_key)'),
            {'lock_key': _projection_lock_key(case_id)},
        )
        db.session.commit()
    except Exception:
        db.session.rollback()
        logger.warning('Failed to release graph projection advisory lock for case %s', case_id)


def _set_projection_running(state, *, mode: Optional[str], task_id: Optional[str]) -> None:
    if state is None:
        return
    now = datetime.utcnow()
    if mode:
        state.mode = mode
    if task_id:
        state.task_id = task_id
    state.status = 'running'
    state.projection_version = GRAPH_PROJECTION_VERSION
    state.started_at = state.started_at or now
    state.completed_at = None
    state.last_error = None
    state.updated_at = now
    db.session.commit()


def _checkpoint_projection_state(
    state,
    *,
    last_timestamp: Any,
    last_evidence_record_key: str,
    events_seen: int,
    relationships_materialized: int,
    errors: int,
    last_error: Optional[str] = None,
) -> None:
    if state is None:
        return
    state.last_timestamp_utc = _coerce_datetime(last_timestamp)
    state.last_evidence_record_key = _clean(last_evidence_record_key) or None
    state.events_seen = int(events_seen)
    state.relationships_materialized = int(relationships_materialized)
    state.errors = int(errors)
    if last_error:
        state.last_error = last_error[:4000]
    state.updated_at = datetime.utcnow()
    db.session.commit()


def _checkpoint_window_started(
    state,
    *,
    window_start: datetime,
    window_end: datetime,
    events_seen: int,
    relationships_materialized: int,
    errors: int,
) -> None:
    if state is None:
        return
    state.current_window_start_utc = _coerce_datetime(window_start)
    state.current_window_end_utc = _coerce_datetime(window_end)
    state.events_seen = int(events_seen)
    state.relationships_materialized = int(relationships_materialized)
    state.errors = int(errors)
    state.updated_at = datetime.utcnow()
    db.session.commit()


def _checkpoint_window_completed(
    state,
    *,
    window_end: datetime,
    events_seen: int,
    relationships_materialized: int,
    errors: int,
) -> None:
    if state is None:
        return
    state.last_completed_window_end_utc = _coerce_datetime(window_end)
    state.current_window_start_utc = None
    state.current_window_end_utc = None
    state.windows_completed = int(state.windows_completed or 0) + 1
    state.events_seen = int(events_seen)
    state.relationships_materialized = int(relationships_materialized)
    state.errors = int(errors)
    state.updated_at = datetime.utcnow()
    db.session.commit()


def _finish_projection_state(state, *, status: str, summary: Dict[str, Any]) -> None:
    if state is None:
        return
    now = datetime.utcnow()
    state.status = status
    state.events_seen = int(summary.get('events_seen', 0) or 0)
    state.relationships_materialized = int(summary.get('relationships_materialized', 0) or 0)
    state.errors = int(summary.get('errors', 0) or 0)
    state.last_error = summary.get('last_error') or None
    state.completed_at = now if status in {'completed', 'no_eligible_evidence'} else None
    state.updated_at = now
    db.session.commit()


def _normalize_case_file_ids(case_file_ids: Optional[Iterable[int]]) -> Optional[tuple[int, ...]]:
    if case_file_ids is None:
        return None
    normalized = []
    seen = set()
    for raw_id in case_file_ids:
        if raw_id in (None, ''):
            continue
        file_id = int(raw_id)
        if file_id not in seen:
            normalized.append(file_id)
            seen.add(file_id)
    return tuple(normalized)


def _case_file_scope_clause(case_file_ids: Optional[tuple[int, ...]]) -> str:
    if case_file_ids is None:
        return ''
    return "\n      AND case_file_id IN {case_file_ids:Array(UInt32)}"


def _next_eligible_timestamp_query(case_file_ids: Optional[tuple[int, ...]] = None) -> str:
    return f"""
    SELECT minOrNull(timestamp_utc)
    FROM events
    PREWHERE case_id = {{case_id:UInt32}}
      {_case_file_scope_clause(case_file_ids).lstrip()}
      AND timestamp_utc >= {{after_timestamp:DateTime64(3)}}
    WHERE ({GRAPH_ELIGIBLE_EVENT_PREDICATE})
    LIMIT 1
    """


def _graph_events_query(case_file_ids: Optional[tuple[int, ...]] = None) -> tuple[str, Dict[str, Any]]:
    sql = f"""
    SELECT {', '.join(GRAPH_EXTRACTOR_EVENT_COLUMNS)}
    FROM events
    PREWHERE case_id = {{case_id:UInt32}}
      {_case_file_scope_clause(case_file_ids).lstrip()}
      AND timestamp_utc >= {{window_start:DateTime64(3)}}
      AND timestamp_utc < {{window_end:DateTime64(3)}}
    WHERE ({GRAPH_ELIGIBLE_EVENT_PREDICATE})
    """
    parameters: Dict[str, Any] = {}
    if case_file_ids is not None:
        parameters['case_file_ids'] = list(case_file_ids)
    return sql, parameters


def materialize_events_for_case(
    case_id: int,
    *,
    case_file_ids: Optional[Iterable[int]] = None,
    client=None,
    batch_size: int = 5000,
    bulk_events: int = 10000,
    projection_state=None,
    resume: bool = False,
    mode: Optional[str] = None,
    task_id: Optional[str] = None,
    progress_interval: int = 50000,
    window_seconds: int = DEFAULT_GRAPH_WINDOW_SECONDS,
) -> Dict[str, Any]:
    lock_acquired = _try_acquire_projection_lock(case_id)
    try:
        return _materialize_events_for_case_impl(
            case_id,
            case_file_ids=case_file_ids,
            client=client,
            batch_size=batch_size,
            bulk_events=bulk_events,
            projection_state=projection_state,
            resume=resume,
            mode=mode,
            task_id=task_id,
            progress_interval=progress_interval,
            window_seconds=window_seconds,
        )
    finally:
        _release_projection_lock(case_id, lock_acquired)


def _materialize_events_for_case_impl(
    case_id: int,
    *,
    case_file_ids: Optional[Iterable[int]] = None,
    client=None,
    batch_size: int = 5000,
    bulk_events: int = 10000,
    projection_state=None,
    resume: bool = False,
    mode: Optional[str] = None,
    task_id: Optional[str] = None,
    progress_interval: int = 50000,
    window_seconds: int = DEFAULT_GRAPH_WINDOW_SECONDS,
) -> Dict[str, Any]:
    """Materialize deterministic graph facts from retained ClickHouse events."""
    if client is None:
        from utils.clickhouse import get_fresh_client

        client = get_fresh_client()

    state = _load_projection_state(projection_state)
    previous_projection_version = getattr(state, 'projection_version', None)
    previous_completed_window_end = getattr(state, 'last_completed_window_end_utc', None)
    _set_projection_running(state, mode=mode, task_id=task_id)
    normalized_case_file_ids = _normalize_case_file_ids(case_file_ids)
    sql, checkpoint_parameters = _graph_events_query(normalized_case_file_ids)
    next_timestamp_sql = _next_eligible_timestamp_query(normalized_case_file_ids)
    from utils.graph_bulk_writer import GraphBulkWriter

    materializer = GraphBulkWriter()
    base_events_seen = int(getattr(state, 'events_seen', 0) or 0)
    base_candidates_seen = int(getattr(state, 'relationships_materialized', 0) or 0)
    base_errors = int(getattr(state, 'errors', 0) or 0)
    events_seen = 0
    candidates_seen = 0
    errors = 0
    last_timestamp = None
    last_evidence_record_key = ''
    last_error = None
    completed_windows_this_run = 0
    effective_window_seconds = max(int(window_seconds or DEFAULT_GRAPH_WINDOW_SECONDS), 1)
    postgres_bulk_enabled = getattr(db.engine.dialect, 'name', '') == 'postgresql'
    effective_bulk_events = max(int(bulk_events or batch_size or 10000), 1) if postgres_bulk_enabled else 1
    batch_timings = []
    if state is not None and resume and previous_projection_version == GRAPH_PROJECTION_VERSION and previous_completed_window_end:
        after_timestamp = previous_completed_window_end
    else:
        # Failed v1/event-keyset projections intentionally replay from the beginning
        # while retaining already materialized idempotent graph facts.
        after_timestamp = datetime(1970, 1, 1)

    def cumulative_events() -> int:
        return base_events_seen + events_seen

    def cumulative_candidates() -> int:
        return base_candidates_seen + candidates_seen

    def cumulative_errors() -> int:
        return base_errors + errors

    def query_next_timestamp(after: datetime) -> Optional[datetime]:
        result = client.query(
            next_timestamp_sql,
            parameters={'case_id': int(case_id), 'after_timestamp': after, **checkpoint_parameters},
        )
        rows = getattr(result, 'result_rows', None) or []
        if not rows:
            return None
        first = rows[0]
        value = first[0] if isinstance(first, (tuple, list)) else first
        return _coerce_datetime(value)

    def iter_rows(window_start: datetime, window_end: datetime):
        parameters = {
            'case_id': int(case_id),
            'window_start': window_start,
            'window_end': window_end,
            **checkpoint_parameters,
        }
        if hasattr(client, 'query_rows_stream'):
            try:
                from utils.clickhouse import migration_source_query_settings
                settings = migration_source_query_settings()
            except Exception:
                settings = {'max_block_size': int(batch_size)}
            with client.query_rows_stream(
                sql,
                parameters=parameters,
                settings=settings,
            ) as rows:
                for streamed_row in rows:
                    yield streamed_row
        else:
            result = client.query(sql, parameters=parameters)
            for result_row in result.result_rows:
                yield result_row

    def validate_candidate_for_batch(candidate) -> None:
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
        # Canonicalize before staging so malformed evidence and KnownSystem
        # infrastructure failures remain isolated to the current event.
        materializer.materializer.canonicalize_entity_spec(case_id, candidate.source)
        materializer.materializer.canonicalize_entity_spec(case_id, candidate.target)

    def flush_candidate_batch(
        pending_candidates,
        pending_events: int,
        pending_extraction_seconds: float,
    ):
        nonlocal candidates_seen, window_candidates, batch_since_commit
        if not pending_candidates and pending_events <= 0:
            return None
        stats = materializer.materialize_candidates(
            case_id,
            pending_candidates,
            events_read=pending_events,
            extraction_seconds=pending_extraction_seconds,
        )
        candidates_seen += int(stats.candidate_relationships)
        window_candidates += int(stats.candidate_relationships)
        batch_since_commit = 0
        batch_timings.append(stats.as_dict())
        _checkpoint_projection_state(
            state,
            last_timestamp=last_timestamp,
            last_evidence_record_key=last_evidence_record_key,
            events_seen=cumulative_events(),
            relationships_materialized=cumulative_candidates(),
            errors=cumulative_errors(),
            last_error=last_error,
        )
        logger.info(
            'Graph bulk materialization progress case=%s window=(%s, %s) stats=%s events_total=%s relationships_total=%s errors_total=%s',
            case_id,
            window_start,
            window_end,
            stats.as_dict(),
            cumulative_events(),
            cumulative_candidates(),
            cumulative_errors(),
        )
        return stats

    next_window_start = None
    while True:
        window_start = next_window_start or query_next_timestamp(after_timestamp)
        if window_start is None:
            break
        window_end = window_start + timedelta(seconds=effective_window_seconds)
        window_events = 0
        window_candidates = 0
        window_errors_before = errors
        batch_since_commit = 0
        pending_candidates = []
        pending_events = 0
        pending_extraction_seconds = 0.0
        started = time.monotonic()
        _checkpoint_window_started(
            state,
            window_start=window_start,
            window_end=window_end,
            events_seen=cumulative_events(),
            relationships_materialized=cumulative_candidates(),
            errors=cumulative_errors(),
        )
        for row in iter_rows(window_start, window_end):
            event = event_from_clickhouse_row(row)
            events_seen += 1
            window_events += 1
            batch_since_commit += 1
            pending_events += 1
            last_timestamp = event.get('timestamp_utc')
            last_evidence_record_key = _clean(event.get('evidence_record_key'))
            try:
                extraction_started = time.monotonic()
                candidates = extract_event_relationships(event)
                pending_extraction_seconds += time.monotonic() - extraction_started
                for candidate in candidates:
                    validate_candidate_for_batch(candidate)
                pending_candidates.extend(candidates)
                if progress_interval and events_seen % int(progress_interval) == 0:
                    logger.info(
                        'Graph materialization progress case=%s window=(%s, %s) events_run=%s events_total=%s relationships_run=%s relationships_total=%s errors_total=%s',
                        case_id,
                        window_start,
                        window_end,
                        events_seen,
                        cumulative_events(),
                        candidates_seen,
                        cumulative_candidates(),
                        cumulative_errors(),
                    )
            except Exception as exc:
                errors += 1
                last_error = str(exc)
                logger.warning(
                    'Graph extraction skipped event %s for case %s: %s',
                    event.get('evidence_record_key'),
                    case_id,
                    exc,
                )
            if pending_events >= effective_bulk_events:
                flush_candidate_batch(pending_candidates, pending_events, pending_extraction_seconds)
                pending_candidates = []
                pending_events = 0
                pending_extraction_seconds = 0.0
        flush_candidate_batch(pending_candidates, pending_events, pending_extraction_seconds)
        _checkpoint_projection_state(
            state,
            last_timestamp=last_timestamp,
            last_evidence_record_key=last_evidence_record_key,
            events_seen=cumulative_events(),
            relationships_materialized=cumulative_candidates(),
            errors=cumulative_errors(),
            last_error=last_error,
        )
        if errors > window_errors_before:
            logger.warning(
                'Graph window failed case=%s window=(%s, %s) elapsed=%.3fs rows=%s relationships=%s errors=%s',
                case_id,
                window_start,
                window_end,
                time.monotonic() - started,
                window_events,
                window_candidates,
                errors - window_errors_before,
            )
            break
        _checkpoint_window_completed(
            state,
            window_end=window_end,
            events_seen=cumulative_events(),
            relationships_materialized=cumulative_candidates(),
            errors=cumulative_errors(),
        )
        completed_windows_this_run += 1
        logger.info(
            'Graph window completed case=%s window=(%s, %s) elapsed=%.3fs rows=%s relationships=%s errors=0 events_total=%s relationships_total=%s',
            case_id,
            window_start,
            window_end,
            time.monotonic() - started,
            window_events,
            window_candidates,
            cumulative_events(),
            cumulative_candidates(),
        )
        after_timestamp = window_end
        next_window_start = window_end if window_events > 0 else None

    db.session.commit()
    summary = {
        'events_seen': events_seen,
        'relationships_materialized': candidates_seen,
        'errors': errors,
        'cumulative_events_seen': cumulative_events(),
        'cumulative_relationships_materialized': cumulative_candidates(),
        'cumulative_errors': cumulative_errors(),
        'windows_completed': completed_windows_this_run,
        'window_seconds': effective_window_seconds,
        'bulk_events': effective_bulk_events,
        'bulk_batches': len(batch_timings),
        'bulk_batch_timings': batch_timings[-20:],
    }
    if normalized_case_file_ids is not None:
        summary['case_file_ids'] = list(normalized_case_file_ids)
    if last_error:
        summary['last_error'] = last_error
    if state is not None:
        if errors:
            _finish_projection_state(
                state,
                status='failed',
                summary={
                    **summary,
                    'events_seen': cumulative_events(),
                    'relationships_materialized': cumulative_candidates(),
                    'errors': cumulative_errors(),
                },
            )
        elif events_seen == 0 and GraphEntity.query.filter_by(case_id=int(case_id)).count() == 0 and GraphRelationship.query.filter_by(case_id=int(case_id)).count() == 0:
            _finish_projection_state(state, status='no_eligible_evidence', summary=summary)
        else:
            _finish_projection_state(
                state,
                status='completed',
                summary={
                    **summary,
                    'events_seen': cumulative_events(),
                    'relationships_materialized': cumulative_candidates(),
                    'errors': cumulative_errors(),
                },
            )
    return summary


def rebuild_case_graph(case_id: int, *, client=None) -> Dict[str, Any]:
    clear_summary = clear_case_graph(case_id)
    materialize_summary = materialize_events_for_case(case_id, client=client)
    return {'cleared': clear_summary, 'materialized': materialize_summary}
