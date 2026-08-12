"""Materialization service for deterministic investigative graph facts."""
from __future__ import annotations

import logging
import re
from datetime import datetime
from typing import Any, Dict, Iterable, Optional

from sqlalchemy.exc import IntegrityError

from models.database import db
from models.graph import (
    GraphEntity,
    GraphEntityObservation,
    GraphRelationship,
    GraphRelationshipEvidence,
)
from utils.graph_extractors import (
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

logger = logging.getLogger(__name__)
EVIDENCE_RECORD_KEY_RE = re.compile(r'^erk:v2:[0-9a-f]{64}$')


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

    def canonicalize_entity_spec(self, case_id: int, spec: EntitySpec) -> EntityIdentity:
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

    def _lookup_known_system_id(self, case_id: int, hostname: Any) -> Optional[int]:
        if not _clean(hostname):
            return None
        try:
            from models.known_system import KnownSystem

            system, _match_type = KnownSystem.find_by_hostname_or_alias(hostname, case_id=case_id)
            return system.id if system else None
        except Exception:
            return None

    def materialize_candidate(self, case_id: int, candidate: GraphRelationshipCandidate) -> GraphRelationship:
        if candidate.case_id != int(case_id):
            raise ValueError('Graph relationship candidate case_id does not match materialization case')
        if candidate.derivation_type not in GraphDerivationType.AUTHORITATIVE_EXTRACTOR_TYPES:
            raise ValueError(f'Authoritative extractor cannot materialize {candidate.derivation_type}')
        if not EVIDENCE_RECORD_KEY_RE.fullmatch(_clean(candidate.evidence_record_key)):
            raise ValueError('Graph relationship provenance requires Evidence Identity v2 key')

        observed_at = _coerce_datetime(candidate.observed_at)
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
        )
        return relationship

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
    ) -> GraphRelationshipEvidence:
        evidence = GraphRelationshipEvidence.query.filter_by(
            relationship_id=relationship_id,
            evidence_record_key=evidence_record_key,
            evidence_role=evidence_role,
            extractor_name=extractor_name,
            extractor_version=extractor_version,
        ).first()
        if evidence:
            return evidence
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


def materialize_events_for_case(case_id: int, *, client=None, batch_size: int = 5000) -> Dict[str, int]:
    """Materialize deterministic graph facts from retained ClickHouse events."""
    if client is None:
        from utils.clickhouse import get_fresh_client

        client = get_fresh_client()

    sql = f"""
    SELECT {', '.join(GRAPH_EXTRACTOR_EVENT_COLUMNS)}
    FROM events
    WHERE case_id = {{case_id:UInt32}}
      AND evidence_record_key != ''
      AND (
        (
          source_host != ''
          AND process_id IS NOT NULL
          AND process_path != ''
          AND (
            event_id = '4688'
            OR (event_id = '1' AND positionCaseInsensitive(channel, 'Sysmon') > 0)
            OR (artifact_type = 'crowdstrike' AND event_id = 'ProcessRollup2')
          )
        )
        OR (
          (target_path != '' OR process_path != '')
          AND (file_hash_sha256 != '' OR file_hash_sha1 != '' OR file_hash_md5 != '')
        )
        OR (
          source_host != ''
          AND positionCaseInsensitive(extra_fields, 'host_ip') > 0
        )
        OR (
          event_id = '4624'
          AND lower(channel) = 'security'
          AND source_host != ''
          AND logon_id != ''
          AND (sid != '' OR (domain != '' AND username != ''))
        )
      )
    ORDER BY timestamp_utc, evidence_record_key
    """
    materializer = GraphMaterializer()
    events_seen = 0
    candidates_seen = 0
    errors = 0

    def iter_rows():
        if hasattr(client, 'query_rows_stream'):
            try:
                from utils.clickhouse import migration_source_query_settings
                settings = migration_source_query_settings()
            except Exception:
                settings = {'max_block_size': int(batch_size)}
            with client.query_rows_stream(
                sql,
                parameters={'case_id': int(case_id)},
                settings=settings,
            ) as rows:
                for streamed_row in rows:
                    yield streamed_row
        else:
            result = client.query(sql, parameters={'case_id': int(case_id)})
            for result_row in result.result_rows:
                yield result_row

    for row in iter_rows():
        event = event_from_clickhouse_row(row)
        events_seen += 1
        try:
            candidates = extract_event_relationships(event)
            candidates_seen += materializer.materialize_candidates(case_id, candidates)
            if events_seen % batch_size == 0:
                db.session.commit()
        except Exception as exc:
            errors += 1
            logger.warning(
                'Graph extraction skipped event %s for case %s: %s',
                event.get('evidence_record_key'),
                case_id,
                exc,
            )
            db.session.rollback()
    db.session.commit()
    return {'events_seen': events_seen, 'relationships_materialized': candidates_seen, 'errors': errors}


def rebuild_case_graph(case_id: int, *, client=None) -> Dict[str, Any]:
    clear_summary = clear_case_graph(case_id)
    materialize_summary = materialize_events_for_case(case_id, client=client)
    return {'cleared': clear_summary, 'materialized': materialize_summary}
