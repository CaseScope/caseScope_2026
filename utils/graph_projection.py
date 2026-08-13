"""Durable graph projection state and historical backfill helpers."""
from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, Optional

from models.case_file import CaseFile, FileStatus
from models.database import db
from models.graph import GraphEntity, GraphEntityObservation, GraphProjectionState, GraphRelationship, GraphRelationshipEvidence
from utils.graph_extractors import GRAPH_ELIGIBLE_EVENT_PREDICATE, GRAPH_EXTRACTOR_EVENT_COLUMNS
from utils.graph_materializer import GRAPH_PROJECTION_VERSION


GRAPH_PROJECTION_STATUSES = {
    'pending',
    'running',
    'completed',
    'no_eligible_evidence',
    'failed',
}
GRAPH_PROJECTION_MODES = {
    'historical_backfill',
    'ingest',
    'manual_build',
    'manual_rebuild',
}
ACTIVE_PROJECTION_STATUSES = {'pending', 'running'}
RESUMABLE_PROJECTION_STATUSES = {'pending', 'failed'}
ACTIVE_INGEST_FILE_STATUSES = {FileStatus.NEW, FileStatus.QUEUED, FileStatus.INGESTING}


def utcnow() -> datetime:
    return datetime.utcnow()


def graph_counts(case_id: int) -> Dict[str, int]:
    return {
        'graph_entities': GraphEntity.query.filter_by(case_id=int(case_id)).count(),
        'graph_entity_observations': GraphEntityObservation.query.filter_by(case_id=int(case_id)).count(),
        'graph_relationships': GraphRelationship.query.filter_by(case_id=int(case_id)).count(),
        'graph_relationship_evidence': GraphRelationshipEvidence.query.filter_by(case_id=int(case_id)).count(),
    }


def has_active_ingest(case_uuid: str) -> bool:
    return bool(
        CaseFile.query.filter(
            CaseFile.case_uuid == str(case_uuid),
            CaseFile.status.in_(sorted(ACTIVE_INGEST_FILE_STATUSES)),
        ).first()
    )


def get_projection_state(case_id: int) -> Optional[GraphProjectionState]:
    return GraphProjectionState.query.filter_by(case_id=int(case_id)).first()


def ensure_projection_state(
    case,
    *,
    mode: str = 'historical_backfill',
    status: str = 'pending',
) -> GraphProjectionState:
    if mode not in GRAPH_PROJECTION_MODES:
        raise ValueError(f'Unsupported graph projection mode: {mode}')
    if status not in GRAPH_PROJECTION_STATUSES:
        raise ValueError(f'Unsupported graph projection status: {status}')
    state = get_projection_state(case.id)
    if state is None:
        state = GraphProjectionState(
            case_id=case.id,
            case_uuid=case.uuid,
            status=status,
            mode=mode,
            projection_version=GRAPH_PROJECTION_VERSION,
        )
        db.session.add(state)
    else:
        state.case_uuid = case.uuid
        state.mode = mode
        state.status = status
        state.projection_version = GRAPH_PROJECTION_VERSION
        state.updated_at = utcnow()
    db.session.commit()
    return state


def mark_projection_state(
    state: GraphProjectionState,
    *,
    status: Optional[str] = None,
    mode: Optional[str] = None,
    task_id: Optional[str] = None,
    last_error: Optional[str] = None,
) -> GraphProjectionState:
    if status:
        if status not in GRAPH_PROJECTION_STATUSES:
            raise ValueError(f'Unsupported graph projection status: {status}')
        state.status = status
        if status in {'completed', 'no_eligible_evidence'}:
            state.completed_at = utcnow()
    if mode:
        if mode not in GRAPH_PROJECTION_MODES:
            raise ValueError(f'Unsupported graph projection mode: {mode}')
        state.mode = mode
    if task_id is not None:
        state.task_id = task_id
    if last_error:
        state.last_error = str(last_error)[:4000]
    state.updated_at = utcnow()
    db.session.commit()
    return state


def graph_eligible_probe(client, case_id: int) -> bool:
    sql = f"""
    SELECT evidence_record_key
    FROM events
    PREWHERE case_id = {{case_id:UInt32}}
    WHERE ({GRAPH_ELIGIBLE_EVENT_PREDICATE})
    LIMIT 1
    """
    result = client.query(sql, parameters={'case_id': int(case_id)})
    return bool(getattr(result, 'result_rows', None))


def graph_stream_explain_sql(case_id: int) -> str:
    columns = ', '.join(GRAPH_EXTRACTOR_EVENT_COLUMNS)
    return f"""
EXPLAIN indexes = 1
SELECT {columns}
FROM events
PREWHERE case_id = {int(case_id)}
WHERE ({GRAPH_ELIGIBLE_EVENT_PREDICATE})
""".strip()


def classify_case_for_graph_backfill(case, *, client=None, probe: bool = True, mutate: bool = True) -> Dict[str, Any]:
    counts = graph_counts(case.id)
    state = get_projection_state(case.id)
    active_ingest = has_active_ingest(case.uuid)
    has_graph = counts['graph_entities'] > 0 or counts['graph_relationships'] > 0
    qualifying_evidence = None
    planned_action = 'skip_existing_graph' if has_graph else 'probe'
    classification = 'existing_graph' if has_graph else 'empty_graph'

    if active_ingest:
        planned_action = 'defer_active_ingest'
        classification = 'active_ingest'
    elif has_graph and state is not None and state.status == 'running':
        planned_action = 'wait_running_projection'
        classification = 'running'
    elif has_graph and state is not None and state.status in RESUMABLE_PROJECTION_STATUSES:
        planned_action = 'resume' if state.status == 'failed' else 'process_pending'
        classification = 'resumable' if state.status == 'failed' else 'pending'
    elif has_graph:
        if state is None and mutate:
            state = ensure_projection_state(case, mode='historical_backfill', status='completed')
            state.last_error = 'existing graph predates projection state; marked completed without rebuild'
            db.session.commit()
    elif state is not None and state.status in RESUMABLE_PROJECTION_STATUSES:
        planned_action = 'resume' if state.status == 'failed' else 'process_pending'
        classification = 'resumable' if state.status == 'failed' else 'pending'
    elif probe and client is not None:
        qualifying_evidence = graph_eligible_probe(client, case.id)
        if qualifying_evidence:
            if mutate:
                state = ensure_projection_state(case, mode='historical_backfill', status='pending')
            planned_action = 'process_missing_graph'
            classification = 'missing_eligible'
        else:
            if mutate:
                state = ensure_projection_state(case, mode='historical_backfill', status='no_eligible_evidence')
            planned_action = 'skip_no_eligible_evidence'
            classification = 'missing_no_eligible'

    return {
        'case_id': case.id,
        'case_uuid': case.uuid,
        'case_name': case.name,
        **counts,
        'projection_state': state.status if state else 'untracked',
        'projection_mode': state.mode if state else '',
        'active_ingest': active_ingest,
        'qualifying_evidence': qualifying_evidence,
        'planned_action': planned_action,
        'classification': classification,
        'state': state,
    }


def serialize_projection_state(state: Optional[GraphProjectionState]) -> Dict[str, Any]:
    if state is None:
        return {
            'status': 'untracked',
            'mode': '',
            'projection_version': GRAPH_PROJECTION_VERSION,
        }
    return {
        'id': state.id,
        'case_id': state.case_id,
        'case_uuid': state.case_uuid,
        'status': state.status,
        'mode': state.mode,
        'projection_version': state.projection_version,
        'started_at': state.started_at.isoformat() if state.started_at else None,
        'updated_at': state.updated_at.isoformat() if state.updated_at else None,
        'completed_at': state.completed_at.isoformat() if state.completed_at else None,
        'last_timestamp_utc': state.last_timestamp_utc.isoformat() if state.last_timestamp_utc else None,
        'last_evidence_record_key': state.last_evidence_record_key,
        'current_window_start_utc': state.current_window_start_utc.isoformat() if state.current_window_start_utc else None,
        'current_window_end_utc': state.current_window_end_utc.isoformat() if state.current_window_end_utc else None,
        'last_completed_window_end_utc': state.last_completed_window_end_utc.isoformat() if state.last_completed_window_end_utc else None,
        'windows_completed': int(state.windows_completed or 0),
        'events_seen': int(state.events_seen or 0),
        'relationships_materialized': int(state.relationships_materialized or 0),
        'errors': int(state.errors or 0),
        'task_id': state.task_id,
        'last_error': state.last_error,
    }
