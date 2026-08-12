"""Exact IOC UUID -> evidence ERK match provenance (Phase 0E).

``events.ioc_types`` is a display label only. It records THAT some IOC of a
given type tagged an event, but never WHICH specific IOC matched. This module
persists the exact, durable link: a specific ``IOC`` (bound by its immutable
``ioc.uuid``) matched a specific normalized evidence record (``evidence_record_key``).

Design rules:

* The exact ``ioc.uuid`` is stored verbatim. It is passed in from the caller
  where the IOC object is known; it is NEVER re-inferred from ``ioc_type`` later.
* ERKs are streamed from ClickHouse in LIMIT/OFFSET batches and upserted per
  batch, so millions of matches never load into a single Python list.
* Upserts are idempotent on ``(case_id, ioc_uuid, evidence_record_key,
  matched_field)`` so re-tagging refreshes rows without duplication.
* Source-removal / reprocess invalidation is handled by
  ``utils.graph_support_lifecycle.GraphSupportLifecycleService`` (CaseFile-scoped)
  which transitions matching rows' ``support_state``.
"""
from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional

from sqlalchemy.dialects.postgresql import insert as pg_insert

from models.database import db
from models.ioc_evidence_match import IOCEvidenceMatch
from utils.graph_identity import GraphSourceRefType, GraphSupportState

logger = logging.getLogger(__name__)

DEFAULT_MATCHED_FIELD = 'search_blob'
_UPSERT_CHUNK = 500
_MATCHED_VALUE_MAX = 4096


def _clean(value: Any) -> str:
    return str(value or '').strip()


def _coerce_dt(value: Any) -> Optional[datetime]:
    if value is None or value == '':
        return None
    if isinstance(value, datetime):
        return value.replace(tzinfo=None)
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value.replace('Z', '+00:00')).replace(tzinfo=None)
        except ValueError:
            return None
    return None


def _normalize_meta_item(item: Any) -> Optional[Dict[str, Any]]:
    """Accept a bare ERK string or a dict of ERK + metadata; normalize to dict."""
    if isinstance(item, str):
        erk = _clean(item)
        return {'evidence_record_key': erk} if erk else None
    if isinstance(item, dict):
        erk = _clean(item.get('evidence_record_key'))
        if not erk:
            return None
        return dict(item, evidence_record_key=erk)
    return None


def record_matches(
    case_id: int,
    ioc_id: int,
    ioc_uuid: str,
    ioc_type: str,
    matched_value: str,
    erks_with_meta: Iterable[Any],
    *,
    matched_field: str = DEFAULT_MATCHED_FIELD,
    source_table: str = 'events',
    default_source_ref_type: Optional[str] = None,
    default_source_ref_id: Optional[int] = None,
    support_state: str = GraphSupportState.ACTIVE,
    scan_version: Optional[str] = None,
    session=None,
) -> Dict[str, int]:
    """Idempotently upsert exact IOC -> ERK matches.

    ``erks_with_meta`` yields either bare ERK strings or dicts with keys:
    ``evidence_record_key`` (required), ``source_ref_type``, ``source_ref_id``,
    ``observed_at``, ``matched_field``, ``source_table``, ``metadata``.
    """
    session = session or db.session
    ioc_uuid = _clean(ioc_uuid)
    if not ioc_uuid:
        raise ValueError('record_matches requires an exact ioc_uuid')

    now = datetime.utcnow()
    value_trunc = _clean(matched_value)[:_MATCHED_VALUE_MAX]
    processed = 0
    buffer: List[Dict[str, Any]] = []

    def _flush() -> None:
        nonlocal processed
        if not buffer:
            return
        stmt = pg_insert(IOCEvidenceMatch.__table__).values(buffer)
        stmt = stmt.on_conflict_do_update(
            constraint='uq_ioc_evidence_match_exact',
            set_={
                'ioc_id': stmt.excluded.ioc_id,
                'ioc_type': stmt.excluded.ioc_type,
                'matched_value': stmt.excluded.matched_value,
                'source_table': stmt.excluded.source_table,
                'source_ref_type': stmt.excluded.source_ref_type,
                'source_ref_id': stmt.excluded.source_ref_id,
                'support_state': stmt.excluded.support_state,
                'observed_at': stmt.excluded.observed_at,
                'metadata_json': stmt.excluded.metadata_json,
                'updated_at': now,
            },
        )
        session.execute(stmt)
        processed += len(buffer)
        buffer.clear()

    for raw in erks_with_meta:
        item = _normalize_meta_item(raw)
        if item is None:
            continue
        row_ref_type = item.get('source_ref_type', default_source_ref_type)
        row_ref_id = item.get('source_ref_id', default_source_ref_id)
        try:
            row_ref_id = int(row_ref_id) if row_ref_id not in (None, '') else None
        except (TypeError, ValueError):
            row_ref_id = None
        buffer.append({
            'case_id': int(case_id),
            'ioc_id': int(ioc_id),
            'ioc_uuid': ioc_uuid,
            'ioc_type': _clean(ioc_type)[:100],
            'matched_value': value_trunc,
            'matched_field': _clean(item.get('matched_field') or matched_field)[:80],
            'evidence_record_key': item['evidence_record_key'][:96],
            'source_table': _clean(item.get('source_table') or source_table)[:80],
            'source_ref_type': _clean(row_ref_type) or None,
            'source_ref_id': row_ref_id,
            'support_state': _clean(item.get('support_state') or support_state)[:40],
            'observed_at': _coerce_dt(item.get('observed_at')),
            'created_at': now,
            'updated_at': now,
            'metadata_json': {
                **(item.get('metadata') or {}),
                **({'scan_version': scan_version} if scan_version else {}),
            },
        })
        if len(buffer) >= _UPSERT_CHUNK:
            _flush()
    _flush()
    return {'processed': processed}


def begin_ioc_match_scan(
    case_id: int,
    *,
    scan_version: str,
    session=None,
) -> int:
    """Mark current exact IOC matches non-active before a retagging scan.

    Current matches must be reproven by this scan. Rows not re-upserted ACTIVE by
    the scan are finalized INVALIDATED, preserving history without continuing to
    drive IOC graph pivots.
    """
    session = session or db.session
    now = datetime.utcnow()
    rows = IOCEvidenceMatch.query.filter(
        IOCEvidenceMatch.case_id == int(case_id),
        IOCEvidenceMatch.support_state == GraphSupportState.ACTIVE,
    ).yield_per(1000)
    updated = 0
    for row in rows:
        row.support_state = GraphSupportState.PENDING_REVALIDATION
        meta = dict(row.metadata_json or {})
        meta['pending_scan_version'] = str(scan_version)
        row.metadata_json = meta
        row.updated_at = now
        updated += 1
    session.flush()
    return updated


def finalize_ioc_match_scan(
    case_id: int,
    *,
    scan_version: str,
    session=None,
) -> int:
    """Invalidate exact IOC matches not reproven by the completed scan."""
    session = session or db.session
    now = datetime.utcnow()
    rows = IOCEvidenceMatch.query.filter(
        IOCEvidenceMatch.case_id == int(case_id),
        IOCEvidenceMatch.support_state == GraphSupportState.PENDING_REVALIDATION,
    ).yield_per(1000)
    updated = 0
    for row in rows:
        row.support_state = GraphSupportState.INVALIDATED
        meta = dict(row.metadata_json or {})
        meta['invalidated_by_scan_version'] = str(scan_version)
        row.metadata_json = meta
        row.updated_at = now
        updated += 1
    session.flush()
    return updated


def query_by_ioc_uuid(
    case_id: int,
    ioc_uuid: str,
    *,
    only_active: bool = False,
) -> List[IOCEvidenceMatch]:
    q = IOCEvidenceMatch.query.filter(
        IOCEvidenceMatch.case_id == int(case_id),
        IOCEvidenceMatch.ioc_uuid == _clean(ioc_uuid),
    )
    if only_active:
        q = q.filter(IOCEvidenceMatch.support_state == GraphSupportState.ACTIVE)
    return q.order_by(IOCEvidenceMatch.evidence_record_key.asc()).all()


def query_by_erk(
    case_id: int,
    evidence_record_key: str,
    *,
    only_active: bool = False,
) -> List[IOCEvidenceMatch]:
    q = IOCEvidenceMatch.query.filter(
        IOCEvidenceMatch.case_id == int(case_id),
        IOCEvidenceMatch.evidence_record_key == _clean(evidence_record_key),
    )
    if only_active:
        q = q.filter(IOCEvidenceMatch.support_state == GraphSupportState.ACTIVE)
    return q.order_by(IOCEvidenceMatch.ioc_uuid.asc()).all()


def invalidate_matches_by_erks(
    case_id: int,
    evidence_record_keys: Iterable[str],
    *,
    final_state: str = GraphSupportState.INVALIDATED,
    session=None,
    batch_size: int = 500,
) -> int:
    """Direct ERK-scoped invalidation helper (source lifecycle uses this pattern)."""
    session = session or db.session
    keys = [_clean(k) for k in evidence_record_keys if _clean(k)]
    updated = 0
    for start in range(0, len(keys), max(1, batch_size)):
        chunk = keys[start:start + max(1, batch_size)]
        if not chunk:
            continue
        rows = IOCEvidenceMatch.query.filter(
            IOCEvidenceMatch.case_id == int(case_id),
            IOCEvidenceMatch.evidence_record_key.in_(chunk),
            IOCEvidenceMatch.support_state != final_state,
        ).all()
        for row in rows:
            row.support_state = final_state
            updated += 1
        session.flush()
    return updated


def _stream_ioc_matching_erks(
    case_id: int,
    ioc_value: str,
    ioc_type: str,
    *,
    match_type: Optional[str] = None,
    aliases: Optional[List[str]] = None,
    client=None,
    batch_size: int = 5000,
):
    """Yield batches of (erk, case_file_id, timestamp) tuples matching an IOC.

    Uses the same match clause as event tagging so provenance stays consistent
    with the visible ``ioc_types`` badges.
    """
    from models.ioc import detect_match_type
    from utils.ioc_artifact_tagger import build_ioc_match_clause

    if not _clean(ioc_value):
        return
    if client is None:
        from utils.clickhouse import get_fresh_client

        client = get_fresh_client()

    effective_match_type = match_type or detect_match_type(ioc_value, ioc_type)
    where_clause = build_ioc_match_clause(ioc_value, ioc_type, effective_match_type, aliases)

    offset = 0
    batch_size = max(1, int(batch_size))
    while True:
        query = f"""
            SELECT evidence_record_key, case_file_id, timestamp
            FROM events
            WHERE case_id = {int(case_id)}
              AND evidence_record_key != ''
              AND ({where_clause})
            ORDER BY evidence_record_key
            LIMIT {batch_size} OFFSET {offset}
        """
        try:
            result = client.query(query)
        except Exception as exc:
            logger.error('IOC provenance ERK stream failed for case %s: %s', case_id, exc)
            return
        rows = result.result_rows or []
        if not rows:
            break
        yield rows
        if len(rows) < batch_size:
            break
        offset += batch_size


def record_ioc_evidence_matches(
    case_id: int,
    ioc,
    *,
    client=None,
    session=None,
    batch_size: int = 5000,
    commit_each_batch: bool = True,
    scan_version: Optional[str] = None,
) -> Dict[str, int]:
    """Stream matching ERKs for an IOC and persist exact IOCEvidenceMatch rows.

    ``ioc`` must expose ``id``, ``uuid``, ``ioc_type``, ``value`` and optionally
    ``aliases`` / ``get_effective_match_type``. The exact ``ioc.uuid`` is stored.
    """
    session = session or db.session
    match_type = None
    if hasattr(ioc, 'get_effective_match_type'):
        try:
            match_type = ioc.get_effective_match_type()
        except Exception:
            match_type = None

    total = 0
    for rows in _stream_ioc_matching_erks(
        case_id,
        ioc.value,
        ioc.ioc_type,
        match_type=match_type,
        aliases=getattr(ioc, 'aliases', None),
        client=client,
        batch_size=batch_size,
    ):
        erks_with_meta = []
        for row in rows:
            erk = _clean(row[0])
            if not erk:
                continue
            case_file_id = row[1]
            timestamp = row[2]
            meta_item = {
                'evidence_record_key': erk,
                'observed_at': timestamp,
            }
            if case_file_id not in (None, '', 0):
                meta_item['source_ref_type'] = GraphSourceRefType.CASE_FILE
                meta_item['source_ref_id'] = case_file_id
            erks_with_meta.append(meta_item)
        if not erks_with_meta:
            continue
        result = record_matches(
            case_id,
            ioc.id,
            ioc.uuid,
            ioc.ioc_type,
            ioc.value,
            erks_with_meta,
            session=session,
            scan_version=scan_version,
        )
        total += result['processed']
        if commit_each_batch:
            session.commit()
    return {'matches_recorded': total}


__all__ = [
    'record_matches',
    'begin_ioc_match_scan',
    'finalize_ioc_match_scan',
    'query_by_ioc_uuid',
    'query_by_erk',
    'invalidate_matches_by_erks',
    'record_ioc_evidence_matches',
]
