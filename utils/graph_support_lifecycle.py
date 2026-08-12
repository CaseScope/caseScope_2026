"""Graph relationship support lifecycle for source removal/reprocessing.

PostgreSQL and ClickHouse are not one ACID transaction. Sequence:

1. Identify affected support for a source.
2. Mark support PENDING_REMOVAL / PENDING_REVALIDATION (non-authoritative).
3. Perform destructive source operation.
4. Finalize support as UNAVAILABLE / INVALIDATED.
5. Revalidate affected relationships (ACTIVE vs UNSUPPORTED).
6. On source-op failure, revalidate remaining evidence and restore ACTIVE where proven.

Thread frozen snapshots are never rewritten by this service.
"""
from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set

from sqlalchemy import and_, or_

from models.database import db
from models.graph import GraphRelationship, GraphRelationshipEvidence
from models.ioc_evidence_match import IOCEvidenceMatch
from utils.graph_identity import GraphSourceRefType, GraphSupportState, GraphValidationState


logger = logging.getLogger(__name__)

DEFAULT_BATCH_SIZE = 500


class GraphSupportLifecycleError(ValueError):
    """Raised for client-correctable lifecycle errors."""


class GraphSupportLifecycleService:
    def __init__(self, session=None, *, batch_size: int = DEFAULT_BATCH_SIZE):
        self.session = session or db.session
        self.batch_size = max(1, int(batch_size))

    def begin_case_file_removal(
        self,
        *,
        case_id: int,
        case_file_id: int,
        reason: str = 'case_file_removal',
        evidence_record_keys: Optional[Iterable[str]] = None,
    ) -> Dict[str, Any]:
        """Mark support non-active before destructive ClickHouse/PG deletion."""
        return self._transition_case_file_support(
            case_id=case_id,
            case_file_id=case_file_id,
            pending_state=GraphSupportState.PENDING_REMOVAL,
            reason=reason,
            evidence_record_keys=evidence_record_keys,
        )

    def begin_case_file_revalidation(
        self,
        *,
        case_id: int,
        case_file_id: int,
        reason: str = 'case_file_reprocess',
        evidence_record_keys: Optional[Iterable[str]] = None,
    ) -> Dict[str, Any]:
        return self._transition_case_file_support(
            case_id=case_id,
            case_file_id=case_file_id,
            pending_state=GraphSupportState.PENDING_REVALIDATION,
            reason=reason,
            evidence_record_keys=evidence_record_keys,
        )

    def finalize_case_file_removal(
        self,
        *,
        case_id: int,
        case_file_id: int,
        reason: str = 'case_file_removed',
    ) -> Dict[str, Any]:
        summary = self._finalize_source_support(
            case_id=case_id,
            source_ref_type=GraphSourceRefType.CASE_FILE,
            source_ref_id=case_file_id,
            final_state=GraphSupportState.UNAVAILABLE,
            reason=reason,
        )
        ioc_summary = self._finalize_ioc_matches_for_source(
            case_id=case_id,
            source_ref_type=GraphSourceRefType.CASE_FILE,
            source_ref_id=case_file_id,
            final_state=GraphSupportState.UNAVAILABLE,
        )
        summary['ioc_matches_updated'] = ioc_summary['updated']
        return summary

    def finalize_case_file_revalidation(
        self,
        *,
        case_id: int,
        case_file_id: int,
        reason: str = 'case_file_reprocessed',
    ) -> Dict[str, Any]:
        """Mark old generation support INVALIDATED after reprocess delete completes."""
        summary = self._finalize_source_support(
            case_id=case_id,
            source_ref_type=GraphSourceRefType.CASE_FILE,
            source_ref_id=case_file_id,
            final_state=GraphSupportState.INVALIDATED,
            reason=reason,
        )
        ioc_summary = self._finalize_ioc_matches_for_source(
            case_id=case_id,
            source_ref_type=GraphSourceRefType.CASE_FILE,
            source_ref_id=case_file_id,
            final_state=GraphSupportState.INVALIDATED,
        )
        summary['ioc_matches_updated'] = ioc_summary['updated']
        return summary

    def restore_case_file_support_if_source_remains(
        self,
        *,
        case_id: int,
        case_file_id: int,
        reason: str = 'source_deletion_failed_restore',
    ) -> Dict[str, Any]:
        """If pending removal failed and source still exists, restore ACTIVE support."""
        now = datetime.utcnow()
        q = GraphRelationshipEvidence.query.filter(
            GraphRelationshipEvidence.case_id == case_id,
            GraphRelationshipEvidence.source_ref_type == GraphSourceRefType.CASE_FILE,
            GraphRelationshipEvidence.source_ref_id == case_file_id,
            GraphRelationshipEvidence.support_state.in_(
                [
                    GraphSupportState.PENDING_REMOVAL,
                    GraphSupportState.PENDING_REVALIDATION,
                ]
            ),
        )
        relationship_ids: Set[int] = set()
        updated = 0
        for row in q.yield_per(self.batch_size):
            row.support_state = GraphSupportState.ACTIVE
            row.support_state_reason = reason
            row.support_state_changed_at = now
            relationship_ids.add(row.relationship_id)
            updated += 1
        self.session.flush()
        revalidated = self.revalidate_relationships(case_id, relationship_ids)
        ioc_restored = self._restore_ioc_matches_for_source(
            case_id=case_id,
            source_ref_type=GraphSourceRefType.CASE_FILE,
            source_ref_id=case_file_id,
            reason=reason,
        )
        return {
            'support_restored': updated,
            'relationships_revalidated': revalidated,
            'ioc_matches_restored': ioc_restored,
        }

    def restore_source_support_if_source_remains(
        self,
        *,
        case_id: int,
        source_ref_type: str,
        source_ref_id: int,
        reason: str = 'source_deletion_failed_restore',
    ) -> Dict[str, Any]:
        """Restore pending support for a non-CaseFile source that still exists."""
        now = datetime.utcnow()
        q = GraphRelationshipEvidence.query.filter(
            GraphRelationshipEvidence.case_id == case_id,
            GraphRelationshipEvidence.source_ref_type == source_ref_type,
            GraphRelationshipEvidence.source_ref_id == int(source_ref_id),
            GraphRelationshipEvidence.support_state.in_(
                [
                    GraphSupportState.PENDING_REMOVAL,
                    GraphSupportState.PENDING_REVALIDATION,
                ]
            ),
        )
        relationship_ids: Set[int] = set()
        updated = 0
        for row in q.yield_per(self.batch_size):
            row.support_state = GraphSupportState.ACTIVE
            row.support_state_reason = reason
            row.support_state_changed_at = now
            relationship_ids.add(row.relationship_id)
            updated += 1
        self.session.flush()
        revalidated = self.revalidate_relationships(case_id, relationship_ids)
        ioc_restored = self._restore_ioc_matches_for_source(
            case_id=case_id,
            source_ref_type=source_ref_type,
            source_ref_id=source_ref_id,
            reason=reason,
        )
        return {
            'support_restored': updated,
            'relationships_revalidated': revalidated,
            'ioc_matches_restored': ioc_restored,
        }

    def begin_memory_job_removal(self, *, case_id: int, memory_job_id: int, reason: str = 'memory_job_removal') -> Dict[str, Any]:
        return self._mark_source_pending(
            case_id=case_id,
            source_ref_type=GraphSourceRefType.MEMORY_JOB,
            source_ref_id=memory_job_id,
            pending_state=GraphSupportState.PENDING_REMOVAL,
            reason=reason,
        )

    def finalize_memory_job_removal(self, *, case_id: int, memory_job_id: int, reason: str = 'memory_job_removed') -> Dict[str, Any]:
        return self._finalize_source_support(
            case_id=case_id,
            source_ref_type=GraphSourceRefType.MEMORY_JOB,
            source_ref_id=memory_job_id,
            final_state=GraphSupportState.UNAVAILABLE,
            reason=reason,
        )

    def begin_memory_job_revalidation(self, *, case_id: int, memory_job_id: int, reason: str = 'memory_job_reprocess') -> Dict[str, Any]:
        return self._mark_source_pending(
            case_id=case_id,
            source_ref_type=GraphSourceRefType.MEMORY_JOB,
            source_ref_id=memory_job_id,
            pending_state=GraphSupportState.PENDING_REVALIDATION,
            reason=reason,
        )

    def finalize_memory_job_revalidation(self, *, case_id: int, memory_job_id: int, reason: str = 'memory_job_reprocessed') -> Dict[str, Any]:
        return self._finalize_source_support(
            case_id=case_id,
            source_ref_type=GraphSourceRefType.MEMORY_JOB,
            source_ref_id=memory_job_id,
            final_state=GraphSupportState.INVALIDATED,
            reason=reason,
        )

    def begin_pcap_removal(self, *, case_id: int, pcap_id: int, reason: str = 'pcap_removal') -> Dict[str, Any]:
        return self._mark_source_pending(
            case_id=case_id,
            source_ref_type=GraphSourceRefType.PCAP_FILE,
            source_ref_id=pcap_id,
            pending_state=GraphSupportState.PENDING_REMOVAL,
            reason=reason,
        )

    def finalize_pcap_removal(self, *, case_id: int, pcap_id: int, reason: str = 'pcap_removed') -> Dict[str, Any]:
        return self._finalize_source_support(
            case_id=case_id,
            source_ref_type=GraphSourceRefType.PCAP_FILE,
            source_ref_id=pcap_id,
            final_state=GraphSupportState.UNAVAILABLE,
            reason=reason,
        )

    def begin_pcap_revalidation(self, *, case_id: int, pcap_id: int, reason: str = 'pcap_reprocess') -> Dict[str, Any]:
        return self._mark_source_pending(
            case_id=case_id,
            source_ref_type=GraphSourceRefType.PCAP_FILE,
            source_ref_id=pcap_id,
            pending_state=GraphSupportState.PENDING_REVALIDATION,
            reason=reason,
        )

    def finalize_pcap_revalidation(self, *, case_id: int, pcap_id: int, reason: str = 'pcap_reprocessed') -> Dict[str, Any]:
        return self._finalize_source_support(
            case_id=case_id,
            source_ref_type=GraphSourceRefType.PCAP_FILE,
            source_ref_id=pcap_id,
            final_state=GraphSupportState.INVALIDATED,
            reason=reason,
        )

    def invalidate_support_by_extractor(
        self,
        *,
        extractor_name: str,
        reason: str,
        case_id: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Invalidate current support produced by an extractor withdrawn for correctness."""
        from sqlalchemy import distinct

        cases_q = self.session.query(distinct(GraphRelationshipEvidence.case_id)).filter(
            GraphRelationshipEvidence.extractor_name == str(extractor_name),
        )
        if case_id is not None:
            cases_q = cases_q.filter(GraphRelationshipEvidence.case_id == int(case_id))
        affected_case_ids = [int(row[0]) for row in cases_q.all()]

        revalidation = {}
        updated = 0
        relationships_touched = 0
        for affected_case_id in affected_case_ids:
            relationship_ids = {
                int(row[0])
                for row in self.session.query(GraphRelationshipEvidence.relationship_id)
                .filter(
                    GraphRelationshipEvidence.case_id == affected_case_id,
                    GraphRelationshipEvidence.extractor_name == str(extractor_name),
                )
                .all()
                if row[0] is not None
            }
            if not relationship_ids:
                continue

            now = datetime.utcnow()
            current_rows = GraphRelationshipEvidence.query.filter(
                GraphRelationshipEvidence.case_id == affected_case_id,
                GraphRelationshipEvidence.extractor_name == str(extractor_name),
                GraphRelationshipEvidence.support_state.in_(
                    [
                        GraphSupportState.ACTIVE,
                        GraphSupportState.PENDING_REMOVAL,
                        GraphSupportState.PENDING_REVALIDATION,
                    ]
                ),
            )
            case_updated = 0
            for row in current_rows.yield_per(self.batch_size):
                row.support_state = GraphSupportState.INVALIDATED
                row.support_state_reason = reason
                row.support_state_changed_at = now
                case_updated += 1
            self.session.flush()
            revalidation[affected_case_id] = self.revalidate_relationships(
                affected_case_id,
                relationship_ids,
                commit=False,
            )
            self.session.commit()
            updated += case_updated
            relationships_touched += len(relationship_ids)
        return {
            'support_updated': updated,
            'relationships_touched': relationships_touched,
            'revalidation': revalidation,
        }

    def revalidate_relationships(self, case_id: int, relationship_ids: Iterable[int], *, commit: bool = True) -> Dict[str, int]:
        """Recalculate relationship validation_state from CURRENT active support only."""
        ids = sorted({int(rid) for rid in relationship_ids if rid is not None})
        active_count = 0
        unsupported_count = 0
        unchanged = 0
        for start in range(0, len(ids), self.batch_size):
            chunk = ids[start:start + self.batch_size]
            if not chunk:
                continue
            relationships = (
                GraphRelationship.query.filter(
                    GraphRelationship.case_id == case_id,
                    GraphRelationship.id.in_(chunk),
                ).all()
            )
            counts = self._active_support_counts(case_id, [r.id for r in relationships])
            now = datetime.utcnow()
            for rel in relationships:
                current_active = int(counts.get(rel.id, 0))
                if current_active > 0:
                    desired = GraphValidationState.ACTIVE
                else:
                    # Preserve INVALIDATED when already explicitly invalidated; otherwise UNSUPPORTED.
                    if rel.validation_state == GraphValidationState.INVALIDATED:
                        desired = GraphValidationState.INVALIDATED
                    else:
                        desired = GraphValidationState.UNSUPPORTED
                if rel.validation_state == desired:
                    unchanged += 1
                    continue
                rel.validation_state = desired
                meta = dict(rel.metadata_json or {})
                meta['support_revalidated_at'] = now.isoformat() + 'Z'
                meta['active_support_count'] = current_active
                rel.metadata_json = meta
                rel.updated_at = now
                if desired == GraphValidationState.ACTIVE:
                    active_count += 1
                else:
                    unsupported_count += 1
            self.session.flush()
        if commit:
            self.session.commit()
        return {
            'activated': active_count,
            'unsupported_or_invalidated': unsupported_count,
            'unchanged': unchanged,
            'examined': len(ids),
        }

    def active_support_count(self, case_id: int, relationship_id: int) -> int:
        return int(self._active_support_counts(case_id, [relationship_id]).get(relationship_id, 0))

    def audit_summary_payload(
        self,
        *,
        case_id: int,
        source_ref_type: str,
        source_ref_id: int,
        operation: str,
        support_summary: Dict[str, Any],
        relationship_summary: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        return {
            'case_id': int(case_id),
            'source_ref_type': source_ref_type,
            'source_ref_id': int(source_ref_id),
            'operation': operation,
            'affected_support_count': int(support_summary.get('support_updated') or support_summary.get('updated') or 0),
            'affected_relationship_count': int(
                (relationship_summary or {}).get('examined')
                or support_summary.get('relationships_touched')
                or 0
            ),
            'resulting_active_count': int((relationship_summary or {}).get('activated') or 0),
            'resulting_unsupported_count': int(
                (relationship_summary or {}).get('unsupported_or_invalidated') or 0
            ),
        }

    def _transition_case_file_support(
        self,
        *,
        case_id: int,
        case_file_id: int,
        pending_state: str,
        reason: str,
        evidence_record_keys: Optional[Iterable[str]],
    ) -> Dict[str, Any]:
        relationship_ids: Set[int] = set()
        updated = 0
        ioc_updated = 0

        # Prefer direct source_ref matches.
        direct = self._mark_source_pending(
            case_id=case_id,
            source_ref_type=GraphSourceRefType.CASE_FILE,
            source_ref_id=case_file_id,
            pending_state=pending_state,
            reason=reason,
            commit=False,
        )
        updated += direct['support_updated']
        relationship_ids.update(direct['relationship_ids'])

        ioc_updated += self._mark_ioc_matches_pending(
            case_id=case_id,
            source_ref_type=GraphSourceRefType.CASE_FILE,
            source_ref_id=case_file_id,
            pending_state=pending_state,
            evidence_record_keys=[],
            include_source_ref=True,
        )

        # Also bind by ERK batches collected BEFORE deletion for legacy rows
        # lacking source_ref. Do not collect a whole CaseFile into memory.
        for keys in _iter_clean_key_batches(evidence_record_keys, self.batch_size):
            erk_summary = self._mark_erks_pending(
                case_id=case_id,
                evidence_record_keys=keys,
                pending_state=pending_state,
                reason=reason,
                source_ref_type=GraphSourceRefType.CASE_FILE,
                source_ref_id=case_file_id,
            )
            updated += erk_summary['support_updated']
            relationship_ids.update(erk_summary['relationship_ids'])
            ioc_updated += self._mark_ioc_matches_pending(
                case_id=case_id,
                source_ref_type=GraphSourceRefType.CASE_FILE,
                source_ref_id=case_file_id,
                pending_state=pending_state,
                evidence_record_keys=keys,
                include_source_ref=False,
            )

        # Pending support must not count as authoritative.
        revalidated = self.revalidate_relationships(case_id, relationship_ids)
        return {
            'support_updated': updated,
            'relationships_touched': len(relationship_ids),
            'relationship_ids': sorted(relationship_ids),
            'ioc_matches_updated': ioc_updated,
            'revalidation': revalidated,
        }

    def _mark_source_pending(
        self,
        *,
        case_id: int,
        source_ref_type: str,
        source_ref_id: int,
        pending_state: str,
        reason: str,
        commit: bool = True,
    ) -> Dict[str, Any]:
        now = datetime.utcnow()
        q = GraphRelationshipEvidence.query.filter(
            GraphRelationshipEvidence.case_id == case_id,
            GraphRelationshipEvidence.source_ref_type == source_ref_type,
            GraphRelationshipEvidence.source_ref_id == int(source_ref_id),
            GraphRelationshipEvidence.support_state == GraphSupportState.ACTIVE,
        )
        relationship_ids: Set[int] = set()
        updated = 0
        for row in q.yield_per(self.batch_size):
            row.support_state = pending_state
            row.support_state_reason = reason
            row.support_state_changed_at = now
            relationship_ids.add(row.relationship_id)
            updated += 1
        self.session.flush()
        if commit:
            self.session.commit()
        return {
            'support_updated': updated,
            'relationship_ids': sorted(relationship_ids),
            'relationships_touched': len(relationship_ids),
        }

    def _mark_erks_pending(
        self,
        *,
        case_id: int,
        evidence_record_keys: Sequence[str],
        pending_state: str,
        reason: str,
        source_ref_type: str,
        source_ref_id: int,
    ) -> Dict[str, Any]:
        now = datetime.utcnow()
        relationship_ids: Set[int] = set()
        updated = 0
        keys = list(evidence_record_keys)
        for start in range(0, len(keys), self.batch_size):
            chunk = keys[start:start + self.batch_size]
            rows = GraphRelationshipEvidence.query.filter(
                GraphRelationshipEvidence.case_id == case_id,
                GraphRelationshipEvidence.evidence_record_key.in_(chunk),
                GraphRelationshipEvidence.support_state == GraphSupportState.ACTIVE,
            ).all()
            for row in rows:
                row.support_state = pending_state
                row.support_state_reason = reason
                row.support_state_changed_at = now
                # Backfill source locator when discovered via ERK set.
                if not row.source_ref_type:
                    row.source_ref_type = source_ref_type
                    row.source_ref_id = int(source_ref_id)
                relationship_ids.add(row.relationship_id)
                updated += 1
            self.session.flush()
        return {
            'support_updated': updated,
            'relationship_ids': sorted(relationship_ids),
        }

    def _finalize_source_support(
        self,
        *,
        case_id: int,
        source_ref_type: str,
        source_ref_id: int,
        final_state: str,
        reason: str,
    ) -> Dict[str, Any]:
        now = datetime.utcnow()
        q = GraphRelationshipEvidence.query.filter(
            GraphRelationshipEvidence.case_id == case_id,
            GraphRelationshipEvidence.source_ref_type == source_ref_type,
            GraphRelationshipEvidence.source_ref_id == int(source_ref_id),
            GraphRelationshipEvidence.support_state.in_(
                [
                    GraphSupportState.ACTIVE,
                    GraphSupportState.PENDING_REMOVAL,
                    GraphSupportState.PENDING_REVALIDATION,
                ]
            ),
        )
        relationship_ids: Set[int] = set()
        updated = 0
        for row in q.yield_per(self.batch_size):
            row.support_state = final_state
            row.support_state_reason = reason
            row.support_state_changed_at = now
            relationship_ids.add(row.relationship_id)
            updated += 1
        self.session.flush()
        revalidated = self.revalidate_relationships(case_id, relationship_ids)
        return {
            'support_updated': updated,
            'relationships_touched': len(relationship_ids),
            'relationship_ids': sorted(relationship_ids),
            'revalidation': revalidated,
        }

    def _mark_ioc_matches_pending(
        self,
        *,
        case_id: int,
        source_ref_type: str,
        source_ref_id: int,
        pending_state: str,
        evidence_record_keys: Sequence[str],
        include_source_ref: bool = True,
    ) -> int:
        updated = 0
        clauses = []
        if include_source_ref:
            clauses.append(
                and_(
                    IOCEvidenceMatch.source_ref_type == source_ref_type,
                    IOCEvidenceMatch.source_ref_id == int(source_ref_id),
                )
            )
        keys = [k for k in evidence_record_keys if k]
        if keys:
            clauses.append(IOCEvidenceMatch.evidence_record_key.in_(keys))
        if not clauses:
            return 0
        q = IOCEvidenceMatch.query.filter(
            IOCEvidenceMatch.case_id == case_id,
            IOCEvidenceMatch.support_state == GraphSupportState.ACTIVE,
            or_(*clauses),
        )
        for row in q.yield_per(self.batch_size):
            row.support_state = pending_state
            if not row.source_ref_type:
                row.source_ref_type = source_ref_type
                row.source_ref_id = int(source_ref_id)
            updated += 1
        self.session.flush()
        return updated

    def _finalize_ioc_matches_for_source(
        self,
        *,
        case_id: int,
        source_ref_type: str,
        source_ref_id: int,
        final_state: str,
    ) -> Dict[str, int]:
        updated = 0
        q = IOCEvidenceMatch.query.filter(
            IOCEvidenceMatch.case_id == case_id,
            IOCEvidenceMatch.source_ref_type == source_ref_type,
            IOCEvidenceMatch.source_ref_id == int(source_ref_id),
            IOCEvidenceMatch.support_state.in_(
                [
                    GraphSupportState.ACTIVE,
                    GraphSupportState.PENDING_REMOVAL,
                    GraphSupportState.PENDING_REVALIDATION,
                ]
            ),
        )
        for row in q.yield_per(self.batch_size):
            row.support_state = final_state
            updated += 1
        self.session.flush()
        self.session.commit()
        return {'updated': updated}

    def _restore_ioc_matches_for_source(
        self,
        *,
        case_id: int,
        source_ref_type: str,
        source_ref_id: int,
        reason: str,
    ) -> int:
        now = datetime.utcnow()
        updated = 0
        q = IOCEvidenceMatch.query.filter(
            IOCEvidenceMatch.case_id == case_id,
            IOCEvidenceMatch.source_ref_type == source_ref_type,
            IOCEvidenceMatch.source_ref_id == int(source_ref_id),
            IOCEvidenceMatch.support_state.in_(
                [
                    GraphSupportState.PENDING_REMOVAL,
                    GraphSupportState.PENDING_REVALIDATION,
                ]
            ),
        )
        for row in q.yield_per(self.batch_size):
            row.support_state = GraphSupportState.ACTIVE
            meta = dict(row.metadata_json or {})
            meta['support_restore_reason'] = reason
            row.metadata_json = meta
            row.updated_at = now
            updated += 1
        self.session.flush()
        self.session.commit()
        return updated

    def _active_support_counts(self, case_id: int, relationship_ids: List[int]) -> Dict[int, int]:
        if not relationship_ids:
            return {}
        from sqlalchemy import func

        rows = (
            self.session.query(
                GraphRelationshipEvidence.relationship_id,
                func.count(GraphRelationshipEvidence.id),
            )
            .filter(
                GraphRelationshipEvidence.case_id == case_id,
                GraphRelationshipEvidence.relationship_id.in_(relationship_ids),
                GraphRelationshipEvidence.support_state == GraphSupportState.ACTIVE,
            )
            .group_by(GraphRelationshipEvidence.relationship_id)
            .all()
        )
        return {int(rid): int(count) for rid, count in rows}


def _clean_key(value: Any) -> str:
    return str(value or '').strip()


def _iter_clean_key_batches(values: Optional[Iterable[Any]], batch_size: int):
    if not values:
        return
    batch = []
    for raw in values:
        key = _clean_key(raw)
        if not key:
            continue
        batch.append(key)
        if len(batch) >= batch_size:
            yield batch
            batch = []
    if batch:
        yield batch


def stream_case_file_evidence_record_keys(case_file_id: int, *, batch_size: int = 1000):
    """Yield ERKs for a CaseFile from ClickHouse in batches (never one giant list)."""
    from utils.clickhouse import get_client

    client = get_client()
    offset = 0
    batch_size = max(1, int(batch_size))
    while True:
        result = client.query(
            """
            SELECT evidence_record_key
            FROM events
            WHERE case_file_id = {case_file_id:UInt32}
              AND evidence_record_key != ''
            ORDER BY evidence_record_key
            LIMIT {limit:UInt32} OFFSET {offset:UInt32}
            """,
            parameters={
                'case_file_id': int(case_file_id),
                'limit': batch_size,
                'offset': offset,
            },
        )
        rows = [str(row[0]).strip() for row in (result.result_rows or []) if row and row[0]]
        if not rows:
            break
        yield rows
        if len(rows) < batch_size:
            break
        offset += batch_size
