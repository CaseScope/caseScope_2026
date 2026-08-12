"""Centralized read-only graph pivot resolver (Phase 0E).

Converts existing CaseScope investigative objects into defensible CURRENT graph
roots. Never creates GraphEntity / GraphRelationship / GraphRelationshipEvidence.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from models.database import db
from models.graph import GraphEntity, GraphEntityObservation, GraphRelationship, GraphRelationshipEvidence
from models.ioc import IOC, IOCSystemSighting
from models.ioc_evidence_match import IOCEvidenceMatch
from models.known_system import KnownSystem
from models.known_user import KnownUser
from models.memory_data import (
    MemoryModule,
    MemoryNetwork,
    MemoryProcess,
    MemoryService,
    MemorySID,
)
from models.rag import PatternMatch
from utils.graph_identity import (
    GraphEntityType,
    GraphSupportState,
    build_domain_entity,
    build_file_hash_entity,
    build_host_entity,
    build_ip_entity,
    build_url_entity,
    build_user_entity,
    normalize_hostname,
)
from utils.graph_support_locator import is_evidence_record_key
from utils.investigation_references import (
    FINDING_KIND_PATTERN_MATCH,
    FINDING_KIND_UNIFIED,
    InvestigationReferenceError,
    build_pattern_match_reference,
    build_unified_finding_reference,
)


MAX_PIVOT_ROOTS = 25
MAX_PIVOT_ERKS = 50
MAX_PIVOT_RELATIONSHIPS = 50

PIVOT_KIND_EVIDENCE = 'evidence'
PIVOT_KIND_PROCESS_HUNT = 'process_hunt'
PIVOT_KIND_MEMORY_PROCESS = 'memory_process'
PIVOT_KIND_MEMORY_SERVICE = 'memory_service'
PIVOT_KIND_MEMORY_NETWORK = 'memory_network'
PIVOT_KIND_MEMORY_MODULE = 'memory_module'
PIVOT_KIND_MEMORY_SID = 'memory_sid'
PIVOT_KIND_IOC = 'ioc'
PIVOT_KIND_KNOWN_SYSTEM = 'known_system'
PIVOT_KIND_KNOWN_USER = 'known_user'
PIVOT_KIND_NETWORK_IP = 'network_ip'
PIVOT_KIND_NETWORK_DOMAIN = 'network_domain'
PIVOT_KIND_UNIFIED_FINDING = 'unified_finding'
PIVOT_KIND_PATTERN_MATCH = 'pattern_match'
PIVOT_KIND_CASE_ANALYSIS_FINDING = 'case_analysis_finding'

PIVOT_KINDS = {
    PIVOT_KIND_EVIDENCE,
    PIVOT_KIND_PROCESS_HUNT,
    PIVOT_KIND_MEMORY_PROCESS,
    PIVOT_KIND_MEMORY_SERVICE,
    PIVOT_KIND_MEMORY_NETWORK,
    PIVOT_KIND_MEMORY_MODULE,
    PIVOT_KIND_MEMORY_SID,
    PIVOT_KIND_IOC,
    PIVOT_KIND_KNOWN_SYSTEM,
    PIVOT_KIND_KNOWN_USER,
    PIVOT_KIND_NETWORK_IP,
    PIVOT_KIND_NETWORK_DOMAIN,
    PIVOT_KIND_UNIFIED_FINDING,
    PIVOT_KIND_PATTERN_MATCH,
    PIVOT_KIND_CASE_ANALYSIS_FINDING,
}


class GraphPivotError(ValueError):
    """Raised for client-correctable pivot errors."""


@dataclass
class GraphPivotResult:
    pivot_type: str
    source_reference: Dict[str, Any]
    resolved: bool = False
    roots: List[Dict[str, Any]] = field(default_factory=list)
    relationship_ids: List[int] = field(default_factory=list)
    evidence_record_keys: List[str] = field(default_factory=list)
    ambiguous: bool = False
    truncated: bool = False
    message: Optional[str] = None
    context: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'pivot_type': self.pivot_type,
            'source_reference': self.source_reference,
            'resolved': self.resolved,
            'roots': self.roots,
            'relationship_ids': self.relationship_ids,
            'evidence_record_keys': self.evidence_record_keys,
            'ambiguous': self.ambiguous,
            'truncated': self.truncated,
            'message': self.message,
            'context': self.context,
        }


class GraphPivotService:
    """Read-only case-scoped pivot resolver."""

    def resolve(self, case_id: int, *, kind: str, reference: Dict[str, Any] | None = None) -> Dict[str, Any]:
        pivot_kind = str(kind or '').strip().lower()
        if pivot_kind not in PIVOT_KINDS:
            raise GraphPivotError(f'Unsupported pivot kind: {kind}')
        ref = dict(reference or {})
        handlers = {
            PIVOT_KIND_EVIDENCE: self._pivot_evidence,
            PIVOT_KIND_PROCESS_HUNT: self._pivot_process_hunt,
            PIVOT_KIND_MEMORY_PROCESS: self._pivot_memory_process,
            PIVOT_KIND_MEMORY_SERVICE: self._pivot_memory_service,
            PIVOT_KIND_MEMORY_NETWORK: self._pivot_memory_network,
            PIVOT_KIND_MEMORY_MODULE: self._pivot_memory_module,
            PIVOT_KIND_MEMORY_SID: self._pivot_memory_sid,
            PIVOT_KIND_IOC: self._pivot_ioc,
            PIVOT_KIND_KNOWN_SYSTEM: self._pivot_known_system,
            PIVOT_KIND_KNOWN_USER: self._pivot_known_user,
            PIVOT_KIND_NETWORK_IP: self._pivot_network_ip,
            PIVOT_KIND_NETWORK_DOMAIN: self._pivot_network_domain,
            PIVOT_KIND_UNIFIED_FINDING: self._pivot_unified_finding,
            PIVOT_KIND_PATTERN_MATCH: self._pivot_pattern_match,
            PIVOT_KIND_CASE_ANALYSIS_FINDING: self._pivot_case_analysis_finding,
        }
        return handlers[pivot_kind](int(case_id), ref).to_dict()

    # ------------------------------------------------------------------ evidence

    def _pivot_evidence(self, case_id: int, ref: Dict[str, Any]) -> GraphPivotResult:
        erk = str(ref.get('evidence_record_key') or '').strip()
        if not is_evidence_record_key(erk):
            raise GraphPivotError('evidence pivot requires Evidence Identity v2 evidence_record_key')
        result = GraphPivotResult(
            pivot_type=PIVOT_KIND_EVIDENCE,
            source_reference={'case_id': case_id, 'evidence_record_key': erk},
            evidence_record_keys=[erk],
            context={'label': 'Opened from Hunt Event'},
        )
        entity_ids = [
            int(row.entity_id)
            for row in GraphEntityObservation.query.filter_by(
                case_id=case_id,
                evidence_record_key=erk,
            ).limit(MAX_PIVOT_ROOTS + 1).all()
        ]
        rel_ids = [
            int(row.relationship_id)
            for row in GraphRelationshipEvidence.query.filter(
                GraphRelationshipEvidence.case_id == case_id,
                GraphRelationshipEvidence.evidence_record_key == erk,
                GraphRelationshipEvidence.support_state == GraphSupportState.ACTIVE,
            ).limit(MAX_PIVOT_RELATIONSHIPS + 1).all()
        ]
        truncated = len(entity_ids) > MAX_PIVOT_ROOTS or len(rel_ids) > MAX_PIVOT_RELATIONSHIPS
        entity_ids = entity_ids[:MAX_PIVOT_ROOTS]
        rel_ids = rel_ids[:MAX_PIVOT_RELATIONSHIPS]
        roots = self._roots_from_entity_ids(case_id, entity_ids)
        if not roots and rel_ids:
            roots = self._endpoint_roots_for_relationships(case_id, rel_ids)
        result.roots = roots
        result.relationship_ids = rel_ids
        result.truncated = truncated
        if roots:
            result.resolved = True
            result.ambiguous = len(roots) > 1
            if truncated:
                result.message = 'Pivot results were truncated; these are not all matching graph objects.'
        else:
            result.message = (
                'No authoritative graph entity or relationship is currently '
                'materialized from this evidence.'
            )
        return result

    # -------------------------------------------------------------- process hunt

    def _pivot_process_hunt(self, case_id: int, ref: Dict[str, Any]) -> GraphPivotResult:
        """Authoritative PROCESS only with execution anchor; else host fallback."""
        erk = str(ref.get('evidence_record_key') or '').strip()
        memory_process_id = ref.get('memory_process_id')
        hostname = str(ref.get('hostname') or ref.get('source_host') or '').strip()
        result = GraphPivotResult(
            pivot_type=PIVOT_KIND_PROCESS_HUNT,
            source_reference={
                'case_id': case_id,
                'evidence_record_key': erk or None,
                'memory_process_id': memory_process_id,
                'hostname': hostname,
                'process_id': ref.get('process_id') or ref.get('pid'),
            },
            context={'label': 'Opened from Process Hunting'},
        )

        if is_evidence_record_key(erk):
            return self._pivot_evidence(case_id, {'evidence_record_key': erk})

        if memory_process_id not in (None, ''):
            return self._pivot_memory_process(case_id, {'memory_process_id': int(memory_process_id)})

        # PID-only is NOT authoritative PROCESS identity.
        if hostname:
            host_root = self._lookup_host_by_hostname(case_id, hostname)
            if host_root:
                result.roots = [host_root]
                result.resolved = True
                result.message = (
                    'Process Hunting row lacks a defensible process-execution anchor '
                    '(ERK or memory process identity). Offering HOST only.'
                )
                result.context['authoritative'] = False
                result.context['exploratory_note'] = 'hostname+PID is exploratory, not graph PROCESS identity'
                return result

        result.message = (
            'Process Hunting row cannot identify a unique graph PROCESS; '
            'PID-only identity is not authoritative.'
        )
        return result

    # ------------------------------------------------------------------- memory

    def _pivot_memory_process(self, case_id: int, ref: Dict[str, Any]) -> GraphPivotResult:
        row = self._load_memory_row(MemoryProcess, case_id, ref.get('memory_process_id') or ref.get('record_id'))
        result = GraphPivotResult(
            pivot_type=PIVOT_KIND_MEMORY_PROCESS,
            source_reference={
                'case_id': case_id,
                'memory_job_id': row.job_id,
                'memory_process_id': row.id,
                'pid': row.pid,
            },
            context={
                'label': f'Opened from Memory Process {row.pid}/{row.name}',
                'memory_job_id': row.job_id,
            },
        )
        # Prefer entities observed from native locator key for this row.
        from utils.graph_support_locator import (
            SOURCE_TYPE_MEMORY_PROCESS,
            build_memory_locator,
            support_key_for_locator,
        )

        locator = build_memory_locator(
            source_type=SOURCE_TYPE_MEMORY_PROCESS,
            case_id=case_id,
            memory_job_id=row.job_id,
            record_id=row.id,
        )
        key = support_key_for_locator(locator)
        roots = self._roots_from_support_key(case_id, key)
        if not roots:
            # Fall back to HOST for the memory hostname if materialized.
            host_root = self._lookup_host_by_hostname(case_id, row.hostname)
            if host_root:
                roots = [host_root]
                result.message = (
                    'Memory process is not currently materialized as a graph PROCESS; '
                    'offering HOST when available.'
                )
        result.roots = roots
        result.resolved = bool(roots)
        result.ambiguous = len(roots) > 1
        if not roots:
            result.message = (
                'No authoritative graph entity or relationship is currently '
                'materialized from this evidence.'
            )
        return result

    def _pivot_memory_service(self, case_id: int, ref: Dict[str, Any]) -> GraphPivotResult:
        row = self._load_memory_row(MemoryService, case_id, ref.get('memory_service_id') or ref.get('record_id'))
        return self._pivot_memory_generic(
            case_id,
            pivot_type=PIVOT_KIND_MEMORY_SERVICE,
            source_type='memory_service',
            row=row,
            label=f'Opened from Memory Service {row.name}',
        )

    def _pivot_memory_network(self, case_id: int, ref: Dict[str, Any]) -> GraphPivotResult:
        row = self._load_memory_row(MemoryNetwork, case_id, ref.get('memory_network_id') or ref.get('record_id'))
        return self._pivot_memory_generic(
            case_id,
            pivot_type=PIVOT_KIND_MEMORY_NETWORK,
            source_type='memory_network',
            row=row,
            label=f'Opened from Memory Network {row.foreign_addr or row.local_addr}',
        )

    def _pivot_memory_module(self, case_id: int, ref: Dict[str, Any]) -> GraphPivotResult:
        row = self._load_memory_row(MemoryModule, case_id, ref.get('memory_module_id') or ref.get('record_id'))
        return self._pivot_memory_generic(
            case_id,
            pivot_type=PIVOT_KIND_MEMORY_MODULE,
            source_type='memory_module',
            row=row,
            label=f'Opened from Memory Module {row.mapped_path or row.id}',
        )

    def _pivot_memory_sid(self, case_id: int, ref: Dict[str, Any]) -> GraphPivotResult:
        row = self._load_memory_row(MemorySID, case_id, ref.get('memory_sid_id') or ref.get('record_id'))
        return self._pivot_memory_generic(
            case_id,
            pivot_type=PIVOT_KIND_MEMORY_SID,
            source_type='memory_sid',
            row=row,
            label=f'Opened from Memory SID {getattr(row, "sid", row.id)}',
        )

    def _pivot_memory_generic(
        self,
        case_id: int,
        *,
        pivot_type: str,
        source_type: str,
        row: Any,
        label: str,
    ) -> GraphPivotResult:
        from utils.graph_support_locator import build_memory_locator, support_key_for_locator

        locator = build_memory_locator(
            source_type=source_type,
            case_id=case_id,
            memory_job_id=row.job_id,
            record_id=row.id,
        )
        key = support_key_for_locator(locator)
        roots = self._roots_from_support_key(case_id, key)
        result = GraphPivotResult(
            pivot_type=pivot_type,
            source_reference={
                'case_id': case_id,
                'memory_job_id': row.job_id,
                'record_id': row.id,
            },
            roots=roots,
            resolved=bool(roots),
            ambiguous=len(roots) > 1,
            context={'label': label, 'memory_job_id': row.job_id},
        )
        if not roots:
            result.message = (
                'No authoritative graph entity or relationship is currently '
                'materialized from this evidence.'
            )
        return result

    # ---------------------------------------------------------------------- IOC

    def _pivot_ioc(self, case_id: int, ref: Dict[str, Any]) -> GraphPivotResult:
        ioc_uuid = str(ref.get('ioc_uuid') or '').strip()
        if not ioc_uuid:
            raise GraphPivotError('ioc pivot requires exact ioc_uuid')
        ioc = IOC.query.filter_by(uuid=ioc_uuid, case_id=case_id).first()
        if not ioc:
            raise GraphPivotError('IOC not found in case')
        result = GraphPivotResult(
            pivot_type=PIVOT_KIND_IOC,
            source_reference={'case_id': case_id, 'ioc_uuid': ioc.uuid, 'ioc_id': ioc.id},
            context={'label': f'Opened from IOC {ioc.value}'},
        )
        roots: List[Dict[str, Any]] = []

        # A) Canonical entity matching IOC value where safe.
        entity = self._lookup_entity_for_ioc_value(case_id, ioc)
        if entity:
            roots.append(self._root_from_entity(entity))

        # B) Explicit IOCSystemSighting host roots.
        sightings = (
            IOCSystemSighting.query.filter_by(case_id=case_id, ioc_id=ioc.id)
            .limit(MAX_PIVOT_ROOTS + 1)
            .all()
        )
        truncated = len(sightings) > MAX_PIVOT_ROOTS
        for sighting in sightings[:MAX_PIVOT_ROOTS]:
            host = GraphEntity.query.filter_by(
                case_id=case_id,
                entity_type=GraphEntityType.HOST,
                entity_key=f'known_system:{sighting.system_id}',
            ).first()
            if host:
                roots.append(self._root_from_entity(host))

        # C) Exact IOC -> ERK provenance.
        matches = (
            IOCEvidenceMatch.query.filter_by(
                case_id=case_id,
                ioc_uuid=ioc.uuid,
                support_state=GraphSupportState.ACTIVE,
            )
            .limit(MAX_PIVOT_ERKS + 1)
            .all()
        )
        if len(matches) > MAX_PIVOT_ERKS:
            truncated = True
        erks = [m.evidence_record_key for m in matches[:MAX_PIVOT_ERKS]]
        result.evidence_record_keys = erks
        for erk in erks:
            for obs in GraphEntityObservation.query.filter_by(
                case_id=case_id,
                evidence_record_key=erk,
            ).limit(5).all():
                entity = GraphEntity.query.filter_by(case_id=case_id, id=obs.entity_id).first()
                if entity:
                    roots.append(self._root_from_entity(entity))

        roots = self._dedupe_roots(roots)[:MAX_PIVOT_ROOTS]
        result.roots = roots
        result.resolved = bool(roots)
        result.ambiguous = len(roots) > 1
        result.truncated = truncated or len(roots) >= MAX_PIVOT_ROOTS
        if result.truncated:
            result.message = 'Pivot results were truncated; these are not all matching graph objects.'
        elif not roots:
            result.message = (
                'No authoritative graph entity or relationship is currently '
                'materialized from this IOC.'
            )
        return result

    # ------------------------------------------------------------- known entities

    def _pivot_known_system(self, case_id: int, ref: Dict[str, Any]) -> GraphPivotResult:
        known_system_id = ref.get('known_system_id')
        if known_system_id in (None, ''):
            raise GraphPivotError('known_system pivot requires known_system_id')
        system = KnownSystem.query.get(int(known_system_id))
        if not system:
            raise GraphPivotError('KnownSystem not found')
        # Case membership via KnownSystemCase or direct case association helpers.
        if not self._known_system_in_case(system, case_id):
            raise GraphPivotError('KnownSystem does not belong to case')
        entity_key = f'known_system:{system.id}'
        entity = GraphEntity.query.filter_by(
            case_id=case_id,
            entity_type=GraphEntityType.HOST,
            entity_key=entity_key,
        ).first()
        result = GraphPivotResult(
            pivot_type=PIVOT_KIND_KNOWN_SYSTEM,
            source_reference={'case_id': case_id, 'known_system_id': system.id},
            context={'label': f'Opened from Known System {system.hostname}'},
        )
        if entity:
            result.roots = [self._root_from_entity(entity)]
            result.resolved = True
        else:
            result.message = 'No canonical graph HOST is currently materialized for this KnownSystem.'
        return result

    def _pivot_known_user(self, case_id: int, ref: Dict[str, Any]) -> GraphPivotResult:
        known_user_id = ref.get('known_user_id')
        if known_user_id in (None, ''):
            raise GraphPivotError('known_user pivot requires known_user_id')
        user = KnownUser.query.get(int(known_user_id))
        if not user:
            raise GraphPivotError('KnownUser not found')
        if not self._known_user_in_case(user, case_id):
            raise GraphPivotError('KnownUser does not belong to case')

        result = GraphPivotResult(
            pivot_type=PIVOT_KIND_KNOWN_USER,
            source_reference={'case_id': case_id, 'known_user_id': user.id},
            context={'label': f'Opened from Known User {user.username}'},
        )
        candidates: List[GraphEntity] = []
        # SID strongest.
        if user.sid:
            try:
                identity = build_user_entity(user.username, sid=user.sid)
                entity = GraphEntity.query.filter_by(
                    case_id=case_id,
                    entity_type=GraphEntityType.USER,
                    entity_key=identity.entity_key,
                ).first()
                if entity:
                    candidates.append(entity)
            except Exception:
                pass
        # Authority + username if available via aliases/domain fields.
        domain = getattr(user, 'domain', None) or ''
        if user.username and domain:
            try:
                identity = build_user_entity(user.username, domain=domain)
                entity = GraphEntity.query.filter_by(
                    case_id=case_id,
                    entity_type=GraphEntityType.USER,
                    entity_key=identity.entity_key,
                ).first()
                if entity:
                    candidates.append(entity)
            except Exception:
                pass

        candidates = self._dedupe_entities(candidates)
        if len(candidates) == 1:
            result.roots = [self._root_from_entity(candidates[0])]
            result.resolved = True
        elif len(candidates) > 1:
            result.roots = [self._root_from_entity(e) for e in candidates[:MAX_PIVOT_ROOTS]]
            result.resolved = True
            result.ambiguous = True
            result.message = 'KnownUser maps to multiple graph USER identities; select a root.'
        else:
            # Bare username must not over-merge host-local Administrators.
            result.message = (
                'KnownUser cannot uniquely identify one graph USER '
                '(SID/authority required; bare username is ambiguous).'
            )
            result.ambiguous = True
        return result

    # ------------------------------------------------------------------- network

    def _pivot_network_ip(self, case_id: int, ref: Dict[str, Any]) -> GraphPivotResult:
        value = str(ref.get('ip') or ref.get('value') or '').strip()
        if not value:
            raise GraphPivotError('network_ip pivot requires ip')
        try:
            identity = build_ip_entity(value)
        except Exception as exc:
            raise GraphPivotError(str(exc)) from exc
        entity = GraphEntity.query.filter_by(
            case_id=case_id,
            entity_type=GraphEntityType.IP_ADDRESS,
            entity_key=identity.entity_key,
        ).first()
        result = GraphPivotResult(
            pivot_type=PIVOT_KIND_NETWORK_IP,
            source_reference={'case_id': case_id, 'ip': identity.canonical_value},
            context={'label': f'Opened from Network IP {identity.display_value}'},
        )
        if entity:
            result.roots = [self._root_from_entity(entity)]
            result.resolved = True
        else:
            result.message = 'No canonical graph IP_ADDRESS entity is currently materialized.'
        return result

    def _pivot_network_domain(self, case_id: int, ref: Dict[str, Any]) -> GraphPivotResult:
        value = str(ref.get('domain') or ref.get('value') or '').strip()
        if not value:
            raise GraphPivotError('network_domain pivot requires domain')
        try:
            identity = build_domain_entity(value)
        except Exception as exc:
            raise GraphPivotError(str(exc)) from exc
        entity = GraphEntity.query.filter_by(
            case_id=case_id,
            entity_type=GraphEntityType.DOMAIN,
            entity_key=identity.entity_key,
        ).first()
        result = GraphPivotResult(
            pivot_type=PIVOT_KIND_NETWORK_DOMAIN,
            source_reference={'case_id': case_id, 'domain': identity.canonical_value},
            context={'label': f'Opened from Network Domain {identity.display_value}'},
        )
        if entity:
            result.roots = [self._root_from_entity(entity)]
            result.resolved = True
        else:
            result.message = 'No canonical graph DOMAIN entity is currently materialized.'
        return result

    # ------------------------------------------------------------------ findings

    def _pivot_unified_finding(self, case_id: int, ref: Dict[str, Any]) -> GraphPivotResult:
        try:
            typed = build_unified_finding_reference(
                case_id=case_id,
                analysis_id=ref.get('analysis_id'),
                source_system=ref.get('source_system'),
                dedup_key=ref.get('dedup_key'),
                finding_id=ref.get('finding_id'),
            )
        except InvestigationReferenceError as exc:
            raise GraphPivotError(str(exc)) from exc
        return self._pivot_finding_common(
            case_id,
            pivot_type=PIVOT_KIND_UNIFIED_FINDING,
            typed_ref=typed,
            erks=self._extract_erks_from_ref(ref),
            title=str(ref.get('title') or typed.get('finding_id') or 'Finding'),
        )

    def _pivot_pattern_match(self, case_id: int, ref: Dict[str, Any]) -> GraphPivotResult:
        pattern_match_id = ref.get('pattern_match_id')
        if pattern_match_id in (None, ''):
            raise GraphPivotError('pattern_match pivot requires pattern_match_id')
        match = PatternMatch.query.filter_by(id=int(pattern_match_id), case_id=case_id).first()
        if not match:
            raise GraphPivotError('PatternMatch not found in case')
        typed = build_pattern_match_reference(case_id=case_id, pattern_match_id=match.id)
        erks = self._extract_erks_from_ref(ref)
        if not erks and isinstance(match.matched_events, list):
            for item in match.matched_events:
                if isinstance(item, dict):
                    erk = str(item.get('evidence_record_key') or '').strip()
                    if is_evidence_record_key(erk):
                        erks.append(erk)
        return self._pivot_finding_common(
            case_id,
            pivot_type=PIVOT_KIND_PATTERN_MATCH,
            typed_ref=typed,
            erks=erks,
            title=str(getattr(match, 'pattern_name', None) or match.id),
        )

    def _pivot_case_analysis_finding(self, case_id: int, ref: Dict[str, Any]) -> GraphPivotResult:
        # Prefer explicit unified finding fields when provided; otherwise treat as
        # typed analysis reference with optional ERK list.
        if ref.get('source_system') and ref.get('dedup_key') and ref.get('finding_id'):
            return self._pivot_unified_finding(case_id, ref)
        return self._pivot_finding_common(
            case_id,
            pivot_type=PIVOT_KIND_CASE_ANALYSIS_FINDING,
            typed_ref={
                'case_id': case_id,
                'analysis_id': ref.get('analysis_id'),
                'finding_type': ref.get('finding_type'),
                'finding_id': ref.get('finding_id'),
            },
            erks=self._extract_erks_from_ref(ref),
            title=str(ref.get('title') or ref.get('finding_id') or 'Case Analysis Finding'),
        )

    def _pivot_finding_common(
        self,
        case_id: int,
        *,
        pivot_type: str,
        typed_ref: Dict[str, Any],
        erks: List[str],
        title: str,
    ) -> GraphPivotResult:
        result = GraphPivotResult(
            pivot_type=pivot_type,
            source_reference=typed_ref,
            context={'label': f'Opened from Finding {title}'},
        )
        roots: List[Dict[str, Any]] = []
        relationship_ids: List[int] = []
        truncated = False
        erks = [e for e in erks if is_evidence_record_key(e)]
        if len(erks) > MAX_PIVOT_ERKS:
            truncated = True
            erks = erks[:MAX_PIVOT_ERKS]
        result.evidence_record_keys = erks
        for erk in erks:
            sub = self._pivot_evidence(case_id, {'evidence_record_key': erk})
            roots.extend(sub.roots)
            relationship_ids.extend(sub.relationship_ids)
            truncated = truncated or sub.truncated
        # Explicit graph entity/relationship stable refs if provided.
        for entity_id in typed_ref.get('graph_entity_ids') or []:
            entity = GraphEntity.query.filter_by(case_id=case_id, id=int(entity_id)).first()
            if entity:
                roots.append(self._root_from_entity(entity))
        roots = self._dedupe_roots(roots)[:MAX_PIVOT_ROOTS]
        relationship_ids = sorted(set(relationship_ids))[:MAX_PIVOT_RELATIONSHIPS]
        result.roots = roots
        result.relationship_ids = relationship_ids
        result.resolved = bool(roots or relationship_ids)
        result.ambiguous = len(roots) > 1
        result.truncated = truncated
        if truncated:
            result.message = 'Pivot results were truncated; these are not all matching graph objects.'
        elif not result.resolved:
            result.message = (
                'No authoritative graph entity or relationship is currently '
                'materialized from this finding support.'
            )
        return result

    # ----------------------------------------------------------------- helpers

    def _load_memory_row(self, model, case_id: int, record_id: Any):
        if record_id in (None, ''):
            raise GraphPivotError(f'{model.__name__} pivot requires record id')
        row = model.query.get(int(record_id))
        if not row or int(row.case_id) != int(case_id):
            raise GraphPivotError(f'{model.__name__} not found in case')
        return row

    def _roots_from_support_key(self, case_id: int, key: str) -> List[Dict[str, Any]]:
        entity_ids = [
            int(row.entity_id)
            for row in GraphEntityObservation.query.filter_by(
                case_id=case_id,
                evidence_record_key=key,
            ).limit(MAX_PIVOT_ROOTS).all()
        ]
        roots = self._roots_from_entity_ids(case_id, entity_ids)
        if roots:
            return roots
        rel_ids = [
            int(row.relationship_id)
            for row in GraphRelationshipEvidence.query.filter(
                GraphRelationshipEvidence.case_id == case_id,
                GraphRelationshipEvidence.evidence_record_key == key,
                GraphRelationshipEvidence.support_state == GraphSupportState.ACTIVE,
            ).limit(MAX_PIVOT_RELATIONSHIPS).all()
        ]
        return self._endpoint_roots_for_relationships(case_id, rel_ids)

    def _roots_from_entity_ids(self, case_id: int, entity_ids: List[int]) -> List[Dict[str, Any]]:
        if not entity_ids:
            return []
        entities = GraphEntity.query.filter(
            GraphEntity.case_id == case_id,
            GraphEntity.id.in_(entity_ids),
        ).all()
        return [self._root_from_entity(entity) for entity in entities]

    def _endpoint_roots_for_relationships(self, case_id: int, relationship_ids: List[int]) -> List[Dict[str, Any]]:
        if not relationship_ids:
            return []
        relationships = GraphRelationship.query.filter(
            GraphRelationship.case_id == case_id,
            GraphRelationship.id.in_(relationship_ids),
        ).all()
        entity_ids = []
        for rel in relationships:
            entity_ids.append(rel.source_entity_id)
            entity_ids.append(rel.target_entity_id)
        return self._dedupe_roots(self._roots_from_entity_ids(case_id, entity_ids))

    def _root_from_entity(self, entity: GraphEntity) -> Dict[str, Any]:
        return {
            'entity_id': entity.id,
            'entity_type': entity.entity_type,
            'display_value': entity.display_value,
            'stable_reference': {
                'case_id': entity.case_id,
                'entity_type': entity.entity_type,
                'entity_key': entity.entity_key,
            },
        }

    def _lookup_host_by_hostname(self, case_id: int, hostname: str) -> Optional[Dict[str, Any]]:
        system, _match = KnownSystem.find_by_hostname_or_alias(hostname, case_id=case_id)
        if system:
            entity = GraphEntity.query.filter_by(
                case_id=case_id,
                entity_type=GraphEntityType.HOST,
                entity_key=f'known_system:{system.id}',
            ).first()
            if entity:
                return self._root_from_entity(entity)
        # Conservative observed-host lookup without creating.
        normalized = normalize_hostname(hostname)
        if not normalized:
            return None
        entities = GraphEntity.query.filter_by(
            case_id=case_id,
            entity_type=GraphEntityType.HOST,
        ).limit(200).all()
        for entity in entities:
            if normalize_hostname(entity.display_value) == normalized:
                return self._root_from_entity(entity)
            canonical = str(entity.canonical_value or '')
            if normalized and normalized in canonical.upper():
                return self._root_from_entity(entity)
        return None

    def _lookup_entity_for_ioc_value(self, case_id: int, ioc: IOC) -> Optional[GraphEntity]:
        ioc_type = str(ioc.ioc_type or '').lower()
        value = ioc.value
        try:
            if 'ip' in ioc_type:
                identity = build_ip_entity(value)
                return GraphEntity.query.filter_by(
                    case_id=case_id,
                    entity_type=GraphEntityType.IP_ADDRESS,
                    entity_key=identity.entity_key,
                ).first()
            if 'domain' in ioc_type or 'hostname' in ioc_type:
                identity = build_domain_entity(value)
                return GraphEntity.query.filter_by(
                    case_id=case_id,
                    entity_type=GraphEntityType.DOMAIN,
                    entity_key=identity.entity_key,
                ).first()
            if 'url' in ioc_type:
                identity = build_url_entity(value)
                return GraphEntity.query.filter_by(
                    case_id=case_id,
                    entity_type=GraphEntityType.URL,
                    entity_key=identity.entity_key,
                ).first()
            if 'hash' in ioc_type or 'md5' in ioc_type or 'sha' in ioc_type:
                algo = 'sha256'
                if 'md5' in ioc_type:
                    algo = 'md5'
                elif 'sha1' in ioc_type:
                    algo = 'sha1'
                identity = build_file_hash_entity(algo, value)
                return GraphEntity.query.filter_by(
                    case_id=case_id,
                    entity_type=GraphEntityType.FILE_HASH,
                    entity_key=identity.entity_key,
                ).first()
        except Exception:
            return None
        return None

    def _known_system_in_case(self, system: KnownSystem, case_id: int) -> bool:
        from models.known_system import KnownSystemCase

        if KnownSystemCase.query.filter_by(system_id=system.id, case_id=case_id).first():
            return True
        # Some deployments keep systems globally but still case-filter via helper.
        found, _ = KnownSystem.find_by_hostname_or_alias(system.hostname, case_id=case_id)
        return bool(found and found.id == system.id)

    def _known_user_in_case(self, user: KnownUser, case_id: int) -> bool:
        from models.known_user import KnownUserCase

        if KnownUserCase.query.filter_by(user_id=user.id, case_id=case_id).first():
            return True
        # Fall back: if KnownUser has case_id attribute.
        if getattr(user, 'case_id', None) is not None:
            return int(user.case_id) == int(case_id)
        return True  # Known users may be global; still require ID exactness above.

    def _extract_erks_from_ref(self, ref: Dict[str, Any]) -> List[str]:
        erks = []
        for key in ('evidence_record_key',):
            value = str(ref.get(key) or '').strip()
            if is_evidence_record_key(value):
                erks.append(value)
        for item in ref.get('evidence_record_keys') or []:
            value = str(item or '').strip()
            if is_evidence_record_key(value):
                erks.append(value)
        return erks

    def _dedupe_roots(self, roots: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        seen = set()
        out = []
        for root in roots:
            entity_id = root.get('entity_id')
            if entity_id in seen:
                continue
            seen.add(entity_id)
            out.append(root)
        return out

    def _dedupe_entities(self, entities: List[GraphEntity]) -> List[GraphEntity]:
        seen = set()
        out = []
        for entity in entities:
            if entity.id in seen:
                continue
            seen.add(entity.id)
            out.append(entity)
        return out
