"""Deterministic investigative graph extractors for Volatility memory artifacts.

Memory rows are native (non-event) sources. They carry NO Evidence Identity v2
key. Instead every candidate is anchored with a typed native support locator
(``utils.graph_support_locator.build_memory_locator``) and a support key derived
from it (``support_key_for_locator``). Provenance is bound to the owning
``MemoryJob`` via ``source_ref_type=MEMORY_JOB`` / ``source_ref_id=job_id``.

Hard identity rules (Phase 0E review hardening):

* A memory process is NEVER merged with an event process on hostname+PID alone.
  Memory process identity uses the memory host identity (KnownSystem when the
  hostname resolves, otherwise a memory-job-scoped observed host) plus the PID
  plus an execution anchor that is unique to the memory capture: the process
  ``create_time`` when present, otherwise the process row's own native support
  key. Event processes anchor on ``start_time`` (creation timestamp) or an
  ``erk:v2`` key, so the identity spaces cannot collide.
* Relationships that reference a process by ``(job_id, pid)`` are only emitted
  when EXACTLY ONE ``MemoryProcess`` row exists for that job+pid. Ambiguous or
  missing process rows are skipped rather than guessed.

Only four extractors are enabled because their source contracts are clean:

1. :class:`MemoryConnectedToIpExtractor`   PROCESS -CONNECTED_TO-> IP_ADDRESS
2. :class:`MemoryLoadedModuleExtractor`    PROCESS -LOADED_MODULE-> FILE_PATH
3. :class:`MemoryServiceRunsProcessExtractor` SERVICE -SERVICE_RUNS_PROCESS-> PROCESS
4. :class:`MemoryHasSecurityContextExtractor` PROCESS -HAS_SECURITY_CONTEXT-> USER
"""
from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional

from models.database import db
from utils.graph_extractors import GraphRelationshipCandidate
from utils.graph_identity import (
    EntitySpec,
    GraphDerivationType,
    GraphEntityType,
    GraphRelationshipType,
    GraphSourceRefType,
)
from utils.graph_support_locator import (
    SOURCE_TYPE_MEMORY_MODULE,
    SOURCE_TYPE_MEMORY_NETWORK,
    SOURCE_TYPE_MEMORY_PROCESS,
    SOURCE_TYPE_MEMORY_SERVICE,
    SOURCE_TYPE_MEMORY_SID,
    build_memory_locator,
    support_key_for_locator,
)

logger = logging.getLogger(__name__)

MEMORY_EXTRACTOR_VERSION = '1'


def _clean(value: Any) -> str:
    return str(value or '').strip()


def _valid_remote_ip(value: Any) -> Optional[str]:
    """Return the canonical IP if value is a routable remote address, else None."""
    text = _clean(value)
    if not text or text in ('*', '::', '0.0.0.0'):
        return None
    try:
        addr = ipaddress.ip_address(text)
    except ValueError:
        return None
    if addr.is_unspecified:
        return None
    return str(addr)


def _iter_job_rows(model, job_id: int, *, page_size: int = 1000):
    """Yield rows for one MemoryJob using bounded id-keyset pages."""
    last_id = 0
    page_size = max(1, int(page_size))
    while True:
        rows = (
            model.query.filter(model.job_id == int(job_id), model.id > last_id)
            .order_by(model.id.asc())
            .limit(page_size)
            .all()
        )
        if not rows:
            break
        for row in rows:
            last_id = int(row.id)
            yield row
        if len(rows) < page_size:
            break


def _iter_memory_jobs(case_id: int, *, memory_job_id: Optional[int] = None, page_size: int = 500):
    from models.memory_job import MemoryJob

    last_id = 0
    page_size = max(1, int(page_size))
    while True:
        q = MemoryJob.query.filter(MemoryJob.case_id == int(case_id), MemoryJob.id > last_id)
        if memory_job_id is not None:
            q = q.filter(MemoryJob.id == int(memory_job_id))
        rows = q.order_by(MemoryJob.id.asc()).limit(page_size).all()
        if not rows:
            break
        for row in rows:
            last_id = int(row.id)
            yield row
        if memory_job_id is not None or len(rows) < page_size:
            break


@dataclass(frozen=True)
class _ProcessRef:
    """Resolved unique memory process identity for a (job, pid)."""

    record_id: int
    pid: int
    name: str
    path: str
    create_time: Any


class MemoryProcessResolver:
    """Resolve the unique MemoryProcess row for a (job_id, pid).

    Queries lazily per pid and caches results so memory stays bounded. A pid
    that maps to zero or more than one process row resolves to ``None`` (caller
    must skip the edge).
    """

    def __init__(self, job_id: int):
        self.job_id = int(job_id)
        self._index: Dict[int, Optional[_ProcessRef]] = {}

    def resolve(self, pid: Any) -> Optional[_ProcessRef]:
        if pid is None:
            return None
        try:
            pid_int = int(pid)
        except (TypeError, ValueError):
            return None
        if pid_int in self._index:
            return self._index.get(pid_int)
        from models.memory_data import MemoryProcess

        rows = (
            MemoryProcess.query.filter_by(job_id=self.job_id, pid=pid_int)
            .order_by(MemoryProcess.id.asc())
            .limit(2)
            .all()
        )
        if len(rows) != 1:
            self._index[pid_int] = None
            return None
        row = rows[0]
        self._index[pid_int] = _ProcessRef(
            record_id=int(row.id),
            pid=int(row.pid),
            name=_clean(row.name),
            path=_clean(row.path or row.audit_path),
            create_time=row.create_time,
        )
        return self._index.get(pid_int)


def _memory_host_spec(job) -> EntitySpec:
    """Host identity for a memory job.

    Resolves to a KnownSystem when the hostname matches, otherwise a
    memory-job-scoped observed host. The job-scoped source context keeps memory
    observed hosts distinct from event observed hosts while remaining stable for
    every row in the same capture.
    """
    return EntitySpec(
        GraphEntityType.HOST,
        _clean(job.hostname),
        hints={
            'source_context': f'memory_job:{int(job.id)}',
            'prefer_known_system': True,
        },
    )


def _memory_process_spec(job, proc: _ProcessRef) -> EntitySpec:
    create_time = getattr(proc, 'create_time', None)
    start_time = create_time.isoformat() if create_time else ''
    anchor_key = ''
    if not start_time:
        anchor_locator = build_memory_locator(
            source_type=SOURCE_TYPE_MEMORY_PROCESS,
            case_id=int(job.case_id),
            memory_job_id=int(job.id),
            record_id=int(proc.record_id),
        )
        anchor_key = support_key_for_locator(anchor_locator)
    return EntitySpec(
        GraphEntityType.PROCESS,
        proc.name or str(proc.pid),
        hints={
            'host': _memory_host_spec(job),
            'pid': proc.pid,
            'start_time': start_time,
            'evidence_record_key': anchor_key,
            'process_name': proc.name,
            'process_path': proc.path,
        },
    )


def _memory_candidate(
    *,
    job,
    source_type: str,
    record_id: int,
    source: EntitySpec,
    relationship_type: str,
    target: EntitySpec,
    derivation_type: str,
    extractor_name: str,
    observed_at: Any = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> GraphRelationshipCandidate:
    locator = build_memory_locator(
        source_type=source_type,
        case_id=int(job.case_id),
        memory_job_id=int(job.id),
        record_id=int(record_id),
    )
    evidence_record_key = support_key_for_locator(locator)
    return GraphRelationshipCandidate(
        case_id=int(job.case_id),
        source=source,
        relationship_type=relationship_type,
        target=target,
        derivation_type=derivation_type,
        evidence_record_key=evidence_record_key,
        observed_at=observed_at,
        source_table=source_type,
        evidence_role='supporting_record',
        extractor_name=extractor_name,
        extractor_version=MEMORY_EXTRACTOR_VERSION,
        metadata=dict(metadata or {}),
        source_ref_type=GraphSourceRefType.MEMORY_JOB,
        source_ref_id=int(job.id),
        support_locator=locator,
    )


class MemoryGraphExtractor:
    name = 'memory_base'
    version = MEMORY_EXTRACTOR_VERSION
    source_type = ''

    def extract_job(self, job, resolver: MemoryProcessResolver) -> Iterable[GraphRelationshipCandidate]:
        raise NotImplementedError


class MemoryConnectedToIpExtractor(MemoryGraphExtractor):
    """PROCESS -CONNECTED_TO-> IP_ADDRESS from netscan/netstat rows.

    ENABLED: a single memory connection record co-locates a process (pid) with a
    concrete remote endpoint (foreign_addr). Anti-merge: the process anchor is
    memory-native, never an event PID+dst_ip.
    """

    name = 'memory_connected_to_ip'
    source_type = SOURCE_TYPE_MEMORY_NETWORK

    def extract_job(self, job, resolver: MemoryProcessResolver) -> Iterable[GraphRelationshipCandidate]:
        from models.memory_data import MemoryNetwork

        for row in _iter_job_rows(MemoryNetwork, int(job.id)):
            remote_ip = _valid_remote_ip(row.foreign_addr)
            if remote_ip is None:
                continue
            proc = resolver.resolve(row.pid)
            if proc is None:
                continue
            yield _memory_candidate(
                job=job,
                source_type=self.source_type,
                record_id=int(row.id),
                source=_memory_process_spec(job, proc),
                relationship_type=GraphRelationshipType.CONNECTED_TO,
                target=EntitySpec(GraphEntityType.IP_ADDRESS, remote_ip),
                derivation_type=GraphDerivationType.OBSERVED,
                extractor_name=self.name,
                observed_at=row.created_time,
                metadata={
                    'rule': 'memory connection record co-locates process and remote IP',
                    'protocol': _clean(row.protocol),
                    'foreign_port': row.foreign_port,
                    'local_addr': _clean(row.local_addr),
                    'local_port': row.local_port,
                    'state': _clean(row.state),
                },
            )


class MemoryLoadedModuleExtractor(MemoryGraphExtractor):
    """PROCESS -LOADED_MODULE-> FILE_PATH from ldrmodules rows.

    ENABLED: a module row binds a pid to a concrete mapped image path.
    """

    name = 'memory_loaded_module'
    source_type = SOURCE_TYPE_MEMORY_MODULE

    def extract_job(self, job, resolver: MemoryProcessResolver) -> Iterable[GraphRelationshipCandidate]:
        from models.memory_data import MemoryModule

        for row in _iter_job_rows(MemoryModule, int(job.id)):
            mapped_path = _clean(row.mapped_path)
            if not mapped_path:
                continue
            proc = resolver.resolve(row.pid)
            if proc is None:
                continue
            host = _memory_host_spec(job)
            yield _memory_candidate(
                job=job,
                source_type=self.source_type,
                record_id=int(row.id),
                source=_memory_process_spec(job, proc),
                relationship_type=GraphRelationshipType.LOADED_MODULE,
                target=EntitySpec(
                    GraphEntityType.FILE_PATH,
                    mapped_path,
                    hints={'host': host, 'path': mapped_path},
                ),
                derivation_type=GraphDerivationType.OBSERVED,
                extractor_name=self.name,
                metadata={
                    'rule': 'memory module record co-locates process and mapped image path',
                    'unlinked': not (row.in_init or row.in_load or row.in_mem),
                },
            )


class MemoryServiceRunsProcessExtractor(MemoryGraphExtractor):
    """SERVICE -SERVICE_RUNS_PROCESS-> PROCESS from svcscan rows.

    ENABLED: a running service row co-locates a service name with the pid of its
    hosting process.
    """

    name = 'memory_service_runs_process'
    source_type = SOURCE_TYPE_MEMORY_SERVICE

    def extract_job(self, job, resolver: MemoryProcessResolver) -> Iterable[GraphRelationshipCandidate]:
        from models.memory_data import MemoryService

        for row in _iter_job_rows(MemoryService, int(job.id)):
            service_name = _clean(row.name)
            if not service_name:
                continue
            proc = resolver.resolve(row.pid)
            if proc is None:
                continue
            host = _memory_host_spec(job)
            yield _memory_candidate(
                job=job,
                source_type=self.source_type,
                record_id=int(row.id),
                source=EntitySpec(
                    GraphEntityType.SERVICE,
                    service_name,
                    hints={'host': host},
                ),
                relationship_type=GraphRelationshipType.SERVICE_RUNS_PROCESS,
                target=_memory_process_spec(job, proc),
                derivation_type=GraphDerivationType.OBSERVED,
                extractor_name=self.name,
                metadata={
                    'rule': 'memory service record co-locates service and hosting process pid',
                    'display_name': _clean(row.display_name),
                    'state': _clean(row.state),
                },
            )


class MemoryHasSecurityContextExtractor(MemoryGraphExtractor):
    """PROCESS -HAS_SECURITY_CONTEXT-> USER from getsids rows.

    ENABLED: a getsids row binds a pid to a SID. SID is the strongest user
    identity, so the USER endpoint canonicalizes on SID.
    """

    name = 'memory_has_security_context'
    source_type = SOURCE_TYPE_MEMORY_SID

    def extract_job(self, job, resolver: MemoryProcessResolver) -> Iterable[GraphRelationshipCandidate]:
        from models.memory_data import MemorySID

        for row in _iter_job_rows(MemorySID, int(job.id)):
            sid = _clean(row.sid)
            if not sid:
                continue
            proc = resolver.resolve(row.pid)
            if proc is None:
                continue
            host = _memory_host_spec(job)
            yield _memory_candidate(
                job=job,
                source_type=self.source_type,
                record_id=int(row.id),
                source=_memory_process_spec(job, proc),
                relationship_type=GraphRelationshipType.HAS_SECURITY_CONTEXT,
                target=EntitySpec(
                    GraphEntityType.USER,
                    _clean(row.sid_name) or sid,
                    hints={'sid': sid, 'host': host},
                ),
                derivation_type=GraphDerivationType.OBSERVED,
                extractor_name=self.name,
                metadata={
                    'rule': 'memory getsids record binds process to SID security context',
                    'sid_name': _clean(row.sid_name),
                },
            )


DEFAULT_MEMORY_EXTRACTORS: tuple[MemoryGraphExtractor, ...] = (
    MemoryConnectedToIpExtractor(),
    MemoryLoadedModuleExtractor(),
    MemoryServiceRunsProcessExtractor(),
    MemoryHasSecurityContextExtractor(),
)


def materialize_memory_for_case(
    case_id: int,
    *,
    session=None,
    extractors: Iterable[MemoryGraphExtractor] = DEFAULT_MEMORY_EXTRACTORS,
    batch_size: int = 1000,
    memory_job_id: Optional[int] = None,
) -> Dict[str, int]:
    """Materialize deterministic graph facts from parsed memory artifacts."""
    from utils.graph_materializer import GraphMaterializer

    session = session or db.session
    materializer = GraphMaterializer(session=session)

    jobs_seen = 0
    candidates_seen = 0
    relationships_materialized = 0
    errors = 0

    for job in _iter_memory_jobs(case_id, memory_job_id=memory_job_id):
        jobs_seen += 1
        resolver = MemoryProcessResolver(job.id)
        for extractor in extractors:
            for candidate in extractor.extract_job(job, resolver):
                candidates_seen += 1
                try:
                    with session.begin_nested():
                        materializer.materialize_candidate(int(case_id), candidate)
                    relationships_materialized += 1
                    if candidates_seen % batch_size == 0:
                        session.commit()
                except Exception as exc:
                    errors += 1
                    logger.warning(
                        'Memory graph extraction skipped %s record %s for case %s: %s',
                        extractor.name,
                        candidate.evidence_record_key,
                        case_id,
                        exc,
                    )
    session.commit()
    return {
        'memory_jobs_seen': jobs_seen,
        'candidates_seen': candidates_seen,
        'relationships_materialized': relationships_materialized,
        'errors': errors,
    }
