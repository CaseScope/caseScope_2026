"""Deterministic investigative graph relationship extractors."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, Iterable, List

from utils.graph_identity import (
    EntitySpec,
    GraphDerivationType,
    GraphEntityType,
    GraphRelationshipType,
)


GRAPH_EXTRACTOR_EVENT_COLUMNS = (
    'case_id',
    'artifact_type',
    'timestamp_utc',
    'source_file',
    'source_path',
    'source_host',
    'case_file_id',
    'event_id',
    'channel',
    'provider',
    'username',
    'domain',
    'sid',
    'logon_type',
    'logon_id',
    'process_name',
    'process_path',
    'process_id',
    'parent_process',
    'parent_pid',
    'command_line',
    'target_path',
    'file_hash_md5',
    'file_hash_sha1',
    'file_hash_sha256',
    'src_ip',
    'dst_ip',
    'src_port',
    'dst_port',
    'raw_json',
    'extra_fields',
    'parser_version',
    'evidence_record_key',
    'evidence_identity_version',
    'evidence_identity_quality',
)


AI_OR_ANALYTIC_CONTEXT_KEYS = {
    'ai_summary',
    'ai_rationale',
    'model_summary',
    'llm_summary',
    'mitre_attack_ids',
    'mitre_attack_tactics',
    'ioc_types',
    'rule_title',
    'rule_level',
}


@dataclass(frozen=True)
class GraphRelationshipCandidate:
    source: EntitySpec
    relationship_type: str
    target: EntitySpec
    derivation_type: str
    evidence_record_key: str
    observed_at: Any = None
    source_table: str = 'events'
    evidence_role: str = 'supporting_record'
    extractor_name: str = ''
    extractor_version: str = ''
    metadata: Dict[str, Any] = field(default_factory=dict)


def _clean(value: Any) -> str:
    return str(value or '').strip()


def _is_set(value: Any) -> bool:
    return bool(_clean(value))


def _parse_jsonish(value: Any) -> Dict[str, Any]:
    if isinstance(value, dict):
        return value
    if not value:
        return {}
    try:
        parsed = json.loads(value)
    except (TypeError, ValueError, json.JSONDecodeError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _source_context(event: Dict[str, Any]) -> str:
    parts = [
        _clean(event.get('source_table') or 'events'),
        _clean(event.get('case_file_id')),
        _clean(event.get('source_file')),
        _clean(event.get('source_path')),
        _clean(event.get('evidence_record_key')),
    ]
    return '|'.join(part for part in parts if part)


def host_spec(event: Dict[str, Any]) -> EntitySpec:
    return EntitySpec(
        GraphEntityType.HOST,
        _clean(event.get('source_host')),
        hints={'source_context': _source_context(event), 'prefer_known_system': True},
    )


def process_spec(event: Dict[str, Any], *, creation_event: bool = False) -> EntitySpec:
    return EntitySpec(
        GraphEntityType.PROCESS,
        _clean(event.get('process_name') or event.get('process_path') or event.get('process_id')),
        hints={
            'host': host_spec(event),
            'pid': event.get('process_id'),
            'start_time': event.get('timestamp_utc') if creation_event else '',
            'evidence_record_key': event.get('evidence_record_key'),
            'process_name': event.get('process_name'),
            'process_path': event.get('process_path'),
        },
    )


def user_spec(event: Dict[str, Any], *, host: EntitySpec) -> EntitySpec:
    return EntitySpec(
        GraphEntityType.USER,
        _clean(event.get('username') or event.get('sid')),
        hints={
            'sid': event.get('sid'),
            'domain': event.get('domain'),
            'username': event.get('username'),
            'host': host,
        },
    )


def logon_session_spec(event: Dict[str, Any], *, host: EntitySpec, user: EntitySpec) -> EntitySpec:
    return EntitySpec(
        GraphEntityType.LOGON_SESSION,
        _clean(event.get('logon_id')),
        hints={'host': host, 'user': user, 'logon_id': event.get('logon_id')},
    )


class GraphRelationshipExtractor:
    name = 'base'
    version = '1'

    def supports(self, event: Dict[str, Any]) -> bool:
        raise NotImplementedError

    def extract(self, event: Dict[str, Any]) -> Iterable[GraphRelationshipCandidate]:
        raise NotImplementedError

    def candidate(
        self,
        event: Dict[str, Any],
        source: EntitySpec,
        relationship_type: str,
        target: EntitySpec,
        derivation_type: str,
        *,
        evidence_role: str = 'supporting_record',
        metadata: Dict[str, Any] | None = None,
    ) -> GraphRelationshipCandidate:
        if derivation_type not in GraphDerivationType.AUTHORITATIVE_EXTRACTOR_TYPES:
            raise ValueError(f'Extractor cannot author {derivation_type} graph edges')
        return GraphRelationshipCandidate(
            source=source,
            relationship_type=relationship_type,
            target=target,
            derivation_type=derivation_type,
            evidence_record_key=_clean(event.get('evidence_record_key')),
            observed_at=event.get('timestamp_utc') or event.get('timestamp'),
            source_table=_clean(event.get('source_table') or 'events'),
            evidence_role=evidence_role,
            extractor_name=self.name,
            extractor_version=self.version,
            metadata=metadata or {},
        )


class ProcessRunsImageExtractor(GraphRelationshipExtractor):
    name = 'events_process_runs_image'
    version = '1'

    def supports(self, event: Dict[str, Any]) -> bool:
        if not (_is_set(event.get('evidence_record_key')) and _is_set(event.get('source_host'))):
            return False
        if not (_is_set(event.get('process_path')) and event.get('process_id') is not None):
            return False
        event_id = _clean(event.get('event_id'))
        channel = _clean(event.get('channel')).lower()
        artifact_type = _clean(event.get('artifact_type')).lower()
        return (
            event_id == '4688'
            or (event_id == '1' and 'sysmon' in channel)
            or (artifact_type == 'crowdstrike' and event_id == 'ProcessRollup2')
        )

    def extract(self, event: Dict[str, Any]) -> Iterable[GraphRelationshipCandidate]:
        yield self.candidate(
            event,
            process_spec(event, creation_event=True),
            GraphRelationshipType.RUNS_IMAGE,
            EntitySpec(
                GraphEntityType.FILE_PATH,
                _clean(event.get('process_path')),
                hints={'host': host_spec(event), 'path': event.get('process_path')},
            ),
            GraphDerivationType.OBSERVED,
            metadata={'rule': 'process creation record co-locates process execution and image path'},
        )


class ProcessConnectedToIpExtractor(GraphRelationshipExtractor):
    name = 'events_process_connected_to_ip'
    version = '1'

    def supports(self, event: Dict[str, Any]) -> bool:
        if not (_is_set(event.get('evidence_record_key')) and _is_set(event.get('source_host'))):
            return False
        if event.get('process_id') is None or not _is_set(event.get('dst_ip')):
            return False
        event_id = _clean(event.get('event_id'))
        channel = _clean(event.get('channel')).lower()
        artifact_type = _clean(event.get('artifact_type')).lower()
        return (event_id == '3' and 'sysmon' in channel) or (
            artifact_type == 'crowdstrike' and event_id == 'NetworkConnectIP4'
        )

    def extract(self, event: Dict[str, Any]) -> Iterable[GraphRelationshipCandidate]:
        yield self.candidate(
            event,
            process_spec(event, creation_event=False),
            GraphRelationshipType.CONNECTED_TO,
            EntitySpec(GraphEntityType.IP_ADDRESS, _clean(event.get('dst_ip'))),
            GraphDerivationType.OBSERVED,
            metadata={
                'rule': 'single network record co-locates process execution and destination IP',
                'dst_port': event.get('dst_port'),
                'src_ip': _clean(event.get('src_ip')),
                'src_port': event.get('src_port'),
            },
        )


class FilePathHadContentExtractor(GraphRelationshipExtractor):
    name = 'events_file_path_had_content'
    version = '1'

    def supports(self, event: Dict[str, Any]) -> bool:
        path = _clean(event.get('target_path') or event.get('process_path'))
        return _is_set(event.get('evidence_record_key')) and bool(path) and self._hashes(event)

    def _hashes(self, event: Dict[str, Any]) -> List[tuple[str, str]]:
        hashes = []
        for algorithm, field_name in (
            ('sha256', 'file_hash_sha256'),
            ('sha1', 'file_hash_sha1'),
            ('md5', 'file_hash_md5'),
        ):
            value = _clean(event.get(field_name))
            if value:
                hashes.append((algorithm, value))
        return hashes

    def extract(self, event: Dict[str, Any]) -> Iterable[GraphRelationshipCandidate]:
        path = _clean(event.get('target_path') or event.get('process_path'))
        for algorithm, digest in self._hashes(event):
            yield self.candidate(
                event,
                EntitySpec(GraphEntityType.FILE_PATH, path, hints={'host': host_spec(event), 'path': path}),
                GraphRelationshipType.HAD_CONTENT,
                EntitySpec(GraphEntityType.FILE_HASH, digest, hints={'algorithm': algorithm, 'hash_value': digest}),
                GraphDerivationType.OBSERVED,
                metadata={'rule': 'single forensic record co-locates path and hash', 'hash_algorithm': algorithm},
            )


class HostOwnsIpExtractor(GraphRelationshipExtractor):
    name = 'events_host_owns_ip'
    version = '1'

    def supports(self, event: Dict[str, Any]) -> bool:
        extra = _parse_jsonish(event.get('extra_fields'))
        return (
            _is_set(event.get('evidence_record_key'))
            and _is_set(event.get('source_host'))
            and _is_set(extra.get('host_ip'))
        )

    def extract(self, event: Dict[str, Any]) -> Iterable[GraphRelationshipCandidate]:
        extra = _parse_jsonish(event.get('extra_fields'))
        host_ip = extra.get('host_ip')
        if isinstance(host_ip, list):
            values = host_ip
        else:
            values = [host_ip]
        for value in values:
            if not _is_set(value):
                continue
            yield self.candidate(
                event,
                host_spec(event),
                GraphRelationshipType.OWNS_IP,
                EntitySpec(GraphEntityType.IP_ADDRESS, _clean(value)),
                GraphDerivationType.OBSERVED,
                metadata={'rule': 'explicit host_ip inventory field, not network src_ip inference'},
            )


class LogonRelationshipsExtractor(GraphRelationshipExtractor):
    name = 'windows_logon_relationships'
    version = '1'
    LOGON_EVENT_IDS = {'4624', '4625', '4634', '4647', '4648'}

    def supports(self, event: Dict[str, Any]) -> bool:
        return (
            _clean(event.get('event_id')) in self.LOGON_EVENT_IDS
            and _clean(event.get('channel')).lower() == 'security'
            and _is_set(event.get('evidence_record_key'))
            and _is_set(event.get('source_host'))
            and _is_set(event.get('logon_id'))
            and (_is_set(event.get('sid')) or (_is_set(event.get('domain')) and _is_set(event.get('username'))))
        )

    def extract(self, event: Dict[str, Any]) -> Iterable[GraphRelationshipCandidate]:
        host = host_spec(event)
        user = user_spec(event, host=host)
        session = logon_session_spec(event, host=host, user=user)
        yield self.candidate(
            event,
            user,
            GraphRelationshipType.LOGGED_ON_TO,
            host,
            GraphDerivationType.OBSERVED,
            metadata={'rule': 'Windows Security logon record identifies account and host'},
        )
        yield self.candidate(
            event,
            session,
            GraphRelationshipType.LOGON_AS,
            user,
            GraphDerivationType.OBSERVED,
            metadata={'rule': 'Windows Security logon record binds logon session to account'},
        )
        yield self.candidate(
            event,
            session,
            GraphRelationshipType.ON_HOST,
            host,
            GraphDerivationType.OBSERVED,
            metadata={'rule': 'Windows Security logon record scopes logon session to source host'},
        )


DEFAULT_EVENT_EXTRACTORS: tuple[GraphRelationshipExtractor, ...] = (
    ProcessRunsImageExtractor(),
    ProcessConnectedToIpExtractor(),
    FilePathHadContentExtractor(),
    HostOwnsIpExtractor(),
    LogonRelationshipsExtractor(),
)


def event_from_clickhouse_row(row: Any, columns: Iterable[str] = GRAPH_EXTRACTOR_EVENT_COLUMNS) -> Dict[str, Any]:
    if isinstance(row, dict):
        event = dict(row)
    else:
        event = dict(zip(columns, row))
    event.setdefault('source_table', 'events')
    return event


def extract_event_relationships(
    event: Dict[str, Any],
    extractors: Iterable[GraphRelationshipExtractor] = DEFAULT_EVENT_EXTRACTORS,
) -> List[GraphRelationshipCandidate]:
    # AI, IOC, and MITRE context is intentionally ignored here. Only explicit
    # normalized evidence fields may author authoritative graph edges.
    if any(_is_set(event.get(key)) for key in AI_OR_ANALYTIC_CONTEXT_KEYS):
        event = {key: value for key, value in event.items() if key not in AI_OR_ANALYTIC_CONTEXT_KEYS}
    candidates: List[GraphRelationshipCandidate] = []
    for extractor in extractors:
        if extractor.supports(event):
            candidates.extend(extractor.extract(event))
    return candidates
