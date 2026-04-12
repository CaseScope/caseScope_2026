"""Shared AttackPattern loader helpers for sync and built-in rule packs."""

from __future__ import annotations

from typing import Any, Dict


SYNC_ATTACK_PATTERN_UPDATE_FIELDS = (
    'description',
    'clickhouse_query',
    'pattern_definition',
    'mitre_tactic',
    'mitre_technique',
    'detection_guidance',
    'procedure_examples',
    'severity',
    'confidence_weight',
    'required_artifact_types',
)

OPENCTI_ATTACK_PATTERN_UPDATE_FIELDS = (
    'description',
    'mitre_tactic',
    'mitre_technique',
    'pattern_definition',
    'required_artifact_types',
)


def apply_attack_pattern_updates(
    target: Any,
    payload: Dict[str, Any],
    *,
    update_fields = SYNC_ATTACK_PATTERN_UPDATE_FIELDS,
    update_name: bool = False,
) -> None:
    """Apply a normalized AttackPattern payload onto an existing ORM row."""
    if update_name and payload.get('name') not in (None, '', [], {}):
        target.name = payload['name']

    for key in update_fields:
        value = payload.get(key)
        if value not in (None, '', [], {}):
            setattr(target, key, value)

    target.last_synced_at = payload.get('last_synced_at')


def resolve_attack_pattern_lookup(pattern: Dict[str, Any]) -> Dict[str, Any]:
    """Prefer source-native identifiers, then fall back to name within a source."""
    source = pattern.get('source', 'unknown')
    source_id = pattern.get('source_id')
    if source_id:
        return {
            'source': source,
            'source_id': source_id,
        }
    return {
        'name': pattern['name'],
        'source': source,
    }


def build_attack_pattern_payload(
    pattern: Dict[str, Any],
    *,
    last_synced_at: Any = None,
    created_by: str | None = None,
    enabled: bool | None = None,
) -> Dict[str, Any]:
    """Normalize a rule-pack dictionary into AttackPattern constructor fields."""
    return {
        'name': pattern['name'],
        'description': pattern.get('description'),
        'mitre_tactic': pattern.get('mitre_tactic'),
        'mitre_technique': pattern.get('mitre_technique'),
        'source': pattern.get('source', 'unknown'),
        'source_id': pattern.get('source_id'),
        'source_url': pattern.get('source_url'),
        'pattern_type': pattern.get('pattern_type', 'single'),
        'pattern_definition': pattern.get('pattern_definition', {}),
        'clickhouse_query': pattern.get('clickhouse_query'),
        'detection_guidance': pattern.get('detection_guidance'),
        'procedure_examples': pattern.get('procedure_examples'),
        'required_event_ids': pattern.get('required_event_ids'),
        'required_channels': pattern.get('required_channels'),
        'required_artifact_types': pattern.get('required_artifact_types'),
        'time_window_minutes': pattern.get('time_window_minutes', 60),
        'severity': pattern.get('severity', 'medium'),
        'confidence_weight': pattern.get('confidence_weight', 0.7),
        'enabled': pattern.get('enabled', True) if enabled is None else enabled,
        'last_synced_at': last_synced_at,
        'created_by': pattern.get('created_by', 'sync_import') if created_by is None else created_by,
    }


def normalize_opencti_attack_pattern(pattern: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize an OpenCTI ATT&CK pattern into the shared AttackPattern input shape."""
    tactic = pattern['kill_chain_phases'][0] if pattern.get('kill_chain_phases') else None
    return {
        'name': pattern['name'],
        'description': pattern.get('detection') or pattern.get('description'),
        'mitre_tactic': tactic,
        'mitre_technique': pattern['mitre_id'],
        'source': 'opencti',
        'source_id': pattern['opencti_id'],
        'pattern_type': 'single',
        'pattern_definition': {
            'type': 'mitre_technique',
            'platforms': pattern.get('platforms', []),
        },
        'required_artifact_types': ['evtx'],
    }


def normalize_opencti_sigma_indicator(indicator: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize an OpenCTI Sigma indicator into the shared AttackPattern input shape."""
    tactic = indicator['kill_chain_phases'][0] if indicator.get('kill_chain_phases') else None
    return {
        'name': indicator['name'],
        'source': 'opencti_sigma',
        'source_id': indicator['opencti_id'],
        'pattern_type': 'sigma',
        'pattern_definition': {
            'type': 'sigma',
            'raw_pattern': indicator['pattern'],
            'score': indicator.get('score', 0),
        },
        'mitre_tactic': tactic,
    }


def normalize_mitre_attack_pattern(pattern_data: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize MITRE ATT&CK sync output into the shared AttackPattern input shape."""
    return {
        'name': pattern_data['name'],
        'description': pattern_data['description'],
        'detection_guidance': pattern_data.get('detection_guidance'),
        'procedure_examples': pattern_data.get('procedure_examples'),
        'mitre_tactic': pattern_data['mitre_tactics'][0] if pattern_data.get('mitre_tactics') else None,
        'mitre_technique': pattern_data['mitre_techniques'][0] if pattern_data.get('mitre_techniques') else None,
        'source': 'mitre_attack_v18',
        'source_id': pattern_data['id'],
        'pattern_type': 'clickhouse_query',
        'clickhouse_query': pattern_data['detection_query'],
        'severity': pattern_data['severity'],
        'pattern_definition': {
            'indicators': pattern_data['indicators'],
            'event_ids': pattern_data.get('event_ids', []),
            'data_components': pattern_data.get('data_components', []),
            'thresholds': pattern_data.get('thresholds', {}),
        },
        'required_artifact_types': ['evtx'],
    }
