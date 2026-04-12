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
