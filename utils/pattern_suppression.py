"""Shared suppression-bookkeeping helpers for deterministic pattern analysis."""

from __future__ import annotations

from typing import Any, Dict, List, Tuple


PATTERN_SUPPRESSION_RULES: Dict[str, List[Dict[str, Any]]] = {
    'dcsync': [
        {
            'pattern': 'bloodhound_sharphound',
            'mode': 'hard',
            'min_score': 50,
            'adjustment': 100,
            'shared_fields': [('source_host',), ('username',)],
        },
    ],
    'lsass_memory_dump': [
        {
            'pattern': 'process_injection',
            'mode': 'soft',
            'min_score': 60,
            'adjustment': 25,
            'shared_fields': [('source_host',)],
        },
    ],
    'remote_registry_sam_access': [
        {
            'pattern': 'sam_database_dump',
            'mode': 'soft',
            'min_score': 55,
            'adjustment': 25,
            'shared_fields': [('source_host',), ('target_host',)],
        },
    ],
    'backup_operator_abuse': [
        {
            'pattern': 'sam_database_dump',
            'mode': 'soft',
            'min_score': 55,
            'adjustment': 20,
            'shared_fields': [('source_host',), ('username',)],
        },
    ],
    'scheduled_task_persistence': [
        {
            'pattern': 'registry_run_keys',
            'mode': 'soft',
            'min_score': 50,
            'adjustment': 20,
            'shared_fields': [('source_host',)],
        },
        {
            'pattern': 'log_clearing',
            'mode': 'soft',
            'min_score': 50,
            'adjustment': 15,
            'shared_fields': [('source_host',)],
        },
    ],
    'wmi_lateral': [
        {
            'pattern': 'registry_run_keys',
            'mode': 'soft',
            'min_score': 50,
            'adjustment': 20,
            'shared_fields': [('source_host',), ('target_host',)],
        },
        {
            'pattern': 'log_clearing',
            'mode': 'soft',
            'min_score': 50,
            'adjustment': 15,
            'shared_fields': [('source_host',), ('target_host',)],
        },
    ],
    'winrm_lateral': [
        {
            'pattern': 'registry_run_keys',
            'mode': 'soft',
            'min_score': 50,
            'adjustment': 20,
            'shared_fields': [('source_host',), ('target_host',)],
        },
        {
            'pattern': 'log_clearing',
            'mode': 'soft',
            'min_score': 50,
            'adjustment': 15,
            'shared_fields': [('source_host',), ('target_host',)],
        },
    ],
    'rdp_lateral': [
        {
            'pattern': 'registry_run_keys',
            'mode': 'soft',
            'min_score': 20,
            'adjustment': 25,
            'shared_fields': [('source_host',), ('target_host',)],
        },
        {
            'pattern': 'log_clearing',
            'mode': 'soft',
            'min_score': 50,
            'adjustment': 15,
            'shared_fields': [('source_host',), ('target_host',)],
        },
    ],
}

PATTERN_SUPPRESSION_PRIORITY = {
    pattern_id: idx
    for idx, pattern_id in enumerate(PATTERN_SUPPRESSION_RULES.keys())
}


def should_track_pattern_for_suppression(pattern_id: str) -> bool:
    return pattern_id in PATTERN_SUPPRESSION_RULES


def build_confirmed_pattern_entry(
    *,
    correlation_key: str,
    score: Any,
    anchor: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    return {
        'correlation_key': correlation_key,
        'score': score or 0,
        'anchor': dict(anchor or {}),
    }


def anchors_overlap(
    anchor_a: Dict[str, Any],
    anchor_b: Dict[str, Any],
    shared_fields: List[Tuple[str, ...]] | None,
) -> bool:
    for field_group in shared_fields or [('source_host',)]:
        matches = True
        for field in field_group:
            left = str(anchor_a.get(field, '') or '').strip().lower()
            right = str(anchor_b.get(field, '') or '').strip().lower()
            if not left or not right or left != right:
                matches = False
                break
        if matches:
            return True
    return False


def get_pattern_suppression_matches(
    pattern_id: str,
    anchor: Dict[str, Any],
    confirmed_patterns: Dict[str, List[Dict[str, Any]]],
) -> List[Dict[str, Any]]:
    matches: List[Dict[str, Any]] = []
    for suppressor_id, rules in PATTERN_SUPPRESSION_RULES.items():
        if suppressor_id not in confirmed_patterns:
            continue
        for rule in rules:
            if rule['pattern'] != pattern_id:
                continue
            for confirmed in confirmed_patterns[suppressor_id]:
                if confirmed.get('score', 0) < rule['min_score']:
                    continue
                if anchors_overlap(
                    confirmed.get('anchor', {}),
                    anchor,
                    rule.get('shared_fields'),
                ):
                    matches.append(
                        {
                            'suppressor': suppressor_id,
                            'mode': rule['mode'],
                            'adjustment': rule['adjustment'],
                            'score': confirmed.get('score', 0),
                        }
                    )
    return matches
