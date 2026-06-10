"""MITRE technique corroboration across Hayabusa and procedure-rule sources."""
from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List, Set

from utils.clickhouse import get_client
from utils.event_mitre_state import MITRE_MATCH_TABLE, ensure_event_mitre_state_tables

MITRE_TECHNIQUE_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$", re.IGNORECASE)


def normalize_technique_id(value: Any) -> str:
    normalized = str(value or "").strip().upper()
    return normalized if MITRE_TECHNIQUE_RE.match(normalized) else ""


def parent_technique_id(value: Any) -> str:
    technique_id = normalize_technique_id(value)
    return technique_id.split(".", 1)[0] if "." in technique_id else technique_id


def _load_reference_equivalents(technique_ids: Iterable[str]) -> Dict[str, Set[str]]:
    clean_ids = {normalize_technique_id(value) for value in technique_ids}
    clean_ids.discard("")
    equivalents = {technique_id: {technique_id, parent_technique_id(technique_id)} for technique_id in clean_ids}
    try:
        from models.mitre_attack import MitreAttackObject

        parent_ids = {parent_technique_id(technique_id) for technique_id in clean_ids}
        rows = MitreAttackObject.query.filter(
            MitreAttackObject.object_type.in_(["technique", "sub_technique"]),
        ).filter(
            (MitreAttackObject.external_id.in_(list(clean_ids | parent_ids)))
            | (MitreAttackObject.technique_external_id.in_(list(clean_ids | parent_ids)))
        ).all()
        children_by_parent: Dict[str, Set[str]] = {}
        for row in rows:
            external_id = normalize_technique_id(row.external_id)
            parent_id = normalize_technique_id(row.technique_external_id) or parent_technique_id(external_id)
            if not external_id or not parent_id:
                continue
            children_by_parent.setdefault(parent_id, set()).add(external_id)

        for technique_id in clean_ids:
            parent_id = parent_technique_id(technique_id)
            equivalents[technique_id].update(children_by_parent.get(parent_id, set()))
    except Exception:
        # If the reference DB is unavailable, parent-prefix matching below still
        # lets T1021 and T1021.001 corroborate each other.
        pass
    return equivalents


def get_corroborated_techniques(case_id: int, technique_ids: Iterable[str], *, client=None) -> List[str]:
    """Return requested techniques present from both Hayabusa and procedure-rule sources."""
    requested = []
    for value in technique_ids or []:
        technique_id = normalize_technique_id(value)
        if technique_id and technique_id not in requested:
            requested.append(technique_id)
    if not requested:
        return []

    equivalents = _load_reference_equivalents(requested)
    query_ids = sorted({candidate for values in equivalents.values() for candidate in values if candidate})
    if not query_ids:
        return []

    client = client or get_client()
    ensure_event_mitre_state_tables(client)
    result = client.query(
        f"""
        SELECT attack_id, groupUniqArray(source)
        FROM {MITRE_MATCH_TABLE}
        WHERE case_id = {{case_id:UInt32}}
          AND attack_id IN {{attack_ids:Array(String)}}
          AND source IN ('hayabusa', 'mitre_procedure_rule')
        GROUP BY attack_id
        """,
        parameters={"case_id": int(case_id), "attack_ids": query_ids},
    )

    sources_by_attack_id = {
        normalize_technique_id(row[0]): {str(source) for source in (row[1] or [])}
        for row in result.result_rows
    }
    corroborated: List[str] = []
    for technique_id in requested:
        family_sources: Set[str] = set()
        for equivalent in equivalents.get(technique_id, {technique_id, parent_technique_id(technique_id)}):
            family_sources.update(sources_by_attack_id.get(equivalent, set()))
        if {"hayabusa", "mitre_procedure_rule"}.issubset(family_sources):
            corroborated.append(technique_id)
    return corroborated


__all__ = [
    "get_corroborated_techniques",
    "normalize_technique_id",
    "parent_technique_id",
]
