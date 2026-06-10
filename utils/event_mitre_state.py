"""ClickHouse storage for deterministic MITRE procedure mappings."""
from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional, Sequence
from uuid import uuid4

from utils.clickhouse import (
    clickhouse_string_array_literal,
    clickhouse_string_literal,
    get_client,
    run_events_update,
    wait_for_mutation_completion,
)

MITRE_MATCH_TABLE = "event_mitre_matches"
MITRE_SUMMARY_COLUMNS = {
    "mitre_attack_ids": "Array(String) DEFAULT []",
    "mitre_attack_tactics": "Array(String) DEFAULT []",
    "mitre_attack_sources": "Array(String) DEFAULT []",
    "mitre_mapping_max_confidence": "UInt8 DEFAULT 0",
}


MITRE_MATCH_SCHEMA = f"""
CREATE TABLE IF NOT EXISTS {MITRE_MATCH_TABLE} (
    case_id UInt32,
    selector_key String,
    artifact_type LowCardinality(String),
    source_host LowCardinality(String),
    timestamp DateTime64(3),
    attack_id LowCardinality(String),
    attack_name String,
    object_type LowCardinality(String),
    tactic String,
    procedure_name String,
    mapping_confidence UInt8,
    evidence_strength LowCardinality(String),
    source LowCardinality(String),
    reason String,
    matched_fields_json String CODEC(ZSTD(1)),
    rule_id LowCardinality(String),
    scan_version String,
    created_at DateTime64(3) DEFAULT now64(3),

    INDEX idx_selector_key selector_key TYPE bloom_filter(0.01) GRANULARITY 4,
    INDEX idx_attack_id attack_id TYPE bloom_filter(0.01) GRANULARITY 4
)
ENGINE = MergeTree()
PARTITION BY case_id
ORDER BY (case_id, attack_id, selector_key, rule_id)
SETTINGS index_granularity = 8192;
"""


def _normalized_username(value: Any) -> str:
    return str(value or "").strip() or "system"


def _existing_columns(client, table_name: str) -> set:
    result = client.query(
        """
        SELECT name
        FROM system.columns
        WHERE database = currentDatabase()
          AND table = {table_name:String}
        """,
        parameters={"table_name": table_name},
    )
    return {row[0] for row in result.result_rows}


def ensure_event_mitre_state_tables(client=None) -> None:
    client = client or get_client()
    client.command(MITRE_MATCH_SCHEMA)

    for table_name in ("events", "events_buffer"):
        existing = _existing_columns(client, table_name)
        if not existing:
            continue
        for column_name, definition in MITRE_SUMMARY_COLUMNS.items():
            if column_name not in existing:
                client.command(
                    f"ALTER TABLE {table_name} ADD COLUMN IF NOT EXISTS {column_name} {definition}"
                )


def start_mitre_mapping_scan(case_id: int, *, updated_by: str, client=None) -> str:
    client = client or get_client()
    ensure_event_mitre_state_tables(client)
    scan_version = str(uuid4())

    command_fragment = (
        f"DELETE WHERE case_id = {int(case_id)} "
        "AND source = 'mitre_procedure_rule'"
    )
    client.command(f"ALTER TABLE {MITRE_MATCH_TABLE} {command_fragment}")
    wait_for_mutation_completion(MITRE_MATCH_TABLE, command_fragment, client=client)
    return scan_version


def _matched_fields_expression(field_names: Iterable[str]) -> str:
    entries = []
    for field_name in field_names or []:
        clean_name = str(field_name or "").strip()
        if not clean_name:
            continue
        entries.append(
            f"{clickhouse_string_literal(clean_name)}, "
            f"substring(toString({clean_name}), 1, 500)"
        )
    if not entries:
        return "toJSONString(map())"
    return f"toJSONString(map({', '.join(entries)}))"


def _delete_source_matches_for_selectors(
    case_id: int,
    source: str,
    selector_keys: Sequence[str],
    *,
    client=None,
) -> None:
    clean_keys = [str(key).strip() for key in selector_keys or [] if str(key).strip()]
    if not clean_keys:
        return
    client = client or get_client()
    ensure_event_mitre_state_tables(client)
    command_fragment = (
        f"DELETE WHERE case_id = {int(case_id)} "
        f"AND source = {clickhouse_string_literal(source)} "
        f"AND has({clickhouse_string_array_literal(clean_keys)}, selector_key)"
    )
    client.command(f"ALTER TABLE {MITRE_MATCH_TABLE} {command_fragment}")
    wait_for_mutation_completion(MITRE_MATCH_TABLE, command_fragment, client=client)


def delete_hayabusa_matches_for_case_file(case_id: int, case_file_id: Optional[int], *, client=None) -> int:
    """Remove Hayabusa match rows for selectors currently attached to a case file."""
    if not case_file_id:
        return 0
    client = client or get_client()
    ensure_event_mitre_state_tables(client)
    result = client.query(
        """
        SELECT selector_key
        FROM events
        WHERE case_id = {case_id:UInt32}
          AND case_file_id = {case_file_id:UInt32}
          AND has(mitre_attack_sources, 'hayabusa')
        """,
        parameters={"case_id": int(case_id), "case_file_id": int(case_file_id)},
    )
    selector_keys = [row[0] for row in result.result_rows if row and row[0]]
    _delete_source_matches_for_selectors(case_id, "hayabusa", selector_keys, client=client)
    return len(selector_keys)


def insert_hayabusa_matches(case_id: int, rows: Iterable[Dict[str, Any]], *, client=None) -> int:
    """Insert Hayabusa event-technique matches into the shared MITRE state table."""
    client = client or get_client()
    ensure_event_mitre_state_tables(client)

    prepared_rows = []
    selector_keys = []
    for row in rows or []:
        selector_key = str(row.get("selector_key") or "").strip()
        attack_id = str(row.get("attack_id") or "").strip().upper()
        if not selector_key or not attack_id:
            continue
        selector_keys.append(selector_key)
        prepared_rows.append(
            (
                int(case_id),
                selector_key,
                str(row.get("artifact_type") or ""),
                str(row.get("source_host") or ""),
                row.get("timestamp"),
                attack_id,
                str(row.get("attack_name") or attack_id),
                str(row.get("object_type") or ""),
                str(row.get("tactic") or ""),
                str(row.get("procedure_name") or ""),
                max(0, min(100, int(row.get("mapping_confidence") or 0))),
                str(row.get("evidence_strength") or "low"),
                "hayabusa",
                str(row.get("reason") or "Hayabusa Sigma detection"),
                str(row.get("matched_fields_json") or "{}"),
                str(row.get("rule_id") or ""),
                str(row.get("scan_version") or "hayabusa_ingest"),
            )
        )

    if not prepared_rows:
        return 0

    _delete_source_matches_for_selectors(case_id, "hayabusa", selector_keys, client=client)
    client.insert(
        MITRE_MATCH_TABLE,
        prepared_rows,
        column_names=[
            "case_id",
            "selector_key",
            "artifact_type",
            "source_host",
            "timestamp",
            "attack_id",
            "attack_name",
            "object_type",
            "tactic",
            "procedure_name",
            "mapping_confidence",
            "evidence_strength",
            "source",
            "reason",
            "matched_fields_json",
            "rule_id",
            "scan_version",
        ],
    )
    return len(prepared_rows)


def insert_mitre_rule_matches(
    case_id: int,
    scan_version: str,
    *,
    rule: Dict[str, Any],
    attack_metadata: Dict[str, Dict[str, str]],
    updated_by: str,
    client=None,
) -> int:
    client = client or get_client()
    ensure_event_mitre_state_tables(client)

    params = {"case_id": int(case_id)}
    where_clause = str(rule["where_sql"]).strip()
    count_result = client.query(
        f"SELECT count() FROM events WHERE {where_clause}",
        parameters=params,
    )
    match_count = int(count_result.result_rows[0][0]) if count_result.result_rows else 0
    if match_count <= 0:
        return 0

    matched_fields_json = _matched_fields_expression(rule.get("matched_fields") or [])
    rule_id = str(rule["id"])
    procedure_name = str(rule.get("name") or rule_id)
    evidence_strength = str(rule.get("evidence_strength") or "medium")
    source = str(rule.get("source") or "mitre_procedure_rule")
    reason = str(rule.get("reason") or procedure_name)
    confidence = max(0, min(100, int(rule.get("mapping_confidence") or 0)))
    attack_ids = [str(attack_id) for attack_id in (rule.get("attack_ids") or []) if str(attack_id).strip()]

    for attack_id in attack_ids:
        metadata = attack_metadata.get(attack_id, {})
        insert_sql = f"""
            INSERT INTO {MITRE_MATCH_TABLE} (
                case_id,
                selector_key,
                artifact_type,
                source_host,
                timestamp,
                attack_id,
                attack_name,
                object_type,
                tactic,
                procedure_name,
                mapping_confidence,
                evidence_strength,
                source,
                reason,
                matched_fields_json,
                rule_id,
                scan_version,
                created_at
            )
            SELECT
                case_id,
                selector_key,
                artifact_type,
                source_host,
                timestamp_utc,
                {clickhouse_string_literal(attack_id)},
                {clickhouse_string_literal(metadata.get('name') or attack_id)},
                {clickhouse_string_literal(metadata.get('object_type') or '')},
                {clickhouse_string_literal(metadata.get('tactic') or '')},
                {clickhouse_string_literal(procedure_name)},
                toUInt8({confidence}),
                {clickhouse_string_literal(evidence_strength)},
                {clickhouse_string_literal(source)},
                {clickhouse_string_literal(reason)},
                {matched_fields_json},
                {clickhouse_string_literal(rule_id)},
                {clickhouse_string_literal(scan_version)},
                now64(3)
            FROM events
            WHERE {where_clause}
        """
        client.command(insert_sql, parameters=params)

        tactic_values = [
            tactic.strip()
            for tactic in str(metadata.get("tactic") or "").split(",")
            if tactic.strip()
        ]
        run_events_update(
            "mitre_attack_ids = arrayDistinct(arrayConcat("
            f"mitre_attack_ids, {clickhouse_string_array_literal([attack_id])})), "
            "mitre_attack_tactics = arrayDistinct(arrayConcat("
            f"mitre_attack_tactics, {clickhouse_string_array_literal(tactic_values)})), "
            "mitre_attack_sources = arrayDistinct(arrayConcat("
            f"mitre_attack_sources, {clickhouse_string_array_literal([source])})), "
            f"mitre_mapping_max_confidence = greatest(mitre_mapping_max_confidence, toUInt8({confidence}))",
            where_clause.replace("{case_id:UInt32}", str(int(case_id))),
            client=client,
        )

    return match_count * len(attack_ids)


def rebuild_mitre_summary_columns(case_id: int, *, client=None) -> int:
    """Rebuild event MITRE summary columns from match rows across all sources."""
    client = client or get_client()
    ensure_event_mitre_state_tables(client)

    run_events_update(
        "mitre_attack_ids = [], "
        "mitre_attack_tactics = [], "
        "mitre_attack_sources = [], "
        "mitre_mapping_max_confidence = 0",
        f"case_id = {int(case_id)} AND ("
        "length(mitre_attack_ids) > 0 OR "
        "length(mitre_attack_tactics) > 0 OR "
        "length(mitre_attack_sources) > 0 OR "
        "mitre_mapping_max_confidence > 0)",
        client=client,
    )

    result = client.query(
        f"""
        SELECT
            attack_id,
            source,
            any(tactic),
            max(mapping_confidence),
            count()
        FROM {MITRE_MATCH_TABLE}
        WHERE case_id = {{case_id:UInt32}}
          AND attack_id != ''
          AND source != ''
        GROUP BY attack_id, source
        """,
        parameters={"case_id": int(case_id)},
    )

    updated_groups = 0
    for attack_id, source, tactic, confidence, match_count in result.result_rows:
        if int(match_count or 0) <= 0:
            continue
        tactic_values = [
            value.strip()
            for value in str(tactic or "").split(",")
            if value.strip()
        ]
        run_events_update(
            "mitre_attack_ids = arrayDistinct(arrayConcat("
            f"mitre_attack_ids, {clickhouse_string_array_literal([attack_id])})), "
            "mitre_attack_tactics = arrayDistinct(arrayConcat("
            f"mitre_attack_tactics, {clickhouse_string_array_literal(tactic_values)})), "
            "mitre_attack_sources = arrayDistinct(arrayConcat("
            f"mitre_attack_sources, {clickhouse_string_array_literal([source])})), "
            f"mitre_mapping_max_confidence = greatest(mitre_mapping_max_confidence, toUInt8({int(confidence or 0)}))",
            f"case_id = {int(case_id)} AND selector_key IN ("
            f"SELECT selector_key FROM {MITRE_MATCH_TABLE} "
            f"WHERE case_id = {int(case_id)} "
            f"AND attack_id = {clickhouse_string_literal(attack_id)} "
            f"AND source = {clickhouse_string_literal(source)})",
            client=client,
        )
        updated_groups += 1

    return updated_groups


def count_mitre_mapped_events(case_id: int, client=None) -> int:
    client = client or get_client()
    ensure_event_mitre_state_tables(client)
    result = client.query(
        "SELECT count() FROM events "
        "WHERE case_id = {case_id:UInt32} AND length(mitre_attack_ids) > 0",
        parameters={"case_id": int(case_id)},
    )
    return int(result.result_rows[0][0]) if result.result_rows else 0


def get_mitre_mapping_stats(case_id: int, client=None) -> Dict[str, Any]:
    client = client or get_client()
    ensure_event_mitre_state_tables(client)

    total_result = client.query(
        "SELECT count() FROM events WHERE case_id = {case_id:UInt32}",
        parameters={"case_id": int(case_id)},
    )
    total_events = int(total_result.result_rows[0][0]) if total_result.result_rows else 0

    mapped_events = count_mitre_mapped_events(case_id, client=client)
    match_result = client.query(
        f"""
        SELECT
            count(),
            max(created_at)
        FROM {MITRE_MATCH_TABLE}
        WHERE case_id = {{case_id:UInt32}}
          AND source = 'mitre_procedure_rule'
        """,
        parameters={"case_id": int(case_id)},
    )
    total_matches, last_scan = match_result.result_rows[0] if match_result.result_rows else (0, None)

    top_result = client.query(
        f"""
        SELECT attack_id, any(attack_name), count()
        FROM {MITRE_MATCH_TABLE}
        WHERE case_id = {{case_id:UInt32}}
          AND source = 'mitre_procedure_rule'
        GROUP BY attack_id
        ORDER BY count() DESC
        LIMIT 10
        """,
        parameters={"case_id": int(case_id)},
    )
    top_techniques = [
        {"attack_id": row[0], "attack_name": row[1], "count": int(row[2])}
        for row in top_result.result_rows
    ]

    artifact_result = client.query(
        f"""
        SELECT artifact_type, count()
        FROM {MITRE_MATCH_TABLE}
        WHERE case_id = {{case_id:UInt32}}
          AND source = 'mitre_procedure_rule'
        GROUP BY artifact_type
        ORDER BY count() DESC
        LIMIT 10
        """,
        parameters={"case_id": int(case_id)},
    )
    artifact_types = [
        {"artifact_type": row[0], "count": int(row[1])}
        for row in artifact_result.result_rows
    ]

    return {
        "case_id": int(case_id),
        "total_events": total_events,
        "mapped_events": mapped_events,
        "total_matches": int(total_matches or 0),
        "mapped_percentage": round((mapped_events / total_events * 100), 2) if total_events else 0,
        "last_scan": last_scan.isoformat() if hasattr(last_scan, "isoformat") else None,
        "top_techniques": top_techniques,
        "artifact_types": artifact_types,
    }


__all__ = [
    "MITRE_MATCH_TABLE",
    "count_mitre_mapped_events",
    "delete_hayabusa_matches_for_case_file",
    "ensure_event_mitre_state_tables",
    "get_mitre_mapping_stats",
    "insert_hayabusa_matches",
    "insert_mitre_rule_matches",
    "rebuild_mitre_summary_columns",
    "start_mitre_mapping_scan",
]
