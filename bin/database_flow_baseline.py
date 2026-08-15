#!/usr/bin/env python3
"""Phase 0A ClickHouse baseline diagnostics for the Database Flow plan.

This script is read-only. It reports storage health, representative EXPLAIN
output, and observational duplicate classification against the current schema.
"""
from __future__ import annotations

import argparse
import json
import statistics
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from utils.clickhouse import get_fresh_client  # noqa: E402
from utils.event_deduplication import (  # noqa: E402
    ARTIFACT_DEDUP_CONFIGS,
    AUTO_DEDUP_MAX_ELIGIBLE_EVENTS,
    SKIP_AUTO_DEDUP_TYPES,
    build_non_null_condition,
)


def _rows(result: Any) -> List[tuple]:
    return list(getattr(result, "result_rows", []) or [])


def _query(client: Any, sql: str, parameters: Optional[Dict[str, Any]] = None) -> List[tuple]:
    return _rows(client.query(sql, parameters=parameters or {}))


def _single(client: Any, sql: str, parameters: Optional[Dict[str, Any]] = None, default: Any = None) -> Any:
    rows = _query(client, sql, parameters)
    return rows[0][0] if rows and rows[0] else default


def _table_exists(client: Any, table: str) -> bool:
    return bool(_single(
        client,
        """
        SELECT count()
        FROM system.tables
        WHERE database = currentDatabase()
          AND table = {table:String}
        """,
        {"table": table},
        0,
    ))


def _percentile(values: Iterable[int], percentile: float) -> Optional[int]:
    ordered = sorted(int(value) for value in values)
    if not ordered:
        return None
    index = min(len(ordered) - 1, max(0, round((len(ordered) - 1) * percentile)))
    return ordered[index]


def collect_clickhouse_baseline(client: Any, representative_case_limit: int = 10) -> Dict[str, Any]:
    part_rows = _query(
        client,
        """
        SELECT
            partition,
            count() AS parts,
            sum(rows) AS rows,
            sum(bytes_on_disk) AS bytes,
            any(part_type) AS sample_part_type
        FROM system.parts
        WHERE database = currentDatabase()
          AND table = 'events'
          AND active
        GROUP BY partition
        ORDER BY parts DESC, bytes DESC
        """,
    )
    part_counts = [int(row[1]) for row in part_rows]
    rows_per_partition = [int(row[2]) for row in part_rows]
    bytes_per_partition = [int(row[3]) for row in part_rows]

    physical_parts = _query(
        client,
        """
        SELECT rows, bytes_on_disk
        FROM system.parts
        WHERE database = currentDatabase()
          AND table = 'events'
          AND active
        """,
    )
    rows_per_part = [int(row[0]) for row in physical_parts]
    bytes_per_part = [int(row[1]) for row in physical_parts]

    physical_part_rows = _query(
        client,
        """
        SELECT part_type, count()
        FROM system.parts
        WHERE database = currentDatabase()
          AND table = 'events'
          AND active
        GROUP BY part_type
        ORDER BY part_type
        """,
    )

    mutation_rows = _query(
        client,
        """
        SELECT mutation_id, command, create_time, is_done, latest_fail_reason
        FROM system.mutations
        WHERE database = currentDatabase()
          AND table IN ('events', 'events_buffer')
        ORDER BY create_time DESC
        LIMIT 20
        """,
    )

    merge_rows = _query(
        client,
        """
        SELECT table, partition_id, elapsed, progress, num_parts, total_size_bytes_compressed
        FROM system.merges
        WHERE database = currentDatabase()
          AND table IN ('events', 'events_buffer')
        ORDER BY elapsed DESC
        LIMIT 20
        """,
    )

    search_index_rows = _query(
        client,
        """
        SELECT name, expr, type, granularity
        FROM system.data_skipping_indices
        WHERE database = currentDatabase()
          AND table = 'events'
        ORDER BY name
        """,
    )

    representative_cases = _query(
        client,
        """
        SELECT partition, sum(rows) AS rows, sum(bytes_on_disk) AS bytes
        FROM system.parts
        WHERE database = currentDatabase()
          AND table = 'events'
          AND active
        GROUP BY partition
        ORDER BY bytes DESC
        LIMIT {limit:UInt32}
        """,
        {"limit": representative_case_limit},
    )

    events_buffer = {"exists": _table_exists(client, "events_buffer")}
    if events_buffer["exists"]:
        events_buffer["engine"] = _single(
            client,
            """
            SELECT engine
            FROM system.tables
            WHERE database = currentDatabase()
              AND table = 'events_buffer'
            """,
        )
        try:
            events_buffer["visible_row_count"] = int(_single(client, "SELECT count() FROM events_buffer", default=0))
        except Exception as exc:
            events_buffer["visible_row_count_error"] = str(exc)

    create_table = _single(client, "SHOW CREATE TABLE events", default="")
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "clickhouse_version": _single(client, "SELECT version()", default="unknown"),
        "database": _single(client, "SELECT currentDatabase()", default="unknown"),
        "events_table_exists": _table_exists(client, "events"),
        "events_show_create": create_table,
        "active_part_count": sum(part_counts),
        "partitions": [
            {
                "partition": row[0],
                "parts": int(row[1]),
                "rows": int(row[2]),
                "bytes": int(row[3]),
                "sample_part_type": row[4],
            }
            for row in part_rows
        ],
        "part_statistics": {
            "median_rows_per_part": statistics.median(rows_per_part) if rows_per_part else None,
            "median_bytes_per_part": statistics.median(bytes_per_part) if bytes_per_part else None,
            "p95_rows_per_part": _percentile(rows_per_part, 0.95),
            "p95_bytes_per_part": _percentile(bytes_per_part, 0.95),
            "median_rows_per_partition": statistics.median(rows_per_partition) if rows_per_partition else None,
            "median_bytes_per_partition": statistics.median(bytes_per_partition) if bytes_per_partition else None,
            "median_parts_per_partition": statistics.median(part_counts) if part_counts else None,
            "p95_parts_per_partition": _percentile(part_counts, 0.95),
            "max_parts_per_partition": max(part_counts) if part_counts else None,
        },
        "compact_vs_wide_counts": {str(row[0]): int(row[1]) for row in physical_part_rows},
        "mutations_recent": [
            {
                "mutation_id": row[0],
                "command": row[1],
                "create_time": str(row[2]),
                "is_done": bool(row[3]),
                "latest_fail_reason": row[4],
            }
            for row in mutation_rows
        ],
        "merge_activity": [
            {
                "table": row[0],
                "partition_id": row[1],
                "elapsed": row[2],
                "progress": row[3],
                "num_parts": row[4],
                "total_size_bytes_compressed": row[5],
            }
            for row in merge_rows
        ],
        "events_buffer": events_buffer,
        "skip_indexes": [
            {"name": row[0], "expr": row[1], "type": row[2], "granularity": row[3]}
            for row in search_index_rows
        ],
        "representative_cases": [
            {"case_partition": str(row[0]), "rows": int(row[1]), "bytes": int(row[2])}
            for row in representative_cases
        ],
    }


def _explain_query_shapes(case_id: int) -> Dict[str, str]:
    return {
        "normal_term_hunt": "SELECT count() FROM events WHERE case_id = {case_id:UInt32} AND lower(search_blob) LIKE {term:String}",
        "ioc_token_search": "SELECT count() FROM events WHERE case_id = {case_id:UInt32} AND hasToken(search_blob, {token:String})",
        "ioc_substring_search": "SELECT count() FROM events WHERE case_id = {case_id:UInt32} AND positionCaseInsensitive(search_blob, {substring:String}) > 0",
        "event_id_filter": "SELECT count() FROM events WHERE case_id = {case_id:UInt32} AND event_id = {event_id:String}",
        "timestamp_range": "SELECT count() FROM events WHERE case_id = {case_id:UInt32} AND timestamp_utc >= {start:DateTime64(3)} AND timestamp_utc < {end:DateTime64(3)}",
        "source_host": "SELECT count() FROM events WHERE case_id = {case_id:UInt32} AND source_host = {source_host:String}",
        "username": "SELECT count() FROM events WHERE case_id = {case_id:UInt32} AND username = {username:String}",
        "process_command_line": "SELECT count() FROM events WHERE case_id = {case_id:UInt32} AND (process_name = {process_name:String} OR positionCaseInsensitive(command_line, {command:String}) > 0)",
        "combined_hunt": "SELECT count() FROM events WHERE case_id = {case_id:UInt32} AND timestamp_utc >= {start:DateTime64(3)} AND timestamp_utc < {end:DateTime64(3)} AND source_host = {source_host:String} AND event_id = {event_id:String}",
    }


def collect_explain_baseline(client: Any, case_id: int) -> Dict[str, Any]:
    anchor_rows = _query(
        client,
        """
        SELECT
            min(timestamp_utc),
            max(timestamp_utc),
            anyIf(source_host, source_host != ''),
            anyIf(username, username != ''),
            anyIf(process_name, process_name != ''),
            anyIf(command_line, command_line != ''),
            anyIf(event_id, event_id != '')
        FROM events
        WHERE case_id = {case_id:UInt32}
        """,
        {"case_id": int(case_id)},
    )
    anchor = anchor_rows[0] if anchor_rows else (None, None, "", "", "", "", "")
    params = {
        "case_id": int(case_id),
        "term": "%powershell%",
        "token": "powershell",
        "substring": "powershell",
        "event_id": str(anchor[6] or "4688"),
        "start": anchor[0],
        "end": anchor[1],
        "source_host": str(anchor[2] or ""),
        "username": str(anchor[3] or ""),
        "process_name": str(anchor[4] or "powershell.exe"),
        "command": str(anchor[5] or "powershell"),
    }
    results = {}
    for name, sql in _explain_query_shapes(case_id).items():
        explain_sql = f"EXPLAIN indexes = 1 {sql}"
        try:
            rows = _query(client, explain_sql, params)
            results[name] = {"query": sql, "explain": [row[0] for row in rows]}
        except Exception as exc:
            results[name] = {"query": sql, "error": str(exc)}
    return {"case_id": int(case_id), "parameters": {k: str(v) for k, v in params.items()}, "results": results}


def collect_duplicate_baseline(client: Any, case_id: int) -> Dict[str, Any]:
    artifacts = []
    for config in ARTIFACT_DEDUP_CONFIGS:
        non_null = build_non_null_condition(config.unique_fields)
        group_fields = ", ".join(config.unique_fields)
        params = {"case_id": int(case_id), "artifact_type": config.artifact_type}
        total = int(_single(
            client,
            "SELECT count() FROM events WHERE case_id = {case_id:UInt32} AND artifact_type = {artifact_type:String}",
            params,
            0,
        ))
        eligible = int(_single(
            client,
            f"""
            SELECT count()
            FROM events
            WHERE case_id = {{case_id:UInt32}}
              AND artifact_type = {{artifact_type:String}}
              AND {non_null}
            """,
            params,
            0,
        ))
        duplicate_groups = _query(
            client,
            f"""
            SELECT
                count() AS duplicate_groups,
                sum(rows - 1) AS duplicate_rows,
                sum(if(case_file_count = 1, rows - 1, 0)) AS same_case_file_duplicates,
                sum(if(case_file_count > 1, rows - 1, 0)) AS cross_case_file_duplicates,
                sum(if(erk_count = 1, rows - 1, 0)) AS same_erk_duplicates,
                sum(if(erk_count > 1, rows - 1, 0)) AS different_erk_duplicates
            FROM (
                SELECT
                    {group_fields},
                    count() AS rows,
                    uniqExact(case_file_id) AS case_file_count,
                    uniqExact(evidence_record_key) AS erk_count
                FROM events
                WHERE case_id = {{case_id:UInt32}}
                  AND artifact_type = {{artifact_type:String}}
                  AND {non_null}
                GROUP BY {group_fields}
                HAVING rows > 1
            )
            """,
            params,
        )
        row = duplicate_groups[0] if duplicate_groups else (0, 0, 0, 0, 0, 0)
        artifacts.append({
            "artifact_type": config.artifact_type,
            "unique_fields": config.unique_fields,
            "event_count": total,
            "currently_dedup_eligible_count": eligible,
            "duplicate_group_count": int(row[0] or 0),
            "duplicate_count_under_legacy_semantics": int(row[1] or 0),
            "duplicates_within_same_case_file": int(row[2] or 0),
            "duplicates_across_case_files": int(row[3] or 0),
            "same_erk_duplicates": int(row[4] or 0),
            "different_erk_duplicates": int(row[5] or 0),
            "source_generation_metrics": "NOT CURRENTLY MEASURABLE",
            "skipped_by_current_auto_dedup_threshold": (
                config.artifact_type in SKIP_AUTO_DEDUP_TYPES
                or (AUTO_DEDUP_MAX_ELIGIBLE_EVENTS and eligible > AUTO_DEDUP_MAX_ELIGIBLE_EVENTS)
            ),
        })
    return {"case_id": int(case_id), "artifacts": artifacts}


def _write_json(path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, default=str) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case-id", type=int, help="representative case id for EXPLAIN/duplicate diagnostics")
    parser.add_argument("--output-dir", default="docs/database_flow_phase0", help="directory for JSON output")
    parser.add_argument("--skip-explain", action="store_true", help="skip EXPLAIN indexes diagnostics")
    parser.add_argument("--skip-duplicates", action="store_true", help="skip duplicate diagnostics")
    args = parser.parse_args()

    client = get_fresh_client()
    output_dir = Path(args.output_dir)
    baseline = collect_clickhouse_baseline(client)
    _write_json(output_dir / "clickhouse_storage_baseline.json", baseline)

    if args.case_id and not args.skip_explain:
        _write_json(output_dir / "clickhouse_query_explain_baseline.json", collect_explain_baseline(client, args.case_id))
    if args.case_id and not args.skip_duplicates:
        _write_json(output_dir / "duplicate_baseline.json", collect_duplicate_baseline(client, args.case_id))

    print(json.dumps({"success": True, "output_dir": str(output_dir), "case_id": args.case_id}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
