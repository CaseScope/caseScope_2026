"""Phase 2.1A search_blob text-index coverage and partition materialization.

ClickHouse 26.7.3.19 stores a materialized ``idx_search_blob_text`` as part
files named ``skp_idx_idx_search_blob_text.*``. Table-level
``system.data_skipping_indices.data_compressed_bytes`` is not partition-scoped.
``EXPLAIN indexes = 1`` shows a scan filter only while *every* queried part is
unmaterialized; after any partition is materialized, EXPLAIN can emit the
``__text_index_idx_search_blob_text_*`` filter even for still-unmaterialized
partitions. Coverage therefore uses per-part files, not EXPLAIN or total
index bytes.

Proven partition-scoped DDL on this server:

    ALTER TABLE events MATERIALIZE INDEX idx_search_blob_text IN PARTITION <case_id>
    SETTINGS mutations_sync = 1
"""
from __future__ import annotations

import hashlib
import os
import re
import subprocess
import time
from typing import Any, Callable, Dict, Iterable, Optional, Sequence

from migrations.add_events_block_number_offset import events_has_block_columns_enabled
from migrations.add_events_search_blob_text_index import (
    BLOOM_INDEX_NAMES,
    INDEX_NAME,
    PRODUCTION_DATABASE_NAMES,
    IncompatibleSearchBlobTextIndex,
    _current_database_name,
    _engine_full,
    _exclude_list,
    _exclude_merge_value,
    _index_by_name,
    _skipping_indices,
    _table_exists,
    search_blob_text_index_is_compatible,
)


PROTOCOL_COLUMNS = (
    "source_ref_type",
    "source_ref_id",
    "source_generation",
    "ingest_batch_id",
    "ingest_row_ordinal",
    "ingest_row_hash",
    "ingest_attempt_id",
)
CONTROL_TABLES = ("visible_evidence_generations", "durable_ingest_batches")
EXCLUDE_MERGE_SETTING = "exclude_materialize_skip_indexes_on_merge"
TEXT_INDEX_FILE_PREFIX = f"skp_idx_{INDEX_NAME}."
TEXT_INDEX_SENTINEL_FILE = f"skp_idx_{INDEX_NAME}.idx"
COVERAGE_MATERIALIZED = "MATERIALIZED"
COVERAGE_PARTIAL = "PARTIAL"
COVERAGE_UNMATERIALIZED = "UNMATERIALIZED"
COVERAGE_UNKNOWN = "UNKNOWN"
CLICKHOUSE_STORE_PREFIXES = ("/var/lib/clickhouse/store/",)
FORBIDDEN_SQL_TOKENS = (
    "OPTIMIZE",
    " DROP INDEX",
    "CLEAR INDEX",
    "ALTER TABLE events UPDATE",
    "UPDATE events",
    "DELETE FROM",
    "ALTER UPDATE",
)


class TextIndexOperatorError(RuntimeError):
    """Fail-closed operator error."""


class ConflictingMutationError(TextIndexOperatorError):
    """An in-progress events mutation blocks partition materialization."""


class DeployedSchemaDrift(TextIndexOperatorError):
    """Phase 1B / Gate B production schema prerequisites are missing."""


PartFileLister = Callable[[str], Sequence[str]]


def sql_table_name(table_name):
    name = str(table_name or "")
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
        raise TextIndexOperatorError(f"Invalid table name {table_name!r}")
    return name


def _query_rows(client, sql, parameters=None):
    result = client.query(sql, parameters=parameters or {})
    return [dict(zip(result.column_names, row)) for row in result.result_rows]


def current_database_name(client):
    return _current_database_name(client)


def is_production_database(client):
    return current_database_name(client) in PRODUCTION_DATABASE_NAMES


def require_non_production_or_ack(client, *, allow_production):
    if is_production_database(client) and not allow_production:
        raise TextIndexOperatorError(
            f"Refusing production database {current_database_name(client)!r} "
            "without --apply-production"
        )


def skipping_indices(client, table_name="events"):
    return _skipping_indices(client, table_name)


def require_compatible_text_index(client, table_name="events"):
    index = _index_by_name(skipping_indices(client, table_name), INDEX_NAME)
    if index is None:
        raise TextIndexOperatorError(
            f"{table_name}.{INDEX_NAME} is missing; ADD INDEX before materializing"
        )
    if not search_blob_text_index_is_compatible(index):
        raise IncompatibleSearchBlobTextIndex(
            f"{table_name}.{INDEX_NAME} has incompatible type "
            f"{index.get('type_full')!r} expr {index.get('expr')!r}"
        )
    return index


def require_bloom_indexes(client, table_name="events"):
    present = {
        item["name"]
        for item in skipping_indices(client, table_name)
        if item["name"] in BLOOM_INDEX_NAMES
    }
    missing = [name for name in BLOOM_INDEX_NAMES if name not in present]
    if missing:
        raise TextIndexOperatorError(
            f"{table_name} is missing required bloom index(es): {missing}"
        )
    return tuple(BLOOM_INDEX_NAMES)


def require_exclude_from_merge(client, table_name="events"):
    excluded = _exclude_list(_exclude_merge_value(_engine_full(client, table_name)))
    if INDEX_NAME not in excluded:
        raise TextIndexOperatorError(
            f"{table_name} {EXCLUDE_MERGE_SETTING} does not contain {INDEX_NAME}: {excluded}"
        )
    return excluded


def inspect_schema_preconditions(client, table_name="events"):
    database = current_database_name(client)
    missing_columns = []
    if _table_exists(client, table_name):
        present = {
            row["name"]
            for row in _query_rows(
                client,
                """
                SELECT name
                FROM system.columns
                WHERE database = currentDatabase() AND table = {table_name:String}
                """,
                {"table_name": table_name},
            )
        }
        missing_columns = [name for name in PROTOCOL_COLUMNS if name not in present]
    else:
        missing_columns = list(PROTOCOL_COLUMNS)
    present_tables = {
        row["name"]
        for row in _query_rows(
            client,
            """
            SELECT name
            FROM system.tables
            WHERE database = currentDatabase()
              AND name IN {names:Array(String)}
            """,
            {"names": list(CONTROL_TABLES)},
        )
    }
    missing_tables = [name for name in CONTROL_TABLES if name not in present_tables]
    engine_full = _engine_full(client, table_name) if _table_exists(client, table_name) else ""
    block_ok = events_has_block_columns_enabled(engine_full)
    ok = not missing_columns and not missing_tables and block_ok
    return {
        "database": database,
        "table": table_name,
        "ok": ok,
        "missing_protocol_columns": missing_columns,
        "missing_control_tables": missing_tables,
        "block_columns_enabled": block_ok,
        "engine_full": engine_full,
    }


def require_schema_preconditions(client, table_name="events"):
    inspection = inspect_schema_preconditions(client, table_name)
    if not inspection["ok"]:
        raise DeployedSchemaDrift(
            "PHASE2_1A_DEPLOYED_SCHEMA_DRIFT: "
            f"missing_columns={inspection['missing_protocol_columns']} "
            f"missing_tables={inspection['missing_control_tables']} "
            f"block_columns_enabled={inspection['block_columns_enabled']}"
        )
    return inspection


def validated_part_path(path):
    text = os.path.abspath(str(path or ""))
    if not text.endswith(os.sep):
        text = text + os.sep
    if ".." in text.split(os.sep):
        raise TextIndexOperatorError(f"Refusing part path with ..: {path!r}")
    if not text.startswith(CLICKHOUSE_STORE_PREFIXES):
        raise TextIndexOperatorError(f"Part path is outside ClickHouse store: {path!r}")
    return text


def _sudo_ls(path):
    proc = subprocess.run(
        ["sudo", "-n", "/bin/ls", "-1", "--", path],
        check=False,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        raise TextIndexOperatorError(
            f"Unable to list part files at {path}: {(proc.stderr or proc.stdout or '').strip()}"
        )
    return [line for line in proc.stdout.splitlines() if line]


def list_part_files(path, lister: Optional[PartFileLister] = None):
    validated = validated_part_path(path)
    if lister is not None:
        return list(lister(validated))
    try:
        return sorted(os.listdir(validated))
    except OSError:
        return _sudo_ls(validated)


def part_has_text_index_files(filenames: Iterable[str]):
    names = [str(name) for name in filenames]
    prefixed = [name for name in names if name.startswith(TEXT_INDEX_FILE_PREFIX)]
    return TEXT_INDEX_SENTINEL_FILE in names and bool(prefixed)


def classify_part_files(filenames: Optional[Sequence[str]], *, listed: bool):
    if not listed or filenames is None:
        return COVERAGE_UNKNOWN
    return COVERAGE_MATERIALIZED if part_has_text_index_files(filenames) else COVERAGE_UNMATERIALIZED


def classify_partition_statuses(part_statuses: Sequence[str]):
    unique = {status for status in part_statuses}
    if not unique:
        return COVERAGE_UNKNOWN
    if unique == {COVERAGE_MATERIALIZED}:
        return COVERAGE_MATERIALIZED
    if unique == {COVERAGE_UNMATERIALIZED}:
        return COVERAGE_UNMATERIALIZED
    if unique <= {COVERAGE_MATERIALIZED, COVERAGE_UNMATERIALIZED}:
        return COVERAGE_PARTIAL
    return COVERAGE_UNKNOWN


def active_parts(client, table_name="events", case_id=None):
    sql = """
        SELECT
            partition,
            partition_id,
            name,
            min_block_number,
            max_block_number,
            rows,
            bytes_on_disk,
            data_compressed_bytes,
            data_uncompressed_bytes,
            secondary_indices_compressed_bytes,
            files,
            hash_of_all_files,
            hash_of_uncompressed_files,
            data_version,
            path,
            active
        FROM system.parts
        WHERE database = currentDatabase()
          AND table = {table_name:String}
          AND active
    """
    parameters = {"table_name": table_name}
    if case_id is not None:
        sql += " AND partition = {partition:String}"
        parameters["partition"] = str(int(case_id))
    sql += " ORDER BY partition, name"
    return _query_rows(client, sql, parameters)


def partition_inventory(client, table_name="events"):
    return _query_rows(
        client,
        """
        SELECT
            partition,
            partition_id,
            count() AS parts,
            sum(rows) AS rows,
            sum(bytes_on_disk) AS compressed_bytes,
            sum(data_uncompressed_bytes) AS uncompressed_bytes,
            sum(secondary_indices_compressed_bytes) AS secondary_indices_compressed_bytes
        FROM system.parts
        WHERE database = currentDatabase() AND table = {table_name:String} AND active
        GROUP BY partition, partition_id
        ORDER BY rows ASC
        """,
        {"table_name": table_name},
    )


def table_parts_summary(client, table_name="events"):
    rows = _query_rows(
        client,
        """
        SELECT
            count() AS active_parts,
            uniqExact(partition) AS partitions,
            sum(rows) AS rows,
            sum(bytes_on_disk) AS compressed_bytes,
            sum(data_uncompressed_bytes) AS uncompressed_bytes,
            sum(secondary_indices_compressed_bytes) AS secondary_indices_compressed_bytes
        FROM system.parts
        WHERE database = currentDatabase() AND table = {table_name:String} AND active
        """,
        {"table_name": table_name},
    )
    return rows[0] if rows else {}


def inspect_part_coverage(part, lister: Optional[PartFileLister] = None):
    listed = False
    filenames = None
    error = None
    try:
        filenames = list(list_part_files(part["path"], lister=lister))
        listed = True
    except Exception as exc:
        error = str(exc)
    status = classify_part_files(filenames, listed=listed)
    text_files = [
        name for name in (filenames or []) if str(name).startswith(TEXT_INDEX_FILE_PREFIX)
    ]
    return {
        "partition": str(part.get("partition")),
        "name": part.get("name"),
        "rows": int(part.get("rows") or 0),
        "bytes_on_disk": int(part.get("bytes_on_disk") or 0),
        "secondary_indices_compressed_bytes": int(
            part.get("secondary_indices_compressed_bytes") or 0
        ),
        "files": part.get("files"),
        "hash_of_all_files": part.get("hash_of_all_files"),
        "path": part.get("path"),
        "coverage": status,
        "text_index_files": text_files,
        "list_error": error,
    }


def inspect_partition_coverage(
    client,
    case_id,
    table_name="events",
    lister: Optional[PartFileLister] = None,
):
    parts = active_parts(client, table_name=table_name, case_id=case_id)
    inspected = [inspect_part_coverage(part, lister=lister) for part in parts]
    coverage = classify_partition_statuses([item["coverage"] for item in inspected])
    return {
        "case_id": int(case_id),
        "partition": str(int(case_id)),
        "coverage": coverage,
        "parts": inspected,
        "part_count": len(inspected),
        "rows": sum(item["rows"] for item in inspected),
        "compressed_bytes": sum(item["bytes_on_disk"] for item in inspected),
        "text_index_file_bytes_hint": sum(len(item["text_index_files"]) for item in inspected),
    }


def inspect_all_partition_coverage(
    client,
    table_name="events",
    lister: Optional[PartFileLister] = None,
):
    inventory = partition_inventory(client, table_name=table_name)
    reports = []
    for item in inventory:
        reports.append(
            inspect_partition_coverage(
                client,
                int(item["partition"]),
                table_name=table_name,
                lister=lister,
            )
        )
    return reports


def active_mutations(client, table_name="events"):
    return _query_rows(
        client,
        """
        SELECT
            mutation_id,
            command,
            create_time,
            is_done,
            latest_failed_part,
            latest_fail_reason,
            parts_to_do
        FROM system.mutations
        WHERE database = currentDatabase()
          AND table = {table_name:String}
          AND is_done = 0
        ORDER BY create_time
        """,
        {"table_name": table_name},
    )


def recent_failed_mutations(client, table_name="events", limit=20):
    return _query_rows(
        client,
        """
        SELECT mutation_id, command, create_time, is_done, latest_fail_reason
        FROM system.mutations
        WHERE database = currentDatabase()
          AND table = {table_name:String}
          AND latest_fail_reason != ''
        ORDER BY create_time DESC
        LIMIT {limit:UInt32}
        """,
        {"table_name": table_name, "limit": int(limit)},
    )


def require_no_conflicting_mutations(client, table_name="events"):
    current = active_mutations(client, table_name=table_name)
    if current:
        raise ConflictingMutationError(
            f"{table_name} has {len(current)} in-progress mutation(s): "
            + ", ".join(item["mutation_id"] for item in current)
        )
    return current


def partition_materialize_sql(case_id, table_name="events"):
    case_id = int(case_id)
    if case_id < 0:
        raise TextIndexOperatorError(f"Invalid case_id {case_id}")
    table_name = sql_table_name(table_name)
    sql = (
        f"ALTER TABLE {table_name} MATERIALIZE INDEX {INDEX_NAME} "
        f"IN PARTITION {case_id} SETTINGS mutations_sync = 1"
    )
    upper = f" {sql.upper()} "
    for token in FORBIDDEN_SQL_TOKENS:
        if token in upper:
            raise TextIndexOperatorError(f"Generated SQL contained forbidden token {token!r}")
    if "MATERIALIZE INDEX" not in sql or "IN PARTITION" not in sql:
        raise TextIndexOperatorError("Generated SQL is not partition-scoped MATERIALIZE INDEX")
    return sql


def explain_has_all_tokens(client, case_id, term="powershell", table_name="events"):
    table_name = sql_table_name(table_name)
    sql = (
        f"SELECT count() FROM {table_name} "
        f"WHERE case_id = {int(case_id)} AND hasAllTokens(search_blob, {{term:String}})"
    )
    recs = _query_rows(client, f"EXPLAIN indexes = 1 {sql}", {"term": term})
    if not recs:
        return ""
    key = list(recs[0].keys())[0]
    return "\n".join(str(item[key]) for item in recs)


def explain_uses_text_index_direct_read(explain_text):
    text = str(explain_text or "")
    return f"__text_index_{INDEX_NAME}_" in text


def explain_uses_token_scan(explain_text):
    text = str(explain_text or "")
    return "hasAllTokens(lower(search_blob)" in text


def partition_value_fingerprint(client, case_id, table_name="events"):
    table_name = sql_table_name(table_name)
    summary = _query_rows(
        client,
        f"""
        SELECT
            count() AS rows,
            sum(cityHash64(evidence_record_key)) AS erk_hash,
            sum(cityHash64(search_blob)) AS search_blob_hash,
            countIf(
                isNotNull(source_ref_type)
                OR isNotNull(source_ref_id)
                OR isNotNull(source_generation)
                OR isNotNull(ingest_batch_id)
                OR isNotNull(ingest_row_ordinal)
                OR isNotNull(ingest_row_hash)
                OR isNotNull(ingest_attempt_id)
            ) AS protocol_identity_nonnull
        FROM {table_name}
        WHERE case_id = {{case_id:UInt32}}
        """,
        {"case_id": int(case_id)},
    )[0]
    samples = _query_rows(
        client,
        f"""
        SELECT
            evidence_record_key,
            cityHash64(search_blob) AS search_blob_hash,
            length(search_blob) AS search_blob_len
        FROM {table_name}
        WHERE case_id = {{case_id:UInt32}}
        ORDER BY evidence_record_key
        LIMIT 25
        """,
        {"case_id": int(case_id)},
    )
    return {
        "case_id": int(case_id),
        "rows": int(summary["rows"] or 0),
        "erk_hash": str(summary["erk_hash"]),
        "search_blob_hash": str(summary["search_blob_hash"]),
        "protocol_identity_nonnull": int(summary["protocol_identity_nonnull"] or 0),
        "samples": samples,
    }


def other_partition_part_map(client, case_id, table_name="events"):
    mapping = {}
    for part in active_parts(client, table_name=table_name):
        if str(part["partition"]) == str(int(case_id)):
            continue
        key = f"{part['partition']}:{int(part['min_block_number'])}:{int(part['max_block_number'])}"
        mapping[key] = {
            "partition": str(part["partition"]),
            "rows": int(part["rows"] or 0),
            "bytes_on_disk": int(part["bytes_on_disk"] or 0),
            "hash_of_all_files": part.get("hash_of_all_files"),
            "hash_of_uncompressed_files": part.get("hash_of_uncompressed_files"),
            "secondary_indices_compressed_bytes": int(
                part.get("secondary_indices_compressed_bytes") or 0
            ),
            "files": part.get("files"),
        }
    return mapping


def compare_other_partitions(before, after):
    unchanged = before == after
    only_before = sorted(set(before) - set(after))
    only_after = sorted(set(after) - set(before))
    changed = []
    for name in sorted(set(before) & set(after)):
        if before[name] != after[name]:
            changed.append({"name": name, "before": before[name], "after": after[name]})
    return {
        "unchanged": unchanged and not only_before and not only_after,
        "only_before": only_before,
        "only_after": only_after,
        "changed": changed,
    }


def wait_for_named_mutation(client, mutation_id, table_name="events", timeout_seconds=86400):
    deadline = time.time() + float(timeout_seconds)
    while True:
        rows = _query_rows(
            client,
            """
            SELECT mutation_id, is_done, latest_fail_reason, parts_to_do, command
            FROM system.mutations
            WHERE database = currentDatabase()
              AND table = {table_name:String}
              AND mutation_id = {mutation_id:String}
            """,
            {"table_name": table_name, "mutation_id": mutation_id},
        )
        if not rows:
            return {"mutation_id": mutation_id, "missing": True}
        row = rows[0]
        if row.get("latest_fail_reason"):
            raise TextIndexOperatorError(
                f"Mutation {mutation_id} failed: {row['latest_fail_reason']}"
            )
        if int(row.get("is_done") or 0) == 1:
            return row
        if time.time() >= deadline:
            raise TextIndexOperatorError(f"Timed out waiting for mutation {mutation_id}")
        time.sleep(0.25)


def _latest_materialize_mutation(client, case_id, table_name="events"):
    needle = f"MATERIALIZE INDEX {INDEX_NAME} IN PARTITION {int(case_id)}"
    rows = _query_rows(
        client,
        """
        SELECT mutation_id, command, is_done, latest_fail_reason, create_time, parts_to_do
        FROM system.mutations
        WHERE database = currentDatabase() AND table = {table_name:String}
        ORDER BY create_time DESC
        LIMIT 20
        """,
        {"table_name": table_name},
    )
    for row in rows:
        if needle in str(row.get("command") or ""):
            return row
    return None


def capture_resource_sample():
    sample = {
        "loadavg": None,
        "clickhouse_memory_tracking": None,
        "memory": None,
        "disk": None,
    }
    try:
        sample["loadavg"] = os.getloadavg()
    except OSError:
        pass
    try:
        mem = {}
        with open("/proc/meminfo", encoding="utf-8") as handle:
            for line in handle:
                if ":" not in line:
                    continue
                key, value = line.split(":", 1)
                parts = value.strip().split()
                if parts and key in ("MemTotal", "MemFree", "MemAvailable", "Buffers", "Cached"):
                    mem[key] = int(parts[0]) * 1024
        sample["memory"] = mem
    except OSError:
        pass
    try:
        usage = os.statvfs("/var/lib/clickhouse")
        sample["disk"] = {
            "path": "/var/lib/clickhouse",
            "total_bytes": usage.f_frsize * usage.f_blocks,
            "free_bytes": usage.f_frsize * usage.f_bavail,
            "used_bytes": usage.f_frsize * (usage.f_blocks - usage.f_bfree),
        }
    except OSError:
        pass
    return sample


def materialize_case_partition(
    client,
    case_id,
    *,
    allow_production=False,
    dry_run=False,
    table_name="events",
    lister: Optional[PartFileLister] = None,
    require_writers_idle: Optional[Callable[[], Dict[str, Any]]] = None,
):
    """Materialize idx_search_blob_text for exactly one case_id partition."""
    case_id = int(case_id)
    require_non_production_or_ack(client, allow_production=allow_production)
    schema = require_schema_preconditions(client, table_name=table_name)
    text_index = require_compatible_text_index(client, table_name=table_name)
    blooms = require_bloom_indexes(client, table_name=table_name)
    excluded = require_exclude_from_merge(client, table_name=table_name)
    idle = require_writers_idle() if require_writers_idle is not None else None
    mutations_before = require_no_conflicting_mutations(client, table_name=table_name)
    coverage_before = inspect_partition_coverage(
        client, case_id, table_name=table_name, lister=lister
    )
    if coverage_before["part_count"] == 0:
        raise TextIndexOperatorError(f"No active parts for case_id={case_id}")
    sql = partition_materialize_sql(case_id, table_name=table_name)
    result = {
        "database": current_database_name(client),
        "table": table_name,
        "case_id": case_id,
        "sql": sql,
        "dry_run": bool(dry_run),
        "already_materialized": coverage_before["coverage"] == COVERAGE_MATERIALIZED,
        "schema": schema,
        "text_index": text_index,
        "bloom_indexes": list(blooms),
        "exclude_from_merge": excluded,
        "idle": idle,
        "mutations_before": mutations_before,
        "coverage_before": coverage_before,
        "pre_fingerprint": None,
        "other_partitions_before": None,
        "started_at": None,
        "finished_at": None,
        "elapsed_seconds": None,
        "mutation": None,
        "resource_before": capture_resource_sample(),
        "resource_after": None,
        "coverage_after": None,
        "post_fingerprint": None,
        "other_partitions_after": None,
        "other_partitions_unchanged": None,
        "rows_unchanged": None,
        "values_unchanged": None,
        "protocol_identity_unchanged": None,
        "executed": False,
        "skipped": False,
    }
    if dry_run:
        result["skipped"] = True
        return result
    if coverage_before["coverage"] == COVERAGE_UNKNOWN:
        raise TextIndexOperatorError(
            f"Coverage UNKNOWN for case_id={case_id}; refusing automatic materialize"
        )
    result["pre_fingerprint"] = partition_value_fingerprint(
        client, case_id, table_name=table_name
    )
    result["other_partitions_before"] = other_partition_part_map(
        client, case_id, table_name=table_name
    )
    if coverage_before["coverage"] == COVERAGE_MATERIALIZED:
        result["skipped"] = True
        result["already_materialized"] = True
        result["coverage_after"] = coverage_before
        result["post_fingerprint"] = result["pre_fingerprint"]
        result["other_partitions_after"] = result["other_partitions_before"]
        result["other_partitions_unchanged"] = compare_other_partitions(
            result["other_partitions_before"], result["other_partitions_after"]
        )
        result["rows_unchanged"] = True
        result["values_unchanged"] = True
        result["protocol_identity_unchanged"] = True
        result["resource_after"] = capture_resource_sample()
        return result

    started = time.time()
    result["started_at"] = started
    client.command(sql)
    result["executed"] = True
    mutation = _latest_materialize_mutation(client, case_id, table_name=table_name)
    if mutation and int(mutation.get("is_done") or 0) != 1:
        mutation = wait_for_named_mutation(
            client, mutation["mutation_id"], table_name=table_name
        )
    result["mutation"] = mutation
    finished = time.time()
    result["finished_at"] = finished
    result["elapsed_seconds"] = finished - started
    result["resource_after"] = capture_resource_sample()
    require_no_conflicting_mutations(client, table_name=table_name)
    coverage_after = inspect_partition_coverage(
        client, case_id, table_name=table_name, lister=lister
    )
    result["coverage_after"] = coverage_after
    if coverage_after["coverage"] != COVERAGE_MATERIALIZED:
        raise TextIndexOperatorError(
            f"case_id={case_id} coverage after materialize is "
            f"{coverage_after['coverage']}, expected MATERIALIZED"
        )
    post = partition_value_fingerprint(client, case_id, table_name=table_name)
    result["post_fingerprint"] = post
    result["rows_unchanged"] = post["rows"] == result["pre_fingerprint"]["rows"]
    result["values_unchanged"] = (
        post["erk_hash"] == result["pre_fingerprint"]["erk_hash"]
        and post["search_blob_hash"] == result["pre_fingerprint"]["search_blob_hash"]
        and post["samples"] == result["pre_fingerprint"]["samples"]
    )
    result["protocol_identity_unchanged"] = (
        post["protocol_identity_nonnull"]
        == result["pre_fingerprint"]["protocol_identity_nonnull"]
    )
    result["other_partitions_after"] = other_partition_part_map(
        client, case_id, table_name=table_name
    )
    result["other_partitions_unchanged"] = compare_other_partitions(
        result["other_partitions_before"], result["other_partitions_after"]
    )
    if not result["rows_unchanged"]:
        raise TextIndexOperatorError(
            f"Row count changed for case_id={case_id}: "
            f"{result['pre_fingerprint']['rows']} -> {post['rows']}"
        )
    if not result["values_unchanged"]:
        raise TextIndexOperatorError(
            f"Retained event values changed for case_id={case_id}"
        )
    if not result["protocol_identity_unchanged"]:
        raise TextIndexOperatorError(
            f"Protocol identity non-null count changed for case_id={case_id}"
        )
    if not result["other_partitions_unchanged"]["unchanged"]:
        raise TextIndexOperatorError(
            f"Unexpected other-partition change while materializing case_id={case_id}: "
            f"{result['other_partitions_unchanged']}"
        )
    require_bloom_indexes(client, table_name=table_name)
    require_compatible_text_index(client, table_name=table_name)
    return result


def stable_json_hash(payload):
    encoded = repr(payload).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()
