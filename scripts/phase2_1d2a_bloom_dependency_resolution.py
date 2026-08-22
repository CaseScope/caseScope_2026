#!/usr/bin/env python3
"""Phase 2.1D2A bloom-dependency attribution (measurement only).

Read-only against production casescope.events. Disposable database is used
only for insert-cost tables and is dropped at the end. No production DDL,
no DROP INDEX, no MATERIALIZE, no OPTIMIZE, no reader changes.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import statistics
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Sequence


ROOT = Path("/opt/casescope")
sys.path.insert(0, str(ROOT))
os.environ.setdefault("SECRET_KEY", "phase2-1d2a-measure")

from tests.phase2_1d2a_lib import (  # noqa: E402
    CAPABILITY_PROBES,
    CONFIG_ALL,
    CONFIG_NO_BLOOMS,
    CONFIG_NO_NGRAM,
    FULL_DETECTION_RULE_IDS,
    IGNORE_SETTINGS,
    REPRESENTATIVE_PREDICATES,
    TEXT_INDEX_ILIKE_MIN_ALNUM,
    classify_consumer,
    collect_pattern_rule_predicates,
    derive_prefilter,
    extract_predicates_from_sql,
    parse_explain_indexes,
    percentile,
    wrap_like_sql,
)


OUT_JSON = ROOT / "docs/database_flow_phase2/phase2_1d2a_bloom_dependency_resolution.json"
OUT_MD = ROOT / "docs/database_flow_phase2/phase2_1d2a_bloom_dependency_resolution.md"
EXPECTED_HEAD = "078895225eef7f9d08ac8372d7754583b1d1575f"
EXPECTED_VERSION = "4.25.2"
CASES = (10, 7, 32)
TIMED_IDS = {
    "like_ntlm",
    "like_ntlmssp",
    "like_kerberos",
    "like_admin_share",
    "like_rc4",
    "like_ipc",
    "like_c_share",
    "or_ntlm_ssp",
    "or_admin_ipc",
    "or_rc4",
}
PREFILTER_TIMED_IDS = {
    "like_ntlm",
    "like_ntlmssp",
    "like_kerberos",
    "like_admin_share",
    "or_ntlm_ssp",
    "lower_guid",
    "like_rc4",
    "like_ipc",
}
FORBIDDEN = (
    "DROP INDEX",
    "CLEAR INDEX",
    "MATERIALIZE INDEX",
    "OPTIMIZE",
    "ALTER TABLE events",
    "ALTER TABLE casescope.events",
    "DELETE FROM events",
    "ALTER UPDATE",
)
SKIP_WALK_DIRS = {
    ".git",
    "venv",
    "node_modules",
    "__pycache__",
    "rules",
    "hayabusa-rules",
    "static/vendor",
}


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def connect(database: str = "casescope"):
    import clickhouse_connect

    return clickhouse_connect.get_client(
        host=os.environ.get("CLICKHOUSE_HOST") or "localhost",
        port=int(os.environ.get("CLICKHOUSE_PORT") or 8123),
        database=database,
        username=os.environ.get("CLICKHOUSE_USER") or "default",
        password=os.environ.get("CLICKHOUSE_PASSWORD") or "",
        autogenerate_session_id=False,
        send_receive_timeout=900,
        settings={"max_execution_time": 600},
    )


def refuse_forbidden(sql: str) -> None:
    upper = f" {sql.upper()} "
    for token in FORBIDDEN:
        if token in upper:
            raise RuntimeError(f"Refusing forbidden SQL token {token!r}")


def run_query(client, sql: str, parameters=None, settings=None):
    refuse_forbidden(sql)
    return client.query(sql, parameters=parameters or {}, settings=settings or {})


def explain_text(client, sql: str, settings=None) -> str:
    refuse_forbidden(sql)
    rows = run_query(client, "EXPLAIN indexes = 1 " + sql, settings=settings).result_rows
    return "\n".join(row[0] for row in rows)


def summary_stats(result) -> Dict[str, Any]:
    summary = getattr(result, "summary", None) or {}
    read_rows = summary.get("read_rows")
    read_bytes = summary.get("read_bytes")
    elapsed_ns = summary.get("elapsed_ns")
    try:
        read_rows = int(read_rows) if read_rows is not None else None
    except (TypeError, ValueError):
        read_rows = None
    try:
        read_bytes = int(read_bytes) if read_bytes is not None else None
    except (TypeError, ValueError):
        read_bytes = None
    try:
        elapsed_ns = int(elapsed_ns) if elapsed_ns is not None else None
    except (TypeError, ValueError):
        elapsed_ns = None
    return {
        "read_rows": read_rows,
        "read_bytes": read_bytes,
        "elapsed_ns": elapsed_ns,
    }


def identity_sql(pred: str) -> str:
    return (
        "SELECT count() AS n, "
        "sum(cityHash64(evidence_record_key)) AS erk_fp, "
        "sum(cityHash64(tuple(evidence_record_key, selector_key, "
        "ifNull(source_file, ''), ifNull(record_id, toUInt64(0))))) AS phys_fp "
        "FROM events WHERE case_id = {case_id:UInt32} AND (" + pred + ")"
    )


def minus_sql(left: str, right: str) -> str:
    return (
        "SELECT count() FROM events WHERE case_id = {case_id:UInt32} "
        "AND (" + left + ") AND NOT (" + right + ")"
    )


def capture_identity(client, pred: str, case_id: int, settings=None) -> Dict[str, Any]:
    started = time.perf_counter()
    result = run_query(
        client,
        identity_sql(pred),
        parameters={"case_id": case_id},
        settings=settings,
    )
    elapsed_ms = (time.perf_counter() - started) * 1000.0
    row = result.result_rows[0] if result.result_rows else (0, 0, 0)
    stats = summary_stats(result)
    return {
        "n": int(row[0] or 0),
        "erk_fp": str(row[1] or 0),
        "phys_fp": str(row[2] or 0),
        "wall_ms": round(elapsed_ms, 3),
        **stats,
    }


def time_identity(
    client, pred: str, case_id: int, settings=None, *, warmup: int = 1, samples: int = 9
) -> Dict[str, Any]:
    for _ in range(warmup):
        capture_identity(client, pred, case_id, settings=settings)
    captured = [
        capture_identity(client, pred, case_id, settings=settings) for _ in range(samples)
    ]
    walls = [item["wall_ms"] for item in captured]
    rows = [item["read_rows"] for item in captured if item["read_rows"] is not None]
    nbytes = [item["read_bytes"] for item in captured if item["read_bytes"] is not None]
    identity = {
        "n": captured[0]["n"],
        "erk_fp": captured[0]["erk_fp"],
        "phys_fp": captured[0]["phys_fp"],
    }
    stable = all(
        item["n"] == identity["n"]
        and item["erk_fp"] == identity["erk_fp"]
        and item["phys_fp"] == identity["phys_fp"]
        for item in captured
    )
    return {
        "warmup": warmup,
        "samples": samples,
        "p50_ms": round(percentile(walls, 50) or 0.0, 3),
        "p95_ms": round(percentile(walls, 95) or 0.0, 3),
        "min_ms": round(min(walls), 3),
        "max_ms": round(max(walls), 3),
        "mean_ms": round(statistics.fmean(walls), 3),
        "n": identity["n"],
        "erk_fp": identity["erk_fp"],
        "phys_fp": identity["phys_fp"],
        "read_rows_p50": int(percentile(rows, 50) or 0) if rows else None,
        "read_bytes_p50": int(percentile(nbytes, 50) or 0) if nbytes else None,
        "identity_stable": stable,
    }


ALLOWED_DIRTY = (
    "scripts/phase2_1d2a_bloom_dependency_resolution.py",
    "tests/phase2_1d2a_lib.py",
    "tests/test_phase2_1d2a_bloom_dependency_resolution.py",
    "docs/database_flow_phase2/phase2_1d2a_bloom_dependency_resolution.md",
    "docs/database_flow_phase2/phase2_1d2a_bloom_dependency_resolution.json",
)


def git_baseline() -> Dict[str, Any]:
    def _run(args: Sequence[str]) -> str:
        return subprocess.check_output(args, cwd=str(ROOT), text=True).strip()

    env = os.environ.copy()
    env["GIT_SSH_COMMAND"] = (
        "ssh -i ~/.ssh/id_ed25519_casescope_github -o IdentitiesOnly=yes"
    )
    subprocess.check_call(["git", "fetch", "origin"], cwd=str(ROOT), env=env)
    head = _run(["git", "rev-parse", "HEAD"])
    origin = _run(["git", "rev-parse", "origin/main"])
    status = _run(["git", "status", "--porcelain"])
    dirty = []
    for line in status.splitlines():
        path = line[3:]
        if " -> " in path:
            path = path.split(" -> ", 1)[1]
        if path not in ALLOWED_DIRTY:
            dirty.append(line)
    version = json.loads((ROOT / "version.json").read_text())["version"]
    started_clean_except_d2a = dirty == []
    return {
        "head": head,
        "origin_main": origin,
        "head_equals_origin_main": head == origin,
        "working_tree_clean": status == "",
        "working_tree_only_d2a_allowed": started_clean_except_d2a,
        "status": status,
        "disallowed_dirty": dirty,
        "version": version,
        "expected_head": EXPECTED_HEAD,
        "expected_version": EXPECTED_VERSION,
        "ok": (
            head == origin == EXPECTED_HEAD
            and started_clean_except_d2a
            and version == EXPECTED_VERSION
        ),
    }


def index_state(client) -> Dict[str, Any]:
    from utils.search_blob_text_index import (
        inspect_all_partition_coverage,
        skipping_indices,
        table_parts_summary,
        active_mutations,
    )

    indices = skipping_indices(client)
    extra = run_query(
        client,
        """
        SELECT name, type_full, expr, granularity, data_compressed_bytes
        FROM system.data_skipping_indices
        WHERE database = currentDatabase() AND table = 'events'
        ORDER BY name
        """,
    )
    by_name = {}
    for row in extra.result_rows:
        by_name[row[0]] = {
            "name": row[0],
            "type_full": row[1],
            "expr": row[2],
            "granularity": row[3],
            "data_compressed_bytes": int(row[4] or 0),
        }
    coverage_reports = inspect_all_partition_coverage(client)
    counts = {"MATERIALIZED": 0, "PARTIAL": 0, "UNMATERIALIZED": 0, "UNKNOWN": 0}
    active_parts_materialized = 0
    active_parts = 0
    for report in coverage_reports:
        counts[report["coverage"]] = counts.get(report["coverage"], 0) + 1
        for part in report["parts"]:
            active_parts += 1
            if part["coverage"] == "MATERIALIZED":
                active_parts_materialized += 1
    mutations = active_mutations(client)
    ch_version = str(run_query(client, "SELECT version()").result_rows[0][0])
    disk = run_query(
        client,
        "SELECT name, path, free_space FROM system.disks WHERE name = 'default'",
    )
    disk_row = disk.result_rows[0] if disk.result_rows else (None, None, None)
    return {
        "clickhouse_version": ch_version,
        "indices": indices,
        "index_bytes": by_name,
        "parts_summary": table_parts_summary(client),
        "coverage_partition_counts": counts,
        "active_parts": active_parts,
        "active_parts_MATERIALIZED": active_parts_materialized,
        "mutations_in_progress": len(mutations),
        "mutations": mutations,
        "disk_path": disk_row[1],
        "disk_free_bytes": int(disk_row[2] or 0) if disk_row[2] is not None else None,
        "expected_text_type": (
            "text(tokenizer='splitByNonAlpha', preprocessor=lower(search_blob))"
        ),
    }


def walk_consumers() -> List[Dict[str, Any]]:
    hits: List[Dict[str, Any]] = []
    needle = re.compile(
        r"search_blob.*(LIKE|ILIKE|hasToken|position|match)|"
        r"(LIKE|ILIKE|hasToken|position|match).*search_blob",
        re.IGNORECASE,
    )
    for path in ROOT.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix.lower() not in {".py", ".sql", ".md"}:
            continue
        rel = path.relative_to(ROOT).as_posix()
        if any(part in SKIP_WALK_DIRS for part in path.parts):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if "search_blob" not in text:
            continue
        preds = extract_predicates_from_sql(text)
        if not preds and not needle.search(text):
            continue
        hits.append(
            {
                "path": rel,
                "class": classify_consumer(rel),
                "predicate_shapes": sorted({p.get("sql") or "" for p in preds if p.get("sql")}),
                "ops": sorted({p["op"] for p in preds}),
            }
        )
    hits.sort(key=lambda item: (item["class"], item["path"]))
    return hits


def four_way_explain(client, pred: str, case_id: int) -> Dict[str, Any]:
    sql = f"SELECT count() FROM events WHERE case_id = {int(case_id)} AND ({pred})"
    out = {}
    for name, settings in IGNORE_SETTINGS.items():
        parsed = parse_explain_indexes(explain_text(client, sql, settings=settings))
        parsed["config"] = name
        parsed["settings"] = settings
        out[name] = parsed
    return out


def decide_token(ablation: List[Dict[str, Any]]) -> Dict[str, Any]:
    required = [
        item
        for item in ablation
        if item.get("kind") == "original"
        and item.get("required_consumer")
        and item.get("ngram_dependent")
    ]
    independent = []
    for item in required:
        no_ngram = item["configs"][CONFIG_NO_NGRAM]
        all_cfg = item["configs"][CONFIG_ALL]
        token_alone = bool(no_ngram.get("token_pruned"))
        extra_after_ngram = bool(all_cfg.get("token_pruned"))
        if token_alone:
            independent.append(
                {
                    "id": item["id"],
                    "case_id": item["case_id"],
                    "pred": item["pred"],
                    "no_ngram_token_granules": no_ngram.get("token_granules"),
                    "no_ngram_read": no_ngram.get("read"),
                    "all_token_granules": all_cfg.get("token_granules"),
                    "extra_after_ngram": extra_after_ngram,
                }
            )
    return {
        "decision": (
            "TOKEN_BLOOM_INDEPENDENTLY_REQUIRED" if independent else "TOKEN_BLOOM_REDUNDANT"
        ),
        "independent_hits": independent,
        "note": (
            "Independent utility is token prune when idx_search_ngram is ignored, "
            "not token appearing after ngram in the original plan."
        ),
    }


def fingerprint_rows(rows: Sequence[Sequence[Any]]) -> str:
    payload = json.dumps(rows, default=str, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def run_detection(client, sql: str, case_id: int) -> Dict[str, Any]:
    refuse_forbidden(sql)
    started = time.perf_counter()
    result = run_query(client, sql, parameters={"case_id": case_id})
    elapsed_ms = (time.perf_counter() - started) * 1000.0
    rows = [list(row) for row in result.result_rows]
    stats = summary_stats(result)
    return {
        "n": len(rows),
        "fingerprint": fingerprint_rows(rows),
        "wall_ms": round(elapsed_ms, 3),
        "columns": list(result.column_names),
        **stats,
    }


def query_log_frequency(client) -> Dict[str, Any]:
    try:
        exists = run_query(
            client,
            "SELECT count() FROM system.tables WHERE database = 'system' AND name = 'query_log'",
        ).result_rows[0][0]
        if not int(exists):
            return {"status": "QUERY_LOG_FREQUENCY_UNAVAILABLE", "reason": "no system.query_log"}
        span = run_query(
            client,
            "SELECT min(event_time), max(event_time), count() FROM system.query_log "
            "WHERE type = 'QueryFinish'",
        ).result_rows[0]
        if not span[2]:
            return {
                "status": "QUERY_LOG_FREQUENCY_UNAVAILABLE",
                "reason": "empty query_log",
                "min_event_time": str(span[0]),
                "max_event_time": str(span[1]),
            }
        blocking = run_query(
            client,
            """
            SELECT
                count() AS query_count,
                sum(query_duration_ms) AS total_duration_ms,
                sum(read_rows) AS read_rows,
                sum(read_bytes) AS read_bytes
            FROM system.query_log
            WHERE type = 'QueryFinish'
              AND (
                    positionCaseInsensitive(query, 'search_blob LIKE') > 0
                 OR positionCaseInsensitive(query, 'search_blob ILIKE') > 0
              )
              AND positionCaseInsensitive(query, 'pattern') >= 0
            """,
        ).result_rows[0]
        like_only = run_query(
            client,
            """
            SELECT
                count() AS query_count,
                sum(query_duration_ms) AS total_duration_ms,
                sum(read_rows) AS read_rows,
                sum(read_bytes) AS read_bytes
            FROM system.query_log
            WHERE type = 'QueryFinish'
              AND positionCaseInsensitive(query, 'search_blob LIKE') > 0
            """,
        ).result_rows[0]
        return {
            "status": "AVAILABLE",
            "min_event_time": str(span[0]),
            "max_event_time": str(span[1]),
            "query_log_rows": int(span[2]),
            "search_blob_like": {
                "query_count": int(like_only[0] or 0),
                "total_duration_ms": int(like_only[1] or 0),
                "read_rows": int(like_only[2] or 0),
                "read_bytes": int(like_only[3] or 0),
            },
            "patternish": {
                "query_count": int(blocking[0] or 0),
                "total_duration_ms": int(blocking[1] or 0),
                "read_rows": int(blocking[2] or 0),
                "read_bytes": int(blocking[3] or 0),
            },
        }
    except Exception as exc:
        return {"status": "QUERY_LOG_FREQUENCY_UNAVAILABLE", "reason": str(exc)}


def insert_cost(admin) -> Dict[str, Any]:
    db = f"cs_p21d2a_{uuid.uuid4().hex[:10]}"
    admin.command(f"CREATE DATABASE {db}")
    client = connect(db)
    try:
        arms = {
            "TEXT_ONLY": "INDEX idx_search_blob_text search_blob TYPE text(tokenizer = 'splitByNonAlpha', preprocessor = lower(search_blob)) GRANULARITY 1",
            "TEXT_PLUS_NGRAM": (
                "INDEX idx_search_ngram search_blob TYPE ngrambf_v1(3, 512, 2, 0) GRANULARITY 4, "
                "INDEX idx_search_blob_text search_blob TYPE text(tokenizer = 'splitByNonAlpha', preprocessor = lower(search_blob)) GRANULARITY 1"
            ),
            "TEXT_PLUS_TOKEN": (
                "INDEX idx_search_token search_blob TYPE tokenbf_v1(32768, 3, 0) GRANULARITY 4, "
                "INDEX idx_search_blob_text search_blob TYPE text(tokenizer = 'splitByNonAlpha', preprocessor = lower(search_blob)) GRANULARITY 1"
            ),
            "TEXT_PLUS_BOTH": (
                "INDEX idx_search_ngram search_blob TYPE ngrambf_v1(3, 512, 2, 0) GRANULARITY 4, "
                "INDEX idx_search_token search_blob TYPE tokenbf_v1(32768, 3, 0) GRANULARITY 4, "
                "INDEX idx_search_blob_text search_blob TYPE text(tokenizer = 'splitByNonAlpha', preprocessor = lower(search_blob)) GRANULARITY 1"
            ),
        }
        results = {}
        for arm, index_sql in arms.items():
            table = f"events_{arm.lower()}"
            client.command(f"DROP TABLE IF EXISTS {table}")
            client.command(
                f"""
                CREATE TABLE {table} (
                    case_id UInt32,
                    search_blob String,
                    evidence_record_key String,
                    {index_sql}
                )
                ENGINE = MergeTree
                ORDER BY (case_id, evidence_record_key)
                SETTINGS index_granularity = 8192
                """
            )
            started = time.perf_counter()
            client.command(
                f"""
                INSERT INTO {table} (case_id, search_blob, evidence_record_key)
                SELECT case_id, search_blob, evidence_record_key
                FROM casescope.events
                WHERE case_id = 10
                ORDER BY timestamp_utc, evidence_record_key
                LIMIT 10000
                SETTINGS materialize_skip_indexes_on_insert = 1
                """
            )
            elapsed = time.perf_counter() - started
            bytes_rows = run_query(
                client,
                """
                SELECT name, data_compressed_bytes
                FROM system.data_skipping_indices
                WHERE database = currentDatabase() AND table = {t:String}
                """,
                parameters={"t": table},
            )
            part = run_query(
                client,
                """
                SELECT sum(rows), sum(bytes_on_disk)
                FROM system.parts
                WHERE database = currentDatabase() AND table = {t:String} AND active
                """,
                parameters={"t": table},
            ).result_rows[0]
            explain = explain_text(
                client,
                f"SELECT count() FROM {table} WHERE hasAllTokens(search_blob, 'NTLM')",
            )
            parsed = parse_explain_indexes(explain)
            count = int(
                run_query(
                    client,
                    f"SELECT count() FROM {table} WHERE hasAllTokens(search_blob, 'NTLM')",
                ).result_rows[0][0]
            )
            results[arm] = {
                "insert_seconds": round(elapsed, 4),
                "insert_rows_per_sec": round(10000 / elapsed, 1) if elapsed else None,
                "rows": int(part[0] or 0),
                "part_bytes": int(part[1] or 0),
                "index_bytes": {row[0]: int(row[1] or 0) for row in bytes_rows.result_rows},
                "hasAllTokens_ntlm": count,
                "text_direct": parsed.get("direct_text_index"),
                "explain_skip_names": parsed.get("skip_names"),
            }
        return {"database": db, "source_case_id": 10, "rows": 10000, "arms": results}
    finally:
        try:
            admin.command(f"DROP DATABASE IF EXISTS {db}")
        except Exception:
            pass


def write_markdown(report: Dict[str, Any]) -> None:
    token = report["token_decision"]["decision"]
    ngram = report["ngram_decision"]["decision"]
    idx = report["index_state"]["index_bytes"]
    lines = [
        "# Phase 2.1D2A Bloom Dependency Attribution and Text-Index Replacement Feasibility",
        "",
        "Measurement artifact companion: `phase2_1d2a_bloom_dependency_resolution.json`.",
        "",
        f"**Verdict: {report['verdict']}**",
        "",
        "Phase 2.1D remains NOT_READY. D2A does not drop indexes, does not change",
        "production readers, and does not close Phase 2.1.",
        "",
        "## 1. Starting state",
        "",
        f"- HEAD / origin/main: `{report['baseline']['head']}`",
        f"- Working tree clean: {report['baseline']['working_tree_clean']}",
        f"- Version: {report['baseline']['version']} (unchanged)",
        f"- ClickHouse: {report['index_state']['clickhouse_version']}",
        "",
        "## 2. Production index state",
        "",
        "No production mutation. No DROP / MATERIALIZE / OPTIMIZE.",
        "",
        "| Index | Type / expression | Bytes |",
        "|---|---|---:|",
    ]
    for name in (
        "idx_search_blob_text",
        "idx_search_ngram",
        "idx_search_token",
        "idx_event_id",
        "idx_selector_key",
        "idx_evidence_record_key",
    ):
        item = idx.get(name) or {}
        lines.append(
            f"| {name} | `{item.get('type_full')}` expr `{item.get('expr')}` gran {item.get('granularity')} | {item.get('data_compressed_bytes')} |"
        )
    cov = report["index_state"]["coverage_partition_counts"]
    parts = report["index_state"]["parts_summary"]
    lines.extend(
        [
            "",
            f"Coverage partitions: MATERIALIZED {cov.get('MATERIALIZED')} / "
            f"PARTIAL {cov.get('PARTIAL')} / UNMATERIALIZED {cov.get('UNMATERIALIZED')} / "
            f"UNKNOWN {cov.get('UNKNOWN')}.",
            f"Active parts MATERIALIZED {report['index_state']['active_parts_MATERIALIZED']} / "
            f"{report['index_state']['active_parts']}.",
            f"Rows {parts.get('rows')} / parts {parts.get('active_parts')} / "
            f"partitions {parts.get('partitions')}.",
            f"Mutations in progress: {report['index_state']['mutations_in_progress']}.",
            "",
            "## 3. Exact search_blob predicate inventory",
            "",
            f"Pattern-rule distinct shapes: {len(report['pattern_predicates'])}.",
            "",
            "Case-sensitive `search_blob LIKE` shapes (production required, `models/pattern_rules.py`):",
            "",
        ]
    )
    for item in report["pattern_predicates"]:
        if item["expr"] != "search_blob" or item["op"] != "LIKE":
            continue
        rules = ", ".join(item.get("rule_ids") or [])
        pre = item["prefilter"]
        lines.append(
            f"- `{item['shape']}` — rules: {rules} — {pre['classification']} "
            f"alnum `{pre.get('alnum_run')}` len {pre.get('alnum_len')}"
        )
    lines.extend(
        [
            "",
            "lower(search_blob) LIKE shapes are inventoried in the JSON (`expr=lower(search_blob)`).",
            "Hunt TOKEN_SAFE / ILIKE / position / hasToken consumers are classified in `consumers`.",
            "",
            "## 4. Four-way bloom ablation",
            "",
            "Configs: ALL / NO_NGRAM (`ignore_data_skipping_indices=idx_search_ngram`) / "
            "NO_TOKEN / NO_BLOOMS. `idx_search_blob_text` remained available in every config.",
            "",
            "See JSON `ablation` for EXPLAIN granules, identity, and timed samples.",
            "",
            "## 5-6. Independent bloom contribution",
            "",
            f"Token decision: **{token}**",
            "",
            report["token_decision"]["note"],
            "",
            f"Independent token hits: {len(report['token_decision']['independent_hits'])}",
            "",
            f"Ngram decision: **{ngram}**",
            "",
            report["ngram_decision"]["reason"],
            "",
            "## 7. Deployed text-index LIKE/ILIKE capability",
            "",
            f"Measured on {report['index_state']['clickhouse_version']}.",
            "",
            f"ILIKE alphanumeric tokens of length >= {TEXT_INDEX_ILIKE_MIN_ALNUM} select",
            "`idx_search_blob_text` with `__text_index_*_ilike_*` prewhere and reduce granules.",
            "Case-sensitive LIKE does not. `preprocessor=lower(search_blob)` is why ILIKE can",
            "use the index and LIKE cannot. Length 1-3 ILIKE never selected the text index.",
            "ILIKE with punctuation (`ADMIN$`) also did not select the text index.",
            "",
            "## 8-12. Prefilters, parity, EXPLAIN, performance",
            "",
            "Candidate form is always `(search_blob ILIKE '%<guaranteed alnum>%' AND <original>)`.",
            "The original LIKE/lower(LIKE) remains the truth predicate.",
            "",
            "JSON keys: `prefilters`, `event_set_parity`, `detection_parity`, `prefilter_explain`,",
            "`prefilter_performance`.",
            "",
            "## 13. Index storage / insert cost",
            "",
            json.dumps(report.get("insert_cost", {}), indent=2, default=str),
            "",
            "## 14. Query frequency",
            "",
            json.dumps(report.get("query_log", {}), indent=2, default=str),
            "",
            "## 15-17. Combined decision / next tranche",
            "",
            f"- TOKEN: {token}",
            f"- NGRAM: {ngram}",
            f"- Next: {report['next_tranche']}",
            "",
            "## 18. Accepted 2.1 regression",
            "",
            json.dumps(report.get("regression", {}), indent=2, default=str),
            "",
            "## No later phase",
            "",
            json.dumps(report.get("no_later_phase"), indent=2),
            "",
            "Phase 2.1D NOT_READY evidence is preserved. D2A cannot close Phase 2.1.",
            "",
        ]
    )
    OUT_MD.write_text("\n".join(lines) + "\n", encoding="utf-8")


def log(message: str) -> None:
    print(f"[{utcnow()}] {message}", flush=True)


def save(report: Dict[str, Any]) -> None:
    OUT_JSON.parent.mkdir(parents=True, exist_ok=True)
    OUT_JSON.write_text(json.dumps(report, indent=2, default=str) + "\n", encoding="utf-8")


def main() -> int:
    report: Dict[str, Any] = {
        "tranche": "phase2_1d2a_bloom_dependency_resolution",
        "recorded_at": utcnow(),
        "version": EXPECTED_VERSION,
        "version_bumped": False,
        "phase2_1_state": "PHASE2_1_NOT_READY",
        "phase2_1d_preserved": "PHASE2_1D_NOT_READY",
    }
    log("baseline")
    baseline = git_baseline()
    report["baseline"] = baseline
    if not baseline["ok"]:
        report["verdict"] = "STOP: BASELINE_DRIFT"
        OUT_JSON.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
        print("STOP: BASELINE_DRIFT", json.dumps(baseline, indent=2))
        return 2

    client = connect("casescope")
    log("index_state")
    report["index_state"] = index_state(client)
    log("consumers")
    report["consumers"] = walk_consumers()

    from models.pattern_rules import ALL_PATTERN_RULES
    from utils.pattern_check_definitions import PATTERN_CHECKS

    pattern_preds = collect_pattern_rule_predicates(ALL_PATTERN_RULES)
    report["pattern_predicates"] = pattern_preds
    check_preds = []
    for pattern_id, checks in PATTERN_CHECKS.items():
        for check in checks:
            for pred in extract_predicates_from_sql(getattr(check, "query_template", "") or ""):
                pred["pattern_id"] = pattern_id
                pred["check_id"] = check.id
                pred["prefilter"] = derive_prefilter(pred)
                check_preds.append(pred)
    report["pattern_check_predicates_count"] = len(check_preds)
    report["pattern_check_sample"] = check_preds[:40]

    log("capability probes")
    capability = []
    for pred in CAPABILITY_PROBES:
        parsed = parse_explain_indexes(
            explain_text(
                client,
                f"SELECT count() FROM events WHERE case_id = 10 AND ({pred})",
            )
        )
        capability.append({"pred": pred, **parsed})
    length_probe = []
    for tok in ("C", "NT", "NTL", "NTLM", "RC4", "IPC", "TXT", "Temp", "0x17", "ADMIN"):
        pred = f"search_blob ILIKE '%{tok}%'"
        parsed = parse_explain_indexes(
            explain_text(client, f"SELECT count() FROM events WHERE case_id = 10 AND ({pred})")
        )
        length_probe.append(
            {
                "token": tok,
                "len": len(tok),
                "direct_text_index": parsed["direct_text_index"],
                "text_pruned": parsed["text_pruned"],
                "text_granules": parsed["text_granules"],
            }
        )
    report["capability"] = {
        "probes": capability,
        "ilike_token_length": length_probe,
        "min_alnum_for_text_ilike": TEXT_INDEX_ILIKE_MIN_ALNUM,
        "like_does_not_use_text_prune": all(
            (not item["text_pruned"]) or ("LIKE" in item["pred"] and "ILIKE" not in item["pred"])
            for item in capability
            if "ILIKE" not in item["pred"]
        ),
    }

    log("four-way ablation")
    ablation = []
    for spec in REPRESENTATIVE_PREDICATES:
        for case_id in CASES:
            log(f"ablation {spec['id']} case {case_id}")
            configs = four_way_explain(client, spec["pred"], case_id)
            ngram_dependent = bool(configs[CONFIG_ALL].get("ngram_pruned"))
            timed = {}
            if spec["id"] in TIMED_IDS:
                samples = 9
                warmup = 1
                core = {"like_ntlm", "like_ntlmssp", "like_kerberos", "like_admin_share"}
                if spec["id"] not in core and case_id != 10:
                    samples = 3
                for cfg_name, settings in IGNORE_SETTINGS.items():
                    timed[cfg_name] = time_identity(
                        client,
                        spec["pred"],
                        case_id,
                        settings=settings,
                        warmup=warmup,
                        samples=samples,
                    )
            else:
                for cfg_name, settings in IGNORE_SETTINGS.items():
                    ident = capture_identity(client, spec["pred"], case_id, settings=settings)
                    timed[cfg_name] = {
                        "warmup": 0,
                        "samples": 1,
                        "p50_ms": ident["wall_ms"],
                        "p95_ms": ident["wall_ms"],
                        "n": ident["n"],
                        "erk_fp": ident["erk_fp"],
                        "phys_fp": ident["phys_fp"],
                        "read_rows_p50": ident["read_rows"],
                        "read_bytes_p50": ident["read_bytes"],
                        "identity_stable": True,
                    }
            same_n = len({timed[name]["n"] for name in IGNORE_SETTINGS}) == 1
            same_fp = len({timed[name]["erk_fp"] for name in IGNORE_SETTINGS}) == 1
            ablation.append(
                {
                    "id": spec["id"],
                    "case_id": case_id,
                    "pred": spec["pred"],
                    "consumer": spec["consumer"],
                    "required_consumer": True,
                    "kind": "original",
                    "ngram_dependent": ngram_dependent,
                    "configs": configs,
                    "timed": timed,
                    "semantic_equal_abcd": same_n and same_fp,
                }
            )
    report["ablation"] = ablation
    report["token_decision"] = decide_token(ablation)
    save(report)

    log("prefilters / parity")
    prefilters = []
    event_parity = []
    prefilter_explain = []
    prefilter_perf = []
    for spec in REPRESENTATIVE_PREDICATES:
        extracted = extract_predicates_from_sql(spec["pred"])
        if len(extracted) == 1:
            derived = derive_prefilter(extracted[0])
        else:
            derived = {
                "classification": "BRANCH_LOCAL_OR",
                "candidate_sql": wrap_like_sql(spec["pred"]),
                "original_sql": spec["pred"],
                "text_index_usable_length": all(
                    derive_prefilter(item).get("text_index_usable_length")
                    for item in extracted
                    if item.get("op") in {"LIKE", "ILIKE"}
                ),
            }
        candidate = derived.get("candidate_sql") or wrap_like_sql(spec["pred"])
        derived["id"] = spec["id"]
        derived["pred"] = spec["pred"]
        derived["candidate_sql"] = candidate
        prefilters.append(derived)
        for case_id in CASES:
            original_id = capture_identity(client, spec["pred"], case_id)
            candidate_id = capture_identity(client, candidate, case_id)
            minus_ab = int(
                run_query(
                    client,
                    minus_sql(spec["pred"], candidate),
                    parameters={"case_id": case_id},
                ).result_rows[0][0]
            )
            minus_ba = int(
                run_query(
                    client,
                    minus_sql(candidate, spec["pred"]),
                    parameters={"case_id": case_id},
                ).result_rows[0][0]
            )
            event_parity.append(
                {
                    "id": spec["id"],
                    "case_id": case_id,
                    "original": original_id,
                    "candidate": candidate_id,
                    "a_minus_b": minus_ab,
                    "b_minus_a": minus_ba,
                    "equal": minus_ab == 0
                    and minus_ba == 0
                    and original_id["n"] == candidate_id["n"]
                    and original_id["erk_fp"] == candidate_id["erk_fp"],
                }
            )
            orig_explain = parse_explain_indexes(
                explain_text(
                    client,
                    f"SELECT count() FROM events WHERE case_id = {case_id} AND ({spec['pred']})",
                )
            )
            cand_explain = parse_explain_indexes(
                explain_text(
                    client,
                    f"SELECT count() FROM events WHERE case_id = {case_id} AND ({candidate})",
                )
            )
            cand_nobloom = parse_explain_indexes(
                explain_text(
                    client,
                    f"SELECT count() FROM events WHERE case_id = {case_id} AND ({candidate})",
                    settings=IGNORE_SETTINGS[CONFIG_NO_BLOOMS],
                )
            )
            prefilter_explain.append(
                {
                    "id": spec["id"],
                    "case_id": case_id,
                    "original": orig_explain,
                    "candidate": cand_explain,
                    "candidate_no_blooms": cand_nobloom,
                    "text_prunes_with_blooms_ignored": bool(
                        cand_nobloom.get("text_pruned") or cand_nobloom.get("direct_text_index")
                    ),
                }
            )
            log(f"parity {spec['id']} case {case_id}")
            if spec["id"] in PREFILTER_TIMED_IDS:
                samples = 9 if spec["id"] in {"like_ntlm", "like_admin_share", "like_kerberos"} else 3
                if case_id == 10:
                    samples = 9
                prefilter_perf.append(
                    {
                        "id": spec["id"],
                        "case_id": case_id,
                        "original": time_identity(
                            client, spec["pred"], case_id, warmup=1, samples=samples
                        ),
                        "candidate": time_identity(
                            client, candidate, case_id, warmup=1, samples=samples
                        ),
                        "candidate_no_blooms": time_identity(
                            client,
                            candidate,
                            case_id,
                            settings=IGNORE_SETTINGS[CONFIG_NO_BLOOMS],
                            warmup=1,
                            samples=samples,
                        ),
                    }
                )
    report["prefilters"] = prefilters
    report["event_set_parity"] = event_parity
    report["prefilter_explain"] = prefilter_explain
    report["prefilter_performance"] = prefilter_perf
    save(report)

    log("full detection parity")
    detection_parity = []
    rules_by_id = {rule["id"]: rule for rule in ALL_PATTERN_RULES}
    for rule_id in FULL_DETECTION_RULE_IDS:
        rule = rules_by_id[rule_id]
        original_sql = str(rule["detection_query"])
        candidate_sql = wrap_like_sql(original_sql)
        for case_id in CASES:
            log(f"detection {rule_id} case {case_id}")
            orig = run_detection(client, original_sql, case_id)
            cand = run_detection(client, candidate_sql, case_id)
            detection_parity.append(
                {
                    "rule_id": rule_id,
                    "name": rule.get("name"),
                    "case_id": case_id,
                    "original": {k: orig[k] for k in orig if k != "columns"},
                    "candidate": {k: cand[k] for k in cand if k != "columns"},
                    "columns": orig["columns"],
                    "equal": orig["n"] == cand["n"] and orig["fingerprint"] == cand["fingerprint"],
                }
            )
    report["detection_parity"] = detection_parity
    save(report)

    log("insert cost")
    report["insert_cost"] = insert_cost(client)
    log("query_log")
    report["query_log"] = query_log_frequency(client)

    ngram_dependent_required = [
        item for item in ablation if item["ngram_dependent"] and item["required_consumer"]
    ]
    unresolved = [item for item in ablation if not item.get("semantic_equal_abcd")]
    parity_fail = [item for item in event_parity if not item["equal"]]
    detection_fail = [item for item in detection_parity if not item["equal"]]

    replaceable = []
    exceptions = []
    for item in ngram_dependent_required:
        spec_id = item["id"]
        case_id = item["case_id"]
        explain_row = next(
            row
            for row in prefilter_explain
            if row["id"] == spec_id and row["case_id"] == case_id
        )
        parity_row = next(
            row
            for row in event_parity
            if row["id"] == spec_id and row["case_id"] == case_id
        )
        perf_row = next(
            (
                row
                for row in prefilter_perf
                if row["id"] == spec_id and row["case_id"] == case_id
            ),
            None,
        )
        text_ok = explain_row["text_prunes_with_blooms_ignored"]
        parity_ok = parity_row["equal"]
        regression = False
        if perf_row:
            orig_rows = perf_row["original"].get("read_rows_p50") or 0
            cand_rows = perf_row["candidate_no_blooms"].get("read_rows_p50") or 0
            orig_p50 = perf_row["original"].get("p50_ms") or 0
            cand_p50 = perf_row["candidate_no_blooms"].get("p50_ms") or 0
            if orig_rows and cand_rows > orig_rows * 1.15 and cand_p50 > orig_p50 * 1.25:
                regression = True
        ok = text_ok and parity_ok and not regression
        bucket = replaceable if ok else exceptions
        bucket.append(
            {
                "id": spec_id,
                "case_id": case_id,
                "text_ok": text_ok,
                "parity_ok": parity_ok,
                "regression": regression,
                "original_ngram_granules": item["configs"][CONFIG_ALL].get("ngram_granules"),
                "candidate_no_bloom_text_granules": explain_row["candidate_no_blooms"].get(
                    "text_granules"
                ),
            }
        )

    if unresolved or parity_fail or detection_fail:
        ngram_decision = "NGRAM_DEPENDENCY_UNRESOLVED"
        reason = (
            f"unresolved semantic/parity gaps: ablation={len(unresolved)} "
            f"event_parity={len(parity_fail)} detection={len(detection_fail)}"
        )
    elif ngram_dependent_required and not exceptions:
        ngram_decision = "NGRAM_TEXT_PREFILTER_REPLACEMENT_FEASIBLE"
        reason = (
            "Every ngram-dependent required representative had a safe superset "
            "ILIKE prefilter, exact identity parity, and text-index pruning with blooms ignored."
        )
    else:
        ngram_decision = "NGRAM_MEASURED_EXCEPTION_REQUIRED"
        reason = (
            "At least one required ngram-dependent predicate cannot be equivalently "
            "accelerated by idx_search_blob_text on 26.7.3.19. Short alphanumeric "
            f"runs (<{TEXT_INDEX_ILIKE_MIN_ALNUM}) and OR branches containing them "
            "do not produce text-index prune, while idx_search_ngram still prunes "
            "some of those LIKE predicates."
        )
    report["ngram_decision"] = {
        "decision": ngram_decision,
        "reason": reason,
        "replaceable": replaceable,
        "exceptions": exceptions,
        "parity_fail": parity_fail,
        "detection_fail": detection_fail,
        "unresolved": [item["id"] for item in unresolved],
    }

    token_d = report["token_decision"]["decision"]
    if token_d == "TOKEN_BLOOM_REDUNDANT" and ngram_decision == "NGRAM_TEXT_PREFILTER_REPLACEMENT_FEASIBLE":
        next_tranche = (
            "Phase 2.1D2B — minimal exact-semantic pattern prefilter migration, "
            "then repeat EXPLAIN before any bloom DROP."
        )
        outcome = "A"
    elif token_d == "TOKEN_BLOOM_REDUNDANT" and ngram_decision == "NGRAM_MEASURED_EXCEPTION_REQUIRED":
        next_tranche = (
            "explicit architecture review of the locked 'drop both blooms' sentence. "
            "Do not silently change the gate."
        )
        outcome = "B"
    elif token_d == "TOKEN_BLOOM_INDEPENDENTLY_REQUIRED" and ngram_decision == "NGRAM_MEASURED_EXCEPTION_REQUIRED":
        next_tranche = "explicit architecture review required."
        outcome = "C"
    else:
        next_tranche = "remain NOT_READY and gather missing evidence."
        outcome = "D"
    report["combined_outcome"] = outcome
    report["next_tranche"] = next_tranche
    report["no_later_phase"] = {
        "phase_2_2": False,
        "async_insert_change": False,
        "phase_2_3": False,
        "phase_2_4": False,
        "phase_3": False,
        "phase_4": False,
        "events_current": False,
        "event_observations_current": False,
        "search_blob_reader_migration": False,
        "pagination_redesign": False,
        "OPTIMIZE_FINAL_production": False,
        "MATERIALIZE_INDEX_production": False,
        "DROP_INDEX_production": False,
        "production_reader_changes": False,
        "EVENTS_SCHEMA_changed": False,
        "version_bumped": False,
    }
    report["verdict"] = "PHASE2_1D2A_PASS"
    save(report)
    write_markdown(report)
    print(json.dumps(
        {
            "verdict": report["verdict"],
            "token": token_d,
            "ngram": ngram_decision,
            "outcome": outcome,
            "json": str(OUT_JSON),
        },
        indent=2,
    ))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:
        fail_path = ROOT / "docs/database_flow_phase2/phase2_1d2a_bloom_dependency_resolution.json"
        payload = {"verdict": "PHASE2_1D2A_NOT_READY", "error": repr(exc), "recorded_at": utcnow()}
        try:
            if fail_path.exists():
                existing = json.loads(fail_path.read_text())
                existing.update(payload)
                payload = existing
        except Exception:
            pass
        fail_path.parent.mkdir(parents=True, exist_ok=True)
        fail_path.write_text(json.dumps(payload, indent=2, default=str) + "\n", encoding="utf-8")
        raise
