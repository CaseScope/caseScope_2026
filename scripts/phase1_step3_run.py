#!/usr/bin/env python3
"""Phase 1 Step 3 measurement harness.

IOC recall comparator and profiler canonical capture. Disposable ClickHouse
for fixtures. Production/retained evidence is read-only.

Refuses to run fixture inserts against database `casescope`.
"""
from __future__ import annotations

import argparse
import json
import os
import resource
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, List
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

DISPOSABLE_PREFIX = "phase1_step3_"
RESULTS_DIR = ROOT / "docs" / "database_flow_phase1"


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _peak_rss_mb() -> float:
    return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024.0


def _ch_client(database: str):
    import clickhouse_connect

    return clickhouse_connect.get_client(
        host=os.environ.get("CLICKHOUSE_HOST", "localhost"),
        port=int(os.environ.get("CLICKHOUSE_PORT", 8123)),
        database=database,
        username=os.environ.get("CLICKHOUSE_USER", "default"),
        password=os.environ.get("CLICKHOUSE_PASSWORD", ""),
        autogenerate_session_id=False,
        settings={"max_execution_time": 120},
        connect_timeout=10,
        send_receive_timeout=180,
    )


def _pg():
    import psycopg2

    conn = psycopg2.connect(os.environ["DATABASE_URL"])
    conn.set_session(readonly=True, autocommit=True)
    return conn


def _load_ioc_specs(case_id: int, limit: int = 40) -> List[Any]:
    from utils.phase1_step3_ioc_recall import IocSpec

    conn = _pg()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT uuid, ioc_type, value, match_type, aliases
        FROM iocs
        WHERE case_id = %s AND active IS TRUE AND false_positive IS FALSE
        ORDER BY created_at ASC, id ASC
        LIMIT %s
        """,
        (case_id, limit),
    )
    specs = []
    for uuid, ioc_type, value, match_type, aliases in cur.fetchall():
        specs.append(
            IocSpec(
                case_id=case_id,
                uuid=str(uuid),
                ioc_type=ioc_type,
                value=value,
                match_type=match_type,
                aliases=aliases or None,
            )
        )
    conn.close()
    return specs


def _load_principals(case_id: int):
    conn = _pg()
    cur = conn.cursor()
    cur.execute(
        "SELECT id, username, sid FROM known_users WHERE case_id = %s ORDER BY id",
        (case_id,),
    )
    users = [
        SimpleNamespace(id=row[0], username=row[1], sid=row[2])
        for row in cur.fetchall()
    ]
    cur.execute(
        "SELECT id, hostname FROM known_systems WHERE case_id = %s ORDER BY id",
        (case_id,),
    )
    systems = [
        SimpleNamespace(id=row[0], hostname=row[1])
        for row in cur.fetchall()
    ]
    conn.close()
    return users, systems


def cmd_fixtures(args: argparse.Namespace) -> Dict[str, Any]:
    from migrations.add_events_table import EVENTS_SCHEMA
    from utils.phase1_step3_ioc_recall import (
        PATH_ILIKE,
        PATH_LEGACY,
        PATH_NO_LOWER,
        PATH_NO_RAW_JSON,
        PATH_STRUCTURED_BLOB,
        CountingClient,
        build_path_clause,
        classify_a_minus_b,
        compare_sets,
        explain_clause,
        fixture_events,
        fixture_specs,
        insert_fixture_events,
        run_path_scan,
        summarize_scan,
    )

    database = args.database or f"{DISPOSABLE_PREFIX}ioc_{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"
    if not database.startswith(DISPOSABLE_PREFIX):
        raise SystemExit(f"Refusing fixture database {database}: must start with {DISPOSABLE_PREFIX}")
    if database == "casescope":
        raise SystemExit("Refusing to write fixtures into production ClickHouse")

    admin = _ch_client("default")
    admin.command(f"CREATE DATABASE IF NOT EXISTS `{database}`")
    client = _ch_client(database)
    client.command(EVENTS_SCHEMA)
    events = fixture_events()
    inserted = insert_fixture_events(client, events)
    specs = fixture_specs()
    counting = CountingClient(client)

    a_records, a_stats = run_path_scan(counting, specs, PATH_LEGACY, classify_sources=True)
    path_results = {}
    for path in (PATH_NO_LOWER, PATH_ILIKE, PATH_NO_RAW_JSON, PATH_STRUCTURED_BLOB):
        b_records, b_stats = run_path_scan(counting, specs, path, classify_sources=False)
        a_keys = [rec.key() for rec in a_records]
        b_keys = [rec.key() for rec in b_records]
        compared = compare_sets(a_keys, b_keys)
        classified = []
        if compared["a_minus_b"]:
            classified = classify_a_minus_b(
                counting,
                compared["a_minus_b"],
                {spec.uuid: spec for spec in specs},
                a_records,
            )
        path_results[path] = {
            **summarize_scan(specs, a_records, b_records, path, classified),
            "b_stats": b_stats,
        }

    explain = {}
    domain_spec = next(spec for spec in specs if spec.label == "mixed_case_domain")
    for path, label in (
        (PATH_LEGACY, "legacy_lower"),
        (PATH_NO_LOWER, "sensitive"),
        (PATH_ILIKE, "ilike"),
        (PATH_NO_RAW_JSON, "no_raw_json"),
    ):
        clause = build_path_clause(
            domain_spec.value,
            domain_spec.ioc_type,
            domain_spec.effective_match_type(),
            path=path,
        )
        explain[label] = explain_clause(counting, domain_spec.case_id, clause)

    token_spec = next(spec for spec in specs if spec.label == "punct_adjacent")
    explain["token_hasTokenCaseInsensitive"] = explain_clause(
        counting,
        token_spec.case_id,
        build_path_clause(token_spec.value, token_spec.ioc_type, "token", path=PATH_LEGACY),
    )

    payload = {
        "generated_at": _utc_now(),
        "database": database,
        "inserted_events": inserted,
        "legacy": a_stats,
        "legacy_match_count": len(a_records),
        "legacy_raw_json_only": sum(
            1
            for rec in a_records
            if rec.hit_raw_json and not rec.hit_search_blob and not rec.hit_structured and not rec.hit_username
        ),
        "paths": path_results,
        "explain": explain,
        "clickhouse_statements": counting.statements,
        "clickhouse_query_wall_ms": round(counting.query_wall_ms, 3),
        "peak_rss_mb": round(_peak_rss_mb(), 2),
        "no_raw_json_verdict": path_results[PATH_NO_RAW_JSON]["ioc_verdict"],
        "no_lower_verdict": path_results[PATH_NO_LOWER]["ioc_verdict"],
        "ilike_verdict": path_results[PATH_ILIKE]["ioc_verdict"],
        "structured_blob_verdict": path_results[PATH_STRUCTURED_BLOB]["ioc_verdict"],
    }
    if args.output:
        Path(args.output).write_text(json.dumps(payload, indent=2, default=str) + "\n")
    if not args.keep:
        admin.command(f"DROP DATABASE IF EXISTS `{database}`")
        payload["dropped"] = True
    print(json.dumps({
        "database": database,
        "legacy_matches": payload["legacy_match_count"],
        "no_raw_json": payload["no_raw_json_verdict"],
        "no_lower": payload["no_lower_verdict"],
        "ilike": payload["ilike_verdict"],
        "structured_blob": payload["structured_blob_verdict"],
        "a_minus_b_no_raw_json": path_results[PATH_NO_RAW_JSON]["a_minus_b_count"],
    }, indent=2))
    return payload


def cmd_retained_ioc(args: argparse.Namespace) -> Dict[str, Any]:
    from utils.phase1_step3_ioc_recall import (
        PATH_ILIKE,
        PATH_LEGACY,
        PATH_NO_RAW_JSON,
        PATH_STRUCTURED_BLOB,
        CountingClient,
        classify_a_minus_b,
        compare_sets,
        run_path_scan,
        summarize_scan,
    )

    case_id = int(args.case_id)
    specs = _load_ioc_specs(case_id, limit=int(args.limit))
    if not specs:
        payload = {"case_id": case_id, "specs": 0, "skipped": "no active IOCs"}
        print(json.dumps(payload, indent=2))
        return payload
    client = CountingClient(_ch_client(os.environ.get("CLICKHOUSE_DATABASE", "casescope")))
    a_records, a_stats = run_path_scan(
        client, specs, PATH_LEGACY, classify_sources=True, max_rows_per_ioc=int(args.max_rows)
    )
    results = {}
    for path in (PATH_NO_RAW_JSON, PATH_STRUCTURED_BLOB, PATH_ILIKE):
        b_records, b_stats = run_path_scan(
            client, specs, path, classify_sources=False, max_rows_per_ioc=int(args.max_rows)
        )
        compared = compare_sets([r.key() for r in a_records], [r.key() for r in b_records])
        classified = []
        if compared["a_minus_b"]:
            classified = classify_a_minus_b(
                client,
                compared["a_minus_b"][: int(args.max_misses)],
                {spec.uuid: spec for spec in specs},
                a_records,
            )
        results[path] = {
            **summarize_scan(specs, a_records, b_records, path, classified),
            "b_stats": b_stats,
        }
    payload = {
        "generated_at": _utc_now(),
        "case_id": case_id,
        "read_only": True,
        "ioc_count": len(specs),
        "legacy": a_stats,
        "legacy_match_count": len(a_records),
        "paths": results,
        "clickhouse_statements": client.statements,
        "clickhouse_query_wall_ms": round(client.query_wall_ms, 3),
        "peak_rss_mb": round(_peak_rss_mb(), 2),
    }
    if args.output:
        Path(args.output).write_text(json.dumps(payload, indent=2, default=str) + "\n")
    print(json.dumps({
        "case_id": case_id,
        "iocs": len(specs),
        "legacy_matches": len(a_records),
        "no_raw_json": results[PATH_NO_RAW_JSON]["ioc_verdict"],
        "a_minus_b": results[PATH_NO_RAW_JSON]["a_minus_b_count"],
        "structured_blob": results[PATH_STRUCTURED_BLOB]["ioc_verdict"],
        "ilike": results[PATH_ILIKE]["ioc_verdict"],
        "ilike_a_minus_b": results[PATH_ILIKE]["a_minus_b_count"],
        "query_wall_ms": payload["clickhouse_query_wall_ms"],
    }, indent=2))
    return payload


def cmd_profiler(args: argparse.Namespace) -> Dict[str, Any]:
    from utils.behavioral_profiler import BehavioralProfiler
    from utils.phase1_step3_profiler import capture_profiles, diff_canonical

    case_id = int(args.case_id)
    users, systems = _load_principals(case_id)
    if args.max_users:
        users = users[: int(args.max_users)]
    if args.max_systems:
        systems = systems[: int(args.max_systems)]
    profiler = BehavioralProfiler(case_id=case_id, analysis_id="phase1-step3-dry-run")
    legacy = capture_profiles(profiler, users, systems, mode="legacy")
    set_based = capture_profiles(profiler, users, systems, mode="set_based")
    diff = diff_canonical(legacy, set_based)
    payload = {
        "generated_at": _utc_now(),
        "case_id": case_id,
        "read_only": True,
        "users_loaded": len(users),
        "systems_loaded": len(systems),
        "legacy": {
            k: legacy[k]
            for k in (
                "users_profiled",
                "systems_profiled",
                "clickhouse_statements",
                "clickhouse_query_wall_ms",
                "rows_returned",
                "wall_ms",
                "user_digest",
                "system_digest",
                "users_skipped_below_min",
                "systems_skipped_below_min",
            )
        },
        "set_based": {
            k: set_based[k]
            for k in (
                "users_profiled",
                "systems_profiled",
                "clickhouse_statements",
                "clickhouse_query_wall_ms",
                "rows_returned",
                "wall_ms",
                "user_digest",
                "system_digest",
                "expected_bounded_statements",
                "users_skipped_below_min",
                "systems_skipped_below_min",
            )
        },
        "diff": diff,
        "peak_rss_mb": round(_peak_rss_mb(), 2),
    }
    if args.include_payloads:
        payload["legacy_users"] = legacy["users"]
        payload["legacy_systems"] = legacy["systems"]
        payload["set_based_users"] = set_based["users"]
        payload["set_based_systems"] = set_based["systems"]
    if args.output:
        Path(args.output).write_text(json.dumps(payload, indent=2, default=str) + "\n")
    print(json.dumps({
        "case_id": case_id,
        "users": len(users),
        "systems": len(systems),
        "legacy_statements": legacy["clickhouse_statements"],
        "set_based_statements": set_based["clickhouse_statements"],
        "legacy_wall_ms": legacy["wall_ms"],
        "set_based_wall_ms": set_based["wall_ms"],
        "semantic_parity": diff["semantic_parity"],
        "user_mismatches": len(diff["user_payload_mismatches"]),
        "system_mismatches": len(diff["system_payload_mismatches"]),
    }, indent=2))
    return payload


def main() -> None:
    parser = argparse.ArgumentParser(description="Phase 1 Step 3 comparators")
    sub = parser.add_subparsers(dest="command", required=True)

    p_fix = sub.add_parser("fixtures")
    p_fix.add_argument("--database", default="")
    p_fix.add_argument("--keep", action="store_true")
    p_fix.add_argument("--output", default="")
    p_fix.set_defaults(func=cmd_fixtures)

    p_ioc = sub.add_parser("retained-ioc")
    p_ioc.add_argument("--case-id", required=True)
    p_ioc.add_argument("--limit", default=20)
    p_ioc.add_argument("--max-rows", default=5000)
    p_ioc.add_argument("--max-misses", default=50)
    p_ioc.add_argument("--output", default="")
    p_ioc.set_defaults(func=cmd_retained_ioc)

    p_prof = sub.add_parser("profiler")
    p_prof.add_argument("--case-id", required=True)
    p_prof.add_argument("--max-users", default=0)
    p_prof.add_argument("--max-systems", default=0)
    p_prof.add_argument("--include-payloads", action="store_true")
    p_prof.add_argument("--output", default="")
    p_prof.set_defaults(func=cmd_profiler)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
