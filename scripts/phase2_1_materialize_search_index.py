#!/usr/bin/env python3
"""Operator-controlled partition materialization for idx_search_blob_text.

    This does NOT materialize the whole production table. One --case-id partition
    per invocation. There is no whole-table default.

Examples:

  /opt/casescope/venv/bin/python scripts/phase2_1_materialize_search_index.py --status
  /opt/casescope/venv/bin/python scripts/phase2_1_materialize_search_index.py \\
      --dry-run --case-id 33 --apply-production
  /opt/casescope/venv/bin/python scripts/phase2_1_materialize_search_index.py \\
      --case-id 33 --apply-production
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def connect(database, timeout=86400):
    import clickhouse_connect

    return clickhouse_connect.get_client(
        host=os.environ.get("CLICKHOUSE_HOST") or "localhost",
        port=int(os.environ.get("CLICKHOUSE_PORT") or 8123),
        database=database,
        username=os.environ.get("CLICKHOUSE_USER") or "default",
        password=os.environ.get("CLICKHOUSE_PASSWORD") or "",
        autogenerate_session_id=False,
        connect_timeout=10,
        send_receive_timeout=int(timeout),
        settings={
            "async_insert": 0,
            "wait_for_async_insert": 1,
        },
    )


def inspect_fence():
    from utils.ingest_fence import (
        IngestFenceUnavailable,
        active_shared_writer_count,
        get_active_exclusive_fence,
    )

    try:
        writers = active_shared_writer_count()
        exclusive = get_active_exclusive_fence()
        return {
            "ok": exclusive is None and int(writers) == 0,
            "shared_writer_count": int(writers),
            "exclusive": exclusive,
            "error": None,
        }
    except IngestFenceUnavailable as exc:
        return {
            "ok": False,
            "shared_writer_count": None,
            "exclusive": None,
            "error": str(exc),
        }


def inspect_systemd():
    units = ("casescope-web", "casescope-workers", "casescope-beat")
    states = {}
    for unit in units:
        proc = subprocess.run(
            ["systemctl", "is-active", unit],
            check=False,
            capture_output=True,
            text=True,
        )
        states[unit] = (proc.stdout or proc.stderr or "").strip() or f"rc={proc.returncode}"
    stopped = all(states[unit] == "inactive" for unit in units)
    return {"ok": stopped, "states": states}


def inspect_celery():
    try:
        os.environ.setdefault("SECRET_KEY", os.environ.get("SECRET_KEY") or "phase2-1a-operator")
        from tasks.celery_tasks import celery_app

        inspector = celery_app.control.inspect(timeout=2)
        active = inspector.active() if inspector is not None else None
        reserved = inspector.reserved() if inspector is not None else None
        scheduled = inspector.scheduled() if inspector is not None else None

        def _count(payload):
            if not payload:
                return 0
            return sum(len(items or []) for items in payload.values())

        total = _count(active) + _count(reserved) + _count(scheduled)
        return {
            "ok": total == 0,
            "active": active or {},
            "reserved": reserved or {},
            "scheduled": scheduled or {},
            "total": total,
            "error": None,
        }
    except Exception as exc:
        return {
            "ok": False,
            "active": {},
            "reserved": {},
            "scheduled": {},
            "total": None,
            "error": str(exc),
        }


def inspect_writers(*, require_idle):
    fence = inspect_fence()
    systemd = inspect_systemd()
    celery = inspect_celery()
    report = {
        "fence": fence,
        "systemd": systemd,
        "celery": celery,
        "ok": bool(fence.get("ok") and systemd.get("ok")),
    }
    if require_idle and not report["ok"]:
        raise SystemExit(
            "Refusing to continue: application writers are not idle "
            f"(fence={fence}, systemd={systemd['states']})"
        )
    return report


def status_payload(client, case_id=None):
    from utils.search_blob_text_index import (
        INDEX_NAME,
        inspect_all_partition_coverage,
        inspect_partition_coverage,
        inspect_schema_preconditions,
        partition_inventory,
        require_bloom_indexes,
        skipping_indices,
        table_parts_summary,
        active_mutations,
        recent_failed_mutations,
        current_database_name,
    )

    schema = inspect_schema_preconditions(client)
    indices = skipping_indices(client)
    blooms = []
    bloom_error = None
    try:
        blooms = list(require_bloom_indexes(client))
    except Exception as exc:
        bloom_error = str(exc)
    text_index = next((item for item in indices if item["name"] == INDEX_NAME), None)
    if case_id is not None:
        coverage = [inspect_partition_coverage(client, case_id)]
    else:
        coverage = inspect_all_partition_coverage(client)
    return {
        "database": current_database_name(client),
        "schema": schema,
        "indexes": indices,
        "text_index": text_index,
        "bloom_indexes": blooms,
        "bloom_error": bloom_error,
        "parts_summary": table_parts_summary(client),
        "inventory": partition_inventory(client),
        "coverage": coverage,
        "mutations_active": active_mutations(client),
        "mutations_failed": recent_failed_mutations(client),
        "writers": inspect_writers(require_idle=False),
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--database",
        default=os.environ.get("CLICKHOUSE_DATABASE") or "casescope",
        help="ClickHouse database. Production name is casescope.",
    )
    parser.add_argument(
        "--case-id",
        type=int,
        help="Exactly one case_id partition. Required to materialize. No all-partitions default.",
    )
    parser.add_argument(
        "--status",
        action="store_true",
        help="Inspect coverage/schema/mutations without DDL.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Build and print the partition MATERIALIZE INDEX command without executing it.",
    )
    parser.add_argument(
        "--apply-production",
        action="store_true",
        help="Acknowledge mutation against the production casescope database.",
    )
    parser.add_argument(
        "--require-idle",
        action="store_true",
        help="Fail if ingest fence or CaseScope systemd units are not idle.",
    )
    args = parser.parse_args(argv)

    if not args.status and args.case_id is None:
        parser.error("--case-id is required unless --status is used; there is no all-partitions default")

    from utils.search_blob_text_index import (
        PRODUCTION_DATABASE_NAMES,
        materialize_case_partition,
    )

    client = connect(args.database)
    if args.status:
        payload = status_payload(client, case_id=args.case_id)
        print(json.dumps(payload, indent=2, default=str))
        return 0

    idle_checker = None
    if args.require_idle or (
        args.database in PRODUCTION_DATABASE_NAMES and args.apply_production and not args.dry_run
    ):
        def _idle_checker():
            return inspect_writers(require_idle=True)

        _idle_checker()
        idle_checker = _idle_checker

    result = materialize_case_partition(
        client,
        args.case_id,
        allow_production=args.apply_production,
        dry_run=args.dry_run,
        require_writers_idle=idle_checker,
    )
    print(json.dumps(result, indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
