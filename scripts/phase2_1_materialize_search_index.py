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

OPERATOR_ENV_FILE = "/etc/casescope/casescope.env"


def load_operator_environment(path=OPERATOR_ENV_FILE):
    """Load the CaseScope service env so fence/Celery use the production keyspace."""
    if os.environ.get("SECRET_KEY"):
        return
    try:
        with open(path, encoding="utf-8") as handle:
            for raw in handle:
                line = raw.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, value = line.split("=", 1)
                os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))
    except OSError:
        return


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


WRITER_UNITS = ("casescope-web", "casescope-workers", "casescope-beat")
CELERY_INSPECT_TIMEOUT_SECONDS = 5
REDIS_UNACKED_KEYS = ("unacked",)


def inspect_fence():
    load_operator_environment()
    from utils.ingest_fence import (
        IngestFenceUnavailable,
        active_shared_writer_count,
        get_active_exclusive_fence,
    )

    try:
        writers = active_shared_writer_count()
        exclusive = get_active_exclusive_fence()
        shared_writer_count = int(writers)
        ok = exclusive is None and shared_writer_count == 0
        refusal_reason = None
        if exclusive is not None:
            refusal_reason = f"ingest fence exclusive owner is active: {exclusive}"
        elif shared_writer_count != 0:
            refusal_reason = f"ingest fence shared_writer_count={shared_writer_count}"
        return {
            "ok": ok,
            "shared_writer_count": shared_writer_count,
            "exclusive": exclusive,
            "error": None,
            "refusal_reason": refusal_reason,
        }
    except IngestFenceUnavailable as exc:
        return {
            "ok": False,
            "shared_writer_count": None,
            "exclusive": None,
            "error": str(exc),
            "refusal_reason": f"ingest fence unavailable: {exc}",
        }
    except Exception as exc:
        return {
            "ok": False,
            "shared_writer_count": None,
            "exclusive": None,
            "error": str(exc),
            "refusal_reason": f"ingest fence inspection error: {exc}",
        }


def inspect_systemd(units=WRITER_UNITS):
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
    active = [unit for unit, state in states.items() if state != "inactive"]
    return {
        "ok": stopped,
        "states": states,
        "refusal_reason": None
        if stopped
        else "local service still active: "
        + ", ".join(f"{unit}={states[unit]}" for unit in active),
    }


def count_celery_inspect_payload(payload, label):
    """Count tasks from a Celery inspect mapping. None/timeout is unknown, not zero."""
    if payload is None:
        return {
            "inspected": False,
            "count": None,
            "no_reply": True,
            "error": None,
        }
    if not isinstance(payload, dict):
        return {
            "inspected": False,
            "count": None,
            "no_reply": False,
            "error": f"{label} returned {type(payload).__name__}, expected dict",
        }
    total = 0
    for worker, items in payload.items():
        if items is None:
            return {
                "inspected": False,
                "count": None,
                "no_reply": False,
                "error": f"{label} worker {worker!r} returned None (unknown; fail closed)",
            }
        if not isinstance(items, (list, tuple)):
            return {
                "inspected": False,
                "count": None,
                "no_reply": False,
                "error": (
                    f"{label} worker {worker!r} returned {type(items).__name__}, "
                    "expected list"
                ),
            }
        total += len(items)
    return {"inspected": True, "count": total, "no_reply": False, "error": None}


def _queue_missing_error(exc):
    text = str(exc).lower()
    return any(
        token in text
        for token in ("not found", "no queue", "not_found", "404", "no such queue")
    )


def inspect_celery_broker(app=None):
    """Prove broker queued/unacked work without treating missing workers as zero."""
    os.environ.setdefault("SECRET_KEY", os.environ.get("SECRET_KEY") or "phase2-1a-operator")
    from tasks.celery_tasks import IOC_TASK_QUEUE, celery_app

    app = app or celery_app
    names = [app.conf.task_default_queue or "celery"]
    if IOC_TASK_QUEUE and IOC_TASK_QUEUE not in names:
        names.append(IOC_TASK_QUEUE)
    queues = {}
    try:
        with app.connection_or_acquire() as conn:
            channel = conn.default_channel
            for name in names:
                try:
                    meta = channel.queue_declare(queue=name, passive=True)
                    queues[name] = int(getattr(meta, "message_count", 0) or 0)
                except Exception as exc:
                    if _queue_missing_error(exc):
                        queues[name] = 0
                    else:
                        raise
            client = getattr(channel, "client", None)
            if client is None or not hasattr(client, "hlen"):
                return {
                    "ok": False,
                    "queues": queues,
                    "queued_count": None,
                    "unacked_count": None,
                    "error": "broker channel has no redis client; cannot inspect unacked",
                }
            unacked = 0
            for key in REDIS_UNACKED_KEYS:
                try:
                    unacked += int(client.hlen(key) or 0)
                except Exception as exc:
                    return {
                        "ok": False,
                        "queues": queues,
                        "queued_count": None,
                        "unacked_count": None,
                        "error": f"unacked inspect failed for {key}: {exc}",
                    }
        return {
            "ok": True,
            "queues": queues,
            "queued_count": int(sum(queues.values())),
            "unacked_count": int(unacked),
            "error": None,
        }
    except Exception as exc:
        return {
            "ok": False,
            "queues": queues,
            "queued_count": None,
            "unacked_count": None,
            "error": str(exc),
        }


def inspect_celery(*, inspector_factory=None, broker_factory=None):
    try:
        load_operator_environment()
        if inspector_factory is None:
            os.environ.setdefault(
                "SECRET_KEY", os.environ.get("SECRET_KEY") or "phase2-1a-operator"
            )
            from tasks.celery_tasks import celery_app

            def inspector_factory():
                inspector = celery_app.control.inspect(timeout=CELERY_INSPECT_TIMEOUT_SECONDS)
                if inspector is None:
                    raise RuntimeError("celery control.inspect() returned None")
                return inspector

        if broker_factory is None:
            broker_factory = inspect_celery_broker

        inspector = inspector_factory()
        if inspector is None:
            raise RuntimeError("celery inspector_factory returned None")
        active_payload = inspector.active()
        reserved_payload = inspector.reserved()
        scheduled_payload = inspector.scheduled()
        broker = broker_factory()
        return compose_celery_report(
            active_payload,
            reserved_payload,
            scheduled_payload,
            broker,
        )
    except Exception as exc:
        return {
            "ok": False,
            "inspected": False,
            "no_worker_reply": True,
            "active": None,
            "reserved": None,
            "scheduled": None,
            "active_count": None,
            "reserved_count": None,
            "scheduled_count": None,
            "total": None,
            "broker_inspected": False,
            "queued_count": None,
            "unacked_count": None,
            "queues": {},
            "broker_error": None,
            "error": str(exc),
            "empty": False,
        }


def compose_celery_report(
    active_payload,
    reserved_payload,
    scheduled_payload,
    broker,
    error=None,
):
    active = count_celery_inspect_payload(active_payload, "celery active")
    reserved = count_celery_inspect_payload(reserved_payload, "celery reserved")
    scheduled = count_celery_inspect_payload(scheduled_payload, "celery scheduled")
    broker = broker or {}
    broker_error = broker.get("error")
    inspected = bool(
        active["inspected"] and reserved["inspected"] and scheduled["inspected"]
    )
    worker_errors = [
        item["error"]
        for item in (active, reserved, scheduled)
        if item.get("error")
    ]
    combined_error = error or broker_error or (worker_errors[0] if worker_errors else None)
    queued_count = broker.get("queued_count")
    unacked_count = broker.get("unacked_count")
    empty = bool(
        inspected
        and active["count"] == 0
        and reserved["count"] == 0
        and scheduled["count"] == 0
        and broker.get("ok")
        and queued_count == 0
        and unacked_count == 0
    )
    return {
        "ok": empty and combined_error is None,
        "inspected": inspected,
        "no_worker_reply": not inspected,
        "active": active_payload if isinstance(active_payload, dict) else None,
        "reserved": reserved_payload if isinstance(reserved_payload, dict) else None,
        "scheduled": scheduled_payload if isinstance(scheduled_payload, dict) else None,
        "active_count": active["count"],
        "reserved_count": reserved["count"],
        "scheduled_count": scheduled["count"],
        "total": (
            None
            if None in (active["count"], reserved["count"], scheduled["count"])
            else active["count"] + reserved["count"] + scheduled["count"]
        ),
        "broker_inspected": bool(broker.get("ok")),
        "queued_count": queued_count,
        "unacked_count": unacked_count,
        "queues": broker.get("queues") or {},
        "broker_error": broker_error,
        "error": combined_error,
        "empty": empty,
    }


def celery_refusal_reasons(celery, *, systemd_stopped):
    """Fail closed: unknown / timeout / broker error is never treated as zero."""
    reasons = []
    if celery.get("error"):
        reasons.append(f"celery inspection error: {celery['error']}")
        return reasons

    for label, key in (
        ("active", "active_count"),
        ("reserved", "reserved_count"),
        ("scheduled", "scheduled_count"),
    ):
        count = celery.get(key)
        if isinstance(count, int) and count > 0:
            reasons.append(f"celery {label} count={count}")

    if not celery.get("broker_inspected"):
        reasons.append(
            "celery broker inspection error: "
            + str(celery.get("broker_error") or "not inspected")
        )
        return reasons

    queued = celery.get("queued_count")
    unacked = celery.get("unacked_count")
    if queued is None or unacked is None:
        reasons.append("celery broker queued/unacked unknown; fail closed")
        return reasons
    if queued > 0:
        reasons.append(f"celery queued count={queued}")
    if unacked > 0:
        reasons.append(f"celery unacked count={unacked}")

    worker_unknown = any(
        celery.get(key) is None
        for key in ("active_count", "reserved_count", "scheduled_count")
    )
    if worker_unknown:
        if systemd_stopped and queued == 0 and unacked == 0:
            return reasons
        reasons.append(
            "celery inspection error: active/reserved/scheduled unknown "
            f"(active={celery.get('active_count')}, reserved={celery.get('reserved_count')}, "
            f"scheduled={celery.get('scheduled_count')}; workers_stopped={systemd_stopped})"
        )
    return reasons


def idle_refusal_reasons(fence, systemd, celery):
    reasons = []
    if fence.get("refusal_reason"):
        reasons.append(fence["refusal_reason"])
    elif not fence.get("ok"):
        reasons.append("ingest fence is not idle")
    if systemd.get("refusal_reason"):
        reasons.append(systemd["refusal_reason"])
    elif not systemd.get("ok"):
        reasons.append("local CaseScope writer-capable service is still active")
    reasons.extend(celery_refusal_reasons(celery, systemd_stopped=bool(systemd.get("ok"))))
    return reasons


def inspect_writers(*, require_idle, fence=None, systemd=None, celery=None):
    fence = inspect_fence() if fence is None else fence
    systemd = inspect_systemd() if systemd is None else systemd
    celery = inspect_celery() if celery is None else celery
    reasons = idle_refusal_reasons(fence, systemd, celery)
    report = {
        "fence": fence,
        "systemd": systemd,
        "celery": celery,
        "ok": not reasons,
        "refusal_reason": "; ".join(reasons) if reasons else None,
    }
    if require_idle and not report["ok"]:
        raise SystemExit(
            "Refusing to continue: application writers are not idle: "
            f"{report['refusal_reason']}"
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
        help=(
            "Fail closed unless ingest fence, writer-capable systemd units, and "
            "Celery are all proven idle. Inspection errors refuse."
        ),
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

    require_idle = bool(
        args.require_idle
        or (
            args.database in PRODUCTION_DATABASE_NAMES
            and args.apply_production
            and not args.dry_run
        )
    )

    def _idle_checker():
        return inspect_writers(require_idle=require_idle)

    writers = inspect_writers(require_idle=False)
    if require_idle:
        inspect_writers(require_idle=True)

    result = materialize_case_partition(
        client,
        args.case_id,
        allow_production=args.apply_production,
        dry_run=args.dry_run,
        require_writers_idle=_idle_checker if require_idle else None,
    )
    result["writers"] = writers
    if args.dry_run and not writers.get("ok"):
        result["idle_unsafe"] = True
        result["idle_refusal_reason"] = writers.get("refusal_reason")
    print(json.dumps(result, indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
