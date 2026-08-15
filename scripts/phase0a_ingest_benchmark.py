#!/usr/bin/env python3
"""Disposable Phase 0A EVTX ingest benchmark harness.

This harness is intentionally measurement-only. It refuses to run unless both
PostgreSQL and ClickHouse database names start with ``phase0a_ingest_``.

Canonical final-count procedure: drain ``events_buffer`` with
``OPTIMIZE TABLE events_buffer`` and confirm pending rows are 0 before any
final ``events`` count or ERK digest. ``OPTIMIZE TABLE events FINAL`` does
not flush Buffer and must not be treated as a drain.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import logging
import os
import resource
import statistics
import sys
import time
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


class Phase0AMetricCollector(logging.Handler):
    def __init__(self) -> None:
        super().__init__(level=logging.INFO)
        self.metrics: List[Dict[str, Any]] = []

    def emit(self, record: logging.LogRecord) -> None:
        if record.msg != "database_flow_phase0a_metric %s" or not record.args:
            return
        payload = record.args[0] if isinstance(record.args, tuple) else record.args
        if isinstance(payload, dict):
            self.metrics.append(dict(payload))
            return
        try:
            self.metrics.append(ast.literal_eval(str(payload)))
        except Exception:
            pass


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _database_name_from_url(url: str) -> str:
    return urlparse(url).path.rsplit("/", 1)[-1]


def _assert_disposable() -> None:
    pg_name = _database_name_from_url(os.environ.get("DATABASE_URL", ""))
    ch_name = os.environ.get("CLICKHOUSE_DATABASE", "")
    failures = []
    if not pg_name.startswith("phase0a_ingest_"):
        failures.append(f"PostgreSQL database is not disposable: {pg_name or '<unset>'}")
    if not ch_name.startswith("phase0a_ingest_"):
        failures.append(f"ClickHouse database is not disposable: {ch_name or '<unset>'}")
    if failures:
        raise SystemExit("Refusing Phase 0A benchmark:\n- " + "\n- ".join(failures))
    os.environ["INGEST_FENCE_KEY_PREFIX"] = f"casescope:ingest_fence:disposable:{ch_name}"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _rss_mb() -> float:
    return round(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024.0, 2)


def _ch_client(database: str | None = None):
    import clickhouse_connect

    return clickhouse_connect.get_client(
        host=os.environ.get("CLICKHOUSE_HOST", "localhost"),
        port=int(os.environ.get("CLICKHOUSE_PORT", "8123")),
        database=database or os.environ.get("CLICKHOUSE_DATABASE", "default"),
        username=os.environ.get("CLICKHOUSE_USER", "default"),
        password=os.environ.get("CLICKHOUSE_PASSWORD", ""),
    )


def _table_exists(client, table_name: str) -> bool:
    result = client.query(
        """
        SELECT count()
        FROM system.tables
        WHERE database = currentDatabase()
          AND name = {table_name:String}
        """,
        parameters={"table_name": table_name},
    )
    return bool(result.result_rows and int(result.result_rows[0][0] or 0))


def _prepare_clickhouse() -> Dict[str, Any]:
    from migrations.add_events_table import EVENTS_SCHEMA, events_buffer_schema
    from migrations.reset_events_wide_part_settings import reset_events_forced_wide_part_settings

    database = os.environ["CLICKHOUSE_DATABASE"]
    admin = _ch_client("default")
    admin.command(f"CREATE DATABASE IF NOT EXISTS `{database}`")
    client = _ch_client(database)
    client.command(EVENTS_SCHEMA)
    created_buffer = False
    if os.environ.get("PHASE1_CREATE_EVENTS_BUFFER", "").lower() in {"1", "true", "yes"}:
        client.command(events_buffer_schema(client))
        created_buffer = True
    settings_reset = reset_events_forced_wide_part_settings(client, allow_production=False)
    engine_full = client.query(
        "SELECT engine_full FROM system.tables WHERE database = currentDatabase() AND name = 'events'"
    ).result_rows[0][0]
    return {
        "settings_reset": settings_reset,
        "events_engine_full": engine_full,
        "events_buffer_created": created_buffer,
    }


def _parts_census(client) -> Dict[str, Any]:
    rows = client.query(
        """
        SELECT
            part_type,
            count() AS parts,
            sum(rows) AS rows,
            sum(bytes_on_disk) AS bytes_on_disk
        FROM system.parts
        WHERE database = currentDatabase()
          AND table = 'events'
          AND active
        GROUP BY part_type
        ORDER BY part_type
        """
    ).result_rows
    by_type = {
        str(part_type): {
            "parts": int(parts or 0),
            "rows": int(row_count or 0),
            "bytes_on_disk": int(bytes_on_disk or 0),
        }
        for part_type, parts, row_count, bytes_on_disk in rows
    }
    mutations = client.query(
        "SELECT count() FROM system.mutations WHERE database = currentDatabase() AND table IN ('events', 'events_buffer')"
    ).result_rows[0][0]
    active = client.query(
        "SELECT count(), sum(rows), sum(bytes_on_disk) FROM system.parts WHERE database = currentDatabase() AND table = 'events' AND active"
    ).result_rows[0]
    return {
        "active_parts": int(active[0] or 0),
        "active_rows": int(active[1] or 0),
        "active_bytes": int(active[2] or 0),
        "mutation_count": int(mutations or 0),
        "by_part_type": by_type,
    }


def _erk_digest(client, case_id: int) -> Dict[str, Any]:
    result = client.query(
        """
        SELECT evidence_record_key
        FROM events
        WHERE case_id = {case_id:UInt32}
        ORDER BY evidence_record_key
        """,
        parameters={"case_id": case_id},
    )
    keys = [str(row[0]) for row in result.result_rows]
    digest = hashlib.sha256("\n".join(keys).encode("utf-8")).hexdigest()
    return {"count": len(keys), "sha256": digest}


def _alias_vault_snapshot(app, case_id: int) -> Dict[str, Any]:
    from models.privacy_alias import PrivacyAlias

    with app.app_context():
        rows = PrivacyAlias.query.filter_by(case_id=case_id).all()
        identities = sorted((row.entity_type, row.normalized_value) for row in rows)
    digest = hashlib.sha256(
        json.dumps(identities, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    by_type: Dict[str, int] = defaultdict(int)
    for entity_type, _value in identities:
        by_type[entity_type] += 1
    return {
        "count": len(identities),
        "sha256": digest,
        "by_type": dict(sorted(by_type.items())),
    }


def _create_app_context(storage_root: Path):
    os.environ.setdefault("SECRET_KEY", "phase0a-disposable-secret")
    os.environ.setdefault("DEFAULT_ADMIN_PASSWORD", "phase0a-not-used")
    storage_root.mkdir(parents=True, exist_ok=True)

    from config import Config

    Config.STORAGE_FOLDER = str(storage_root)
    Config.STAGING_FOLDER = str(storage_root / "staging")
    Config.UPLOAD_FOLDER = str(storage_root / "uploads")

    from app import create_app
    from models.database import db

    app = create_app(run_startup_bootstrap=False, register_blueprints=False)
    with app.app_context():
        # Import models needed by db.create_all and ingestion side effects.
        from models.audit_log import AuditLog  # noqa: F401
        from models.case import Case  # noqa: F401
        from models.case_file import CaseFile  # noqa: F401
        import models.graph  # noqa: F401
        import models.privacy_alias  # noqa: F401
        import models.user  # noqa: F401

        db.create_all()
    return app, db


def _prepare_case(app, db, files: List[Path]) -> tuple[int, str, Dict[str, int]]:
    from models.case import Case
    from models.case_file import CaseFile, ExtractionStatus, FileStatus

    case_uuid = str(uuid.uuid4())
    case_file_ids: Dict[str, int] = {}
    with app.app_context():
        case = Case(
            uuid=case_uuid,
            name="Phase 0A EVTX disposable benchmark",
            company="PHASE0A",
            description="Disposable Phase 0A EVTX benchmark case",
            created_by="phase0a",
            timezone="UTC",
        )
        db.session.add(case)
        db.session.flush()
        for path in files:
            case_file = CaseFile(
                case_uuid=case_uuid,
                filename=path.name,
                original_filename=path.name,
                file_path=str(path),
                source_path=str(path),
                file_size=path.stat().st_size,
                sha256_hash=_sha256(path),
                hostname="",
                file_type="EVTX",
                upload_source="phase0a_benchmark",
                is_archive=False,
                is_extracted=True,
                extraction_status=ExtractionStatus.NA,
                status=FileStatus.NEW,
                retention_state="phase0a_disposable",
                uploaded_by="phase0a",
            )
            db.session.add(case_file)
            db.session.flush()
            case_file_ids[str(path)] = int(case_file.id)
        db.session.commit()
        return int(case.id), case_uuid, case_file_ids


def _metric_summary(metrics: List[Dict[str, Any]]) -> Dict[str, Any]:
    by_stage: Dict[str, Dict[str, Any]] = {}
    grouped: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for metric in metrics:
        grouped[str(metric.get("stage", "unknown"))].append(metric)
    for stage, rows in sorted(grouped.items()):
        durations = [float(row["duration_ms"]) for row in rows if row.get("duration_ms") is not None]
        by_stage[stage] = {
            "count": len(rows),
            "duration_ms_total": round(sum(durations), 3) if durations else None,
            "duration_ms_median": round(statistics.median(durations), 3) if durations else None,
            "duration_ms_max": round(max(durations), 3) if durations else None,
            "events_inserted": sum(int(row.get("events_inserted") or 0) for row in rows),
            "events_parsed": sum(int(row.get("events_parsed") or 0) for row in rows),
            "batch_rows": sum(int(row.get("batch_row_count") or 0) for row in rows),
            "estimated_bytes": sum(int(row.get("estimated_bytes") or 0) for row in rows),
            "alias_extract_duration_ms": round(sum(float(row.get("alias_extract_duration_ms") or 0) for row in rows), 3),
            "jsonl_rows_consumed": sum(int(row.get("jsonl_rows_consumed") or 0) for row in rows),
            "outer_json_decode_ms": round(sum(float(row.get("outer_json_decode_ms") or 0) for row in rows), 3),
            "nested_payload_json_decode_ms": round(sum(float(row.get("nested_payload_json_decode_ms") or 0) for row in rows), 3),
            "normalization_ms": round(sum(float(row.get("normalization_ms") or 0) for row in rows), 3),
            "search_blob_construction_ms": round(sum(float(row.get("search_blob_construction_ms") or 0) for row in rows), 3),
            "probe_hit_count": sum(1 for row in rows if row.get("probe_hit")),
            "probe_miss_count": sum(1 for row in rows if row.get("probe_miss")),
            "candidate_count": sum(int(row.get("candidate_count") or 0) for row in rows),
        }
    return by_stage


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus-dir", required=True)
    parser.add_argument("--output-json", required=True)
    parser.add_argument("--storage-root", required=True)
    parser.add_argument("--batch-size", type=int, default=None)
    parser.add_argument(
        "--evtx-group-mode",
        action="store_true",
        help="Parse the corpus as bounded EVTX directory groups (Phase 1.7)",
    )
    parser.add_argument(
        "--evtx-eager-first",
        action="store_true",
        help="Parse the first queued EVTX with the per-file path, remaining as directory groups",
    )
    parser.add_argument("--evtx-target-files", type=int, default=None)
    parser.add_argument("--evtx-target-bytes", type=int, default=None)
    parser.add_argument("--evtx-order", choices=["queue", "smallest"], default="queue")
    args = parser.parse_args()

    _assert_disposable()
    corpus_dir = Path(args.corpus_dir)
    files = sorted(corpus_dir.glob("*.evtx"))
    if not files:
        raise SystemExit(f"No EVTX files found in {corpus_dir}")

    collector = Phase0AMetricCollector()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    for logger_name in ("casescope.database_flow.ingest", "utils.ingest_metrics"):
        metric_logger = logging.getLogger(logger_name)
        metric_logger.addHandler(collector)
        metric_logger.setLevel(logging.INFO)

    started = time.perf_counter()
    result: Dict[str, Any] = {
        "started_at": _utc_now(),
        "corpus_dir": str(corpus_dir),
        "python_executable": sys.executable,
        "postgres_database": _database_name_from_url(os.environ.get("DATABASE_URL", "")),
        "clickhouse_database": os.environ.get("CLICKHOUSE_DATABASE"),
        "source_files": [
            {"path": str(path), "size_bytes": path.stat().st_size, "sha256": _sha256(path)}
            for path in files
        ],
    }

    clickhouse_setup = _prepare_clickhouse()
    app, db = _create_app_context(Path(args.storage_root))
    case_id, case_uuid, case_file_ids = _prepare_case(app, db, files)
    result.update({
        "case_id": case_id,
        "case_uuid": case_uuid,
        "case_file_ids": case_file_ids,
        "clickhouse_setup": clickhouse_setup,
    })

    from parsers.registry import process_file, process_evtx_group
    from utils.clickhouse import delete_file_events, get_fresh_client
    from utils.evtx_directory_mode import (
        EVTX_DIRECTORY_GROUP_MAX_BYTES,
        EVTX_DIRECTORY_GROUP_MAX_FILES,
        EvtxGroupMember,
        plan_evtx_parse_units,
    )

    ch = get_fresh_client()
    result["clickhouse_before"] = _parts_census(ch)
    result["evtx_group_mode"] = bool(args.evtx_group_mode)
    result["evtx_eager_first"] = bool(args.evtx_eager_first)
    result["evtx_target_files"] = args.evtx_target_files
    result["evtx_order"] = args.evtx_order

    per_file = []
    first_physical_latency = None
    first_searchable_latency = None
    extra = {}
    if args.batch_size:
        extra["batch_size"] = int(args.batch_size)

    use_plan = bool(args.evtx_group_mode or args.evtx_eager_first or args.evtx_target_files)

    def _event_count() -> int:
        return int(
            ch.query(
                "SELECT count() FROM events WHERE case_id = {case_id:UInt32}",
                parameters={"case_id": case_id},
            ).result_rows[0][0] or 0
        )

    if use_plan:
        members = [
            EvtxGroupMember(
                file_path=str(path),
                case_file_id=case_file_ids[str(path)],
                source_host=path.stem,
                source_file=path.name,
                size_bytes=path.stat().st_size,
            )
            for path in files
        ]
        target_files = int(args.evtx_target_files or EVTX_DIRECTORY_GROUP_MAX_FILES)
        target_bytes = int(args.evtx_target_bytes or EVTX_DIRECTORY_GROUP_MAX_BYTES)
        units = plan_evtx_parse_units(
            members,
            eager_first=bool(args.evtx_eager_first),
            target_files=target_files,
            target_bytes=target_bytes,
            order=args.evtx_order,
        )
        result["evtx_plan"] = [
            {
                "mode": unit.mode,
                "files": [member.source_file for member in unit.members],
                "case_file_ids": [member.case_file_id for member in unit.members],
                "bytes": unit.size_bytes,
            }
            for unit in units
        ]
        group_timeline = []
        parsed_by_path = {}
        for unit_index, unit in enumerate(units):
            cleanup_ms = 0.0
            for member in unit.members:
                cleanup_started = time.perf_counter()
                delete_file_events(member.case_file_id, wait=True, client=ch)
                cleanup_ms += (time.perf_counter() - cleanup_started) * 1000.0
            metric_at = len(collector.metrics)
            unit_started = time.perf_counter()
            with app.app_context():
                if unit.mode == "per_file":
                    member = unit.members[0]
                    parsed_list = [process_file(
                        file_path=member.file_path,
                        case_id=case_id,
                        source_host=member.source_host,
                        case_file_id=member.case_file_id,
                        clickhouse_client=ch,
                        case_tz="UTC",
                        parser_hints=["evtx"],
                        force_parser=True,
                        **extra,
                    )]
                else:
                    parsed_list = process_evtx_group(
                        list(unit.members),
                        case_id=case_id,
                        clickhouse_client=ch,
                        case_tz="UTC",
                        **extra,
                    )
            unit_wall = time.perf_counter() - unit_started
            unit_complete_at = time.perf_counter() - started
            first_event_from_metric = None
            first_insert_from_metric = None
            for metric in collector.metrics[metric_at:]:
                if metric.get("stage") != "process_evtx_group_total":
                    continue
                if metric.get("first_event_ms") is not None:
                    first_event_from_metric = (unit_started - started) + (float(metric["first_event_ms"]) / 1000.0)
                if metric.get("first_insert_ms") is not None:
                    first_insert_from_metric = (unit_started - started) + (float(metric["first_insert_ms"]) / 1000.0)
            physical_count = _event_count()
            searchable_at = first_insert_from_metric
            if searchable_at is None and physical_count and first_physical_latency is None:
                searchable_at = unit_complete_at
            elif searchable_at is None and physical_count and first_physical_latency is not None:
                searchable_at = unit_complete_at
            if first_physical_latency is None and physical_count:
                first_physical_latency = searchable_at if searchable_at is not None else unit_complete_at
                first_searchable_latency = first_physical_latency
            group_timeline.append({
                "unit_index": unit_index,
                "mode": unit.mode,
                "files": [member.source_file for member in unit.members],
                "bytes": unit.size_bytes,
                "unit_wall_seconds": round(unit_wall, 3),
                "complete_at_seconds": round(unit_complete_at, 3),
                "searchable_at_seconds": None if searchable_at is None else round(searchable_at, 3),
                "first_parsed_event_seconds": None if first_event_from_metric is None else round(first_event_from_metric, 3),
                "events_after": int(physical_count),
            })
            for member, parsed in zip(unit.members, parsed_list):
                parsed_by_path[member.file_path] = parsed
                per_file.append(
                    {
                        "path": member.file_path,
                        "case_file_id": member.case_file_id,
                        "size_bytes": member.size_bytes,
                        "events_inserted": parsed.events_count,
                        "success": parsed.success,
                        "artifact_type": parsed.artifact_type,
                        "duration_seconds": round(unit_wall, 3),
                        "cleanup_delete_ms": round(cleanup_ms, 3),
                        "errors": parsed.errors,
                        "warnings": parsed.warnings,
                        "directory_group": unit.mode == "directory",
                        "plan_unit_index": unit_index,
                    }
                )
        result["group_timeline"] = group_timeline
        result["directory_first_parsed_event_seconds"] = next(
            (row["first_parsed_event_seconds"] for row in group_timeline if row.get("first_parsed_event_seconds") is not None),
            None,
        )
        result["directory_group_complete_seconds"] = round(time.perf_counter() - started, 3)
        result["second_group_searchable_seconds"] = (
            group_timeline[1]["searchable_at_seconds"] if len(group_timeline) > 1 else None
        )
        result["completion_tail_seconds"] = (
            None if first_searchable_latency is None
            else round((time.perf_counter() - started) - first_searchable_latency, 3)
        )
    else:
        for path in files:
            file_started = time.perf_counter()
            case_file_id = case_file_ids[str(path)]
            cleanup_started = time.perf_counter()
            delete_file_events(case_file_id, wait=True, client=ch)
            cleanup_ms = (time.perf_counter() - cleanup_started) * 1000.0
            with app.app_context():
                parsed = process_file(
                    file_path=str(path),
                    case_id=case_id,
                    source_host=path.stem,
                    case_file_id=case_file_id,
                    clickhouse_client=ch,
                    case_tz="UTC",
                    parser_hints=["evtx"],
                    force_parser=True,
                    **extra,
                )
            physical_count = ch.query(
                "SELECT count() FROM events WHERE case_id = {case_id:UInt32}",
                parameters={"case_id": case_id},
            ).result_rows[0][0]
            if first_physical_latency is None and physical_count:
                first_physical_latency = time.perf_counter() - started
                first_searchable_latency = first_physical_latency
            per_file.append(
                {
                    "path": str(path),
                    "case_file_id": case_file_id,
                    "size_bytes": path.stat().st_size,
                    "events_inserted": parsed.events_count,
                    "success": parsed.success,
                    "artifact_type": parsed.artifact_type,
                    "duration_seconds": round(time.perf_counter() - file_started, 3),
                    "cleanup_delete_ms": round(cleanup_ms, 3),
                    "errors": parsed.errors,
                    "warnings": parsed.warnings,
                }
            )

    result["clickhouse_after_insert"] = _parts_census(ch)
    result["alias_vault_before_completion"] = _alias_vault_snapshot(app, case_id)

    buffer_flush_started = time.perf_counter()
    events_before_buffer_flush = int(
        ch.query("SELECT count() FROM events WHERE case_id = {case_id:UInt32}", parameters={"case_id": case_id}).result_rows[0][0] or 0
    )
    buffer_exists = _table_exists(ch, "events_buffer")
    buffer_visible_before = 0
    pending_after = 0
    events_after_buffer_flush = events_before_buffer_flush
    buffer_visible_after = 0
    if buffer_exists:
        buffer_visible_before = int(
            ch.query("SELECT count() FROM events_buffer WHERE case_id = {case_id:UInt32}", parameters={"case_id": case_id}).result_rows[0][0] or 0
        )
        ch.command("OPTIMIZE TABLE events_buffer")
        events_after_buffer_flush = int(
            ch.query("SELECT count() FROM events WHERE case_id = {case_id:UInt32}", parameters={"case_id": case_id}).result_rows[0][0] or 0
        )
        buffer_visible_after = int(
            ch.query("SELECT count() FROM events_buffer WHERE case_id = {case_id:UInt32}", parameters={"case_id": case_id}).result_rows[0][0] or 0
        )
        pending_after = max(buffer_visible_after - events_after_buffer_flush, 0)
        if pending_after:
            raise SystemExit(
                "events_buffer still has pending rows after OPTIMIZE TABLE events_buffer; "
                f"refusing final benchmark counts (pending={pending_after})"
            )
    buffer_flush_ms = (time.perf_counter() - buffer_flush_started) * 1000.0
    result["erk_before_dedup"] = _erk_digest(ch, case_id)

    optimize_started = time.perf_counter()
    ch.command("OPTIMIZE TABLE events FINAL")
    buffer_optimize_ms = (time.perf_counter() - optimize_started) * 1000.0

    completion = {
        "events_buffer_exists": buffer_exists,
        "events_buffer_flush_ms": round(buffer_flush_ms, 3) if buffer_exists else 0.0,
        "events_count_before_buffer_flush": events_before_buffer_flush,
        "events_buffer_visible_before_flush": buffer_visible_before,
        "events_count_after_buffer_flush": events_after_buffer_flush,
        "events_buffer_pending_after_flush": pending_after,
        "buffer_optimize_ms": round(buffer_optimize_ms, 3),
        "buffer_visibility_note": (
            "Direct events inserts do not use events_buffer. "
            "OPTIMIZE TABLE events FINAL is not a Buffer drain."
            if not buffer_exists
            else (
                "OPTIMIZE TABLE events FINAL does not flush events_buffer. "
                "Final counts are taken only after OPTIMIZE TABLE events_buffer."
            )
        ),
    }
    try:
        from utils.event_deduplication import deduplicate_case_events

        dedup_started = time.perf_counter()
        completion["dedup"] = deduplicate_case_events(
            case_id=case_id,
            case_uuid=case_uuid,
            track_progress=False,
        )
        completion["dedup_ms"] = round((time.perf_counter() - dedup_started) * 1000.0, 3)
    except Exception as exc:
        completion["dedup_error"] = str(exc)
    try:
        from utils.known_systems_discovery import discover_known_systems

        systems_started = time.perf_counter()
        with app.app_context():
            completion["known_systems"] = discover_known_systems(case_id, case_uuid, track_progress=False)
        completion["known_systems_ms"] = round((time.perf_counter() - systems_started) * 1000.0, 3)
    except Exception as exc:
        completion["known_systems_error"] = str(exc)
    try:
        from utils.known_users_discovery import discover_known_users

        users_started = time.perf_counter()
        with app.app_context():
            completion["known_users"] = discover_known_users(case_id, case_uuid, track_progress=False)
        completion["known_users_ms"] = round((time.perf_counter() - users_started) * 1000.0, 3)
    except Exception as exc:
        completion["known_users_error"] = str(exc)
    completion["mitre"] = "NOT REPRODUCED - parse_file harness does not run parse_file_task Hayabusa MITRE match insert/queue"
    completion["embeddings"] = "NOT REPRODUCED - disposable harness does not enqueue embedding workers"
    completion["graph"] = "NOT REPRODUCED - disposable harness does not enqueue graph materialization workers"

    total_wall = time.perf_counter() - started
    total_events = sum(item["events_inserted"] for item in per_file)
    total_bytes = sum(item["size_bytes"] for item in per_file)
    final_count = ch.query(
        "SELECT count() FROM events WHERE case_id = {case_id:UInt32}",
        parameters={"case_id": case_id},
    ).result_rows[0][0]
    parts_after = _parts_census(ch)

    result.update(
        {
            "completed_at": _utc_now(),
            "wall_time_seconds": round(total_wall, 3),
            "file_count": len(files),
            "total_source_bytes": total_bytes,
            "total_source_mb": round(total_bytes / (1024 * 1024), 3),
            "events_inserted": int(final_count),
            "events_parsed_before_dedup": total_events,
            "events_per_second": round((total_events / total_wall), 3) if total_wall else None,
            "source_mb_per_second": round((total_bytes / (1024 * 1024) / total_wall), 3) if total_wall else None,
            "time_to_first_physical_row_seconds": round(first_physical_latency, 3) if first_physical_latency else None,
            "time_to_first_current_searchable_event_seconds": round(first_searchable_latency, 3) if first_searchable_latency else None,
            "current_searchable_note": "Current product search reads events; in this disposable process first searchable was treated as first observed events row in the disposable events table.",
            "per_file": per_file,
            "completion": completion,
            "metrics": collector.metrics,
            "metric_summary": _metric_summary(collector.metrics),
            "peak_rss_mb": _rss_mb(),
            "cpu_self_seconds": round(resource.getrusage(resource.RUSAGE_SELF).ru_utime + resource.getrusage(resource.RUSAGE_SELF).ru_stime, 3),
            "cpu_children_seconds": round(resource.getrusage(resource.RUSAGE_CHILDREN).ru_utime + resource.getrusage(resource.RUSAGE_CHILDREN).ru_stime, 3),
            "clickhouse_after": parts_after,
            "erk_after_dedup": _erk_digest(ch, case_id),
            "alias_vault_after_completion": _alias_vault_snapshot(app, case_id),
            "errors": [err for item in per_file for err in item.get("errors", [])],
            "retries": 0,
        }
    )

    Path(args.output_json).parent.mkdir(parents=True, exist_ok=True)
    Path(args.output_json).write_text(json.dumps(result, indent=2, default=str) + "\n")
    print(json.dumps({k: result[k] for k in ("wall_time_seconds", "file_count", "total_source_bytes", "events_parsed_before_dedup", "events_inserted", "events_per_second", "source_mb_per_second", "peak_rss_mb")}, indent=2))
    return 0 if not result["errors"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
