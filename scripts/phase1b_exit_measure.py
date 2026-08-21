#!/usr/bin/env python3
"""Phase 1B EXIT measurement harness.

Disposable managed-EVTX ingest of the existing Phase 0 corpus. This does not
start Phase 2 and does not create events_current.
"""
from __future__ import annotations

import json
import os
import resource
import statistics
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path("/opt/casescope")
sys.path.insert(0, str(ROOT))
CORPUS = Path("/opt/casescope-benchmark/phase0a_evtx")
ARTIFACT = ROOT / "docs/database_flow_phase1b/phase1b_exit_baseline.json"


def _utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def _rss_mb() -> float:
    return round(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024.0, 2)


def _assert_disposable() -> tuple[str, str]:
    pg = urlparse(os.environ.get("DATABASE_URL", "")).path.rsplit("/", 1)[-1]
    ch = os.environ.get("CLICKHOUSE_DATABASE", "")
    if not pg.startswith("phase1b_exit_") or not ch.startswith("phase1b_exit_"):
        raise SystemExit(f"Refusing non-disposable databases: pg={pg!r} ch={ch!r}")
    return pg, ch


def _percentile(values, pct):
    if not values:
        return None
    ordered = sorted(values)
    rank = (len(ordered) - 1) * (pct / 100.0)
    low = int(rank)
    high = min(low + 1, len(ordered) - 1)
    weight = rank - low
    return round(ordered[low] * (1.0 - weight) + ordered[high] * weight, 3)


def main() -> int:
    pg_name, ch_name = _assert_disposable()
    os.environ.setdefault("SECRET_KEY", "phase1b-exit-measure")
    os.environ["INGEST_FENCE_KEY_PREFIX"] = f"casescope:ingest_fence:disposable:{ch_name}"

    from unittest.mock import patch

    import clickhouse_connect
    from sqlalchemy import text

    from app import create_app
    from config import Config
    from migrations.add_events_table import EVENTS_SCHEMA
    from migrations.add_phase1b_tranche_b_manifest_protocol import (
        POSTGRES_INDEX_DDL,
        clickhouse_control_table_ddl,
    )
    from models.case import Case
    from models.case_file import CaseFile
    from models.client import Client
    from models.database import db
    from models.database_flow import IngestBatch, IngestBatchState
    from models.graph import GraphProjectionState
    from parsers.evtx_parser import EvtxECmdParser
    from routes.hunting_query_helpers import build_hunting_publication_bridge
    from tasks.celery_tasks import _process_managed_initial_case_file
    from utils.capability_watermarks import PRIVACY_ALIASES_V1
    from utils.completion_reconciler import ReconciliationHooks, reconcile_case_completion
    from utils.manifest_protocol import project_generation_control_state as original_project
    from utils.row_local_derivations import derive_privacy_aliases_for_durable_batch

    Config.PHASE1B_MANIFEST_PROTOCOL_ENABLED = True
    if not getattr(Config, "PHASE1B_MANIFEST_BATCH_SIZE", None):
        Config.PHASE1B_MANIFEST_BATCH_SIZE = 10000

    files = sorted(path for path in CORPUS.iterdir() if path.suffix.lower() == ".evtx")
    if not files:
        raise SystemExit(f"No EVTX files in {CORPUS}")
    total_bytes = sum(path.stat().st_size for path in files)

    ch_admin = clickhouse_connect.get_client(
        host=os.environ.get("CLICKHOUSE_HOST", "localhost"),
        port=int(os.environ.get("CLICKHOUSE_PORT", "8123")),
        username=os.environ.get("CLICKHOUSE_USER", "default"),
        password=os.environ.get("CLICKHOUSE_PASSWORD", ""),
        database="default",
    )
    ch_admin.command(f"CREATE DATABASE IF NOT EXISTS `{ch_name}`")
    ch = clickhouse_connect.get_client(
        host=os.environ.get("CLICKHOUSE_HOST", "localhost"),
        port=int(os.environ.get("CLICKHOUSE_PORT", "8123")),
        username=os.environ.get("CLICKHOUSE_USER", "default"),
        password=os.environ.get("CLICKHOUSE_PASSWORD", ""),
        database=ch_name,
    )
    ch.command(EVENTS_SCHEMA)
    for ddl in clickhouse_control_table_ddl():
        ch.command(ddl)

    app = create_app(run_startup_bootstrap=False, register_blueprints=False)
    first_searchable = {"seconds": None, "hunt_total": None, "file": None}
    started = time.perf_counter()

    def _project_and_probe(clickhouse_client, session, generation):
        original_project(clickhouse_client, session, generation)
        if first_searchable["seconds"] is not None:
            return
        bridge = build_hunting_publication_bridge(alias="e")
        result = clickhouse_client.query(
            f"""
            SELECT count()
            FROM events AS e
            {bridge["join_sql"]}
            WHERE e.case_id = {{case_id:UInt32}}{bridge["where_sql"]}
            """,
            parameters={"case_id": int(generation.case_id)},
        )
        total = int(result.result_rows[0][0]) if result.result_rows else 0
        if total > 0:
            first_searchable["seconds"] = round(time.perf_counter() - started, 3)
            first_searchable["hunt_total"] = total
            first_searchable["source_generation"] = int(generation.source_generation)

    with app.app_context():
        import models.audit_log as _audit_log
        import models.graph as _graph
        import models.privacy_alias as _privacy_alias
        import models.user as _user_models
        from models.database_flow import EvidenceSourceGeneration

        _ = (_audit_log, _graph, _privacy_alias, _user_models.User, EvidenceSourceGeneration)
        db.create_all()
        for ddl in POSTGRES_INDEX_DDL:
            db.session.execute(text(ddl))
        db.session.commit()

        client_row = Client(name="Phase1B Exit", code=f"P1B{int(time.time()) % 100000}", created_by="phase1b-exit")
        case = Case(
            uuid=str(uuid.uuid4()),
            name="Phase 1B exit baseline",
            company="PHASE1B",
            client=client_row,
            created_by="phase1b-exit",
            timezone="UTC",
        )
        db.session.add_all([client_row, case])
        db.session.commit()

        per_file = []
        events_total = 0
        with patch("tasks.celery_tasks.get_flask_app", return_value=app), patch(
            "utils.manifest_protocol.project_generation_control_state",
            side_effect=_project_and_probe,
        ):
            for path in files:
                case_file = CaseFile(
                    case_uuid=case.uuid,
                    filename=path.name,
                    original_filename=path.name,
                    file_path=str(path),
                    file_size=path.stat().st_size,
                    sha256_hash="0" * 64,
                    uploaded_by="phase1b-exit",
                )
                db.session.add(case_file)
                db.session.commit()
                parser = EvtxECmdParser(
                    case_id=case.id,
                    source_host="EXITHOST",
                    case_file_id=case_file.id,
                    case_tz="UTC",
                )
                file_started = time.perf_counter()
                result = _process_managed_initial_case_file(
                    parser=parser,
                    file_path=str(path),
                    case_id=case.id,
                    case_file_id=case_file.id,
                    clickhouse_client=ch,
                    task_id=f"phase1b-exit-{path.name}",
                )
                elapsed = round(time.perf_counter() - file_started, 3)
                events_total += int(result.events_count or 0)
                if first_searchable["file"] is None and first_searchable["seconds"] is not None:
                    first_searchable["file"] = path.name
                per_file.append({
                    "file": path.name,
                    "bytes": path.stat().st_size,
                    "events": int(result.events_count or 0),
                    "success": bool(result.success),
                    "errors": list(result.errors or []),
                    "wall_seconds": elapsed,
                })

        ingest_wall = round(time.perf_counter() - started, 3)
        gb = total_bytes / (1024 ** 3)
        privacy_started = time.perf_counter()
        privacy_batches = 0
        for batch in db.session.query(IngestBatch).filter_by(state=IngestBatchState.DURABLE).all():
            derive_privacy_aliases_for_durable_batch(
                session=db.session,
                ingest_batch_id=batch.ingest_batch_id,
                derivation_version=PRIVACY_ALIASES_V1,
                clickhouse_client=ch,
            )
            privacy_batches += 1
        db.session.commit()
        privacy_seconds = round(time.perf_counter() - privacy_started, 3)

        db.session.add(GraphProjectionState(
            case_id=case.id,
            case_uuid=case.uuid,
            status="completed",
            mode="ingest",
        ))
        db.session.commit()
        recon_started = time.perf_counter()
        recon = reconcile_case_completion(
            session=db.session,
            case_id=case.id,
            case_uuid=case.uuid,
            trigger_reason="phase1b_exit_measure",
            hooks=ReconciliationHooks(),
        )
        recon_seconds = round(time.perf_counter() - recon_started, 3)

        bridge = build_hunting_publication_bridge(alias="e")
        count_sql = f"""
            SELECT count()
            FROM events AS e
            {bridge["join_sql"]}
            WHERE e.case_id = {{case_id:UInt32}}{bridge["where_sql"]}
        """
        page_sql = f"""
            SELECT e.search_blob
            FROM events AS e
            {bridge["join_sql"]}
            WHERE e.case_id = {{case_id:UInt32}}{bridge["where_sql"]}
            ORDER BY COALESCE(e.timestamp_utc, e.timestamp) DESC
            LIMIT 50
        """
        params = {"case_id": case.id}
        hunt_count = []
        hunt_page = []
        last_summary = {}
        for _ in range(20):
            c_started = time.perf_counter()
            count_result = ch.query(count_sql, parameters=params)
            hunt_count.append(round((time.perf_counter() - c_started) * 1000.0, 3))
            p_started = time.perf_counter()
            ch.query(page_sql, parameters=params)
            hunt_page.append(round((time.perf_counter() - p_started) * 1000.0, 3))
            last_summary = dict(count_result.summary or {})

        explain = ch.query("EXPLAIN indexes = 1\n" + count_sql, parameters=params)
        explain_lines = [" ".join(str(col) for col in row) for row in explain.result_rows]

        payload = {
            "measured_at": _utc(),
            "baseline_sha": "9aaafaf3ce13ccb9eee7676a9ec636637b16b765",
            "version": "4.22.1",
            "postgres_database": pg_name,
            "clickhouse_database": ch_name,
            "corpus_dir": str(CORPUS),
            "file_count": len(files),
            "bytes": total_bytes,
            "events": events_total,
            "ingest_wall_seconds": ingest_wall,
            "ingest_seconds_per_gb": round(ingest_wall / gb, 3) if gb else None,
            "ingest_seconds_per_million_events": round(ingest_wall / (events_total / 1_000_000.0), 3) if events_total else None,
            "time_to_first_searchable_managed_seconds": first_searchable["seconds"],
            "first_durable_to_hunt": first_searchable,
            "privacy_alias_time_to_ready_seconds": privacy_seconds,
            "privacy_batches": privacy_batches,
            "completion_reconciliation_seconds": recon_seconds,
            "completion_reconciliation_assessment": recon.assessment,
            "hunt_count_ms": {
                "p50": _percentile(hunt_count, 50),
                "p95": _percentile(hunt_count, 95),
                "p99": _percentile(hunt_count, 99),
                "mean": round(statistics.mean(hunt_count), 3) if hunt_count else None,
                "samples": len(hunt_count),
            },
            "hunt_page_ms": {
                "p50": _percentile(hunt_page, 50),
                "p95": _percentile(hunt_page, 95),
                "p99": _percentile(hunt_page, 99),
                "mean": round(statistics.mean(hunt_page), 3) if hunt_page else None,
                "samples": len(hunt_page),
            },
            "hunt_last_summary": last_summary,
            "hunt_count_explain_indexes_1": explain_lines,
            "events_per_second": round(events_total / ingest_wall, 3) if ingest_wall else None,
            "ingest_mb_per_second": round((total_bytes / (1024 * 1024)) / ingest_wall, 3) if ingest_wall else None,
            "peak_rss_mb": _rss_mb(),
            "per_file": per_file,
            "corpus_deviation": {
                "preferred": "multi-host >=20 EVTX including large Security.evtx plus memory image and PCAP",
                "used": "existing Phase 0A authorized EVTX corpus: 8 files, 77,103,104 bytes, includes Security.evtx",
                "memory_image": False,
                "pcap": False,
            },
            "ioc_full_run": {
                "included": False,
                "reason": "Phase 1.5 IOC raw_json recall gate failed; no established passing full-run baseline was shipped",
            },
            "phase2_started": False,
            "events_current": False,
        }
        ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
        ARTIFACT.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        print(json.dumps({
            "artifact": str(ARTIFACT),
            "ingest_wall_seconds": ingest_wall,
            "events": events_total,
            "first_searchable_seconds": first_searchable["seconds"],
            "privacy_seconds": privacy_seconds,
            "reconciliation_seconds": recon_seconds,
            "assessment": recon.assessment,
        }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
