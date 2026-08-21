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


def _round_seconds(value):
    return round(float(value), 3)


def _round_ms(value):
    return round(float(value) * 1000.0, 3)


class FirstDurableHuntClock:
    """Capture first DURABLE -> Hunt visibility at protocol boundaries.

    Measurement/test instrumentation only. Production functions stay unchanged;
    callers wrap existing mark_batch_durable / project_generation_control_state.
    """

    def __init__(self, started):
        self.started = float(started)
        self.ingest_batch_id = None
        self.case_id = None
        self.source_ref_id = None
        self.source_generation = None
        self.batch_ordinal = None
        self.file = None
        self.hunt_total = None
        self.durable_monotonic = None
        self.projection_monotonic = None
        self.hunt_visible_monotonic = None

    def record_durable(self, *, batch, generation, now=None):
        if self.durable_monotonic is not None:
            return
        self.durable_monotonic = time.perf_counter() if now is None else float(now)
        self.ingest_batch_id = str(batch.ingest_batch_id)
        self.case_id = int(generation.case_id)
        self.source_ref_id = str(generation.source_ref_id)
        self.source_generation = int(generation.source_generation)
        self.batch_ordinal = int(batch.batch_ordinal)

    def record_projection_complete(self, now=None):
        if self.durable_monotonic is None or self.projection_monotonic is not None:
            return
        self.projection_monotonic = time.perf_counter() if now is None else float(now)

    def record_hunt_visible(self, *, ingest_batch_id, hunt_total, now=None):
        if self.hunt_visible_monotonic is not None:
            return
        if self.ingest_batch_id is None:
            raise AssertionError("Hunt visibility recorded before first DURABLE batch identity")
        visible_id = str(ingest_batch_id)
        if visible_id != str(self.ingest_batch_id):
            raise AssertionError(
                f"Hunt visibility batch {visible_id!r} does not match first DURABLE {self.ingest_batch_id!r}"
            )
        self.hunt_visible_monotonic = time.perf_counter() if now is None else float(now)
        self.hunt_total = int(hunt_total)

    def _matches_timed_generation(self, generation):
        if self.durable_monotonic is None:
            return False
        return (
            int(generation.case_id) == int(self.case_id)
            and str(generation.source_ref_id) == str(self.source_ref_id)
            and int(generation.source_generation) == int(self.source_generation)
        )

    def wrap_mark_batch_durable(self, original):
        def _wrapped(*, session, batch, verification):
            result = original(session=session, batch=batch, verification=verification)
            generation = getattr(result, "generation", None)
            if generation is None:
                from models.database_flow import EvidenceSourceGeneration
                generation = session.query(EvidenceSourceGeneration).filter_by(
                    id=result.generation_id
                ).one()
            self.record_durable(batch=result, generation=generation)
            return result
        return _wrapped

    def wrap_project_generation_control_state(self, original, probe_hunt):
        def _wrapped(clickhouse_client, session, generation):
            original(clickhouse_client, session, generation)
            if not self._matches_timed_generation(generation):
                return
            self.record_projection_complete()
            if self.hunt_visible_monotonic is not None:
                return
            probe_hunt(clickhouse_client, generation)
        return _wrapped

    def artifact(self):
        if self.durable_monotonic is None:
            raise AssertionError("first DURABLE timestamp was not captured")
        if self.hunt_visible_monotonic is None:
            raise AssertionError("Hunt visible timestamp was not captured")
        if self.hunt_visible_monotonic < self.durable_monotonic:
            raise AssertionError("Hunt visible timestamp occurs before first DURABLE")
        if self.durable_monotonic == self.started:
            raise AssertionError(
                "first_durable_to_hunt used benchmark-start origin instead of mark_batch_durable"
            )
        if self.ingest_batch_id is None:
            raise AssertionError("first DURABLE batch identity was not captured")
        ingest_start_to_hunt = self.hunt_visible_monotonic - self.started
        durable_to_hunt = self.hunt_visible_monotonic - self.durable_monotonic
        if abs(durable_to_hunt - ingest_start_to_hunt) <= 0.0:
            raise AssertionError(
                "first_durable_to_hunt collapsed onto ingest-start -> first-searchable"
            )
        projection_offset = None
        durable_to_projection_ms = None
        if self.projection_monotonic is not None:
            if self.projection_monotonic < self.durable_monotonic:
                raise AssertionError("projection complete timestamp occurs before first DURABLE")
            projection_offset = _round_seconds(self.projection_monotonic - self.started)
            durable_to_projection_ms = _round_ms(self.projection_monotonic - self.durable_monotonic)
        return {
            "time_to_first_searchable_managed_seconds": _round_seconds(ingest_start_to_hunt),
            "first_durable_to_hunt": {
                "seconds": _round_seconds(durable_to_hunt),
                "milliseconds": _round_ms(durable_to_hunt),
                "durable_to_hunt_ms": _round_ms(durable_to_hunt),
                "ingest_batch_id": self.ingest_batch_id,
                "case_id": self.case_id,
                "source_ref_id": self.source_ref_id,
                "source_generation": self.source_generation,
                "batch_ordinal": self.batch_ordinal,
                "durable_offset_seconds": _round_seconds(self.durable_monotonic - self.started),
                "projection_complete_offset_seconds": projection_offset,
                "hunt_visible_offset_seconds": _round_seconds(self.hunt_visible_monotonic - self.started),
                "durable_to_projection_ms": durable_to_projection_ms,
                "ingest_start_to_hunt_seconds": _round_seconds(ingest_start_to_hunt),
                "file": self.file,
                "hunt_total": self.hunt_total,
            },
        }


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
    from utils.manifest_protocol import mark_batch_durable as original_mark
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
    started = time.perf_counter()
    clock = FirstDurableHuntClock(started)

    def _probe_exact_batch_hunt(clickhouse_client, _generation):
        bridge = build_hunting_publication_bridge(alias="e")
        result = clickhouse_client.query(
            f"""
            SELECT count()
            FROM events AS e
            {bridge["join_sql"]}
            WHERE e.case_id = {{case_id:UInt32}}
              AND e.ingest_batch_id = {{ingest_batch_id:String}}
              AND e.source_ref_id = {{source_ref_id:String}}
              AND e.source_generation = {{source_generation:UInt32}}
              {bridge["where_sql"]}
            """,
            parameters={
                "case_id": int(clock.case_id),
                "ingest_batch_id": str(clock.ingest_batch_id),
                "source_ref_id": str(clock.source_ref_id),
                "source_generation": int(clock.source_generation),
            },
        )
        total = int(result.result_rows[0][0]) if result.result_rows else 0
        if total > 0:
            clock.record_hunt_visible(
                ingest_batch_id=clock.ingest_batch_id,
                hunt_total=total,
            )

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
            "utils.manifest_protocol.mark_batch_durable",
            side_effect=clock.wrap_mark_batch_durable(original_mark),
        ), patch(
            "utils.manifest_protocol.project_generation_control_state",
            side_effect=clock.wrap_project_generation_control_state(
                original_project,
                _probe_exact_batch_hunt,
            ),
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
                if clock.file is None and clock.hunt_visible_monotonic is not None:
                    clock.file = path.name
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

        measured = clock.artifact()
        if (
            measured["first_durable_to_hunt"]["seconds"]
            == measured["time_to_first_searchable_managed_seconds"]
        ):
            raise SystemExit(
                "first_durable_to_hunt collapsed onto ingest-start -> first-searchable"
            )
        payload = {
            "measured_at": _utc(),
            "baseline_sha": "16bede5ac622820492b09813146ea9b3a351ec8a",
            "version": "4.22.2",
            "postgres_database": pg_name,
            "clickhouse_database": ch_name,
            "corpus_dir": str(CORPUS),
            "file_count": len(files),
            "bytes": total_bytes,
            "events": events_total,
            "ingest_wall_seconds": ingest_wall,
            "ingest_seconds_per_gb": round(ingest_wall / gb, 3) if gb else None,
            "ingest_seconds_per_million_events": round(ingest_wall / (events_total / 1_000_000.0), 3) if events_total else None,
            "time_to_first_searchable_managed_seconds": measured["time_to_first_searchable_managed_seconds"],
            "first_durable_to_hunt": measured["first_durable_to_hunt"],
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
            "first_searchable_seconds": measured["time_to_first_searchable_managed_seconds"],
            "first_durable_to_hunt_seconds": measured["first_durable_to_hunt"]["seconds"],
            "first_durable_to_hunt_ms": measured["first_durable_to_hunt"]["milliseconds"],
            "timed_ingest_batch_id": measured["first_durable_to_hunt"]["ingest_batch_id"],
            "privacy_seconds": privacy_seconds,
            "reconciliation_seconds": recon_seconds,
            "assessment": recon.assessment,
        }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
