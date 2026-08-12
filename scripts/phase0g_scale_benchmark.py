#!/usr/bin/env python3
"""Disposable Phase 0G scale corpus and benchmark harness."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import resource
import subprocess
import sys
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlparse

import clickhouse_connect

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _git_sha() -> str:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"],
            cwd=str(ROOT),
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except Exception:
        return "UNKNOWN"


def _rss_mb() -> float:
    return round(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024.0, 2)


def _erk(marker: str, logical_index: int) -> str:
    digest = hashlib.sha256(f"{marker}|event|{logical_index}".encode("utf-8")).hexdigest()
    return f"erk:v2:{digest}"


def _disposable_name(value: str | None) -> bool:
    return bool(value) and value.lower().startswith("phase0g_")


def _database_name_from_url(url: str) -> str:
    parsed = urlparse(url)
    return parsed.path.rsplit("/", 1)[-1]


def _assert_disposable(args) -> None:
    if not args.marker.startswith("PHASE0G_"):
        raise SystemExit("--marker must start with PHASE0G_")
    pg_name = _database_name_from_url(os.environ.get("DATABASE_URL", ""))
    ch_name = args.clickhouse_database or os.environ.get("CLICKHOUSE_DATABASE", "")
    failures = []
    if not _disposable_name(pg_name):
        failures.append(f"PostgreSQL database is not disposable: {pg_name or '<unset>'}")
    if not _disposable_name(ch_name):
        failures.append(f"ClickHouse database is not disposable: {ch_name or '<unset>'}")
    if failures:
        raise SystemExit("Refusing Phase 0G runtime benchmark:\n- " + "\n- ".join(failures))


def _ch_client(database: str | None = None):
    return clickhouse_connect.get_client(
        host=os.environ.get("CLICKHOUSE_HOST", "localhost"),
        port=int(os.environ.get("CLICKHOUSE_PORT", "8123")),
        database=database or os.environ.get("CLICKHOUSE_DATABASE", "default"),
        username=os.environ.get("CLICKHOUSE_USER", "default"),
        password=os.environ.get("CLICKHOUSE_PASSWORD", ""),
    )


def _prepare_clickhouse(database: str) -> None:
    admin = _ch_client("default")
    admin.command(f"CREATE DATABASE IF NOT EXISTS `{database}`")
    os.environ["CLICKHOUSE_DATABASE"] = database
    from migrations.add_events_table import EVENTS_SCHEMA

    client = _ch_client(database)
    client.command(EVENTS_SCHEMA)


def _create_app_context():
    os.environ.setdefault("SECRET_KEY", "phase0g-disposable-secret")
    os.environ.setdefault("DEFAULT_ADMIN_PASSWORD", "phase0g-not-used")
    storage_root = os.environ.get("PHASE0G_STORAGE_ROOT", "/tmp/casescope-phase0g-storage")
    Path(storage_root).mkdir(parents=True, exist_ok=True)
    from config import Config
    Config.STORAGE_FOLDER = storage_root
    from app import create_app
    from models.database import db

    app = create_app(run_startup_bootstrap=False, register_blueprints=False)
    with app.app_context():
        from models.audit_log import AuditLog  # noqa: F401
        from models.case import Case  # noqa: F401
        from models.case_report import CaseReport  # noqa: F401
        from models.graph import GraphEntity, GraphEntityObservation, GraphRelationship, GraphRelationshipEvidence  # noqa: F401
        from models.graph_saved_view import GraphSavedView  # noqa: F401
        from models.investigation_thread import (  # noqa: F401
            InvestigationThread,
            InvestigationThreadEntity,
            InvestigationThreadEvidence,
            InvestigationThreadNote,
            InvestigationThreadRelationship,
            InvestigationThreadReportSnapshot,
        )
        from models.user import User  # noqa: F401

        db.create_all()
    return app, db


def _insert_events(client, *, case_id: int, marker: str, total: int, chunk_size: int) -> dict:
    columns = [
        "case_id",
        "artifact_type",
        "timestamp",
        "timestamp_utc",
        "source_file",
        "source_path",
        "source_host",
        "case_file_id",
        "event_id",
        "channel",
        "provider",
        "record_id",
        "level",
        "username",
        "domain",
        "sid",
        "logon_type",
        "logon_id",
        "process_name",
        "process_path",
        "process_id",
        "parent_process",
        "parent_pid",
        "command_line",
        "thread_id",
        "target_path",
        "file_hash_sha256",
        "src_ip",
        "dst_ip",
        "src_port",
        "dst_port",
        "raw_json",
        "search_blob",
        "extra_fields",
        "parser_version",
        "evidence_record_key",
        "evidence_identity_version",
        "evidence_identity_quality",
    ]
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    event_ids = ["4688", "4689", "1", "5", "5156"]
    artifact_types = ["evtx_security", "evtx_sysmon", "generic_json", "pcap_zeek", "memory_artifact"]
    duplicate_rows = 0
    duplicate_erk = None
    first_erk = None
    process_creations = 0
    inserted = 0

    while inserted < total:
        batch_count = min(chunk_size, total - inserted)
        rows = []
        for offset in range(batch_count):
            row_number = inserted + offset
            duplicate = row_number > 0 and row_number % 10000 == 0
            logical_index = row_number - 1 if duplicate else row_number
            erk = _erk(marker, logical_index)
            if first_erk is None:
                first_erk = erk
            if duplicate:
                duplicate_rows += 1
                duplicate_erk = erk
            event_id = event_ids[row_number % len(event_ids)]
            artifact_type = artifact_types[row_number % len(artifact_types)]
            host = f"HOST-{row_number % 100:03d}"
            user = f"user{row_number % 200:03d}"
            ts = start + timedelta(milliseconds=row_number * 250)
            pid = 1000 + (row_number % 5000)
            parent_pid = 1000 + ((row_number - 17) % 5000)
            if event_id in {"4688", "1"}:
                process_creations += 1
            rows.append(
                [
                    case_id,
                    artifact_type,
                    ts,
                    ts,
                    f"{artifact_type}_{row_number % 16}.log",
                    f"/phase0g/{marker}/{artifact_type}_{row_number % 16}.log",
                    host,
                    (row_number % 8) + 1,
                    event_id,
                    "Security" if event_id in {"4688", "4689"} else "Microsoft-Windows-Sysmon/Operational",
                    "Microsoft-Windows-Security-Auditing" if event_id in {"4688", "4689"} else "Sysmon",
                    row_number + 1,
                    "Information",
                    user,
                    f"DOMAIN{row_number % 7}",
                    f"S-1-5-21-1000-2000-3000-{1000 + (row_number % 200)}",
                    2 + (row_number % 9),
                    hex(row_number % 500),
                    f"proc{row_number % 300}.exe",
                    f"C:\\Windows\\System32\\proc{row_number % 300}.exe",
                    pid,
                    f"parent{row_number % 100}.exe",
                    parent_pid,
                    f"proc{row_number % 300}.exe --marker {marker} --row {row_number}",
                    row_number % 4096,
                    f"C:\\Temp\\phase0g\\file{row_number % 1000}.dll",
                    hashlib.sha256(f"file|{row_number % 1000}".encode("utf-8")).hexdigest(),
                    f"10.{row_number % 200}.{(row_number // 200) % 200}.{(row_number % 250) + 1}",
                    f"172.16.{row_number % 200}.{((row_number // 7) % 250) + 1}",
                    1024 + (row_number % 50000),
                    80 if row_number % 3 else 443,
                    json.dumps({"phase0g_marker": marker, "row": row_number}, separators=(",", ":")),
                    f"{marker} {host} {user} proc{row_number % 300}.exe {event_id}",
                    json.dumps({"source_class": artifact_type, "logical_index": logical_index}, separators=(",", ":")),
                    "phase0g:v1",
                    erk,
                    "v2",
                    "native-or-content",
                ]
            )
        client.insert("events", rows, column_names=columns)
        inserted += batch_count
        print(json.dumps({"event": "clickhouse_insert_progress", "inserted": inserted, "target": total}))
    return {
        "first_erk": first_erk,
        "duplicate_erk": duplicate_erk,
        "physical_duplicate_rows": duplicate_rows,
        "process_creation_events": process_creations,
    }


def _build_graph(app, db, *, marker: str):
    from models.case import Case
    from models.graph import GraphEntity, GraphEntityObservation, GraphRelationship, GraphRelationshipEvidence
    from utils.graph_identity import GraphDerivationType, GraphSupportState, GraphValidationState

    with app.app_context():
        case_a = Case(
            uuid=str(uuid.uuid4()),
            name=f"{marker} million-event runtime case",
            company="PHASE0G",
            description="Disposable Phase 0G scale benchmark case",
            created_by="phase0g",
            timezone="UTC",
        )
        case_b = Case(
            uuid=str(uuid.uuid4()),
            name=f"{marker} cross-case control",
            company="PHASE0G",
            description="Disposable Phase 0G cross-case control",
            created_by="phase0g",
            timezone="UTC",
        )
        db.session.add_all([case_a, case_b])
        db.session.flush()

        entity_specs = []
        for i in range(100):
            entity_specs.append(("HOST", f"host:{i:03d}", f"HOST-{i:03d}"))
        for i in range(200):
            entity_specs.append(("USER", f"user:domain:{i:03d}", f"DOMAIN\\user{i:03d}"))
        for i in range(3000):
            entity_specs.append(("PROCESS", f"process:host:{i % 100:03d}:pid:{1000 + i}:anchor:{i}", f"proc{i % 300}.exe"))
        for i in range(2500):
            entity_specs.append(("IP_ADDRESS", f"ip:10.50.{i // 250}.{i % 250}", f"10.50.{i // 250}.{i % 250}"))
        for i in range(1200):
            entity_specs.append(("DOMAIN", f"domain:phase0g-{i}.example.test", f"phase0g-{i}.example.test"))
        for i in range(1600):
            entity_specs.append(("FILE_PATH", f"path:C:/Temp/phase0g/file{i}.dll", f"C:\\Temp\\phase0g\\file{i}.dll"))
        for i in range(1000):
            entity_specs.append(("LOGON_SESSION", f"logon:host:{i % 100:03d}:id:{i}", f"HOST-{i % 100:03d}:0x{i:x}"))
        for i in range(400):
            entity_specs.append(("SERVICE", f"service:svc{i:03d}", f"svc{i:03d}"))
        seen_keys = set()
        for entity_type, entity_key, _display in entity_specs:
            identity = (entity_type, entity_key)
            if identity in seen_keys:
                raise SystemExit(f"Duplicate graph entity identity in scale harness: {identity}")
            seen_keys.add(identity)

        entities = [
            GraphEntity(
                case_id=case_a.id,
                entity_type=entity_type,
                entity_key=entity_key,
                display_value=display,
                canonical_value=display.lower(),
                metadata_json={"phase0g_marker": marker},
            )
            for entity_type, entity_key, display in entity_specs
        ]
        control_entity = GraphEntity(
            case_id=case_b.id,
            entity_type="HOST",
            entity_key="host:000",
            display_value="HOST-000",
            canonical_value="host-000",
            metadata_json={"phase0g_marker": marker, "control": True},
        )
        db.session.add_all(entities + [control_entity])
        db.session.flush()

        high_degree_entity = next(item for item in entities if item.entity_type == "IP_ADDRESS")
        rel_types = ["CONNECTED_TO", "ON_HOST", "LOGGED_ON_TO", "RUNS_IMAGE", "REFERENCES", "HAS_SECURITY_CONTEXT"]
        relationships = []
        seen_edges = set()
        ordinal = 0
        attempt = 0
        while len(relationships) < 25000:
            if len(relationships) < 2200:
                source = high_degree_entity
                target = entities[(attempt % (len(entities) - 1)) + 1]
                rel_type = "CONNECTED_TO"
            elif len(relationships) < 2300:
                source = entities[attempt % len(entities)]
                target = entities[(attempt + 1) % len(entities)]
                rel_type = "REFERENCES"
            else:
                source = entities[attempt % len(entities)]
                target = entities[(attempt * 37 + 11) % len(entities)]
                rel_type = rel_types[attempt % len(rel_types)]
            if source.id == target.id:
                target = entities[(attempt + 3) % len(entities)]
            derivation = GraphDerivationType.OBSERVED if ordinal % 2 == 0 else GraphDerivationType.DETERMINISTIC
            edge_key = (source.id, rel_type, target.id, derivation)
            attempt += 1
            if edge_key in seen_edges:
                continue
            seen_edges.add(edge_key)
            relationships.append(
                GraphRelationship(
                    case_id=case_a.id,
                    source_entity_id=source.id,
                    relationship_type=rel_type,
                    target_entity_id=target.id,
                    confidence=1.0,
                    derivation_type=derivation,
                    extractor_name="phase0g_runtime_harness",
                    extractor_version="1",
                    validation_state=GraphValidationState.ACTIVE,
                    metadata_json={"phase0g_marker": marker, "ordinal": ordinal},
                )
            )
            ordinal += 1
            if attempt > 200000:
                raise SystemExit(f"Unable to generate 25000 unique canonical edges; got {len(relationships)}")
        db.session.add_all(relationships)
        db.session.flush()

        observed_start = datetime(2026, 1, 1)
        support_rows = []
        for i, relationship in enumerate(relationships):
            support_rows.append(
                GraphRelationshipEvidence(
                    case_id=case_a.id,
                    relationship_id=relationship.id,
                    evidence_record_key=_erk(marker, i),
                    source_table="events",
                    evidence_role="supporting_record",
                    extractor_name="phase0g_runtime_harness",
                    extractor_version="1",
                    observed_at=observed_start + timedelta(seconds=i),
                    metadata_json={"phase0g_marker": marker},
                    support_state=GraphSupportState.ACTIVE,
                    source_ref_type=["CASE_FILE", "PCAP_FILE", "MEMORY_JOB"][i % 3],
                    source_ref_id=(i % 9) + 1,
                    support_locator_json={"phase0g_marker": marker, "source_class": i % 3},
                )
            )
            if i % 10 == 0:
                support_rows.append(
                    GraphRelationshipEvidence(
                        case_id=case_a.id,
                        relationship_id=relationship.id,
                        evidence_record_key=_erk(marker, 500000 + i),
                        source_table="events",
                        evidence_role="independent_support",
                        extractor_name="phase0g_runtime_harness",
                        extractor_version="1",
                        observed_at=observed_start + timedelta(seconds=i + 1),
                        metadata_json={"phase0g_marker": marker, "secondary": True},
                        support_state=GraphSupportState.ACTIVE,
                        source_ref_type="CASE_FILE",
                        source_ref_id=99,
                        support_locator_json={"phase0g_marker": marker, "source_class": "secondary"},
                    )
                )
        db.session.add_all(support_rows)
        for entity in entities[:500]:
            db.session.add(
                GraphEntityObservation(
                    case_id=case_a.id,
                    entity_id=entity.id,
                    evidence_record_key=_erk(marker, entity.id),
                    observation_role="phase0g_observed",
                    observed_value=entity.display_value,
                    observed_at=observed_start,
                    source_table="events",
                    metadata_json={"phase0g_marker": marker},
                )
            )
        db.session.commit()
        return {
            "case_id": case_a.id,
            "case_uuid": case_a.uuid,
            "control_case_id": case_b.id,
            "control_case_uuid": case_b.uuid,
            "entities": len(entities),
            "relationships": len(relationships),
            "support_rows": len(support_rows),
            "high_degree_entity_id": high_degree_entity.id,
            "high_degree_entity_type": high_degree_entity.entity_type,
            "high_degree_entity_value": high_degree_entity.display_value,
        }


def _operation(name: str, fn, *, hard_limit=None, notes="") -> dict:
    start = time.perf_counter()
    try:
        payload = fn()
        duration = round(time.perf_counter() - start, 4)
        returned = 0
        truncated = False
        pagination = None
        if isinstance(payload, dict):
            for key in ("entities", "edges", "evidence", "records", "paths"):
                if key in payload and isinstance(payload[key], list):
                    returned = len(payload[key])
                    break
            truncated = bool(payload.get("truncated") or payload.get("has_more"))
            pagination = payload.get("pagination") or {"has_more": payload.get("has_more")}
        return {
            "operation": name,
            "success": True,
            "duration_seconds": duration,
            "returned_logical_record_count": returned,
            "hard_limit": hard_limit,
            "truncated": truncated,
            "pagination_state": pagination,
            "peak_process_rss_mb": _rss_mb(),
            "notes": notes,
        }
    except Exception as exc:
        return {
            "operation": name,
            "success": False,
            "duration_seconds": round(time.perf_counter() - start, 4),
            "returned_logical_record_count": 0,
            "hard_limit": hard_limit,
            "truncated": None,
            "pagination_state": None,
            "peak_process_rss_mb": _rss_mb(),
            "notes": f"{notes} error={type(exc).__name__}: {exc}",
        }


def _benchmark(app, graph_meta: dict, ch_meta: dict, ch_client) -> list[dict]:
    from utils.graph_query import MAX_EVIDENCE_LIMIT, MAX_NEIGHBOR_LIMIT, MAX_PATHS, GraphQueryService
    from utils.investigation_context import MAX_CONTEXT_LIMIT, InvestigationContextService

    case_id = graph_meta["case_id"]
    high_degree_id = graph_meta["high_degree_entity_id"]
    graph = GraphQueryService()
    context = InvestigationContextService(client=ch_client)
    operations = []
    with app.app_context():
        rel_id = graph.neighborhood(case_id, high_degree_id, limit=1)["edges"][0]["id"]
        target_id = graph.neighborhood(case_id, high_degree_id, limit=1)["edges"][0]["target_entity_id"]
        operations.extend(
            [
                _operation("exact_case_erk_lookup", lambda: graph.exact_evidence(case_id, ch_meta["duplicate_erk"], client=ch_client), hard_limit=2),
                _operation("entity_search_real_term", lambda: graph.search_entities(case_id, q="HOST-001", limit=50), hard_limit=50),
                _operation("empty_graph_search", lambda: graph.search_entities(case_id, q="", limit=50), hard_limit=50),
                _operation("high_degree_one_hop", lambda: graph.neighborhood(case_id, high_degree_id, limit=200), hard_limit=MAX_NEIGHBOR_LIMIT),
                _operation("relationship_support_page", lambda: graph.relationship_evidence(case_id, rel_id, limit=200), hard_limit=MAX_EVIDENCE_LIMIT),
                _operation("bounded_path_search", lambda: graph.path_search(case_id, source_entity_id=high_degree_id, target_entity_id=target_id, max_depth=2, max_paths=3), hard_limit=MAX_PATHS),
                _operation("cyclic_path_search", lambda: graph.path_search(case_id, source_entity_id=target_id, target_entity_id=high_degree_id, max_depth=4, max_paths=3), hard_limit=MAX_PATHS),
                _operation("relationship_type_filtered_path", lambda: graph.path_search(case_id, source_entity_id=high_degree_id, target_entity_id=target_id, relationship_types=["CONNECTED_TO"], max_depth=2, max_paths=3), hard_limit=MAX_PATHS),
                _operation("derivation_type_filtered_path", lambda: graph.path_search(case_id, source_entity_id=high_degree_id, target_entity_id=target_id, derivation_types=["OBSERVED"], max_depth=2, max_paths=3), hard_limit=MAX_PATHS),
                _operation("time_filtered_path", lambda: graph.path_search(case_id, source_entity_id=high_degree_id, target_entity_id=target_id, time_start="2026-01-01T00:00:00", time_end="2026-01-01T01:00:00", max_depth=2, max_paths=3), hard_limit=MAX_PATHS),
                _operation("context_relative_1s", lambda: context.context(case_id, anchor_erk=ch_meta["first_erk"], window="1s", mode="relative"), hard_limit=MAX_CONTEXT_LIMIT),
                _operation("context_relative_30s", lambda: context.context(case_id, anchor_erk=ch_meta["first_erk"], window="30s", mode="relative"), hard_limit=MAX_CONTEXT_LIMIT),
                _operation("context_relative_5m", lambda: context.context(case_id, anchor_erk=ch_meta["first_erk"], window="5m", mode="relative"), hard_limit=MAX_CONTEXT_LIMIT),
                _operation("context_relative_1h", lambda: context.context(case_id, anchor_erk=ch_meta["first_erk"], window="1h", mode="relative"), hard_limit=MAX_CONTEXT_LIMIT),
                _operation("context_same_host", lambda: context.context(case_id, anchor_erk=ch_meta["first_erk"], mode="same_host"), hard_limit=MAX_CONTEXT_LIMIT),
                _operation("context_same_user", lambda: context.context(case_id, anchor_erk=ch_meta["first_erk"], mode="same_user"), hard_limit=MAX_CONTEXT_LIMIT),
                _operation("context_process_lifetime", lambda: context.context(case_id, anchor_erk=ch_meta["first_erk"], mode="process_lifetime"), hard_limit=MAX_CONTEXT_LIMIT),
                _operation("context_logon_session", lambda: context.context(case_id, anchor_erk=ch_meta["first_erk"], mode="logon_session"), hard_limit=MAX_CONTEXT_LIMIT),
                _operation("context_explicit_all_host", lambda: context.context(case_id, anchor_erk=ch_meta["first_erk"], mode="relative", all_hosts=True), hard_limit=MAX_CONTEXT_LIMIT),
            ]
        )
        cursor = None
        seen_ids = set()
        pagination_ok = True
        for page in range(1, 4):
            page_cursor = cursor

            def _page(current_cursor=page_cursor):
                return graph.neighborhood(case_id, high_degree_id, limit=200, cursor=current_cursor)

            page_result = _operation(
                f"neighborhood_pagination_page_{page}",
                _page,
                hard_limit=MAX_NEIGHBOR_LIMIT,
                notes="high-degree neighborhood pagination",
            )
            operations.append(page_result)
            if not page_result["success"]:
                pagination_ok = False
                break
            result = graph.neighborhood(case_id, high_degree_id, limit=200, cursor=page_cursor)
            page_ids = [edge["id"] for edge in result["edges"]]
            if seen_ids.intersection(page_ids):
                pagination_ok = False
                operations[-1]["success"] = False
                operations[-1]["notes"] += " duplicate relationship ids across pages"
            seen_ids.update(page_ids)
            cursor = result["pagination"].get("next_cursor")
            if not cursor:
                break
        operations.append(
            {
                "operation": "neighborhood_pagination_correctness",
                "success": pagination_ok and len(seen_ids) > 200,
                "duration_seconds": 0.0,
                "returned_logical_record_count": len(seen_ids),
                "hard_limit": MAX_NEIGHBOR_LIMIT,
                "truncated": True,
                "pagination_state": {"unique_ids": len(seen_ids), "pages": page},
                "peak_process_rss_mb": _rss_mb(),
                "notes": "duplicate-free high-degree pagination across pages",
            }
        )

        from utils.graph_saved_views import GraphSavedViewService
        from utils.investigation_thread_report_adapter import InvestigationThreadReportAdapter
        from utils.investigation_thread_report_snapshots import InvestigationThreadReportSnapshotService
        from utils.investigation_threads import InvestigationThreadService
        from utils.report_generator import ReportGenerator
        from docx import Document

        actor = {"username": "phase0g", "user_id": 1, "actor_type": "analyst", "is_ai": False}
        thread_service = InvestigationThreadService()
        view_service = GraphSavedViewService()
        snapshot_service = InvestigationThreadReportSnapshotService()
        source_entity_id = high_degree_id
        operations.append(
            _operation(
                "thread_create",
                lambda: thread_service.create_thread(case_id, title="PHASE0G scale thread", actor=actor),
                notes="Investigation Thread create",
            )
        )
        thread = thread_service.create_thread(case_id, title="PHASE0G scale thread durable", actor=actor)
        operations.append(
            _operation(
                "saved_view_create",
                lambda: view_service.create_view(
                    case_id,
                    title="PHASE0G scale view",
                    view_payload={
                        "root_entity_ids": [source_entity_id],
                        "expanded_entity_ids": [source_entity_id, target_id],
                        "visible_relationship_ids": [rel_id],
                        "node_coordinates_json": {
                            str(source_entity_id): {"x": 10, "y": 20},
                            str(target_id): {"x": 300, "y": 20},
                        },
                    },
                    actor=actor,
                ),
                notes="Saved View create",
            )
        )
        view = view_service.create_view(
            case_id,
            title="PHASE0G scale view durable",
            view_payload={
                "root_entity_ids": [source_entity_id],
                "expanded_entity_ids": [source_entity_id, target_id],
                "visible_relationship_ids": [rel_id],
                "node_coordinates_json": {
                    str(source_entity_id): {"x": 10, "y": 20},
                    str(target_id): {"x": 300, "y": 20},
                },
            },
            actor=actor,
        )["view"]
        operations.append(
            _operation(
                "saved_view_load",
                lambda: view_service.get_view(case_id, view["uuid"], resolve_live=True),
                notes="Saved View load",
            )
        )
        version = thread_service.link_entity(
            case_id, thread["uuid"], expected_version=thread["version"], entity_id=source_entity_id, actor=actor
        )["version"]
        version = thread_service.link_relationship(
            case_id, thread["uuid"], expected_version=version, relationship_id=rel_id, actor=actor
        )["version"]
        version = thread_service.link_evidence(
            case_id, thread["uuid"], expected_version=version, evidence_record_key=ch_meta["first_erk"], actor=actor
        )["version"]
        thread = thread_service.update_thread(
            case_id,
            thread["uuid"],
            expected_version=version,
            actor=actor,
            current_saved_view_uuid=view["uuid"],
            include_in_report=True,
        )
        operations.append(
            _operation(
                "immutable_report_snapshot",
                lambda: snapshot_service.create_snapshot(
                    case_id,
                    thread_uuid=thread["uuid"],
                    expected_thread_version=thread["version"],
                    expected_saved_view_version=view["version"],
                    actor=actor,
                ),
                notes="immutable Thread report snapshot",
            )
        )
        snapshot = snapshot_service.create_snapshot(
            case_id,
            thread_uuid=thread["uuid"],
            expected_thread_version=thread["version"],
            expected_saved_view_version=view["version"],
            actor=actor,
        )

        def _docx():
            template_path = Path(os.environ.get("PHASE0G_STORAGE_ROOT", "/tmp/casescope-phase0g-storage")) / "phase0g_template.docx"
            output_path = Path(os.environ.get("PHASE0G_STORAGE_ROOT", "/tmp/casescope-phase0g-storage")) / "phase0g_report.docx"
            document = Document()
            document.add_paragraph("PHASE0G deterministic report template")
            document.save(template_path)
            ReportGenerator(str(template_path)).generate(
                InvestigationThreadReportAdapter().build_context([snapshot]),
                str(output_path),
            )
            return {"records": [str(output_path)], "ai_used": snapshot.get("ai_used")}

        operations.append(
            _operation(
                "deterministic_non_ai_docx",
                _docx,
                notes="deterministic non-AI DOCX from immutable snapshot",
            )
        )
    return operations


def _query_plan_review(case_id: int, ch_client) -> dict:
    from models.database import db

    postgres_sql = {
        "entity_search": "EXPLAIN ANALYZE SELECT * FROM graph_entities WHERE case_id = :case_id AND lower(display_value) LIKE '%host-001%' LIMIT 51",
        "high_degree_neighborhood": "EXPLAIN ANALYZE SELECT * FROM graph_relationships WHERE case_id = :case_id AND (source_entity_id = :entity_id OR target_entity_id = :entity_id) ORDER BY id LIMIT 201",
        "relationship_support": "EXPLAIN ANALYZE SELECT * FROM graph_relationship_evidence WHERE case_id = :case_id AND relationship_id = :relationship_id ORDER BY id LIMIT 201",
        "path_expansion": "EXPLAIN ANALYZE SELECT * FROM graph_relationships WHERE case_id = :case_id AND validation_state = 'ACTIVE' AND (source_entity_id = :entity_id OR target_entity_id = :entity_id) LIMIT 251",
        "support_time_filtering": "EXPLAIN ANALYZE SELECT * FROM graph_relationship_evidence WHERE case_id = :case_id AND support_state = 'ACTIVE' AND observed_at >= TIMESTAMP '2026-01-01 00:00:00' AND observed_at < TIMESTAMP '2026-01-01 01:00:00' LIMIT 201",
        "thread_stable_ref_resolution": "EXPLAIN ANALYZE SELECT * FROM graph_entities WHERE case_id = :case_id AND entity_type = 'HOST' AND entity_key = 'host:001' LIMIT 2",
        "saved_view_lookup": "EXPLAIN ANALYZE SELECT * FROM graph_saved_views WHERE case_id = :case_id ORDER BY updated_at DESC LIMIT 26",
    }
    pg_results = {}
    entity_id = db.session.execute(db.text("SELECT id FROM graph_entities WHERE case_id = :case_id ORDER BY id LIMIT 1"), {"case_id": case_id}).scalar()
    rel_id = db.session.execute(db.text("SELECT id FROM graph_relationships WHERE case_id = :case_id ORDER BY id LIMIT 1"), {"case_id": case_id}).scalar()
    for name, sql in postgres_sql.items():
        rows = db.session.execute(db.text(sql), {"case_id": case_id, "entity_id": entity_id, "relationship_id": rel_id}).fetchall()
        pg_results[name] = [row[0] for row in rows]

    ch_queries = {
        "exact_case_erk": "EXPLAIN indexes = 1 SELECT * FROM events WHERE case_id = {case_id:UInt32} AND evidence_record_key = {erk:String} LIMIT 2",
        "bounded_timestamp_context": "EXPLAIN indexes = 1 SELECT * FROM events WHERE case_id = {case_id:UInt32} AND timestamp_utc >= {start:DateTime64(3)} AND timestamp_utc <= {end:DateTime64(3)} LIMIT 501",
        "same_host_context": "EXPLAIN indexes = 1 SELECT * FROM events WHERE case_id = {case_id:UInt32} AND source_host = {host:String} LIMIT 501",
        "process_lifetime_context": "EXPLAIN indexes = 1 SELECT * FROM events WHERE case_id = {case_id:UInt32} AND source_host = {host:String} AND process_id = {pid:UInt64} LIMIT 501",
        "logon_session_context": "EXPLAIN indexes = 1 SELECT * FROM events WHERE case_id = {case_id:UInt32} AND source_host = {host:String} AND logon_id = {logon:String} LIMIT 501",
    }
    ch_results = {}
    anchor = ch_client.query(
        "SELECT evidence_record_key, timestamp_utc, source_host, process_id, logon_id FROM events WHERE case_id = {case_id:UInt32} ORDER BY timestamp_utc LIMIT 1",
        parameters={"case_id": case_id},
    ).result_rows[0]
    params = {
        "case_id": case_id,
        "erk": anchor[0],
        "start": anchor[1],
        "end": anchor[1] + timedelta(minutes=5),
        "host": anchor[2],
        "pid": anchor[3],
        "logon": anchor[4],
    }
    for name, sql in ch_queries.items():
        ch_results[name] = [row[0] for row in ch_client.query(sql, parameters=params).result_rows]
    return {"postgresql": pg_results, "clickhouse": ch_results}


def run(args) -> dict:
    _assert_disposable(args)
    database = args.clickhouse_database or os.environ["CLICKHOUSE_DATABASE"]
    print(json.dumps({
        "event": "phase0g_targets",
        "postgres_host": urlparse(os.environ.get("DATABASE_URL", "")).hostname,
        "postgres_database": _database_name_from_url(os.environ.get("DATABASE_URL", "")),
        "clickhouse_host": os.environ.get("CLICKHOUSE_HOST", "localhost"),
        "clickhouse_database": database,
        "storage_root": os.environ.get("PHASE0G_STORAGE_ROOT", "/tmp/casescope-phase0g-storage"),
        "marker": args.marker,
        "git_sha": _git_sha(),
    }))
    _prepare_clickhouse(database)
    app, db = _create_app_context()
    graph_meta = _build_graph(app, db, marker=args.marker)
    print(json.dumps({
        "event": "phase0g_disposable_cases",
        "postgres_host": urlparse(os.environ.get("DATABASE_URL", "")).hostname,
        "postgres_database": _database_name_from_url(os.environ.get("DATABASE_URL", "")),
        "clickhouse_host": os.environ.get("CLICKHOUSE_HOST", "localhost"),
        "clickhouse_database": database,
        "storage_root": os.environ.get("PHASE0G_STORAGE_ROOT", "/tmp/casescope-phase0g-storage"),
        "case_uuid": graph_meta["case_uuid"],
        "control_case_uuid": graph_meta["control_case_uuid"],
        "git_sha": _git_sha(),
    }))
    client = _ch_client(database)
    ch_meta = _insert_events(client, case_id=graph_meta["case_id"], marker=args.marker, total=args.events, chunk_size=args.chunk_size)
    count = client.query("SELECT count() FROM events WHERE case_id = {case_id:UInt32}", parameters={"case_id": graph_meta["case_id"]}).result_rows[0][0]
    distinct_erks = client.query("SELECT uniqExact(evidence_record_key) FROM events WHERE case_id = {case_id:UInt32}", parameters={"case_id": graph_meta["case_id"]}).result_rows[0][0]
    hosts = client.query("SELECT uniqExact(source_host) FROM events WHERE case_id = {case_id:UInt32}", parameters={"case_id": graph_meta["case_id"]}).result_rows[0][0]
    users = client.query("SELECT uniqExact(username) FROM events WHERE case_id = {case_id:UInt32}", parameters={"case_id": graph_meta["case_id"]}).result_rows[0][0]
    operations = _benchmark(app, graph_meta, ch_meta, client)
    with app.app_context():
        plans = _query_plan_review(graph_meta["case_id"], client)
    return {
        "tested_sha": _git_sha(),
        "marker": args.marker,
        "generated_at": _utc_now(),
        "status": "PASS" if count >= 1_000_000 and all(item["success"] for item in operations) else "FAIL",
        "scale": {
            "clickhouse_event_rows": int(count),
            "distinct_logical_erks": int(distinct_erks),
            "physical_duplicate_rows": int(ch_meta["physical_duplicate_rows"]),
            "hosts": int(hosts),
            "users": int(users),
            "process_creation_events": int(ch_meta["process_creation_events"]),
            "postgresql_graph_entities": int(graph_meta["entities"]),
            "graph_relationships": int(graph_meta["relationships"]),
            "relationship_support_rows": int(graph_meta["support_rows"]),
            "high_degree_entity": {
                "id": graph_meta["high_degree_entity_id"],
                "type": graph_meta["high_degree_entity_type"],
                "value": graph_meta["high_degree_entity_value"],
                "target_degree": 2200,
            },
        },
        "cases": {
            "primary": {"id": graph_meta["case_id"], "uuid": graph_meta["case_uuid"]},
            "control": {"id": graph_meta["control_case_id"], "uuid": graph_meta["control_case_uuid"]},
        },
        "benchmark_operations": operations,
        "query_plan_review": plans,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--marker", default=f"PHASE0G_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}_{uuid.uuid4().hex[:8]}")
    parser.add_argument("--clickhouse-database", default=os.environ.get("CLICKHOUSE_DATABASE"))
    parser.add_argument("--events", type=int, default=1_000_000)
    parser.add_argument("--chunk-size", type=int, default=25_000)
    parser.add_argument("--output", default="/tmp/casescope-phase0g-results/phase0g_scale_benchmark.json")
    args = parser.parse_args()
    result = run(args)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps({"event": "phase0g_scale_result", "output": str(output), "status": result["status"]}))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
