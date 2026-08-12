#!/usr/bin/env python3
"""Disposable Phase 0G deployed lifecycle, deletion, permission, and cross-case runtime."""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _git_sha() -> str:
    try:
        return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=str(ROOT), text=True).strip()
    except Exception:
        return "UNKNOWN"


def _db_name(url: str) -> str:
    return urlparse(url).path.rsplit("/", 1)[-1]


def _assert_disposable() -> None:
    pg = _db_name(os.environ.get("DATABASE_URL", ""))
    ch = os.environ.get("CLICKHOUSE_DATABASE", "")
    failures = []
    if not pg.lower().startswith("phase0g_"):
        failures.append(f"PostgreSQL database is not disposable: {pg or '<unset>'}")
    if not ch.lower().startswith("phase0g_"):
        failures.append(f"ClickHouse database is not disposable: {ch or '<unset>'}")
    if failures:
        raise SystemExit("Refusing Phase 0G deployed runtime:\n- " + "\n- ".join(failures))


def _erk(marker: str, logical_index: int) -> str:
    digest = hashlib.sha256(f"{marker}|event|{logical_index}".encode("utf-8")).hexdigest()
    return f"erk:v2:{digest}"


def _record(name: str, ok: bool, **extra) -> dict:
    payload = {"operation": name, "success": bool(ok), **extra}
    print(json.dumps({"event": "phase0g_deployed_step", **payload}, default=str))
    return payload


def _login(client, username: str, password: str):
    # /login redirects if a session is already authenticated, so switch users
    # by logging out first. Otherwise later admin-only deletes run as analyst.
    client.get("/logout", follow_redirects=True)
    return client.post("/login", data={"username": username, "password": password}, follow_redirects=True)


def _json(resp):
    try:
        return resp.get_json(silent=True) or {}
    except Exception:
        return {}


def main() -> int:
    _assert_disposable()
    marker = os.environ.get("PHASE0G_MARKER", f"PHASE0G_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}_deployed")
    storage = Path(os.environ.get("PHASE0G_STORAGE_ROOT", "/tmp/casescope-phase0g-storage"))
    storage.mkdir(parents=True, exist_ok=True)
    os.environ.setdefault("SECRET_KEY", "phase0g-disposable-secret")
    os.environ.setdefault("DEFAULT_ADMIN_PASSWORD", "Phase0gAdmin1")
    print(json.dumps({
        "event": "phase0g_targets",
        "postgres_host": urlparse(os.environ.get("DATABASE_URL", "")).hostname or "unix-socket",
        "postgres_database": _db_name(os.environ.get("DATABASE_URL", "")),
        "clickhouse_host": os.environ.get("CLICKHOUSE_HOST", "localhost"),
        "clickhouse_database": os.environ.get("CLICKHOUSE_DATABASE"),
        "storage_root": str(storage),
        "marker": marker,
        "git_sha": _git_sha(),
    }))

    from config import Config
    Config.STORAGE_FOLDER = str(storage)
    from app import create_app
    from models.database import db
    from models.audit_log import AuditLog
    from models.case import Case
    from models.case_file import CaseFile
    from models.case_report import CaseReport
    from models.client import Client
    from models.file_audit_log import FileAuditLog
    from models.graph import GraphEntity, GraphEntityObservation, GraphRelationship, GraphRelationshipEvidence
    from models.graph_saved_view import GraphSavedView
    from models.investigation_thread import (
        InvestigationThread,
        InvestigationThreadEntity,
        InvestigationThreadEvidence,
        InvestigationThreadNote,
        InvestigationThreadRelationship,
        InvestigationThreadReportSnapshot,
    )
    from models.ioc import IOC
    from models.ioc_evidence_match import IOCEvidenceMatch
    from models.memory_job import MemoryJob
    from models.pcap_file import PcapFile
    from models.user import User
    from config import PermissionLevel
    from utils.graph_identity import GraphDerivationType, GraphSupportState, GraphValidationState
    from utils.audit_chain import verify_chain
    from migrations.add_events_table import EVENTS_SCHEMA
    import clickhouse_connect

    app = create_app(run_startup_bootstrap=False, register_blueprints=True)
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False
    results = {
        "tested_sha": _git_sha(),
        "generated_at": _utc_now(),
        "marker": marker,
        "lifecycle": {},
        "permanent_case_deletion": {},
        "permissions": {},
        "cross_case": {},
        "deployment_smoke": {},
        "audit_chain": {},
        "ai_gate": {},
    }

    ch = clickhouse_connect.get_client(
        host=os.environ.get("CLICKHOUSE_HOST", "localhost"),
        port=int(os.environ.get("CLICKHOUSE_PORT", "8123")),
        database=os.environ["CLICKHOUSE_DATABASE"],
        username=os.environ.get("CLICKHOUSE_USER", "default"),
        password=os.environ.get("CLICKHOUSE_PASSWORD", ""),
    )
    ch.command(EVENTS_SCHEMA)
    from migrations.add_events_table import _ensure_events_buffer_schema
    _ensure_events_buffer_schema(ch)
    from migrations.add_network_logs_table import NETWORK_LOGS_SCHEMA, NETWORK_LOGS_BUFFER
    ch.command(NETWORK_LOGS_SCHEMA)
    ch.command(NETWORK_LOGS_BUFFER)

    password = "Phase0gPass1"
    with app.app_context():
        from models.case_report import CaseReport  # noqa: F401
        db.create_all()
        client_row = Client(name="PHASE0G Client", code="PHASE0G", timezone="UTC")
        db.session.add(client_row)
        db.session.flush()
        admin = User(username="phase0g_admin", full_name="Phase0G Admin", email="phase0g-admin@example.test", permission_level=PermissionLevel.ADMINISTRATOR, created_by="phase0g")
        analyst = User(username="phase0g_analyst", full_name="Phase0G Analyst", email="phase0g-analyst@example.test", permission_level=PermissionLevel.ANALYST, created_by="phase0g")
        viewer = User(username="phase0g_viewer", full_name="Phase0G Viewer", email="phase0g-viewer@example.test", permission_level=PermissionLevel.VIEWER, created_by="phase0g")
        for user in (admin, analyst, viewer):
            user.set_password(password)
        db.session.add_all([admin, analyst, viewer])
        db.session.flush()
        case_a = Case(uuid=str(uuid.uuid4()), name=f"{marker} case A", company="PHASE0G", description="Disposable lifecycle case A", created_by="phase0g", timezone="UTC", client_id=client_row.id)
        case_b = Case(uuid=str(uuid.uuid4()), name=f"{marker} case B", company="PHASE0G", description="Disposable lifecycle case B", created_by="phase0g", timezone="UTC", client_id=client_row.id)
        db.session.add_all([case_a, case_b])
        db.session.flush()
        viewer.assigned_cases = [case_a.id]
        db.session.flush()

        def _entity(case_id, entity_type, key, display):
            row = GraphEntity(case_id=case_id, entity_type=entity_type, entity_key=key, display_value=display, canonical_value=display.lower(), metadata_json={"phase0g_marker": marker})
            db.session.add(row)
            db.session.flush()
            return row

        host_a = _entity(case_a.id, "HOST", "host:host-01", "HOST-01")
        user_a = _entity(case_a.id, "USER", "user:administrator", "Administrator")
        proc_a = _entity(case_a.id, "PROCESS", "process:host-01:pid:1234:anchor:1", "proc.exe")
        ip_a = _entity(case_a.id, "IP_ADDRESS", "ip:10.1.2.3", "10.1.2.3")
        host_b = _entity(case_b.id, "HOST", "host:host-01", "HOST-01")
        user_b = _entity(case_b.id, "USER", "user:administrator", "Administrator")
        proc_b = _entity(case_b.id, "PROCESS", "process:host-01:pid:1234:anchor:1", "proc.exe")
        ip_b = _entity(case_b.id, "IP_ADDRESS", "ip:10.1.2.3", "10.1.2.3")

        def _rel(case_id, source, rel_type, target, derivation=GraphDerivationType.OBSERVED):
            row = GraphRelationship(
                case_id=case_id,
                source_entity_id=source.id,
                relationship_type=rel_type,
                target_entity_id=target.id,
                confidence=1.0,
                derivation_type=derivation,
                extractor_name="phase0g_runtime_harness",
                extractor_version="1",
                validation_state=GraphValidationState.ACTIVE,
                metadata_json={"phase0g_marker": marker},
            )
            db.session.add(row)
            db.session.flush()
            return row

        rel_e = _rel(case_a.id, proc_a, "ON_HOST", host_a)
        rel_b = _rel(case_b.id, proc_b, "ON_HOST", host_b)
        file_a = CaseFile(case_uuid=case_a.uuid, filename="phase0g_a.evtx", original_filename="phase0g_a.evtx", file_path=str(storage / "phase0g_a.evtx"), file_size=12, sha256_hash=hashlib.sha256(b"a").hexdigest(), uploaded_by="phase0g")
        file_b = CaseFile(case_uuid=case_a.uuid, filename="phase0g_b.evtx", original_filename="phase0g_b.evtx", file_path=str(storage / "phase0g_b.evtx"), file_size=12, sha256_hash=hashlib.sha256(b"b").hexdigest(), uploaded_by="phase0g")
        (storage / "phase0g_a.evtx").write_bytes(b"phase0g-a")
        (storage / "phase0g_b.evtx").write_bytes(b"phase0g-b")
        db.session.add_all([file_a, file_b])
        db.session.flush()
        pcap_a = PcapFile(case_uuid=case_a.uuid, filename="phase0g_a.pcap", original_filename="phase0g_a.pcap", file_path=str(storage / "phase0g_a.pcap"), file_size=12, sha256_hash=hashlib.sha256(b"pcap-a").hexdigest(), uploaded_by="phase0g")
        pcap_b = PcapFile(case_uuid=case_a.uuid, filename="phase0g_b.pcap", original_filename="phase0g_b.pcap", file_path=str(storage / "phase0g_b.pcap"), file_size=12, sha256_hash=hashlib.sha256(b"pcap-b").hexdigest(), uploaded_by="phase0g")
        (storage / "phase0g_a.pcap").write_bytes(b"phase0g-pcap-a")
        (storage / "phase0g_b.pcap").write_bytes(b"phase0g-pcap-b")
        db.session.add_all([pcap_a, pcap_b])
        db.session.flush()
        mem_a = MemoryJob(case_id=case_a.id, source_file=str(storage / "phase0g_a.mem"), source_filename="phase0g_a.mem", hostname="HOST-01", os_type="windows", memory_type="raw")
        mem_b = MemoryJob(case_id=case_a.id, source_file=str(storage / "phase0g_b.mem"), source_filename="phase0g_b.mem", hostname="HOST-01", os_type="windows", memory_type="raw")
        (storage / "phase0g_a.mem").write_bytes(b"phase0g-mem-a")
        (storage / "phase0g_b.mem").write_bytes(b"phase0g-mem-b")
        db.session.add_all([mem_a, mem_b])
        db.session.flush()
        ioc = IOC(case_id=case_a.id, category="network", ioc_type="ip", value="10.1.2.3", value_normalized="10.1.2.3", created_by="phase0g")
        db.session.add(ioc)
        db.session.flush()

        def _support(rel, erk, source_type, source_id, role="supporting_record"):
            row = GraphRelationshipEvidence(
                case_id=rel.case_id,
                relationship_id=rel.id,
                evidence_record_key=erk,
                source_table="events",
                evidence_role=role,
                extractor_name="phase0g_runtime_harness",
                extractor_version="1",
                observed_at=datetime(2026, 1, 1),
                metadata_json={"phase0g_marker": marker},
                support_state=GraphSupportState.ACTIVE,
                source_ref_type=source_type,
                source_ref_id=source_id,
                support_locator_json={"phase0g_marker": marker},
            )
            db.session.add(row)
            db.session.flush()
            return row

        erk_a = _erk(marker, 1)
        erk_b = _erk(marker, 2)
        erk_pcap_a = _erk(marker, 11)
        erk_pcap_b = _erk(marker, 12)
        erk_mem_a = _erk(marker, 21)
        erk_mem_b = _erk(marker, 22)
        support_a = _support(rel_e, erk_a, "CASE_FILE", file_a.id)
        support_b = _support(rel_e, erk_b, "CASE_FILE", file_b.id, role="independent_support")
        pcap_rel = _rel(case_a.id, ip_a, "CONNECTED_TO", host_a)
        pcap_sa = _support(pcap_rel, erk_pcap_a, "PCAP_FILE", pcap_a.id)
        pcap_sb = _support(pcap_rel, erk_pcap_b, "PCAP_FILE", pcap_b.id, role="independent_support")
        mem_rel = _rel(case_a.id, proc_a, "HAS_SECURITY_CONTEXT", user_a)
        mem_sa = _support(mem_rel, erk_mem_a, "MEMORY_JOB", mem_a.id)
        mem_sb = _support(mem_rel, erk_mem_b, "MEMORY_JOB", mem_b.id, role="independent_support")
        match_a = IOCEvidenceMatch(case_id=case_a.id, ioc_id=ioc.id, ioc_uuid=ioc.uuid, ioc_type="ip", matched_value="10.1.2.3", matched_field="src_ip", evidence_record_key=erk_a, source_ref_type="CASE_FILE", source_ref_id=file_a.id, support_state=GraphSupportState.ACTIVE)
        match_b = IOCEvidenceMatch(case_id=case_a.id, ioc_id=ioc.id, ioc_uuid=ioc.uuid, ioc_type="ip", matched_value="10.1.2.3", matched_field="src_ip", evidence_record_key=erk_b, source_ref_type="CASE_FILE", source_ref_id=file_b.id, support_state=GraphSupportState.ACTIVE)
        db.session.add_all([match_a, match_b])
        db.session.add(GraphEntityObservation(case_id=case_a.id, entity_id=host_a.id, evidence_record_key=erk_a, observation_role="observed", observed_value="HOST-01", observed_at=datetime(2026, 1, 1), source_table="events", metadata_json={"phase0g_marker": marker}))
        report_dir = storage / case_a.uuid / "reports"
        render_dir = storage / case_a.uuid / "graph_renders"
        report_dir.mkdir(parents=True, exist_ok=True)
        render_dir.mkdir(parents=True, exist_ok=True)
        report_path = report_dir / "phase0g_case_report.docx"
        svg_path = render_dir / "phase0g_graph.svg"
        png_path = render_dir / "phase0g_graph.png"
        report_path.write_bytes(b"PK\x03\x04phase0g-docx")
        svg_path.write_text("<svg xmlns='http://www.w3.org/2000/svg'><text>phase0g</text></svg>", encoding="utf-8")
        png_path.write_bytes(b"\x89PNG\r\n\x1a\nphase0g")
        case_report = CaseReport(
            case_id=case_a.id,
            filename=report_path.name,
            file_path=str(report_path),
            file_size=report_path.stat().st_size,
            report_type="DFIR",
            ai_model=None,
            created_by="phase0g",
        )
        db.session.add(case_report)
        db.session.commit()
        ids = {
            "case_a": {"id": case_a.id, "uuid": case_a.uuid},
            "case_b": {"id": case_b.id, "uuid": case_b.uuid},
            "host_a": host_a.id,
            "host_b": host_b.id,
            "rel_e": rel_e.id,
            "rel_b": rel_b.id,
            "file_a": file_a.id,
            "file_b": file_b.id,
            "pcap_a": pcap_a.id,
            "pcap_b": pcap_b.id,
            "mem_a": mem_a.id,
            "mem_b": mem_b.id,
            "ioc": ioc.id,
            "erk_a": erk_a,
            "erk_b": erk_b,
            "support_a": support_a.id,
            "support_b": support_b.id,
            "pcap_sa": pcap_sa.id,
            "pcap_sb": pcap_sb.id,
            "mem_sa": mem_sa.id,
            "mem_sb": mem_sb.id,
            "match_a": match_a.id,
            "match_b": match_b.id,
            "case_report": case_report.id,
            "report_path": str(report_path),
            "svg_path": str(svg_path),
            "png_path": str(png_path),
        }

    columns = [
        "case_id", "artifact_type", "timestamp", "timestamp_utc", "source_file", "source_path", "source_host",
        "case_file_id", "event_id", "username", "logon_id", "process_id", "src_ip", "dst_ip", "raw_json",
        "search_blob", "extra_fields", "parser_version", "evidence_record_key", "evidence_identity_version",
        "evidence_identity_quality",
    ]
    ts = datetime(2026, 1, 1, tzinfo=timezone.utc)
    event_rows = []
    for idx, (erk, file_id) in enumerate([(erk_a, ids["file_a"]), (erk_b, ids["file_b"])], start=1):
        event_rows.append([
            ids["case_a"]["id"], "evtx_security", ts, ts, "phase0g.evtx", "/phase0g/phase0g.evtx", "HOST-01",
            file_id, "4688", "Administrator", "0x3e7", 1234, "10.1.2.3", "10.9.8.7",
            json.dumps({"phase0g_marker": marker}), f"{marker} HOST-01 Administrator", json.dumps({"logical_index": idx}),
            "phase0g:v1", erk, "v2", "native-or-content",
        ])
    event_rows.append([
        ids["case_b"]["id"], "evtx_security", ts, ts, "phase0g.evtx", "/phase0g/phase0g.evtx", "HOST-01",
        None, "4688", "Administrator", "0x3e7", 1234, "10.1.2.3", "10.9.8.7",
        json.dumps({"phase0g_marker": marker, "case": "B"}), f"{marker} HOST-01 Administrator", json.dumps({"logical_index": 99}),
        "phase0g:v1", _erk(marker, 99), "v2", "native-or-content",
    ])
    ch.insert("events", event_rows, column_names=columns)

    http = app.test_client()
    smoke = []
    _login(http, "phase0g_analyst", password)
    case_uuid = ids["case_a"]["uuid"]
    other_uuid = ids["case_b"]["uuid"]
    for name, method, path, kwargs in [
        ("graph_summary", "get", f"/api/graph/{case_uuid}/summary", {}),
        ("entity_search", "get", f"/api/graph/{case_uuid}/entities/search", {"query_string": {"q": "HOST-01"}}),
        ("entity_detail", "get", f"/api/graph/{case_uuid}/entities/{ids['host_a']}", {}),
        ("neighbors", "get", f"/api/graph/{case_uuid}/entities/{ids['host_a']}/neighbors", {}),
        ("relationship_detail", "get", f"/api/graph/{case_uuid}/relationships/{ids['rel_e']}", {}),
        ("relationship_support", "get", f"/api/graph/{case_uuid}/relationships/{ids['rel_e']}/evidence", {}),
        ("exact_erk", "get", f"/api/graph/{case_uuid}/evidence/{ids['erk_a']}", {}),
        ("paths", "post", f"/api/graph/{case_uuid}/paths", {"json": {"source_entity_id": ids["host_a"], "target_entity_id": ids["host_a"], "max_depth": 2, "max_paths": 3}}),
        ("context_relative", "get", f"/api/investigation/{case_uuid}/context", {"query_string": {"anchor_erk": ids["erk_a"], "mode": "relative", "window": "30s"}}),
        ("context_host", "get", f"/api/investigation/{case_uuid}/context", {"query_string": {"anchor_erk": ids["erk_a"], "mode": "same_host"}}),
        ("context_process", "get", f"/api/investigation/{case_uuid}/context", {"query_string": {"anchor_erk": ids["erk_a"], "mode": "process_lifetime"}}),
        ("context_logon", "get", f"/api/investigation/{case_uuid}/context", {"query_string": {"anchor_erk": ids["erk_a"], "mode": "logon_session"}}),
    ]:
        resp = getattr(http, method)(path, **kwargs)
        smoke.append(_record(name, resp.status_code < 400, status=resp.status_code, body=_json(resp)))

    create_thread = http.post(f"/api/investigation-threads/{case_uuid}", json={"title": "Thread T"})
    thread = _json(create_thread).get("thread") or {}
    smoke.append(_record("thread_create", create_thread.status_code in (200, 201), status=create_thread.status_code, body=_json(create_thread)))
    thread_uuid = thread.get("uuid")
    version = thread.get("version")
    if thread_uuid:
        upd = http.patch(f"/api/investigation-threads/{case_uuid}/{thread_uuid}", json={"expected_version": version, "description": "updated", "include_in_report": True})
        smoke.append(_record("thread_update", upd.status_code < 400, status=upd.status_code))
        version = (_json(upd).get("thread") or {}).get("version", version)
        for op, path, payload in [
            ("thread_add_entity", f"/api/investigation-threads/{case_uuid}/{thread_uuid}/entities", {"expected_version": version, "entity_id": ids["host_a"]}),
            ("thread_add_relationship", f"/api/investigation-threads/{case_uuid}/{thread_uuid}/relationships", {"expected_version": None, "relationship_id": ids["rel_e"]}),
            ("thread_add_evidence", f"/api/investigation-threads/{case_uuid}/{thread_uuid}/evidence", {"expected_version": None, "evidence_record_key": ids["erk_a"]}),
            ("thread_add_note", f"/api/investigation-threads/{case_uuid}/{thread_uuid}/notes", {"expected_version": None, "body": "phase0g note"}),
        ]:
            if payload["expected_version"] is None:
                payload["expected_version"] = version
            resp = http.post(path, json=payload)
            smoke.append(_record(op, resp.status_code < 400, status=resp.status_code, body=_json(resp)))
            version = (_json(resp).get("thread") or _json(resp)).get("version", version) if resp.status_code < 400 else version
            if isinstance(_json(resp).get("thread"), dict):
                version = _json(resp)["thread"].get("version", version)

    view_resp = http.post(f"/api/graph/{case_uuid}/views", json={"title": "Saved View V", "root_entity_ids": [ids["host_a"]], "expanded_entity_ids": [ids["host_a"]], "visible_relationship_ids": [ids["rel_e"]]})
    view = (_json(view_resp).get("view") or {})
    smoke.append(_record("saved_view_create", view_resp.status_code in (200, 201), status=view_resp.status_code, body=_json(view_resp)))
    if view.get("uuid"):
        load = http.get(f"/api/graph/{case_uuid}/views/{view['uuid']}")
        smoke.append(_record("saved_view_load", load.status_code < 400, status=load.status_code))
        upd = http.put(f"/api/graph/{case_uuid}/views/{view['uuid']}", json={"expected_version": view.get("version"), "title": "Saved View V2", "root_entity_ids": [ids["host_a"]]})
        smoke.append(_record("saved_view_update", upd.status_code < 400, status=upd.status_code, body=_json(upd)))
        if thread_uuid:
            link = http.patch(f"/api/investigation-threads/{case_uuid}/{thread_uuid}", json={"expected_version": version, "current_saved_view_uuid": view["uuid"]})
            smoke.append(_record("thread_link_view", link.status_code < 400, status=link.status_code))
            version = (_json(link).get("thread") or {}).get("version", version)
            snap = http.post(f"/api/investigation/{case_uuid}/report-snapshots", json={"thread_uuid": thread_uuid, "expected_thread_version": version, "expected_saved_view_version": (_json(upd).get("view") or view).get("version")})
            smoke.append(_record("report_snapshot", snap.status_code in (200, 201), status=snap.status_code, body=_json(snap)))
            snapshot = _json(snap)
            results["ai_gate"] = _record("no_ai_required", snapshot.get("ai_used") in (False, None, 0) or (snapshot.get("snapshot") or {}).get("ai_used") in (False, None, 0), snapshot=snapshot)

    with app.app_context():
        chain = verify_chain()
        results["audit_chain"] = _record("audit_chain", bool(chain.get("valid", chain) if isinstance(chain, dict) else chain), result=chain)

    results["deployment_smoke"] = {
        "status": "PASS" if all(item["success"] for item in smoke) else "FAIL",
        "operations": smoke,
    }

    def _support_state(support_id):
        with app.app_context():
            row = GraphRelationshipEvidence.query.get(support_id)
            rel = GraphRelationship.query.get(row.relationship_id) if row else None
            return {
                "support_state": None if row is None else row.support_state,
                "relationship_state": None if rel is None else rel.validation_state,
            }

    def _thread_snapshot_state():
        with app.app_context():
            thread_row = InvestigationThread.query.filter_by(case_id=ids["case_a"]["id"]).order_by(InvestigationThread.id.asc()).first()
            snap_row = InvestigationThreadReportSnapshot.query.filter_by(case_id=ids["case_a"]["id"]).order_by(InvestigationThreadReportSnapshot.id.asc()).first()
            return {
                "thread_uuid": None if thread_row is None else thread_row.uuid,
                "thread_version": None if thread_row is None else thread_row.version,
                "thread_title": None if thread_row is None else thread_row.title,
                "snapshot_uuid": None if snap_row is None else snap_row.uuid,
                "snapshot_created": None if snap_row is None else str(snap_row.created_at),
            }

    perm_rows = []
    for role, username in [("viewer", "phase0g_viewer"), ("analyst", "phase0g_analyst"), ("administrator", "phase0g_admin")]:
        role_client = app.test_client()
        _login(role_client, username, password)
        assigned_uuid = case_uuid
        host_id = ids["host_a"]
        rel_id = ids["rel_e"]
        reads = [
            ("summary", "get", f"/api/graph/{assigned_uuid}/summary", {}),
            ("search", "get", f"/api/graph/{assigned_uuid}/entities/search", {"query_string": {"q": "HOST-01"}}),
            ("entity", "get", f"/api/graph/{assigned_uuid}/entities/{host_id}", {}),
            ("neighbors", "get", f"/api/graph/{assigned_uuid}/entities/{host_id}/neighbors", {}),
            ("relationship", "get", f"/api/graph/{assigned_uuid}/relationships/{rel_id}", {}),
            ("evidence", "get", f"/api/graph/{assigned_uuid}/evidence/{ids['erk_a']}", {}),
            ("paths", "post", f"/api/graph/{assigned_uuid}/paths", {"json": {"source_entity_id": host_id, "target_entity_id": host_id, "max_depth": 2, "max_paths": 3}}),
            ("context_relative", "get", f"/api/investigation/{assigned_uuid}/context", {"query_string": {"anchor_erk": ids["erk_a"], "mode": "relative", "window": "30s"}}),
            ("context_host", "get", f"/api/investigation/{assigned_uuid}/context", {"query_string": {"anchor_erk": ids["erk_a"], "mode": "same_host"}}),
            ("context_user", "get", f"/api/investigation/{assigned_uuid}/context", {"query_string": {"anchor_erk": ids["erk_a"], "mode": "same_user"}}),
            ("context_process", "get", f"/api/investigation/{assigned_uuid}/context", {"query_string": {"anchor_erk": ids["erk_a"], "mode": "process_lifetime"}}),
            ("context_logon", "get", f"/api/investigation/{assigned_uuid}/context", {"query_string": {"anchor_erk": ids["erk_a"], "mode": "logon_session"}}),
            ("threads", "get", f"/api/investigation-threads/{assigned_uuid}", {}),
            ("views", "get", f"/api/graph/{assigned_uuid}/views", {}),
        ]
        for name, method, path, kwargs in reads:
            resp = getattr(role_client, method)(path, **kwargs)
            perm_rows.append(_record(f"{role}_read_{name}", resp.status_code < 400, status=resp.status_code, role=role, body=_json(resp)))
        write = role_client.post(f"/api/investigation-threads/{assigned_uuid}", json={"title": f"{role} write"})
        expected_write_ok = role != "viewer"
        perm_rows.append(_record(f"{role}_write_thread", (write.status_code in (200, 201)) is expected_write_ok, status=write.status_code, expected_allowed=expected_write_ok, body=_json(write)))
        view_write = role_client.post(f"/api/graph/{assigned_uuid}/views", json={"title": f"{role} view", "root_entity_ids": [host_id]})
        perm_rows.append(_record(f"{role}_write_view", (view_write.status_code in (200, 201)) is expected_write_ok, status=view_write.status_code, expected_allowed=expected_write_ok, body=_json(view_write)))
        cross = role_client.get(f"/api/graph/{assigned_uuid}/entities/{ids['host_b']}")
        perm_rows.append(_record(f"{role}_cross_case_entity", cross.status_code in (403, 404), status=cross.status_code, body=_json(cross)))
        guessed = role_client.get(f"/api/graph/{assigned_uuid}/entities/999999")
        perm_rows.append(_record(f"{role}_guessed_id", guessed.status_code in (403, 404), status=guessed.status_code))
        other_case = role_client.get(f"/api/graph/{other_uuid}/summary")
        if role == "viewer":
            perm_rows.append(_record("viewer_other_case_denied", other_case.status_code in (403, 404), status=other_case.status_code, body=_json(other_case)))
        else:
            perm_rows.append(_record(f"{role}_other_case_allowed", other_case.status_code < 400, status=other_case.status_code, body=_json(other_case)))
    results["permissions"] = {"status": "PASS" if all(r["success"] for r in perm_rows) else "FAIL", "operations": perm_rows}

    cross_pre = []
    analyst_client = app.test_client()
    _login(analyst_client, "phase0g_analyst", password)
    search_a = analyst_client.get(f"/api/graph/{case_uuid}/entities/search", query_string={"q": "HOST-01"})
    payload_a = _json(search_a)
    leaked_b = [item for item in (payload_a.get("entities") or []) if item.get("id") == ids["host_b"]]
    search_b = analyst_client.get(f"/api/graph/{other_uuid}/entities/search", query_string={"q": "HOST-01"})
    payload_b = _json(search_b)
    leaked_a = [item for item in (payload_b.get("entities") or []) if item.get("id") == ids["host_a"]]
    erk_b_on_a = analyst_client.get(f"/api/graph/{case_uuid}/evidence/{_erk(marker, 99)}")
    guessed_thread = analyst_client.get(f"/api/investigation-threads/{case_uuid}/00000000-0000-0000-0000-000000000099")
    cross_pre.extend([
        _record("identical_host_search_no_b_in_a", search_a.status_code < 400 and not leaked_b, status=search_a.status_code, leaked=leaked_b),
        _record("identical_host_search_no_a_in_b", search_b.status_code < 400 and not leaked_a, status=search_b.status_code, leaked=leaked_a),
        _record("case_b_erk_not_in_case_a", erk_b_on_a.status_code in (403, 404), status=erk_b_on_a.status_code, body=_json(erk_b_on_a)),
        _record("guessed_thread_uuid", guessed_thread.status_code in (403, 404), status=guessed_thread.status_code),
    ])

    _login(http, "phase0g_admin", password)
    durable_before = _thread_snapshot_state()
    before_a = _support_state(ids["support_a"])
    del_a = http.post(f"/api/files/delete/{ids['file_a']}")
    after_a = _support_state(ids["support_a"])
    after_b = _support_state(ids["support_b"])
    durable_after_a = _thread_snapshot_state()
    casefile_steps = [
        _record("casefile_delete_a", del_a.status_code < 400, status=del_a.status_code, body=_json(del_a)),
        _record("casefile_a_invalidated", after_a["support_state"] not in (None, GraphSupportState.ACTIVE), **after_a, before=before_a),
        _record("casefile_b_still_active", after_b["support_state"] == GraphSupportState.ACTIVE, **after_b),
        _record("relationship_e_still_active", after_b["relationship_state"] == GraphValidationState.ACTIVE, **after_b),
        _record("thread_unchanged_after_a", durable_after_a == durable_before, before=durable_before, after=durable_after_a),
        _record("report_unchanged_after_a", durable_after_a["snapshot_uuid"] == durable_before["snapshot_uuid"], before=durable_before, after=durable_after_a),
    ]
    del_b = http.post(f"/api/files/delete/{ids['file_b']}")
    after_b2 = _support_state(ids["support_b"])
    durable_after_b = _thread_snapshot_state()
    casefile_steps.append(_record("casefile_delete_b", del_b.status_code < 400, status=del_b.status_code, body=_json(del_b)))
    casefile_steps.append(_record("relationship_e_unsupported_after_b", after_b2["relationship_state"] != GraphValidationState.ACTIVE, **after_b2))
    casefile_steps.append(_record("thread_readable_after_b", durable_after_b["thread_uuid"] == durable_before["thread_uuid"] and durable_after_b["thread_uuid"] is not None, before=durable_before, after=durable_after_b))
    results["lifecycle"]["casefile"] = {"status": "PASS" if all(s["success"] for s in casefile_steps) else "FAIL", "steps": casefile_steps}

    pcap_before = _support_state(ids["pcap_sa"])
    pcap_del_a = http.post(f"/api/pcap/{ids['pcap_a']}/delete")
    pcap_after_a = _support_state(ids["pcap_sa"])
    pcap_after_b = _support_state(ids["pcap_sb"])
    pcap_steps = [
        _record("pcap_delete_a", pcap_del_a.status_code < 400, status=pcap_del_a.status_code, body=_json(pcap_del_a), before=pcap_before),
        _record("pcap_a_not_active", pcap_after_a["support_state"] not in (None, GraphSupportState.ACTIVE), **pcap_after_a),
        _record("pcap_b_still_active", pcap_after_b["support_state"] == GraphSupportState.ACTIVE, **pcap_after_b),
    ]
    pcap_del_b = http.post(f"/api/pcap/{ids['pcap_b']}/delete")
    pcap_after_b2 = _support_state(ids["pcap_sb"])
    pcap_steps.append(_record("pcap_delete_b", pcap_del_b.status_code < 400, status=pcap_del_b.status_code, body=_json(pcap_del_b)))
    pcap_steps.append(_record("pcap_rel_unsupported", pcap_after_b2["relationship_state"] != GraphValidationState.ACTIVE, **pcap_after_b2))
    results["lifecycle"]["pcap"] = {"status": "PASS" if all(s["success"] for s in pcap_steps) else "FAIL", "steps": pcap_steps}

    mem_del_a = http.post(f"/api/memory/job/{ids['mem_a']}/delete")
    mem_after_a = _support_state(ids["mem_sa"])
    mem_after_b = _support_state(ids["mem_sb"])
    mem_steps = [
        _record("memory_delete_a", mem_del_a.status_code < 400, status=mem_del_a.status_code, body=_json(mem_del_a)),
        _record("memory_a_not_active", mem_after_a["support_state"] not in (None, GraphSupportState.ACTIVE), **mem_after_a),
        _record("memory_b_still_active", mem_after_b["support_state"] == GraphSupportState.ACTIVE, **mem_after_b),
    ]
    mem_del_b = http.post(f"/api/memory/job/{ids['mem_b']}/delete")
    mem_after_b2 = _support_state(ids["mem_sb"])
    mem_steps.append(_record("memory_delete_b", mem_del_b.status_code < 400, status=mem_del_b.status_code, body=_json(mem_del_b)))
    mem_steps.append(_record("memory_rel_unsupported", mem_after_b2["relationship_state"] != GraphValidationState.ACTIVE, **mem_after_b2))
    results["lifecycle"]["memory"] = {"status": "PASS" if all(s["success"] for s in mem_steps) else "FAIL", "steps": mem_steps}

    with app.app_context():
        ioc_before = {
            "match_a": IOCEvidenceMatch.query.get(ids["match_a"]).support_state if IOCEvidenceMatch.query.get(ids["match_a"]) else None,
            "match_b": IOCEvidenceMatch.query.get(ids["match_b"]).support_state if IOCEvidenceMatch.query.get(ids["match_b"]) else None,
        }
    ioc_del = http.post(f"/api/iocs/{ids['ioc']}/delete", json={"case_uuid": case_uuid})
    with app.app_context():
        ioc_row = IOC.query.get(ids["ioc"])
        ioc_after = {
            "ioc_exists": ioc_row is not None,
            "match_a": IOCEvidenceMatch.query.get(ids["match_a"]).support_state if IOCEvidenceMatch.query.get(ids["match_a"]) else None,
            "match_b": IOCEvidenceMatch.query.get(ids["match_b"]).support_state if IOCEvidenceMatch.query.get(ids["match_b"]) else None,
        }
    ioc_steps = [
        _record("ioc_delete_route", ioc_del.status_code < 400, status=ioc_del.status_code, body=_json(ioc_del), before=ioc_before, after=ioc_after),
        _record("ioc_removed_or_unlinked", ioc_after["ioc_exists"] is False or ioc_del.status_code < 400, **ioc_after),
    ]
    results["lifecycle"]["ioc"] = {"status": "PASS" if all(s["success"] for s in ioc_steps) else "FAIL", "steps": ioc_steps}
    results["lifecycle"]["status"] = "PASS" if all(results["lifecycle"][k]["status"] == "PASS" for k in ("casefile", "pcap", "memory", "ioc")) else "FAIL"

    with app.app_context():
        before_counts = {
            "entities_a": GraphEntity.query.filter_by(case_id=ids["case_a"]["id"]).count(),
            "entities_b": GraphEntity.query.filter_by(case_id=ids["case_b"]["id"]).count(),
            "threads_a": InvestigationThread.query.filter_by(case_id=ids["case_a"]["id"]).count(),
            "views_a": GraphSavedView.query.filter_by(case_id=ids["case_a"]["id"]).count(),
            "snapshots_a": InvestigationThreadReportSnapshot.query.filter_by(case_id=ids["case_a"]["id"]).count(),
            "reports_a": CaseReport.query.filter_by(case_id=ids["case_a"]["id"]).count(),
            "ch_a": int(ch.query("SELECT count() FROM events WHERE case_id = {id:UInt32}", parameters={"id": ids["case_a"]["id"]}).result_rows[0][0]),
            "ch_b": int(ch.query("SELECT count() FROM events WHERE case_id = {id:UInt32}", parameters={"id": ids["case_b"]["id"]}).result_rows[0][0]),
            "svg_exists": Path(ids["svg_path"]).exists(),
            "png_exists": Path(ids["png_path"]).exists(),
        }
    delete_case = http.post(f"/admin/cases/{case_uuid}/delete", follow_redirects=True)
    delete_body = delete_case.get_data(as_text=True)[-2000:]
    with app.app_context():
        after_counts = {
            "entities_a": GraphEntity.query.filter_by(case_id=ids["case_a"]["id"]).count(),
            "support_a": GraphRelationshipEvidence.query.filter_by(case_id=ids["case_a"]["id"]).count(),
            "threads_a": InvestigationThread.query.filter_by(case_id=ids["case_a"]["id"]).count(),
            "memberships_a": InvestigationThreadEntity.query.filter_by(case_id=ids["case_a"]["id"]).count(),
            "views_a": GraphSavedView.query.filter_by(case_id=ids["case_a"]["id"]).count(),
            "snapshots_a": InvestigationThreadReportSnapshot.query.filter_by(case_id=ids["case_a"]["id"]).count(),
            "reports_a": CaseReport.query.filter_by(case_id=ids["case_a"]["id"]).count(),
            "case_a": Case.query.get(ids["case_a"]["id"]) is not None,
            "entities_b": GraphEntity.query.filter_by(case_id=ids["case_b"]["id"]).count(),
            "case_b": Case.query.get(ids["case_b"]["id"]) is not None,
            "ch_a": int(ch.query("SELECT count() FROM events WHERE case_id = {id:UInt32}", parameters={"id": ids["case_a"]["id"]}).result_rows[0][0]),
            "ch_b": int(ch.query("SELECT count() FROM events WHERE case_id = {id:UInt32}", parameters={"id": ids["case_b"]["id"]}).result_rows[0][0]),
            "svg_exists": Path(ids["svg_path"]).exists(),
            "png_exists": Path(ids["png_path"]).exists(),
            "audit_remaining": AuditLog.query.filter_by(case_uuid=case_uuid).count(),
        }
    deletion_steps = [
        _record("permanent_delete_route", delete_case.status_code < 400, status=delete_case.status_code, body=delete_body[-500:]),
        _record("deleted_graph_zero", after_counts["entities_a"] == 0 and after_counts["support_a"] == 0, **after_counts),
        _record("deleted_threads_zero", after_counts["threads_a"] == 0 and after_counts["views_a"] == 0 and after_counts["snapshots_a"] == 0 and after_counts["memberships_a"] == 0, **after_counts),
        _record("deleted_clickhouse_zero", after_counts["ch_a"] == 0, **after_counts),
        _record("deleted_renders_absent", after_counts["svg_exists"] is False and after_counts["png_exists"] is False, **after_counts),
        _record("control_case_unchanged", after_counts["case_b"] is True and after_counts["entities_b"] == before_counts["entities_b"] and after_counts["ch_b"] == before_counts["ch_b"], before=before_counts, after=after_counts),
        _record("audit_retained", after_counts["audit_remaining"] >= 0, audit_remaining=after_counts["audit_remaining"]),
    ]
    results["permanent_case_deletion"] = {
        "status": "PASS" if all(s["success"] for s in deletion_steps) else "FAIL",
        "before": before_counts,
        "after": after_counts,
        "steps": deletion_steps,
    }

    summary_b = analyst_client.get(f"/api/graph/{other_uuid}/summary")
    summary_a_missing = analyst_client.get(f"/api/graph/{case_uuid}/summary")
    cross_pre.append(_record("deleted_case_a_not_found", summary_a_missing.status_code in (403, 404), status=summary_a_missing.status_code))
    cross_pre.append(_record("case_b_still_readable", summary_b.status_code < 400, status=summary_b.status_code, body=_json(summary_b)))
    results["cross_case"] = {"status": "PASS" if all(r["success"] for r in cross_pre) else "FAIL", "operations": cross_pre}

    results["status"] = "PASS" if all(
        results[key].get("status") == "PASS"
        for key in ("lifecycle", "permanent_case_deletion", "permissions", "cross_case", "deployment_smoke")
    ) else "FAIL"
    output = Path(os.environ.get("PHASE0G_DEPLOYED_OUTPUT", "/tmp/casescope-phase0g-results/phase0g_deployed_runtime.json"))
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(results, indent=2, sort_keys=True, default=str), encoding="utf-8")
    print(json.dumps({"event": "phase0g_deployed_result", "output": str(output), "status": results["status"]}))
    return 0 if results["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
