#!/usr/bin/env python3
"""Improvement #1 smoke for a disposable fresh Ubuntu install."""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def _virt() -> str:
    try:
        return subprocess.check_output(["systemd-detect-virt"], text=True).strip()
    except Exception:
        return ""


def main() -> int:
    virt = _virt()
    hostname = os.uname().nodename
    pg = os.environ.get("DATABASE_URL", "")
    ch = os.environ.get("CLICKHOUSE_DATABASE", "")
    disposable = "phase0g_" in pg.lower() or "phase0g_" in ch.lower()
    if os.environ.get("PHASE0G_FRESH_INSTALL") != "1" and not (
        virt in {"lxc", "lxd"} and hostname.startswith("phase0g-")
    ):
        raise SystemExit(
            f"Refusing fresh-install smoke outside a disposable Phase 0G environment "
            f"(virt={virt or 'unknown'} hostname={hostname})"
        )
    if virt not in {"lxc", "lxd"} and not disposable:
        raise SystemExit("Refusing fresh-install smoke against a non-phase0g_ database on the host")
    os.environ.setdefault("SECRET_KEY", "phase0g-fresh-secret")
    from app import create_app
    from models.database import db
    from models.case import Case
    from models.client import Client
    from models.user import User
    from models.graph import GraphEntity, GraphRelationship, GraphRelationshipEvidence
    from config import PermissionLevel
    from utils.graph_identity import GraphDerivationType, GraphSupportState, GraphValidationState
    from utils.audit_chain import verify_chain

    from migrations.add_events_table import EVENTS_SCHEMA
    import clickhouse_connect

    app = create_app(run_startup_bootstrap=False, register_blueprints=True)
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False
    password = "Phase0gPass1"
    marker = f"PHASE0G_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}_fresh"
    with app.app_context():
        db.create_all()
        client_row = Client.query.filter_by(code="PHASE0G").first()
        if client_row is None:
            client_row = Client(name="PHASE0G Client", code="PHASE0G", timezone="UTC")
            db.session.add(client_row)
            db.session.flush()
        user = User.query.filter_by(username="phase0g_fresh_admin").first()
        if user is None:
            user = User(
                username="phase0g_fresh_admin",
                full_name="Phase0G Fresh Admin",
                email="phase0g-fresh-admin@example.test",
                permission_level=PermissionLevel.ADMINISTRATOR,
                created_by="phase0g",
            )
            user.set_password(password)
            db.session.add(user)
            db.session.flush()
        case = Case(
            uuid=str(uuid.uuid4()),
            name=f"{marker} fresh case",
            company="PHASE0G",
            description="Disposable fresh-install smoke case",
            created_by="phase0g",
            timezone="UTC",
            client_id=client_row.id,
        )
        db.session.add(case)
        db.session.flush()
        host = GraphEntity(case_id=case.id, entity_type="HOST", entity_key="host:host-01", display_value="HOST-01", canonical_value="host-01", metadata_json={"phase0g_marker": marker})
        proc = GraphEntity(case_id=case.id, entity_type="PROCESS", entity_key="process:host-01:pid:1234:anchor:1", display_value="proc.exe", canonical_value="proc.exe", metadata_json={"phase0g_marker": marker})
        db.session.add_all([host, proc])
        db.session.flush()
        rel = GraphRelationship(
            case_id=case.id,
            source_entity_id=proc.id,
            relationship_type="ON_HOST",
            target_entity_id=host.id,
            confidence=1.0,
            derivation_type=GraphDerivationType.OBSERVED,
            extractor_name="phase0g_fresh_smoke",
            extractor_version="1",
            validation_state=GraphValidationState.ACTIVE,
            metadata_json={"phase0g_marker": marker},
        )
        db.session.add(rel)
        db.session.flush()
        erk = "erk:v2:" + hashlib.sha256(f"{marker}|event|1".encode("utf-8")).hexdigest()
        db.session.add(GraphRelationshipEvidence(
            case_id=case.id,
            relationship_id=rel.id,
            evidence_record_key=erk,
            source_table="events",
            evidence_role="supporting_record",
            extractor_name="phase0g_fresh_smoke",
            extractor_version="1",
            observed_at=datetime(2026, 1, 1),
            metadata_json={"phase0g_marker": marker},
            support_state=GraphSupportState.ACTIVE,
        ))
        db.session.commit()
        ids = {"case_id": case.id, "case": case.uuid, "host": host.id, "rel": rel.id, "erk": erk}

    ch = clickhouse_connect.get_client(
        host=os.environ.get("CLICKHOUSE_HOST", "localhost"),
        port=int(os.environ.get("CLICKHOUSE_PORT", "8123")),
        database=os.environ.get("CLICKHOUSE_DATABASE", "casescope"),
        username=os.environ.get("CLICKHOUSE_USER", "default"),
        password=os.environ.get("CLICKHOUSE_PASSWORD", ""),
    )
    ch.command(EVENTS_SCHEMA)
    ts = datetime(2026, 1, 1, tzinfo=timezone.utc)
    ch.insert(
        "events",
        [[
            ids["case_id"], "evtx_security", ts, ts, "phase0g.evtx", "/phase0g/phase0g.evtx", "HOST-01",
            None, "4688", "Administrator", "0x3e7", 1234, "10.1.2.3", "10.9.8.7",
            json.dumps({"phase0g_marker": marker}), f"{marker} HOST-01 Administrator", json.dumps({"logical_index": 1}),
            "phase0g:v1", ids["erk"], "v2", "native-or-content",
        ]],
        column_names=[
            "case_id", "artifact_type", "timestamp", "timestamp_utc", "source_file", "source_path", "source_host",
            "case_file_id", "event_id", "username", "logon_id", "process_id", "src_ip", "dst_ip", "raw_json",
            "search_blob", "extra_fields", "parser_version", "evidence_record_key", "evidence_identity_version",
            "evidence_identity_quality",
        ],
    )

    http = app.test_client()
    http.get("/logout", follow_redirects=True)
    login = http.post("/login", data={"username": "phase0g_fresh_admin", "password": password}, follow_redirects=True)
    steps = [{"operation": "login", "success": login.status_code < 400, "status": login.status_code}]
    case_uuid = ids["case"]
    checks = [
        ("graph_summary", "get", f"/api/graph/{case_uuid}/summary", {}),
        ("entity_search", "get", f"/api/graph/{case_uuid}/entities/search", {"query_string": {"q": "HOST-01"}}),
        ("entity_detail", "get", f"/api/graph/{case_uuid}/entities/{ids['host']}", {}),
        ("neighbors", "get", f"/api/graph/{case_uuid}/entities/{ids['host']}/neighbors", {}),
        ("relationship_detail", "get", f"/api/graph/{case_uuid}/relationships/{ids['rel']}", {}),
        ("relationship_support", "get", f"/api/graph/{case_uuid}/relationships/{ids['rel']}/evidence", {}),
        ("exact_erk", "get", f"/api/graph/{case_uuid}/evidence/{ids['erk']}", {}),
        ("paths", "post", f"/api/graph/{case_uuid}/paths", {"json": {"source_entity_id": ids["host"], "target_entity_id": ids["host"], "max_depth": 2, "max_paths": 3}}),
        ("context_relative", "get", f"/api/investigation/{case_uuid}/context", {"query_string": {"anchor_erk": ids["erk"], "mode": "relative", "window": "30s"}}),
        ("context_host", "get", f"/api/investigation/{case_uuid}/context", {"query_string": {"anchor_erk": ids["erk"], "mode": "same_host"}}),
        ("context_process", "get", f"/api/investigation/{case_uuid}/context", {"query_string": {"anchor_erk": ids["erk"], "mode": "process_lifetime"}}),
        ("context_logon", "get", f"/api/investigation/{case_uuid}/context", {"query_string": {"anchor_erk": ids["erk"], "mode": "logon_session"}}),
    ]
    for name, method, path, kwargs in checks:
        resp = getattr(http, method)(path, **kwargs)
        steps.append({"operation": name, "success": resp.status_code < 400, "status": resp.status_code})
    thread = http.post(f"/api/investigation-threads/{case_uuid}", json={"title": "Thread T"})
    payload = thread.get_json(silent=True) or {}
    thread_uuid = (payload.get("thread") or {}).get("uuid")
    version = (payload.get("thread") or {}).get("version")
    steps.append({"operation": "thread_create", "success": thread.status_code in (200, 201), "status": thread.status_code})
    if thread_uuid:
        upd = http.patch(f"/api/investigation-threads/{case_uuid}/{thread_uuid}", json={"expected_version": version, "description": "updated"})
        steps.append({"operation": "thread_update", "success": upd.status_code < 400, "status": upd.status_code})
        version = ((upd.get_json(silent=True) or {}).get("thread") or {}).get("version", version)
        def _refresh_version(current):
            got = http.get(f"/api/investigation-threads/{case_uuid}/{thread_uuid}")
            return ((got.get_json(silent=True) or {}).get("thread") or {}).get("version", current)
        version = _refresh_version(version)
        for op, path, body in [
            ("thread_add_entity", f"/api/investigation-threads/{case_uuid}/{thread_uuid}/entities", {"expected_version": version, "entity_id": ids["host"]}),
            ("thread_add_relationship", f"/api/investigation-threads/{case_uuid}/{thread_uuid}/relationships", {"expected_version": None, "relationship_id": ids["rel"]}),
            ("thread_add_evidence", f"/api/investigation-threads/{case_uuid}/{thread_uuid}/evidence", {"expected_version": None, "evidence_record_key": ids["erk"]}),
            ("thread_add_note", f"/api/investigation-threads/{case_uuid}/{thread_uuid}/notes", {"expected_version": None, "body": "fresh smoke note"}),
        ]:
            body["expected_version"] = version
            resp = http.post(path, json=body)
            steps.append({"operation": op, "success": resp.status_code < 400, "status": resp.status_code})
            version = _refresh_version(version)
    view = http.post(f"/api/graph/{case_uuid}/views", json={"title": "Saved View V", "root_entity_ids": [ids["host"]]})
    view_payload = (view.get_json(silent=True) or {}).get("view") or {}
    steps.append({"operation": "saved_view_create", "success": view.status_code in (200, 201), "status": view.status_code})
    if view_payload.get("uuid"):
        load = http.get(f"/api/graph/{case_uuid}/views/{view_payload['uuid']}")
        steps.append({"operation": "saved_view_load", "success": load.status_code < 400, "status": load.status_code})
        upd = http.put(f"/api/graph/{case_uuid}/views/{view_payload['uuid']}", json={"expected_version": view_payload.get("version"), "title": "Saved View V2", "root_entity_ids": [ids["host"]]})
        steps.append({"operation": "saved_view_update", "success": upd.status_code < 400, "status": upd.status_code})
        if thread_uuid:
            version = _refresh_version(version)
            link = http.patch(f"/api/investigation-threads/{case_uuid}/{thread_uuid}", json={"expected_version": version, "current_saved_view_uuid": view_payload["uuid"]})
            steps.append({"operation": "thread_link_view", "success": link.status_code < 400, "status": link.status_code})
            version = ((link.get_json(silent=True) or {}).get("thread") or {}).get("version", version)
            snap = http.post(
                f"/api/investigation/{case_uuid}/report-snapshots",
                json={
                    "thread_uuid": thread_uuid,
                    "expected_thread_version": version,
                    "expected_saved_view_version": ((upd.get_json(silent=True) or {}).get("view") or view_payload).get("version"),
                },
            )
            snap_json = snap.get_json(silent=True) or {}
            steps.append({"operation": "report_snapshot", "success": snap.status_code in (200, 201), "status": snap.status_code, "ai_used": (snap_json.get("snapshot") or snap_json).get("ai_used"), "body": snap_json})
    with app.app_context():
        chain = verify_chain()
        steps.append({"operation": "audit_chain", "success": bool(chain.get("valid", chain) if isinstance(chain, dict) else chain), "result": chain})
    result = {
        "status": "PASS" if all(item["success"] for item in steps) else "FAIL",
        "virt": virt,
        "hostname": hostname,
        "marker": marker,
        "steps": steps,
    }
    output = Path(os.environ.get("PHASE0G_FRESH_SMOKE_OUTPUT", "/opt/casescope/temp/phase0g_fresh_smoke.json"))
    output.write_text(json.dumps(result, indent=2, default=str), encoding="utf-8")
    print(json.dumps({"event": "phase0g_fresh_smoke", "status": result["status"], "output": str(output)}))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
