"""Phase 1B Tranche F2 publication gate against the actual Hunt Artifacts path.

This is a verification gate, not a product-reader migration. It calls
`GET /api/hunting/events/<case_id>` (`routes.hunting.get_hunting_events`),
the endpoint used by `static/templates/case_hunting.html`.
"""
from __future__ import annotations

import json
import os
import tempfile
import time
import unittest
from copy import deepcopy
from datetime import datetime, timedelta
from unittest.mock import patch

os.environ.setdefault("SECRET_KEY", "phase1b-f2-gate-secret")

import clickhouse_connect
from flask import Flask
from flask_login import LoginManager
from sqlalchemy import text

from config import Config
from migrations.add_events_table import EVENTS_COLUMN_DEFINITIONS
from models.case import Case
from models.case_file import CaseFile, IngestProtocolOrigin
from models.client import Client
from models.database import db
from models.database_flow import (
    EvidenceGenerationAudit,
    EvidenceSourceGeneration,
    IngestAttempt,
    IngestBatch,
)
from parsers.log_parsers import IISLogParser
from routes.hunting import hunting_bp
from utils.ingest_fence import install_memory_backend, reset_fence_backend
from utils.manifest_protocol import (
    ManifestParserContract,
    activate_initial_generation,
    activate_replacement_generation,
    allocate_case_file_initial_generation,
    allocate_case_file_replacement_generation,
    construct_managed_batch,
    create_ingest_attempt,
    declare_generation_ingest_complete,
    insert_managed_batch,
    mark_batch_durable,
    project_generation_authority_swap,
    project_generation_control_state,
    reserve_staged_batch,
    update_generation_ingest_accounting,
    verify_ingest_batch,
)


PG_URL = os.environ.get("PHASE1B_PG_TEST_DATABASE_URL")
CH_DB = os.environ.get("PHASE1B_CH_TEST_DATABASE")

POSTGRES_INDEX_DDL = [
    """
    CREATE UNIQUE INDEX IF NOT EXISTS uq_evidence_source_generation_open_building
    ON evidence_source_generations (case_id, source_ref_type, source_ref_id)
    WHERE visibility_state IN ('BUILDING_INITIAL', 'BUILDING_REPLACEMENT')
    """,
    """
    CREATE UNIQUE INDEX IF NOT EXISTS uq_evidence_source_generation_active
    ON evidence_source_generations (case_id, source_ref_type, source_ref_id)
    WHERE visibility_state = 'ACTIVE'
    """,
]

CLICKHOUSE_CONTROL_TABLE_DDL = [
    """
    CREATE TABLE IF NOT EXISTS visible_evidence_generations (
        case_id UInt32,
        source_ref_type String,
        source_ref_id String,
        source_generation UInt32,
        visibility_state LowCardinality(String),
        state_version UInt64,
        publishable UInt8,
        updated_at DateTime64(3) DEFAULT now64(3)
    )
    ENGINE = ReplacingMergeTree(state_version)
    ORDER BY (case_id, source_ref_type, source_ref_id, source_generation)
    SETTINGS index_granularity = 8192
    """,
    """
    CREATE TABLE IF NOT EXISTS durable_ingest_batches (
        ingest_batch_id String,
        case_id UInt32,
        source_ref_type String,
        source_ref_id String,
        source_generation UInt32,
        batch_ordinal UInt32,
        expected_row_count UInt64,
        batch_content_hash String,
        state LowCardinality(String),
        state_version UInt64,
        durable_at Nullable(DateTime64(3)),
        updated_at DateTime64(3) DEFAULT now64(3)
    )
    ENGINE = ReplacingMergeTree(state_version)
    ORDER BY ingest_batch_id
    SETTINGS index_granularity = 8192
    """,
]


class _GateUser:
    is_authenticated = True
    is_active = True
    is_anonymous = False
    id = 1
    username = "f2-gate"
    permission_level = "analyst"

    def get_id(self):
        return "1"

    def can_access_case(self, _case_id):
        return True


@unittest.skipUnless(PG_URL and CH_DB, "PHASE1B_PG_TEST_DATABASE_URL and PHASE1B_CH_TEST_DATABASE are required")
class Phase1BF2ProductSearchPublicationGateTestCase(unittest.TestCase):
    """Prove whether the actual Hunt Artifacts path obeys Phase 1B publication."""

    PRODUCT_PATH = "GET /api/hunting/events/<case_id> -> routes.hunting.get_hunting_events"

    @classmethod
    def setUpClass(cls):
        install_memory_backend()
        cls._old_flag = getattr(Config, "PHASE1B_MANIFEST_PROTOCOL_ENABLED", False)
        cls._old_batch_size = getattr(Config, "PHASE1B_MANIFEST_BATCH_SIZE", None)
        Config.PHASE1B_MANIFEST_PROTOCOL_ENABLED = True
        Config.PHASE1B_MANIFEST_BATCH_SIZE = 4
        cls.app = Flask(__name__)
        cls.app.config.update(
            SQLALCHEMY_DATABASE_URI=PG_URL,
            SQLALCHEMY_TRACK_MODIFICATIONS=False,
            SECRET_KEY="phase1b-f2-gate",
            LOGIN_DISABLED=False,
        )
        db.init_app(cls.app)
        login_manager = LoginManager()
        login_manager.init_app(cls.app)
        login_manager.user_loader(lambda _user_id: _GateUser())
        cls.app.register_blueprint(hunting_bp)
        cls.ctx = cls.app.app_context()
        cls.ctx.push()
        db.session.remove()
        with db.engine.begin() as conn:
            conn.execute(text("DROP SCHEMA IF EXISTS public CASCADE"))
            conn.execute(text("CREATE SCHEMA public"))
        for table in (
            Client.__table__,
            Case.__table__,
            CaseFile.__table__,
            EvidenceSourceGeneration.__table__,
            EvidenceGenerationAudit.__table__,
            IngestAttempt.__table__,
            IngestBatch.__table__,
        ):
            table.create(db.engine, checkfirst=True)
        with db.engine.begin() as conn:
            for ddl in POSTGRES_INDEX_DDL:
                conn.execute(text(ddl))
        cls.ch = clickhouse_connect.get_client(
            host=os.environ.get("CLICKHOUSE_HOST", "localhost"),
            port=int(os.environ.get("CLICKHOUSE_PORT", 8123)),
            username=os.environ.get("CLICKHOUSE_USER", "default"),
            password=os.environ.get("CLICKHOUSE_PASSWORD", ""),
            database=CH_DB,
            autogenerate_session_id=False,
        )
        columns = ",\n".join(f"    {name} {definition}" for name, definition in EVENTS_COLUMN_DEFINITIONS.items())
        cls.ch.command(f"""
        CREATE TABLE IF NOT EXISTS events (
        {columns}
        )
        ENGINE = MergeTree
        PARTITION BY case_id
        ORDER BY (case_id, timestamp_utc, artifact_type, source_host, source_file, event_id)
        SETTINGS index_granularity = 8192
        """)
        for ddl in CLICKHOUSE_CONTROL_TABLE_DDL:
            cls.ch.command(ddl)

    @classmethod
    def tearDownClass(cls):
        cls.ch.command("DROP TABLE IF EXISTS events")
        cls.ch.command("DROP TABLE IF EXISTS visible_evidence_generations")
        cls.ch.command("DROP TABLE IF EXISTS durable_ingest_batches")
        cls.ch.command("DROP TABLE IF EXISTS event_mitre_matches")
        cls.ch.close()
        with db.engine.begin() as conn:
            conn.execute(text("DROP SCHEMA IF EXISTS public CASCADE"))
            conn.execute(text("CREATE SCHEMA public"))
        cls.ctx.pop()
        Config.PHASE1B_MANIFEST_PROTOCOL_ENABLED = cls._old_flag
        if cls._old_batch_size is None:
            try:
                delattr(Config, "PHASE1B_MANIFEST_BATCH_SIZE")
            except AttributeError:
                pass
        else:
            Config.PHASE1B_MANIFEST_BATCH_SIZE = cls._old_batch_size
        reset_fence_backend()

    def setUp(self):
        self.ch.command("TRUNCATE TABLE events")
        self.ch.command("TRUNCATE TABLE visible_evidence_generations")
        self.ch.command("TRUNCATE TABLE durable_ingest_batches")
        IngestBatch.query.delete()
        IngestAttempt.query.delete()
        EvidenceGenerationAudit.query.delete()
        EvidenceSourceGeneration.query.delete()
        CaseFile.query.delete()
        Case.query.delete()
        Client.query.delete()
        db.session.commit()
        self.client_row = Client(name="F2 Gate", code=f"F2G{time.time_ns() % 100000}", created_by="tester")
        self.case = Case(
            uuid=f"f2-gate-{time.time_ns()}",
            name="F2 Gate",
            company="Example",
            client=self.client_row,
            created_by="tester",
        )
        self.tempdir = tempfile.TemporaryDirectory()
        iis_path = os.path.join(self.tempdir.name, "u_ex260101.log")
        lines = [
            "#Software: Microsoft Internet Information Services",
            "#Version: 1.0",
            "#Fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs(User-Agent) sc-status",
        ]
        for idx in range(8):
            query = f"id={idx}&q=alpha" if idx % 2 else "-"
            username = f"user{idx}" if idx % 3 else "-"
            lines.append(
                f"2026-01-01 00:00:{idx:02d} 10.0.0.10 GET /path/{idx} {query} 443 {username} 192.0.2.{idx + 1} Agent{idx} 200"
            )
        with open(iis_path, "w", encoding="utf-8") as handle:
            handle.write("\n".join(lines) + "\n")
        self.case_file = CaseFile(
            case_uuid=self.case.uuid,
            filename="u_ex260101.log",
            original_filename="u_ex260101.log",
            file_path=iis_path,
            file_size=1,
            sha256_hash="c" * 64,
            uploaded_by="tester",
            ingest_protocol_origin=IngestProtocolOrigin.NOT_STARTED,
        )
        db.session.add_all([self.client_row, self.case, self.case_file])
        db.session.commit()
        parser = IISLogParser(case_id=self.case.id, case_file_id=self.case_file.id)
        self.events = list(parser.parse(iis_path))
        self.contract = ManifestParserContract(
            parser_version=parser.parser_version,
            normalization_version="normalization:v1",
            configured_batch_size=4,
            ordering_contract=parser.manifest_ordering_contract,
            producer_version=parser.parser_version,
            manifest_eligible=True,
        )

    def tearDown(self):
        db.session.remove()
        self.tempdir.cleanup()

    def _product_search(self):
        with patch("utils.clickhouse.get_client", return_value=self.ch):
            client = self.app.test_client()
            with client.session_transaction() as session:
                session["_user_id"] = "1"
                session["_fresh"] = True
            response = client.get(f"/api/hunting/events/{self.case.id}")
        payload = response.get_json() or {}
        self.assertEqual(
            response.status_code,
            200,
            msg=f"{self.PRODUCT_PATH} HTTP {response.status_code}: {payload}",
        )
        self.assertTrue(payload.get("success"), msg=payload)
        events = payload.get("events") or []
        return {
            "total": payload.get("total"),
            "event_ids": [str(event.get("event_id") or "") for event in events],
            "search_blobs": [str(event.get("search_blob") or "") for event in events],
        }

    def _ingest_slice(self, generation, events, *, batch_ordinal, durable):
        attempt = create_ingest_attempt(session=db.session, generation=generation)
        manifest = construct_managed_batch(
            generation=generation,
            attempt=attempt,
            events=events,
            batch_ordinal=batch_ordinal,
        )
        batch = reserve_staged_batch(session=db.session, manifest=manifest)
        db.session.commit()
        insert_managed_batch(self.ch, manifest)
        if durable:
            mark_batch_durable(
                session=db.session,
                batch=batch,
                verification=verify_ingest_batch(self.ch, manifest),
            )
            update_generation_ingest_accounting(session=db.session, generation=generation)
            db.session.commit()
            project_generation_control_state(self.ch, db.session, generation)
        return batch, manifest

    def test_actual_hunt_artifacts_path_obeys_phase1b_publication(self):
        slices = [self.events[0:4], self.events[4:8]]
        staged_blobs = {event.search_blob for event in slices[0]}
        durable_blobs = {event.search_blob for event in slices[0]}
        n_blobs = {event.search_blob for event in self.events}

        observations = {
            "product_path": self.PRODUCT_PATH,
            "from_clause": "FROM events AS e",
            "publication_join": False,
        }

        generation = allocate_case_file_initial_generation(
            session=db.session,
            case_id=self.case.id,
            case_file_id=self.case_file.id,
            contract=self.contract,
        )
        db.session.commit()
        batch0, manifest0 = self._ingest_slice(generation, slices[0], batch_ordinal=0, durable=False)
        found = self._product_search()
        observations["A_staged_physical_present"] = True
        observations["A_staged_blobs"] = sorted(staged_blobs)
        observations["A_staged_returned_blobs"] = sorted(set(found["search_blobs"]) & staged_blobs)
        observations["A_staged_visible"] = bool(set(found["search_blobs"]) & staged_blobs)
        observations["A_product_total"] = found["total"]

        generation = db.session.get(EvidenceSourceGeneration, generation.id)
        batch0 = db.session.get(IngestBatch, batch0.id)
        mark_batch_durable(
            session=db.session,
            batch=batch0,
            verification=verify_ingest_batch(self.ch, manifest0),
        )
        update_generation_ingest_accounting(session=db.session, generation=generation)
        db.session.commit()
        project_generation_control_state(self.ch, db.session, generation)
        self.assertIsNone(generation.completed_at)
        found = self._product_search()
        observations["B_building_initial_eof"] = generation.completed_at is not None
        observations["B_durable_blobs"] = sorted(durable_blobs)
        observations["B_durable_returned_blobs"] = sorted(set(found["search_blobs"]) & durable_blobs)
        observations["B_durable_building_initial_searchable"] = bool(set(found["search_blobs"]) & durable_blobs)
        observations["B_product_total"] = found["total"]

        self._ingest_slice(generation, slices[1], batch_ordinal=1, durable=True)
        declare_generation_ingest_complete(
            session=db.session,
            generation=generation,
            expected_rows=len(self.events),
            final_batch_ordinal=1,
        )
        activate_initial_generation(session=db.session, generation=generation, actor="f2-gate")
        db.session.commit()
        project_generation_control_state(self.ch, db.session, generation)
        found = self._product_search()
        observations["active_n_visible"] = n_blobs.issubset(set(found["search_blobs"]))

        replacement_events = []
        for idx, event in enumerate(self.events):
            copied = deepcopy(event)
            copied.event_id = f"repl-{idx}"
            copied.record_id = 100 + idx
            copied.search_blob = f"replacement {idx} {event.search_blob}"
            copied.timestamp = datetime(2026, 2, 1) + timedelta(seconds=idx)
            copied.timestamp_utc = copied.timestamp
            replacement_events.append(copied)
        replacement_ids = {event.event_id for event in replacement_events}
        replacement = allocate_case_file_replacement_generation(
            session=db.session,
            case_id=self.case.id,
            case_file_id=self.case_file.id,
            contract=self.contract,
        )
        db.session.commit()
        self._ingest_slice(replacement, replacement_events[0:4], batch_ordinal=0, durable=True)
        self._ingest_slice(replacement, replacement_events[4:8], batch_ordinal=1, durable=True)
        found = self._product_search()
        observations["C_replacement_ids"] = sorted(replacement_ids)
        observations["C_replacement_returned_ids"] = sorted(
            set(found["event_ids"]) & replacement_ids
        )
        observations["C_n_blobs_still_visible"] = bool(set(found["search_blobs"]) & n_blobs)
        observations["C_replacement_visible_before_activation"] = bool(
            set(found["event_ids"]) & replacement_ids
        )
        observations["C_product_total"] = found["total"]

        declare_generation_ingest_complete(
            session=db.session,
            generation=replacement,
            expected_rows=len(replacement_events),
            final_batch_ordinal=1,
        )
        activate_replacement_generation(
            session=db.session,
            replacement=replacement,
            actor="f2-gate",
        )
        db.session.commit()
        generation = db.session.get(EvidenceSourceGeneration, generation.id)
        replacement = db.session.get(EvidenceSourceGeneration, replacement.id)
        project_generation_authority_swap(
            self.ch,
            db.session,
            prior_generation=generation,
            new_generation=replacement,
        )
        found = self._product_search()
        observations["D_n_state"] = generation.visibility_state
        observations["D_n1_state"] = replacement.visibility_state
        observations["D_stale_n_visible"] = bool(set(found["search_blobs"]) & n_blobs)
        observations["D_n1_visible"] = bool(set(found["event_ids"]) & replacement_ids)
        observations["D_product_total"] = found["total"]
        observations["D_authority_follows_current_generation_only"] = (
            bool(set(found["event_ids"]) & replacement_ids)
            and not bool(set(found["search_blobs"]) & n_blobs)
        )

        failures = []
        if observations["A_staged_visible"]:
            failures.append("STAGED rows are returned by the actual Hunt Artifacts path")
        if not observations["B_durable_building_initial_searchable"]:
            failures.append("DURABLE BUILDING_INITIAL rows are not searchable before EOF")
        if observations["C_replacement_visible_before_activation"]:
            failures.append("BUILDING_REPLACEMENT rows are returned before activation")
        if not observations["D_authority_follows_current_generation_only"]:
            failures.append("after activation, search does not follow current-generation authority only")

        self.assertEqual(
            failures,
            [],
            msg="Phase 1B product publication gate failed on "
            f"{self.PRODUCT_PATH}: {json.dumps(observations, indent=2)}",
        )
