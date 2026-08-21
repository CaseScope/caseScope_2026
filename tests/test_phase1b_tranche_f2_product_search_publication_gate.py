"""Phase 1B Tranche F2 publication gate against the actual Hunt Artifacts path.

This is a verification gate, not a product-reader migration. It calls
`GET /api/hunting/events/<case_id>` (`routes.hunting.get_hunting_events`),
the endpoint used by `static/templates/case_hunting.html`.
"""
from __future__ import annotations

import json
import os
import time
import tempfile
import unittest
from copy import deepcopy
from datetime import datetime, timedelta
from unittest.mock import patch
from urllib.parse import urlencode

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
    EvidenceGenerationState,
    EvidenceSourceGeneration,
    IngestAttempt,
    IngestBatch,
)
from utils.clickhouse import clickhouse_string_literal
from parsers.base import ParsedEvent
from parsers.log_parsers import IISLogParser
from routes.hunting import hunting_bp
from routes.hunting_query_helpers import build_hunting_publication_bridge
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


class _CountingClickHouse:
    def __init__(self, inner):
        self._inner = inner
        self.queries = []
        self.commands = []

    def query(self, *args, **kwargs):
        sql = args[0] if args else kwargs.get("query", "")
        self.queries.append(sql)
        return self._inner.query(*args, **kwargs)

    def command(self, *args, **kwargs):
        sql = args[0] if args else kwargs.get("cmd", kwargs.get("query", ""))
        self.commands.append(sql)
        return self._inner.command(*args, **kwargs)

    def insert(self, *args, **kwargs):
        return self._inner.insert(*args, **kwargs)

    def __getattr__(self, name):
        return getattr(self._inner, name)


class HuntingPublicationBridgeUnitTestCase(unittest.TestCase):
    def test_bridge_uses_final_control_projections_and_legacy_null_identity(self):
        bridge = build_hunting_publication_bridge(alias="e")
        join_sql = bridge["join_sql"]
        where_sql = bridge["where_sql"]
        self.assertIn("FROM visible_evidence_generations FINAL", join_sql)
        self.assertIn("FROM durable_ingest_batches FINAL", join_sql)
        self.assertIn("veg.publishable = 1", where_sql)
        self.assertIn("BUILDING_INITIAL", where_sql)
        self.assertIn("ACTIVE", where_sql)
        self.assertIn("dib.state = 'DURABLE'", where_sql)
        self.assertIn("e.source_ref_type IS NULL", where_sql)
        self.assertIn("e.ingest_attempt_id IS NULL", where_sql)
        self.assertNotIn("events_current", join_sql + where_sql)
        self.assertNotIn("event_observations_current", join_sql + where_sql)
        self.assertNotIn("redis", (join_sql + where_sql).lower())


@unittest.skipUnless(PG_URL and CH_DB, "PHASE1B_PG_TEST_DATABASE_URL and PHASE1B_CH_TEST_DATABASE are required")
class Phase1BF2ProductSearchPublicationGateTestCase(unittest.TestCase):
    """Prove the actual Hunt Artifacts path obeys Phase 1B publication."""

    PRODUCT_PATH = "GET /api/hunting/events/<case_id> -> routes.hunting.get_hunting_events"
    DETAIL_PATH = "GET /api/hunting/event/detail/<case_id> -> routes.hunting.get_hunting_event_detail"
    RAW_PATH = "GET /api/hunting/event/raw/<case_id> -> routes.hunting.get_raw_event_data"

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

    def _request(self, path, *, counter=None):
        wrapper = counter if counter is not None else self.ch
        with patch("utils.clickhouse.get_client", return_value=wrapper):
            client = self.app.test_client()
            with client.session_transaction() as session:
                session["_user_id"] = "1"
                session["_fresh"] = True
            return client.get(path)

    def _product_search(self, extra_params=None, *, counter=None):
        query = f"/api/hunting/events/{self.case.id}"
        if extra_params:
            query = f"{query}?{urlencode(extra_params, doseq=True)}"
        response = self._request(query, counter=counter)
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
            "page": payload.get("page"),
            "per_page": payload.get("per_page"),
            "total_pages": payload.get("total_pages"),
            "event_ids": [str(event.get("event_id") or "") for event in events],
            "search_blobs": [str(event.get("search_blob") or "") for event in events],
            "selector_keys": [str(event.get("selector_key") or "") for event in events],
            "artifact_types": [str(event.get("artifact_type") or "") for event in events],
            "events": events,
            "payload": payload,
        }

    def _product_token_search(self, **kwargs):
        params = {"search": "alpha"}
        params.update(kwargs)
        return self._product_search(params)

    def _product_detail(self, selector_key, *, counter=None):
        query = f"/api/hunting/event/detail/{self.case.id}?{urlencode({'selector_key': selector_key})}"
        response = self._request(query, counter=counter)
        return response.status_code, response.get_json() or {}

    def _product_raw(self, selector_key, *, counter=None):
        query = f"/api/hunting/event/raw/{self.case.id}?{urlencode({'selector_key': selector_key})}"
        response = self._request(query, counter=counter)
        return response.status_code, response.get_json() or {}

    def _assert_hidden_selector(self, selector_key, label):
        detail_status, detail_payload = self._product_detail(selector_key)
        self.assertEqual(
            detail_status,
            404,
            msg=f"{self.DETAIL_PATH} exposed {label}: {detail_payload}",
        )
        raw_status, raw_payload = self._product_raw(selector_key)
        self.assertEqual(
            raw_status,
            404,
            msg=f"{self.RAW_PATH} exposed {label}: {raw_payload}",
        )

    def _assert_visible_selector(self, selector_key, label):
        detail_status, detail_payload = self._product_detail(selector_key)
        self.assertEqual(
            detail_status,
            200,
            msg=f"{self.DETAIL_PATH} hid {label}: {detail_payload}",
        )
        self.assertTrue(detail_payload.get("success"), msg=detail_payload)
        raw_status, raw_payload = self._product_raw(selector_key)
        self.assertEqual(
            raw_status,
            200,
            msg=f"{self.RAW_PATH} hid {label}: {raw_payload}",
        )

    def _selector_for_blob(self, search_blob):
        rows = self.ch.query(
            """
            SELECT selector_key
            FROM events
            WHERE case_id = {case_id:UInt32}
              AND search_blob = {search_blob:String}
            LIMIT 1
            """,
            parameters={"case_id": self.case.id, "search_blob": search_blob},
        ).result_rows
        self.assertTrue(rows, msg=f"missing physical row for blob {search_blob!r}")
        return str(rows[0][0])

    def _selector_for_event_id(self, event_id):
        rows = self.ch.query(
            """
            SELECT selector_key
            FROM events
            WHERE case_id = {case_id:UInt32}
              AND event_id = {event_id:String}
            LIMIT 1
            """,
            parameters={"case_id": self.case.id, "event_id": event_id},
        ).result_rows
        self.assertTrue(rows, msg=f"missing physical row for event_id {event_id!r}")
        return str(rows[0][0])

    def _insert_legacy_event(self, event):
        copied = deepcopy(event)
        self.ch.insert(
            "events",
            [copied.to_clickhouse_row()],
            column_names=list(ParsedEvent.clickhouse_columns()),
        )

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
        first_batch_blobs = {event.search_blob for event in slices[0]}
        second_batch_blobs = {event.search_blob for event in slices[1]}
        n_blobs = {event.search_blob for event in self.events}

        observations = {
            "product_path": self.PRODUCT_PATH,
            "from_clause": "FROM events AS e",
            "publication_join": True,
        }

        generation = allocate_case_file_initial_generation(
            session=db.session,
            case_id=self.case.id,
            case_file_id=self.case_file.id,
            contract=self.contract,
        )
        db.session.commit()
        batch0, manifest0 = self._ingest_slice(generation, slices[0], batch_ordinal=0, durable=False)
        staged_selector = self._selector_for_blob(next(iter(staged_blobs)))
        found = self._product_search()
        observations["A_staged_physical_present"] = True
        observations["A_staged_blobs"] = sorted(staged_blobs)
        observations["A_staged_returned_blobs"] = sorted(set(found["search_blobs"]) & staged_blobs)
        observations["A_staged_visible"] = bool(set(found["search_blobs"]) & staged_blobs)
        observations["A_product_total"] = found["total"]
        self.assertFalse(observations["A_staged_visible"], msg=json.dumps(observations, indent=2))
        self.assertEqual(found["total"], 0)
        token = self._product_token_search()
        observations["A_token_safe_total"] = token["total"]
        self.assertEqual(token["total"], 0)
        self._assert_hidden_selector(staged_selector, "STAGED managed row")

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
        observations["B_durable_blobs"] = sorted(first_batch_blobs)
        observations["B_durable_returned_blobs"] = sorted(set(found["search_blobs"]) & first_batch_blobs)
        observations["B_durable_building_initial_searchable"] = first_batch_blobs.issubset(set(found["search_blobs"]))
        observations["B_product_total"] = found["total"]
        self.assertTrue(observations["B_durable_building_initial_searchable"], msg=json.dumps(observations, indent=2))
        self.assertEqual(found["total"], 4)
        token = self._product_token_search()
        alpha_first = {blob for blob in first_batch_blobs if "alpha" in blob}
        observations["B_token_safe_blobs"] = sorted(token["search_blobs"])
        observations["B_token_safe_searchable_before_eof"] = bool(alpha_first) and alpha_first.issubset(set(token["search_blobs"]))
        self.assertTrue(observations["B_token_safe_searchable_before_eof"], msg=json.dumps(observations, indent=2))
        self.assertTrue(set(token["search_blobs"]).issubset(first_batch_blobs))
        self._assert_visible_selector(self._selector_for_blob(next(iter(first_batch_blobs))), "DURABLE BUILDING_INITIAL")

        self._ingest_slice(generation, slices[1], batch_ordinal=1, durable=True)
        found = self._product_search()
        observations["C_second_batch_visible"] = second_batch_blobs.issubset(set(found["search_blobs"]))
        observations["C_product_total"] = found["total"]
        self.assertTrue(observations["C_second_batch_visible"], msg=json.dumps(observations, indent=2))
        self.assertEqual(found["total"], 8)
        token = self._product_token_search()
        observations["C_token_safe_hidden_unrelated"] = not bool(set(token["search_blobs"]) - (first_batch_blobs | second_batch_blobs))
        self.assertTrue(observations["C_token_safe_hidden_unrelated"])

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
        self.assertTrue(observations["active_n_visible"], msg=json.dumps(observations, indent=2))

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
        replacement_selector = self._selector_for_event_id("repl-0")
        n_selector = self._selector_for_blob(next(iter(n_blobs)))
        found = self._product_search()
        observations["D_replacement_ids"] = sorted(replacement_ids)
        observations["D_replacement_returned_ids"] = sorted(set(found["event_ids"]) & replacement_ids)
        observations["D_n_blobs_still_visible"] = n_blobs.issubset(set(found["search_blobs"]))
        observations["D_replacement_visible_before_activation"] = bool(set(found["event_ids"]) & replacement_ids)
        observations["D_product_total"] = found["total"]
        self.assertFalse(observations["D_replacement_visible_before_activation"], msg=json.dumps(observations, indent=2))
        self.assertTrue(observations["D_n_blobs_still_visible"], msg=json.dumps(observations, indent=2))
        self.assertEqual(found["total"], 8)
        token = self._product_token_search()
        observations["D_token_safe_replacement_visible"] = bool(set(token["event_ids"]) & replacement_ids)
        self.assertFalse(observations["D_token_safe_replacement_visible"], msg=json.dumps(observations, indent=2))
        self.assertTrue(set(token["search_blobs"]).issubset(n_blobs))
        self._assert_hidden_selector(replacement_selector, "BUILDING_REPLACEMENT row")
        self._assert_visible_selector(n_selector, "ACTIVE generation N")

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
        observations["E_n_state"] = generation.visibility_state
        observations["E_n1_state"] = replacement.visibility_state
        observations["E_stale_n_visible"] = bool(set(found["search_blobs"]) & n_blobs)
        observations["E_n1_visible"] = replacement_ids.issubset(set(found["event_ids"]))
        observations["E_product_total"] = found["total"]
        observations["E_authority_follows_current_generation_only"] = (
            replacement_ids.issubset(set(found["event_ids"]))
            and not bool(set(found["search_blobs"]) & n_blobs)
        )
        self.assertTrue(
            observations["E_authority_follows_current_generation_only"],
            msg=json.dumps(observations, indent=2),
        )
        self.assertEqual(found["total"], 8)
        token = self._product_token_search()
        observations["E_token_safe_stale_n_visible"] = bool(set(token["search_blobs"]) & n_blobs)
        observations["E_token_safe_n1_visible"] = bool(set(token["event_ids"]) & replacement_ids)
        self.assertFalse(observations["E_token_safe_stale_n_visible"], msg=json.dumps(observations, indent=2))
        self.assertTrue(observations["E_token_safe_n1_visible"], msg=json.dumps(observations, indent=2))
        self._assert_hidden_selector(n_selector, "SUPERSEDED generation N")
        self._assert_visible_selector(replacement_selector, "ACTIVE generation N+1")

        stale_initial = list(self.ch.query(
            """
            SELECT case_id, source_ref_type, source_ref_id, source_generation,
                   visibility_state, state_version, publishable, now()
            FROM visible_evidence_generations
            WHERE source_generation = 1
            LIMIT 1
            """
        ).result_rows[0])
        stale_initial[4] = EvidenceGenerationState.ACTIVE
        stale_initial[5] = 1
        stale_initial[6] = 1
        self.ch.insert(
            "visible_evidence_generations",
            [tuple(stale_initial)],
            column_names=[
                "case_id",
                "source_ref_type",
                "source_ref_id",
                "source_generation",
                "visibility_state",
                "state_version",
                "publishable",
                "updated_at",
            ],
        )
        found = self._product_search()
        observations["F_stale_n_visible"] = bool(set(found["search_blobs"]) & n_blobs)
        observations["F_n1_still_visible"] = replacement_ids.issubset(set(found["event_ids"]))
        self.assertFalse(observations["F_stale_n_visible"], msg=json.dumps(observations, indent=2))
        self.assertTrue(observations["F_n1_still_visible"], msg=json.dumps(observations, indent=2))
        token = self._product_token_search()
        observations["F_token_safe_stale_n_visible"] = bool(set(token["search_blobs"]) & n_blobs)
        self.assertFalse(observations["F_token_safe_stale_n_visible"], msg=json.dumps(observations, indent=2))
        self._assert_hidden_selector(n_selector, "stale-projection resurrected N")

        failures = []
        if observations["A_staged_visible"]:
            failures.append("STAGED rows are returned by the actual Hunt Artifacts path")
        if not observations["B_durable_building_initial_searchable"]:
            failures.append("DURABLE BUILDING_INITIAL rows are not searchable before EOF")
        if not observations["C_second_batch_visible"]:
            failures.append("second DURABLE BUILDING_INITIAL batch is not searchable before EOF")
        if observations["D_replacement_visible_before_activation"]:
            failures.append("BUILDING_REPLACEMENT rows are returned before activation")
        if not observations["E_authority_follows_current_generation_only"]:
            failures.append("after activation, search does not follow current-generation authority only")
        if observations["F_stale_n_visible"]:
            failures.append("stale lower-version projection resurrected superseded generation N")

        self.assertEqual(
            failures,
            [],
            msg="Phase 1B product publication gate failed on "
            f"{self.PRODUCT_PATH}: {json.dumps(observations, indent=2)}",
        )

    def test_legacy_only_hunt_list_and_detail_preserved(self):
        for idx, event in enumerate(self.events[:3]):
            copied = deepcopy(event)
            copied.event_id = f"legacy-{idx}"
            copied.record_id = 500 + idx
            copied.search_blob = f"legacy-only {idx} {event.search_blob}"
            self._insert_legacy_event(copied)
        found = self._product_search()
        self.assertEqual(found["total"], 3)
        self.assertTrue(all(blob.startswith("legacy-only ") for blob in found["search_blobs"]))
        token = self._product_token_search()
        self.assertGreater(token["total"], 0)
        self.assertTrue(all("alpha" in blob for blob in token["search_blobs"]))
        self.assertTrue(all(blob.startswith("legacy-only ") for blob in token["search_blobs"]))
        selector = self._selector_for_event_id("legacy-0")
        self._assert_visible_selector(selector, "legacy-only row")

    def test_mixed_legacy_published_staged_and_hidden_replacement(self):
        generation = allocate_case_file_initial_generation(
            session=db.session,
            case_id=self.case.id,
            case_file_id=self.case_file.id,
            contract=self.contract,
        )
        db.session.commit()
        published = self.events[0:4]
        self._ingest_slice(generation, published, batch_ordinal=0, durable=True)
        declare_generation_ingest_complete(
            session=db.session,
            generation=generation,
            expected_rows=4,
            final_batch_ordinal=0,
        )
        activate_initial_generation(session=db.session, generation=generation, actor="f2-gate")
        db.session.commit()
        project_generation_control_state(self.ch, db.session, generation)

        replacement_events = []
        for idx, event in enumerate(self.events[0:4]):
            copied = deepcopy(event)
            copied.event_id = f"hidden-repl-{idx}"
            copied.record_id = 700 + idx
            copied.search_blob = f"hidden-replacement {idx}"
            copied.timestamp = datetime(2026, 3, 1) + timedelta(seconds=idx)
            copied.timestamp_utc = copied.timestamp
            replacement_events.append(copied)
        replacement = allocate_case_file_replacement_generation(
            session=db.session,
            case_id=self.case.id,
            case_file_id=self.case_file.id,
            contract=self.contract,
        )
        db.session.commit()
        self._ingest_slice(replacement, replacement_events, batch_ordinal=0, durable=True)

        staged_events = []
        for idx, event in enumerate(self.events[4:6]):
            copied = deepcopy(event)
            copied.event_id = f"staged-extra-{idx}"
            copied.record_id = 800 + idx
            copied.search_blob = f"staged-extra {idx}"
            staged_events.append(copied)
        self._ingest_slice(generation, staged_events, batch_ordinal=1, durable=False)

        legacy_blobs = []
        for idx, event in enumerate(self.events[6:8]):
            copied = deepcopy(event)
            copied.event_id = f"mixed-legacy-{idx}"
            copied.record_id = 900 + idx
            copied.search_blob = f"mixed-legacy {idx}"
            copied.artifact_type = "iis"
            legacy_blobs.append(copied.search_blob)
            self._insert_legacy_event(copied)

        found = self._product_search()
        visible_blobs = set(found["search_blobs"])
        published_blobs = {event.search_blob for event in published}
        self.assertTrue(published_blobs.issubset(visible_blobs), msg=found["search_blobs"])
        self.assertTrue(set(legacy_blobs).issubset(visible_blobs), msg=found["search_blobs"])
        self.assertFalse(any(blob.startswith("hidden-replacement ") for blob in found["search_blobs"]))
        self.assertFalse(any(blob.startswith("staged-extra ") for blob in found["search_blobs"]))
        self.assertEqual(found["total"], 6)
        token = self._product_token_search()
        self.assertFalse(any(blob.startswith("hidden-replacement ") for blob in token["search_blobs"]))
        self.assertFalse(any(blob.startswith("staged-extra ") for blob in token["search_blobs"]))

    def test_malformed_managed_identity_fail_closed(self):
        copied = deepcopy(self.events[0])
        copied.event_id = "malformed-partial"
        copied.record_id = 12345
        copied.search_blob = "malformed partial protocol identity"
        self.ch.insert(
            "events",
            [copied.to_clickhouse_row() + ("CASE_FILE",)],
            column_names=list(ParsedEvent.clickhouse_columns()) + ["source_ref_type"],
        )
        found = self._product_search()
        self.assertNotIn("malformed partial protocol identity", found["search_blobs"])
        self.assertEqual(found["total"], 0)
        token = self._product_search({"search": "malformed"})
        self.assertNotIn("malformed partial protocol identity", token["search_blobs"])
        self.assertEqual(token["total"], 0)
        self._assert_hidden_selector(
            self._selector_for_event_id("malformed-partial"),
            "malformed managed-looking row",
        )

    def test_published_hunt_search_filters_sort_pagination_and_overlays(self):
        generation = allocate_case_file_initial_generation(
            session=db.session,
            case_id=self.case.id,
            case_file_id=self.case_file.id,
            contract=self.contract,
        )
        db.session.commit()
        self._ingest_slice(generation, self.events[0:4], batch_ordinal=0, durable=True)
        self._ingest_slice(generation, self.events[4:8], batch_ordinal=1, durable=True)
        declare_generation_ingest_complete(
            session=db.session,
            generation=generation,
            expected_rows=8,
            final_batch_ordinal=1,
        )
        activate_initial_generation(session=db.session, generation=generation, actor="f2-gate")
        db.session.commit()
        project_generation_control_state(self.ch, db.session, generation)

        legacy = deepcopy(self.events[0])
        legacy.event_id = "legacy-evtx"
        legacy.record_id = 4242
        legacy.artifact_type = "evtx"
        legacy.search_blob = "legacy evtx control row"
        legacy.timestamp = datetime(2026, 1, 1, 0, 0, 30)
        legacy.timestamp_utc = legacy.timestamp
        self._insert_legacy_event(legacy)

        for extra_idx in range(7):
            extra = deepcopy(self.events[0])
            extra.event_id = f"page-legacy-{extra_idx}"
            extra.record_id = 6100 + extra_idx
            extra.search_blob = f"page-legacy {extra_idx}"
            extra.timestamp = datetime(2026, 1, 1, 1, extra_idx)
            extra.timestamp_utc = extra.timestamp
            self._insert_legacy_event(extra)

        baseline = self._product_search()
        self.assertEqual(baseline["total"], 16)

        alpha = self._product_search({"search": "alpha"})
        self.assertGreater(alpha["total"], 0)
        self.assertTrue(all("alpha" in blob for blob in alpha["search_blobs"]))
        self.assertLess(alpha["total"], baseline["total"])

        iis_only = self._product_search({"types": "iis"})
        self.assertEqual(iis_only["total"], 15)
        self.assertTrue(all(artifact == "iis" for artifact in iis_only["artifact_types"]))
        evtx_only = self._product_search({"types": "evtx"})
        self.assertEqual(evtx_only["total"], 1)
        self.assertEqual(evtx_only["artifact_types"], ["evtx"])

        self.ch.command(
            "ALTER TABLE events UPDATE rule_title = 'Sigma Hit', rule_level = 'high' "
            f"WHERE case_id = {int(self.case.id)} AND search_blob = "
            f"{clickhouse_string_literal(self.events[1].search_blob)} SETTINGS mutations_sync = 1"
        )
        sigma_only = self._product_search({
            "sigma_filter": "include",
            "ioc_filter": "exclude",
            "analyst_filter": "exclude",
            "other_filter": "exclude",
        })
        self.assertEqual(sigma_only["total"], 1)
        self.assertEqual(sigma_only["events"][0]["rule_title"], "Sigma Hit")

        noisy_blob = self.events[2].search_blob
        self.ch.command(
            "ALTER TABLE events UPDATE noise_matched = 1 "
            f"WHERE case_id = {int(self.case.id)} AND search_blob = "
            f"{clickhouse_string_literal(noisy_blob)} SETTINGS mutations_sync = 1"
        )
        hidden_noise = self._product_search({"show_noise": "false"})
        self.assertNotIn(noisy_blob, hidden_noise["search_blobs"])
        shown_noise = self._product_search({"show_noise": "true"})
        self.assertIn(noisy_blob, shown_noise["search_blobs"])

        ioc_blob = self.events[3].search_blob
        self.ch.command(
            "ALTER TABLE events UPDATE ioc_types = ['ip'] "
            f"WHERE case_id = {int(self.case.id)} AND search_blob = "
            f"{clickhouse_string_literal(ioc_blob)} SETTINGS mutations_sync = 1"
        )
        ioc_only = self._product_search({
            "sigma_filter": "exclude",
            "ioc_filter": "include",
            "analyst_filter": "exclude",
            "other_filter": "exclude",
        })
        self.assertEqual(ioc_only["total"], 1)
        self.assertEqual(ioc_only["search_blobs"], [ioc_blob])
        self.assertEqual(ioc_only["events"][0]["ioc_types"], ["ip"])

        paged = self._product_search({
            "per_page": 10,
            "page": 1,
            "sort_by": "timestamp",
            "sort_dir": "asc",
            "show_noise": "true",
        })
        self.assertEqual(paged["total"], 16)
        self.assertEqual(paged["payload"]["per_page"], 10)
        self.assertEqual(len(paged["events"]), 10)
        page2 = self._product_search({
            "per_page": 10,
            "page": 2,
            "sort_by": "timestamp",
            "sort_dir": "asc",
            "show_noise": "true",
        })
        self.assertEqual(len(page2["events"]), 6)
        self.assertNotEqual(paged["search_blobs"], page2["search_blobs"])
        self.assertEqual(paged["total"], page2["total"])

        timed = self._product_search({
            "time_range": "custom",
            "time_start": "2026-01-01 00:00:00",
            "time_end": "2026-01-01 00:00:03",
            "show_noise": "true",
        })
        self.assertGreater(timed["total"], 0)
        self.assertLess(timed["total"], baseline["total"])

        published_selector = self._selector_for_blob(self.events[0].search_blob)
        self._assert_visible_selector(published_selector, "published Hunt overlay row")

    def test_publication_bridge_query_shape_and_latency(self):
        generation = allocate_case_file_initial_generation(
            session=db.session,
            case_id=self.case.id,
            case_file_id=self.case_file.id,
            contract=self.contract,
        )
        db.session.commit()
        self._ingest_slice(generation, self.events, batch_ordinal=0, durable=True)
        declare_generation_ingest_complete(
            session=db.session,
            generation=generation,
            expected_rows=len(self.events),
            final_batch_ordinal=0,
        )
        activate_initial_generation(session=db.session, generation=generation, actor="f2-gate")
        db.session.commit()
        project_generation_control_state(self.ch, db.session, generation)

        before_count = self.ch.query(
            "SELECT count() FROM events AS e WHERE e.case_id = {case_id:UInt32}",
            parameters={"case_id": self.case.id},
        )
        self.assertEqual(int(before_count.result_rows[0][0]), 8)

        started = time.perf_counter()
        raw_started = time.perf_counter()
        self.ch.query(
            "SELECT count() FROM events AS e WHERE e.case_id = {case_id:UInt32}",
            parameters={"case_id": self.case.id},
        )
        raw_count_ms = (time.perf_counter() - raw_started) * 1000.0
        raw_data_started = time.perf_counter()
        self.ch.query(
            """
            SELECT e.search_blob
            FROM events AS e
            WHERE e.case_id = {case_id:UInt32}
            ORDER BY COALESCE(e.timestamp_utc, e.timestamp) DESC, e.record_id DESC
            LIMIT 50
            """,
            parameters={"case_id": self.case.id},
        )
        raw_data_ms = (time.perf_counter() - raw_data_started) * 1000.0

        counter = _CountingClickHouse(self.ch)
        product_started = time.perf_counter()
        found = self._product_search(counter=counter)
        product_ms = (time.perf_counter() - product_started) * 1000.0
        self.assertEqual(found["total"], 8)

        hunt_selects = [sql for sql in counter.queries if "FROM events AS e" in sql]
        self.assertGreaterEqual(len(hunt_selects), 2)
        count_sql = next(sql for sql in hunt_selects if "SELECT count()" in sql)
        data_sql = next(sql for sql in hunt_selects if "SELECT count()" not in sql)
        self.assertIn("visible_evidence_generations FINAL", count_sql)
        self.assertIn("durable_ingest_batches FINAL", count_sql)
        self.assertIn("visible_evidence_generations FINAL", data_sql)
        self.assertIn("durable_ingest_batches FINAL", data_sql)
        extra_round_trips = len(hunt_selects) - 2
        self.assertEqual(extra_round_trips, 0)

        self.assertLess(product_ms, 5000.0)
        observations = {
            "query_shape_before": "FROM events AS e WHERE e.case_id = {case_id:UInt32}",
            "query_shape_after_count": " ".join(count_sql.split()),
            "clickhouse_queries_during_request": len(counter.queries),
            "hunt_select_queries": len(hunt_selects),
            "extra_hunt_select_round_trips": extra_round_trips,
            "raw_count_ms": round(raw_count_ms, 3),
            "raw_data_ms": round(raw_data_ms, 3),
            "product_request_ms": round(product_ms, 3),
            "elapsed_ms": round((time.perf_counter() - started) * 1000.0, 3),
        }
        self.assertIn("veg.publishable = 1", count_sql)
        print("F2_PUBLICATION_PERF " + json.dumps(observations))

    def test_missing_control_tables_fail_closed(self):
        generation = allocate_case_file_initial_generation(
            session=db.session,
            case_id=self.case.id,
            case_file_id=self.case_file.id,
            contract=self.contract,
        )
        db.session.commit()
        self._ingest_slice(generation, self.events[0:4], batch_ordinal=0, durable=True)
        self.ch.command("DROP TABLE durable_ingest_batches")
        try:
            response = self._request(f"/api/hunting/events/{self.case.id}")
            payload = response.get_json() or {}
            self.assertEqual(response.status_code, 500, msg=payload)
            self.assertFalse(payload.get("success", True), msg=payload)
            self.assertNotIn("events", payload)
        finally:
            self.ch.command(CLICKHOUSE_CONTROL_TABLE_DDL[1])
