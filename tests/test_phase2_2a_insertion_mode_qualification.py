"""Focused Phase 2.2A insertion-mode qualification tests.

These tests lock the decision tokens, mode-setting construction, schema
contract, identity invariance, and artifact shape. They do not change
production insert mode.
"""
from __future__ import annotations

import importlib.util
import inspect
import json
import os
import unittest
import uuid

os.environ.setdefault("SECRET_KEY", "phase2-2a-test-secret")

from migrations.add_events_table import EVENTS_SCHEMA
from utils import clickhouse as clickhouse_utils
from utils.ingest_identity import batch_content_hash, deterministic_ingest_batch_id
from utils.manifest_protocol import construct_managed_batch


SCRIPT_PATH = os.path.join(
    os.path.dirname(os.path.dirname(__file__)),
    "scripts",
    "phase2_2a_insertion_mode_qualification.py",
)
ARTIFACT_JSON = os.path.join(
    os.path.dirname(os.path.dirname(__file__)),
    "docs",
    "database_flow_phase2",
    "phase2_2a_insertion_mode_qualification.json",
)


def _load_script():
    spec = importlib.util.spec_from_file_location("phase2_2a_insertion_mode_qualification", SCRIPT_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


p22a = _load_script()


class Phase22AModeContractTests(unittest.TestCase):
    def test_valid_candidate_enumeration(self):
        self.assertEqual(
            p22a.valid_candidate_modes(),
            (p22a.MODE_SYNC, p22a.MODE_ASYNC_WAIT),
        )
        self.assertNotIn(p22a.ASYNC_NO_WAIT_FORBIDDEN, p22a.valid_candidate_modes())
        self.assertTrue(p22a.is_production_eligible_mode(p22a.MODE_SYNC))
        self.assertTrue(p22a.is_production_eligible_mode(p22a.MODE_ASYNC_WAIT))
        self.assertFalse(p22a.is_production_eligible_mode(p22a.ASYNC_NO_WAIT_FORBIDDEN))

    def test_mode_setting_construction_is_explicit(self):
        sync = p22a.insert_settings_for_mode(p22a.MODE_SYNC)
        async_wait = p22a.insert_settings_for_mode(p22a.MODE_ASYNC_WAIT)
        self.assertEqual(sync["async_insert"], 0)
        self.assertEqual(sync["materialize_skip_indexes_on_insert"], 1)
        self.assertNotIn("wait_for_async_insert", sync)
        self.assertEqual(async_wait["async_insert"], 1)
        self.assertEqual(async_wait["wait_for_async_insert"], 1)
        self.assertEqual(async_wait["materialize_skip_indexes_on_insert"], 1)

    def test_summary_query_id_calls_method(self):
        class FakeSummary:
            def query_id(self):
                return "abc-123"

        self.assertEqual(p22a.summary_query_id(FakeSummary(), "fallback"), "abc-123")
        self.assertEqual(p22a.summary_query_id(None, "fallback"), "fallback")

    def test_hunt_publication_sql_does_not_wrap_and(self):
        source = inspect.getsource(p22a.hunt_publication_count_sql)
        self.assertNotIn("AND ({bridge", source)
        self.assertIn('bridge["where_sql"]', source)

    def test_async_no_wait_is_forbidden(self):
        with self.assertRaises(ValueError) as raised:
            p22a.insert_settings_for_mode(p22a.ASYNC_NO_WAIT_FORBIDDEN)
        self.assertEqual(str(raised.exception), p22a.ASYNC_NO_WAIT_FORBIDDEN)
        with self.assertRaises(ValueError):
            p22a.insert_settings_for_mode("PHASE2_2_MODE_ASYNC_NO_WAIT")

    def test_runtime_clients_do_not_pin_insert_mode(self):
        source = inspect.getsource(clickhouse_utils.get_client) + inspect.getsource(
            clickhouse_utils.get_fresh_client
        )
        self.assertNotIn("async_insert", source)
        self.assertNotIn("wait_for_async_insert", source)

    def test_benchmark_schema_is_final_phase21(self):
        checks = p22a.assert_events_schema_is_final_phase21(EVENTS_SCHEMA)
        self.assertTrue(all(checks.values()), msg=checks)
        contract = p22a.final_phase21_schema_contract()
        self.assertTrue(contract["idx_search_blob_text"]["present"])
        self.assertTrue(contract["idx_search_ngram"]["present"])
        self.assertFalse(contract["idx_search_token"]["present"])
        self.assertEqual(contract["idx_search_ngram"]["exception"], "PHASE2_1_EXC_001")

    def test_identity_invariance_of_batch_construction(self):
        from models.database_flow import EvidenceSourceGeneration, EvidenceGenerationState, SourceRefType
        from models.database_flow import IngestAttempt

        generation = EvidenceSourceGeneration(
            case_id=42,
            source_ref_type=SourceRefType.CASE_FILE,
            source_ref_id="99",
            source_generation=1,
            visibility_state=EvidenceGenerationState.BUILDING_INITIAL,
            parser_version="phase2-2a:v1",
            normalization_version="normalization:v1",
            batching_contract_version="ingest-batch:v1",
            configured_batch_size=10,
            ordering_contract="test:phase2-2a-order:v1",
            producer_version="phase2-2a:v1",
        )
        generation.id = 1
        attempt = IngestAttempt(ingest_attempt_id=str(uuid.uuid4()), generation_id=1)
        events = [p22a.make_parsed_event(i, case_id=42, case_file_id=99) for i in range(10)]
        sync_manifest = construct_managed_batch(
            generation=generation, attempt=attempt, events=tuple(events), batch_ordinal=3
        )
        async_manifest = construct_managed_batch(
            generation=generation, attempt=attempt, events=tuple(events), batch_ordinal=3
        )
        expected_id = deterministic_ingest_batch_id(
            case_id=42,
            source_ref_type=SourceRefType.CASE_FILE,
            source_ref_id="99",
            source_generation=1,
            batch_ordinal=3,
            batching_contract_version="ingest-batch:v1",
        )
        self.assertEqual(sync_manifest.ingest_batch_id, expected_id)
        self.assertEqual(sync_manifest.ingest_batch_id, async_manifest.ingest_batch_id)
        self.assertEqual([row.ordinal for row in sync_manifest.rows], list(range(10)))
        self.assertEqual(sync_manifest.row_hashes, async_manifest.row_hashes)
        self.assertEqual(sync_manifest.batch_content_hash, async_manifest.batch_content_hash)
        self.assertEqual(sync_manifest.batch_content_hash, batch_content_hash(sync_manifest.row_hashes))
        self.assertEqual(
            {event.evidence_record_key for event in events},
            {row.event.evidence_record_key for row in async_manifest.rows},
        )
        # Insertion transport is not part of forensic identity.
        self.assertNotEqual(
            p22a.insert_settings_for_mode(p22a.MODE_SYNC),
            p22a.insert_settings_for_mode(p22a.MODE_ASYNC_WAIT),
        )

    def test_2_2b_boundary_is_per_events_insert(self):
        boundary = p22a.recommended_2_2b_configuration_boundary()
        self.assertEqual(boundary["option"], "A")
        self.assertIn("insert_managed_batch", " ".join(boundary["apply_to"]))
        self.assertIn("get_fresh_client", " ".join(boundary["do_not_apply_to"]))
        self.assertIn("visible_evidence_generations", " ".join(boundary["do_not_apply_to"]))

    def test_existing_generation_resume_hazard_is_documented(self):
        design = p22a.existing_generation_compatibility_design()
        self.assertIn("_assert_frozen_contract_matches", design["resume_hazard"])
        self.assertTrue(any("BUILDING" in item for item in design["if_new_default_chosen_2_2b_must"]))

    def test_events_insert_client_pins_only_events(self):
        class Inner:
            def __init__(self):
                self.calls = []

            def insert(self, table, data, column_names=None, settings=None, **kwargs):
                self.calls.append((table, settings))
                return type("S", (), {"query_id": "q"})()

        inner = Inner()
        proxy = p22a.EventsInsertClient(inner, p22a.insert_settings_for_mode(p22a.MODE_SYNC))
        proxy.insert("events", [(1,)], column_names=["case_id"])
        proxy.insert("visible_evidence_generations", [(1,)], column_names=["case_id"])
        self.assertEqual(inner.calls[0][0], "events")
        self.assertEqual(inner.calls[0][1]["async_insert"], 0)
        self.assertIsNone(inner.calls[1][1])
        self.assertEqual(proxy.events_insert_calls, 1)
        self.assertEqual(proxy.other_insert_calls, 1)

    def test_decision_artifact_shape_constant(self):
        for key in (
            "insert_mode_decision",
            "async_no_wait_decision",
            "batch_size_decision",
            "verdict",
            "phase2_2_state",
            "clickhouse_connect_async_mode_proof",
            "identity_invariance",
        ):
            self.assertIn(key, p22a.REQUIRED_ARTIFACT_KEYS)


class Phase22AArtifactShapeTests(unittest.TestCase):
    @unittest.skipUnless(os.path.exists(ARTIFACT_JSON), "qualification JSON is produced by the measurement script")
    def test_artifact_contains_required_keys_and_tokens(self):
        with open(ARTIFACT_JSON, encoding="utf-8") as handle:
            payload = json.load(handle)
        for key in p22a.REQUIRED_ARTIFACT_KEYS:
            self.assertIn(key, payload, msg=key)
        self.assertIn(
            payload["insert_mode_decision"],
            {p22a.MODE_SYNC, p22a.MODE_ASYNC_WAIT, p22a.MODE_NOT_READY},
        )
        self.assertEqual(payload["async_no_wait_decision"], p22a.ASYNC_NO_WAIT_FORBIDDEN)
        self.assertIn(
            payload["batch_size_decision"],
            {p22a.BATCH_KEEP_10000, p22a.BATCH_NEW_25000, p22a.BATCH_NEW_50000, p22a.BATCH_NEW_100000},
        )
        self.assertEqual(payload["version"], "4.26.0")
        self.assertFalse(payload.get("version_bumped"))
        self.assertEqual(payload.get("production_mutation_audit"), "NONE")
        self.assertIn(payload["verdict"], {"PHASE2_2A_PASS", "PHASE2_2A_NOT_READY"})


def _clickhouse_available():
    try:
        client = p22a.ch_connect("default")
        client.query("SELECT 1")
        client.close()
        return True
    except Exception:
        return False


@unittest.skipUnless(_clickhouse_available(), "live ClickHouse is required")
class LivePhase22ASchemaAndModeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.database = f"cs_p22a_test_{uuid.uuid4().hex[:12]}"
        admin = p22a.ch_connect("default")
        admin.command(f"CREATE DATABASE {cls.database}")
        cls.client = p22a.ch_connect(cls.database)
        p22a.create_events_table(cls.client, "events")

    @classmethod
    def tearDownClass(cls):
        try:
            cls.client.command(f"DROP DATABASE IF EXISTS {cls.database}")
        except Exception:
            pass

    def test_created_table_matches_final_phase21_indexes(self):
        rows, _ = p22a.q(
            self.client,
            """
            SELECT name, type_full, expr, granularity
            FROM system.data_skipping_indices
            WHERE database = currentDatabase() AND table = 'events'
            ORDER BY name
            """,
        )
        names = {row["name"] for row in rows}
        self.assertIn("idx_search_blob_text", names)
        self.assertIn("idx_search_ngram", names)
        self.assertNotIn("idx_search_token", names)
        ngram = next(row for row in rows if row["name"] == "idx_search_ngram")
        self.assertEqual(ngram["type_full"], "ngrambf_v1(3, 512, 2, 0)")
        self.assertEqual(int(ngram["granularity"]), 4)
        text = next(row for row in rows if row["name"] == "idx_search_blob_text")
        self.assertIn("splitByNonAlpha", text["type_full"])
        self.assertIn("lower(search_blob)", text["type_full"])

    def test_client_insert_settings_are_accepted(self):
        self.client.command("TRUNCATE TABLE events")
        event = p22a.make_parsed_event(0, case_id=1, case_file_id=1)
        from utils.manifest_protocol import PROTOCOL_CLICKHOUSE_COLUMNS
        from models.database_flow import EvidenceSourceGeneration, EvidenceGenerationState, SourceRefType, IngestAttempt
        from utils.manifest_protocol import construct_managed_batch

        generation = EvidenceSourceGeneration(
            case_id=1,
            source_ref_type=SourceRefType.CASE_FILE,
            source_ref_id="1",
            source_generation=1,
            visibility_state=EvidenceGenerationState.BUILDING_INITIAL,
            parser_version="phase2-2a:v1",
            normalization_version="normalization:v1",
            batching_contract_version="ingest-batch:v1",
            configured_batch_size=1,
            ordering_contract="test:phase2-2a-order:v1",
        )
        generation.id = 1
        attempt = IngestAttempt(ingest_attempt_id=str(uuid.uuid4()), generation_id=1)
        manifest = construct_managed_batch(
            generation=generation, attempt=attempt, events=(event,), batch_ordinal=0
        )
        proxy = p22a.EventsInsertClient(self.client, p22a.insert_settings_for_mode(p22a.MODE_SYNC))
        proxy.insert("events", list(manifest.clickhouse_rows), column_names=list(PROTOCOL_CLICKHOUSE_COLUMNS))
        count = p22a.scalar(self.client, "SELECT count() FROM events")
        self.assertEqual(int(count), 1)


if __name__ == "__main__":
    unittest.main()
