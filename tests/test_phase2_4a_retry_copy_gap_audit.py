"""Phase 2.4A retry-copy gap audit classification tests.

Unit gates always run. Live ClickHouse/PostgreSQL proofs fail closed if
those services are unreachable and never mutate production `casescope`.
"""
from __future__ import annotations

import importlib.util
import inspect
import json
import os
import unittest
import uuid

os.environ.setdefault("SECRET_KEY", "phase2-4a-test-secret")

from utils.event_deduplication import deduplicate_case_events
from utils.ingest_identity import ROW_HASH_EXCLUDED_FIELDS, canonical_ingest_batch_identity
from utils.manifest_protocol import update_generation_ingest_accounting, verify_ingest_batch
from utils.staged_batch_reconciler import classify_batch, reconcile_staged_batch
from routes.hunting_query_helpers import build_hunting_publication_bridge


REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT_PATH = os.path.join(REPO_ROOT, "scripts", "phase2_4a_retry_copy_gap_audit.py")


def _load_audit():
    spec = importlib.util.spec_from_file_location("phase2_4a_retry_copy_gap_audit", SCRIPT_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


AUDIT = _load_audit()


class Phase24AClassificationTests(unittest.TestCase):
    def test_same_erk_is_not_retry(self):
        self.assertEqual(
            AUDIT.classify_negative_control("same_erk_different_batch"),
            "NOT_PHASE2_4_RETRY_COPY",
        )
        self.assertFalse(
            AUDIT.is_deterministic_retry_equivalent(
                ingest_batch_id_a="batch-a",
                ingest_batch_id_b="batch-b",
                ingest_row_ordinal_a=0,
                ingest_row_ordinal_b=0,
                ingest_row_hash_a="a" * 64,
                ingest_row_hash_b="a" * 64,
                expected_hash="a" * 64,
            )
        )

    def test_same_selector_is_not_retry(self):
        self.assertEqual(
            AUDIT.classify_negative_control("same_selector_different_batch"),
            "NOT_PHASE2_4_RETRY_COPY",
        )

    def test_same_artifact_fields_are_not_retry(self):
        self.assertEqual(
            AUDIT.classify_negative_control("same_artifact_fields_different_source_generation"),
            "NOT_PHASE2_4_RETRY_COPY",
        )

    def test_different_batch_id_is_not_retry(self):
        self.assertEqual(
            AUDIT.classify_negative_control("different_batch_id"),
            "NOT_PHASE2_4_RETRY_COPY",
        )

    def test_different_generation_is_not_retry(self):
        self.assertEqual(
            AUDIT.classify_negative_control("different_generation"),
            "NOT_PHASE2_4_RETRY_COPY",
        )

    def test_legacy_semantic_duplicate_is_not_retry(self):
        self.assertEqual(
            AUDIT.classify_negative_control("legacy_protocol_null_semantic_duplicate"),
            "NOT_PHASE2_4_RETRY_COPY",
        )

    def test_different_hash_same_ordinal_is_integrity_conflict(self):
        self.assertEqual(
            AUDIT.classify_negative_control("different_hash_same_ordinal"),
            "integrity_conflict",
        )
        self.assertEqual(
            AUDIT.classify_physical_group(
                physical_copies=2,
                uniq_hashes=2,
                stored_hashes=["a" * 64, "b" * 64],
                pg_expected_hash="a" * 64,
            ),
            "integrity_conflict",
        )
        self.assertFalse(
            AUDIT.is_deterministic_retry_equivalent(
                ingest_batch_id_a="batch-a",
                ingest_batch_id_b="batch-a",
                ingest_row_ordinal_a=0,
                ingest_row_ordinal_b=0,
                ingest_row_hash_a="a" * 64,
                ingest_row_hash_b="b" * 64,
                expected_hash="a" * 64,
            )
        )

    def test_ordinary_single_copy(self):
        self.assertEqual(
            AUDIT.classify_physical_group(
                physical_copies=1,
                uniq_hashes=1,
                stored_hashes=["a" * 64],
                pg_expected_hash="a" * 64,
            ),
            "ordinary",
        )

    def test_retry_copy_requires_pg_hash_match(self):
        self.assertEqual(
            AUDIT.classify_physical_group(
                physical_copies=2,
                uniq_hashes=1,
                stored_hashes=["a" * 64],
                pg_expected_hash="a" * 64,
            ),
            "deterministic_retry_copy_candidate",
        )
        self.assertEqual(
            AUDIT.classify_physical_group(
                physical_copies=2,
                uniq_hashes=1,
                stored_hashes=["a" * 64],
                pg_expected_hash="c" * 64,
            ),
            "integrity_conflict",
        )

    def test_retry_equivalent_positive(self):
        self.assertTrue(
            AUDIT.is_deterministic_retry_equivalent(
                ingest_batch_id_a="ingest-batch:v1:abc",
                ingest_batch_id_b="ingest-batch:v1:abc",
                ingest_row_ordinal_a=3,
                ingest_row_ordinal_b=3,
                ingest_row_hash_a="ab" * 32,
                ingest_row_hash_b="AB" * 32,
                expected_hash="ab" * 32,
            )
        )

    def test_current_state_parity_ignores_attempt_and_indexed_at(self):
        rows = [
            {
                "selector_key": "record:1|file:a|host:h",
                "indexed_at": "2026-01-01T00:00:00",
                "ingest_attempt_id": "11111111-1111-1111-1111-111111111111",
                "analyst_tagged": False,
                "analyst_tags": [],
                "analyst_notes": None,
                "noise_matched": False,
                "noise_rules": [],
                "ioc_types": [],
                "mitre_attack_ids": [],
                "mitre_attack_tactics": [],
                "mitre_attack_sources": [],
                "mitre_mapping_max_confidence": 0,
            },
            {
                "selector_key": "record:1|file:a|host:h",
                "indexed_at": "2026-01-01T00:00:01",
                "ingest_attempt_id": "22222222-2222-2222-2222-222222222222",
                "analyst_tagged": False,
                "analyst_tags": [],
                "analyst_notes": None,
                "noise_matched": False,
                "noise_rules": [],
                "ioc_types": [],
                "mitre_attack_ids": [],
                "mitre_attack_tactics": [],
                "mitre_attack_sources": [],
                "mitre_mapping_max_confidence": 0,
            },
        ]
        self.assertEqual(AUDIT.classify_current_state_parity(rows), "CURRENT_STATE_PARITY")
        rows[1]["analyst_notes"] = "diverged"
        self.assertEqual(AUDIT.classify_current_state_parity(rows), "CURRENT_STATE_DIVERGENCE")

    def test_strategy_tokens(self):
        self.assertEqual(
            AUDIT.recommend_strategy(
                production_copies_present=False,
                integrity_conflict=False,
                current_consumers_need_exclusion=True,
                production_state_divergence=False,
            ),
            "PHASE2_4_STRATEGY_HYBRID",
        )
        self.assertEqual(
            AUDIT.recommend_strategy(
                production_copies_present=True,
                integrity_conflict=True,
                current_consumers_need_exclusion=True,
                production_state_divergence=False,
            ),
            "PHASE2_4_STRATEGY_NOT_READY",
        )

    def test_every_inventory_path_classified(self):
        allowed = {
            "ALREADY_RETRY_SAFE",
            "NEEDS_PHASE2_4_RETRY_EXCLUSION",
            "LEGACY_ONLY_OUT_OF_SCOPE",
            "LATER_PHASE_DEFERRED",
            "PHASE4_LOGICAL_DEDUP_OUT_OF_SCOPE",
            "INTEGRITY_FAIL_CLOSED",
        }
        inventory = AUDIT.consumer_inventory()
        self.assertGreaterEqual(len(inventory), 20)
        for item in inventory:
            self.assertIn(item["classification"], allowed)


class Phase24ASourceInspectionTests(unittest.TestCase):
    def test_version_remains_4_26_2(self):
        with open(os.path.join(REPO_ROOT, "version.json"), encoding="utf-8") as handle:
            payload = json.load(handle)
        self.assertEqual(payload["version"], "4.26.2")

    def test_batch_identity_excludes_attempt_id(self):
        source = inspect.getsource(canonical_ingest_batch_identity)
        self.assertNotIn("ingest_attempt_id", source)

    def test_row_hash_excludes_mutable_current_fields(self):
        self.assertTrue(
            ROW_HASH_EXCLUDED_FIELDS.issuperset(
                {
                    "indexed_at",
                    "selector_key",
                    "ingest_attempt_id",
                    "analyst_tagged",
                    "analyst_notes",
                    "noise_matched",
                    "ioc_types",
                    "extra_fields",
                }
            )
        )

    def test_verify_and_classify_accept_duplicate_identical(self):
        self.assertIn("duplicate_identical", inspect.getsource(verify_ingest_batch))
        self.assertIn("duplicate_identical", inspect.getsource(classify_batch))

    def test_reconcile_marks_duplicate_identical_durable_without_purge(self):
        source = inspect.getsource(reconcile_staged_batch)
        self.assertIn('"duplicate_identical"', source)
        success = source.split("if classification.classification in", 1)[1]
        success = success.split("\n    if classification.classification", 1)[0]
        self.assertIn("mark_batch_durable", success)
        self.assertNotIn("purge", success.lower())

    def test_landed_rows_use_pg_durable_row_count(self):
        source = inspect.getsource(update_generation_ingest_accounting)
        self.assertIn("func.sum(IngestBatch.row_count)", source)
        self.assertIn("generation.landed_rows", source)

    def test_hunt_publication_has_no_retry_collapse(self):
        source = inspect.getsource(build_hunting_publication_bridge)
        self.assertIn("dib.state = 'DURABLE'", source)
        self.assertNotIn("LIMIT 1 BY", source)
        self.assertNotIn("uniqExact", source)
        self.assertNotIn("GROUP BY ingest_row_ordinal", source)

    def test_no_production_allow_managed_evidence_true(self):
        source = inspect.getsource(deduplicate_case_events)
        self.assertIn("allow_managed_evidence: bool = False", source)
        for rel in ("tasks/celery_tasks.py", "routes/case_files.py"):
            with open(os.path.join(REPO_ROOT, rel), encoding="utf-8") as handle:
                text = handle.read()
            self.assertNotIn("allow_managed_evidence=True", text)
            self.assertNotIn("allow_managed_evidence = True", text)

    def test_starting_facts_helper_agrees(self):
        facts = AUDIT.source_starting_facts()
        self.assertTrue(facts["all_starting_facts_match_prompt"])


class LivePhase24ATests(unittest.TestCase):
    """Disposable protocol proof that current Hunt counts physical retry copies."""

    @classmethod
    def setUpClass(cls):
        from utils.ingest_fence import install_memory_backend

        install_memory_backend()
        try:
            admin = AUDIT.ch_connect("default")
            admin.query("SELECT 1")
        except Exception as exc:
            raise AssertionError(
                f"live ClickHouse is required for Phase 2.4A tests and was unreachable: {exc}"
            ) from exc
        cls.ch_db = f"cs_p24a_{uuid.uuid4().hex[:12]}"
        admin.command(f"CREATE DATABASE {cls.ch_db}")
        admin.close()
        cls.pg_db = f"phase2_4a_{uuid.uuid4().hex[:8]}"
        cls.pg_url = AUDIT.ensure_pg_database(cls.pg_db)
        cls.clickhouse_version = str(AUDIT.ch_connect(cls.ch_db).query("SELECT version()").result_rows[0][0])
        if not cls.clickhouse_version.startswith("26.7.3"):
            raise AssertionError(f"expected ClickHouse 26.7.3.x, got {cls.clickhouse_version}")

    @classmethod
    def tearDownClass(cls):
        from utils.ingest_fence import reset_fence_backend

        try:
            admin = AUDIT.ch_connect("default")
            admin.command(f"DROP DATABASE IF EXISTS {cls.ch_db}")
            admin.close()
        except Exception:
            pass
        reset_fence_backend()

    def test_lost_ack_duplicate_identical_hunt_counts_physical_copies(self):
        from utils.ingest_fence import install_memory_backend, reset_fence_backend

        install_memory_backend()
        app, ctx, db = AUDIT.make_pg_app(self.pg_url)
        ch = AUDIT.ch_connect(self.ch_db)
        try:
            AUDIT.create_events_and_control(ch)
            n = 4
            case, case_file, generation, attempt, _contract = AUDIT.seed_case(
                db, name="P24A-live", batch_size=n
            )
            events = [
                AUDIT.make_parsed_event(i, case_id=case.id, case_file_id=case_file.id)
                for i in range(n)
            ]
            lost = AUDIT.insert_retry_copies(
                ch, db, generation=generation, attempt=attempt, events=events, lost_ack=True
            )
            hunt_n, _ = AUDIT.hunt_count(ch, case.id)
            excl_n, _ = AUDIT.hunt_count_excluded(ch, case.id)
            self.assertEqual(lost["verify_after_retry"]["outcome"], "duplicate_identical")
            self.assertTrue(lost["verify_after_retry"]["success"])
            self.assertEqual(lost["pg_landed_rows"], n)
            self.assertEqual(lost["physical_rows"], n * 2)
            self.assertEqual(hunt_n, n * 2)
            self.assertEqual(excl_n, n)
            self.assertFalse(
                AUDIT.is_deterministic_retry_equivalent(
                    ingest_batch_id_a=lost["manifest"].ingest_batch_id,
                    ingest_batch_id_b="other-batch",
                    ingest_row_ordinal_a=0,
                    ingest_row_ordinal_b=0,
                    ingest_row_hash_a=lost["manifest"].row_hashes[0],
                    ingest_row_hash_b=lost["manifest"].row_hashes[0],
                    expected_hash=lost["manifest"].row_hashes[0],
                )
            )
        finally:
            try:
                ch.close()
            except Exception:
                pass
            ctx.pop()
            reset_fence_backend()


if __name__ == "__main__":
    unittest.main()
