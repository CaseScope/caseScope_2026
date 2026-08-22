"""Phase 2.3C ingest-fence contract alignment tests.

Verifies that INGEST_FENCE_CONTRACT records accepted Phase 2.3 shared
lightweight UPDATE writers without rewriting the Phase 0B historical
baseline or starting Phase 2.4. No production mutation.
"""
from __future__ import annotations

import inspect
import os
import re
import unittest

os.environ.setdefault("SECRET_KEY", "phase2-3c-test-secret")

from utils.clickhouse import (
    LIGHTWEIGHT_UPDATE_MAX_SELECTOR_KEYS,
    run_events_lightweight_update,
    run_events_update,
)
from utils.ingest_fence import exclusive_ingest_fence, shared_ingest_admission
from utils.manifest_protocol import insert_managed_batch
from parsers.registry import BatchProcessor


REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONTRACT_PATH = os.path.join(
    REPO_ROOT, "docs", "database_flow_contracts", "INGEST_FENCE_CONTRACT.md"
)
ADDENDUM_HEADING = "## Implemented Extensions / Phase 2.3"
HISTORICAL_BASELINE_SNIPPET = (
    "`delete_file_events`, `run_events_update`, and normal inserts "
    "do not use a shared writer lease."
)
LATER_PHASE_TOKENS = (
    ("LEK", r"\bLEK\b"),
    ("events_current", r"\bevents_current\b"),
    ("event_observations_current", r"\bevent_observations_current\b"),
    ("Phase 2.4", r"Phase 2\.4"),
    ("ERK API cutover", r"ERK API"),
)
EXCLUSION_WINDOW = re.compile(
    r"(does NOT change|does not change|does not implement|"
    r"does not introduce|not implement|not introduce|"
    r"NOT change|unchanged authorities|only as explicit exclusions|"
    r"explicit exclusions)",
    re.IGNORECASE,
)


def _read_contract() -> str:
    with open(CONTRACT_PATH, encoding="utf-8") as handle:
        return handle.read()


def _split_contract(text: str) -> tuple[str, str]:
    if ADDENDUM_HEADING not in text:
        raise AssertionError("INGEST_FENCE_CONTRACT is missing the Phase 2.3 addendum heading")
    historical, addendum = text.split(ADDENDUM_HEADING, 1)
    return historical, addendum


class Phase23CRuntimeFactsTests(unittest.TestCase):
    def test_lightweight_helper_exists_with_shared_admission(self):
        self.assertTrue(callable(run_events_lightweight_update))
        self.assertEqual(LIGHTWEIGHT_UPDATE_MAX_SELECTOR_KEYS, 1000)
        source = inspect.getsource(run_events_lightweight_update)
        self.assertIn('shared_ingest_admission("events_lightweight_update"', source)
        self.assertIn("case_id=case_id", source)
        self.assertNotIn("exclusive_ingest_fence", source)

    def test_classic_helper_remains_exclusive(self):
        source = inspect.getsource(run_events_update)
        self.assertIn("exclusive_ingest_fence('events_alter_update')", source)
        self.assertNotIn("shared_ingest_admission", source)

    def test_physical_event_inserts_use_shared_admission(self):
        processor_source = inspect.getsource(BatchProcessor)
        managed_source = inspect.getsource(insert_managed_batch)
        for source, label in (
            (processor_source, "BatchProcessor"),
            (managed_source, "insert_managed_batch"),
        ):
            self.assertIn("shared_ingest_admission", source, msg=label)
            self.assertIn("events_insert", source, msg=label)

    def test_fence_primitives_unchanged(self):
        self.assertTrue(callable(shared_ingest_admission))
        self.assertTrue(callable(exclusive_ingest_fence))
        shared_source = inspect.getsource(shared_ingest_admission)
        exclusive_source = inspect.getsource(exclusive_ingest_fence)
        self.assertIn("Acquire a shared writer lease", shared_source)
        self.assertIn("Acquire the exclusive events fence after draining shared writers", exclusive_source)


class Phase23CFenceContractAlignmentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.contract = _read_contract()
        cls.historical, cls.addendum = _split_contract(cls.contract)

    def test_historical_phase0b_baseline_not_rewritten(self):
        self.assertIn("## Current Baseline", self.historical)
        self.assertIn(HISTORICAL_BASELINE_SNIPPET, self.historical)
        self.assertIn("## Fail-Closed Rule", self.historical)
        self.assertIn("## Lease Semantics", self.historical)
        self.assertIn("acquire shared admission lease", self.historical)
        self.assertIn("INSERT", self.historical)
        self.assertNotIn("run_events_lightweight_update", self.historical)
        self.assertNotIn("LIGHTWEIGHT_UPDATE_MAX_SELECTOR_KEYS", self.historical)

    def test_addendum_is_dated_2026_08_22(self):
        self.assertIn("Dated: 2026-08-22", self.addendum)

    def test_mentions_run_events_lightweight_update(self):
        self.assertIn("run_events_lightweight_update", self.addendum)
        self.assertIn("utils.clickhouse.run_events_lightweight_update", self.addendum)

    def test_lightweight_update_is_shared_admission_work(self):
        self.assertIn("shared-admission events writers", self.addendum)
        self.assertIn("bounded Phase 2.3 lightweight SQL UPDATE of `events`", self.addendum)
        self.assertIn("shared_ingest_admission", self.addendum)
        self.assertIn('"events_lightweight_update"', self.addendum)
        self.assertIn("physical INSERT into `events`", self.addendum)

    def test_records_1000_selector_implementation_boundary(self):
        self.assertIn("LIGHTWEIGHT_UPDATE_MAX_SELECTOR_KEYS = 1000", self.addendum)
        self.assertIn("CaseScope Phase 2.3 measurement-derived bridge boundary", self.addendum)

    def test_classic_rewrites_stay_exclusive(self):
        self.assertIn("exclusive_ingest_fence", self.addendum)
        self.assertIn('"events_alter_update"', self.addendum)
        self.assertIn("Existing broad/classic events rewrites continue to acquire", self.addendum)
        self.assertIn("blocks new shared INSERT writers", self.addendum)
        self.assertIn("blocks new shared lightweight UPDATE writers", self.addendum)
        self.assertIn("drains active shared INSERT/UPDATE writers", self.addendum)
        self.assertIn("proceeds only after drain", self.addendum)
        self.assertIn("Predicate-driven/case-wide updates remain classic/exclusive", self.addendum)

    def test_retains_fail_closed_behavior(self):
        self.assertIn("## Fail-Closed Rule", self.historical)
        self.assertIn("FAILS CLOSED when shared-admission authority is unavailable", self.addendum)
        self.assertIn("remains fail closed", self.addendum)

    def test_does_not_authorize_arbitrary_predicate_lightweight_update(self):
        lowered = self.addendum.lower()
        self.assertIn("not permission for arbitrary predicate", lowered)
        self.assertIn("does not accept", lowered)
        self.assertIn("caller-supplied predicates", lowered)
        self.assertIn("structurally limited to explicit", lowered)
        self.assertIn("case_id", lowered)
        self.assertIn("selector_key set", lowered)
        self.assertIn("optional `artifact_type`", lowered)
        self.assertNotIn("accepts caller-supplied where", lowered)
        self.assertNotIn("arbitrary predicate lightweight update is allowed", lowered)

    def test_1000_limit_is_not_universal_clickhouse_behavior(self):
        self.assertIn("NOT a universal ClickHouse limit", self.addendum)
        remainder = self.addendum.replace("NOT a universal ClickHouse limit", "")
        self.assertNotIn("universal ClickHouse", remainder)
        self.assertNotIn("ClickHouse limit is 1000", remainder)
        self.assertNotIn("universal ClickHouse threshold", remainder)

    def test_later_phase_tokens_are_exclusions_only(self):
        for label, pattern in LATER_PHASE_TOKENS:
            matches = list(re.finditer(pattern, self.contract))
            self.assertTrue(matches, msg=f"{label} must appear as an explicit exclusion")
            for match in matches:
                start = max(0, match.start() - 280)
                end = min(len(self.contract), match.end() + 280)
                window = self.contract[start:end]
                self.assertRegex(
                    window,
                    EXCLUSION_WINDOW,
                    msg=f"{label} at {match.start()} is not an explicit exclusion",
                )
            self.assertNotIn(label, self.historical)

    def test_addendum_does_not_alter_core_fence_model(self):
        lowered = self.addendum.lower()
        self.assertNotIn("rewrite lease ownership", lowered)
        self.assertNotIn("new lock system", lowered)
        self.assertNotIn("change ttl", lowered)
        self.assertNotIn("replace redis authority", lowered)
