import json
import unittest
from datetime import datetime
from types import SimpleNamespace
from unittest.mock import Mock

from parsers.base import ParsedEvent
from utils.clickhouse import get_event_by_evidence_record_key
from utils.event_selector import build_event_selector_key
from utils.evidence_identity import (
    EVIDENCE_IDENTITY_VERSION,
    EvidenceIdentityQuality,
    build_evidence_record_identity,
    build_evidence_record_locator,
)


class EvidenceIdentityTestCase(unittest.TestCase):
    def _event(self, **overrides):
        data = {
            "case_id": 7,
            "artifact_type": "custom_log",
            "timestamp": datetime(2026, 4, 21, 12, 0, 0, 123000),
            "timestamp_utc": datetime(2026, 4, 21, 12, 0, 0, 123000),
            "timestamp_source_tz": "UTC",
            "source_file": "source.log",
            "source_path": "/evidence/source.log",
            "source_host": "HOST1",
            "case_file_id": 99,
            "event_id": "1000",
            "raw_json": json.dumps({"message": "alpha"}),
            "extra_fields": "{}",
            "parser_version": "Parser-1",
        }
        data.update(overrides)
        return ParsedEvent(**data)

    def test_same_second_selector_collision_gets_distinct_evidence_keys(self):
        first = self._event(raw_json=json.dumps({"message": "alpha"}))
        second = self._event(raw_json=json.dumps({"message": "bravo"}))

        first_selector = build_event_selector_key(
            event_id=first.event_id,
            record_id=first.record_id,
            source_file=first.source_file,
            source_host=first.source_host,
            timestamp=first.timestamp_utc.strftime("%Y-%m-%d %H:%M:%S"),
            artifact_type=first.artifact_type,
        )
        second_selector = build_event_selector_key(
            event_id=second.event_id,
            record_id=second.record_id,
            source_file=second.source_file,
            source_host=second.source_host,
            timestamp=second.timestamp_utc.strftime("%Y-%m-%d %H:%M:%S"),
            artifact_type=second.artifact_type,
        )

        self.assertEqual(first_selector, second_selector)
        self.assertNotEqual(
            build_evidence_record_identity(first).evidence_record_key,
            build_evidence_record_identity(second).evidence_record_key,
        )

    def test_deterministic_reingestion_generates_same_key(self):
        event = self._event()
        clone = self._event()

        self.assertEqual(
            build_evidence_record_identity(event).evidence_record_key,
            build_evidence_record_identity(clone).evidence_record_key,
        )

    def test_native_record_id_is_scoped_to_source_evidence(self):
        first = self._event(record_id=55, source_file="Security.evtx")
        second = self._event(record_id=55, source_file="ForwardedEvents.evtx")

        first_identity = build_evidence_record_identity(first)
        second_identity = build_evidence_record_identity(second)

        self.assertEqual(first_identity.evidence_identity_quality, EvidenceIdentityQuality.NATIVE.value)
        self.assertNotEqual(first_identity.evidence_record_key, second_identity.evidence_record_key)

    def test_cross_case_records_have_distinct_keys(self):
        case_a = self._event(case_id=1)
        case_b = self._event(case_id=2)

        self.assertNotEqual(
            build_evidence_record_identity(case_a).evidence_record_key,
            build_evidence_record_identity(case_b).evidence_record_key,
        )

    def test_mutable_analyst_state_does_not_change_identity(self):
        baseline = self._event()
        mutated = self._event()
        mutated.analyst_tags = ["reviewed"]
        mutated.analyst_notes = "Analyst note"
        mutated.noise_matched = True
        mutated.noise_rules = ["noise-rule"]
        mutated.ioc_types = ["ip"]

        self.assertEqual(
            build_evidence_record_identity(baseline).evidence_record_key,
            build_evidence_record_identity(mutated).evidence_record_key,
        )

    def test_timestamp_precision_is_preserved_for_fingerprints(self):
        first = self._event(
            timestamp=datetime(2026, 4, 21, 12, 0, 0, 100000),
            timestamp_utc=datetime(2026, 4, 21, 12, 0, 0, 100000),
            raw_json="{}",
            search_blob="same content",
        )
        second = self._event(
            timestamp=datetime(2026, 4, 21, 12, 0, 0, 900000),
            timestamp_utc=datetime(2026, 4, 21, 12, 0, 0, 900000),
            raw_json="{}",
            search_blob="same content",
        )

        self.assertNotEqual(
            build_evidence_record_identity(first).evidence_record_key,
            build_evidence_record_identity(second).evidence_record_key,
        )

    def test_canonical_serialization_ignores_dictionary_order(self):
        first = self._event(raw_json='{"b": 2, "a": 1}')
        second = self._event(raw_json='{"a": 1, "b": 2}')

        self.assertEqual(
            build_evidence_record_identity(first).evidence_record_key,
            build_evidence_record_identity(second).evidence_record_key,
        )

    def test_meaningful_source_record_difference_changes_fingerprint(self):
        first = self._event(raw_json=json.dumps({"message": "alpha", "code": 1}))
        second = self._event(raw_json=json.dumps({"message": "alpha", "code": 2}))

        self.assertNotEqual(
            build_evidence_record_identity(first).evidence_record_key,
            build_evidence_record_identity(second).evidence_record_key,
        )

    def test_existing_selector_behavior_still_uses_second_precision_fallback(self):
        selector = build_event_selector_key(
            event_id="4104",
            timestamp="2026-04-21 12:00:00",
            source_file="PowerShell.evtx",
            source_host="HOST1",
            artifact_type="evtx",
        )

        self.assertEqual(
            selector,
            "ts:2026-04-21 12:00:00|host:HOST1|artifact:evtx|event:4104|file:PowerShell.evtx",
        )

    def test_case_scoped_lookup_does_not_resolve_cross_case_key(self):
        key = build_evidence_record_identity(self._event(case_id=1)).evidence_record_key
        client = Mock()
        client.query.return_value = SimpleNamespace(result_rows=[])

        self.assertIsNone(get_event_by_evidence_record_key(2, key, client=client))
        self.assertEqual(client.query.call_args.kwargs["parameters"]["case_id"], 2)
        self.assertEqual(client.query.call_args.kwargs["parameters"]["evidence_record_key"], key)

    def test_parsed_event_row_includes_identity_columns(self):
        event = self._event()
        row = event.to_clickhouse_row()
        columns = {name: index for index, name in enumerate(ParsedEvent.clickhouse_columns())}

        self.assertTrue(row[columns["evidence_record_key"]].startswith("erk:v1:"))
        self.assertEqual(row[columns["evidence_identity_version"]], EVIDENCE_IDENTITY_VERSION)
        self.assertEqual(row[columns["evidence_identity_quality"]], EvidenceIdentityQuality.FINGERPRINTED.value)

    def test_locator_carries_future_provenance_context(self):
        event = self._event(extra_fields=json.dumps({"entry_id": "abc"}))
        identity = build_evidence_record_identity(event)
        locator = build_evidence_record_locator(
            event,
            selector_key="selector",
            evidence_record_key=identity.evidence_record_key,
        )

        self.assertEqual(locator.case_id, 7)
        self.assertEqual(locator.evidence_record_key, identity.evidence_record_key)
        self.assertEqual(locator.selector_key, "selector")
        self.assertEqual(locator.case_file_id, 99)
        self.assertEqual(locator.source_native_identifier, "entry_id:abc")


if __name__ == "__main__":
    unittest.main()
