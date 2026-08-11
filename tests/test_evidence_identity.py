import importlib.util
import json
import os
import sys
import types
import unittest
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

from parsers.base import ParsedEvent


os.environ.setdefault("SECRET_KEY", "test-secret")
REPO_ROOT = Path(__file__).resolve().parent.parent


def _load_module(module_name, relative_path):
    spec = importlib.util.spec_from_file_location(module_name, REPO_ROOT / relative_path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


evidence_identity = _load_module("evidence_identity_under_test", "utils/evidence_identity.py")
EVIDENCE_IDENTITY_VERSION = evidence_identity.EVIDENCE_IDENTITY_VERSION
EvidenceIdentityQuality = evidence_identity.EvidenceIdentityQuality
build_evidence_record_identity = evidence_identity.build_evidence_record_identity
build_identity_from_clickhouse_row = evidence_identity.build_identity_from_clickhouse_row
build_evidence_record_locator = evidence_identity.build_evidence_record_locator
event_selector = _load_module("event_selector_under_test", "utils/event_selector.py")
build_event_selector_key = event_selector.build_event_selector_key

sys.modules.setdefault("clickhouse_connect", types.SimpleNamespace(get_client=lambda *args, **kwargs: None))
_original_config = sys.modules.get("config")
if "config" not in sys.modules:
    config_module = types.ModuleType("config")
    config_module.Config = types.SimpleNamespace(
        CLICKHOUSE_HOST="localhost",
        CLICKHOUSE_PORT=8123,
        CLICKHOUSE_DATABASE="casescope",
        CLICKHOUSE_USER="default",
        CLICKHOUSE_PASSWORD="",
    )
    sys.modules["config"] = config_module
try:
    clickhouse_module = _load_module("clickhouse_under_test", "utils/clickhouse.py")
finally:
    if _original_config is None:
        sys.modules.pop("config", None)
    else:
        sys.modules["config"] = _original_config
get_event_by_evidence_record_key = clickhouse_module.get_event_by_evidence_record_key


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

    def test_v2_key_prefix_and_version_are_explicit(self):
        identity = build_evidence_record_identity(self._event())

        self.assertTrue(identity.evidence_record_key.startswith("erk:v2:"))
        self.assertEqual(identity.evidence_identity_version, "2")
        self.assertFalse(identity.evidence_record_key.startswith("erk:v1:"))

    def test_legacy_v1_prefix_is_distinguishable_from_v2(self):
        identity = build_evidence_record_identity(self._event())

        self.assertNotEqual("erk:v1:" + identity.evidence_record_key.rsplit(":", 1)[-1], identity.evidence_record_key)

    def test_native_record_id_is_scoped_to_source_evidence(self):
        first = self._event(artifact_type="evtx", record_id=55, source_file="Security.evtx", case_file_id=101)
        second = self._event(artifact_type="evtx", record_id=55, source_file="Security.evtx", case_file_id=202)

        first_identity = build_evidence_record_identity(first)
        second_identity = build_evidence_record_identity(second)

        self.assertEqual(first_identity.evidence_identity_quality, EvidenceIdentityQuality.NATIVE.value)
        self.assertNotEqual(first_identity.evidence_record_key, second_identity.evidence_record_key)

    def test_parser_version_change_does_not_change_evidence_key(self):
        first = self._event(parser_version="Parser-1.0")
        second = self._event(parser_version="Parser-2.0")

        self.assertEqual(
            build_evidence_record_identity(first).evidence_record_key,
            build_evidence_record_identity(second).evidence_record_key,
        )

    def test_raw_backed_identity_ignores_parser_interpretation_changes(self):
        raw = json.dumps({"message": "same", "record": 42})
        first = self._event(
            raw_json=raw,
            source_host="OLDHOST",
            event_id="1000",
            timestamp=datetime(2026, 4, 21, 12, 0, 0, 123000),
            timestamp_utc=datetime(2026, 4, 21, 12, 0, 0, 123000),
            timestamp_source_tz="UTC",
        )
        second = self._event(
            raw_json=raw,
            source_host="NEWHOST",
            event_id="2000",
            timestamp=datetime(2026, 4, 21, 8, 0, 0, 999000),
            timestamp_utc=datetime(2026, 4, 21, 12, 0, 1, 124000),
            timestamp_source_tz="America/New_York",
        )

        self.assertEqual(
            build_evidence_record_identity(first).evidence_record_key,
            build_evidence_record_identity(second).evidence_record_key,
        )

    def test_retained_source_path_change_does_not_change_key_with_case_file_scope(self):
        first = self._event(source_path="/originals/foo.evtx", case_file_id=42)
        second = self._event(source_path="/archive/reindexed/foo.evtx", case_file_id=42)

        self.assertEqual(
            build_evidence_record_identity(first).evidence_record_key,
            build_evidence_record_identity(second).evidence_record_key,
        )

    def test_evtx_record_id_is_authoritative_native_identity(self):
        identity = build_evidence_record_identity(
            self._event(artifact_type="evtx", record_id=100, raw_json="{}")
        )

        self.assertEqual(identity.evidence_identity_quality, EvidenceIdentityQuality.NATIVE.value)

    def test_native_identity_does_not_parse_unused_raw_json(self):
        parsed_values = []
        original_parse = evidence_identity._parse_jsonish

        def tracking_parse(value):
            parsed_values.append(value)
            return original_parse(value)

        evidence_identity._parse_jsonish = tracking_parse
        try:
            identity = build_evidence_record_identity(
                self._event(artifact_type="evtx", record_id=100, raw_json="{not-json")
            )
        finally:
            evidence_identity._parse_jsonish = original_parse

        self.assertEqual(identity.evidence_identity_quality, EvidenceIdentityQuality.NATIVE.value)
        self.assertNotIn("{not-json", parsed_values)

    def test_evtx_native_identity_ignores_normalized_event_fields(self):
        first = self._event(
            artifact_type="evtx",
            record_id=100,
            event_id="4624",
            channel="Security",
            provider="Microsoft-Windows-Security-Auditing",
            parser_version="Parser-1",
        )
        second = self._event(
            artifact_type="evtx",
            record_id=100,
            event_id="9999",
            channel="System",
            provider="Corrected-Provider",
            parser_version="Parser-2",
        )

        self.assertEqual(
            build_evidence_record_identity(first).evidence_record_key,
            build_evidence_record_identity(second).evidence_record_key,
        )

    def test_positive_non_native_record_id_is_not_native_identity(self):
        identity = build_evidence_record_identity(
            self._event(record_id=100, raw_json=json.dumps({"message": "same"}))
        )

        self.assertEqual(identity.evidence_identity_quality, EvidenceIdentityQuality.FINGERPRINTED.value)

    def test_acquisition_records_with_same_count_remain_distinct(self):
        first = self._event(
            artifact_type="cylr_acquisition",
            event_id="archive_extracted",
            record_id=100,
            raw_json=json.dumps({"archive_name": "a.zip", "extracted_file_count": 100}),
        )
        second = self._event(
            artifact_type="cylr_acquisition",
            event_id="archive_extracted",
            record_id=100,
            raw_json=json.dumps({"archive_name": "b.zip", "extracted_file_count": 100}),
        )

        self.assertNotEqual(
            build_evidence_record_identity(first).evidence_record_key,
            build_evidence_record_identity(second).evidence_record_key,
        )

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

    def test_search_blob_changes_do_not_change_identity(self):
        baseline = self._event(search_blob="original search text")
        mutated = self._event(search_blob="new enrichment search text")

        self.assertEqual(
            build_evidence_record_identity(baseline).evidence_record_key,
            build_evidence_record_identity(mutated).evidence_record_key,
        )

    def test_enrichment_and_provenance_changes_do_not_change_identity(self):
        baseline = self._event()
        mutated = self._event(
            rule_title="Suspicious Thing",
            rule_level="high",
            mitre_tactics=["Execution"],
            mitre_tags=["T1059"],
            mitre_attack_ids=["T1059"],
            mitre_attack_tactics=["Execution"],
            mitre_attack_sources=["hayabusa"],
            mitre_mapping_max_confidence=90,
            extra_fields=json.dumps({
                "field_provenance": {"command_line": "MODEL_SYNTHESIZED"},
                "emitted_provenance": "MODEL_SYNTHESIZED",
                "hayabusa_detections": [{"rule": "new"}],
                "model_name": "new-model",
                "ai_summary": "new summary",
            }),
        )

        self.assertEqual(
            build_evidence_record_identity(baseline).evidence_record_key,
            build_evidence_record_identity(mutated).evidence_record_key,
        )

    def test_raw_source_fields_named_like_casescope_metadata_are_preserved(self):
        first = self._event(raw_json=json.dumps({"model_name": "A", "message": "x"}))
        second = self._event(raw_json=json.dumps({"model_name": "B", "message": "x"}))
        third = self._event(raw_json=json.dumps({"ioc_types": ["ip"], "message": "x"}))
        fourth = self._event(raw_json=json.dumps({"ioc_types": ["domain"], "message": "x"}))

        self.assertNotEqual(
            build_evidence_record_identity(first).evidence_record_key,
            build_evidence_record_identity(second).evidence_record_key,
        )
        self.assertNotEqual(
            build_evidence_record_identity(third).evidence_record_key,
            build_evidence_record_identity(fourth).evidence_record_key,
        )

    def test_normalized_fallback_still_distinguishes_stable_source_data(self):
        first = self._event(raw_json="{}", event_id="1000")
        second = self._event(raw_json="{}", event_id="2000")

        self.assertNotEqual(
            build_evidence_record_identity(first).evidence_record_key,
            build_evidence_record_identity(second).evidence_record_key,
        )

    def test_timestamp_precision_is_millisecond_for_fingerprints(self):
        first = self._event(
            timestamp=datetime(2026, 4, 21, 12, 0, 0, 123456),
            timestamp_utc=datetime(2026, 4, 21, 12, 0, 0, 123456),
            raw_json="{}",
        )
        second = self._event(
            timestamp=datetime(2026, 4, 21, 12, 0, 0, 123000),
            timestamp_utc=datetime(2026, 4, 21, 12, 0, 0, 123000),
            raw_json="{}",
        )

        self.assertEqual(
            build_evidence_record_identity(first).evidence_record_key,
            build_evidence_record_identity(second).evidence_record_key,
        )

    def test_millisecond_timestamp_difference_changes_fingerprint(self):
        first = self._event(
            timestamp=datetime(2026, 4, 21, 12, 0, 0, 123000),
            timestamp_utc=datetime(2026, 4, 21, 12, 0, 0, 123000),
            raw_json="{}",
        )
        second = self._event(
            timestamp=datetime(2026, 4, 21, 12, 0, 0, 124000),
            timestamp_utc=datetime(2026, 4, 21, 12, 0, 0, 124000),
            raw_json="{}",
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

    def test_raw_missing_and_null_are_distinct(self):
        self.assertNotEqual(
            build_evidence_record_identity(self._event(raw_json="{}")).evidence_record_key,
            build_evidence_record_identity(self._event(raw_json='{"a": null}')).evidence_record_key,
        )

    def test_raw_null_and_empty_string_are_distinct(self):
        self.assertNotEqual(
            build_evidence_record_identity(self._event(raw_json='{"a": null}')).evidence_record_key,
            build_evidence_record_identity(self._event(raw_json='{"a": ""}')).evidence_record_key,
        )

    def test_raw_zero_is_preserved(self):
        self.assertNotEqual(
            build_evidence_record_identity(self._event(raw_json='{"a": 0}')).evidence_record_key,
            build_evidence_record_identity(self._event(raw_json="{}")).evidence_record_key,
        )

    def test_raw_false_is_preserved(self):
        self.assertNotEqual(
            build_evidence_record_identity(self._event(raw_json='{"a": false}')).evidence_record_key,
            build_evidence_record_identity(self._event(raw_json="{}")).evidence_record_key,
        )

    def test_raw_dict_ordering_with_null_is_stable(self):
        self.assertEqual(
            build_evidence_record_identity(self._event(raw_json='{"a": null, "b": 1}')).evidence_record_key,
            build_evidence_record_identity(self._event(raw_json='{"b": 1, "a": null}')).evidence_record_key,
        )

    def test_meaningful_source_record_difference_changes_fingerprint(self):
        first = self._event(raw_json=json.dumps({"message": "alpha", "code": 1}))
        second = self._event(raw_json=json.dumps({"message": "alpha", "code": 2}))

        self.assertNotEqual(
            build_evidence_record_identity(first).evidence_record_key,
            build_evidence_record_identity(second).evidence_record_key,
        )

    def test_zero_valued_discovered_source_identifier_is_locator_metadata_only(self):
        identity = build_evidence_record_identity(
            self._event(raw_json="{}", extra_fields=json.dumps({"row_id": 0}))
        )
        locator = build_evidence_record_locator(
            self._event(raw_json="{}", extra_fields=json.dumps({"row_id": 0})),
            evidence_record_key=identity.evidence_record_key,
        )

        self.assertEqual(identity.evidence_identity_quality, EvidenceIdentityQuality.FINGERPRINTED.value)
        self.assertEqual(locator.source_native_identifier, "row_id:0")

    def test_newly_extracted_unapproved_row_id_does_not_rename_raw_backed_identity(self):
        first = self._event(raw_json=json.dumps({"message": "same"}), extra_fields="{}")
        second = self._event(
            raw_json=json.dumps({"message": "same"}),
            extra_fields=json.dumps({"row_id": 123}),
        )

        self.assertEqual(
            build_evidence_record_identity(first).evidence_record_key,
            build_evidence_record_identity(second).evidence_record_key,
        )

    def test_explicit_source_identifier_opt_in_uses_source_identifier_quality(self):
        identity = build_evidence_record_identity(
            self._event(
                raw_json=json.dumps({"message": "same"}),
                extra_fields=json.dumps({
                    "source_record_identifier_authoritative": True,
                    "source_record_identifier_type": "sqlite_rowid",
                    "source_record_identifier_value": 123,
                }),
            )
        )

        self.assertEqual(identity.evidence_identity_quality, EvidenceIdentityQuality.SOURCE_IDENTIFIER.value)

    def test_authoritative_source_identifier_is_source_scoped(self):
        first = self._event(
            case_file_id=99,
            extra_fields=json.dumps({
                "source_record_identifier_authoritative": True,
                "source_record_identifier_type": "sqlite_rowid",
                "source_record_identifier_value": 123,
            }),
        )
        second = self._event(
            case_file_id=100,
            extra_fields=json.dumps({
                "source_record_identifier_authoritative": True,
                "source_record_identifier_type": "sqlite_rowid",
                "source_record_identifier_value": 123,
            }),
        )

        self.assertNotEqual(
            build_evidence_record_identity(first).evidence_record_key,
            build_evidence_record_identity(second).evidence_record_key,
        )

    def test_different_authoritative_source_identifier_changes_key(self):
        first = self._event(
            extra_fields=json.dumps({
                "source_record_identifier_authoritative": True,
                "source_record_identifier_type": "sqlite_rowid",
                "source_record_identifier_value": 123,
            }),
        )
        second = self._event(
            extra_fields=json.dumps({
                "source_record_identifier_authoritative": True,
                "source_record_identifier_type": "sqlite_rowid",
                "source_record_identifier_value": 124,
            }),
        )

        self.assertNotEqual(
            build_evidence_record_identity(first).evidence_record_key,
            build_evidence_record_identity(second).evidence_record_key,
        )

    def test_fake_uid_without_authority_does_not_outrank_raw_source(self):
        first = self._event(raw_json=json.dumps({"message": "same"}), extra_fields=json.dumps({"uid": "derived-a"}))
        second = self._event(raw_json=json.dumps({"message": "same"}), extra_fields=json.dumps({"uid": "derived-b"}))

        self.assertEqual(
            build_evidence_record_identity(first).evidence_record_key,
            build_evidence_record_identity(second).evidence_record_key,
        )

    def test_identity_hierarchy_order_is_explicit(self):
        source_authority = {
            "source_record_identifier_authoritative": True,
            "source_record_identifier_type": "sqlite_rowid",
            "source_record_identifier_value": 123,
        }

        native = build_evidence_record_identity(
            self._event(
                artifact_type="evtx",
                record_id=44,
                raw_json=json.dumps({"message": "raw"}),
                extra_fields=json.dumps(source_authority),
            )
        )
        source_identifier = build_evidence_record_identity(
            self._event(
                raw_json=json.dumps({"message": "raw-a"}),
                extra_fields=json.dumps(source_authority),
            )
        )
        same_source_identifier_changed_raw = build_evidence_record_identity(
            self._event(
                raw_json=json.dumps({"message": "raw-b"}),
                extra_fields=json.dumps(source_authority),
            )
        )
        raw_backed = build_evidence_record_identity(
            self._event(
                raw_json=json.dumps({"message": "raw"}),
                extra_fields=json.dumps({"row_id": 123}),
                event_id="1000",
            )
        )
        same_raw_changed_normalized = build_evidence_record_identity(
            self._event(
                raw_json=json.dumps({"message": "raw"}),
                extra_fields=json.dumps({"row_id": 456}),
                event_id="2000",
            )
        )
        normalized = build_evidence_record_identity(self._event(raw_json="{}", event_id="1000"))
        legacy = build_identity_from_clickhouse_row({
            "case_id": 7,
            "artifact_type": "",
            "timestamp": "",
            "timestamp_utc": "",
            "source_file": "",
            "source_path": "",
            "source_host": "",
            "case_file_id": None,
            "event_id": "",
            "record_id": None,
            "raw_json": "{}",
            "search_blob": "",
            "extra_fields": "{}",
            "parser_version": "old-parser",
        })

        self.assertEqual(native.evidence_identity_quality, EvidenceIdentityQuality.NATIVE.value)
        self.assertEqual(source_identifier.evidence_identity_quality, EvidenceIdentityQuality.SOURCE_IDENTIFIER.value)
        self.assertEqual(source_identifier.evidence_record_key, same_source_identifier_changed_raw.evidence_record_key)
        self.assertEqual(raw_backed.evidence_identity_quality, EvidenceIdentityQuality.FINGERPRINTED.value)
        self.assertEqual(raw_backed.evidence_record_key, same_raw_changed_normalized.evidence_record_key)
        self.assertEqual(normalized.evidence_identity_quality, EvidenceIdentityQuality.FINGERPRINTED.value)
        self.assertEqual(legacy.evidence_identity_quality, EvidenceIdentityQuality.LEGACY_FALLBACK.value)

    def test_legacy_fallback_quality_does_not_change_key_material(self):
        row = {
            "case_id": 7,
            "artifact_type": "",
            "timestamp": "",
            "timestamp_utc": "",
            "source_file": "",
            "source_path": "",
            "source_host": "",
            "case_file_id": None,
            "event_id": "",
            "record_id": None,
            "raw_json": "{}",
            "search_blob": "",
            "extra_fields": "{}",
            "parser_version": "old-parser",
        }

        generic = build_evidence_record_identity(row)
        backfilled = build_identity_from_clickhouse_row(row)

        self.assertEqual(generic.evidence_record_key, backfilled.evidence_record_key)
        self.assertEqual(backfilled.evidence_identity_quality, EvidenceIdentityQuality.LEGACY_FALLBACK.value)

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

    def test_empty_evidence_key_lookup_returns_none_without_query(self):
        client = Mock()

        self.assertIsNone(get_event_by_evidence_record_key(1, "", client=client))
        client.query.assert_not_called()

    def test_parsed_event_row_includes_identity_columns(self):
        event = self._event()
        original_utils = sys.modules.get("utils")
        original_evidence_identity = sys.modules.get("utils.evidence_identity")
        utils_package = types.ModuleType("utils")
        utils_package.evidence_identity = evidence_identity
        sys.modules["utils"] = utils_package
        sys.modules["utils.evidence_identity"] = evidence_identity
        try:
            row = event.to_clickhouse_row()
        finally:
            if original_utils is None:
                sys.modules.pop("utils", None)
            else:
                sys.modules["utils"] = original_utils
            if original_evidence_identity is None:
                sys.modules.pop("utils.evidence_identity", None)
            else:
                sys.modules["utils.evidence_identity"] = original_evidence_identity
        columns = {name: index for index, name in enumerate(ParsedEvent.clickhouse_columns())}

        self.assertTrue(row[columns["evidence_record_key"]].startswith("erk:v2:"))
        self.assertEqual(row[columns["evidence_identity_version"]], EVIDENCE_IDENTITY_VERSION)
        self.assertEqual(row[columns["evidence_identity_quality"]], EvidenceIdentityQuality.FINGERPRINTED.value)

    def test_locator_carries_future_provenance_context(self):
        event = self._event(
            extra_fields=json.dumps({"entry_id": "abc"}),
            parser_version="Parser-2.0",
            source_path="/archive/reindexed/source.log",
        )
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
        self.assertEqual(locator.parser_version, "Parser-2.0")
        self.assertEqual(locator.source_path, "/archive/reindexed/source.log")


if __name__ == "__main__":
    unittest.main()
