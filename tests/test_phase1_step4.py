"""Phase 1 Step 4 tests: Hayabusa/EvtxECmd directory-mode identity and fallback.

Run with:

    /opt/casescope/venv/bin/python -m unittest tests.test_phase1_step4

Do not use production-bound full unittest discovery.
"""
from __future__ import annotations

import json
import os
import tempfile
import unittest
from unittest.mock import patch

os.environ.setdefault("SECRET_KEY", "phase1-step4-test-secret")

from utils.evtx_directory_mode import (
    AttributionError,
    DirectoryModeError,
    EvtxGroupMember,
    chunk_evtx_members,
    detection_correlation_key,
    evtxecmd_json_cmd,
    hayabusa_detection_entry,
    hayabusa_directory_had_errors,
    hayabusa_json_timeline_cmd,
    index_hayabusa_detections,
    lookup_hayabusa_detections,
    remap_evtxecmd_sourcefile,
    stage_evtx_group,
)


def _touch_evtx(path: str, payload: bytes = b"ElfFile\x00fake") -> str:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as handle:
        handle.write(payload)
    return path


class SourceIdentityTestCase(unittest.TestCase):
    def test_correlation_key_requires_source_and_record_id(self):
        self.assertEqual(detection_correlation_key("/a/Security.evtx", 100), ("/a/Security.evtx", "100"))
        with self.assertRaises(AttributionError):
            detection_correlation_key("", 100)
        with self.assertRaises(AttributionError):
            detection_correlation_key("/a/Security.evtx", None)

    def test_record_id_100_in_two_files_does_not_cross_attach(self):
        rows = [
            {
                "EvtxFile": "/hostA/Security.evtx",
                "RecordID": 100,
                "EventID": 4624,
                "Channel": "Sec",
                "RuleTitle": "From A",
                "Level": "high",
                "RuleFile": "a.yml",
                "MitreTactics": ["Credential Access"],
                "MitreTags": ["T1110"],
            },
            {
                "EvtxFile": "/hostB/System.evtx",
                "RecordID": 100,
                "EventID": 7045,
                "Channel": "Sys",
                "RuleTitle": "From B",
                "Level": "med",
                "RuleFile": "b.yml",
                "MitreTactics": [],
                "MitreTags": [],
            },
        ]
        indexed = index_hayabusa_detections(rows)
        a = lookup_hayabusa_detections(indexed, 100, "/hostA/Security.evtx")
        b = lookup_hayabusa_detections(indexed, 100, "/hostB/System.evtx")
        self.assertEqual([item["rule_title"] for item in a], ["From A"])
        self.assertEqual([item["rule_title"] for item in b], ["From B"])
        self.assertEqual(lookup_hayabusa_detections(indexed, 100, "/hostA/System.evtx"), [])

    def test_duplicate_basename_distinct_paths_stay_unambiguous(self):
        rows = [
            {
                "EvtxFile": "/hostA/Security.evtx",
                "RecordID": 100,
                "RuleTitle": "hostA",
                "Level": "info",
                "RuleFile": "a.yml",
            },
            {
                "EvtxFile": "/hostB/Security.evtx",
                "RecordID": 100,
                "RuleTitle": "hostB",
                "Level": "info",
                "RuleFile": "b.yml",
            },
        ]
        indexed = index_hayabusa_detections(rows)
        self.assertEqual(
            lookup_hayabusa_detections(indexed, 100, "/hostA/Security.evtx")[0]["rule_title"],
            "hostA",
        )
        self.assertEqual(
            lookup_hayabusa_detections(indexed, 100, "/hostB/Security.evtx")[0]["rule_title"],
            "hostB",
        )

    def test_missing_evtxfile_in_directory_mode_is_attribution_error(self):
        with self.assertRaises(AttributionError):
            index_hayabusa_detections([{"RecordID": 100, "RuleTitle": "x", "Level": "info"}])

    def test_tuple_map_never_falls_back_to_record_id_only(self):
        indexed = index_hayabusa_detections(
            [{"EvtxFile": "/a/Security.evtx", "RecordID": 100, "RuleTitle": "A", "Level": "high"}]
        )
        self.assertEqual(lookup_hayabusa_detections(indexed, 100), [])
        self.assertEqual(
            lookup_hayabusa_detections(indexed, 100, allow_record_id_only=True),
            [],
        )
        legacy = {"100": [{"rule_title": "legacy"}]}
        self.assertEqual(
            lookup_hayabusa_detections(legacy, 100, allow_record_id_only=True)[0]["rule_title"],
            "legacy",
        )

    def test_detection_entry_preserves_current_fields_and_level_map(self):
        entry = hayabusa_detection_entry(
            {
                "RuleTitle": "RDP Logon",
                "Level": "informational",
                "RuleFile": "rdp.yml",
                "RuleID": "uuid-should-not-be-required-on-event",
                "MitreTactics": "LatMov",
                "MitreTags": "T1021.001",
                "AllFieldInfo": {"User": "alice"},
            }
        )
        self.assertEqual(
            set(entry),
            {"rule_title", "rule_level", "rule_file", "mitre_tactics", "mitre_tags"},
        )
        self.assertEqual(entry["rule_level"], "info")
        self.assertNotIn("AllFieldInfo", entry)
        self.assertNotIn("rule_id", entry)


class StagingAndAttributionTestCase(unittest.TestCase):
    def test_staging_preserves_duplicate_basenames_in_unique_dirs(self):
        with tempfile.TemporaryDirectory() as tmp:
            host_a = _touch_evtx(os.path.join(tmp, "hostA", "Security.evtx"), b"ElfFile\x00A")
            host_b = _touch_evtx(os.path.join(tmp, "hostB", "Security.evtx"), b"ElfFile\x00B")
            members = [
                EvtxGroupMember(file_path=host_a, case_file_id=11, source_host="HOSTA"),
                EvtxGroupMember(file_path=host_b, case_file_id=22, source_host="HOSTB"),
            ]
            manifest = stage_evtx_group(members)
            try:
                staged_names = [
                    os.path.basename(path)
                    for path in manifest.members_by_staged_token
                    if os.path.isfile(path)
                ]
                self.assertEqual(sorted(set(os.path.basename(p) for p in staged_names if p.endswith(".evtx") or True)), ["Security.evtx"])
                member_a = manifest.lookup_staged(
                    os.path.join(manifest.staging_dir, "cf_11", "Security.evtx")
                )
                member_b = manifest.lookup_staged(
                    os.path.join(manifest.staging_dir, "cf_22", "Security.evtx")
                )
                self.assertEqual(member_a.case_file_id, 11)
                self.assertEqual(member_b.case_file_id, 22)
                self.assertEqual(member_a.source_file, "Security.evtx")
                self.assertEqual(member_b.source_file, "Security.evtx")
                relative_a = manifest.lookup_staged(os.path.join("cf_11", "Security.evtx"))
                self.assertEqual(relative_a.case_file_id, 11)
            finally:
                import shutil
                shutil.rmtree(manifest.staging_dir, ignore_errors=True)

    def test_evtxecmd_sourcefile_remaps_to_original_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            original = _touch_evtx(os.path.join(tmp, "Security.evtx"))
            member = EvtxGroupMember(file_path=original, case_file_id=7, source_host="SEC")
            manifest = stage_evtx_group([member])
            try:
                staged = os.path.join(manifest.staging_dir, "cf_7", "Security.evtx")
                remapped, mapped = remap_evtxecmd_sourcefile(
                    {"EventRecordId": "100", "SourceFile": staged, "Channel": "Security"},
                    manifest,
                )
                self.assertEqual(mapped.case_file_id, 7)
                self.assertEqual(remapped["SourceFile"], os.path.abspath(original))
            finally:
                import shutil
                shutil.rmtree(manifest.staging_dir, ignore_errors=True)

    def test_missing_sourcefile_is_attribution_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            original = _touch_evtx(os.path.join(tmp, "Security.evtx"))
            manifest = stage_evtx_group(
                [EvtxGroupMember(file_path=original, case_file_id=1, source_host="H")]
            )
            try:
                with self.assertRaises(AttributionError):
                    remap_evtxecmd_sourcefile({"EventRecordId": "1"}, manifest)
                with self.assertRaises(AttributionError):
                    remap_evtxecmd_sourcefile(
                        {"EventRecordId": "1", "SourceFile": "/not/in/manifest.evtx"},
                        manifest,
                    )
            finally:
                import shutil
                shutil.rmtree(manifest.staging_dir, ignore_errors=True)

    def test_unknown_hayabusa_evtxfile_is_attribution_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            original = _touch_evtx(os.path.join(tmp, "Security.evtx"))
            manifest = stage_evtx_group(
                [EvtxGroupMember(file_path=original, case_file_id=1, source_host="H")]
            )
            try:
                with self.assertRaises(AttributionError):
                    index_hayabusa_detections(
                        [{"EvtxFile": "/other/Security.evtx", "RecordID": 1, "RuleTitle": "x"}],
                        manifest=manifest,
                    )
            finally:
                import shutil
                shutil.rmtree(manifest.staging_dir, ignore_errors=True)


class GroupBoundaryAndCommandTestCase(unittest.TestCase):
    def test_chunking_is_bounded_by_count_and_bytes(self):
        members = [
            EvtxGroupMember(file_path=f"/x/{i}.evtx", case_file_id=i, source_host="H", size_bytes=100)
            for i in range(5)
        ]
        groups = chunk_evtx_members(members, max_files=2, max_bytes=10000)
        self.assertEqual([len(g) for g in groups], [2, 2, 1])
        groups_bytes = chunk_evtx_members(members, max_files=32, max_bytes=250)
        self.assertTrue(all(sum(m.size_bytes for m in g) <= 250 or len(g) == 1 for g in groups_bytes))

    def test_plan_target_files_splits_without_using_safety_max(self):
        from utils.evtx_directory_mode import plan_evtx_parse_units

        members = [
            EvtxGroupMember(file_path=f"/x/{i}.evtx", case_file_id=i, source_host="H", size_bytes=100)
            for i in range(8)
        ]
        units = plan_evtx_parse_units(members, eager_first=False, target_files=4, max_files=32)
        self.assertEqual([unit.mode for unit in units], ["directory", "directory"])
        self.assertEqual([len(unit.members) for unit in units], [4, 4])
        self.assertEqual(
            [m.case_file_id for unit in units for m in unit.members],
            list(range(8)),
        )

    def test_eager_first_uses_per_file_and_does_not_reprocess(self):
        from utils.evtx_directory_mode import plan_evtx_parse_units

        members = [
            EvtxGroupMember(file_path=f"/x/{i}.evtx", case_file_id=i, source_host="H", size_bytes=100)
            for i in range(8)
        ]
        units = plan_evtx_parse_units(members, eager_first=True, target_files=8, max_files=32)
        self.assertEqual(units[0].mode, "per_file")
        self.assertEqual(units[0].members[0].case_file_id, 0)
        self.assertEqual(units[1].mode, "directory")
        self.assertEqual([m.case_file_id for m in units[1].members], list(range(1, 8)))
        ids = [m.case_file_id for unit in units for m in unit.members]
        self.assertEqual(ids, list(range(8)))
        self.assertEqual(len(ids), len(set(ids)))

    def test_eager_first_with_groups_of_two(self):
        from utils.evtx_directory_mode import plan_evtx_parse_units

        members = [
            EvtxGroupMember(file_path=f"/x/{i}.evtx", case_file_id=i, source_host="H", size_bytes=100)
            for i in range(8)
        ]
        units = plan_evtx_parse_units(members, eager_first=True, target_files=2, max_files=32)
        self.assertEqual(units[0].mode, "per_file")
        self.assertEqual([unit.mode for unit in units], ["per_file", "directory", "directory", "directory", "per_file"])
        self.assertEqual([len(unit.members) for unit in units], [1, 2, 2, 2, 1])
        ids = [m.case_file_id for unit in units for m in unit.members]
        self.assertEqual(sorted(ids), list(range(8)))
        self.assertNotIn(0, [m.case_file_id for unit in units[1:] for m in unit.members])

    def test_single_file_never_enters_directory_or_eager_split(self):
        from utils.evtx_directory_mode import plan_evtx_parse_units

        members = [EvtxGroupMember(file_path="/x/only.evtx", case_file_id=9, source_host="H", size_bytes=100)]
        units = plan_evtx_parse_units(members, eager_first=True, target_files=8)
        self.assertEqual(len(units), 1)
        self.assertEqual(units[0].mode, "per_file")
        self.assertEqual(units[0].members[0].case_file_id, 9)

    def test_target_bytes_splits_large_files_independently_of_count(self):
        from utils.evtx_directory_mode import plan_evtx_parse_units

        members = [
            EvtxGroupMember(file_path="/x/a.evtx", case_file_id=1, source_host="H", size_bytes=40),
            EvtxGroupMember(file_path="/x/b.evtx", case_file_id=2, source_host="H", size_bytes=40),
            EvtxGroupMember(file_path="/x/c.evtx", case_file_id=3, source_host="H", size_bytes=40),
        ]
        units = plan_evtx_parse_units(
            members,
            eager_first=False,
            target_files=8,
            target_bytes=50,
            max_files=32,
            max_bytes=512,
        )
        self.assertEqual([len(unit.members) for unit in units], [1, 1, 1])
        self.assertTrue(all(unit.mode == "per_file" for unit in units))

    def test_smallest_first_is_measurement_only_and_does_not_duplicate(self):
        from utils.evtx_directory_mode import plan_evtx_parse_units

        members = [
            EvtxGroupMember(file_path="/x/big.evtx", case_file_id=1, source_host="H", size_bytes=500),
            EvtxGroupMember(file_path="/x/small.evtx", case_file_id=2, source_host="H", size_bytes=10),
            EvtxGroupMember(file_path="/x/mid.evtx", case_file_id=3, source_host="H", size_bytes=50),
        ]
        units = plan_evtx_parse_units(members, eager_first=True, target_files=8, order="smallest")
        self.assertEqual(units[0].members[0].case_file_id, 2)
        ids = [m.case_file_id for unit in units for m in unit.members]
        self.assertEqual(sorted(ids), [1, 2, 3])
        queue_units = plan_evtx_parse_units(members, eager_first=True, target_files=8, order="queue")
        self.assertEqual(queue_units[0].members[0].case_file_id, 1)

    def test_group_fill_window_remains_disabled(self):
        from utils.evtx_directory_mode import EVTX_DIRECTORY_GROUP_FILL_WINDOW_SECONDS

        self.assertEqual(EVTX_DIRECTORY_GROUP_FILL_WINDOW_SECONDS, 0)

    def test_hayabusa_directory_command_keeps_current_flags(self):
        cmd = hayabusa_json_timeline_cmd(
            hayabusa_bin="/opt/casescope/bin/hayabusa",
            output_path="/tmp/out.jsonl",
            directory="/tmp/evtx",
            rules_dir="/opt/casescope/rules/hayabusa-rules",
        )
        self.assertEqual(cmd[1], "json-timeline")
        self.assertIn("-d", cmd)
        self.assertNotIn("-f", cmd)
        self.assertIn("-L", cmd)
        self.assertIn("-U", cmd)
        self.assertIn("all-field-info-verbose", cmd)
        self.assertIn("informational", cmd)
        self.assertNotIn("--remove-duplicate-detections", cmd)
        self.assertNotIn("-c", cmd)
        cmd_with_config = hayabusa_json_timeline_cmd(
            hayabusa_bin="/opt/casescope/bin/hayabusa",
            output_path="/tmp/out.jsonl",
            directory="/tmp/evtx",
            rules_dir="/opt/casescope/rules/hayabusa-rules",
            rules_config_dir="/opt/casescope/rules/config",
        )
        self.assertIn("-c", cmd_with_config)
        self.assertIn("/opt/casescope/rules/config", cmd_with_config)

    def test_evtxecmd_directory_command_does_not_dedupe_or_use_fj(self):
        cmd = evtxecmd_json_cmd(
            evtxecmd_bin="/opt/casescope/bin/evtxecmd",
            json_dir="/tmp/json",
            json_name="out.json",
            directory="/tmp/evtx",
            maps_dir="/opt/casescope/bin/EvtxECmd/EvtxeCmd/Maps",
        )
        self.assertIn("-d", cmd)
        self.assertNotIn("-f", cmd)
        self.assertNotIn("--dedupe", cmd)
        self.assertNotIn("--fj", cmd)

    def test_hayabusa_error_log_marker_triggers_fallback(self):
        self.assertTrue(hayabusa_directory_had_errors("Errors were generated. Please check ./logs", ""))
        self.assertFalse(hayabusa_directory_had_errors("Saved file: /tmp/out.jsonl", ""))


class ParserDirectoryModeTestCase(unittest.TestCase):
    def test_transform_uses_source_token_and_does_not_cross_attach(self):
        from parsers.base import BaseParser
        from parsers.evtx_parser import EvtxECmdParser

        parser = object.__new__(EvtxECmdParser)
        BaseParser.__init__(parser, case_id=1, source_host="HOSTA", case_file_id=11, case_tz="UTC")
        detections = index_hayabusa_detections(
            [
                {
                    "EvtxFile": "/tmp/Security.evtx",
                    "RecordID": 100,
                    "RuleTitle": "Security Rule",
                    "Level": "high",
                    "RuleFile": "sec.yml",
                    "MitreTactics": ["Credential Access"],
                    "MitreTags": ["T1110"],
                },
                {
                    "EvtxFile": "/tmp/System.evtx",
                    "RecordID": 100,
                    "RuleTitle": "System Rule",
                    "Level": "low",
                    "RuleFile": "sys.yml",
                },
            ]
        )
        event = {
            "TimeCreated": "2026-03-14T12:00:00Z",
            "EventId": "4624",
            "Channel": "Security",
            "Computer": "HOSTA",
            "EventRecordId": "100",
            "Provider": "Microsoft-Windows-Security-Auditing",
            "Payload": "{}",
        }
        parsed = parser._transform_evtxecmd_event(
            event,
            "/tmp/Security.evtx",
            "Security.evtx",
            detections,
            source_token="/tmp/Security.evtx",
        )
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed.rule_title, "Security Rule")
        extra = json.loads(parsed.extra_fields)
        self.assertEqual(len(extra["hayabusa_detections"]), 1)
        self.assertEqual(extra["hayabusa_detections"][0]["rule_title"], "Security Rule")

    def test_per_file_record_id_lookup_still_works(self):
        from parsers.base import BaseParser
        from parsers.evtx_parser import EvtxECmdParser

        parser = object.__new__(EvtxECmdParser)
        BaseParser.__init__(parser, case_id=1, source_host="HOST1", case_file_id=58, case_tz="UTC")
        parsed = parser._transform_evtxecmd_event(
            {
                "TimeCreated": "2026-03-14T12:00:00Z",
                "EventId": "4624",
                "Channel": "Security",
                "Computer": "HOST1",
                "EventRecordId": "88",
                "Provider": "Microsoft-Windows-Security-Auditing",
                "Payload": "{}",
            },
            "/tmp/Security.evtx",
            "Security.evtx",
            {
                "88": [
                    {
                        "rule_title": "Rule One",
                        "rule_level": "high",
                        "rule_file": "one.yml",
                        "mitre_tactics": ["Credential Access"],
                        "mitre_tags": ["T1110"],
                    }
                ]
            },
        )
        self.assertEqual(parsed.rule_title, "Rule One")


class FallbackBehaviorTestCase(unittest.TestCase):
    def _run_fallback(self, reason: str, message: str, unsafe_retry: bool = False):
        from parsers.base import ParseResult
        from parsers.registry import process_evtx_group

        member_paths = ["/tmp/a.evtx", "/tmp/b.evtx"]
        calls = []

        def fake_process_file(**kwargs):
            calls.append(kwargs["file_path"])
            return ParseResult(
                success=True,
                file_path=kwargs["file_path"],
                artifact_type="evtx",
                events_count=1,
                errors=[],
                warnings=[],
                duration_seconds=0.01,
            )

        class BoomParser:
            errors = []
            warnings = []

            def parse_directory_group(self, members):
                raise DirectoryModeError(reason, message, unsafe_retry=unsafe_retry)
                yield  # pragma: no cover

        class FakeRegistry:
            def get_parser(self, *args, **kwargs):
                return BoomParser()

        with patch("parsers.registry._get_registry", return_value=FakeRegistry()), patch(
            "parsers.registry.process_file", side_effect=fake_process_file
        ):
            results = process_evtx_group(
                [
                    {"file_path": member_paths[0], "case_file_id": 1, "source_host": "A"},
                    {"file_path": member_paths[1], "case_file_id": 2, "source_host": "B"},
                ],
                case_id=1,
                clickhouse_client=object(),
            )
        return calls, results, member_paths

    def test_process_evtx_group_falls_back_to_per_file_on_directory_error(self):
        calls, results, member_paths = self._run_fallback("tool_crash", "hayabusa directory failed")
        self.assertEqual(calls, member_paths)
        self.assertEqual(len(results), 2)
        self.assertTrue(all(r.success for r in results))

    def test_fallback_on_timeout_empty_output_malformed_and_attribution(self):
        for reason, message, unsafe in (
            ("timeout", "Hayabusa directory mode timed out", False),
            ("empty_output", "EvtxECmd directory mode produced no output", False),
            ("malformed_member", "is not an evtx file! Skipping...", False),
            ("evtxecmd_directory_failure", "EvtxECmd directory failed", False),
            ("hayabusa_directory_failure", "Hayabusa directory failed", False),
            ("attribution_ambiguity", "missing EvtxFile", True),
        ):
            with self.subTest(reason=reason):
                calls, results, member_paths = self._run_fallback(reason, message, unsafe)
                self.assertEqual(calls, member_paths)
                self.assertTrue(all(r.success for r in results))

    def test_single_member_uses_per_file_not_directory(self):
        from parsers.base import ParseResult
        from parsers.registry import process_evtx_group

        called = []

        def fake_process_file(**kwargs):
            called.append(kwargs["file_path"])
            return ParseResult(
                success=True,
                file_path=kwargs["file_path"],
                artifact_type="evtx",
                events_count=3,
                errors=[],
                warnings=[],
                duration_seconds=0.01,
            )

        class FakeRegistry:
            def get_parser(self, *args, **kwargs):
                raise AssertionError("directory parser must not be used for a single file")

        with patch("parsers.registry._get_registry", return_value=FakeRegistry()), patch(
            "parsers.registry.process_file", side_effect=fake_process_file
        ):
            results = process_evtx_group(
                [{"file_path": "/tmp/only.evtx", "case_file_id": 9, "source_host": "H"}],
                case_id=1,
                clickhouse_client=object(),
            )
        self.assertEqual(called, ["/tmp/only.evtx"])
        self.assertEqual(results[0].events_count, 3)

    def test_eager_first_fallback_does_not_reprocess_eager_file(self):
        from parsers.base import ParseResult
        from parsers.registry import process_evtx_group
        from utils.evtx_directory_mode import plan_evtx_parse_units

        members = [
            {"file_path": "/tmp/eager.evtx", "case_file_id": 1, "source_host": "A", "size_bytes": 10},
            {"file_path": "/tmp/g1.evtx", "case_file_id": 2, "source_host": "B", "size_bytes": 10},
            {"file_path": "/tmp/g2.evtx", "case_file_id": 3, "source_host": "C", "size_bytes": 10},
        ]
        typed = [
            EvtxGroupMember(
                file_path=item["file_path"],
                case_file_id=item["case_file_id"],
                source_host=item["source_host"],
                size_bytes=item["size_bytes"],
            )
            for item in members
        ]
        units = plan_evtx_parse_units(typed, eager_first=True, target_files=8)
        self.assertEqual(units[0].members[0].file_path, os.path.abspath("/tmp/eager.evtx"))
        directory_members = list(units[1].members)
        self.assertEqual(
            [m.file_path for m in directory_members],
            [os.path.abspath("/tmp/g1.evtx"), os.path.abspath("/tmp/g2.evtx")],
        )

        process_file_calls = []

        def fake_process_file(**kwargs):
            process_file_calls.append(kwargs["file_path"])
            return ParseResult(
                success=True,
                file_path=kwargs["file_path"],
                artifact_type="evtx",
                events_count=1,
                errors=[],
                warnings=[],
                duration_seconds=0.01,
            )

        class BoomParser:
            errors = []
            warnings = []

            def parse_directory_group(self, group_members):
                raise DirectoryModeError("tool_crash", "hayabusa directory failed")
                yield  # pragma: no cover

        class FakeRegistry:
            def get_parser(self, *args, **kwargs):
                return BoomParser()

        with patch("parsers.registry._get_registry", return_value=FakeRegistry()), patch(
            "parsers.registry.process_file", side_effect=fake_process_file
        ):
            results = process_evtx_group(
                [
                    {"file_path": m.file_path, "case_file_id": m.case_file_id, "source_host": m.source_host}
                    for m in directory_members
                ],
                case_id=1,
                clickhouse_client=object(),
            )
        self.assertEqual(
            process_file_calls,
            [os.path.abspath("/tmp/g1.evtx"), os.path.abspath("/tmp/g2.evtx")],
        )
        self.assertNotIn(os.path.abspath("/tmp/eager.evtx"), process_file_calls)
        self.assertEqual(len(results), 2)


if __name__ == "__main__":
    unittest.main()
