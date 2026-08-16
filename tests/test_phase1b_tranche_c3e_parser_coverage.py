from __future__ import annotations

import json
import os
import unittest
from pathlib import Path
from types import SimpleNamespace

os.environ.setdefault("SECRET_KEY", "phase1b-c3e-test-secret")

from models.database_flow import EvidenceGenerationState
from parsers.base import BaseParser
from parsers.registry import ParserRegistry
from utils.manifest_protocol import (
    FrozenGenerationMismatch,
    INGEST_MODE_LEGACY,
    INGEST_MODE_MANAGED_INITIAL,
    ManifestParserContract,
    ManifestRoutingError,
    _assert_frozen_contract_matches,
    select_case_file_ingest_mode,
)

COVERAGE_PATH = Path("docs/database_flow_phase1b/phase1b_tranche_c3e_parser_coverage.json")
ALLOWED_CLASSIFICATIONS = {"CERTIFIED_MANAGED", "DEFERRED_LEGACY_ONLY", "NOT_APPLICABLE"}


class _Config:
    PHASE1B_MANIFEST_PROTOCOL_ENABLED = True


class _Session:
    def __init__(self, generations):
        self._generations = generations

    def query(self, *_args, **_kwargs):
        return self

    def filter(self, *_args, **_kwargs):
        return self

    def order_by(self, *_args, **_kwargs):
        return self

    def all(self):
        return list(self._generations)


class _FutureParser(BaseParser):
    @property
    def artifact_type(self):
        return "future"

    def can_parse(self, _file_path):
        return True

    def parse(self, _file_path):
        return iter(())


class Phase1BTrancheC3EParserCoverageTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.registry = ParserRegistry()
        cls.coverage_entries = json.loads(COVERAGE_PATH.read_text())
        cls.coverage_by_name = {entry["registration_name"]: entry for entry in cls.coverage_entries}

    def test_coverage_manifest_matches_live_case_file_registry(self):
        live = self.registry._parsers
        self.assertEqual(set(self.coverage_by_name), set(live))
        self.assertEqual(len(self.coverage_by_name), len(self.coverage_entries))

        for name, mapping in live.items():
            entry = self.coverage_by_name[name]
            parser_cls = mapping.parser_class
            supports = bool(getattr(parser_cls, "supports_manifest_protocol", False))
            contract = getattr(parser_cls, "manifest_ordering_contract", None)
            self.assertIn(entry["classification"], ALLOWED_CLASSIFICATIONS, name)
            self.assertEqual(entry["class"], parser_cls.__name__, name)
            self.assertEqual(entry["module"], parser_cls.__module__, name)
            self.assertEqual(entry["parser_version"], f"{parser_cls.__name__}-{getattr(parser_cls, 'VERSION', '')}", name)
            self.assertEqual(entry["supports_manifest_protocol"], supports, name)
            self.assertEqual(entry["manifest_ordering_contract"], contract, name)

            if entry["classification"] == "CERTIFIED_MANAGED":
                self.assertTrue(supports, name)
                self.assertIsInstance(contract, str, name)
                self.assertRegex(contract, r":v\d+$", name)
                self.assertTrue(entry["certification_document"], name)
                self.assertTrue(Path(entry["certification_document"]).exists(), name)
            elif entry["classification"] == "DEFERRED_LEGACY_ONLY":
                self.assertFalse(supports, name)
                self.assertIsNone(contract, name)
                self.assertTrue(entry["deferred_reason"], name)
                self.assertTrue(entry["minimum_future_evidence"], name)
            else:
                self.fail(f"Unexpected NOT_APPLICABLE registry entry: {name}")

    def test_future_parser_defaults_to_manifest_deny_by_default(self):
        parser = _FutureParser(case_id=1)
        self.assertFalse(parser.supports_manifest_protocol)
        self.assertIsNone(parser.manifest_ordering_contract)
        mode = select_case_file_ingest_mode(
            parser=parser,
            case_file=SimpleNamespace(id=1, ingest_protocol_origin="not_started"),
            config=_Config,
        )
        self.assertEqual(mode, INGEST_MODE_LEGACY)

    def test_all_registered_parser_routing_matrix_for_new_sources(self):
        case_file = SimpleNamespace(id=1, ingest_protocol_origin="not_started")
        for name, entry in sorted(self.coverage_by_name.items()):
            parser = self.registry.get_parser(name, case_id=1, source_host="C3EHOST", case_file_id=1, case_tz="UTC")
            self.assertIsNotNone(parser, name)
            mode = select_case_file_ingest_mode(parser=parser, case_file=case_file, config=_Config)
            if entry["classification"] == "CERTIFIED_MANAGED":
                self.assertEqual(mode, INGEST_MODE_MANAGED_INITIAL, name)
            else:
                self.assertEqual(mode, INGEST_MODE_LEGACY, name)

    def test_legacy_or_unknown_cannot_newly_adopt_managed(self):
        for name, entry in sorted(self.coverage_by_name.items()):
            if entry["classification"] != "CERTIFIED_MANAGED":
                continue
            parser = self.registry.get_parser(name, case_id=1, source_host="C3EHOST", case_file_id=1, case_tz="UTC")
            case_file = SimpleNamespace(id=1, ingest_protocol_origin="legacy_or_unknown")
            mode = select_case_file_ingest_mode(parser=parser, case_file=case_file, config=_Config)
            self.assertEqual(mode, INGEST_MODE_LEGACY, name)

    def test_existing_building_initial_retry_is_pinned_and_fails_closed(self):
        parser = self.registry.get_parser("iis", case_id=7, source_host="C3EHOST", case_file_id=42, case_tz="UTC")
        generation = SimpleNamespace(
            visibility_state=EvidenceGenerationState.BUILDING_INITIAL,
            ordering_contract=parser.manifest_ordering_contract,
            parser_version=parser.parser_version,
        )
        case_file = SimpleNamespace(id=42, case_id=7, ingest_protocol_origin="manifest_initial")
        flag_off = SimpleNamespace(PHASE1B_MANIFEST_PROTOCOL_ENABLED=False)

        mode = select_case_file_ingest_mode(
            parser=parser,
            case_file=case_file,
            config=flag_off,
            session=_Session([generation]),
        )
        self.assertEqual(mode, INGEST_MODE_MANAGED_INITIAL)

        parser_without_capability = SimpleNamespace(
            supports_manifest_protocol=False,
            manifest_ordering_contract=None,
            parser_version=parser.parser_version,
        )
        with self.assertRaises(ManifestRoutingError):
            select_case_file_ingest_mode(
                parser=parser_without_capability,
                case_file=case_file,
                config=flag_off,
                session=_Session([generation]),
            )

        parser_new_order = SimpleNamespace(
            supports_manifest_protocol=True,
            manifest_ordering_contract="iis:w3c-data-line-order:v2",
            parser_version=parser.parser_version,
        )
        with self.assertRaises(ManifestRoutingError):
            select_case_file_ingest_mode(
                parser=parser_new_order,
                case_file=case_file,
                config=_Config,
                session=_Session([generation]),
            )

        parser_new_version = SimpleNamespace(
            supports_manifest_protocol=True,
            manifest_ordering_contract=parser.manifest_ordering_contract,
            parser_version="IISLogParser-9.9.9",
        )
        with self.assertRaises(ManifestRoutingError):
            select_case_file_ingest_mode(
                parser=parser_new_version,
                case_file=case_file,
                config=_Config,
                session=_Session([generation]),
            )

    def test_frozen_generation_contract_mismatch_fails_closed(self):
        frozen = SimpleNamespace(
            parser_version="IISLogParser-1.0.0",
            normalization_version="phase1b-normalization:v1",
            batching_contract_version="ingest-batch:v1",
            configured_batch_size=3,
            ordering_contract="iis:w3c-data-line-order:v1",
            producer_version="iis-producer:v1",
        )
        matching = ManifestParserContract(
            parser_version="IISLogParser-1.0.0",
            normalization_version="phase1b-normalization:v1",
            configured_batch_size=3,
            ordering_contract="iis:w3c-data-line-order:v1",
            producer_version="iis-producer:v1",
            manifest_eligible=True,
        )
        _assert_frozen_contract_matches(frozen, matching)

        for override in (
            {"configured_batch_size": 4},
            {"normalization_version": "phase1b-normalization:v2"},
            {"producer_version": "iis-producer:v2"},
        ):
            values = matching.__dict__.copy()
            values.update(override)
            with self.assertRaises(FrozenGenerationMismatch):
                _assert_frozen_contract_matches(frozen, ManifestParserContract(**values))


if __name__ == "__main__":
    unittest.main()
