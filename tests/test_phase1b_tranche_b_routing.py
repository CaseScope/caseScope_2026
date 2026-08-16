from __future__ import annotations

import os
import tempfile
import unittest
from datetime import datetime
from unittest.mock import patch

os.environ.setdefault("SECRET_KEY", "phase1b-routing-test-secret")

from celery.exceptions import SoftTimeLimitExceeded
from flask import Flask

from models.case import Case
from models.case_file import CaseFile, IngestProtocolOrigin
from models.client import Client
from models.database import db
from models.database_flow import EvidenceSourceGeneration, IngestAttempt, IngestBatch
from models.database_flow import EvidenceGenerationState, IngestBatchState, SourceRefType
from models.graph_saved_view import GraphSavedView  # noqa: F401
from models.investigation_thread import InvestigationThread  # noqa: F401
from parsers.base import BaseParser, ParseResult
from tasks.celery_tasks import parse_file_task
from utils.manifest_protocol import ManifestRoutingError


class _RoutingParser(BaseParser):
    def __init__(self, *args, eligible=False, **kwargs):
        super().__init__(*args, **kwargs)
        self.supports_manifest_protocol = eligible
        self.manifest_ordering_contract = "test:fixture-order:v1" if eligible else None

    @property
    def artifact_type(self):
        return "fixture"

    def can_parse(self, _file_path):
        return True

    def parse(self, _file_path):
        return iter(())


class _Registry:
    def __init__(self, parser):
        self.parser = parser

    def resolve_parser_for_file(self, **_kwargs):
        return "fixture", self.parser

    def detect_type(self, _file_path):
        return "fixture"


class _Client:
    pass


class Phase1BTrancheBRoutingTestCase(unittest.TestCase):
    def setUp(self):
        self.app = Flask(__name__)
        self.app.config.update(
            SQLALCHEMY_DATABASE_URI="sqlite:///:memory:",
            SQLALCHEMY_TRACK_MODIFICATIONS=False,
            SECRET_KEY="phase1b-routing-test",
        )
        db.init_app(self.app)
        self.ctx = self.app.app_context()
        self.ctx.push()
        for table in (
            Client.__table__,
            Case.__table__,
            CaseFile.__table__,
            EvidenceSourceGeneration.__table__,
            IngestAttempt.__table__,
            IngestBatch.__table__,
        ):
            table.create(db.engine, checkfirst=True)
        self.case = Case(uuid="case-routing", name="Routing", company="Example", created_by="tester")
        db.session.add(self.case)
        db.session.flush()
        self.case_file = CaseFile(
            case_uuid=self.case.uuid,
            filename="routing.log",
            original_filename="routing.log",
            file_path="/tmp/routing.log",
            file_size=1,
            sha256_hash="c" * 64,
            uploaded_by="tester",
        )
        db.session.add(self.case_file)
        db.session.commit()
        handle, self.file_path = tempfile.mkstemp(prefix="casescope-routing-", suffix=".log")
        os.close(handle)

    def tearDown(self):
        try:
            os.remove(self.file_path)
        except FileNotFoundError:
            pass
        db.session.remove()
        db.drop_all()
        self.ctx.pop()

    def _run_task(self, *, parser, flag_enabled, managed_side_effect=None, expected_exception=None):
        cleanup_calls = []
        managed_calls = []
        status_calls = []

        def _cleanup(case_file_id):
            cleanup_calls.append(case_file_id)

        def _managed(**kwargs):
            managed_calls.append(kwargs)
            if managed_side_effect:
                raise managed_side_effect
            return ParseResult(
                success=True,
                file_path=self.file_path,
                artifact_type="fixture",
                events_count=2,
                errors=[],
                warnings=[],
                duration_seconds=0,
            )

        def _legacy_process_file(**_kwargs):
            return ParseResult(
                success=True,
                file_path=self.file_path,
                artifact_type="fixture",
                events_count=1,
                errors=[],
                warnings=[],
                duration_seconds=0,
            )

        def _status(**kwargs):
            status_calls.append(kwargs)

        with patch("tasks.celery_tasks.get_flask_app", return_value=self.app), \
             patch("parsers.get_registry", return_value=_Registry(parser)), \
             patch("parsers.process_file", side_effect=_legacy_process_file), \
             patch("utils.clickhouse.get_fresh_client", return_value=_Client()), \
             patch("tasks.celery_tasks._cleanup_case_file_events", side_effect=_cleanup), \
             patch("tasks.celery_tasks._process_managed_initial_case_file", side_effect=_managed), \
             patch("tasks.celery_tasks._update_case_file_status", side_effect=_status), \
             patch("utils.event_mitre_state.delete_hayabusa_matches_for_case_file", return_value=None), \
             patch.object(parse_file_task, "update_state", return_value=None), \
             patch("tasks.celery_tasks.Config.PHASE1B_MANIFEST_PROTOCOL_ENABLED", flag_enabled):
            expected = expected_exception or (managed_side_effect.__class__ if managed_side_effect else None)
            if expected:
                with self.assertRaises(expected):
                    parse_file_task.run(
                        file_path=self.file_path,
                        case_id=self.case.id,
                        source_host="HOST1",
                        case_file_id=self.case_file.id,
                    )
                result = None
            else:
                result = parse_file_task.run(
                    file_path=self.file_path,
                    case_id=self.case.id,
                    source_host="HOST1",
                    case_file_id=self.case_file.id,
                )
        return result, cleanup_calls, managed_calls, status_calls

    def test_flag_off_uses_legacy_before_manifest_engine(self):
        result, cleanup_calls, managed_calls, status_calls = self._run_task(
            parser=_RoutingParser(self.case.id, eligible=True),
            flag_enabled=False,
        )
        self.assertTrue(result["success"])
        self.assertEqual(cleanup_calls, [self.case_file.id])
        self.assertEqual(managed_calls, [])
        self.assertTrue(status_calls[-1]["trigger_completion"])
        db.session.expire_all()
        self.assertEqual(
            db.session.get(CaseFile, self.case_file.id).ingest_protocol_origin,
            IngestProtocolOrigin.LEGACY_OR_UNKNOWN,
        )

    def test_global_on_parser_ineligible_uses_legacy(self):
        result, cleanup_calls, managed_calls, _status_calls = self._run_task(
            parser=_RoutingParser(self.case.id, eligible=False),
            flag_enabled=True,
        )
        self.assertTrue(result["success"])
        self.assertEqual(cleanup_calls, [self.case_file.id])
        self.assertEqual(managed_calls, [])

    def test_global_on_certified_previously_legacy_source_uses_legacy(self):
        self.case_file.ingest_protocol_origin = IngestProtocolOrigin.LEGACY_OR_UNKNOWN
        db.session.commit()
        result, cleanup_calls, managed_calls, _status_calls = self._run_task(
            parser=_RoutingParser(self.case.id, eligible=True),
            flag_enabled=True,
        )
        self.assertTrue(result["success"])
        self.assertEqual(cleanup_calls, [self.case_file.id])
        self.assertEqual(managed_calls, [])

    def test_global_on_eligible_parser_uses_managed_without_legacy_cleanup(self):
        result, cleanup_calls, managed_calls, status_calls = self._run_task(
            parser=_RoutingParser(self.case.id, eligible=True),
            flag_enabled=True,
        )
        self.assertTrue(result["success"])
        self.assertEqual(cleanup_calls, [])
        self.assertEqual(len(managed_calls), 1)
        self.assertFalse(status_calls[-1]["trigger_completion"])

    def test_managed_retry_with_prior_durable_batch_does_not_casefile_cleanup(self):
        parser = _RoutingParser(self.case.id, eligible=True)
        generation = EvidenceSourceGeneration(
            case_id=self.case.id,
            source_ref_type=SourceRefType.CASE_FILE,
            source_ref_id=str(self.case_file.id),
            source_generation=1,
            visibility_state=EvidenceGenerationState.BUILDING_INITIAL,
            parser_version=parser.parser_version,
            normalization_version="test:norm:v1",
            batching_contract_version="ingest-batch:v1",
            configured_batch_size=2,
            ordering_contract=parser.manifest_ordering_contract,
        )
        self.case_file.ingest_protocol_origin = IngestProtocolOrigin.MANIFEST_INITIAL
        db.session.add(generation)
        db.session.flush()
        durable_batch = IngestBatch(
            ingest_batch_id="ingest-batch:v1:" + "a" * 64,
            generation_id=generation.id,
            batch_ordinal=0,
            row_count=2,
            batch_content_hash="b" * 64,
            expected_ingest_row_hashes=["c" * 64, "d" * 64],
            state=IngestBatchState.DURABLE,
        )
        db.session.add(durable_batch)
        db.session.commit()

        result, cleanup_calls, managed_calls, _status_calls = self._run_task(
            parser=parser,
            flag_enabled=False,
        )
        self.assertTrue(result["success"])
        self.assertEqual(cleanup_calls, [])
        self.assertEqual(len(managed_calls), 1)
        self.assertEqual(
            db.session.get(IngestBatch, durable_batch.id).state,
            IngestBatchState.DURABLE,
        )

    def test_existing_building_generation_parser_capability_removed_fails_closed(self):
        parser = _RoutingParser(self.case.id, eligible=True)
        self._create_existing_generation(
            parser_version=parser.parser_version,
            ordering_contract=parser.manifest_ordering_contract,
        )
        _result, cleanup_calls, managed_calls, status_calls = self._run_task(
            parser=_RoutingParser(self.case.id, eligible=False),
            flag_enabled=False,
            expected_exception=ManifestRoutingError,
        )
        self.assertEqual(cleanup_calls, [])
        self.assertEqual(managed_calls, [])
        self.assertFalse(status_calls[-1]["trigger_completion"])

    def test_existing_building_generation_ordering_contract_mismatch_fails_closed(self):
        parser = _RoutingParser(self.case.id, eligible=True)
        self._create_existing_generation(
            parser_version=parser.parser_version,
            ordering_contract="test:old-order:v1",
        )
        _result, cleanup_calls, managed_calls, status_calls = self._run_task(
            parser=parser,
            flag_enabled=True,
            expected_exception=ManifestRoutingError,
        )
        self.assertEqual(cleanup_calls, [])
        self.assertEqual(managed_calls, [])
        self.assertFalse(status_calls[-1]["trigger_completion"])

    def test_existing_building_generation_parser_version_mismatch_fails_closed(self):
        parser = _RoutingParser(self.case.id, eligible=True)
        self._create_existing_generation(
            parser_version="old-parser:v1",
            ordering_contract=parser.manifest_ordering_contract,
        )
        _result, cleanup_calls, managed_calls, status_calls = self._run_task(
            parser=parser,
            flag_enabled=True,
            expected_exception=ManifestRoutingError,
        )
        self.assertEqual(cleanup_calls, [])
        self.assertEqual(managed_calls, [])
        self.assertFalse(status_calls[-1]["trigger_completion"])

    def _create_existing_generation(self, *, parser_version, ordering_contract):
        self.case_file.ingest_protocol_origin = IngestProtocolOrigin.MANIFEST_INITIAL
        db.session.add(EvidenceSourceGeneration(
            case_id=self.case.id,
            source_ref_type=SourceRefType.CASE_FILE,
            source_ref_id=str(self.case_file.id),
            source_generation=1,
            visibility_state=EvidenceGenerationState.BUILDING_INITIAL,
            parser_version=parser_version,
            normalization_version="test:norm:v1",
            batching_contract_version="ingest-batch:v1",
            configured_batch_size=2,
            ordering_contract=ordering_contract,
        ))
        db.session.commit()

    def test_managed_exception_does_not_casefile_cleanup(self):
        _result, cleanup_calls, managed_calls, status_calls = self._run_task(
            parser=_RoutingParser(self.case.id, eligible=True),
            flag_enabled=True,
            managed_side_effect=RuntimeError("managed failed"),
        )
        self.assertEqual(cleanup_calls, [])
        self.assertEqual(len(managed_calls), 1)
        self.assertFalse(status_calls[-1]["trigger_completion"])

    def test_managed_soft_timeout_does_not_casefile_cleanup(self):
        _result, cleanup_calls, managed_calls, status_calls = self._run_task(
            parser=_RoutingParser(self.case.id, eligible=True),
            flag_enabled=True,
            managed_side_effect=SoftTimeLimitExceeded(),
        )
        self.assertEqual(cleanup_calls, [])
        self.assertEqual(len(managed_calls), 1)
        self.assertFalse(status_calls[-1]["trigger_completion"])


if __name__ == "__main__":
    unittest.main()
