import json
import os
import tempfile
import unittest
from datetime import datetime, timedelta
from unittest.mock import patch

from flask import Flask

from config import Config
from parsers.base import BaseParser
from parsers.base import ParsedEvent
from parsers.evtx_parser import EvtxECmdParser, EvtxFallbackParser
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
    IngestBatchState,
)
from models.graph_saved_view import GraphSavedView  # noqa: F401
from models.investigation_thread import InvestigationThread  # noqa: F401
from utils.evtx_directory_mode import DirectoryModeError
from utils.evtx_producer_signature import compact_evtx_producer_signature

_MODEL_REGISTRATION_SENTINELS = (GraphSavedView, InvestigationThread)


class _QueryResult:
    def __init__(self, rows):
        self.result_rows = rows


class _ManagedEvtxFakeClickHouse:
    def __init__(self):
        self.tables = {
            'events': [],
            'visible_evidence_generations': [],
            'durable_ingest_batches': [],
        }
        self.delete_calls = []

    def insert(self, table, rows, column_names=None):
        names = list(column_names or [])
        for row in rows:
            self.tables.setdefault(table, []).append(dict(zip(names, row)) if names else tuple(row))

    def query(self, sql, parameters=None):
        if 'WHERE ingest_batch_id = {id:String}' in sql:
            ingest_batch_id = parameters['id']
            grouped = {}
            for row in self.tables['events']:
                if row['ingest_batch_id'] != ingest_batch_id:
                    continue
                key = (row['ingest_row_ordinal'], row['ingest_row_hash'])
                grouped.setdefault(key, 0)
                grouped[key] += 1
            return _QueryResult([
                (ordinal, row_hash, copies, 1)
                for (ordinal, row_hash), copies in sorted(grouped.items())
            ])
        if 'countDistinct(case_file_id)' in sql:
            rows = []
            by_batch = {}
            for row in self.tables['events']:
                by_batch.setdefault(row['ingest_batch_id'], set()).add(row['case_file_id'])
            for batch_id, case_file_ids in sorted(by_batch.items()):
                rows.append((batch_id, len(case_file_ids)))
            return _QueryResult(rows)
        return _QueryResult([])


class _ManagedEvtxFakeParser(BaseParser):
    VERSION = '1.0.0'
    ARTIFACT_TYPE = 'evtx'
    supports_manifest_protocol = True
    manifest_ordering_contract = 'evtx:fixture-source-order:v1'
    file_events = {}
    fail_directory_after_events = None

    @property
    def artifact_type(self):
        return self.ARTIFACT_TYPE

    def can_parse(self, file_path):
        return True

    def manifest_producer_version(self):
        return 'evtx-test-producer:v1'

    def _event(self, file_path, record_id, case_file_id=None, source_host=None):
        resolved_source_host = source_host if source_host is not None else self.source_host
        return ParsedEvent(
            case_id=self.case_id,
            artifact_type='evtx',
            timestamp=datetime(2026, 1, 1) + timedelta(seconds=record_id),
            timestamp_utc=datetime(2026, 1, 1) + timedelta(seconds=record_id),
            timestamp_source_tz='UTC',
            source_file=os.path.basename(file_path),
            source_path=file_path,
            source_host=resolved_source_host,
            case_file_id=case_file_id if case_file_id is not None else self.case_file_id,
            event_id=str(record_id),
            record_id=record_id,
            raw_json=json.dumps({'record_id': record_id}, sort_keys=True),
            search_blob=f'record {record_id}',
            parser_version=self.parser_version,
            native_record_id_authoritative=True,
        )

    def parse(self, file_path):
        for record_id in self.file_events.get(os.path.basename(file_path), []):
            yield self._event(file_path, record_id)

    def parse_directory_group(self, members):
        emitted = 0
        for member in members:
            for record_id in self.file_events.get(os.path.basename(member.file_path), []):
                emitted += 1
                yield self._event(
                    member.file_path,
                    record_id,
                    case_file_id=member.case_file_id,
                    source_host=member.source_host,
                )
                if self.fail_directory_after_events and emitted >= self.fail_directory_after_events:
                    raise DirectoryModeError('fixture_directory_failure', 'fixture failure after durable batch')


class Phase1BTrancheC2EvtxSafetyTestCase(unittest.TestCase):
    def _evtx_parser(self):
        parser = object.__new__(EvtxECmdParser)
        BaseParser.__init__(parser, case_id=1, source_host='HOST1', case_file_id=58, case_tz='UTC')
        parser._evtx_payload_decode_ms = 0.0
        parser._evtx_normalization_ms = 0.0
        parser._evtx_search_blob_ms = 0.0
        return parser

    def _sample_evtxecmd_row(self):
        return {
            'TimeCreated': '2026-03-14T12:00:00Z',
            'EventId': '4624',
            'Channel': 'Security',
            'Computer': 'HOST1',
            'EventRecordId': '88',
            'Provider': 'Microsoft-Windows-Security-Auditing',
            'Payload': json.dumps({
                'EventData': {
                    'Data': [
                        {'@Name': 'TargetUserName', '#text': 'alice'},
                        {'@Name': 'IpAddress', '#text': '10.0.0.10'},
                        {'@Name': 'LogonType', '#text': '3'},
                    ]
                }
            }),
        }

    def test_evtx_detection_ties_are_canonicalized(self):
        parser = self._evtx_parser()
        detections_a = {
            '88': [
                {
                    'rule_title': 'Zulu Rule',
                    'rule_level': 'high',
                    'rule_file': 'z.yml',
                    'mitre_tactics': ['Lateral Movement'],
                    'mitre_tags': ['T1021'],
                },
                {
                    'rule_title': 'Alpha Rule',
                    'rule_level': 'high',
                    'rule_file': 'a.yml',
                    'mitre_tactics': ['Credential Access'],
                    'mitre_tags': ['T1110'],
                },
            ]
        }
        detections_b = {'88': list(reversed(detections_a['88']))}

        event_a = parser._transform_evtxecmd_event(
            self._sample_evtxecmd_row(), '/tmp/Security.evtx', 'Security.evtx', detections_a
        )
        event_b = parser._transform_evtxecmd_event(
            self._sample_evtxecmd_row(), '/tmp/Security.evtx', 'Security.evtx', detections_b
        )

        self.assertEqual(event_a.rule_title, 'Alpha Rule')
        self.assertEqual(event_a.rule_title, event_b.rule_title)
        self.assertEqual(event_a.rule_file, event_b.rule_file)
        self.assertEqual(event_a.mitre_tactics, event_b.mitre_tactics)
        self.assertEqual(event_a.mitre_tags, event_b.mitre_tags)
        self.assertEqual(event_a.search_blob, event_b.search_blob)
        self.assertEqual(json.loads(event_a.raw_json), json.loads(event_b.raw_json))

    def test_evtx_search_blob_and_raw_json_are_key_order_stable(self):
        parser = self._evtx_parser()
        event_a = self._sample_evtxecmd_row()
        event_b = dict(reversed(list(event_a.items())))

        parsed_a = parser._transform_evtxecmd_event(event_a, '/tmp/Security.evtx', 'Security.evtx', {})
        parsed_b = parser._transform_evtxecmd_event(event_b, '/tmp/Security.evtx', 'Security.evtx', {})

        self.assertEqual(parsed_a.search_blob, parsed_b.search_blob)
        self.assertEqual(parsed_a.raw_json, parsed_b.raw_json)

    def test_managed_evtx_hayabusa_failure_is_fatal(self):
        parser = self._evtx_parser()
        parser.enrich_detections = True
        parser.managed_manifest_mode = True

        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = os.path.join(tmpdir, 'events.json')
            with open(output_path, 'w', encoding='utf-8') as handle:
                handle.write(json.dumps(self._sample_evtxecmd_row()) + '\n')

            with patch.object(parser, '_run_evtxecmd_to_file', return_value=(output_path, tmpdir)), \
                 patch.object(parser, '_get_hayabusa_detections', side_effect=RuntimeError('hayabusa failed')):
                with self.assertRaisesRegex(RuntimeError, 'Managed EVTX Hayabusa enrichment failed'):
                    list(parser._parse_parallel('/tmp/Security.evtx', 'Security.evtx'))

    def test_evtx_producer_signature_is_content_based(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            maps = os.path.join(tmpdir, 'maps')
            rules = os.path.join(tmpdir, 'rules')
            config = os.path.join(tmpdir, 'config')
            os.makedirs(maps)
            os.makedirs(rules)
            os.makedirs(config)
            evtxecmd = os.path.join(tmpdir, 'evtxecmd')
            hayabusa = os.path.join(tmpdir, 'hayabusa')
            for path, body in (
                (evtxecmd, '#!/bin/sh\necho evtx-version\n'),
                (hayabusa, '#!/bin/sh\necho hayabusa-version\n'),
                (os.path.join(maps, 'a.map'), 'map-a\n'),
                (os.path.join(rules, 'r.yml'), 'rule-a\n'),
                (os.path.join(config, 'c.txt'), 'config-a\n'),
            ):
                with open(path, 'w', encoding='utf-8') as handle:
                    handle.write(body)
            os.chmod(evtxecmd, 0o755)
            os.chmod(hayabusa, 0o755)

            first = compact_evtx_producer_signature(
                evtxecmd_bin=evtxecmd,
                maps_dir=maps,
                hayabusa_bin=hayabusa,
                rules_dir=rules,
                rules_config_dir=config,
                hayabusa_profile='all-field-info-verbose',
                min_level='informational',
                enrich_detections=True,
                wrapper_version='EvtxECmdParser-2.2.3',
            )
            os.utime(os.path.join(rules, 'r.yml'), None)
            second = compact_evtx_producer_signature(
                evtxecmd_bin=evtxecmd,
                maps_dir=maps,
                hayabusa_bin=hayabusa,
                rules_dir=rules,
                rules_config_dir=config,
                hayabusa_profile='all-field-info-verbose',
                min_level='informational',
                enrich_detections=True,
                wrapper_version='EvtxECmdParser-2.2.3',
            )
            self.assertEqual(first, second)
            with open(os.path.join(rules, 'r.yml'), 'a', encoding='utf-8') as handle:
                handle.write('changed\n')
            third = compact_evtx_producer_signature(
                evtxecmd_bin=evtxecmd,
                maps_dir=maps,
                hayabusa_bin=hayabusa,
                rules_dir=rules,
                rules_config_dir=config,
                hayabusa_profile='all-field-info-verbose',
                min_level='informational',
                enrich_detections=True,
                wrapper_version='EvtxECmdParser-2.2.3',
            )
            self.assertNotEqual(first, third)

    def test_evtxecmd_manifest_capability_is_enabled_after_certification(self):
        self.assertTrue(EvtxECmdParser.supports_manifest_protocol)
        self.assertEqual(
            EvtxECmdParser.manifest_ordering_contract,
            'evtx:evtxecmd-source-file-json-order:v1',
        )
        self.assertFalse(EvtxFallbackParser.supports_manifest_protocol)
        self.assertIsNone(EvtxFallbackParser.manifest_ordering_contract)


class Phase1BTrancheC2ManagedDirectoryTestCase(unittest.TestCase):
    def setUp(self):
        self._old_flag = Config.PHASE1B_MANIFEST_PROTOCOL_ENABLED
        self._old_batch_size = getattr(Config, 'PHASE1B_MANIFEST_BATCH_SIZE', None)
        Config.PHASE1B_MANIFEST_PROTOCOL_ENABLED = True
        Config.PHASE1B_MANIFEST_BATCH_SIZE = 2
        self.app = Flask(__name__)
        self.app.config.update(
            SQLALCHEMY_DATABASE_URI='sqlite:///:memory:',
            SQLALCHEMY_TRACK_MODIFICATIONS=False,
            SECRET_KEY='phase1b-c2-managed-directory',
        )
        db.init_app(self.app)
        self.ctx = self.app.app_context()
        self.ctx.push()
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
        self.client = Client(name='C2', code='C2', created_by='tester')
        self.case = Case(uuid='c2-case', name='C2 Case', company='Example', client=self.client, created_by='tester')
        db.session.add_all([self.client, self.case])
        db.session.commit()
        self.files = [
            self._case_file('A.evtx'),
            self._case_file('B.evtx'),
        ]
        self.members = [
            {'file_path': f'/tmp/{case_file.filename}', 'case_file_id': case_file.id, 'source_host': case_file.filename[0]}
            for case_file in self.files
        ]
        _ManagedEvtxFakeParser.file_events = {
            'A.evtx': [1, 2, 3],
            'B.evtx': [10, 11],
        }
        _ManagedEvtxFakeParser.fail_directory_after_events = None
        self.get_app_patch = patch('tasks.celery_tasks.get_flask_app', return_value=self.app)
        self.get_app_patch.start()

    def tearDown(self):
        self.get_app_patch.stop()
        db.session.remove()
        db.drop_all()
        self.ctx.pop()
        Config.PHASE1B_MANIFEST_PROTOCOL_ENABLED = self._old_flag
        if self._old_batch_size is None:
            try:
                delattr(Config, 'PHASE1B_MANIFEST_BATCH_SIZE')
            except AttributeError:
                pass
        else:
            Config.PHASE1B_MANIFEST_BATCH_SIZE = self._old_batch_size

    def _case_file(self, filename):
        case_file = CaseFile(
            case_uuid=self.case.uuid,
            filename=filename,
            original_filename=filename,
            file_path=f'/tmp/{filename}',
            file_size=1,
            sha256_hash=(filename[0].lower() * 64),
            uploaded_by='tester',
            ingest_protocol_origin=IngestProtocolOrigin.NOT_STARTED,
        )
        db.session.add(case_file)
        db.session.commit()
        return case_file

    def test_managed_directory_batches_are_per_case_file(self):
        from tasks.celery_tasks import _process_managed_evtx_directory_group

        clickhouse = _ManagedEvtxFakeClickHouse()
        parser = _ManagedEvtxFakeParser(case_id=self.case.id, case_tz='UTC')

        results = _process_managed_evtx_directory_group(
            parser=parser,
            members=self.members,
            case_id=self.case.id,
            clickhouse_client=clickhouse,
            case_tz='UTC',
            task_id='c2-directory-success',
        )

        self.assertEqual([result.events_count for result in results], [3, 2])
        generations = db.session.query(EvidenceSourceGeneration).order_by(EvidenceSourceGeneration.source_ref_id).all()
        self.assertEqual(len(generations), 2)
        self.assertTrue(all(g.visibility_state == EvidenceGenerationState.ACTIVE for g in generations))
        batches = db.session.query(IngestBatch).order_by(IngestBatch.ingest_batch_id).all()
        self.assertEqual(len(batches), 3)
        self.assertTrue(all(batch.state == IngestBatchState.DURABLE for batch in batches))
        self.assertEqual(
            clickhouse.query('SELECT ingest_batch_id, countDistinct(case_file_id) FROM events GROUP BY ingest_batch_id').result_rows,
            [(batch.ingest_batch_id, 1) for batch in batches],
        )
        self.assertTrue(all(attempt.status == 'SUCCEEDED' for attempt in db.session.query(IngestAttempt).all()))

    def test_directory_failure_recovers_per_file_without_broad_cleanup(self):
        from tasks.celery_tasks import _process_managed_evtx_directory_group

        clickhouse = _ManagedEvtxFakeClickHouse()
        parser = _ManagedEvtxFakeParser(case_id=self.case.id, case_tz='UTC')
        parser.fail_directory_after_events = 2

        with patch('utils.clickhouse.delete_file_events', side_effect=AssertionError('managed recovery must not broad delete')):
            results = _process_managed_evtx_directory_group(
                parser=parser,
                members=self.members,
                case_id=self.case.id,
                clickhouse_client=clickhouse,
                case_tz='UTC',
                task_id='c2-directory-recovery',
            )

        self.assertEqual([result.events_count for result in results], [3, 2])
        attempts = db.session.query(IngestAttempt).order_by(IngestAttempt.id).all()
        self.assertEqual([attempt.status for attempt in attempts].count('FAILED'), 2)
        self.assertEqual([attempt.status for attempt in attempts].count('SUCCEEDED'), 2)
        generations = db.session.query(EvidenceSourceGeneration).all()
        self.assertEqual(len(generations), 2)
        self.assertTrue(all(g.visibility_state == EvidenceGenerationState.ACTIVE for g in generations))
        batches = db.session.query(IngestBatch).all()
        self.assertEqual(len(batches), 3)
        self.assertTrue(all(batch.state == IngestBatchState.DURABLE for batch in batches))


if __name__ == '__main__':
    unittest.main()
