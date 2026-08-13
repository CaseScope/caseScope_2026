import json
import unittest
from datetime import datetime

from utils.graph_extractors import GRAPH_ELIGIBLE_EVENT_PREDICATE, HostOwnsIpExtractor, extract_event_relationships
from utils.graph_identity import GraphRelationshipType


EVIDENCE_KEY = 'erk:v2:' + ('a' * 64)


def event(**overrides):
    data = {
        'case_id': 7,
        'artifact_type': 'evtx',
        'timestamp_utc': datetime(2026, 1, 1, 12, 0, 0),
        'source_host': 'WKS-1',
        'case_file_id': 99,
        'source_file': 'Security.evtx',
        'source_path': '/evidence/Security.evtx',
        'event_id': '4688',
        'channel': 'Security',
        'provider': 'Microsoft-Windows-Security-Auditing',
        'username': 'jsmith',
        'domain': 'CONTOSO',
        'sid': 'S-1-5-21-1-2-3-1001',
        'logon_id': '',
        'process_name': 'cmd.exe',
        'process_path': r'C:\Windows\System32\cmd.exe',
        'process_id': 4242,
        'parent_pid': 100,
        'dst_ip': None,
        'src_ip': None,
        'extra_fields': '{}',
        'evidence_record_key': EVIDENCE_KEY,
    }
    data.update(overrides)
    return data


class GraphExtractorTestCase(unittest.TestCase):
    def test_process_runs_image_from_process_creation(self):
        candidates = extract_event_relationships(event())

        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0].relationship_type, GraphRelationshipType.RUNS_IMAGE)
        self.assertEqual(candidates[0].evidence_record_key, EVIDENCE_KEY)

    def test_same_pid_alone_does_not_create_spawned(self):
        candidates = extract_event_relationships(event(parent_pid=4242))

        self.assertTrue(candidates)
        self.assertNotIn(GraphRelationshipType.__dict__.get('SPAWNED', 'SPAWNED'), [c.relationship_type for c in candidates])

    def test_connected_to_is_disabled_until_process_execution_can_be_resolved(self):
        candidates = extract_event_relationships(event(event_id='3', channel='Microsoft-Windows-Sysmon/Operational', dst_ip='93.184.216.34'))

        self.assertEqual(candidates, [])

    def test_network_src_ip_does_not_create_host_owns_ip(self):
        candidates = extract_event_relationships(event(event_id='3', channel='Microsoft-Windows-Sysmon/Operational', src_ip='10.0.0.5', dst_ip='93.184.216.34'))
        relationship_types = [candidate.relationship_type for candidate in candidates]

        self.assertNotIn(GraphRelationshipType.OWNS_IP, relationship_types)

    def test_explicit_host_ip_creates_host_owns_ip(self):
        candidates = extract_event_relationships(event(extra_fields=json.dumps({'host_ip': '10.0.0.5'})))
        relationship_types = [candidate.relationship_type for candidate in candidates]

        self.assertIn(GraphRelationshipType.OWNS_IP, relationship_types)

    def test_host_ip_requires_non_empty_parsed_value(self):
        extractor = HostOwnsIpExtractor()
        for extra_fields in (
            {},
            {'host_ip': ''},
            {'host_ip': None},
            {'host_ip': []},
            {'host_ip': ['', None]},
        ):
            self.assertFalse(extractor.supports(event(extra_fields=json.dumps(extra_fields))))

        self.assertTrue(extractor.supports(event(extra_fields=json.dumps({'host_ip': '10.1.2.3'}))))
        self.assertTrue(extractor.supports(event(extra_fields=json.dumps({'host_ip': ['', '10.1.2.3']}))))

    def test_host_ip_sql_prefilter_uses_json_non_empty_semantics(self):
        self.assertIn("JSONExtractString(extra_fields, 'host_ip') != ''", GRAPH_ELIGIBLE_EVENT_PREDICATE)
        self.assertIn("JSONExtractArrayRaw(extra_fields, 'host_ip')", GRAPH_ELIGIBLE_EVENT_PREDICATE)
        self.assertNotIn("positionCaseInsensitive(extra_fields, 'host_ip')", GRAPH_ELIGIBLE_EVENT_PREDICATE)

    def test_same_file_path_without_hash_does_not_create_had_content(self):
        candidates = extract_event_relationships(event(target_path=r'C:\Temp\a.exe', process_path='', event_id='11', channel='Microsoft-Windows-Sysmon/Operational'))
        relationship_types = [candidate.relationship_type for candidate in candidates]

        self.assertNotIn(GraphRelationshipType.HAD_CONTENT, relationship_types)

    def test_path_and_hash_same_record_create_had_content(self):
        candidates = extract_event_relationships(
            event(
                target_path=r'C:\Temp\a.exe',
                file_hash_sha256='b' * 64,
                event_id='11',
                channel='Microsoft-Windows-Sysmon/Operational',
            )
        )
        relationship_types = [candidate.relationship_type for candidate in candidates]

        self.assertIn(GraphRelationshipType.HAD_CONTENT, relationship_types)

    def test_logon_relationships_require_scoped_user_identity(self):
        candidates = extract_event_relationships(
            event(
                event_id='4624',
                channel='Security',
                process_path='',
                process_id=None,
                logon_id='0x3e7',
                sid='',
                username='Administrator',
                domain='HOSTA',
            )
        )
        relationship_types = sorted(candidate.relationship_type for candidate in candidates)

        self.assertEqual(
            relationship_types,
            sorted([GraphRelationshipType.LOGGED_ON_TO, GraphRelationshipType.LOGON_AS, GraphRelationshipType.ON_HOST]),
        )

    def test_failed_logon_does_not_create_successful_logon_edges(self):
        candidates = extract_event_relationships(
            event(
                event_id='4625',
                channel='Security',
                process_path='',
                process_id=None,
                logon_id='0x3e7',
            )
        )

        self.assertEqual(candidates, [])

    def test_explicit_credential_attempt_does_not_create_session_edges(self):
        candidates = extract_event_relationships(
            event(
                event_id='4648',
                channel='Security',
                process_path='',
                process_id=None,
                logon_id='0x3e7',
            )
        )

        self.assertEqual(candidates, [])

    def test_temporal_proximity_does_not_create_relationships(self):
        first = event(event_id='3', channel='Microsoft-Windows-Sysmon/Operational', process_id=None, dst_ip='93.184.216.34')
        second = event(event_id='4688', process_id=9999, process_path='')

        self.assertEqual(extract_event_relationships(first), [])
        self.assertEqual(extract_event_relationships(second), [])

    def test_ai_ioc_and_mitre_metadata_do_not_author_edges(self):
        candidates = extract_event_relationships(
            event(
                event_id='9999',
                process_path='',
                process_id=None,
                model_summary='looks related',
                mitre_attack_ids=['T1059'],
                ioc_types=['IP Address'],
            )
        )

        self.assertEqual(candidates, [])


if __name__ == '__main__':
    unittest.main()
