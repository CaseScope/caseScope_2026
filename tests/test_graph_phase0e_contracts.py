"""Phase 0E UI contract + IOC provenance + memory/network extractor contracts."""
import inspect
import unittest
from unittest.mock import patch

from utils.graph_extractors import ProcessConnectedToIpExtractor
from utils.graph_identity import GraphRelationshipType
from utils.graph_memory_extractors import (
    MemoryConnectedToIpExtractor,
    MemoryHasSecurityContextExtractor,
    MemoryLoadedModuleExtractor,
    MemoryServiceRunsProcessExtractor,
)
from utils.graph_network_extractors import DomainResolvedToIpExtractor
from utils.graph_support_locator import (
    SOURCE_TYPE_ZEEK_DNS,
    build_memory_locator,
    build_zeek_dns_locator,
    is_evidence_record_key,
    is_native_support_key,
    support_key_for_locator,
)
from utils.ioc_match_provenance import DEFAULT_MATCHED_FIELD


class Phase0EUIContractTestCase(unittest.TestCase):
    def test_shared_pivot_helper_exists(self):
        with open('/opt/casescope/static/js/graph_pivot.js', encoding='utf-8') as handle:
            source = handle.read()
        self.assertIn('function openGraphPivot', source)
        self.assertIn('createElement', source)
        self.assertNotIn('innerHTML =', source)

    def test_hunt_artifacts_pivot_control(self):
        with open('/opt/casescope/static/templates/case_hunting.html', encoding='utf-8') as handle:
            source = handle.read()
        self.assertIn('Open in Relationship Graph', source)
        self.assertIn("openGraphPivot(caseUuid, 'evidence'", source)

    def test_process_hunting_pivot_control(self):
        with open('/opt/casescope/static/templates/case_hunting_processes.html', encoding='utf-8') as handle:
            source = handle.read()
        self.assertIn('Open in Relationship Graph', source)
        self.assertIn('process_hunt', source)
        self.assertIn('memory_process', source)

    def test_memory_hunting_pivot_controls(self):
        with open('/opt/casescope/static/templates/case_hunting_memory.html', encoding='utf-8') as handle:
            source = handle.read()
        self.assertIn("openGraphPivot(caseUuid, 'memory_process'", source)
        self.assertIn("openGraphPivot(caseUuid, 'memory_network'", source)
        self.assertIn("openGraphPivot(caseUuid, 'memory_service'", source)

    def test_network_ioc_known_finding_pivots(self):
        files = {
            '/opt/casescope/static/templates/case_hunting_network.html': ('network_ip', 'network_domain'),
            '/opt/casescope/static/templates/case_ioc_management.html': ('ioc_uuid', 'Relationships'),
            '/opt/casescope/static/templates/case_known_systems.html': ('known_system',),
            '/opt/casescope/static/templates/case_known_users.html': ('known_user',),
            '/opt/casescope/static/templates/case_analysis_results.html': ('Graph Supporting Evidence',),
        }
        for path, needles in files.items():
            with open(path, encoding='utf-8') as handle:
                source = handle.read()
            for needle in needles:
                self.assertIn(needle, source, msg=f'{needle} missing from {path}')

    def test_graph_deep_link_and_unsupported_styling(self):
        with open('/opt/casescope/static/templates/case_graph.html', encoding='utf-8') as handle:
            source = handle.read()
        self.assertIn('root_entity_id', source)
        self.assertIn('pivot_context', source)
        self.assertIn('UNSUPPORTED', source)
        self.assertIn('Unsupported', source)
        self.assertNotIn('Attack Chain', source)


class Phase0EExtractorContractTestCase(unittest.TestCase):
    def test_event_connected_to_remains_disabled(self):
        extractor = ProcessConnectedToIpExtractor()
        self.assertFalse(extractor.supports({'process_id': 1, 'dst_ip': '1.2.3.4'}))

    def test_memory_extractors_registered(self):
        self.assertTrue(hasattr(MemoryConnectedToIpExtractor, 'extract_job'))
        self.assertTrue(hasattr(MemoryLoadedModuleExtractor, 'extract_job'))
        self.assertTrue(hasattr(MemoryServiceRunsProcessExtractor, 'extract_job'))
        self.assertTrue(hasattr(MemoryHasSecurityContextExtractor, 'extract_job'))
        self.assertIn(GraphRelationshipType.LOADED_MODULE, GraphRelationshipType.ALL)
        self.assertIn(GraphRelationshipType.HAS_SECURITY_CONTEXT, GraphRelationshipType.ALL)

    def test_dns_resolved_to_uses_native_locator(self):
        locator = build_zeek_dns_locator(
            case_id=1,
            pcap_id=5,
            uid='Cabc123',
            query='example.com',
            answer='1.2.3.4',
        )
        self.assertEqual(locator['source_type'], SOURCE_TYPE_ZEEK_DNS)
        key = support_key_for_locator(locator)
        self.assertTrue(is_native_support_key(key))
        self.assertFalse(is_evidence_record_key(key))
        self.assertTrue(hasattr(DomainResolvedToIpExtractor, 'extract_row'))

    def test_memory_locator_is_not_erk(self):
        locator = build_memory_locator(
            source_type='memory_network',
            case_id=1,
            memory_job_id=44,
            record_id=919,
        )
        key = support_key_for_locator(locator)
        self.assertTrue(key.startswith('native:v1:'))
        self.assertFalse(is_evidence_record_key(key))

    def test_service_registry_task_event_extractors_not_enabled(self):
        source = open('/opt/casescope/utils/graph_extractors.py', encoding='utf-8').read()
        self.assertIn('NOT ENABLED', source)
        self.assertIn('INSUFFICIENT SOURCE CONTRACT', source)


class Phase0EIOCProvenanceContractTestCase(unittest.TestCase):
    def test_ioc_types_alone_cannot_prove_exact_match(self):
        source = open('/opt/casescope/utils/ioc_match_provenance.py', encoding='utf-8').read()
        self.assertIn('ioc.uuid', source)
        self.assertIn('NEVER re-inferred from', source)
        self.assertEqual(DEFAULT_MATCHED_FIELD, 'search_blob')

    def test_tagger_persists_exact_ioc_uuid(self):
        source = open('/opt/casescope/utils/ioc_artifact_tagger.py', encoding='utf-8').read()
        self.assertIn('record_ioc_evidence_matches', source)


class Phase0ELifecycleHookContractTestCase(unittest.TestCase):
    def test_case_file_delete_hooks_lifecycle(self):
        source = open('/opt/casescope/routes/case_files.py', encoding='utf-8').read()
        self.assertIn('begin_case_file_removal', source)
        self.assertIn('finalize_case_file_removal', source)
        self.assertIn('restore_case_file_support_if_source_remains', source)

    def test_rebuild_uses_revalidation_mode(self):
        source = open('/opt/casescope/tasks/celery_tasks.py', encoding='utf-8').read()
        self.assertIn("lifecycle_mode='revalidation'", source)
        self.assertIn('materialize_memory_for_case', source)
        self.assertIn('materialize_network_for_case', source)


if __name__ == '__main__':
    unittest.main()
