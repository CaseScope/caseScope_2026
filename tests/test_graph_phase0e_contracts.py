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
    validate_support_provenance,
)
from utils.ioc_match_provenance import DEFAULT_MATCHED_FIELD, record_matches


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

    def test_dns_resolved_to_disabled_until_exact_transaction_identity(self):
        with self.assertRaises(ValueError):
            build_zeek_dns_locator(
                case_id=1,
                pcap_id=5,
                uid='Cabc123',
                query='example.com',
                answer='1.2.3.4',
            )
        extractor = DomainResolvedToIpExtractor()
        candidates = list(extractor.extract_row(
            case_id=1,
            pcap_id=5,
            uid='Cabc123',
            query='example.com',
            answers=['1.2.3.4'],
        ))
        self.assertEqual(candidates, [])

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

    def test_native_locator_key_must_match_locator(self):
        locator_a = build_memory_locator(
            source_type='memory_network',
            case_id=1,
            memory_job_id=44,
            record_id=919,
        )
        locator_b = build_memory_locator(
            source_type='memory_network',
            case_id=1,
            memory_job_id=45,
            record_id=919,
        )
        with self.assertRaises(ValueError):
            validate_support_provenance(
                evidence_record_key=support_key_for_locator(locator_a),
                source_table='memory_network',
                support_locator=locator_b,
            )

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
        self.assertIn('scan not finalized', source)

    def test_ioc_provenance_rejects_malformed_erk(self):
        with self.assertRaises(ValueError):
            record_matches(
                1,
                1,
                '11111111-1111-1111-1111-111111111111',
                'Hash',
                'aaa',
                ['not-an-erk'],
            )


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

    def test_lifecycle_prep_failures_are_not_logged_and_ignored(self):
        case_file_source = open('/opt/casescope/routes/case_files.py', encoding='utf-8').read()
        rebuild_source = open('/opt/casescope/tasks/celery_tasks.py', encoding='utf-8').read()
        self.assertIn('Graph support preparation failed; file evidence was left unchanged', case_file_source)
        self.assertIn('rebuild aborted before evidence deletion', rebuild_source)
        self.assertIn('deleted_clickhouse_ids', case_file_source)
        self.assertIn('deleted_ids', rebuild_source)

    def test_native_source_delete_hooks_exist(self):
        pcap_route = open('/opt/casescope/routes/pcap.py', encoding='utf-8').read()
        pcap_task = open('/opt/casescope/tasks/pcap_tasks.py', encoding='utf-8').read()
        memory_route = open('/opt/casescope/routes/memory.py', encoding='utf-8').read()
        memory_task = open('/opt/casescope/tasks/memory_tasks.py', encoding='utf-8').read()
        self.assertIn('begin_pcap_removal', pcap_route)
        self.assertIn('begin_pcap_revalidation', pcap_task)
        self.assertIn('begin_memory_job_removal', memory_route)
        self.assertIn('begin_memory_job_revalidation', memory_task)
        self.assertIn('restore_source_support_if_source_remains', pcap_route)
        self.assertIn('restore_source_support_if_source_remains', memory_task)

    def test_4162_lifecycle_hooks_are_complete(self):
        pcap_task = open('/opt/casescope/tasks/pcap_tasks.py', encoding='utf-8').read()
        memory_task = open('/opt/casescope/tasks/memory_tasks.py', encoding='utf-8').read()
        memory_extractors = open('/opt/casescope/utils/graph_memory_extractors.py', encoding='utf-8').read()
        migration = open('/opt/casescope/migrations/invalidate_phase0e_4160_dns_relationships.py', encoding='utf-8').read()
        self.assertIn('begin_pcap_revalidation', pcap_task)
        self.assertIn('finalize_pcap_revalidation', pcap_task)
        self.assertIn('materialize_memory_for_case', memory_task)
        self.assertIn('memory_job_id=job.id', memory_task)
        self.assertNotIn('yield_per(1000)', memory_extractors)
        self.assertIn('zeek_dns_resolved_to_ip', migration)
        self.assertIn('invalidate_support_by_extractor', migration)

    def test_rematerialization_updates_existing_support_locator(self):
        materializer = open('/opt/casescope/utils/graph_materializer.py', encoding='utf-8').read()
        self.assertIn('evidence.source_ref_type = source_ref_type', materializer)
        self.assertIn('evidence.support_locator_json = support_locator', materializer)
        self.assertNotIn('source_ref_type and not evidence.source_ref_type', materializer)
        self.assertNotIn('support_locator and not evidence.support_locator_json', materializer)


if __name__ == '__main__':
    unittest.main()
