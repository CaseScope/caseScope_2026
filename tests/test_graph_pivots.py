"""Phase 0E graph pivot service and route contract tests."""
import inspect
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from flask import Flask

import routes.graph as graph_routes
from utils.graph_pivots import (
    MAX_PIVOT_ROOTS,
    PIVOT_KIND_EVIDENCE,
    PIVOT_KIND_IOC,
    PIVOT_KIND_KNOWN_SYSTEM,
    PIVOT_KIND_PROCESS_HUNT,
    GraphPivotError,
    GraphPivotService,
)
from utils.graph_support_locator import is_evidence_record_key


def erk(char='a'):
    return 'erk:v2:' + (char * 64)


class GraphPivotServiceTestCase(unittest.TestCase):
    def setUp(self):
        self.service = GraphPivotService()

    def test_unsupported_kind_raises(self):
        with self.assertRaises(GraphPivotError):
            self.service.resolve(1, kind='not_a_kind', reference={})

    def test_evidence_requires_erk_v2(self):
        with self.assertRaises(GraphPivotError):
            self.service.resolve(1, kind=PIVOT_KIND_EVIDENCE, reference={'evidence_record_key': 'bad'})

    def test_process_hunt_pid_only_does_not_invent_process(self):
        with patch.object(self.service, '_lookup_host_by_hostname', return_value=None):
            result = self.service.resolve(
                1,
                kind=PIVOT_KIND_PROCESS_HUNT,
                reference={'hostname': 'WKS-1', 'process_id': 1234},
            )
        self.assertFalse(result['resolved'])
        self.assertIn('PID-only', result['message'])

    def test_process_hunt_host_fallback_when_hostname_resolves(self):
        host_root = {
            'entity_id': 9,
            'entity_type': 'HOST',
            'display_value': 'WKS-1',
            'stable_reference': {'case_id': 1, 'entity_type': 'HOST', 'entity_key': 'known_system:3'},
        }
        with patch.object(self.service, '_lookup_host_by_hostname', return_value=host_root):
            result = self.service.resolve(
                1,
                kind=PIVOT_KIND_PROCESS_HUNT,
                reference={'hostname': 'WKS-1', 'process_id': 1234},
            )
        self.assertTrue(result['resolved'])
        self.assertEqual(result['roots'][0]['entity_type'], 'HOST')
        self.assertFalse(result['context'].get('authoritative', True))

    def test_ioc_requires_uuid_not_type(self):
        with self.assertRaises(GraphPivotError):
            self.service.resolve(1, kind=PIVOT_KIND_IOC, reference={'ioc_type': 'Hash'})

    def test_known_system_cross_case_rejected(self):
        system = SimpleNamespace(id=5, hostname='HOST-A')
        with patch('utils.graph_pivots.KnownSystem') as KS:
            KS.query.get.return_value = system
            with patch.object(self.service, '_known_system_in_case', return_value=False):
                with self.assertRaises(GraphPivotError):
                    self.service.resolve(1, kind=PIVOT_KIND_KNOWN_SYSTEM, reference={'known_system_id': 5})

    def test_evidence_unresolved_message(self):
        with patch('utils.graph_pivots.GraphEntityObservation') as Obs, \
                patch('utils.graph_pivots.GraphRelationshipEvidence') as RelEv:
            Obs.query.filter_by.return_value.limit.return_value.all.return_value = []
            RelEv.query.filter.return_value.limit.return_value.all.return_value = []
            result = self.service.resolve(
                1,
                kind=PIVOT_KIND_EVIDENCE,
                reference={'evidence_record_key': erk('b')},
            )
        self.assertFalse(result['resolved'])
        self.assertIn('No authoritative graph entity or relationship is currently', result['message'])

    def test_pivot_bounds_constants(self):
        self.assertEqual(MAX_PIVOT_ROOTS, 25)
        self.assertTrue(is_evidence_record_key(erk('c')))


class GraphPivotRouteTestCase(unittest.TestCase):
    def setUp(self):
        self.app = Flask(__name__)
        self.app.secret_key = 'test-secret'
        self.case = SimpleNamespace(id=7, uuid='case-uuid')

    def test_pivot_route_is_login_protected(self):
        self.assertTrue(hasattr(graph_routes.graph_pivot, '__wrapped__'))

    def test_viewer_can_call_pivot_read_only(self):
        service = Mock()
        service.resolve.return_value = {
            'pivot_type': 'evidence',
            'resolved': False,
            'roots': [],
            'message': 'none',
        }
        with self.app.test_request_context(
            '/api/graph/case-uuid/pivot',
            method='POST',
            json={'kind': 'evidence', 'reference': {'evidence_record_key': erk('d')}},
        ):
            with patch.object(graph_routes.Case, 'get_by_uuid', return_value=self.case), \
                    patch.object(graph_routes, '_pivot_service', return_value=service):
                response = graph_routes.graph_pivot.__wrapped__('case-uuid')
        payload = response.get_json()
        self.assertTrue(payload['success'])
        service.resolve.assert_called_once_with(
            7,
            kind='evidence',
            reference={'evidence_record_key': erk('d')},
        )

    def test_pivot_route_source_listed_in_module(self):
        source = inspect.getsource(graph_routes)
        self.assertIn('/graph/<case_uuid>/pivot', source)
        self.assertIn('Read-only', source)


if __name__ == '__main__':
    unittest.main()
