import os
import sys
import types
import unittest
import importlib.util
from datetime import datetime
from ipaddress import IPv6Address
from unittest.mock import patch


os.environ.setdefault('SECRET_KEY', 'test-secret')

if 'clickhouse_connect' not in sys.modules:
    clickhouse_stub = types.ModuleType('clickhouse_connect')
    clickhouse_stub.get_client = lambda *args, **kwargs: None
    sys.modules['clickhouse_connect'] = clickhouse_stub

REPO_ROOT = os.path.dirname(os.path.dirname(__file__))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)


def _load_module(module_name, relative_path):
    spec = importlib.util.spec_from_file_location(
        module_name,
        os.path.join(REPO_ROOT, relative_path),
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


network_log = _load_module('test_network_log_ip_display_model', os.path.join('models', 'network_log.py'))


class _QueryResult:
    def __init__(self, rows):
        self.result_rows = rows


class _NetworkLogClient:
    def __init__(self):
        self.queries = []

    def query(self, sql, parameters=None):
        self.queries.append((sql, parameters or {}))
        if 'SELECT count()' in sql:
            return _QueryResult([(1,)])

        return _QueryResult([(
            datetime(2026, 5, 31, 2, 18, 25),
            IPv6Address('::ffff:192.168.1.119'),
            51908,
            IPv6Address('::ffff:8.8.8.8'),
            53,
            'udp',
            'dns',
            0.125,
            'SF',
            128,
            256,
            '{}',
            'C1',
            7,
            'HOST-1',
        )])


class NetworkLogIpDisplayTests(unittest.TestCase):
    def test_ipv4_mapped_ipv6_is_displayed_as_dotted_ipv4(self):
        self.assertEqual(
            network_log.normalize_ip_for_display(IPv6Address('::ffff:192.168.1.119')),
            '192.168.1.119',
        )

    def test_query_logs_normalizes_display_and_preserves_ipv4_prefix_filters(self):
        client = _NetworkLogClient()

        with patch.object(network_log, 'get_client', return_value=client):
            result = network_log.query_logs(
                case_id=1,
                log_type='conn',
                src_ip='192.168.',
                dst_ip='8.8.8.',
            )

        self.assertTrue(result['success'])
        self.assertEqual(result['logs'][0]['src_ip'], '192.168.1.119')
        self.assertEqual(result['logs'][0]['dst_ip'], '8.8.8.8')

        count_query, count_params = client.queries[0]
        self.assertIn('search_blob ILIKE {src_ip_search:String}', count_query)
        self.assertIn('search_blob ILIKE {dst_ip_search:String}', count_query)
        self.assertEqual(count_params['src_ip_search'], '%id.orig_h:192.168.%')
        self.assertEqual(count_params['dst_ip_search'], '%id.resp_h:8.8.8.%')


if __name__ == '__main__':
    unittest.main()
