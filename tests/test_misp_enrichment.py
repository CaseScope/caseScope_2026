import importlib.util
import os
import unittest


REPO_ROOT = os.path.dirname(os.path.dirname(__file__))
os.environ.setdefault('SECRET_KEY', 'test-secret-key')


class MISPEnrichmentTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        module_path = os.path.join(REPO_ROOT, 'utils', 'misp.py')
        spec = importlib.util.spec_from_file_location('misp_under_test', module_path)
        cls.misp = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.misp)

    def _make_client(self):
        client = self.misp.MISPClient.__new__(self.misp.MISPClient)
        client.url = 'https://misp.test'
        client.api_key = 'token'
        client.ssl_verify = False
        client.timeout = 10
        client.init_error = None
        client.last_error = None
        return client

    def test_threat_name_uses_event_context_lookup(self):
        client = self._make_client()
        client._search_name_events = lambda candidate: [{
            'id': '42',
            'info': 'TrickBot phishing delivery',
            'Tag': [{'name': 'tlp:amber'}, {'name': 'malware:family="trickbot"'}],
            'Galaxy': [{
                'name': 'Threat Actor',
                'GalaxyCluster': [{'value': 'TrickBot', 'description': 'Malware family'}],
            }],
        }] if candidate == 'Trickbot' else []

        result = client.check_threat_name('Trojan:JS/Trickbot.S!MSR', 'Threat Name')

        self.assertTrue(result['found'])
        self.assertEqual(result['match_category'], 'threat_name_match')
        self.assertEqual(result['matched_name'], 'Trickbot')
        self.assertEqual(result['external_references'][0]['url'], 'https://misp.test/events/view/42')
        self.assertIn('TrickBot', result['malware_families'])


if __name__ == '__main__':
    unittest.main()
