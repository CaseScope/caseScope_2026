import importlib.util
import os
import sys
import types
import unittest


REPO_ROOT = os.path.dirname(os.path.dirname(__file__))


class _FakeIndicatorApi:
    def __init__(self, responses=None):
        self.responses = responses or {}
        self.calls = []

    def list(self, filters=None, first=10, **_kwargs):
        self.calls.append({'filters': filters, 'first': first})
        filter_item = (filters or {}).get('filters', [{}])[0]
        operator = filter_item.get('operator')
        value = (filter_item.get('values') or [None])[0]
        return self.responses.get((operator, value), [])


class _FakeObservableApi:
    def __init__(self, responses=None):
        self.responses = responses or {}
        self.calls = []

    def list(self, filters=None, first=20, **_kwargs):
        self.calls.append({'filters': filters, 'first': first})
        filter_item = (filters or {}).get('filters', [{}])[0]
        operator = filter_item.get('operator')
        value = (filter_item.get('values') or [None])[0]
        return self.responses.get((operator, value), [])


class _FakeMalwareApi:
    def __init__(self, responses=None):
        self.responses = responses or {}
        self.calls = []

    def list(self, search=None, first=20, **_kwargs):
        self.calls.append({'search': search, 'first': first})
        return self.responses.get(search, [])


class _FakePyctiClient:
    def __init__(self, indicator_responses=None, observable_responses=None, malware_responses=None, query_response=None):
        self.indicator = _FakeIndicatorApi(indicator_responses)
        self.stix_cyber_observable = _FakeObservableApi(observable_responses)
        self.malware = _FakeMalwareApi(malware_responses)
        self.query_response = query_response or {}

    def query(self, _query):
        return self.query_response


class OpenCTIExactEnrichmentTestCase(unittest.TestCase):
    def setUp(self):
        fake_ioc_module = types.ModuleType('models.ioc')

        class FakeIOC:
            @staticmethod
            def normalize_value(value, ioc_type=None):
                value = (value or '').strip()
                if ioc_type in {
                    'Domain', 'FQDN', 'URL', 'Hostname', 'Email Address',
                    'MD5 Hash', 'SHA1 Hash', 'SHA256 Hash', 'Imphash',
                    'File Name', 'Process Name', 'File Path', 'Process Path',
                }:
                    return value.lower()
                return value

        def detect_ioc_type_from_value(value):
            value = (value or '').strip()
            if value.startswith(('http://', 'https://', 'ftp://')):
                return 'URL'
            if len(value) == 64 and all(ch in '0123456789abcdefABCDEF' for ch in value):
                return 'SHA256 Hash'
            return 'File Name'

        fake_ioc_module.IOC = FakeIOC
        fake_ioc_module.detect_ioc_type_from_value = detect_ioc_type_from_value
        sys.modules['models.ioc'] = fake_ioc_module

        fake_misp_module = types.ModuleType('utils.misp')
        fake_misp_module.get_misp_client = lambda: None
        fake_misp_module.is_misp_auto_enrich_enabled = lambda: False
        sys.modules['utils.misp'] = fake_misp_module

        module_path = os.path.join(REPO_ROOT, 'utils', 'opencti.py')
        spec = importlib.util.spec_from_file_location('opencti_under_test', module_path)
        self.opencti = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.opencti)

    def _make_client(self, indicator_responses=None, observable_responses=None, malware_responses=None, query_response=None):
        client = self.opencti.OpenCTIClient.__new__(self.opencti.OpenCTIClient)
        client.client = _FakePyctiClient(indicator_responses, observable_responses, malware_responses, query_response)
        client.init_error = None
        client.url = 'http://opencti.test'
        client.api_key = 'token'
        client._connector_catalog = None
        return client

    def test_non_enrichable_file_name_returns_not_applicable_without_lookup(self):
        client = self._make_client()

        result = client.check_indicator('document.pdf', 'File Name')

        self.assertFalse(result['found'])
        self.assertEqual(result['status'], 'not_applicable')
        self.assertEqual(result['match_source'], 'not_applicable')
        self.assertEqual(result['schema_version'], self.opencti.OPENCTI_ENRICHMENT_SCHEMA_VERSION)
        self.assertEqual(client.client.indicator.calls, [])
        self.assertEqual(client.client.stix_cyber_observable.calls, [])

    def test_unknown_type_is_inferred_and_matches_exact_observable(self):
        observable = {
            'id': 'obs-1',
            'entity_type': 'Url',
            'value': 'https://example.com/dropper.exe',
            'confidence': 80,
            'objectLabel': [{'value': 'phishing'}],
        }
        client = self._make_client(
            observable_responses={
                ('eq', 'https://example.com/dropper.exe'): [observable]
            }
        )

        result = client.check_indicator('https://example.com/dropper.exe', 'Unknown')

        self.assertTrue(result['found'])
        self.assertEqual(result['resolved_ioc_type'], 'URL')
        self.assertEqual(result['match_source'], 'observable_exact')
        self.assertEqual(result['lookup_type'], 'Unknown')
        self.assertEqual(result['lookup_value'], 'https://example.com/dropper.exe')

    def test_hash_uses_exact_indicator_pattern_match(self):
        sha256 = 'a' * 64
        pattern = f"[file:hashes.'SHA-256' = '{sha256}']"
        indicator = {
            'id': 'ind-1',
            'name': sha256,
            'pattern': pattern,
            'confidence': 70,
            'indicator_types': ['malicious-activity'],
        }
        client = self._make_client(
            indicator_responses={
                ('eq', pattern): [indicator]
            }
        )

        result = client.check_indicator(sha256, 'SHA256 Hash')

        self.assertTrue(result['found'])
        self.assertEqual(result['match_source'], 'indicator_exact')
        self.assertEqual(result['matched_pattern'], pattern)
        self.assertEqual(client.client.indicator.calls[0]['filters']['filters'][0]['operator'], 'eq')

    def test_result_includes_applicable_connectors(self):
        client = self._make_client(
            query_response={
                'data': {
                    'connectors': [
                        {
                            'id': 'conn-1',
                            'name': 'DNSTwist',
                            'active': True,
                            'auto': False,
                            'connector_type': 'INTERNAL_ENRICHMENT',
                            'connector_scope': ['Domain-Name'],
                            'only_contextual': False,
                            'updated_at': '',
                        },
                        {
                            'id': 'conn-2',
                            'name': 'Shodan InternetDB',
                            'active': True,
                            'auto': False,
                            'connector_type': 'INTERNAL_ENRICHMENT',
                            'connector_scope': ['IPv4-Addr'],
                            'only_contextual': False,
                            'updated_at': '',
                        },
                    ]
                }
            }
        )

        result = client.check_indicator('example.org', 'Domain')

        self.assertFalse(result['found'])
        self.assertEqual(result['connector_count'], 1)
        self.assertEqual(result['available_connectors'][0]['name'], 'DNSTwist')

    def test_threat_name_uses_malware_entity_lookup(self):
        client = self._make_client(
            malware_responses={
                'Trickbot': [{
                    'id': 'mal-1',
                    'entity_type': 'Malware',
                    'name': 'TrickBot',
                    'aliases': ['Trickbot'],
                    'description': 'Banking trojan family',
                    'confidence': 70,
                    'objectLabel': [{'value': 'banking'}],
                }]
            }
        )

        result = client.check_threat_name('Trojan:JS/Trickbot.S!MSR', 'Threat Name')

        self.assertTrue(result['found'])
        self.assertEqual(result['match_category'], self.opencti.THREAT_INTEL_CATEGORY_THREAT_NAME)
        self.assertEqual(result['matched_name'], 'Trickbot')
        self.assertEqual(result['matched_entities'][0]['name'], 'TrickBot')

    def test_lookup_threat_intel_derives_defanged_url_from_command_context(self):
        derived_url = 'https://bad.example/payload.exe'
        observable = {
            'id': 'obs-derived',
            'entity_type': 'Url',
            'value': derived_url,
            'confidence': 65,
            'objectLabel': [{'value': 'phishing'}],
        }
        client = self._make_client(
            observable_responses={
                ('eq', derived_url): [observable]
            }
        )
        self.opencti.get_opencti_client = lambda: client

        enrichment = self.opencti.lookup_threat_intel(
            'msiexec.exe',
            'Command Line',
            context_values=[
                '"C:\\Windows\\System32\\msiexec.exe" /i "hxxps[:]//bad[.]example/payload.exe"'
            ],
        )

        self.assertTrue(enrichment['found'])
        self.assertEqual(enrichment['lookup_path'], 'derived')
        self.assertEqual(enrichment['match_category'], self.opencti.THREAT_INTEL_CATEGORY_DERIVED)
        self.assertEqual(enrichment['derived_indicators'][0]['extracted_type'], 'URL')
        self.assertEqual(enrichment['derived_indicators'][0]['extracted_value'], derived_url)

    def test_lookup_threat_intel_returns_contextual_tool_match_for_screenconnect_service(self):
        client = self._make_client()
        self.opencti.get_opencti_client = lambda: client

        enrichment = self.opencti.lookup_threat_intel(
            'ScreenConnect Client (80ad4b9fdcdcd119)',
            'Service Name',
        )

        self.assertTrue(enrichment['found'])
        self.assertEqual(enrichment['match_category'], self.opencti.THREAT_INTEL_CATEGORY_CONTEXTUAL_TOOL)
        self.assertEqual(enrichment['contextual_tools'][0]['tool_name'], 'ConnectWise ScreenConnect')

    def test_legacy_positive_results_are_flagged_for_revalidation(self):
        self.assertTrue(
            self.opencti.is_legacy_unverified_enrichment({'found': True, 'name': 'legacy-hit'})
        )
        self.assertFalse(
            self.opencti.is_legacy_unverified_enrichment({
                'found': True,
                'schema_version': self.opencti.OPENCTI_ENRICHMENT_SCHEMA_VERSION,
            })
        )

    def test_auth_required_error_is_classified_as_token_rejection(self):
        client = self.opencti.OpenCTIClient.__new__(self.opencti.OpenCTIClient)

        message = client._classify_connection_error(
            "{'name': 'AUTH_REQUIRED', 'error_message': 'You must be logged in to do this.'}"
        )

        self.assertEqual(
            message,
            'Authentication failed - OpenCTI rejected the API token'
        )

    def test_reachability_error_is_classified_cleanly(self):
        client = self.opencti.OpenCTIClient.__new__(self.opencti.OpenCTIClient)

        message = client._classify_connection_error(
            'OpenCTI API is not reachable. Waiting for OpenCTI API to start or check your configuration...'
        )

        self.assertEqual(message, 'OpenCTI API is not reachable - Check URL')


if __name__ == '__main__':
    unittest.main()
