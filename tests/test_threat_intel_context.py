import importlib.util
import os
import sys
import types
import unittest


REPO_ROOT = os.path.dirname(os.path.dirname(__file__))


class _QueryChain:
    def __init__(self, rows):
        self.rows = list(rows)

    def filter_by(self, **kwargs):
        return self

    def filter(self, *args, **kwargs):
        return self

    def limit(self, _count):
        return self

    def all(self):
        return list(self.rows)


class ThreatIntelContextTestCase(unittest.TestCase):
    def setUp(self):
        self.previous_modules = {}
        self.lookup_calls = []

        fake_feature_availability = types.ModuleType('utils.feature_availability')

        class FeatureAvailability:
            @staticmethod
            def is_threat_intel_enabled():
                return True

        fake_feature_availability.FeatureAvailability = FeatureAvailability

        fake_opencti_context = types.ModuleType('utils.opencti_context')

        class OpenCTIContextProvider:
            def __init__(self, case_id):
                self.case_id = case_id

            def is_available(self):
                return True

            def get_threat_actor_context(self, techniques):
                return []

            def get_campaign_context(self, techniques, days_back=180):
                return []

            def get_vulnerability_context(self, cve_values):
                return [
                    {
                        'name': value,
                        'base_score': 9.8,
                        'external_references': [{'source_name': 'NVD'}],
                    }
                    for value in cve_values
                ]

        fake_opencti_context.OpenCTIContextProvider = OpenCTIContextProvider

        fake_opencti = types.ModuleType('utils.opencti')

        def lookup_threat_intel(value, ioc_type, context_values=None):
            self.lookup_calls.append((value, ioc_type, tuple(context_values or [])))
            return {
                'found': True,
                'score': 80,
                'labels': ['known-bad'],
                'providers_found': ['OpenCTI'],
                'available_connectors': [{'name': 'Connector A'}],
            }

        fake_opencti.lookup_threat_intel = lookup_threat_intel

        fake_rag = types.ModuleType('models.rag')

        class AIAnalysisResult:
            final_confidence = 50
            query = _QueryChain([])

        class PatternRuleMatch:
            confidence = 50
            query = _QueryChain([])

        fake_rag.AIAnalysisResult = AIAnalysisResult
        fake_rag.PatternRuleMatch = PatternRuleMatch

        fake_ioc = types.ModuleType('models.ioc')

        class IOCRow:
            def __init__(self, value, ioc_type, aliases=None):
                self.value = value
                self.ioc_type = ioc_type
                self.aliases = aliases or []

        class IOC:
            query = _QueryChain(
                [
                    IOCRow('example.org', 'Domain'),
                    IOCRow('example.org', 'Domain'),
                    IOCRow('CVE-2024-0001', 'CVE'),
                ]
            )

        fake_ioc.IOC = IOC

        for name, module in {
            'utils.feature_availability': fake_feature_availability,
            'utils.opencti_context': fake_opencti_context,
            'utils.opencti': fake_opencti,
            'models.rag': fake_rag,
            'models.ioc': fake_ioc,
        }.items():
            self.previous_modules[name] = sys.modules.get(name)
            sys.modules[name] = module

        module_path = os.path.join(REPO_ROOT, 'utils', 'threat_intel_context.py')
        spec = importlib.util.spec_from_file_location('threat_intel_context_under_test', module_path)
        self.context_module = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(self.context_module)

    def tearDown(self):
        for name, previous in self.previous_modules.items():
            if previous is not None:
                sys.modules[name] = previous
            else:
                sys.modules.pop(name, None)

    def test_prompt_context_caches_duplicate_ioc_lookups_and_skips_cves(self):
        context = self.context_module.get_threat_intel_context(case_id=7, include_iocs=True)

        self.assertIn('IOC Intelligence:', context)
        self.assertIn('Vulnerability Intelligence:', context)
        self.assertEqual(
            self.lookup_calls,
            [('example.org', 'Domain', ())],
        )


if __name__ == '__main__':
    unittest.main()
