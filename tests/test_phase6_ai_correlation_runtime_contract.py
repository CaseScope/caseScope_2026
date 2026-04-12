import os
import unittest


REPO_ROOT = os.path.dirname(os.path.dirname(__file__))


class Phase6AICorrelationRuntimeContractTestCase(unittest.TestCase):
    def test_correlation_analyzer_uses_shared_router_for_json_calls(self):
        with open(
            os.path.join(REPO_ROOT, 'utils', 'ai_correlation_analyzer.py'),
            'r',
            encoding='utf-8',
        ) as handle:
            source = handle.read()

        self.assertIn('from utils.ai.router import invoke_json', source)
        self.assertIn('def _invoke_json(self, *, prompt: str, system: str) -> Dict[str, Any]:', source)
        self.assertIn("return invoke_json(", source)
        self.assertIn("provider=self._provider,", source)
        self.assertNotIn('OllamaClient', source)
        self.assertNotIn('self.client.generate_json', source)


if __name__ == '__main__':
    unittest.main()
