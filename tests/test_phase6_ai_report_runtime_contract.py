import os
import unittest


REPO_ROOT = os.path.dirname(os.path.dirname(__file__))


class Phase6AIReportRuntimeContractTestCase(unittest.TestCase):
    def test_report_generator_uses_shared_router_and_surfaces_runtime(self):
        with open(
            os.path.join(REPO_ROOT, 'utils', 'ai_report_generator.py'),
            'r',
            encoding='utf-8',
        ) as handle:
            source = handle.read()

        self.assertIn('from utils.ai.router import invoke_text', source)
        self.assertIn("result = invoke_text(", source)
        self.assertIn("self._last_runtime = result.get('runtime', {})", source)
        self.assertIn("'ai_runtime': self._last_runtime", source)


if __name__ == '__main__':
    unittest.main()
