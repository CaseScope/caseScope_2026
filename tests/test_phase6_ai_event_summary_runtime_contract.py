import os
import unittest


REPO_ROOT = os.path.dirname(os.path.dirname(__file__))


class Phase6AIEventSummaryRuntimeContractTestCase(unittest.TestCase):
    def test_event_summary_uses_shared_ai_router_and_surfaces_runtime(self):
        with open(
            os.path.join(REPO_ROOT, 'utils', 'ai_event_summary.py'),
            'r',
            encoding='utf-8',
        ) as handle:
            source = handle.read()

        self.assertIn('from utils.ai.router import invoke_text', source)
        self.assertIn("result = invoke_text(", source)
        self.assertIn("self.runtime = result.get('runtime', {})", source)
        self.assertIn("'ai_runtime': self.runtime", source)


if __name__ == '__main__':
    unittest.main()
