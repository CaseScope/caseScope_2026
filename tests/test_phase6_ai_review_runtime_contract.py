import os
import unittest


REPO_ROOT = os.path.dirname(os.path.dirname(__file__))


class Phase6AIReviewRuntimeContractTestCase(unittest.TestCase):
    def test_ai_review_routes_text_and_json_reviews_through_shared_router(self):
        with open(
            os.path.join(REPO_ROOT, 'utils', 'ai_review.py'),
            'r',
            encoding='utf-8',
        ) as handle:
            source = handle.read()

        self.assertIn('from utils.ai.router import invoke_json, invoke_text', source)
        self.assertIn('result = invoke_text(', source)
        self.assertIn('provider=provider,', source)
        self.assertIn('result = invoke_json(', source)


if __name__ == '__main__':
    unittest.main()
