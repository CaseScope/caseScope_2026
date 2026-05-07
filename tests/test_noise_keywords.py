import os
import unittest

os.environ.setdefault("SECRET_KEY", "test-secret")
from utils.noise_keywords import build_keyword_clause, build_keyword_not_clause


class NoiseKeywordTestCase(unittest.TestCase):
    def test_match_clause_ignores_huntress_raw_vendor_metadata(self):
        clause = build_keyword_clause(["huntress"], "raw_json")

        self.assertIn("artifact_type NOT IN ('huntress')", clause)
        self.assertIn("hasTokenCaseInsensitive(raw_json, 'huntress')", clause)
        self.assertIn("hasTokenCaseInsensitive(search_blob, 'huntress')", clause)

    def test_not_clause_keeps_huntress_raw_vendor_metadata_neutral(self):
        clause = build_keyword_not_clause(["huntress"], "raw_json")

        self.assertIn("artifact_type IN ('huntress')", clause)
        self.assertIn("NOT hasTokenCaseInsensitive(raw_json, 'huntress')", clause)
        self.assertIn("NOT hasTokenCaseInsensitive(search_blob, 'huntress')", clause)

    def test_separator_keywords_still_use_substring_matching(self):
        clause = build_keyword_clause(["huntress.io"], "raw_json")

        self.assertIn("positionCaseInsensitive(raw_json, 'huntress.io') > 0", clause)
        self.assertIn("positionCaseInsensitive(search_blob, 'huntress.io') > 0", clause)


if __name__ == "__main__":
    unittest.main()
