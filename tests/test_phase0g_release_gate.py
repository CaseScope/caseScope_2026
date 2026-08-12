import json
import unittest
from pathlib import Path


MATRIX_PATH = Path("/opt/casescope/docs/investigation_graph_phase0g_matrix.json")
VALID_STATUSES = {"PASS", "FAIL", "APPROVED_EXCLUSION", "NOT_APPLICABLE"}


def _matrix():
    return json.loads(MATRIX_PATH.read_text(encoding="utf-8"))


class Phase0GReleaseGateTestCase(unittest.TestCase):
    def test_phase0g_matrix_covers_all_acceptance_criteria_and_uses_closed_statuses(self):
        matrix = _matrix()
        criteria = {item["id"]: item for item in matrix["acceptance_criteria"]}

        self.assertEqual(set(criteria), set(range(1, 61)))
        self.assertLessEqual({item["status"] for item in criteria.values()}, VALID_STATUSES)
        self.assertTrue(all(criteria[item_id]["status"] == "PASS" for item_id in range(42, 61)))

    def test_phase0g_approved_exclusions_are_explicit_and_limited_to_locked_contracts(self):
        matrix = _matrix()
        exclusions = {item["acceptance_criterion"]: item for item in matrix["approved_exclusions"]}

        self.assertEqual(set(exclusions), {9, 15, 16})
        for item in exclusions.values():
            self.assertTrue(item["missing_contract"])
            self.assertTrue(item["negative_tests"])
            self.assertTrue(item["future_prerequisites"])

    def test_phase0g_not_ready_while_mandatory_runtime_gates_are_missing(self):
        matrix = _matrix()
        criteria = {item["id"]: item for item in matrix["acceptance_criteria"]}
        risk = {item["id"]: item for item in matrix["risks"]}

        self.assertEqual(criteria[33]["status"], "FAIL")
        self.assertEqual(risk["R11"]["status"], "FAIL")
        self.assertEqual(matrix["regression_results"]["large_case_runtime"]["status"], "FAIL")
        self.assertEqual(matrix["regression_results"]["fresh_install_runtime"]["status"], "FAIL")
        self.assertEqual(matrix["regression_results"]["upgrade_runtime"]["status"], "FAIL")
        self.assertEqual(matrix["final_verdict"], "NOT READY")


if __name__ == "__main__":
    unittest.main()
