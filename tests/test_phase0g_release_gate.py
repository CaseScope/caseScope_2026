import json
import unittest
from pathlib import Path


MATRIX_PATH = Path("/opt/casescope/docs/investigation_graph_phase0g_matrix.json")
RUNTIME_PATH = Path("/opt/casescope/docs/investigation_graph_phase0g_runtime.json")
SCALE_HARNESS_PATH = Path("/opt/casescope/scripts/phase0g_scale_benchmark.py")
RUNTIME_HARNESS_PATH = Path("/opt/casescope/scripts/phase0g_runtime_gate.py")
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

    def test_phase0g_ready_when_mandatory_runtime_gates_pass(self):
        matrix = _matrix()
        criteria = {item["id"]: item for item in matrix["acceptance_criteria"]}
        risk = {item["id"]: item for item in matrix["risks"]}

        self.assertEqual(criteria[33]["status"], "PASS")
        self.assertEqual(risk["R11"]["status"], "PASS")
        self.assertEqual(matrix["regression_results"]["large_case_runtime"]["status"], "PASS")
        self.assertEqual(matrix["regression_results"]["fresh_install_runtime"]["status"], "PASS")
        self.assertEqual(matrix["regression_results"]["upgrade_runtime"]["status"], "PASS")
        self.assertEqual(matrix["final_verdict"], "READY FOR EXTERNAL REVIEW")

    def test_phase0g_matrix_master_checklist_marks_runtime_gates_pass(self):
        matrix = _matrix()
        checklist = {item["id"]: item for item in matrix["master_completion_checklist"]}

        self.assertEqual(checklist[7]["status"], "PASS")
        self.assertEqual(checklist[10]["status"], "PASS")
        self.assertEqual(checklist[11]["status"], "PASS")
        self.assertTrue(all(checklist[item_id]["status"] == "PASS" for item_id in range(1, 17)))

    def test_phase0g_runtime_artifact_records_executed_mandatory_gates(self):
        runtime = json.loads(RUNTIME_PATH.read_text(encoding="utf-8"))

        self.assertIn(runtime["status"], {"PASS", "READY", "READY FOR EXTERNAL REVIEW"})
        self.assertEqual(runtime["scale"]["status"], "PASS")
        self.assertEqual(runtime["fresh_install"]["status"], "PASS")
        self.assertEqual(runtime["lifecycle"]["status"], "PASS")
        self.assertEqual(runtime["permissions"]["status"], "PASS")
        self.assertEqual(runtime["permanent_case_deletion"]["status"], "PASS")

    def test_phase0g_runtime_harnesses_refuse_unmarked_targets(self):
        scale_harness = SCALE_HARNESS_PATH.read_text(encoding="utf-8")
        runtime_harness = RUNTIME_HARNESS_PATH.read_text(encoding="utf-8")

        self.assertIn("PHASE0G_", scale_harness)
        self.assertIn("phase0g_", scale_harness)
        self.assertIn("Refusing Phase 0G runtime benchmark", scale_harness)
        self.assertIn("GitHub REST API", runtime_harness)
        self.assertIn("Fresh Ubuntu 24.04 install validation not executed", runtime_harness)


if __name__ == "__main__":
    unittest.main()
