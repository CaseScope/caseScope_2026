import json
from pathlib import Path


MATRIX_PATH = Path("/opt/casescope/docs/investigation_graph_phase0g_matrix.json")
VALID_STATUSES = {"PASS", "FAIL", "APPROVED_EXCLUSION", "NOT_APPLICABLE"}


def _matrix():
    return json.loads(MATRIX_PATH.read_text(encoding="utf-8"))


def test_phase0g_matrix_covers_all_acceptance_criteria_and_uses_closed_statuses():
    matrix = _matrix()
    criteria = {item["id"]: item for item in matrix["acceptance_criteria"]}

    assert set(criteria) == set(range(1, 61))
    assert {item["status"] for item in criteria.values()} <= VALID_STATUSES
    assert all(criteria[item_id]["status"] == "PASS" for item_id in range(42, 61))


def test_phase0g_approved_exclusions_are_explicit_and_limited_to_locked_contracts():
    matrix = _matrix()
    exclusions = {item["acceptance_criterion"]: item for item in matrix["approved_exclusions"]}

    assert set(exclusions) == {9, 15, 16}
    for item in exclusions.values():
        assert item["missing_contract"]
        assert item["negative_tests"]
        assert item["future_prerequisites"]


def test_phase0g_not_ready_while_mandatory_runtime_gates_are_missing():
    matrix = _matrix()
    criteria = {item["id"]: item for item in matrix["acceptance_criteria"]}
    risk = {item["id"]: item for item in matrix["risks"]}

    assert criteria[33]["status"] == "FAIL"
    assert risk["R11"]["status"] == "FAIL"
    assert matrix["regression_results"]["large_case_runtime"]["status"] == "FAIL"
    assert matrix["regression_results"]["fresh_install_runtime"]["status"] == "FAIL"
    assert matrix["regression_results"]["upgrade_runtime"]["status"] == "FAIL"
    assert matrix["final_verdict"] == "NOT READY"
