import unittest
import os
from types import SimpleNamespace

os.environ.setdefault("SECRET_KEY", "test-secret")
from utils import hunt_trace


class HuntTraceContractTestCase(unittest.TestCase):
    def test_selector_hash_ignores_existing_hash(self):
        selector = {
            "case_id": 123,
            "source_table": "events",
            "source_file": "Security.evtx",
            "artifact_type": "windows_event",
            "timestamp_utc": "2026-05-06T19:31:02Z",
            "event_id": "4688",
            "record_id": "123456",
            "source_host": "ATN82151",
            "username": "HLA\\SOuimet",
            "selector_hash": "old-value",
        }

        left = hunt_trace.hash_selector(selector)
        selector["selector_hash"] = "different-value"
        right = hunt_trace.hash_selector(selector)

        self.assertEqual(left, right)

    def test_result_fingerprint_is_order_stable(self):
        refs_a = [
            {"selector": {"selector_hash": "b"}},
            {"selector": {"selector_hash": "a"}},
        ]
        refs_b = [
            {"selector": {"selector_hash": "a"}},
            {"selector": {"selector_hash": "b"}},
        ]

        left = hunt_trace.fingerprint_result(
            tool_name="query_events",
            tool_params={"event_id": "4688"},
            result_summary="result_count=2",
            evidence_refs=refs_a,
        )
        right = hunt_trace.fingerprint_result(
            tool_name="query_events",
            tool_params={"event_id": "4688"},
            result_summary="result_count=2",
            evidence_refs=refs_b,
        )

        self.assertEqual(left, right)

    def test_decision_evidence_fingerprint_is_order_stable(self):
        step_a = SimpleNamespace(result_fingerprint="step-b")
        step_b = SimpleNamespace(result_fingerprint="step-a")
        ref_a = SimpleNamespace(selector_hash="selector-b")
        ref_b = SimpleNamespace(selector_hash="selector-a")
        links_a = [
            {"step": step_a, "evidence_ref": ref_a},
            {"step": step_b, "evidence_ref": ref_b},
        ]
        links_b = [
            {"step": step_b, "evidence_ref": ref_b},
            {"step": step_a, "evidence_ref": ref_a},
        ]

        left = hunt_trace.fingerprint_decision_evidence(links_a)
        right = hunt_trace.fingerprint_decision_evidence(links_b)

        self.assertEqual(left, right)

    def test_extract_evidence_refs_normalizes_main_tool_shapes(self):
        refs, warnings = hunt_trace.extract_evidence_refs(
            case_id=123,
            tool_name="query_events",
            result_payload={
                "events": [
                    {
                        "timestamp": "2026-05-06 19:31:02",
                        "event_id": "4688",
                        "host": "ATN82151",
                        "user": "HLA\\SOuimet",
                        "source_file": "Security.evtx",
                        "summary": "powershell.exe launched",
                    }
                ]
            },
        )

        self.assertEqual(warnings, [])
        self.assertEqual(len(refs), 1)
        selector = refs[0]["selector"]
        self.assertEqual(selector["case_id"], 123)
        self.assertEqual(selector["source_table"], "events")
        self.assertEqual(selector["event_id"], "4688")
        self.assertEqual(selector["source_host"], "ATN82151")
        self.assertTrue(selector["selector_hash"])


if __name__ == "__main__":
    unittest.main()
