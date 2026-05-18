import unittest
import os
from contextlib import contextmanager
from types import SimpleNamespace
from unittest.mock import patch

os.environ.setdefault("SECRET_KEY", "test-secret")
from models.hunt import HuntCreatedByType, HuntDecision, HuntDecisionState, HuntEvidenceRef, HuntRun, HuntStep
from utils import hunt_trace


class _DummySession:
    def __init__(self):
        self.added = []
        self.next_id = 1000
        self.commits = 0

    def add(self, item):
        self.added.append(item)

    def flush(self):
        for item in self.added:
            if hasattr(item, "id") and getattr(item, "id", None) is None:
                item.id = self.next_id
                self.next_id += 1

    def commit(self):
        self.commits += 1


class _QueryById:
    def __init__(self, items):
        self.items = {int(item.id): item for item in items if getattr(item, "id", None) is not None}

    def get(self, item_id):
        return self.items.get(int(item_id))


class _DecisionQuery:
    def __init__(self, decisions):
        self.decisions = list(decisions)

    def filter_by(self, **kwargs):
        self.decisions = [
            decision for decision in self.decisions
            if all(getattr(decision, key) == value for key, value in kwargs.items())
        ]
        return self

    def filter(self, *_args, **_kwargs):
        return self

    def order_by(self, *_args, **_kwargs):
        self.decisions.sort(key=lambda decision: (decision.created_at is None, decision.id or 0), reverse=True)
        return self

    def all(self):
        return self.decisions


@contextmanager
def _patched_hunt_queries(*, runs=None, steps=None, refs=None, decisions=None):
    patches = {
        hunt_trace.HuntRun: _QueryById(runs or []),
        hunt_trace.HuntStep: _QueryById(steps or []),
        hunt_trace.HuntEvidenceRef: _QueryById(refs or []),
        hunt_trace.HuntDecision: _QueryById(decisions or []),
    }
    originals = {}
    missing = set()
    for model, query in patches.items():
        if "query" in model.__dict__:
            originals[model] = model.__dict__["query"]
        else:
            missing.add(model)
        setattr(model, "query", query)
    try:
        yield
    finally:
        for model in patches:
            if model in missing:
                delattr(model, "query")
            else:
                setattr(model, "query", originals[model])


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

    def test_ai_draft_accept_supersede_and_reject_lifecycle(self):
        run = HuntRun(id=1, case_id=123, objective="Phase 2.5 smoke")
        step = HuntStep(id=10, hunt_run_id=1, step_number=1, tool_name="query_events", result_fingerprint="step-fp")
        evidence_ref = HuntEvidenceRef(id=20, hunt_step_id=10, case_id=123, selector_hash="selector-fp", summary="ScreenConnect service")
        evidence_ref.step = step
        session = _DummySession()

        with _patched_hunt_queries(runs=[run], steps=[step], refs=[evidence_ref]), \
                patch.object(hunt_trace.db, "session", session):
            draft = hunt_trace.create_decision(
                hunt_run_id=1,
                decision_state="draft",
                created_by_type="ai",
                created_by="chat_agent",
                classification="suspicious",
                decision_scope="host",
                target_host="ATN62288",
                confidence=0.7,
                rationale="AI draft",
                evidence_links=[{"hunt_step_id": 10, "hunt_evidence_ref_id": 20, "support_role": "primary"}],
            )

        self.assertEqual(draft.decision_state, HuntDecisionState.DRAFT)
        self.assertEqual(draft.created_by_type, HuntCreatedByType.AI)
        self.assertFalse(draft.is_authoritative)
        self.assertEqual(draft.target_host, "ATN62288")
        self.assertEqual(draft.to_dict()["decision_scope"], "host")
        self.assertTrue(draft.evidence_fingerprint)

        with _patched_hunt_queries(runs=[run], steps=[step], refs=[evidence_ref], decisions=[draft]), \
                patch.object(hunt_trace.db, "session", session):
            accepted = hunt_trace.accept_decision(
                draft.id,
                reviewed_by="analyst",
                review_note="Accepted from real trace evidence",
                evidence_links=[{"hunt_step_id": 10, "hunt_evidence_ref_id": 20, "support_role": "primary"}],
            )

        self.assertEqual(draft.decision_state, HuntDecisionState.DRAFT)
        self.assertFalse(draft.is_authoritative)
        self.assertEqual(draft.reviewed_by, "analyst")
        self.assertEqual(accepted.source_decision_id, draft.id)
        self.assertEqual(accepted.decision_state, HuntDecisionState.ACCEPTED)
        self.assertEqual(accepted.created_by_type, HuntCreatedByType.ANALYST)
        self.assertTrue(accepted.is_authoritative)

        with _patched_hunt_queries(runs=[run], steps=[step], refs=[evidence_ref], decisions=[accepted]), \
                patch.object(hunt_trace.db, "session", session):
            replacement = hunt_trace.supersede_decision(
                accepted.id,
                created_by="analyst",
                classification="malicious",
                rationale="Escalated after review",
                evidence_links=[{"hunt_step_id": 10, "hunt_evidence_ref_id": 20, "support_role": "primary"}],
            )

        self.assertEqual(accepted.decision_state, HuntDecisionState.SUPERSEDED)
        self.assertEqual(accepted.superseded_by_decision_id, replacement.id)
        self.assertFalse(accepted.is_authoritative)
        self.assertEqual(replacement.supersedes_decision_id, accepted.id)
        self.assertTrue(replacement.is_authoritative)

        draft.hunt_run = run
        with _patched_hunt_queries(decisions=[draft]), \
                patch.object(hunt_trace.db, "session", session):
            rejected = hunt_trace.reject_decision(draft.id, reviewed_by="analyst", review_note="Rejected duplicate draft")

        self.assertEqual(rejected.decision_state, HuntDecisionState.REJECTED)
        self.assertFalse(rejected.is_authoritative)

    def test_accepted_decisions_require_valid_same_run_evidence_links(self):
        run = HuntRun(id=1, case_id=123, objective="Validate evidence links")
        step = HuntStep(id=10, hunt_run_id=1, step_number=1, tool_name="query_events")
        mismatch_step = HuntStep(id=12, hunt_run_id=1, step_number=2, tool_name="query_events")
        other_step = HuntStep(id=11, hunt_run_id=2, step_number=1, tool_name="query_events")
        evidence_ref = HuntEvidenceRef(id=20, hunt_step_id=10, case_id=123, selector_hash="selector-fp")
        evidence_ref.step = step
        other_run_ref = HuntEvidenceRef(id=21, hunt_step_id=11, case_id=123, selector_hash="other-run")
        other_run_ref.step = other_step
        wrong_case_ref = HuntEvidenceRef(id=22, hunt_step_id=10, case_id=456, selector_hash="wrong-case")
        wrong_case_ref.step = step

        with _patched_hunt_queries(
                runs=[run],
                steps=[step, mismatch_step, other_step],
                refs=[evidence_ref, other_run_ref, wrong_case_ref],
        ), patch.object(hunt_trace.db, "session", _DummySession()):
            with self.assertRaisesRegex(ValueError, "accepted decisions require at least one evidence link"):
                hunt_trace.create_decision(
                    hunt_run_id=1,
                    decision_state="accepted",
                    created_by_type="analyst",
                    created_by="analyst",
                    classification="suspicious",
                )

            with self.assertRaisesRegex(ValueError, "hunt_step_id does not belong to hunt_run_id"):
                hunt_trace.create_decision(
                    hunt_run_id=1,
                    decision_state="accepted",
                    created_by_type="analyst",
                    created_by="analyst",
                    classification="suspicious",
                    evidence_links=[{"hunt_step_id": 11}],
                )

            with self.assertRaisesRegex(ValueError, "hunt_evidence_ref_id does not belong to hunt_run_id"):
                hunt_trace.create_decision(
                    hunt_run_id=1,
                    decision_state="accepted",
                    created_by_type="analyst",
                    created_by="analyst",
                    classification="suspicious",
                    evidence_links=[{"hunt_evidence_ref_id": 21}],
                )

            with self.assertRaisesRegex(ValueError, "hunt_evidence_ref_id does not belong to case_id"):
                hunt_trace.create_decision(
                    hunt_run_id=1,
                    decision_state="accepted",
                    created_by_type="analyst",
                    created_by="analyst",
                    classification="suspicious",
                    evidence_links=[{"hunt_evidence_ref_id": 22}],
                )

            with self.assertRaisesRegex(ValueError, "hunt_evidence_ref_id does not belong to hunt_step_id"):
                hunt_trace.create_decision(
                    hunt_run_id=1,
                    decision_state="accepted",
                    created_by_type="analyst",
                    created_by="analyst",
                    classification="suspicious",
                    evidence_links=[{"hunt_step_id": 12, "hunt_evidence_ref_id": 20}],
                )

    def test_scope_targets_and_active_authoritative_filter_contract(self):
        run = HuntRun(id=1, case_id=123, objective="Target filtering")
        step = HuntStep(id=10, hunt_run_id=1, step_number=1, tool_name="query_events")
        evidence_ref = HuntEvidenceRef(id=20, hunt_step_id=10, case_id=123, selector_hash="selector-fp")
        evidence_ref.step = step

        with _patched_hunt_queries(runs=[run], steps=[step], refs=[evidence_ref]), \
                patch.object(hunt_trace.db, "session", _DummySession()):
            with self.assertRaisesRegex(ValueError, "target field required for non-case decision_scope"):
                hunt_trace.create_decision(
                    hunt_run_id=1,
                    decision_state="draft",
                    created_by_type="ai",
                    classification="suspicious",
                    decision_scope="host",
                )

            active = hunt_trace.create_decision(
                hunt_run_id=1,
                decision_state="accepted",
                created_by_type="analyst",
                created_by="analyst",
                classification="suspicious",
                decision_scope="host",
                target_host="ATN62288",
                evidence_links=[{"hunt_step_id": 10, "hunt_evidence_ref_id": 20}],
            )

        rejected = HuntDecision(
            id=2000,
            hunt_run_id=1,
            case_id=123,
            decision_state=HuntDecisionState.REJECTED,
            created_by_type=HuntCreatedByType.AI,
            classification="suspicious",
            decision_scope="host",
            target_host="ATN62288",
        )
        superseded = HuntDecision(
            id=2001,
            hunt_run_id=1,
            case_id=123,
            decision_state=HuntDecisionState.ACCEPTED,
            created_by_type=HuntCreatedByType.ANALYST,
            classification="benign",
            decision_scope="host",
            target_host="ATN62288",
            superseded_by_decision_id=active.id,
        )

        old_query = hunt_trace.HuntDecision.__dict__.get("query")
        had_query = "query" in hunt_trace.HuntDecision.__dict__
        hunt_trace.HuntDecision.query = _DecisionQuery([active, rejected, superseded])
        try:
            active_rows = hunt_trace.active_authoritative_decisions(
                hunt_run_id=1,
                case_id=123,
                decision_scope="host",
                target_filters={"target_host": "ATN62288"},
            )
        finally:
            if had_query:
                hunt_trace.HuntDecision.query = old_query
            else:
                delattr(hunt_trace.HuntDecision, "query")

        self.assertEqual([decision.id for decision in active_rows], [active.id])
        self.assertTrue(active.to_dict()["is_authoritative"])
        self.assertEqual(active.to_dict()["target_host"], "ATN62288")


if __name__ == "__main__":
    unittest.main()
