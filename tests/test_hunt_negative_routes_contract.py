import os
import unittest
from unittest.mock import Mock, patch

from flask import Flask

os.environ.setdefault("SECRET_KEY", "test-secret")

import routes.hunt as hunt_routes


class _DummyUser:
    username = "tester"
    is_authenticated = True


class _Query:
    def __init__(self, result):
        self.result = result

    def get(self, _id):
        return self.result

    def filter_by(self, **_kwargs):
        return self

    def order_by(self, *_args, **_kwargs):
        return self

    def all(self):
        return self.result if isinstance(self.result, list) else [self.result]

    def first(self):
        if isinstance(self.result, list):
            return self.result[0] if self.result else None
        return self.result


class HuntNegativeRoutesContractTestCase(unittest.TestCase):
    def setUp(self):
        self.app = Flask(__name__)
        self.app.secret_key = "test-secret"

    def test_list_and_get_checklist_definitions(self):
        definition = Mock()
        definition.to_dict.return_value = {
            "slug": "file_exfiltration_review",
            "version": "1.0",
        }

        with self.app.test_request_context("/api/hunt-checklists"):
            with patch.object(hunt_routes.HuntChecklistDefinition, "query", _Query([definition])):
                response = hunt_routes.list_hunt_checklists.__wrapped__()

        self.assertEqual(response.get_json()["checklists"][0]["slug"], "file_exfiltration_review")

        with self.app.test_request_context("/api/hunt-checklists/file_exfiltration_review"):
            with patch.object(hunt_routes.HuntChecklistDefinition, "query", _Query(definition)):
                response = hunt_routes.get_hunt_checklist.__wrapped__("file_exfiltration_review")

        self.assertEqual(response.get_json()["checklist"]["version"], "1.0")

    def test_create_checklist_run_calls_trace_service(self):
        run = Mock(id=9, case_id=3)
        checklist_run = Mock()
        checklist_run.to_dict.return_value = {
            "id": 22,
            "checklist_slug": "file_exfiltration_review",
        }

        with self.app.test_request_context(
            "/api/hunt-runs/9/checklists",
            method="POST",
            json={
                "checklist_slug": "file_exfiltration_review",
                "decision_scope": "host",
                "target_metadata": {"target_host": "ATN62288"},
            },
        ):
            with patch.object(hunt_routes, "current_user", _DummyUser()), \
                    patch.object(hunt_routes.HuntRun, "query", _Query(run)), \
                    patch.object(hunt_routes.Case, "get_by_id", return_value=object()), \
                    patch.object(hunt_routes.hunt_trace, "create_checklist_run", return_value=checklist_run) as create_mock:
                response, status = hunt_routes.create_hunt_checklist_run.__wrapped__(9)

        self.assertEqual(status, 201)
        self.assertEqual(response.get_json()["checklist_run"]["id"], 22)
        self.assertEqual(create_mock.call_args.kwargs["hunt_run_id"], 9)
        self.assertEqual(create_mock.call_args.kwargs["created_by"], "tester")
        self.assertEqual(create_mock.call_args.kwargs["target_metadata"]["target_host"], "ATN62288")

    def test_get_and_list_checklist_runs_return_children(self):
        run = Mock(id=9, case_id=3)
        checklist_run = Mock(case_id=3)
        checklist_run.to_dict.return_value = {
            "id": 22,
            "checks": [{"check_key": "archive_staging_check"}],
        }

        with self.app.test_request_context("/api/hunt-runs/9/checklists"):
            with patch.object(hunt_routes.HuntRun, "query", _Query(run)), \
                    patch.object(hunt_routes.Case, "get_by_id", return_value=object()), \
                    patch.object(hunt_routes.hunt_trace, "list_checklist_runs", return_value=[checklist_run]):
                response = hunt_routes.list_hunt_checklist_runs.__wrapped__(9)

        self.assertEqual(response.get_json()["checklist_runs"][0]["checks"][0]["check_key"], "archive_staging_check")

        with self.app.test_request_context("/api/hunt-checklist-runs/22"):
            with patch.object(hunt_routes.HuntChecklistRun, "query", _Query(checklist_run)), \
                    patch.object(hunt_routes.Case, "get_by_id", return_value=object()):
                response = hunt_routes.get_hunt_checklist_run.__wrapped__(22)

        self.assertEqual(response.get_json()["checklist_run"]["id"], 22)
        checklist_run.to_dict.assert_called_with(include_children=True)

    def test_check_update_routes_delegate_to_trace_service(self):
        checklist_run = Mock(case_id=3)
        updated_check = Mock()
        updated_check.to_dict.return_value = {"check_key": "archive_staging_check", "check_status": "completed"}

        with self.app.test_request_context(
            "/api/hunt-checklist-runs/22/checks/archive_staging_check/attach-step",
            method="POST",
            json={"hunt_step_id": 44},
        ):
            with patch.object(hunt_routes.HuntChecklistRun, "query", _Query(checklist_run)), \
                    patch.object(hunt_routes.Case, "get_by_id", return_value=object()), \
                    patch.object(hunt_routes.hunt_trace, "attach_step_to_check", return_value=updated_check) as attach_mock:
                response = hunt_routes.attach_hunt_check_step.__wrapped__(22, "archive_staging_check")

        self.assertEqual(response.get_json()["check"]["check_status"], "completed")
        self.assertEqual(attach_mock.call_args.kwargs["hunt_step_id"], 44)

        with self.app.test_request_context(
            "/api/hunt-checklist-runs/22/checks/large_outbound_transfer_check/source-metadata",
            method="POST",
            json={"source_metadata": {"source_name": "Firewall export"}, "source_availability_status": "partial"},
        ):
            with patch.object(hunt_routes.HuntChecklistRun, "query", _Query(checklist_run)), \
                    patch.object(hunt_routes.Case, "get_by_id", return_value=object()), \
                    patch.object(hunt_routes.hunt_trace, "record_check_source_metadata", return_value=updated_check) as metadata_mock:
                response = hunt_routes.record_hunt_check_source_metadata.__wrapped__(22, "large_outbound_transfer_check")

        self.assertEqual(response.get_json()["check"]["check_key"], "archive_staging_check")
        self.assertEqual(metadata_mock.call_args.kwargs["source_metadata"]["source_name"], "Firewall export")

        with self.app.test_request_context(
            "/api/hunt-checklist-runs/22/checks/browser_upload_or_web_upload_check/not-applicable",
            method="POST",
            json={"reason": "Browser artifacts were not relevant to this scope."},
        ):
            with patch.object(hunt_routes.HuntChecklistRun, "query", _Query(checklist_run)), \
                    patch.object(hunt_routes.Case, "get_by_id", return_value=object()), \
                    patch.object(hunt_routes.hunt_trace, "mark_check_not_applicable", return_value=updated_check) as na_mock:
                response = hunt_routes.mark_hunt_check_not_applicable.__wrapped__(22, "browser_upload_or_web_upload_check")

        self.assertTrue(response.get_json()["success"])
        self.assertIn("Browser artifacts", na_mock.call_args.kwargs["reason"])

    def test_complete_checklist_route_delegates_to_trace_service(self):
        checklist_run = Mock(case_id=3)
        completed = Mock()
        completed.to_dict.return_value = {
            "id": 22,
            "status": "completed",
            "finding_eligible": True,
        }

        with self.app.test_request_context(
            "/api/hunt-checklist-runs/22/complete",
            method="POST",
            json={"coverage_status": "partial", "limitations": ["Network logs incomplete"]},
        ):
            with patch.object(hunt_routes.HuntChecklistRun, "query", _Query(checklist_run)), \
                    patch.object(hunt_routes.Case, "get_by_id", return_value=object()), \
                    patch.object(hunt_routes.hunt_trace, "complete_checklist_run", return_value=completed) as complete_mock:
                response = hunt_routes.complete_hunt_checklist_run.__wrapped__(22)

        self.assertTrue(response.get_json()["checklist_run"]["finding_eligible"])
        self.assertEqual(complete_mock.call_args.kwargs["coverage_status"], "partial")
        self.assertEqual(complete_mock.call_args.kwargs["limitations"], ["Network logs incomplete"])

    def test_negative_finding_draft_route_blocks_when_trace_rejects(self):
        checklist_run = Mock(case_id=3)

        with self.app.test_request_context(
            "/api/hunt-checklist-runs/22/negative-findings/drafts",
            method="POST",
            json={"finding_type": "no_file_exfiltration_identified", "statement": "No exfiltration occurred."},
        ):
            with patch.object(hunt_routes, "current_user", _DummyUser()), \
                    patch.object(hunt_routes.HuntChecklistRun, "query", _Query(checklist_run)), \
                    patch.object(hunt_routes.Case, "get_by_id", return_value=object()), \
                    patch.object(hunt_routes.hunt_trace, "create_negative_finding_draft", side_effect=ValueError("checklist_run is not eligible")):
                response, status = hunt_routes.create_hunt_negative_finding_draft.__wrapped__(22)

        self.assertEqual(status, 400)
        self.assertIn("not eligible", response.get_json()["error"])

    def test_negative_finding_lifecycle_routes_delegate_to_trace_service(self):
        checklist_run = Mock(case_id=3)
        draft = Mock(case_id=3)
        draft.to_dict.return_value = {"id": 30, "finding_state": "draft", "created_by_type": "ai"}
        accepted = Mock()
        accepted.to_dict.return_value = {
            "id": 31,
            "source_finding_id": 30,
            "finding_state": "accepted",
            "created_by_type": "analyst",
            "is_reportable": True,
        }
        rejected = Mock(case_id=3)
        rejected.to_dict.return_value = {"id": 30, "finding_state": "rejected", "review_note": "Too broad"}
        replacement = Mock(case_id=3)
        replacement.to_dict.return_value = {"id": 32, "supersedes_finding_id": 31, "finding_state": "accepted"}

        with self.app.test_request_context(
            "/api/hunt-checklist-runs/22/negative-findings/drafts",
            method="POST",
            json={
                "finding_type": "no_file_exfiltration_identified",
                "statement": "No evidence of file exfiltration was identified in the reviewed artifacts.",
            },
        ):
            with patch.object(hunt_routes, "current_user", _DummyUser()), \
                    patch.object(hunt_routes.HuntChecklistRun, "query", _Query(checklist_run)), \
                    patch.object(hunt_routes.Case, "get_by_id", return_value=object()), \
                    patch.object(hunt_routes.hunt_trace, "create_negative_finding_draft", return_value=draft) as draft_mock:
                response, status = hunt_routes.create_hunt_negative_finding_draft.__wrapped__(22)

        self.assertEqual(status, 201)
        self.assertEqual(response.get_json()["negative_finding"]["finding_state"], "draft")
        self.assertEqual(draft_mock.call_args.kwargs["created_by"], "tester")

        with self.app.test_request_context("/api/hunt-negative-findings/30/accept", method="POST", json={"review_note": "Accept"}):
            with patch.object(hunt_routes, "current_user", _DummyUser()), \
                    patch.object(hunt_routes.HuntNegativeFinding, "query", _Query(draft)), \
                    patch.object(hunt_routes.Case, "get_by_id", return_value=object()), \
                    patch.object(hunt_routes.hunt_trace, "accept_negative_finding", return_value=accepted) as accept_mock:
                response, status = hunt_routes.accept_hunt_negative_finding.__wrapped__(30)

        self.assertEqual(status, 201)
        self.assertTrue(response.get_json()["negative_finding"]["is_reportable"])
        self.assertEqual(accept_mock.call_args.kwargs["reviewed_by"], "tester")

        with self.app.test_request_context("/api/hunt-negative-findings/30/reject", method="POST", json={"review_note": "Too broad"}):
            with patch.object(hunt_routes, "current_user", _DummyUser()), \
                    patch.object(hunt_routes.HuntNegativeFinding, "query", _Query(draft)), \
                    patch.object(hunt_routes.Case, "get_by_id", return_value=object()), \
                    patch.object(hunt_routes.hunt_trace, "reject_negative_finding", return_value=rejected) as reject_mock:
                response = hunt_routes.reject_hunt_negative_finding.__wrapped__(30)

        self.assertEqual(response.get_json()["negative_finding"]["finding_state"], "rejected")
        self.assertEqual(reject_mock.call_args.kwargs["review_note"], "Too broad")

        with self.app.test_request_context(
            "/api/hunt-negative-findings/31/supersede",
            method="POST",
            json={"statement": "No evidence of file exfiltration was identified in the reviewed artifacts."},
        ):
            with patch.object(hunt_routes, "current_user", _DummyUser()), \
                    patch.object(hunt_routes.HuntNegativeFinding, "query", _Query(accepted)), \
                    patch.object(hunt_routes.Case, "get_by_id", return_value=object()), \
                    patch.object(hunt_routes.hunt_trace, "supersede_negative_finding", return_value=replacement) as supersede_mock:
                response, status = hunt_routes.supersede_hunt_negative_finding.__wrapped__(31)

        self.assertEqual(status, 201)
        self.assertEqual(response.get_json()["negative_finding"]["supersedes_finding_id"], 31)
        self.assertEqual(supersede_mock.call_args.kwargs["created_by"], "tester")

    def test_negative_finding_readback_separates_active_and_history(self):
        run = Mock(id=9, case_id=3)
        active = Mock(id=31, finding_state="accepted")
        active.to_dict.return_value = {"id": 31, "finding_state": "accepted", "is_active": True}
        draft = Mock(id=30, finding_state="draft")
        draft.to_dict.return_value = {"id": 30, "finding_state": "draft"}
        rejected = Mock(id=29, finding_state="rejected")
        rejected.to_dict.return_value = {"id": 29, "finding_state": "rejected"}
        superseded = Mock(id=28, finding_state="superseded")
        superseded.to_dict.return_value = {"id": 28, "finding_state": "superseded"}
        run.negative_findings.order_by.return_value.all.return_value = [superseded, rejected, draft, active]

        with self.app.test_request_context("/api/hunt-runs/9/negative-findings?finding_type=no_file_exfiltration_identified"):
            with patch.object(hunt_routes.HuntRun, "query", _Query(run)), \
                    patch.object(hunt_routes.Case, "get_by_id", return_value=object()), \
                    patch.object(hunt_routes.hunt_trace, "get_active_negative_findings", return_value=[active]) as active_mock:
                response = hunt_routes.list_hunt_negative_findings.__wrapped__(9)

        payload = response.get_json()
        self.assertEqual([item["id"] for item in payload["active_findings"]], [31])
        self.assertEqual([item["id"] for item in payload["draft_findings"]], [30])
        self.assertEqual([item["id"] for item in payload["rejected_findings"]], [29])
        self.assertEqual([item["id"] for item in payload["superseded_findings"]], [28])
        self.assertEqual(payload["active_rule"]["checklist_run_status"], "completed")
        self.assertEqual(active_mock.call_args.kwargs["finding_type"], "no_file_exfiltration_identified")


if __name__ == "__main__":
    unittest.main()
