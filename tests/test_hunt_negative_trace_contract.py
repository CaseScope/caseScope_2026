import os
import unittest
from contextlib import contextmanager
from unittest.mock import patch

os.environ.setdefault("SECRET_KEY", "test-secret")

from models.hunt import (
    HuntChecklistCheck,
    HuntChecklistCheckStatus,
    HuntChecklistDefinition,
    HuntChecklistRun,
    HuntChecklistRunStatus,
    HuntCoverageStatus,
    HuntCreatedByType,
    HuntNegativeFinding,
    HuntNegativeFindingState,
    HuntNegativeFindingType,
    HuntRun,
    HuntSourceAvailabilityStatus,
    HuntStep,
)
from utils import hunt_checklist_templates, hunt_trace


class _DummySession:
    def __init__(self):
        self.added = []
        self.next_id = 1000
        self.commits = 0
        self.flushes = 0

    def add(self, item):
        self.added.append(item)

    def flush(self):
        self.flushes += 1
        for item in self.added:
            if hasattr(item, "id") and getattr(item, "id", None) is None:
                item.id = self.next_id
                self.next_id += 1

    def commit(self):
        self.commits += 1


class _Query:
    def __init__(self, items):
        self.items = list(items or [])

    def get(self, item_id):
        for item in self.items:
            if getattr(item, "id", None) == int(item_id):
                return item
        return None

    def filter_by(self, **kwargs):
        return _Query([
            item for item in self.items
            if all(getattr(item, key, None) == value for key, value in kwargs.items())
        ])

    def first(self):
        return self.items[0] if self.items else None

    def all(self):
        return list(self.items)

    def order_by(self, *_args, **_kwargs):
        return self


@contextmanager
def _patched_queries(
    *,
    runs=None,
    definitions=None,
    checklist_runs=None,
    checks=None,
    steps=None,
    findings=None,
):
    patches = {
        hunt_trace.HuntRun: _Query(runs or []),
        hunt_trace.HuntChecklistDefinition: _Query(definitions or []),
        hunt_trace.HuntChecklistRun: _Query(checklist_runs or []),
        hunt_trace.HuntChecklistCheck: _Query(checks or []),
        hunt_trace.HuntStep: _Query(steps or []),
        hunt_trace.HuntNegativeFinding: _Query(findings or []),
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


def _definition(slug="file_exfiltration_review"):
    definition_json = hunt_checklist_templates.get_checklist_definition(slug)
    return HuntChecklistDefinition(
        id=10,
        slug=definition_json["slug"],
        version=definition_json["version"],
        display_name=definition_json["display_name"],
        is_active=True,
        definition_json=definition_json,
    )


def _checklist_run(definition, *, coverage=HuntCoverageStatus.COMPLETE, limitations=None, eligible=False):
    return HuntChecklistRun(
        id=100,
        case_id=123,
        hunt_run_id=1,
        checklist_definition_id=definition.id,
        checklist_slug=definition.slug,
        checklist_version=definition.version,
        definition_snapshot_json=definition.definition_json,
        status=HuntChecklistRunStatus.COMPLETED if eligible else HuntChecklistRunStatus.IN_PROGRESS,
        coverage_status=coverage,
        finding_eligible=eligible,
        finding_block_reasons_json=[],
        missing_sources_json=[],
        limitations_json=limitations or [],
        target_metadata_json={"decision_scope": "host", "target_host": "ATN62288"},
    )


def _checks_for(definition, checklist_run, completed=True):
    checks = []
    for idx, check_definition in enumerate(definition.definition_json["required_checks"], start=1):
        check = HuntChecklistCheck(
            id=200 + idx,
            case_id=checklist_run.case_id,
            hunt_run_id=checklist_run.hunt_run_id,
            checklist_run_id=checklist_run.id,
            check_key=check_definition["key"],
            check_name=check_definition["name"],
            check_status=HuntChecklistCheckStatus.PENDING,
            coverage_status=HuntCoverageStatus.UNKNOWN,
            source_availability_status=HuntSourceAvailabilityStatus.UNKNOWN,
        )
        if completed:
            if check_definition["type"] == "source_metadata":
                check.check_status = HuntChecklistCheckStatus.COMPLETED
                check.source_availability_status = HuntSourceAvailabilityStatus.AVAILABLE
                check.source_metadata_json = {
                    "source_name": "Firewall export",
                    "reviewed_time_start": "2026-05-14T00:00:00Z",
                    "reviewed_time_end": "2026-05-15T00:00:00Z",
                    "review_summary": "Reviewed for large outbound sessions.",
                }
            else:
                check.check_status = HuntChecklistCheckStatus.COMPLETED
                check.hunt_step_id = 500 + idx
                check.source_availability_status = HuntSourceAvailabilityStatus.AVAILABLE
                if check_definition.get("source_metadata_required"):
                    check.source_metadata_json = {
                        "source_table": "network_logs",
                        "reviewed_time_start": "2026-05-14T00:00:00Z",
                        "reviewed_time_end": "2026-05-15T00:00:00Z",
                        "reviewed_pcap_ids": [12],
                        "reviewed_log_types": ["conn"],
                        "available_log_types": ["conn"],
                        "source_availability_status": HuntSourceAvailabilityStatus.AVAILABLE,
                        "limitations": [],
                    }
        checks.append(check)
    return checks


def _network_step(
    *,
    step_id=900,
    result_count=0,
    total=0,
    returned_count=0,
    truncated=False,
    source_metadata=True,
    source_availability_status=HuntSourceAvailabilityStatus.AVAILABLE,
):
    coverage_detail = {
        "result_metadata": {
            "total": total,
            "returned_count": returned_count,
            "truncated": truncated,
        }
    }
    if source_metadata:
        coverage_detail["source_metadata"] = {
            "source_table": "network_logs",
            "reviewed_time_start": "2026-05-14T19:50:04Z",
            "reviewed_time_end": "2026-05-14T20:01:24Z",
            "reviewed_pcap_ids": [12],
            "reviewed_log_types": ["conn", "dns"],
            "available_log_types": ["conn", "dns", "ssl"],
            "source_availability_status": source_availability_status,
            "missing_sources": [],
            "limitations": [],
        }
    step = HuntStep(
        id=step_id,
        hunt_run_id=1,
        step_number=1,
        tool_name="search_network_logs",
        coverage_status=HuntCoverageStatus.COMPLETE,
        result_count=result_count,
        result_summary=(
            "total={}; returned={}; log_type=all; pcap_id=12; "
            "time_start=2026-05-14T19:50:04Z; time_end=2026-05-14T20:01:24Z; search=screenconnect"
        ).format(total, returned_count),
        coverage_detail_json=coverage_detail,
    )
    step.hunt_run = HuntRun(id=1, case_id=123, objective="File exfiltration review")
    return step


class HuntNegativeTraceContractTestCase(unittest.TestCase):
    def test_create_checklist_run_snapshots_definition_and_required_checks(self):
        definition = _definition("ransomware_preparation_review")
        run = HuntRun(id=1, case_id=123, objective="Ransomware prep review")
        session = _DummySession()

        with _patched_queries(runs=[run], definitions=[definition]), patch.object(hunt_trace.db, "session", session):
            checklist_run = hunt_trace.create_checklist_run(
                hunt_run_id=1,
                checklist_slug="ransomware_preparation_review",
                decision_scope="host",
                target_metadata={"target_host": "ATN62288"},
                created_by="analyst",
            )

        self.assertEqual(checklist_run.definition_snapshot_json["slug"], "ransomware_preparation_review")
        self.assertEqual(checklist_run.target_metadata_json["decision_scope"], "host")
        self.assertEqual(checklist_run.target_metadata_json["target_host"], "ATN62288")
        created_checks = [item for item in session.added if isinstance(item, HuntChecklistCheck)]
        self.assertEqual(
            len(created_checks),
            len(definition.definition_json["required_checks"]),
        )
        self.assertTrue(all(check.check_status == HuntChecklistCheckStatus.PENDING for check in created_checks))

    def test_check_updates_enforce_step_linkage_and_source_metadata(self):
        definition = _definition("file_exfiltration_review")
        checklist_run = _checklist_run(definition)
        checks = _checks_for(definition, checklist_run, completed=False)
        archive_check = next(check for check in checks if check.check_key == "archive_staging_check")
        outbound_check = next(check for check in checks if check.check_key == "large_outbound_transfer_check")
        step = HuntStep(
            id=501,
            hunt_run_id=1,
            step_number=1,
            tool_name="get_processes",
            coverage_status=HuntCoverageStatus.COMPLETE,
            result_count=0,
            result_summary="result_count=0",
        )
        step.hunt_run = HuntRun(id=1, case_id=123, objective="File exfiltration review")
        network_step = HuntStep(
            id=502,
            hunt_run_id=1,
            step_number=2,
            tool_name="search_network_logs",
            coverage_status=HuntCoverageStatus.COMPLETE,
            coverage_detail_json={
                "source_metadata": {
                    "source_table": "network_logs",
                    "reviewed_time_start": "2026-05-14T00:00:00Z",
                    "reviewed_time_end": "2026-05-15T00:00:00Z",
                    "reviewed_pcap_ids": [12],
                    "reviewed_log_types": ["conn"],
                    "available_log_types": ["conn"],
                    "source_availability_status": HuntSourceAvailabilityStatus.AVAILABLE,
                    "limitations": [],
                },
                "result_metadata": {
                    "total": 0,
                    "returned_count": 0,
                    "truncated": False,
                },
            },
            result_count=0,
            result_summary="total=0; returned=0; log_type=conn",
        )
        network_step.hunt_run = HuntRun(id=1, case_id=123, objective="File exfiltration review")

        with _patched_queries(
            checklist_runs=[checklist_run],
            checks=[archive_check, outbound_check],
            steps=[step, network_step],
        ), patch.object(hunt_trace.db, "session", _DummySession()):
            updated = hunt_trace.attach_step_to_check(
                checklist_run_id=100,
                check_key="archive_staging_check",
                hunt_step_id=501,
            )
            source_updated = hunt_trace.attach_step_to_check(
                checklist_run_id=100,
                check_key="large_outbound_transfer_check",
                hunt_step_id=502,
            )

        self.assertEqual(updated.check_status, HuntChecklistCheckStatus.COMPLETED)
        self.assertEqual(updated.hunt_step_id, 501)
        self.assertEqual(source_updated.check_status, HuntChecklistCheckStatus.COMPLETED)
        self.assertEqual(source_updated.source_availability_status, HuntSourceAvailabilityStatus.AVAILABLE)
        self.assertEqual(source_updated.hunt_step_id, 502)
        self.assertEqual(source_updated.source_metadata_json["source_table"], "network_logs")
        self.assertEqual(source_updated.source_metadata_json["reviewed_time_start"], "2026-05-14T00:00:00Z")

    def test_complete_checklist_distinguishes_completion_from_eligibility(self):
        definition = _definition("file_exfiltration_review")
        checklist_run = _checklist_run(definition, coverage=HuntCoverageStatus.PARTIAL)
        checks = _checks_for(definition, checklist_run, completed=True)

        with _patched_queries(checklist_runs=[checklist_run], checks=checks), patch.object(hunt_trace.db, "session", _DummySession()):
            completed = hunt_trace.complete_checklist_run(
                checklist_run,
                coverage_status=HuntCoverageStatus.PARTIAL,
                missing_sources=["network logs incomplete"],
                limitations=[],
            )

        self.assertEqual(completed.status, HuntChecklistRunStatus.COMPLETED)
        self.assertFalse(completed.finding_eligible)
        self.assertEqual(
            completed.finding_block_reasons_json[0]["code"],
            "mandatory_limitation_missing",
        )

    def test_negative_finding_lifecycle_requires_templates_and_analyst_acceptance(self):
        definition = _definition("file_exfiltration_review")
        checklist_run = _checklist_run(
            definition,
            coverage=HuntCoverageStatus.PARTIAL,
            limitations=["network, proxy, firewall, or remote-access transfer logs were incomplete"],
        )
        checks = _checks_for(definition, checklist_run, completed=True)
        statement = definition.definition_json["allowed_language_by_coverage"]["partial"][0]["statement"]
        session = _DummySession()

        with _patched_queries(checklist_runs=[checklist_run], checks=checks), patch.object(hunt_trace.db, "session", session):
            completed = hunt_trace.complete_checklist_run(checklist_run)
            draft = hunt_trace.create_negative_finding_draft(
                checklist_run_id=100,
                finding_type=HuntNegativeFindingType.NO_FILE_EXFILTRATION_IDENTIFIED,
                statement=statement,
                created_by_type=HuntCreatedByType.AI,
                created_by="chat_agent",
            )

        self.assertTrue(completed.finding_eligible)
        self.assertEqual(draft.finding_state, HuntNegativeFindingState.DRAFT)
        self.assertFalse(draft.is_reportable)
        self.assertEqual(draft.language_template_key, "partial_network_limited")

        with _patched_queries(
            checklist_runs=[checklist_run],
            checks=checks,
            findings=[draft],
        ), patch.object(hunt_trace.db, "session", session):
            accepted = hunt_trace.accept_negative_finding(
                draft,
                reviewed_by="analyst",
                review_note="Accepted bounded statement",
            )

        self.assertEqual(accepted.source_finding_id, draft.id)
        self.assertEqual(accepted.created_by_type, HuntCreatedByType.ANALYST)
        self.assertTrue(accepted.is_active)
        self.assertTrue(accepted.is_reportable)

    def test_negative_finding_reject_supersede_and_active_filter(self):
        definition = _definition("ransomware_preparation_review")
        checklist_run = _checklist_run(definition, coverage=HuntCoverageStatus.COMPLETE, eligible=True)
        checks = _checks_for(definition, checklist_run, completed=True)
        statement = definition.definition_json["allowed_language_by_coverage"]["complete"][0]["statement"]
        replacement_statement = statement
        draft = HuntNegativeFinding(
            id=300,
            case_id=123,
            hunt_run_id=1,
            checklist_run_id=100,
            finding_state=HuntNegativeFindingState.DRAFT,
            finding_type=HuntNegativeFindingType.NO_RANSOMWARE_PREPARATION_IDENTIFIED,
            statement=statement,
            coverage_status=HuntCoverageStatus.COMPLETE,
            created_by_type=HuntCreatedByType.AI,
            language_template_key="complete_standard",
        )
        draft.checklist_run = checklist_run
        accepted = HuntNegativeFinding(
            id=301,
            case_id=123,
            hunt_run_id=1,
            checklist_run_id=100,
            finding_state=HuntNegativeFindingState.ACCEPTED,
            finding_type=HuntNegativeFindingType.NO_RANSOMWARE_PREPARATION_IDENTIFIED,
            statement=statement,
            coverage_status=HuntCoverageStatus.COMPLETE,
            created_by_type=HuntCreatedByType.ANALYST,
            language_template_key="complete_standard",
        )
        accepted.checklist_run = checklist_run
        session = _DummySession()

        with _patched_queries(
            checklist_runs=[checklist_run],
            checks=checks,
            findings=[draft, accepted],
        ), patch.object(hunt_trace.db, "session", session):
            rejected = hunt_trace.reject_negative_finding(draft, reviewed_by="analyst", review_note="Too broad")
            replacement = hunt_trace.supersede_negative_finding(
                accepted,
                created_by="analyst",
                statement=replacement_statement,
                review_note="Updated review language",
            )

        with _patched_queries(findings=[draft, accepted, replacement]):
            active_rows = hunt_trace.get_active_negative_findings(
                hunt_run_id=1,
                case_id=123,
                finding_type=HuntNegativeFindingType.NO_RANSOMWARE_PREPARATION_IDENTIFIED,
            )

        self.assertEqual(rejected.finding_state, HuntNegativeFindingState.REJECTED)
        self.assertEqual(accepted.finding_state, HuntNegativeFindingState.SUPERSEDED)
        self.assertEqual(accepted.superseded_by_finding_id, replacement.id)
        self.assertEqual(replacement.supersedes_finding_id, accepted.id)
        self.assertEqual([finding.id for finding in active_rows], [replacement.id])

    def test_unapproved_or_insufficient_language_is_rejected(self):
        definition = _definition("direct_lateral_movement_review")
        checklist_run = _checklist_run(definition, coverage=HuntCoverageStatus.INSUFFICIENT)
        checks = _checks_for(definition, checklist_run, completed=True)

        with _patched_queries(checklist_runs=[checklist_run], checks=checks), patch.object(hunt_trace.db, "session", _DummySession()):
            completed = hunt_trace.complete_checklist_run(checklist_run)
            with self.assertRaisesRegex(ValueError, "not eligible"):
                hunt_trace.create_negative_finding_draft(
                    checklist_run_id=100,
                    finding_type=HuntNegativeFindingType.NO_DIRECT_LATERAL_MOVEMENT_IDENTIFIED,
                    statement="No lateral movement occurred.",
                    created_by_type=HuntCreatedByType.AI,
                )

        self.assertFalse(completed.finding_eligible)
        self.assertIn("coverage_insufficient", [reason["code"] for reason in completed.finding_block_reasons_json])

    def test_network_logs_extractors_preserve_network_selectors_and_total(self):
        payload = {
            "logs": [{
                "timestamp": "2026-05-14T12:00:00Z",
                "uid": "C8F2",
                "pcap_id": 12,
                "log_type": "http",
                "source_host": "sensor-1",
                "src_ip": "10.0.0.5",
                "src_port": 51515,
                "dst_ip": "203.0.113.10",
                "dst_port": 443,
                "uri": "/upload",
            }],
            "total": 7,
            "returned_count": 1,
        }

        refs, warnings = hunt_trace.extract_evidence_refs(
            case_id=123,
            tool_name="search_network_logs",
            result_payload=payload,
        )

        self.assertEqual(warnings, [])
        self.assertEqual(len(refs), 1)
        selector = refs[0]["selector"]
        self.assertEqual(selector["source_table"], "network_logs")
        self.assertEqual(selector["source_id"], "C8F2")
        self.assertEqual(selector["pcap_id"], 12)
        self.assertEqual(selector["log_type"], "http")
        self.assertEqual(selector["src_ip"], "10.0.0.5")
        self.assertEqual(selector["dst_port"], 443)
        self.assertEqual(hunt_trace._result_count(payload, refs), 7)

    def test_network_absence_check_blocks_when_results_or_missing_source_metadata(self):
        definition = _definition("file_exfiltration_review")
        checklist_run = _checklist_run(definition, coverage=HuntCoverageStatus.COMPLETE)
        checks = _checks_for(definition, checklist_run, completed=True)
        outbound_check = next(check for check in checks if check.check_key == "large_outbound_transfer_check")
        outbound_check.hunt_step_id = 900
        network_step = HuntStep(
            id=900,
            hunt_run_id=1,
            step_number=1,
            tool_name="search_network_logs",
            coverage_status=HuntCoverageStatus.COMPLETE,
            result_count=2,
            coverage_detail_json={
                "result_metadata": {"total": 2, "returned_count": 2, "truncated": False}
            },
        )

        with _patched_queries(checklist_runs=[checklist_run], checks=checks, steps=[network_step]):
            eligibility = hunt_trace.calculate_finding_eligibility(checklist_run)

        reason_codes = [reason["code"] for reason in eligibility["block_reasons"]]
        self.assertFalse(eligibility["finding_eligible"])
        self.assertIn("network_absence_query_has_results", reason_codes)

    def test_network_zero_result_with_time_bounds_and_source_metadata_is_eligible(self):
        definition = _definition("file_exfiltration_review")
        checklist_run = _checklist_run(definition, coverage=HuntCoverageStatus.COMPLETE)
        checks = _checks_for(definition, checklist_run, completed=True)
        outbound_check = next(check for check in checks if check.check_key == "large_outbound_transfer_check")
        network_step = _network_step(result_count=0, total=0, returned_count=0)
        outbound_check.hunt_step_id = network_step.id
        outbound_check.result_count = network_step.result_count
        outbound_check.result_summary = network_step.result_summary
        outbound_check.source_metadata_json = network_step.coverage_detail_json["source_metadata"]
        statement = definition.definition_json["allowed_language_by_coverage"]["complete"][0]["statement"]

        with _patched_queries(checklist_runs=[checklist_run], checks=checks, steps=[network_step]), \
             patch.object(hunt_trace.db, "session", _DummySession()):
            completed = hunt_trace.complete_checklist_run(checklist_run)
            draft = hunt_trace.create_negative_finding_draft(
                checklist_run_id=100,
                finding_type=HuntNegativeFindingType.NO_FILE_EXFILTRATION_IDENTIFIED,
                statement=statement,
                created_by_type=HuntCreatedByType.AI,
                created_by="chat_agent",
            )

        self.assertTrue(completed.finding_eligible)
        self.assertEqual(completed.finding_block_reasons_json, [])
        self.assertEqual(draft.statement, statement)

    def test_network_absence_check_blocks_when_source_metadata_is_missing(self):
        definition = _definition("file_exfiltration_review")
        checklist_run = _checklist_run(definition, coverage=HuntCoverageStatus.COMPLETE)
        checks = _checks_for(definition, checklist_run, completed=True)
        outbound_check = next(check for check in checks if check.check_key == "large_outbound_transfer_check")
        network_step = _network_step(source_metadata=False)
        outbound_check.hunt_step_id = network_step.id
        outbound_check.source_metadata_json = {}

        with _patched_queries(checklist_runs=[checklist_run], checks=checks, steps=[network_step]):
            eligibility = hunt_trace.calculate_finding_eligibility(checklist_run)

        reason_codes = [reason["code"] for reason in eligibility["block_reasons"]]
        self.assertFalse(eligibility["finding_eligible"])
        self.assertIn("source_metadata_not_documented", reason_codes)

    def test_network_absence_check_blocks_when_results_are_truncated(self):
        definition = _definition("file_exfiltration_review")
        checklist_run = _checklist_run(definition, coverage=HuntCoverageStatus.COMPLETE)
        checks = _checks_for(definition, checklist_run, completed=True)
        outbound_check = next(check for check in checks if check.check_key == "large_outbound_transfer_check")
        network_step = _network_step(result_count=10, total=10, returned_count=5, truncated=True)
        outbound_check.hunt_step_id = network_step.id
        outbound_check.source_metadata_json = network_step.coverage_detail_json["source_metadata"]

        with _patched_queries(checklist_runs=[checklist_run], checks=checks, steps=[network_step]):
            eligibility = hunt_trace.calculate_finding_eligibility(checklist_run)

        reason_codes = [reason["code"] for reason in eligibility["block_reasons"]]
        self.assertFalse(eligibility["finding_eligible"])
        self.assertIn("network_results_truncated", reason_codes)

    def test_network_absence_check_blocks_when_absence_query_returns_matches(self):
        definition = _definition("file_exfiltration_review")
        checklist_run = _checklist_run(definition, coverage=HuntCoverageStatus.COMPLETE)
        checks = _checks_for(definition, checklist_run, completed=True)
        outbound_check = next(check for check in checks if check.check_key == "large_outbound_transfer_check")
        network_step = _network_step(result_count=2, total=2, returned_count=2, truncated=False)
        outbound_check.hunt_step_id = network_step.id
        outbound_check.source_metadata_json = network_step.coverage_detail_json["source_metadata"]

        with _patched_queries(checklist_runs=[checklist_run], checks=checks, steps=[network_step]):
            eligibility = hunt_trace.calculate_finding_eligibility(checklist_run)

        reason_codes = [reason["code"] for reason in eligibility["block_reasons"]]
        self.assertFalse(eligibility["finding_eligible"])
        self.assertIn("network_absence_query_has_results", reason_codes)


if __name__ == "__main__":
    unittest.main()
