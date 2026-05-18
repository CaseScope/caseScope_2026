import os
from datetime import datetime
from types import SimpleNamespace

import pytest

os.environ.setdefault("SECRET_KEY", "test-secret")

from models.hunt import HuntCoverageStatus
from utils import hunt_negative_report_adapter as adapter


class _Query:
    def __init__(self, items):
        self.items = list(items)

    def filter_by(self, **kwargs):
        return _Query([
            item for item in self.items
            if all(getattr(item, key, None) == value for key, value in kwargs.items())
        ])

    def order_by(self, *_args, **_kwargs):
        return self

    def all(self):
        return list(self.items)


class _Column:
    def asc(self):
        return self


def _finding(
    finding_id,
    *,
    statement="No evidence of file exfiltration was identified in the reviewed artifacts.",
    coverage_status=HuntCoverageStatus.COMPLETE,
    limitations=None,
    reportable=True,
    finding_state="accepted",
    created_by_type="analyst",
    superseded_by_finding_id=None,
):
    evidence_ref = SimpleNamespace(
        to_dict=lambda: {
            "id": 801,
            "hunt_step_id": 701,
            "selector_hash": "abc123",
            "summary": "Reviewed event selector",
        }
    )
    step = SimpleNamespace(
        id=701,
        tool_name="query_events",
        result_count=0,
        result_summary="No matching events returned",
        coverage_status=coverage_status,
        result_fingerprint="fingerprint-1",
        evidence_refs=[evidence_ref],
    )
    check = SimpleNamespace(
        id=601,
        check_key="archive_staging_check",
        check_name="Archive staging check",
        check_status="completed",
        coverage_status=coverage_status,
        source_availability_status="available",
        hunt_step_id=step.id,
        hunt_step=step,
        result_count=0,
        result_summary="No archive staging evidence",
        not_applicable_reason=None,
        source_metadata_json={},
        limitations_json=[],
    )
    checklist_run = SimpleNamespace(
        id=501,
        checklist_slug="file_exfiltration_review",
        definition_snapshot_json={"display_name": "File Exfiltration Review"},
        limitations_json=limitations or [],
        missing_sources_json=[],
        target_metadata_json={"decision_scope": "case"},
        checks=[check],
    )
    return SimpleNamespace(
        id=finding_id,
        case_id=123,
        hunt_run_id=401,
        checklist_run_id=checklist_run.id,
        checklist_run=checklist_run,
        is_reportable=reportable,
        finding_state=finding_state,
        created_by_type=created_by_type,
        superseded_by_finding_id=superseded_by_finding_id,
        finding_type="no_file_exfiltration_identified",
        statement=statement,
        coverage_status=coverage_status,
        limitations_json=limitations or [],
        missing_sources_json=[],
        decision_scope="case",
        target_metadata_json={"decision_scope": "case"},
        reviewed_by="analyst",
        created_by="analyst",
        accepted_at=datetime(2026, 5, 18, 12, 0, 0),
        source_finding_id=300,
        language_template_key="complete_standard",
        evidence_fingerprint="evidence-fingerprint-1",
    )


def test_reportable_query_uses_is_reportable_and_explicit_selection(monkeypatch):
    reportable = _finding(1)
    active_but_ineligible = _finding(2, reportable=False)
    rejected = _finding(3, reportable=False, finding_state="rejected")

    fake_model = SimpleNamespace(
        query=_Query([reportable, active_but_ineligible, rejected]),
        accepted_at=_Column(),
        id=_Column(),
    )
    monkeypatch.setattr(adapter, "HuntNegativeFinding", fake_model)

    assert adapter.get_reportable_negative_findings_for_case(123) == [reportable]
    assert adapter.get_reportable_negative_findings_for_case(123, selected_finding_ids=[2, 1]) == [reportable]
    assert adapter.get_reportable_negative_findings_for_case(123, selected_finding_ids=[]) == []


def test_serializer_preserves_statement_and_required_report_fields():
    statement = "No evidence of file exfiltration was identified in the reviewed artifacts."
    payload = adapter.serialize_reportable_negative_finding(_finding(1, statement=statement))

    assert payload["statement"] == statement
    assert payload["negative_finding_id"] == 1
    assert payload["checklist_definition_key"] == "file_exfiltration_review"
    assert payload["checklist_definition_name"] == "File Exfiltration Review"
    assert payload["checklist_run_id"] == 501
    assert payload["hunt_run_id"] == 401
    assert payload["reviewed_checks_summary"][0]["check_key"] == "archive_staging_check"
    assert payload["linked_hunt_steps"][0]["tool_name"] == "query_events"
    assert payload["linked_evidence_refs"][0]["selector_hash"] == "abc123"
    assert payload["audit_references"]["language_template_key"] == "complete_standard"


def test_report_context_includes_separate_audit_appendix():
    finding = _finding(1)
    payload = adapter.serialize_reportable_negative_finding(finding)
    appendix = adapter._render_audit_appendix([payload])

    assert appendix.startswith("Negative Finding Audit Appendix")
    assert "No evidence of file exfiltration was identified in the reviewed artifacts." in appendix
    assert "Checklist Run ID: 501" in appendix
    assert "HuntRun ID: 401" in appendix
    assert "Linked HuntSteps:" in appendix
    assert "tool=query_events" in appendix
    assert "Evidence References:" in appendix
    assert "selector_hash=abc123" in appendix
    assert "Audit References:" in appendix


def test_network_backed_audit_appendix_preserves_bounded_report_statement():
    statement = "No evidence of file exfiltration was identified in the reviewed artifacts."
    finding = _finding(1, statement=statement)
    check = finding.checklist_run.checks[0]
    check.check_key = "large_outbound_transfer_check"
    check.check_name = "Large outbound transfer check"
    check.source_availability_status = "available"
    check.source_metadata_json = {
        "source_table": "network_logs",
        "reviewed_time_start": "2026-05-14T19:50:04Z",
        "reviewed_time_end": "2026-05-14T20:01:24Z",
        "reviewed_pcap_ids": [12],
        "reviewed_log_types": ["conn", "dns"],
        "available_log_types": ["conn", "dns", "ssl"],
        "source_availability_status": "available",
        "limitations": [],
    }
    check.hunt_step.tool_name = "search_network_logs"
    check.hunt_step.result_summary = (
        "total=0; returned=0; log_type=all; pcap_id=12; "
        "time_start=2026-05-14T19:50:04Z; time_end=2026-05-14T20:01:24Z; search=screenconnect"
    )

    payload = adapter.serialize_reportable_negative_finding(finding)
    section = adapter._render_section([payload])
    appendix = adapter._render_audit_appendix([payload])
    section_lines = [line for line in section.splitlines() if line.strip()]

    assert payload["statement"] == statement
    assert section_lines[1] == statement
    assert "No files left the network" not in section
    assert "No exfiltration occurred" not in section
    assert "tool=search_network_logs" in appendix
    assert "source_table: network_logs" in appendix
    assert "reviewed_time_start: 2026-05-14T19:50:04Z" in appendix
    assert "reviewed_time_end: 2026-05-14T20:01:24Z" in appendix


def test_partial_coverage_requires_visible_limitations():
    partial = _finding(
        1,
        coverage_status=HuntCoverageStatus.PARTIAL,
        limitations=[],
        statement=(
            "No evidence of file exfiltration was identified in the reviewed artifacts available "
            "for this case. This conclusion is limited by unavailable or incomplete network, "
            "proxy, firewall, or remote-access file-transfer logs."
        ),
    )

    with pytest.raises(ValueError, match="visible limitations"):
        adapter.serialize_reportable_negative_finding(partial)

    partial.limitations_json = ["Network, proxy, and firewall telemetry was incomplete."]
    partial.checklist_run.limitations_json = partial.limitations_json
    section = adapter._render_section([adapter.serialize_reportable_negative_finding(partial)])
    assert "Network, proxy, and firewall telemetry was incomplete." in section


def test_blocked_report_language_is_rejected():
    finding = _finding(1, statement="No breach occurred.")

    with pytest.raises(ValueError, match="report-blocked language"):
        adapter.serialize_reportable_negative_finding(finding)
