import os
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from flask import Flask

os.environ.setdefault("SECRET_KEY", "test-secret")

from models.hunt import HuntCoverageStatus
from utils import ai_report_generator
from utils import hunt_negative_report_adapter as adapter
from utils import report_generator as static_report_generator
import routes.reports as report_routes


REPO_ROOT = Path("/opt/casescope")


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


class _DummyUser:
    username = "tester"
    full_name = "Test Analyst"
    is_authenticated = True
    permission_level = "analyst"


def _case():
    return SimpleNamespace(
        id=123,
        uuid="case-uuid-123",
        name="Phase 4.5 Test Case",
        client=None,
        company="Example Client",
        description="",
        status="in_progress",
        timezone="UTC",
        created_by="tester",
        created_at=datetime(2026, 5, 18, 12, 0, 0),
        assigned_to="tester",
    )


def _reportable_finding(finding_id, statement, *, selected=True):
    checklist_run = SimpleNamespace(
        id=501 + finding_id,
        checklist_slug="file_exfiltration_review",
        definition_snapshot_json={"display_name": "File Exfiltration Review"},
        limitations_json=["Network, proxy, and firewall telemetry was incomplete."],
        missing_sources_json=["Complete firewall telemetry"],
        target_metadata_json={"decision_scope": "case"},
        checks=[],
    )
    return SimpleNamespace(
        id=finding_id,
        case_id=123,
        hunt_run_id=401 + finding_id,
        checklist_run=checklist_run,
        is_reportable=True,
        finding_state="accepted",
        created_by_type="analyst",
        superseded_by_finding_id=None,
        finding_type="no_file_exfiltration_identified",
        statement=statement,
        coverage_status=HuntCoverageStatus.PARTIAL,
        limitations_json=["Network, proxy, and firewall telemetry was incomplete."],
        missing_sources_json=["Complete firewall telemetry"],
        decision_scope="case",
        target_metadata_json={"decision_scope": "case", "selected": selected},
        reviewed_by="analyst",
        created_by="analyst",
        accepted_at=datetime(2026, 5, 18, 12, 0, 0),
        source_finding_id=300 + finding_id,
        language_template_key="partial_network_limited",
        evidence_fingerprint=f"fingerprint-{finding_id}",
    )


def _patch_reportable_findings(monkeypatch, findings):
    fake_model = SimpleNamespace(
        query=_Query(findings),
        accepted_at=_Column(),
        id=_Column(),
    )
    monkeypatch.setattr(adapter, "HuntNegativeFinding", fake_model)


def test_static_report_path_uses_shared_adapter_and_explicit_selection():
    source = (REPO_ROOT / "routes/reports.py").read_text()

    assert "preview_report_negative_findings" in source
    assert "build_negative_findings_report_context" in source
    assert 'data.get("negative_finding_ids", [])' in source
    assert "reserved_negative_finding_keys" in source
    assert "negative_findings_audit_appendix" in source
    assert '"approval_rule": "Negative findings are included only when selected for this report."' in source
    assert "HuntNegativeFinding.query" not in source


def test_ai_report_path_inserts_deterministic_section_without_prompt_rewrite():
    source = (REPO_ROOT / "utils/ai_report_generator.py").read_text()
    base_prompt = source[source.index("_BASE_SYSTEM_PROMPT"):source.index("_PROVIDER_PROFILES")]

    assert "selected_negative_finding_ids" in source
    assert "build_negative_findings_report_context" in source
    assert "negative_findings_section" in source
    assert "selected_negative_finding_ids=data.get(\"negative_finding_ids\", [])" in (
        REPO_ROOT / "routes/ai.py"
    ).read_text()
    assert "negative_findings" not in base_prompt
    assert "absence statement" not in base_prompt.lower()


def test_report_generator_still_does_not_query_hunt_negative_findings_directly():
    source = (REPO_ROOT / "utils/report_generator.py").read_text().lower()

    assert "huntnegativefinding" not in source
    assert "hunt_negative_findings" not in source
    assert "huntnegativefinding.query" not in source


class _FakeDocument:
    def __init__(self):
        self.calls = []

    def add_page_break(self):
        self.calls.append(("page_break",))

    def add_heading(self, text, level):
        self.calls.append(("heading", text, level))

    def add_paragraph(self, text):
        self.calls.append(("paragraph", text))


def test_static_report_appends_negative_findings_when_template_lacks_placeholder():
    document = _FakeDocument()
    generator = static_report_generator.ReportGenerator.__new__(static_report_generator.ReportGenerator)
    generator.template = SimpleNamespace(docx=document)
    context = {
        "negative_findings_section_title": "Reviewed Artifacts With No Matching Evidence Identified",
        "negative_findings_section": (
            "Reviewed Artifacts With No Matching Evidence Identified\n"
            "No evidence of file exfiltration was identified in the reviewed artifacts.\n"
            "Limitations: Network telemetry was incomplete."
        ),
    }

    generator._append_negative_findings_fallback(context, placeholders=set())

    assert ("page_break",) in document.calls
    assert ("heading", "Reviewed Artifacts With No Matching Evidence Identified", 1) in document.calls
    assert any("No evidence of file exfiltration" in call[-1] for call in document.calls if call[0] == "paragraph")


def test_static_report_appends_audit_appendix_when_template_lacks_placeholder():
    document = _FakeDocument()
    generator = static_report_generator.ReportGenerator.__new__(static_report_generator.ReportGenerator)
    generator.template = SimpleNamespace(docx=document)
    context = {
        "negative_findings_audit_appendix_title": "Negative Finding Audit Appendix",
        "negative_findings_audit_appendix": (
            "Negative Finding Audit Appendix\n"
            "Negative Finding 10\n"
            "Checklist Run ID: 501\n"
            "HuntRun ID: 401\n"
            "Linked HuntSteps:\n"
            "- HuntStep 701 (tool=query_events)"
        ),
    }

    generator._append_text_section_fallback(
        context,
        placeholders=set(),
        section_key="negative_findings_audit_appendix",
        title_key="negative_findings_audit_appendix_title",
    )

    assert ("heading", "Negative Finding Audit Appendix", 1) in document.calls
    assert any("Checklist Run ID: 501" in call[-1] for call in document.calls if call[0] == "paragraph")
    assert any("HuntRun ID: 401" in call[-1] for call in document.calls if call[0] == "paragraph")
    assert any("Linked HuntSteps:" in call[-1] for call in document.calls if call[0] == "paragraph")


def test_static_report_does_not_append_when_template_has_placeholder():
    document = _FakeDocument()
    generator = static_report_generator.ReportGenerator.__new__(static_report_generator.ReportGenerator)
    generator.template = SimpleNamespace(docx=document)

    generator._append_negative_findings_fallback(
        {"negative_findings_section": "Reviewed Artifacts With No Matching Evidence Identified"},
        placeholders={"negative_findings_section"},
    )

    assert document.calls == []


def test_e2e_negative_finding_report_selection_chain(monkeypatch):
    selected_statement = (
        "No evidence of file exfiltration was identified in the reviewed artifacts available "
        "for this case. This conclusion is limited by unavailable or incomplete network, "
        "proxy, firewall, or remote-access file-transfer logs."
    )
    unselected_statement = (
        "No evidence of direct threat-actor lateral movement was identified in the reviewed "
        "artifacts available for this case. This conclusion is limited by unavailable or "
        "incomplete authentication, endpoint, or network telemetry."
    )
    selected = _reportable_finding(10, selected_statement)
    unselected = _reportable_finding(11, unselected_statement, selected=False)
    _patch_reportable_findings(monkeypatch, [selected, unselected])

    app = Flask(__name__)
    app.secret_key = "test-secret"
    case = _case()
    template = SimpleNamespace(id=3, file_exists=True)

    with app.test_request_context(
        f"/api/reports/negative-findings/preview/{case.uuid}",
        method="POST",
        json={"negative_finding_ids": [selected.id]},
    ), patch.object(report_routes, "current_user", _DummyUser()), \
            patch.object(report_routes.Case, "get_by_uuid", return_value=case):
        response = report_routes.preview_report_negative_findings.__wrapped__(case.uuid)
        payload = response.get_json()

    assert payload["success"] is True
    assert {item["negative_finding_id"] for item in payload["candidates"]} == {selected.id, unselected.id}
    assert [item["negative_finding_id"] for item in payload["selected_negative_findings"]] == [selected.id]
    assert selected_statement in payload["negative_findings_section"]
    assert unselected_statement not in payload["negative_findings_section"]
    assert "Network, proxy, and firewall telemetry was incomplete." in payload["negative_findings_section"]

    captured_context = {}

    def fake_generate_case_report(*, case_uuid, template_id, context, filename_prefix="CaseReport"):
        captured_context.update(context)
        return f"/tmp/{case_uuid}.docx"

    with (
        app.test_request_context(
            f"/api/reports/generate/{case.uuid}",
            method="POST",
            json={
                "template_id": template.id,
                "negative_finding_ids": [selected.id],
                "context": {
                    "negative_findings_section": "caller override must be ignored",
                    "negative_findings_audit_appendix": "caller appendix override must be ignored",
                    "executive_summary": "caller-provided summary",
                },
            },
        ),
        patch.object(report_routes, "current_user", _DummyUser()),
        patch.object(report_routes.Case, "get_by_uuid", return_value=case),
        patch("models.report_template.ReportTemplate.query") as template_query,
        patch("utils.report_generator.get_base_case_context", return_value={"case_name": case.name}),
        patch("utils.report_generator.generate_case_report", side_effect=fake_generate_case_report),
    ):
        template_query.get.return_value = template
        response = report_routes.generate_report.__wrapped__(case.uuid)
        payload = response.get_json()

    assert payload["success"] is True
    assert payload["negative_findings_included"] == 1
    assert captured_context["executive_summary"] == "caller-provided summary"
    assert captured_context["negative_findings_included"] == 1
    assert selected_statement in captured_context["negative_findings_section"]
    assert unselected_statement not in captured_context["negative_findings_section"]
    assert "caller override must be ignored" not in captured_context["negative_findings_section"]
    assert "Negative Finding Audit Appendix" in captured_context["negative_findings_audit_appendix"]
    assert "Checklist Run ID:" in captured_context["negative_findings_audit_appendix"]
    assert "HuntRun ID:" in captured_context["negative_findings_audit_appendix"]
    assert "caller appendix override must be ignored" not in captured_context["negative_findings_audit_appendix"]

    rendered_context = {}
    appended_document = _FakeDocument()

    class FakeDocxTemplate:
        def __init__(self, template_path):
            self.template_path = template_path
            self.docx = appended_document

        def get_undeclared_template_variables(self):
            return set()

        def render(self, context, **kwargs):
            rendered_context.update(context)
            rendered_context["render_kwargs"] = kwargs

        def save(self, output_path):
            rendered_context["output_path"] = output_path

    generator = ai_report_generator.AIReportGenerator.__new__(ai_report_generator.AIReportGenerator)
    generator.case = case
    generator.template_id = None
    generator.sections = {
        "executive_summary": "Executive summary",
        "timeline": "Timeline",
        "ioc_list": "IOCs",
        "summary_what": "What",
        "summary_why": "Why",
        "summary_how": "How",
    }
    generator.selected_negative_finding_ids = [selected.id]

    with patch.object(ai_report_generator.ReportTemplate, "get_default_template_for_type", return_value=SimpleNamespace(filename="template.docx")), \
            patch.object(ai_report_generator.ReportTemplate, "get_default_template", return_value=None), \
            patch.object(ai_report_generator.ReportTemplate, "get_template_path", return_value="/tmp/template.docx"), \
            patch.object(ai_report_generator.os.path, "exists", return_value=True), \
            patch.object(ai_report_generator.os, "makedirs"), \
            patch.object(ai_report_generator, "DocxTemplate", FakeDocxTemplate):
        output_path = generator._generate_word_document()

    assert output_path == rendered_context["output_path"]
    assert rendered_context["render_kwargs"] == {"autoescape": True}
    assert rendered_context["negative_findings_included"] == 1
    assert selected_statement in rendered_context["negative_findings_section"]
    assert unselected_statement not in rendered_context["negative_findings_section"]
    assert generator.sections["negative_findings_section"] == rendered_context["negative_findings_section"]
    assert ("heading", "Reviewed Artifacts With No Matching Evidence Identified", 1) in appended_document.calls
    assert ("heading", "Negative Finding Audit Appendix", 1) in appended_document.calls
    assert any(selected_statement in call[-1] for call in appended_document.calls if call[0] == "paragraph")
