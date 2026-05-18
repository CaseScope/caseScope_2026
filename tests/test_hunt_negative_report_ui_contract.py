from pathlib import Path


REPO_ROOT = Path("/opt/casescope")


def test_report_negative_finding_selection_ui_is_present_and_api_backed():
    template = (REPO_ROOT / "static/templates/case_dashboard.html").read_text()
    css = (REPO_ROOT / "static/css/main.css").read_text()

    assert "reportNegativeFindingsPanel" in template
    assert "Reviewed Artifacts With No Matching Evidence Identified" in template
    assert "Accepted negative findings are not included automatically" in template
    assert "loadReportNegativeFindings" in template
    assert "renderReportNegativeFindings" in template
    assert "toggleReportNegativeFinding" in template
    assert "selectedNegativeFindingIds" in template
    assert "reportNegativeFindingsSelectionSummary" in template
    assert "fetch(`/api/reports/negative-findings/preview/${CASE_UUID}`" in template
    assert "negative_finding_ids: selectedNegativeFindingIds()" in template
    assert "fetch(`/api/reports/generate-ai/${CASE_UUID}`" in template
    assert ".report-negative-findings-panel" in css
    assert ".report-negative-finding-card.selected" in css
    assert ".report-negative-finding-limitations" in css


def test_report_negative_finding_ui_preserves_phase5_guardrails():
    template = (REPO_ROOT / "static/templates/case_dashboard.html").read_text()
    panel_source = template[
        template.index("reportNegativeFindingsPanel"):
        template.index("<!-- Description Section -->")
    ]
    script_source = template[
        template.index("function loadReportNegativeFindings"):
        template.index("function closeAIReportModal")
    ]

    assert "Accepted negative findings are not included automatically" in panel_source
    assert "selectedReportNegativeFindingIds = new Set()" in template
    assert "data.candidates" in script_source
    assert "data.selected_negative_findings" not in script_source
    assert "finding.statement" in script_source
    assert "finding.limitations" in script_source
    assert "reviewed_checks_summary" in script_source
    assert "reviewed_sources_summary" in script_source
    assert "free-text" not in panel_source.lower()
    assert "no compromise" not in panel_source.lower()
    assert "no breach" not in panel_source.lower()
