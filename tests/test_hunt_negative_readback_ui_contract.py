from pathlib import Path


REPO_ROOT = Path("/opt/casescope")


def test_hunt_negative_readback_ui_sections_are_present():
    template = (REPO_ROOT / "static/templates/case_hunting.html").read_text()
    css = (REPO_ROOT / "static/css/main.css").read_text()

    assert "fetch(`/api/hunt-runs/${huntRunId}/checklists`)" in template
    assert "fetch(`/api/hunt-runs/${huntRunId}/negative-findings`)" in template
    assert "renderHuntChecklistSections" in template
    assert "renderHuntChecklistRun" in template
    assert "renderHuntChecklistCheck" in template
    assert "renderHuntNegativeFindingSections" in template
    assert "renderHuntNegativeFinding" in template
    assert "renderHuntAllowedStatementPreview" in template
    assert "Checklist Runs" in template
    assert "Checklist progress" not in template  # represented by status/coverage/eligibility pills
    assert "Required checks" in template
    assert "Coverage status" in template
    assert "Finding eligibility" in template
    assert "Finding block reasons" in template
    assert "Missing sources" in template
    assert "Limitations required" in template
    assert "Linked HuntStep" in template
    assert "Source-driven metadata" in template
    assert "Allowed statement preview" in template
    assert "Negative Findings" in template
    assert "Checklist-backed absence review" in template
    assert "Active analyst-accepted negative findings" in template
    assert "Draft negative findings" in template
    assert "Rejected negative findings" in template
    assert "Superseded negative finding history" in template
    assert "Other history" in template
    assert "Reviewed artifacts" not in template
    assert "reviewed artifacts" in template
    assert ".hunt-checklist-card" in css
    assert ".hunt-check-card" in css
    assert ".hunt-negative-finding-card" in css
    assert ".hunt-negative-language-preview" in css


def test_hunt_negative_readback_ui_is_read_only_and_report_safe():
    template = (REPO_ROOT / "static/templates/case_hunting.html").read_text()
    negative_source = template[
        template.index("function renderHuntListItems"):
        template.index("async function postHuntDecisionAction")
    ]

    assert "report export" not in negative_source.lower()
    assert "mark clean" not in negative_source.lower()
    assert "free-text" not in negative_source.lower()
    assert "ai-written absence" not in negative_source.lower()
    assert "no compromise" not in negative_source.lower()
    assert "no breach" not in negative_source.lower()
    assert "no exfiltration occurred" not in negative_source.lower()
    assert "no lateral movement occurred" not in negative_source.lower()
    assert "Clean" not in negative_source
    assert "No compromise" not in negative_source
    assert "No breach" not in negative_source
    assert "No exfiltration occurred" not in negative_source
    assert "No lateral movement occurred" not in negative_source
