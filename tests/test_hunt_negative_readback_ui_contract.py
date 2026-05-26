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
    assert "renderHuntRunStatePanel" in template
    assert "summarizeHuntRunState" in template
    assert "No active tool execution detected" in template
    assert "Latest step:" in template
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
    assert ".hunt-run-state-panel" in css
    assert ".hunt-run-state-stats" in css
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


def test_hunt_network_checklist_readback_ui_is_discoverable():
    template = (REPO_ROOT / "static/templates/case_hunting.html").read_text()

    assert "function renderHuntNetworkChecklistDetails" in template
    assert "Network log review details" in template
    assert "uniqueHuntList" in template
    assert "coverage_detail_json" in template
    assert "tool_parameters_json" in template
    assert "Eligibility blockers" in template


def test_ioc_backed_hunting_review_ui_is_discoverable():
    template = (REPO_ROOT / "static/templates/case_hunting.html").read_text()
    ai_tab = (REPO_ROOT / "static/templates/hunting/tab_ai_hunting.html").read_text()
    css = (REPO_ROOT / "static/css/main.css").read_text()

    assert "IOC-backed hunting review" in ai_tab
    assert "Run IOC Hunting Review" in ai_tab
    assert "IOC Category" in ai_tab
    assert "IOCs to Review" in ai_tab
    assert "Rows Per Network Search" in ai_tab
    assert "Run bounded network log searches for network IOCs" in ai_tab
    assert "btnRefreshIOCHuntMenu" in ai_tab
    assert "Hunt Run Ledger" in ai_tab
    assert "startIOCHuntReview" in template
    assert "loadIOCHuntMenuOptions" in template
    assert "selectedIOCHuntIOCIds" in template
    assert "resolveIOCHuntTimeBounds" in template
    assert "fetch('/api/hunt-runs/ioc-review'" in template
    assert "fetch(`/api/iocs/list/${caseUuid}?per_page=200`)" in template
    assert "normalizeIOCHuntReviewTime" in template
    assert "renderIOCHuntReviewResults" in template
    assert "include_network" in template
    assert "ioc_ids" in template
    assert "generateCaseReportFromAI" not in template[
        template.index("function startIOCHuntReview"):
        template.index("async function loadHuntingUnifiedFindings")
    ]
    assert ".ioc-hunt-review-menu" in css
    assert ".ioc-hunt-review-results" in css
