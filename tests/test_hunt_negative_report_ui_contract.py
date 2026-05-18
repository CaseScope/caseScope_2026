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


def test_hunt_checklist_network_review_details_are_rendered_from_existing_payloads():
    template = (REPO_ROOT / "static/templates/case_hunting.html").read_text()
    css = (REPO_ROOT / "static/css/main.css").read_text()
    checklist_source = template[
        template.index("function networkChecklistBlockersForCheck"):
        template.index("function renderHuntChecklistRun")
    ]

    assert "Network log review details" in checklist_source
    assert "Reviewed time window" in checklist_source
    assert "Reviewed PCAP IDs" in checklist_source
    assert "Reviewed log types" in checklist_source
    assert "Available log types" in checklist_source
    assert "Source availability" in checklist_source
    assert "Coverage status" in checklist_source
    assert "Result total" in checklist_source
    assert "Returned rows" in checklist_source
    assert "Truncated or paginated" in checklist_source
    assert "Search/query bounds" in checklist_source
    assert "Missing sources" in checklist_source
    assert "Limitations" in checklist_source
    assert "Eligibility blockers" in checklist_source

    assert "large_outbound_transfer_check" in checklist_source
    assert "search_network_logs" in checklist_source
    assert "source_table === 'network_logs'" in checklist_source
    assert "reviewed_time_start" in checklist_source
    assert "reviewed_time_end" in checklist_source
    assert "reviewed_pcap_ids" in checklist_source
    assert "reviewed_log_types" in checklist_source
    assert "available_log_types" in checklist_source
    assert "source_availability_status" in checklist_source
    assert "result_metadata" in checklist_source
    assert "returned_count" in checklist_source
    assert "truncated" in checklist_source
    assert "tool_parameters_json" in checklist_source
    assert "finding_block_reasons_json" in checklist_source

    assert ".hunt-network-review-details" in css
    assert ".hunt-network-review-grid" in css
    assert ".hunt-network-review-lists" in css


def test_hunt_checklist_limitations_are_visible_before_draft_or_acceptance_actions():
    template = (REPO_ROOT / "static/templates/case_hunting.html").read_text()
    allowed_preview_source = template[
        template.index("function renderHuntChecklistLimitationNotice"):
        template.index("function renderHuntCheckWorkflowActions")
    ]
    negative_finding_source = template[
        template.index("function renderHuntNegativeFinding(finding)"):
        template.index("function renderHuntNegativeFindingGroup")
    ]

    assert "Limitations before draft creation" in allowed_preview_source
    assert allowed_preview_source.index("Limitations before draft creation") < allowed_preview_source.index("Create Draft From Approved Template")
    assert negative_finding_source.index("<h5>Limitations</h5>") < negative_finding_source.index("renderHuntNegativeFindingActions")


def test_hunt_checklist_network_ui_avoids_broad_absence_wording():
    template = (REPO_ROOT / "static/templates/case_hunting.html").read_text()
    network_source = template[
        template.index("function renderHuntNetworkChecklistDetails"):
        template.index("function renderHuntChecklistLimitationNotice")
    ].lower()

    assert "no exfiltration occurred" not in network_source
    assert "network is clean" not in network_source
    assert "no files left the network" not in network_source
