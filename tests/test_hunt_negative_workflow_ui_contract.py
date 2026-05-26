from pathlib import Path


REPO_ROOT = Path("/opt/casescope")


def test_checklist_workflow_ui_controls_are_present_and_api_backed():
    template = (REPO_ROOT / "static/templates/case_hunting.html").read_text()
    css = (REPO_ROOT / "static/css/main.css").read_text()

    assert "HUNT_CHECKLIST_TEMPLATES" in template
    assert "ransomware_preparation_review" in template
    assert "file_exfiltration_review" in template
    assert "direct_lateral_movement_review" in template
    assert "HUNT_COVERAGE_STATUSES" in template
    assert "startHuntChecklistReview" in template
    assert "attachHuntStepToChecklistCheck" in template
    assert "recordHuntCheckSourceMetadata" in template
    assert "markHuntCheckNotApplicable" in template
    assert "completeHuntChecklistRun" in template
    assert "postHuntChecklistWorkflowAction" in template
    assert "Start Checklist Review" in template
    assert "hunt-checklist-start-modal" in template
    assert "huntChecklistTemplateSelect" in template
    assert "huntChecklistScopeSelect" in template
    assert "submitHuntChecklistReview" in template
    assert "Attach Existing HuntStep" in template
    assert "Record Source Metadata" in template
    assert "Mark Not Applicable" in template
    assert "Complete Checklist Run" in template
    assert "Checklist workflow controls" in template
    assert "postHuntChecklistWorkflowAction(`/api/hunt-runs/${activeHuntRunId}/checklists`" in template
    assert "/api/hunt-checklist-runs/${checklistRunId}/checks/${encodeURIComponent(checkKey)}/attach-step" in template
    assert "/api/hunt-checklist-runs/${checklistRunId}/checks/${encodeURIComponent(checkKey)}/source-metadata" in template
    assert "/api/hunt-checklist-runs/${checklistRunId}/checks/${encodeURIComponent(checkKey)}/not-applicable" in template
    assert "/api/hunt-checklist-runs/${checklistRunId}/complete" in template
    assert ".hunt-checklist-workflow-panel" in css
    assert ".modal-hunt-checklist-start" in css
    assert ".hunt-check-workflow-actions" in css


def test_checklist_workflow_ui_preserves_phase35_guardrails():
    template = (REPO_ROOT / "static/templates/case_hunting.html").read_text()
    workflow_source = template[
        template.index("async function postHuntChecklistWorkflowAction"):
        template.index("async function postHuntNegativeFindingAction")
    ]
    negative_source = template[
        template.index("async function postHuntNegativeFindingAction"):
        template.index("async function postHuntDecisionAction")
    ]

    assert "db.session" not in template
    assert "template.statement" in negative_source
    assert "statement: template.statement" in negative_source
    assert "Start Checklist Review using one slug" not in workflow_source
    assert "promptForHuntChecklistTemplate" not in workflow_source
    assert "prompt('Statement" not in workflow_source
    assert "prompt('Statement" not in negative_source
    assert "mark clean" not in template.lower()
    assert "no compromise" not in template.lower()
    assert "report export" not in template.lower()
    assert "report insertion" not in template.lower()
    assert "No exfiltration occurred" not in template
    assert "No lateral movement occurred" not in template
