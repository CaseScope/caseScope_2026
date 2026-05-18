from pathlib import Path


REPO_ROOT = Path("/opt/casescope")


def test_negative_finding_review_actions_are_present_and_template_backed():
    template = (REPO_ROOT / "static/templates/case_hunting.html").read_text()
    css = (REPO_ROOT / "static/css/main.css").read_text()

    assert "createHuntNegativeFindingDraft" in template
    assert "acceptHuntNegativeFinding" in template
    assert "rejectHuntNegativeFinding" in template
    assert "supersedeHuntNegativeFinding" in template
    assert "postHuntNegativeFindingAction" in template
    assert "approvedTemplatesForChecklistRun" in template
    assert "approvedStatementForChecklistRun" in template
    assert "huntFindingTypeForChecklist" in template
    assert "Create Draft From Approved Template" in template
    assert "Accept Draft" in template
    assert "Reject Draft" in template
    assert "Supersede With Approved Template" in template
    assert "/api/hunt-checklist-runs/${checklistRunId}/negative-findings/drafts" in template
    assert "/api/hunt-negative-findings/${findingId}/accept" in template
    assert "/api/hunt-negative-findings/${findingId}/reject" in template
    assert "/api/hunt-negative-findings/${findingId}/supersede" in template
    assert ".hunt-negative-actions" in css


def test_negative_finding_review_ui_preserves_guardrails():
    template = (REPO_ROOT / "static/templates/case_hunting.html").read_text()
    review_source = template[
        template.index("function approvedTemplatesForChecklistRun"):
        template.index("async function postHuntDecisionAction")
    ]

    assert "template.statement" in review_source
    assert "finding_eligible" in review_source
    assert "source_finding_id" in template
    assert "supersedes_finding_id" in template
    assert "superseded_by_finding_id" in template
    assert "is_reportable" in template
    assert "mark clean" not in review_source.lower()
    assert "no compromise" not in review_source.lower()
    assert "no breach" not in review_source.lower()
    assert "report export" not in review_source.lower()
    assert "report insertion" not in review_source.lower()
    assert "free-text" not in review_source.lower()
    assert "ai free-written" not in review_source.lower()
    assert "No exfiltration occurred" not in review_source
    assert "No lateral movement occurred" not in review_source
