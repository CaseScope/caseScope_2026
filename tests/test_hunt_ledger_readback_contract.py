from pathlib import Path


REPO_ROOT = Path("/opt/casescope")


def test_hunt_ledger_readback_ui_is_case_hunting_scoped():
    template = (REPO_ROOT / "static/templates/case_hunting.html").read_text()
    css = (REPO_ROOT / "static/css/main.css").read_text()

    assert "Hunt Runs" in template
    assert "huntLedgerRuns" in template
    assert "GET /api/hunt-runs" not in template
    assert "fetch(`/api/hunt-runs?case_id=${caseId}`)" in template
    assert "fetch(`/api/hunt-runs/${huntRunId}`)" in template
    assert "payload.hunt_run_id = activeHuntRunId" in template
    assert "renderHuntStep" in template
    assert "renderHuntEvidenceRefs" in template
    assert "renderHuntDecisionSections" in template
    assert "acceptHuntDecision" in template
    assert "supersedeHuntDecision" in template
    assert "Current Authoritative Classifications" in template
    assert "AI Drafts Awaiting Review" in template
    assert "Rejected Drafts" in template
    assert "Superseded Decision History" in template
    assert "Review Note" in template
    assert "Reviewed At" in template
    assert "Superseded At" in template
    assert "Hypothesis" in template
    assert "formatHuntDecisionStatus" in template
    assert "selector_hash" in template
    assert "result_fingerprint" in template
    assert "evidence_fingerprint" in template
    assert "source_decision_id" in template
    assert "supersedes_decision_id" in template
    assert ".hunt-ledger-panel" in css
    assert ".hunt-step-card" in css
    assert ".hunt-decision-card" in css
    assert ".hunt-decision-card.state-draft" in css
    assert ".hunt-decision-card.state-rejected" in css
    assert ".hunt-decision-card.state-superseded" in css
    decision_ui_source = template[template.index("function formatHuntDecisionStatus"):template.index("function renderHuntStep")]
    assert "not observed" not in decision_ui_source.lower()
    assert "no evidence of" not in decision_ui_source.lower()
    assert "absent" not in decision_ui_source.lower()
    assert "not found" not in decision_ui_source.lower()


def test_hunt_decision_phase2_models_and_phase3_negative_surfaces_are_separate():
    models_source = (REPO_ROOT / "models/hunt.py").read_text()
    route_source = (REPO_ROOT / "routes/hunt.py").read_text()
    report_source = (REPO_ROOT / "utils/report_generator.py").read_text()

    assert "class HuntDecision" in models_source
    assert "class HuntDecisionEvidenceLink" in models_source
    assert "source_decision_id" in models_source
    assert "supersedes_decision_id" in models_source
    assert "decision_scope" in models_source
    assert "active_authoritative_decisions" in (REPO_ROOT / "utils/hunt_trace.py").read_text()
    assert "class HuntNegativeFinding" in models_source
    assert "class HuntChecklistDefinition" in models_source
    assert "class HuntChecklistRun" in models_source
    assert "class HuntChecklistCheck" in models_source
    assert "is_active" in models_source
    assert "is_reportable" in models_source
    assert "finding_state == HuntNegativeFindingState.ACCEPTED" in models_source
    assert "checklist_run.finding_eligible is True" in models_source
    assert "create_hunt_negative_finding_draft" in route_source
    assert "list_hunt_negative_findings" in route_source
    assert "negative_finding" not in report_source.lower()
