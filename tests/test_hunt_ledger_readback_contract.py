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
    assert "selector_hash" in template
    assert "result_fingerprint" in template
    assert "evidence_fingerprint" in template
    assert "source_decision_id" in template
    assert "supersedes_decision_id" in template
    assert ".hunt-ledger-panel" in css
    assert ".hunt-step-card" in css
    assert ".hunt-decision-card" in css


def test_hunt_decision_phase2_models_are_present_without_negative_findings():
    models_source = (REPO_ROOT / "models/hunt.py").read_text()
    route_source = (REPO_ROOT / "routes/hunt.py").read_text()

    assert "class HuntDecision" in models_source
    assert "class HuntDecisionEvidenceLink" in models_source
    assert "source_decision_id" in models_source
    assert "supersedes_decision_id" in models_source
    assert "decision_scope" in models_source
    assert "active_authoritative_decisions" in (REPO_ROOT / "utils/hunt_trace.py").read_text()
    assert "class HuntNegativeFinding" not in models_source
    assert "negative_finding" not in route_source.lower()
