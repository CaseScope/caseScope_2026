from pathlib import Path


REPO_ROOT = Path("/opt/casescope")


def test_static_report_path_uses_shared_adapter_and_explicit_selection():
    source = (REPO_ROOT / "routes/reports.py").read_text()

    assert "preview_report_negative_findings" in source
    assert "build_negative_findings_report_context" in source
    assert 'data.get("negative_finding_ids", [])' in source
    assert "reserved_negative_finding_keys" in source
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
    assert "negative_finding" not in source
