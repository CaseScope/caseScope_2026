import os
from pathlib import Path

os.environ.setdefault("SECRET_KEY", "test-secret")

from utils import hunt_checklist_templates as templates

REPO_ROOT = Path("/opt/casescope")


def _all_strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from _all_strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from _all_strings(item)


def _by_slug():
    return {definition["slug"]: definition for definition in templates.checklist_definitions()}


def test_phase3a_seeded_templates_are_exact_initial_set():
    definitions = templates.checklist_definitions()
    assert [definition["slug"] for definition in definitions] == [
        "ransomware_preparation_review",
        "file_exfiltration_review",
        "direct_lateral_movement_review",
    ]
    assert {definition["version"] for definition in definitions} == {"1.0"}
    assert templates.get_checklist_definition("file_exfiltration_review")["slug"] == "file_exfiltration_review"
    assert templates.get_checklist_definition("missing") is None


def test_phase3a_templates_include_required_contract_sections():
    required_keys = {
        "slug",
        "version",
        "display_name",
        "description",
        "supported_scopes",
        "target_metadata_fields",
        "required_sources",
        "optional_sources",
        "required_checks",
        "tool_mappings",
        "coverage_rules",
        "finding_eligibility_rules",
        "finding_block_reasons",
        "allowed_language_by_coverage",
        "blocked_language",
        "mandatory_limitations",
        "report_safe_examples",
    }
    for definition in templates.checklist_definitions():
        assert required_keys.issubset(definition)
        assert definition["required_checks"]
        assert definition["tool_mappings"]
        assert set(definition["coverage_rules"]) == {
            "complete",
            "partial",
            "insufficient",
            "not_available",
            "unknown",
        }
        assert "complete" in definition["allowed_language_by_coverage"]
        assert "partial" in definition["allowed_language_by_coverage"]
        assert definition["mandatory_limitations"]
        assert definition["report_safe_examples"]


def test_phase3a_templates_use_only_locked_scopes_and_tools():
    approved_tools = templates.APPROVED_TRACED_TOOLS
    supported_scopes = templates.SUPPORTED_TEMPLATE_SCOPES

    for definition in templates.checklist_definitions():
        assert set(definition["supported_scopes"]).issubset(supported_scopes)
        for check in definition["required_checks"]:
            assert set(check.get("approved_tools") or []).issubset(approved_tools)
        if definition["slug"] != "file_exfiltration_review":
            for value in _all_strings(definition):
                assert value != "search_network_logs"


def test_file_exfiltration_large_outbound_check_is_network_hybrid_only():
    definition = _by_slug()["file_exfiltration_review"]
    checks = {check["key"]: check for check in definition["required_checks"]}
    large_outbound = checks["large_outbound_transfer_check"]

    assert large_outbound["type"] == "hybrid_source_traced_tool"
    assert large_outbound["approved_tools"] == ["search_network_logs"]
    assert large_outbound["source_metadata_required"] is True
    assert large_outbound["requires_explicit_time_bounds"] is True
    assert large_outbound["requires_zero_results_for_absence"] is True
    assert large_outbound["requires_source_availability_metadata"] is True
    assert large_outbound["forces_partial_limitation_if_unavailable"] is True
    assert definition["tool_mappings"]["large_outbound_transfer_check"]["type"] == "hybrid_source_traced_tool"
    assert "network_or_remote_access_transfer_visibility" in definition["required_sources"]
    assert "search_network_logs" in list(_all_strings(definition))
    assert "search_network_logs" not in list(_all_strings(_by_slug()["ransomware_preparation_review"]))


def test_lateral_movement_source_destination_values_are_target_metadata_not_scopes():
    definition = _by_slug()["direct_lateral_movement_review"]

    assert definition["supported_scopes"] == ["case", "host", "user", "process", "network"]
    assert "source_host" not in definition["supported_scopes"]
    assert "destination_host" not in definition["supported_scopes"]
    assert "target_source_host" in definition["target_metadata_fields"]
    assert "target_destination_host" in definition["target_metadata_fields"]
    assert "target_source_user" in definition["target_metadata_fields"]
    assert "target_destination_user" in definition["target_metadata_fields"]
    assert "target_protocol" in definition["target_metadata_fields"]


def test_phase3a_language_policy_blocks_overbroad_absence_claims():
    for definition in templates.checklist_definitions():
        blocked_text = " ".join(definition["blocked_language"]).lower()
        assert "reviewed artifacts" in " ".join(_all_strings(definition["allowed_language_by_coverage"])).lower()
        assert "no compromise" in blocked_text
        assert "host is clean" in blocked_text
        assert "attacker did not" in blocked_text
        assert definition["coverage_rules"]["insufficient"]["negative_finding_allowed"] is False
        assert definition["coverage_rules"]["not_available"]["negative_finding_allowed"] is False
        assert definition["coverage_rules"]["unknown"]["negative_finding_allowed"] is False
        assert definition["coverage_rules"]["partial"]["limitation_required"] is True


def test_template_validator_and_seed_migration_reference_are_present():
    templates.validate_all_checklist_definitions()
    migration_source = (REPO_ROOT / "migrations/seed_hunt_checklist_definitions.py").read_text()
    assert "seed_hunt_checklist_definitions" in migration_source
    assert "run_migration" in migration_source
