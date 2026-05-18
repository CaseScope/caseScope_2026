import os

os.environ.setdefault("SECRET_KEY", "test-secret")

from models.hunt import (
    HuntChecklistCheck,
    HuntChecklistCheckStatus,
    HuntChecklistDefinition,
    HuntChecklistRun,
    HuntChecklistRunStatus,
    HuntCreatedByType,
    HuntNegativeFinding,
    HuntNegativeFindingState,
    HuntNegativeFindingType,
    HuntSourceAvailabilityStatus,
)


def _column_names(model):
    return {column.name for column in model.__table__.columns}


def test_hunt_negative_finding_vocabularies_match_phase3_contract():
    assert HuntChecklistRunStatus.all() == [
        "draft",
        "in_progress",
        "completed",
        "invalidated",
    ]
    assert HuntChecklistCheckStatus.all() == [
        "pending",
        "completed",
        "not_applicable",
        "failed",
        "skipped",
    ]
    assert HuntNegativeFindingState.all() == [
        "draft",
        "accepted",
        "rejected",
        "superseded",
    ]
    assert HuntNegativeFindingType.all() == [
        "no_ransomware_preparation_identified",
        "no_file_exfiltration_identified",
        "no_direct_lateral_movement_identified",
    ]
    assert HuntSourceAvailabilityStatus.all() == [
        "available",
        "partial",
        "not_available",
        "unknown",
        "not_applicable",
    ]


def test_hunt_checklist_definition_preserves_versioned_template_contract():
    assert HuntChecklistDefinition.__tablename__ == "hunt_checklist_definitions"
    assert {
        "id",
        "slug",
        "version",
        "display_name",
        "description",
        "category",
        "is_active",
        "definition_json",
        "created_at",
        "updated_at",
    }.issubset(_column_names(HuntChecklistDefinition))
    assert any(
        constraint.name == "uq_hunt_checklist_definitions_slug_version"
        for constraint in HuntChecklistDefinition.__table__.constraints
    )


def test_hunt_checklist_run_tracks_snapshot_eligibility_and_limitations():
    assert HuntChecklistRun.__tablename__ == "hunt_checklist_runs"
    assert {
        "case_id",
        "hunt_run_id",
        "checklist_definition_id",
        "checklist_slug",
        "checklist_version",
        "definition_snapshot_json",
        "status",
        "coverage_status",
        "finding_eligible",
        "finding_block_reasons_json",
        "missing_sources_json",
        "limitations_json",
        "target_metadata_json",
        "created_by_type",
        "created_by",
        "completed_at",
        "metadata_json",
    }.issubset(_column_names(HuntChecklistRun))

    run = HuntChecklistRun(
        id=1,
        case_id=10,
        hunt_run_id=20,
        checklist_slug="file_exfiltration_review",
        checklist_version="1.0",
        definition_snapshot_json={"slug": "file_exfiltration_review"},
        finding_eligible=False,
        finding_block_reasons_json=[{"code": "coverage_insufficient"}],
    )
    payload = run.to_dict()
    assert payload["definition_snapshot_json"]["slug"] == "file_exfiltration_review"
    assert payload["finding_eligible"] is False
    assert payload["finding_block_reasons_json"][0]["code"] == "coverage_insufficient"


def test_hunt_checklist_check_links_steps_or_source_metadata():
    assert HuntChecklistCheck.__tablename__ == "hunt_checklist_checks"
    assert {
        "case_id",
        "hunt_run_id",
        "checklist_run_id",
        "check_key",
        "check_name",
        "check_status",
        "coverage_status",
        "source_availability_status",
        "hunt_step_id",
        "result_count",
        "result_summary",
        "not_applicable_reason",
        "source_metadata_json",
        "limitations_json",
        "completed_at",
        "metadata_json",
    }.issubset(_column_names(HuntChecklistCheck))
    assert any(
        constraint.name == "uq_hunt_checklist_checks_run_key"
        for constraint in HuntChecklistCheck.__table__.constraints
    )


def test_hunt_negative_finding_has_independent_reportable_rule():
    assert HuntNegativeFinding.__tablename__ == "hunt_negative_findings"
    assert {
        "case_id",
        "hunt_run_id",
        "checklist_run_id",
        "finding_state",
        "finding_type",
        "statement",
        "coverage_status",
        "decision_scope",
        "target_metadata_json",
        "created_by_type",
        "created_by",
        "reviewed_by",
        "reviewed_at",
        "review_note",
        "source_finding_id",
        "supersedes_finding_id",
        "superseded_by_finding_id",
        "accepted_at",
        "rejected_at",
        "superseded_at",
        "evidence_fingerprint",
        "language_template_key",
        "limitations_json",
        "missing_sources_json",
        "schema_version",
    }.issubset(_column_names(HuntNegativeFinding))

    active = HuntNegativeFinding(
        finding_state=HuntNegativeFindingState.ACCEPTED,
        created_by_type=HuntCreatedByType.ANALYST,
        superseded_by_finding_id=None,
        finding_type=HuntNegativeFindingType.NO_FILE_EXFILTRATION_IDENTIFIED,
        statement="No evidence of file exfiltration was identified in the reviewed artifacts.",
    )
    draft = HuntNegativeFinding(
        finding_state=HuntNegativeFindingState.DRAFT,
        created_by_type=HuntCreatedByType.AI,
        finding_type=HuntNegativeFindingType.NO_FILE_EXFILTRATION_IDENTIFIED,
        statement="No evidence of file exfiltration was identified in the reviewed artifacts.",
    )
    superseded = HuntNegativeFinding(
        finding_state=HuntNegativeFindingState.ACCEPTED,
        created_by_type=HuntCreatedByType.ANALYST,
        superseded_by_finding_id=99,
        finding_type=HuntNegativeFindingType.NO_FILE_EXFILTRATION_IDENTIFIED,
        statement="No evidence of file exfiltration was identified in the reviewed artifacts.",
    )

    assert active.is_reportable is True
    assert active.to_dict()["is_reportable"] is True
    assert draft.is_reportable is False
    assert superseded.is_reportable is False
