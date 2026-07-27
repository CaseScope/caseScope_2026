"""Helpers for inspecting and repairing single-table event state."""

from __future__ import annotations

from typing import Dict, Iterable, Tuple

from utils.clickhouse import destructive_event_rewrite_guard, get_client, run_events_update, wait_for_mutation_completion
from utils.evidence_audit import EVIDENCE_UNTAGGED, EvidenceChange, new_operation_id

EVENT_OVERLAY_TABLE_GROUPS = {
    "analyst": ("analyst_events",),
    "ioc": ("ioc_events",),
    "noise": ("noise_events",),
}

LEGACY_SELECTOR_TABLES = (
    "event_analyst_state",
    "event_ioc_case_state",
    "event_ioc_state",
    "event_noise_case_state",
    "event_noise_state",
    "event_noise_manual_state",
)


def iter_event_overlay_tables(
    *,
    include_analyst: bool = True,
    include_ioc: bool = True,
    include_noise: bool = True,
) -> Tuple[str, ...]:
    tables = []
    if include_analyst:
        tables.extend(EVENT_OVERLAY_TABLE_GROUPS["analyst"])
    if include_ioc:
        tables.extend(EVENT_OVERLAY_TABLE_GROUPS["ioc"])
    if include_noise:
        tables.extend(EVENT_OVERLAY_TABLE_GROUPS["noise"])
    return tuple(tables)


def get_case_event_overlay_row_counts(
    case_id: int,
    *,
    client=None,
    tables: Iterable[str] | None = None,
    include_analyst: bool = True,
    include_ioc: bool = True,
    include_noise: bool = True,
) -> Dict[str, int]:
    client = client or get_client()
    counts: Dict[str, int] = {}
    selected_tables = tuple(
        tables
        or iter_event_overlay_tables(
            include_analyst=include_analyst,
            include_ioc=include_ioc,
            include_noise=include_noise,
        )
    )
    for table in selected_tables:
        if table == "analyst_events":
            sql = (
                "SELECT count() FROM events "
                "WHERE case_id = {case_id:UInt32} "
                "AND (analyst_tagged = true OR length(analyst_tags) > 0 OR analyst_notes IS NOT NULL)"
            )
        elif table == "ioc_events":
            sql = (
                "SELECT count() FROM events "
                "WHERE case_id = {case_id:UInt32} "
                "AND length(ioc_types) > 0"
            )
        elif table == "noise_events":
            sql = (
                "SELECT count() FROM events "
                "WHERE case_id = {case_id:UInt32} "
                "AND (noise_matched = true OR length(noise_rules) > 0)"
            )
        else:
            counts[table] = 0
            continue
        result = client.query(sql, parameters={"case_id": int(case_id)})
        counts[table] = int(result.result_rows[0][0]) if result.result_rows else 0
    return counts


def get_case_legacy_overlay_selector_counts(case_id: int, *, client=None) -> Dict[str, int]:
    client = client or get_client()
    counts: Dict[str, int] = {}
    for table in LEGACY_SELECTOR_TABLES:
        try:
            result = client.query(
                f"SELECT count() FROM {table} WHERE case_id = {{case_id:UInt32}}",
                parameters={"case_id": int(case_id)},
            )
            counts[table] = int(result.result_rows[0][0]) if result.result_rows else 0
        except Exception:
            counts[table] = 0
    return counts


def purge_case_legacy_overlay_rows(case_id: int, *, client=None, wait: bool = True) -> Dict[str, object]:
    """Delete obsolete overlay-table rows for a case."""
    client = client or get_client()
    existing_counts = get_case_legacy_overlay_selector_counts(case_id, client=client)
    deleted_counts = {table: 0 for table in LEGACY_SELECTOR_TABLES}
    commands_issued = 0
    mutations_completed = 0

    with destructive_event_rewrite_guard("case_legacy_overlay_purge", case_id=case_id):
        for table in LEGACY_SELECTOR_TABLES:
            if existing_counts.get(table, 0) <= 0:
                continue
            command_fragment = f"DELETE WHERE case_id = {int(case_id)}"
            client.command(f"ALTER TABLE {table} {command_fragment}")
            commands_issued += 1
            if wait:
                wait_for_mutation_completion(table, command_fragment, client=client)
                mutations_completed += 1
            deleted_counts[table] = existing_counts[table]

    return {
        "case_id": int(case_id),
        "tables": deleted_counts,
        "commands_issued": commands_issued,
        "mutations_completed": mutations_completed,
    }


def _reset_audit(case_id, field_name, affected_count, updated_by, operation_id, reason):
    """Build the audit record for one branch of a case event state reset."""
    return EvidenceChange(
        case_id=case_id,
        field_name=field_name,
        action=EVIDENCE_UNTAGGED,
        old_value="(prior analyst-visible state)",
        new_value="(cleared)",
        affected_count=affected_count,
        username=updated_by or "system",
        operation_id=operation_id,
        details={"reason": reason, "scope_note": "destructive reset of derived event state"},
    )


def purge_case_event_overlay_state(
    case_id: int,
    *,
    client=None,
    wait: bool = True,
    include_analyst: bool = True,
    include_ioc: bool = True,
    include_noise: bool = True,
    updated_by: str = None,
    operation_id: str = None,
) -> Dict[str, object]:
    """Reset derived event state on `events` for a case."""
    client = client or get_client()
    operation_id = operation_id or new_operation_id()
    tables = iter_event_overlay_tables(
        include_analyst=include_analyst,
        include_ioc=include_ioc,
        include_noise=include_noise,
    )
    existing_counts = get_case_event_overlay_row_counts(case_id, client=client, tables=tables)
    deleted_counts = {table: 0 for table in tables}
    commands_issued = 0
    mutations_completed = 0

    with destructive_event_rewrite_guard("case_event_state_reset", case_id=case_id):
        for table in tables:
            if existing_counts.get(table, 0) <= 0:
                continue
            if table == "analyst_events":
                run_events_update(
                    "analyst_tagged = false, analyst_tags = [], analyst_notes = NULL",
                    (
                        f"case_id = {int(case_id)} "
                        "AND (analyst_tagged = true OR length(analyst_tags) > 0 OR analyst_notes IS NOT NULL)"
                    ),
                    client=client,
                    audit=_reset_audit(
                        case_id, "analyst_tags", existing_counts[table], updated_by, operation_id,
                        "Analyst tags, flags and notes cleared by case event state reset",
                    ),
                )
            elif table == "ioc_events":
                run_events_update(
                    "ioc_types = []",
                    f"case_id = {int(case_id)} AND length(ioc_types) > 0",
                    client=client,
                    audit=_reset_audit(
                        case_id, "ioc_types", existing_counts[table], updated_by, operation_id,
                        "IOC tags cleared by case event state reset",
                    ),
                )
            elif table == "noise_events":
                run_events_update(
                    "noise_matched = false, noise_rules = []",
                    (
                        f"case_id = {int(case_id)} "
                        "AND (noise_matched = true OR length(noise_rules) > 0)"
                    ),
                    client=client,
                    audit=_reset_audit(
                        case_id, "noise_matched", existing_counts[table], updated_by, operation_id,
                        "Noise flags and rules cleared by case event state reset",
                    ),
                )
            else:
                continue
            commands_issued += 1
            if wait:
                mutations_completed += 1
            deleted_counts[table] = existing_counts[table]

    return {
        "case_id": int(case_id),
        "tables": deleted_counts,
        "commands_issued": commands_issued,
        "mutations_completed": mutations_completed,
    }


__all__ = [
    "EVENT_OVERLAY_TABLE_GROUPS",
    "LEGACY_SELECTOR_TABLES",
    "get_case_event_overlay_row_counts",
    "get_case_legacy_overlay_selector_counts",
    "iter_event_overlay_tables",
    "purge_case_legacy_overlay_rows",
    "purge_case_event_overlay_state",
]
