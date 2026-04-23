"""Helpers for inspecting and repairing ClickHouse event overlay state."""

from __future__ import annotations

from typing import Dict, Iterable, Tuple

from utils.clickhouse import (
    destructive_event_rewrite_guard,
    get_client,
    wait_for_mutation_completion,
)

EVENT_OVERLAY_TABLE_GROUPS = {
    "analyst": ("event_analyst_state",),
    "ioc": ("event_ioc_case_state", "event_ioc_state"),
    "noise": (
        "event_noise_case_state",
        "event_noise_state",
        "event_noise_manual_state",
    ),
}

LEGACY_SELECTOR_TABLES = (
    "event_analyst_state",
    "event_ioc_state",
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
        result = client.query(
            f"SELECT count() FROM {table} WHERE case_id = {{case_id:UInt32}}",
            parameters={"case_id": int(case_id)},
        )
        counts[table] = int(result.result_rows[0][0]) if result.result_rows else 0
    return counts


def get_case_legacy_overlay_selector_counts(case_id: int, *, client=None) -> Dict[str, int]:
    client = client or get_client()
    counts: Dict[str, int] = {}
    for table in LEGACY_SELECTOR_TABLES:
        result = client.query(
            f"""
            SELECT count()
            FROM {table}
            WHERE case_id = {{case_id:UInt32}}
              AND startsWith(selector_key, 'event_id:')
            """,
            parameters={"case_id": int(case_id)},
        )
        counts[table] = int(result.result_rows[0][0]) if result.result_rows else 0
    return counts


def purge_case_event_overlay_state(
    case_id: int,
    *,
    client=None,
    wait: bool = True,
    include_analyst: bool = True,
    include_ioc: bool = True,
    include_noise: bool = True,
) -> Dict[str, object]:
    """Delete all overlay rows for a case from the selected overlay tables."""
    client = client or get_client()
    tables = iter_event_overlay_tables(
        include_analyst=include_analyst,
        include_ioc=include_ioc,
        include_noise=include_noise,
    )
    existing_counts = get_case_event_overlay_row_counts(case_id, client=client, tables=tables)
    deleted_counts = {table: 0 for table in tables}
    commands_issued = 0
    mutations_completed = 0

    with destructive_event_rewrite_guard("case_event_overlay_purge", case_id=case_id):
        for table in tables:
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


__all__ = [
    "EVENT_OVERLAY_TABLE_GROUPS",
    "LEGACY_SELECTOR_TABLES",
    "get_case_event_overlay_row_counts",
    "get_case_legacy_overlay_selector_counts",
    "iter_event_overlay_tables",
    "purge_case_event_overlay_state",
]
