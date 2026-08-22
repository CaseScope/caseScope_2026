"""Neutral Phase 1B current-publication helpers over physical ``events``.

This is not ``events_current``, not LEK, and not a counting-basis cutover.
Transitional product readers may consume:

- true legacy rows whose seven protocol identity columns are all NULL; or
- managed rows whose protocol identity is complete and whose control
  projections currently prove publishable BUILDING_INITIAL/ACTIVE plus a
  DURABLE ingest batch.

Partial protocol identity fails closed. Hidden replacement, STAGED, SUPERSEDED,
FAILED, INVALIDATED, and missing-projection rows stay unpublished.
"""
from __future__ import annotations

from typing import Optional


PROTOCOL_IDENTITY_COLUMNS = (
    "source_ref_type",
    "source_ref_id",
    "source_generation",
    "ingest_batch_id",
    "ingest_row_ordinal",
    "ingest_row_hash",
    "ingest_attempt_id",
)

_PUBLISHABLE_VISIBILITY_STATES = ("BUILDING_INITIAL", "ACTIVE")
_STRING_IDENTITY_COLUMNS = (
    "source_ref_type",
    "source_ref_id",
    "ingest_batch_id",
    "ingest_row_hash",
)
_UUID_IDENTITY_COLUMNS = (
    "ingest_attempt_id",
)
_NULL_ONLY_IDENTITY_COLUMNS = (
    "source_generation",
    "ingest_row_ordinal",
)


def protocol_legacy_null_sql(alias: str = "e") -> str:
    """True legacy rows keep all seven protocol identity columns NULL."""
    prefix = f"{alias}." if alias else ""
    return " AND ".join(f"{prefix}{column} IS NULL" for column in PROTOCOL_IDENTITY_COLUMNS)


def protocol_complete_sql(alias: str = "e") -> str:
    """Managed rows must carry the full protocol identity, not a partial subset."""
    prefix = f"{alias}." if alias else ""
    parts = []
    for column in PROTOCOL_IDENTITY_COLUMNS:
        if column in _STRING_IDENTITY_COLUMNS:
            parts.append(f"{prefix}{column} IS NOT NULL AND {prefix}{column} != ''")
        elif column in _UUID_IDENTITY_COLUMNS:
            # ClickHouse 26.7 rejects UUID != '' (it tries to parse '' as UUID).
            parts.append(f"{prefix}{column} IS NOT NULL AND toString({prefix}{column}) != ''")
        else:
            parts.append(f"{prefix}{column} IS NOT NULL")
    return " AND ".join(parts)


def _case_id_filter_sql(case_id_param: Optional[str]) -> str:
    if not case_id_param:
        return ""
    return f"\n                WHERE case_id = {case_id_param}"


def build_event_publication_bridge(alias: str = "e", *, case_id_param: Optional[str] = None) -> dict:
    """LEFT JOIN control-projection bridge used by Hunt and other SELECT readers.

    ``case_id_param`` is an optional ClickHouse parameter expression such as
    ``{case_id:UInt32}``. When set, control-projection subqueries are restricted
    to that case. Semantics stay identical because callers already filter
    ``events`` by case_id and the joins already require matching case_id.
    """
    veg_from = "FROM visible_evidence_generations FINAL" + _case_id_filter_sql(case_id_param)
    dib_from = "FROM durable_ingest_batches FINAL" + _case_id_filter_sql(case_id_param)
    join_sql = f"""
            LEFT JOIN (
                SELECT
                    case_id,
                    source_ref_type,
                    source_ref_id,
                    source_generation,
                    visibility_state,
                    publishable
                {veg_from}
            ) AS veg
                ON veg.case_id = {alias}.case_id
               AND veg.source_ref_type = {alias}.source_ref_type
               AND veg.source_ref_id = {alias}.source_ref_id
               AND veg.source_generation = {alias}.source_generation
            LEFT JOIN (
                SELECT
                    ingest_batch_id,
                    case_id,
                    source_ref_type,
                    source_ref_id,
                    source_generation,
                    state
                {dib_from}
            ) AS dib
                ON dib.ingest_batch_id = {alias}.ingest_batch_id
               AND dib.case_id = {alias}.case_id
               AND dib.source_ref_type = {alias}.source_ref_type
               AND dib.source_ref_id = {alias}.source_ref_id
               AND dib.source_generation = {alias}.source_generation
    """
    visibility_sql = ", ".join(f"'{state}'" for state in _PUBLISHABLE_VISIBILITY_STATES)
    where_sql = f"""
            AND (
                (
                    {protocol_legacy_null_sql(alias)}
                )
                OR (
                    {protocol_complete_sql(alias)}
                    AND veg.publishable = 1
                    AND veg.visibility_state IN ({visibility_sql})
                    AND dib.state = 'DURABLE'
                )
            )
    """
    return {
        "join_sql": join_sql,
        "where_sql": where_sql,
        "form": "left_join_bridge",
    }


def build_event_publication_predicate(alias: str = "e", *, case_id_param: Optional[str] = None) -> dict:
    """Predicate-only form using FINAL control-projection IN subqueries.

    Intended for UPDATE / ALTER UPDATE contexts that cannot take a SELECT JOIN.
    ClickHouse 26.7.3.19 rejects a SELECT alias such as ``e.column`` inside
    ``ALTER TABLE events UPDATE``. Callers must pass ``alias=""`` or
    ``alias="events"`` for mutation predicates. B2A qualifies the form; B2B
    may adopt it only after disposable proof.
    """
    prefix = f"{alias}." if alias else ""
    veg_where = _case_id_filter_sql(case_id_param)
    dib_where = _case_id_filter_sql(case_id_param)
    visibility_sql = ", ".join(f"'{state}'" for state in _PUBLISHABLE_VISIBILITY_STATES)
    veg_filter = "publishable = 1 AND visibility_state IN ({visibility_sql})".format(
        visibility_sql=visibility_sql
    )
    if veg_where:
        veg_filter = f"case_id = {case_id_param} AND {veg_filter}"
    dib_filter = "state = 'DURABLE'"
    if dib_where:
        dib_filter = f"case_id = {case_id_param} AND {dib_filter}"
    predicate_sql = f"""
            (
                (
                    {protocol_legacy_null_sql(alias)}
                )
                OR (
                    {protocol_complete_sql(alias)}
                    AND ({prefix}case_id, {prefix}source_ref_type, {prefix}source_ref_id, {prefix}source_generation) IN (
                        SELECT case_id, source_ref_type, source_ref_id, source_generation
                        FROM visible_evidence_generations FINAL
                        WHERE {veg_filter}
                    )
                    AND ({prefix}ingest_batch_id, {prefix}case_id, {prefix}source_ref_type, {prefix}source_ref_id, {prefix}source_generation) IN (
                        SELECT ingest_batch_id, case_id, source_ref_type, source_ref_id, source_generation
                        FROM durable_ingest_batches FINAL
                        WHERE {dib_filter}
                    )
                )
            )
    """
    exists_sql = f"""
            (
                (
                    {protocol_legacy_null_sql(alias)}
                )
                OR (
                    {protocol_complete_sql(alias)}
                    AND EXISTS (
                        SELECT 1
                        FROM visible_evidence_generations AS veg FINAL
                        WHERE veg.case_id = {prefix}case_id
                          AND veg.source_ref_type = {prefix}source_ref_type
                          AND veg.source_ref_id = {prefix}source_ref_id
                          AND veg.source_generation = {prefix}source_generation
                          AND veg.publishable = 1
                          AND veg.visibility_state IN ({visibility_sql})
                    )
                    AND EXISTS (
                        SELECT 1
                        FROM durable_ingest_batches AS dib FINAL
                        WHERE dib.ingest_batch_id = {prefix}ingest_batch_id
                          AND dib.case_id = {prefix}case_id
                          AND dib.source_ref_type = {prefix}source_ref_type
                          AND dib.source_ref_id = {prefix}source_ref_id
                          AND dib.source_generation = {prefix}source_generation
                          AND dib.state = 'DURABLE'
                    )
                )
            )
    """
    return {
        "predicate_sql": predicate_sql,
        "exists_sql": exists_sql,
        "form": "tuple_in_subquery",
        "exists_form": "correlated_exists",
    }
