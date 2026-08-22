#!/usr/bin/env python3
"""Retire events.idx_search_token after PHASE2_1_EXC_001.

Architecture exception PHASE2_1_EXC_001 retains idx_search_ngram. This
migration drops ONLY the redundant legacy token bloom:

    INDEX idx_search_token search_blob TYPE tokenbf_v1(32768, 3, 0) GRANULARITY 4

It does not:

- DROP or mutate idx_search_ngram
- DROP or mutate idx_search_blob_text
- rewrite search_blob or any evidence column
- MATERIALIZE INDEX
- OPTIMIZE FINAL
- change pattern detection semantics

Fail-closed: if an index named idx_search_token exists with a different
expression, type, or granularity than the canonical legacy definition,
refuse to drop it.

Absent idx_search_token is a successful no-op (idempotent).

Not invoked from application startup. Production ``casescope`` requires
``--apply-production``.
"""
from __future__ import annotations

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from migrations.add_events_search_blob_text_index import (
    PRODUCTION_DATABASE_NAMES,
    _current_database_name,
    _index_by_name,
    _skipping_indices,
    _table_exists,
    normalize_index_expression,
)


ARCHITECTURE_EXCEPTION_ID = "PHASE2_1_EXC_001"
INDEX_NAME = "idx_search_token"
NGRAM_INDEX_NAME = "idx_search_ngram"
TEXT_INDEX_NAME = "idx_search_blob_text"
PRESERVED_INDEX_NAMES = (
    NGRAM_INDEX_NAME,
    TEXT_INDEX_NAME,
    "idx_event_id",
    "idx_selector_key",
    "idx_evidence_record_key",
)
EXPECTED_EXPR = "search_blob"
EXPECTED_TYPE_FULL = "tokenbf_v1(32768, 3, 0)"
EXPECTED_GRANULARITY = 4
NGRAM_EXPECTED_TYPE_FULL = "ngrambf_v1(3, 512, 2, 0)"
NGRAM_EXPECTED_GRANULARITY = 4
DROP_INDEX_SQL_TEMPLATE = (
    "ALTER TABLE {table} DROP INDEX {index} SETTINGS mutations_sync = 1"
)
FORBIDDEN_SQL_TOKENS = (
    "DROP INDEX idx_search_ngram",
    "CLEAR INDEX",
    "MATERIALIZE INDEX",
    "OPTIMIZE FINAL",
    "ALTER TABLE EVENTS UPDATE",
    "DELETE FROM",
)


class IncompatibleSearchTokenIndex(RuntimeError):
    """idx_search_token exists but is not the canonical legacy token bloom."""


class TokenBloomRetirementRefused(RuntimeError):
    """Refuse to continue without dropping anything."""


def normalize_index_type(type_full):
    return str(type_full or "").replace(" ", "").lower()


EXPECTED_TYPE_NORMALIZED = normalize_index_type(EXPECTED_TYPE_FULL)
NGRAM_TYPE_NORMALIZED = normalize_index_type(NGRAM_EXPECTED_TYPE_FULL)


def token_bloom_identity_is_canonical(index):
    index = index or {}
    try:
        granularity = int(index.get("granularity"))
    except (TypeError, ValueError):
        granularity = None
    return (
        normalize_index_expression(index.get("expr")) == EXPECTED_EXPR
        and normalize_index_type(index.get("type_full")) == EXPECTED_TYPE_NORMALIZED
        and granularity == EXPECTED_GRANULARITY
    )


def ngram_index_is_approved_exception(index):
    index = index or {}
    try:
        granularity = int(index.get("granularity"))
    except (TypeError, ValueError):
        granularity = None
    return (
        index.get("name") == NGRAM_INDEX_NAME
        and normalize_index_expression(index.get("expr")) == EXPECTED_EXPR
        and normalize_index_type(index.get("type_full")) == NGRAM_TYPE_NORMALIZED
        and granularity == NGRAM_EXPECTED_GRANULARITY
    )


def drop_index_sql(table_name="events"):
    sql = DROP_INDEX_SQL_TEMPLATE.format(table=table_name, index=INDEX_NAME)
    upper = sql.upper()
    for token in FORBIDDEN_SQL_TOKENS:
        if token in upper:
            raise TokenBloomRetirementRefused(
                f"Generated SQL contained forbidden token {token!r}: {sql}"
            )
    if NGRAM_INDEX_NAME in sql:
        raise TokenBloomRetirementRefused(
            f"Generated SQL must not mention {NGRAM_INDEX_NAME}: {sql}"
        )
    return sql


def _incompatible_error(table_name, index):
    return IncompatibleSearchTokenIndex(
        f"{table_name}.{INDEX_NAME} exists with incompatible identity "
        f"type={index.get('type_full')!r} expr={index.get('expr')!r} "
        f"granularity={index.get('granularity')!r}; refusing to DROP"
    )


def drop_events_search_token_bloom(
    client,
    *,
    allow_production=False,
    table_name="events",
):
    """Idempotently drop the canonical legacy token bloom. Never touches ngram."""
    database = _current_database_name(client)
    if database in PRODUCTION_DATABASE_NAMES and not allow_production:
        raise TokenBloomRetirementRefused(
            f"Refusing to alter production database {database!r} without allow_production=True"
        )

    result = {
        "database": database,
        "table": table_name,
        "architecture_exception": ARCHITECTURE_EXCEPTION_ID,
        "exists": False,
        "changed": False,
        "already_applied": False,
        "sql": None,
        "index_before": None,
        "index_after": None,
        "preserved_indexes": {},
        "search_blob_mutated": False,
        "ngram_mutated": False,
    }
    if not _table_exists(client, table_name):
        return result

    result["exists"] = True
    indices_before = _skipping_indices(client, table_name)
    existing = _index_by_name(indices_before, INDEX_NAME)
    result["index_before"] = existing
    result["preserved_indexes"] = {
        name: _index_by_name(indices_before, name) for name in PRESERVED_INDEX_NAMES
    }

    ngram_before = _index_by_name(indices_before, NGRAM_INDEX_NAME)
    if ngram_before is None:
        raise TokenBloomRetirementRefused(
            f"{table_name}.{NGRAM_INDEX_NAME} is missing; "
            f"{ARCHITECTURE_EXCEPTION_ID} requires it to remain present"
        )
    if not ngram_index_is_approved_exception(ngram_before):
        raise TokenBloomRetirementRefused(
            f"{table_name}.{NGRAM_INDEX_NAME} is not the approved "
            f"{ARCHITECTURE_EXCEPTION_ID} definition "
            f"type={ngram_before.get('type_full')!r} expr={ngram_before.get('expr')!r} "
            f"granularity={ngram_before.get('granularity')!r}; refusing to continue"
        )

    if existing is None:
        result["already_applied"] = True
        result["index_after"] = None
        return result

    if not token_bloom_identity_is_canonical(existing):
        raise _incompatible_error(table_name, existing)

    sql = drop_index_sql(table_name)
    client.command(sql)
    result["changed"] = True
    result["sql"] = sql

    indices_after = _skipping_indices(client, table_name)
    result["index_after"] = _index_by_name(indices_after, INDEX_NAME)
    if result["index_after"] is not None:
        raise TokenBloomRetirementRefused(
            f"{table_name}.{INDEX_NAME} still present after DROP INDEX"
        )
    ngram_after = _index_by_name(indices_after, NGRAM_INDEX_NAME)
    if ngram_after is None or not ngram_index_is_approved_exception(ngram_after):
        result["ngram_mutated"] = True
        raise TokenBloomRetirementRefused(
            f"{table_name}.{NGRAM_INDEX_NAME} changed during token retirement; "
            f"before={ngram_before!r} after={ngram_after!r}"
        )
    result["preserved_indexes"] = {
        name: _index_by_name(indices_after, name) for name in PRESERVED_INDEX_NAMES
    }
    return result


def migrate(client=None, *, allow_production=False, table_name="events"):
    if client is None:
        from utils.clickhouse import get_fresh_client

        client = get_fresh_client()
    return drop_events_search_token_bloom(
        client,
        allow_production=allow_production,
        table_name=table_name,
    )


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--apply-production",
        action="store_true",
        help="Allow DROP INDEX against the production ClickHouse database named casescope.",
    )
    args = parser.parse_args(argv)
    result = migrate(allow_production=args.apply_production)
    print(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
