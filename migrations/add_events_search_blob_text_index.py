#!/usr/bin/env python3
"""Add the Phase 2 Gate A search_blob text index without reader cutover.

Fresh CREATE TABLE events (see EVENTS_SCHEMA) already defines:

    INDEX idx_search_blob_text search_blob TYPE text(
        tokenizer = 'splitByNonAlpha',
        preprocessor = lower(search_blob)
    )

This migration is the upgrade path for existing tables:

- ADD INDEX IF NOT EXISTS only (metadata)
- does not MATERIALIZE INDEX
- does not drop idx_search_ngram / idx_search_token
- does not rewrite search_blob
- is NOT invoked from application startup
- refuses the production ``casescope`` database unless ``--apply-production``

ClickHouse 26.7 rewrites the declared GRANULARITY to 100000000 for text indexes.
Already-applied detection ignores granularity and matches tokenizer + preprocessor.

Existing rows stay unindexed until an operator runs MATERIALIZE INDEX or a merge
builds the index. Upgrade installs set exclude_materialize_skip_indexes_on_merge
so background merges cannot silently materialize the new index across retained
production parts. New INSERTs still follow materialize_skip_indexes_on_insert.
"""
from __future__ import annotations

import argparse
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


PRODUCTION_DATABASE_NAMES = frozenset({"casescope"})
INDEX_NAME = "idx_search_blob_text"
BLOOM_INDEX_NAMES = ("idx_search_ngram", "idx_search_token")
TOKENIZER = "splitByNonAlpha"
PREPROCESSOR = "lower(search_blob)"
INDEX_TYPE_SQL = (
    f"text(tokenizer = '{TOKENIZER}', preprocessor = {PREPROCESSOR})"
)
ADD_INDEX_SQL = (
    f"ALTER TABLE events ADD INDEX IF NOT EXISTS {INDEX_NAME} search_blob "
    f"TYPE {INDEX_TYPE_SQL} GRANULARITY 1"
)
EXCLUDE_MERGE_SETTING = "exclude_materialize_skip_indexes_on_merge"


class IncompatibleSearchBlobTextIndex(RuntimeError):
    """Existing idx_search_blob_text does not match the locked Gate A type."""


def _current_database_name(client):
    result = client.query("SELECT currentDatabase()")
    if result.result_rows:
        return str(result.result_rows[0][0])
    return os.environ.get("CLICKHOUSE_DATABASE") or "casescope"


def _table_exists(client, table_name="events"):
    result = client.query(
        """
        SELECT count()
        FROM system.tables
        WHERE database = currentDatabase()
          AND name = {table_name:String}
        """,
        parameters={"table_name": table_name},
    )
    return bool(result.result_rows and result.result_rows[0][0])


def _engine_full(client, table_name="events"):
    result = client.query(
        """
        SELECT engine_full
        FROM system.tables
        WHERE database = currentDatabase()
          AND name = {table_name:String}
        """,
        parameters={"table_name": table_name},
    )
    if not result.result_rows:
        return ""
    return str(result.result_rows[0][0] or "")


def normalize_text_index_type(type_full):
    text = str(type_full or "").lower()
    text = text.replace("'", "").replace('"', "").replace(" ", "")
    return text


EXPECTED_TYPE_NORMALIZED = normalize_text_index_type(INDEX_TYPE_SQL)


def text_index_type_is_compatible(type_full):
    normalized = normalize_text_index_type(type_full)
    return normalized.startswith(EXPECTED_TYPE_NORMALIZED)


def _skipping_indices(client, table_name="events"):
    result = client.query(
        """
        SELECT name, type, type_full, expr, granularity
        FROM system.data_skipping_indices
        WHERE database = currentDatabase()
          AND table = {table_name:String}
        ORDER BY name
        """,
        parameters={"table_name": table_name},
    )
    return [
        {
            "name": row[0],
            "type": row[1],
            "type_full": row[2],
            "expr": row[3],
            "granularity": row[4],
        }
        for row in result.result_rows
    ]


def _index_by_name(indices, name):
    for index in indices:
        if index["name"] == name:
            return index
    return None


def _exclude_merge_value(engine_full):
    match = re.search(
        rf"{EXCLUDE_MERGE_SETTING}\s*=\s*'([^']*)'",
        str(engine_full or ""),
    )
    if match:
        return match.group(1)
    match = re.search(
        rf"{EXCLUDE_MERGE_SETTING}\s*=\s*([0-9A-Za-z_,-]+)",
        str(engine_full or ""),
    )
    if match:
        return match.group(1)
    return ""


def _exclude_list(value):
    return [item.strip() for item in str(value or "").split(",") if item.strip()]


def add_events_search_blob_text_index(
    client,
    *,
    allow_production=False,
    materialize=False,
    exclude_from_merge=True,
    table_name="events",
):
    """Idempotently add the Gate A text index. Never rewrites search_blob."""
    database = _current_database_name(client)
    if database in PRODUCTION_DATABASE_NAMES and not allow_production:
        raise RuntimeError(
            f"Refusing to alter production database {database!r} without allow_production=True"
        )
    if materialize and database in PRODUCTION_DATABASE_NAMES:
        raise RuntimeError(
            f"Refusing to MATERIALIZE INDEX {INDEX_NAME} on production database "
            f"{database!r}; that is a full retained-evidence build"
        )

    result = {
        "database": database,
        "table": table_name,
        "exists": False,
        "changed": False,
        "already_applied": False,
        "sql": None,
        "exclude_from_merge_sql": None,
        "materialize_sql": None,
        "index_before": None,
        "index_after": None,
        "bloom_indexes_present": [],
        "search_blob_mutated": False,
    }
    if not _table_exists(client, table_name):
        return result

    result["exists"] = True
    indices_before = _skipping_indices(client, table_name)
    existing = _index_by_name(indices_before, INDEX_NAME)
    result["index_before"] = existing
    result["bloom_indexes_present"] = [
        name for name in BLOOM_INDEX_NAMES if _index_by_name(indices_before, name)
    ]

    if existing is not None and not text_index_type_is_compatible(existing.get("type_full")):
        raise IncompatibleSearchBlobTextIndex(
            f"{table_name}.{INDEX_NAME} exists with incompatible type "
            f"{existing.get('type_full')!r}; refusing to continue"
        )

    sql = (
        f"ALTER TABLE {table_name} ADD INDEX IF NOT EXISTS {INDEX_NAME} search_blob "
        f"TYPE {INDEX_TYPE_SQL} GRANULARITY 1"
    )
    if existing is None:
        client.command(sql)
        result["changed"] = True
        result["sql"] = sql
    else:
        result["already_applied"] = True

    if exclude_from_merge:
        engine_full = _engine_full(client, table_name)
        excluded = _exclude_list(_exclude_merge_value(engine_full))
        if INDEX_NAME not in excluded:
            new_value = ",".join(excluded + [INDEX_NAME])
            exclude_sql = (
                f"ALTER TABLE {table_name} MODIFY SETTING {EXCLUDE_MERGE_SETTING} = '{new_value}'"
            )
            client.command(exclude_sql)
            result["exclude_from_merge_sql"] = exclude_sql
            result["changed"] = True

    if materialize:
        materialize_sql = (
            f"ALTER TABLE {table_name} MATERIALIZE INDEX {INDEX_NAME} "
            "SETTINGS mutations_sync = 1"
        )
        client.command(materialize_sql)
        result["materialize_sql"] = materialize_sql
        result["changed"] = True

    indices_after = _skipping_indices(client, table_name)
    result["index_after"] = _index_by_name(indices_after, INDEX_NAME)
    result["bloom_indexes_present"] = [
        name for name in BLOOM_INDEX_NAMES if _index_by_name(indices_after, name)
    ]
    if result["index_after"] is None:
        raise RuntimeError(f"{table_name}.{INDEX_NAME} missing after migration")
    if not text_index_type_is_compatible(result["index_after"].get("type_full")):
        raise IncompatibleSearchBlobTextIndex(
            f"{table_name}.{INDEX_NAME} after migration has incompatible type "
            f"{result['index_after'].get('type_full')!r}"
        )
    return result


def migrate(client=None, *, allow_production=False, materialize=False, exclude_from_merge=True):
    if client is None:
        from utils.clickhouse import get_fresh_client

        client = get_fresh_client()
    return add_events_search_blob_text_index(
        client,
        allow_production=allow_production,
        materialize=materialize,
        exclude_from_merge=exclude_from_merge,
    )


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--apply-production",
        action="store_true",
        help="Allow ADD INDEX against the production ClickHouse database named casescope.",
    )
    parser.add_argument(
        "--materialize",
        action="store_true",
        help="Also MATERIALIZE INDEX. Refused on production. Unsafe for 700M+ retained rows.",
    )
    parser.add_argument(
        "--allow-merge-materialize",
        action="store_true",
        help="Do not set exclude_materialize_skip_indexes_on_merge for the text index.",
    )
    args = parser.parse_args(argv)
    result = migrate(
        allow_production=args.apply_production,
        materialize=args.materialize,
        exclude_from_merge=not args.allow_merge_materialize,
    )
    print(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
