#!/usr/bin/env python3
"""Controlled events_buffer drain and drop.

Phase 1.4 replaces Buffer's accidental writer-fence role with the explicit
ingest fence, then removes Buffer. This migration:

- requires exclusive ingest admission (fail-closed if Redis is unavailable)
- waits until admitted writers are zero
- drains events_buffer with OPTIMIZE TABLE events_buffer (not events FINAL)
- refuses to DROP if pending rows remain or state is ambiguous
- is idempotent when events_buffer is already absent
- is NOT invoked from application startup
- refuses the production ``casescope`` database unless ``--apply-production``

Do not run this against production during the Phase 1 Step 2 development pass.
"""
from __future__ import annotations

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from migrations.add_events_table import (
    _buffer_pending_rows,
    _count_table_rows,
    _current_database_name,
    _table_engine,
    _table_exists,
    assert_events_buffer_is_buffer_engine,
)
from utils.ingest_fence import (
    IngestFenceUnavailable,
    active_shared_writer_count,
    exclusive_ingest_fence,
)

PRODUCTION_DATABASE_NAMES = frozenset({"casescope"})


def _assert_disposable_or_explicit(client, *, allow_production: bool) -> str:
    database = _current_database_name(client)
    if database in PRODUCTION_DATABASE_NAMES and not allow_production:
        raise RuntimeError(
            f"Refusing to drop events_buffer on production database {database!r} "
            "without allow_production=True"
        )
    return database


def remove_events_buffer(
    client,
    *,
    allow_production: bool = False,
    timeout_seconds: float | None = None,
) -> dict:
    """Drain and drop events_buffer under exclusive ingest admission."""
    database = _assert_disposable_or_explicit(client, allow_production=allow_production)
    result = {
        "database": database,
        "existed_before": False,
        "dropped": False,
        "already_removed": False,
        "pending_before": 0,
        "pending_after_drain": 0,
        "events_rows_after_drain": None,
        "buffer_visible_after_drain": None,
        "writer_count_at_drop": None,
    }

    try:
        with exclusive_ingest_fence(
            "remove_events_buffer",
            timeout_seconds=timeout_seconds,
        ) as lease:
            lease.assert_active()
            writers = active_shared_writer_count()
            if writers != 0:
                raise RuntimeError(
                    f"Refusing Buffer drop; {writers} shared ingest writer(s) still admitted"
                )
            result["writer_count_at_drop"] = writers

            if not _table_exists(client, "events_buffer"):
                result["already_removed"] = True
                return result

            result["existed_before"] = True
            engine = _table_engine(client, "events_buffer")
            assert_events_buffer_is_buffer_engine(client, engine=engine)

            pending_before = _buffer_pending_rows(client)
            result["pending_before"] = int(pending_before)
            events_before = _count_table_rows(client, "events")
            buffer_visible_before = _count_table_rows(client, "events_buffer")
            result["events_rows_before"] = events_before
            result["buffer_visible_before"] = buffer_visible_before

            lease.assert_active()
            client.command("OPTIMIZE TABLE events_buffer")
            lease.assert_active()

            pending_after = _buffer_pending_rows(client)
            events_after = _count_table_rows(client, "events")
            buffer_visible_after = _count_table_rows(client, "events_buffer")
            result["pending_after_drain"] = int(pending_after)
            result["events_rows_after_drain"] = events_after
            result["buffer_visible_after_drain"] = buffer_visible_after

            if pending_after != 0:
                raise RuntimeError(
                    "events_buffer still has pending rows after OPTIMIZE TABLE events_buffer; "
                    f"refusing DROP (pending={pending_after})"
                )
            if buffer_visible_after != events_after:
                raise RuntimeError(
                    "events_buffer visible count does not match events after drain; "
                    f"refusing DROP (buffer={buffer_visible_after}, events={events_after})"
                )
            if events_after < events_before:
                raise RuntimeError(
                    "events row count decreased during Buffer drain; refusing DROP "
                    f"(before={events_before}, after={events_after})"
                )

            lease.assert_active()
            if active_shared_writer_count() != 0:
                raise RuntimeError(
                    "Shared ingest writer appeared before DROP; refusing Buffer removal"
                )
            client.command("DROP TABLE IF EXISTS events_buffer")
            if _table_exists(client, "events_buffer"):
                raise RuntimeError("events_buffer still exists after DROP; refusing to continue")
            result["dropped"] = True
            return result
    except IngestFenceUnavailable:
        raise


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Drain and drop events_buffer under the ingest fence")
    parser.add_argument(
        "--apply-production",
        action="store_true",
        help="Allow running against the production casescope database",
    )
    args = parser.parse_args(argv)

    from utils.clickhouse import get_migration_client

    client = get_migration_client()
    result = remove_events_buffer(client, allow_production=args.apply_production)
    print(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
