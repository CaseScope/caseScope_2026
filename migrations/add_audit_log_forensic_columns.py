#!/usr/bin/env python3
"""Database migration adding forensic targeting and hash-chain columns to audit_log.

Adds client attribution (client_id, client_name), evidence targeting
(source_file, event_selector_key), bulk-operation grouping (operation_id,
affected_count) and the tamper-evident chain (hash_version,
previous_record_hash, record_hash).

Existing rows are backfilled: client identity is resolved from the case where
possible, then the hash chain is computed across every row in id order so the
chain verifies from the first record onward.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import inspect, text

from app import create_app
from models.database import db

NEW_COLUMNS = (
    ("client_id", "INTEGER"),
    ("client_name", "VARCHAR(255)"),
    ("source_file", "VARCHAR(512)"),
    ("event_selector_key", "VARCHAR(512)"),
    ("operation_id", "VARCHAR(36)"),
    ("affected_count", "BIGINT"),
    ("hash_version", "VARCHAR(10)"),
    ("previous_record_hash", "VARCHAR(80)"),
    ("record_hash", "VARCHAR(80)"),
)

NEW_INDEXES = (
    ("ix_audit_log_client_id", "audit_log (client_id)"),
    ("ix_audit_log_event_selector_key", "audit_log (event_selector_key)"),
    ("ix_audit_log_operation_id", "audit_log (operation_id)"),
    ("ix_audit_client_time", "audit_log (client_id, timestamp)"),
    ("ix_audit_operation", "audit_log (operation_id)"),
)


def add_columns():
    """Add any missing columns, leaving existing ones untouched."""
    inspector = inspect(db.engine)
    existing = {column["name"] for column in inspector.get_columns("audit_log")}

    added = []
    for name, ddl_type in NEW_COLUMNS:
        if name in existing:
            continue
        db.session.execute(text(f"ALTER TABLE audit_log ADD COLUMN {name} {ddl_type}"))
        added.append(name)

    db.session.commit()
    return added


def add_indexes():
    """Create supporting indexes, including the uniqueness guard on record_hash."""
    for name, definition in NEW_INDEXES:
        db.session.execute(text(f"CREATE INDEX IF NOT EXISTS {name} ON {definition}"))
    db.session.execute(
        text("CREATE UNIQUE INDEX IF NOT EXISTS ix_audit_log_record_hash ON audit_log (record_hash)")
    )
    db.session.commit()


def backfill_client_identity():
    """Resolve client_id/client_name for historical rows via their case."""
    result = db.session.execute(
        text(
            """
            UPDATE audit_log AS a
               SET client_id = c.client_id,
                   client_name = cl.name
              FROM cases AS c
              LEFT JOIN clients AS cl ON cl.id = c.client_id
             WHERE a.case_uuid = c.uuid
               AND a.client_id IS NULL
               AND c.client_id IS NOT NULL
            """
        )
    )
    db.session.commit()
    return result.rowcount or 0


def backfill_hash_chain():
    """Compute the chain across every row in id order.

    Written with a direct UPDATE rather than the ORM because the model blocks
    updates by design; this runs once, before the chain exists.
    """
    from models.audit_log import AuditLog
    from utils.audit_chain import (
        HASH_VERSION,
        build_record_metadata,
        compute_record_hash,
        record_values,
    )

    records = AuditLog.query.order_by(AuditLog.id.asc()).all()
    previous_hash = None
    updated = 0

    for record in records:
        metadata = build_record_metadata(record_values(record), previous_hash)
        record_hash = compute_record_hash(metadata)
        db.session.execute(
            text(
                """
                UPDATE audit_log
                   SET hash_version = :hash_version,
                       previous_record_hash = :previous_record_hash,
                       record_hash = :record_hash
                 WHERE id = :id
                """
            ),
            {
                "hash_version": HASH_VERSION,
                "previous_record_hash": previous_hash,
                "record_hash": record_hash,
                "id": record.id,
            },
        )
        previous_hash = record_hash
        updated += 1

    db.session.commit()
    return updated


def run_migration():
    """Apply the schema additions and backfill historical rows."""
    app = create_app()

    with app.app_context():
        added = add_columns()
        print(f"Columns added: {', '.join(added) if added else 'none (already present)'}")

        add_indexes()
        print("Indexes ensured")

        clients_backfilled = backfill_client_identity()
        print(f"Client identity backfilled on {clients_backfilled} row(s)")

        chained = backfill_hash_chain()
        print(f"Hash chain computed across {chained} row(s)")

        from utils.audit_chain import verify_chain

        result = verify_chain()
        if not result["valid"]:
            raise RuntimeError(
                f"Chain verification failed at record {result['first_inconsistent_record_id']}"
            )
        print(f"Chain verified across {result['record_count_checked']} record(s)")
        return True


if __name__ == "__main__":
    print("=" * 60)
    print("Audit Log Forensic Columns Migration")
    print("=" * 60)
    print()

    try:
        run_migration()
        sys.exit(0)
    except Exception as exc:
        print(f"Migration failed: {exc}")
        import traceback

        traceback.print_exc()
        sys.exit(1)
