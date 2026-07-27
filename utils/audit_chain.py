"""Tamper-evident hash chaining for the forensic audit log.

Each `audit_log` row carries a SHA-256 digest over its own forensically
material fields plus the digest of the preceding row. Rewriting or removing
any row breaks every digest after it, so tampering is detectable even by a
party who holds database superuser rights.

The v1 record hash covers exactly: hash_version, timestamp, username,
user_id, remote_ip, client_id, case_uuid, entity_type, entity_id, action,
field_name, old_value, new_value, source_file, event_selector_key,
operation_id, affected_count, details, and previous_record_hash.

Excluded: the database id, record_hash itself, and denormalized display-only
fields (entity_name, client_name, user_agent) which carry no evidentiary
weight and may be re-rendered. Adding a field to the hash requires a new
hash version so previously written chains stay verifiable.
"""
from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import text

from models.database import db

logger = logging.getLogger(__name__)

HASH_VERSION = "v1"

# Transaction-scoped advisory lock serializing chain appends so concurrent
# writers cannot interleave and produce two rows claiming the same parent.
AUDIT_CHAIN_LOCK_KEY = int.from_bytes(
    hashlib.sha256(b"audit_log_chain").digest()[:8],
    byteorder="big",
    signed=False,
) & 0x7FFFFFFFFFFFFFFF

HASHED_FIELDS = (
    "timestamp",
    "username",
    "user_id",
    "remote_ip",
    "client_id",
    "case_uuid",
    "entity_type",
    "entity_id",
    "action",
    "field_name",
    "old_value",
    "new_value",
    "source_file",
    "event_selector_key",
    "operation_id",
    "affected_count",
    "details",
)


def canonical_json(value: dict[str, Any]) -> str:
    """Serialize hash metadata with stable key order and compact separators."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def _as_utc(value: Optional[datetime] = None) -> datetime:
    current = value or datetime.now(timezone.utc)
    if current.tzinfo is None:
        return current.replace(tzinfo=timezone.utc)
    return current.astimezone(timezone.utc)


def timestamp_for_hash(value: Optional[datetime] = None) -> str:
    """Return timezone-explicit ISO 8601 timestamp text used by v1 hashes."""
    return _as_utc(value).isoformat().replace("+00:00", "Z")


def build_record_metadata(values: dict[str, Any], previous_record_hash: Optional[str]) -> dict[str, Any]:
    """Build the explicit v1 metadata set included in an audit record hash."""
    metadata: dict[str, Any] = {"hash_version": HASH_VERSION}
    for field in HASHED_FIELDS:
        value = values.get(field)
        if field == "timestamp":
            metadata[field] = timestamp_for_hash(value) if isinstance(value, datetime) else value
        else:
            metadata[field] = value
    metadata["previous_record_hash"] = previous_record_hash
    return metadata


def compute_record_hash(metadata: dict[str, Any]) -> str:
    """Return a versioned SHA-256 hash for canonical record metadata."""
    digest = hashlib.sha256(canonical_json(metadata).encode("utf-8")).hexdigest()
    return f"{HASH_VERSION}:{digest}"


def acquire_chain_lock() -> None:
    """Serialize chain appends for the remainder of the current transaction."""
    if db.engine.dialect.name == "postgresql":
        db.session.execute(text("SELECT pg_advisory_xact_lock(:lock_key)"), {"lock_key": AUDIT_CHAIN_LOCK_KEY})


def current_tail_hash() -> Optional[str]:
    """Return the record hash of the newest audit row, or None when empty."""
    from models.audit_log import AuditLog

    tail = AuditLog.query.order_by(AuditLog.id.desc()).first()
    return tail.record_hash if tail else None


def record_values(record) -> dict[str, Any]:
    """Extract the hashed field values from an AuditLog instance."""
    return {field: getattr(record, field, None) for field in HASHED_FIELDS}


def verify_chain(query=None) -> dict[str, Any]:
    """Walk audit records in insertion order and report the first break.

    Returns a dict with `valid`, the number of records checked, the covered
    timestamp range, and — when a break is found — the offending record id
    alongside the expected and actual hashes.
    """
    from models.audit_log import AuditLog

    if query is None:
        query = AuditLog.query
    records = query.order_by(AuditLog.id.asc()).all()

    previous_hash: Optional[str] = None
    first_timestamp = None
    last_timestamp = None

    for index, record in enumerate(records, start=1):
        if first_timestamp is None:
            first_timestamp = record.timestamp
        last_timestamp = record.timestamp

        metadata = build_record_metadata(record_values(record), previous_hash)
        expected_record_hash = compute_record_hash(metadata)

        if record.previous_record_hash != previous_hash or record.record_hash != expected_record_hash:
            return {
                "valid": False,
                "record_count_checked": index,
                "first_record_timestamp": first_timestamp.isoformat() if first_timestamp else None,
                "last_record_timestamp": last_timestamp.isoformat() if last_timestamp else None,
                "first_inconsistent_record_id": record.id,
                "expected_hash": expected_record_hash,
                "actual_hash": record.record_hash,
                "previous_record_hash": previous_hash,
            }
        previous_hash = record.record_hash

    return {
        "valid": True,
        "record_count_checked": len(records),
        "first_record_timestamp": first_timestamp.isoformat() if first_timestamp else None,
        "last_record_timestamp": last_timestamp.isoformat() if last_timestamp else None,
        "first_inconsistent_record_id": None,
        "expected_hash": None,
        "actual_hash": None,
        "previous_record_hash": previous_hash,
    }


__all__ = [
    "AUDIT_CHAIN_LOCK_KEY",
    "HASHED_FIELDS",
    "HASH_VERSION",
    "acquire_chain_lock",
    "build_record_metadata",
    "canonical_json",
    "compute_record_hash",
    "current_tail_hash",
    "record_values",
    "timestamp_for_hash",
    "verify_chain",
]
