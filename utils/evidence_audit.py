"""Audit recording for mutations applied to stored evidence.

Every change to the ClickHouse `events` table flows through
`utils.clickhouse.run_events_update`. That statement is predicate-driven and
a single call can rewrite hundreds of millions of rows, so per-event
before/after capture is only viable when the caller is acting on a bounded,
explicitly named set of events.

Two shapes are therefore recorded:

* **Per-event** -- an analyst tagging specific events. One audit row per
  event, carrying the event's selector key plus the old and new values.
* **Summary** -- a predicate-driven bulk run such as IOC tagging or MITRE
  mapping. One audit row for the whole operation, carrying the WHERE clause
  that selected the rows, the value applied and how many rows it reached.

Both shapes share an `operation_id`, so the rows emitted by one logical
action can be pulled back together regardless of which shape was used.

Audit failures are never allowed to abort the underlying mutation, but they
are logged at error level: an unrecorded evidence change is a chain of
custody gap and needs to surface rather than pass silently.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Iterable, Optional
from uuid import uuid4

logger = logging.getLogger(__name__)

# Action vocabulary for evidence mutations. Defined here rather than imported
# from models.audit_log so the low-level mutation modules stay free of the
# SQLAlchemy model graph; AuditAction re-exports these as the canonical registry.
EVIDENCE_TAGGED = 'evidence_tagged'
EVIDENCE_UNTAGGED = 'evidence_untagged'
EVIDENCE_BULK_UPDATED = 'evidence_bulk_updated'


@dataclass
class EvidenceChange:
    """Describes one logical modification to stored evidence."""

    case_id: int
    field_name: str
    action: str
    new_value: Any = None
    old_value: Any = None
    # The WHERE clause that selected the affected rows, recorded verbatim so
    # the scope of a bulk change can be reconstructed and re-run.
    predicate: Optional[str] = None
    affected_count: Optional[int] = None
    entity_name: Optional[str] = None
    source_file: Optional[str] = None
    username: Optional[str] = None
    remote_ip: Optional[str] = None
    operation_id: Optional[str] = None
    details: dict = field(default_factory=dict)

    def __post_init__(self):
        if not self.operation_id:
            self.operation_id = str(uuid4())


@dataclass
class EventChange:
    """A single event's before/after state within an operation."""

    selector_key: str
    old_value: Any = None
    new_value: Any = None
    source_file: Optional[str] = None
    artifact_type: Optional[str] = None


def new_operation_id() -> str:
    """Return an identifier grouping the rows emitted by one action."""
    return str(uuid4())


def resolve_case_uuid(case_id: int) -> Optional[str]:
    """Map a ClickHouse case_id to the PostgreSQL case UUID."""
    try:
        from models.case import Case

        case = Case.query.filter_by(id=int(case_id)).first()
        return case.uuid if case else None
    except Exception:
        logger.debug("Could not resolve case_uuid for case_id=%s", case_id, exc_info=True)
        return None


def _resolve_case(case_id: int):
    """Return (case_uuid, case_name, client_id) for a ClickHouse case_id."""
    try:
        from models.case import Case

        case = Case.query.filter_by(id=int(case_id)).first()
        if case is None:
            return None, None, None
        return case.uuid, case.name, case.client_id
    except Exception:
        logger.debug("Could not resolve case for case_id=%s", case_id, exc_info=True)
        return None, None, None


def _has_context() -> bool:
    try:
        from flask import has_app_context

        return has_app_context()
    except Exception:
        return False


def record_bulk_change(change: EvidenceChange) -> Optional[str]:
    """Record a predicate-driven bulk evidence mutation as one summary row.

    Returns the operation id, or None when the record could not be written.
    """
    if not _has_context():
        logger.error(
            "Evidence mutation on case_id=%s field=%s was not audited: no application context",
            change.case_id,
            change.field_name,
        )
        return None

    try:
        from models.audit_log import AuditEntityType, AuditLog

        case_uuid, case_name, client_id = _resolve_case(change.case_id)

        details = dict(change.details)
        details.setdefault("predicate", change.predicate)
        details.setdefault("scope", "bulk")
        details.setdefault("case_id", change.case_id)

        AuditLog.log(
            entity_type=AuditEntityType.EVENT,
            entity_id=f"case:{change.case_id}",
            entity_name=change.entity_name or case_name,
            action=change.action,
            field_name=change.field_name,
            old_value=change.old_value,
            new_value=change.new_value,
            case_uuid=case_uuid,
            client_id=client_id,
            source_file=change.source_file,
            operation_id=change.operation_id,
            affected_count=change.affected_count,
            username=change.username,
            remote_ip=change.remote_ip,
            details=details,
        )
        return change.operation_id
    except Exception:
        logger.exception(
            "Failed to audit evidence mutation on case_id=%s field=%s",
            change.case_id,
            change.field_name,
        )
        return None


def record_event_changes(change: EvidenceChange, events: Iterable[EventChange]) -> Optional[str]:
    """Record one audit row per named event, with that event's before/after.

    Use when the caller acted on an explicit list of events. Falls back to a
    summary row when the list is empty.
    """
    event_list = list(events)
    if not event_list:
        return record_bulk_change(change)

    if not _has_context():
        logger.error(
            "Evidence mutation on case_id=%s field=%s affecting %d event(s) was not audited: "
            "no application context",
            change.case_id,
            change.field_name,
            len(event_list),
        )
        return None

    try:
        from models.audit_log import AuditEntityType, AuditLog

        case_uuid, case_name, client_id = _resolve_case(change.case_id)

        records = []
        for event in event_list:
            details = dict(change.details)
            details.setdefault("scope", "event")
            details.setdefault("case_id", change.case_id)
            if event.artifact_type:
                details.setdefault("artifact_type", event.artifact_type)

            records.append(
                dict(
                    entity_type=AuditEntityType.EVENT,
                    entity_id=event.selector_key,
                    entity_name=change.entity_name or case_name,
                    action=change.action,
                    field_name=change.field_name,
                    old_value=event.old_value if event.old_value is not None else change.old_value,
                    new_value=event.new_value if event.new_value is not None else change.new_value,
                    case_uuid=case_uuid,
                    client_id=client_id,
                    source_file=event.source_file or change.source_file,
                    event_selector_key=event.selector_key,
                    operation_id=change.operation_id,
                    username=change.username,
                    remote_ip=change.remote_ip,
                    details=details,
                )
            )

        AuditLog.log_many(records)
        return change.operation_id
    except Exception:
        logger.exception(
            "Failed to audit %d event change(s) on case_id=%s field=%s",
            len(event_list),
            change.case_id,
            change.field_name,
        )
        return None


__all__ = [
    "EVIDENCE_BULK_UPDATED",
    "EVIDENCE_TAGGED",
    "EVIDENCE_UNTAGGED",
    "EventChange",
    "EvidenceChange",
    "new_operation_id",
    "record_bulk_change",
    "record_event_changes",
    "resolve_case_uuid",
]
