"""Service layer for analyst-authored Investigation Threads.

Investigation Threads curate durable references to graph objects, evidence,
IOCs, and findings. They do not create graph relationships and they are never
authored by AI flows.
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any, Iterable

from sqlalchemy import func
from sqlalchemy.exc import IntegrityError

from models.audit_log import AuditAction, AuditEntityType, AuditLog
from models.case import Case
from models.database import db
from models.graph_saved_view import GraphSavedView
from models.investigation_thread import (
    InvestigationThread,
    InvestigationThreadEntity,
    InvestigationThreadEvidence,
    InvestigationThreadFinding,
    InvestigationThreadIOC,
    InvestigationThreadNote,
    InvestigationThreadRelationship,
    InvestigationThreadStatus,
)
from models.ioc import IOC
from models.rag import PatternMatch
from utils.graph_query import EVIDENCE_RECORD_KEY_RE, GraphNotFoundError, GraphQueryError, GraphQueryService
from utils.investigation_references import (
    FINDING_KIND_PATTERN_MATCH,
    FINDING_KIND_UNIFIED,
    FINDING_KINDS,
    build_entity_reference,
    build_evidence_reference,
    build_evidence_snapshot,
    build_ioc_reference,
    build_pattern_match_reference,
    build_relationship_reference,
    build_unified_finding_reference,
    entity_reference_from_graph_entity,
    entity_snapshot_from_graph_entity,
    evidence_set_fingerprint,
    ioc_snapshot_from_model,
    membership_fingerprint_entry,
    pattern_match_snapshot,
    relationship_reference_from_graph_relationship,
    relationship_snapshot_from_graph,
    require_graph_entity,
    require_graph_relationship,
    resolve_entity_reference,
    resolve_relationship_reference,
    snapshot_sha256,
    unified_finding_snapshot,
)
from utils.unified_findings_store import UNIFIED_FINDINGS_TABLE


TITLE_MAX = 255
DESCRIPTION_MAX = 20000
CONCLUSION_MAX = 50000
RATIONALE_MAX = 20000
NOTE_MAX = 20000
LIST_DEFAULT = 50
LIST_MAX = 200
MEMBERSHIP_MAX = 2000

AUDIT_ENTITY_TYPE = AuditEntityType.INVESTIGATION_THREAD


class InvestigationThreadError(ValueError):
    """Client-correctable investigation-thread service error."""


class InvestigationThreadConflictError(InvestigationThreadError):
    """Raised when an optimistic concurrency check fails."""

    def __init__(self, message, *, current_version):
        super().__init__(message)
        self.current_version = current_version


class InvestigationThreadNotFoundError(InvestigationThreadError):
    """Raised when a case-scoped thread or membership is absent."""


class InvestigationThreadService:
    """Case-scoped service for analyst-curated Investigation Threads."""

    def create_thread(
        self,
        case_id,
        *,
        title,
        description=None,
        status=InvestigationThreadStatus.DRAFT,
        owner_user_id=None,
        owner_username=None,
        time_start=None,
        time_end=None,
        include_in_report=False,
        actor,
    ):
        case = self._require_case(case_id)
        title = self._validate_text("title", title, TITLE_MAX, required=True)
        description = self._validate_text("description", description, DESCRIPTION_MAX)
        status = self._validate_status(status)
        actor_fields = self._actor_fields(actor)
        now = datetime.utcnow()

        thread = InvestigationThread(
            case_id=case.id,
            title=title,
            description=description,
            status=status,
            owner_user_id=owner_user_id,
            owner_username=self._validate_text("owner_username", owner_username, 80),
            time_start=self._parse_dt(time_start),
            time_end=self._parse_dt(time_end),
            include_in_report=self._parse_bool(include_in_report),
            evidence_set_fingerprint=evidence_set_fingerprint([]),
            version=1,
            created_by_user_id=actor_fields["user_id"],
            created_by_username=actor_fields["username"],
            created_at=now,
            updated_by_user_id=actor_fields["user_id"],
            updated_by_username=actor_fields["username"],
            updated_at=now,
        )
        db.session.add(thread)
        db.session.flush()

        AuditLog.log(
            entity_type=AUDIT_ENTITY_TYPE,
            entity_id=thread.uuid,
            entity_name=thread.title,
            action=AuditAction.CREATED,
            case_uuid=case.uuid,
            details={"thread_uuid": thread.uuid, "status": thread.status},
            **actor_fields,
        )
        return self._serialize_thread(thread)

    def list_threads(self, case_id, *, limit=LIST_DEFAULT, offset=0, status=None):
        case_id = self._case_id(case_id)
        limit = self._parse_limit(limit)
        offset = self._parse_offset(offset)
        query = InvestigationThread.query.filter_by(case_id=case_id)
        if status is not None:
            query = query.filter_by(status=self._validate_status(status))
        total = query.count()
        rows = (
            query.order_by(InvestigationThread.updated_at.desc(), InvestigationThread.id.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )
        return {
            "threads": [self._serialize_thread(row) for row in rows],
            "pagination": {
                "limit": limit,
                "offset": offset,
                "total": int(total),
                "has_more": offset + len(rows) < total,
            },
        }

    def get_thread(self, case_id, thread_uuid, *, include_memberships=True):
        thread = self._get_thread(case_id, thread_uuid)
        payload = {
            "thread": self._serialize_thread(thread),
            "entities": [],
            "relationships": [],
            "evidence": [],
            "iocs": [],
            "findings": [],
            "notes": [],
            "counts": self._counts(thread),
        }
        if not include_memberships:
            return payload

        payload["entities"] = [
            self._serialize_entity_membership(row)
            for row in thread.entity_memberships.order_by(InvestigationThreadEntity.sequence_order.asc(), InvestigationThreadEntity.id.asc()).all()
        ]
        payload["relationships"] = [
            self._serialize_relationship_membership(row)
            for row in thread.relationship_memberships.order_by(
                InvestigationThreadRelationship.sequence_order.asc(),
                InvestigationThreadRelationship.id.asc(),
            ).all()
        ]
        payload["evidence"] = [
            self._serialize_evidence_membership(row)
            for row in thread.evidence_memberships.order_by(
                InvestigationThreadEvidence.sequence_order.asc(),
                InvestigationThreadEvidence.id.asc(),
            ).all()
        ]
        payload["iocs"] = [
            self._serialize_ioc_membership(row)
            for row in thread.ioc_memberships.order_by(InvestigationThreadIOC.sequence_order.asc(), InvestigationThreadIOC.id.asc()).all()
        ]
        payload["findings"] = [
            self._serialize_finding_membership(row)
            for row in thread.finding_memberships.order_by(
                InvestigationThreadFinding.sequence_order.asc(),
                InvestigationThreadFinding.id.asc(),
            ).all()
        ]
        payload["notes"] = [
            self._serialize_note(row)
            for row in thread.notes.order_by(InvestigationThreadNote.sequence_order.asc(), InvestigationThreadNote.id.asc()).all()
        ]
        return payload

    def update_thread(self, case_id, thread_uuid, *, expected_version, actor, **fields):
        case = self._require_case(case_id)
        thread = self._get_thread(case.id, thread_uuid)
        allowed_fields = {
            "title",
            "description",
            "analyst_conclusion",
            "status",
            "owner_user_id",
            "owner_username",
            "time_start",
            "time_end",
            "include_in_report",
            "current_saved_view_uuid",
        }
        unknown = sorted(set(fields) - allowed_fields)
        if unknown:
            raise InvestigationThreadError(f"Unsupported field: {unknown[0]}")

        values = {}
        if "title" in fields:
            values["title"] = self._validate_text("title", fields["title"], TITLE_MAX, required=True)
        if "description" in fields:
            values["description"] = self._validate_text("description", fields["description"], DESCRIPTION_MAX)
        if "analyst_conclusion" in fields:
            values["analyst_conclusion"] = self._validate_text("analyst_conclusion", fields["analyst_conclusion"], CONCLUSION_MAX)
        if "status" in fields:
            values["status"] = self._validate_status(fields["status"])
        if "owner_user_id" in fields:
            values["owner_user_id"] = fields["owner_user_id"]
        if "owner_username" in fields:
            values["owner_username"] = self._validate_text("owner_username", fields["owner_username"], 80)
        if "time_start" in fields:
            values["time_start"] = self._parse_dt(fields["time_start"])
        if "time_end" in fields:
            values["time_end"] = self._parse_dt(fields["time_end"])
        if "include_in_report" in fields:
            values["include_in_report"] = self._parse_bool(fields["include_in_report"])
        if "current_saved_view_uuid" in fields:
            view_uuid = fields["current_saved_view_uuid"]
            if view_uuid in (None, ""):
                values["current_saved_view_id"] = None
            else:
                view = GraphSavedView.query.filter_by(case_id=case.id, uuid=str(view_uuid)).first()
                if view is None:
                    raise InvestigationThreadError("Saved graph view not found for this case")
                values["current_saved_view_id"] = view.id

        changes = {}
        for key, value in values.items():
            audit_key = "current_saved_view_uuid" if key == "current_saved_view_id" else key
            old_value = (
                thread.current_saved_view.uuid
                if key == "current_saved_view_id" and thread.current_saved_view is not None
                else getattr(thread, key)
            )
            new_value = (
                fields.get("current_saved_view_uuid")
                if key == "current_saved_view_id"
                else value
            )
            if self._values_differ(old_value, new_value):
                changes[audit_key] = (self._json_safe(old_value), self._json_safe(new_value))
        if not changes:
            self._ensure_expected_version_current(thread, expected_version)
            return self._serialize_thread(thread)

        self._bump_version(thread, expected_version, actor, values)
        db.session.flush()
        AuditLog.log_many(
            [
                self._audit_record(
                    case,
                    thread,
                    AuditAction.UPDATED,
                    actor,
                    field_name=field_name,
                    old_value=old_value,
                    new_value=new_value,
                )
                for field_name, (old_value, new_value) in changes.items()
            ]
        )
        return self._serialize_thread(thread)

    def create_from_selection(
        self,
        case_id,
        *,
        title,
        description=None,
        entity_ids=None,
        relationship_ids=None,
        evidence_record_keys=None,
        actor,
    ):
        case = self._require_case(case_id)
        title = self._validate_text("title", title, TITLE_MAX, required=True)
        description = self._validate_text("description", description, DESCRIPTION_MAX)
        actor_fields = self._actor_fields(actor)
        operation_id = str(uuid.uuid4())
        now = datetime.utcnow()

        entity_ids = self._dedupe(entity_ids or [])
        relationship_ids = self._dedupe(relationship_ids or [])
        evidence_record_keys = self._dedupe(evidence_record_keys or [])
        self._ensure_membership_capacity_values(
            len(entity_ids) + len(relationship_ids) + len(evidence_record_keys)
        )

        thread = InvestigationThread(
            case_id=case.id,
            title=title,
            description=description,
            status=InvestigationThreadStatus.DRAFT,
            owner_user_id=actor_fields["user_id"],
            owner_username=actor_fields["username"],
            include_in_report=False,
            evidence_set_fingerprint=evidence_set_fingerprint([]),
            version=1,
            created_by_user_id=actor_fields["user_id"],
            created_by_username=actor_fields["username"],
            created_at=now,
            updated_by_user_id=actor_fields["user_id"],
            updated_by_username=actor_fields["username"],
            updated_at=now,
        )
        db.session.add(thread)
        db.session.flush()

        added_counts = {"entities": 0, "relationships": 0, "evidence": 0}
        for entity_id in entity_ids:
            entity = require_graph_entity(case.id, entity_id)
            db.session.add(self._build_entity_membership(case.id, thread.id, entity, actor, added_counts["entities"]))
            added_counts["entities"] += 1
        for relationship_id in relationship_ids:
            relationship, source, target = require_graph_relationship(case.id, relationship_id)
            db.session.add(
                self._build_relationship_membership(
                    case.id,
                    thread.id,
                    relationship,
                    source,
                    target,
                    actor,
                    added_counts["relationships"],
                )
            )
            added_counts["relationships"] += 1
        for erk in evidence_record_keys:
            db.session.add(
                self._build_evidence_membership(case.id, thread.id, erk, actor, added_counts["evidence"])
            )
            added_counts["evidence"] += 1

        db.session.flush()
        thread.evidence_set_fingerprint = self._recompute_fingerprint(thread)
        db.session.flush()
        audit_records = [
            self._audit_record(
                case,
                thread,
                AuditAction.CREATED,
                actor,
                operation_id=operation_id,
                details={"thread_uuid": thread.uuid, "created_from_selection": True, "added": added_counts},
            )
        ]
        audit_records.extend(
            self._membership_audit_records(case, thread, actor, operation_id, "created_from_selection", added_counts)
        )
        AuditLog.log_many(audit_records)
        return {
            "thread": self._serialize_thread(thread),
            "added": added_counts,
            "operation_id": operation_id,
        }

    def add_selection(
        self,
        case_id,
        thread_uuid,
        *,
        expected_version,
        entity_ids=None,
        relationship_ids=None,
        evidence_record_keys=None,
        actor,
    ):
        case = self._require_case(case_id)
        thread = self._get_thread(case.id, thread_uuid)
        self._ensure_expected_version_current(thread, expected_version)
        entity_ids = self._dedupe(entity_ids or [])
        relationship_ids = self._dedupe(relationship_ids or [])
        evidence_record_keys = self._dedupe(evidence_record_keys or [])

        counts = {
            "entities": {"added": 0, "already_present": 0},
            "relationships": {"added": 0, "already_present": 0},
            "evidence": {"added": 0, "already_present": 0},
        }
        current_membership_count = self._membership_count(thread)
        pending_additions = 0
        for entity_id in entity_ids:
            entity = require_graph_entity(case.id, entity_id)
            ref = entity_reference_from_graph_entity(entity)
            if self._entity_membership(thread, ref["stable_reference_key"]):
                counts["entities"]["already_present"] += 1
                continue
            self._ensure_membership_capacity_values(current_membership_count + pending_additions + 1)
            db.session.add(self._build_entity_membership(case.id, thread.id, entity, actor))
            counts["entities"]["added"] += 1
            pending_additions += 1
        for relationship_id in relationship_ids:
            relationship, source, target = require_graph_relationship(case.id, relationship_id)
            ref = relationship_reference_from_graph_relationship(relationship, source_entity=source, target_entity=target)
            if self._relationship_membership(thread, ref["stable_reference_key"]):
                counts["relationships"]["already_present"] += 1
                continue
            self._ensure_membership_capacity_values(current_membership_count + pending_additions + 1)
            db.session.add(self._build_relationship_membership(case.id, thread.id, relationship, source, target, actor))
            counts["relationships"]["added"] += 1
            pending_additions += 1
        for erk in evidence_record_keys:
            self._validate_evidence_record_key(erk)
            if self._evidence_membership(thread, erk):
                counts["evidence"]["already_present"] += 1
                continue
            self._ensure_membership_capacity_values(current_membership_count + pending_additions + 1)
            db.session.add(self._build_evidence_membership(case.id, thread.id, erk, actor))
            counts["evidence"]["added"] += 1
            pending_additions += 1

        added_total = sum(bucket["added"] for bucket in counts.values())
        if not added_total:
            return {
                "version": thread.version,
                "evidence_set_fingerprint": thread.evidence_set_fingerprint,
                "counts": counts,
            }
        self._finalize_membership_mutation(case, thread, expected_version, actor, AuditAction.LINKED, "add_selection", counts)
        return {
            "version": thread.version,
            "evidence_set_fingerprint": thread.evidence_set_fingerprint,
            "counts": counts,
        }

    def link_entity(
        self,
        case_id,
        thread_uuid,
        *,
        expected_version,
        entity_id=None,
        stable_reference_key=None,
        stable_reference=None,
        entity_type=None,
        entity_key=None,
        analyst_rationale=None,
        actor,
    ):
        case = self._require_case(case_id)
        thread = self._get_thread(case.id, thread_uuid)
        if entity_id is not None:
            entity = require_graph_entity(case.id, entity_id)
            reference = entity_reference_from_graph_entity(entity)
        else:
            reference = self._coerce_entity_reference(case.id, stable_reference_key, stable_reference, entity_type, entity_key)
            entity, live_available = resolve_entity_reference(case.id, reference)
            if not live_available:
                raise InvestigationThreadError("Graph entity is not currently available for snapshot")
        existing = self._entity_membership(thread, reference["stable_reference_key"])
        if existing:
            self._ensure_expected_version_current(thread, expected_version)
            return {"added": False, "version": thread.version, "entity": self._serialize_entity_membership(existing)}
        self._ensure_membership_capacity(thread, 1)
        membership = self._build_entity_membership(case.id, thread.id, entity, actor, analyst_rationale=analyst_rationale)
        db.session.add(membership)
        self._finalize_single_membership_mutation(case, thread, expected_version, actor, AuditAction.LINKED, "entity", reference)
        return {"added": True, "version": thread.version, "entity": self._serialize_entity_membership(membership)}

    def unlink_entity(self, case_id, thread_uuid, *, expected_version, stable_reference_key, actor):
        return self._unlink_membership(
            case_id,
            thread_uuid,
            expected_version=expected_version,
            stable_reference_key=stable_reference_key,
            actor=actor,
            model=InvestigationThreadEntity,
            kind="entity",
            lookup_field="stable_reference_key",
        )

    def link_relationship(
        self,
        case_id,
        thread_uuid,
        *,
        expected_version,
        relationship_id=None,
        stable_reference_key=None,
        stable_reference=None,
        source_entity_type=None,
        source_entity_key=None,
        relationship_type=None,
        target_entity_type=None,
        target_entity_key=None,
        derivation_type=None,
        analyst_rationale=None,
        actor,
    ):
        case = self._require_case(case_id)
        thread = self._get_thread(case.id, thread_uuid)
        if relationship_id is not None:
            relationship, source, target = require_graph_relationship(case.id, relationship_id)
            reference = relationship_reference_from_graph_relationship(
                relationship,
                source_entity=source,
                target_entity=target,
            )
        else:
            reference = self._coerce_relationship_reference(
                case.id,
                stable_reference_key,
                stable_reference,
                source_entity_type,
                source_entity_key,
                relationship_type,
                target_entity_type,
                target_entity_key,
                derivation_type,
            )
            relationship, live_available, source, target = resolve_relationship_reference(case.id, reference)
            if not live_available:
                raise InvestigationThreadError("Graph relationship is not currently available for snapshot")
        existing = self._relationship_membership(thread, reference["stable_reference_key"])
        if existing:
            self._ensure_expected_version_current(thread, expected_version)
            return {"added": False, "version": thread.version, "relationship": self._serialize_relationship_membership(existing)}
        self._ensure_membership_capacity(thread, 1)
        membership = self._build_relationship_membership(
            case.id,
            thread.id,
            relationship,
            source,
            target,
            actor,
            analyst_rationale=analyst_rationale,
        )
        db.session.add(membership)
        self._finalize_single_membership_mutation(case, thread, expected_version, actor, AuditAction.LINKED, "relationship", reference)
        return {"added": True, "version": thread.version, "relationship": self._serialize_relationship_membership(membership)}

    def unlink_relationship(self, case_id, thread_uuid, *, expected_version, stable_reference_key, actor):
        return self._unlink_membership(
            case_id,
            thread_uuid,
            expected_version=expected_version,
            stable_reference_key=stable_reference_key,
            actor=actor,
            model=InvestigationThreadRelationship,
            kind="relationship",
            lookup_field="stable_reference_key",
        )

    def link_evidence(
        self,
        case_id,
        thread_uuid,
        *,
        expected_version,
        evidence_record_key,
        originating_relationship_id=None,
        analyst_visible_summary=None,
        analyst_rationale=None,
        actor,
    ):
        case = self._require_case(case_id)
        thread = self._get_thread(case.id, thread_uuid)
        erk = self._validate_evidence_record_key(evidence_record_key)
        existing = self._evidence_membership(thread, erk)
        if existing:
            self._ensure_expected_version_current(thread, expected_version)
            return {"added": False, "version": thread.version, "evidence": self._serialize_evidence_membership(existing)}
        self._ensure_expected_version_current(thread, expected_version)
        self._ensure_membership_capacity(thread, 1)
        membership = self._build_evidence_membership(
            case.id,
            thread.id,
            erk,
            actor,
            originating_relationship_id=originating_relationship_id,
            analyst_visible_summary=analyst_visible_summary,
            analyst_rationale=analyst_rationale,
        )
        db.session.add(membership)
        self._finalize_single_membership_mutation(
            case,
            thread,
            expected_version,
            actor,
            AuditAction.LINKED,
            "evidence",
            {"evidence_record_key": erk},
        )
        return {"added": True, "version": thread.version, "evidence": self._serialize_evidence_membership(membership)}

    def unlink_evidence(self, case_id, thread_uuid, *, expected_version, snapshot_uuid, actor):
        return self._unlink_membership(
            case_id,
            thread_uuid,
            expected_version=expected_version,
            stable_reference_key=snapshot_uuid,
            actor=actor,
            model=InvestigationThreadEvidence,
            kind="evidence",
            lookup_field="snapshot_uuid",
        )

    def link_ioc(
        self,
        case_id,
        thread_uuid,
        *,
        expected_version,
        ioc_uuid,
        analyst_rationale=None,
        actor,
    ):
        case = self._require_case(case_id)
        thread = self._get_thread(case.id, thread_uuid)
        ioc = self._require_ioc(case.id, ioc_uuid)
        existing = InvestigationThreadIOC.query.filter_by(thread_id=thread.id, ioc_uuid=ioc.uuid).first()
        if existing:
            self._ensure_expected_version_current(thread, expected_version)
            return {"added": False, "version": thread.version, "ioc": self._serialize_ioc_membership(existing)}
        self._ensure_membership_capacity(thread, 1)
        membership = self._build_ioc_membership(case.id, thread.id, ioc, actor, analyst_rationale=analyst_rationale)
        db.session.add(membership)
        self._finalize_single_membership_mutation(
            case,
            thread,
            expected_version,
            actor,
            AuditAction.LINKED,
            "ioc",
            {"ioc_uuid": ioc.uuid},
        )
        return {"added": True, "version": thread.version, "ioc": self._serialize_ioc_membership(membership)}

    def unlink_ioc(self, case_id, thread_uuid, *, expected_version, ioc_uuid, actor):
        return self._unlink_membership(
            case_id,
            thread_uuid,
            expected_version=expected_version,
            stable_reference_key=ioc_uuid,
            actor=actor,
            model=InvestigationThreadIOC,
            kind="ioc",
            lookup_field="ioc_uuid",
        )

    def link_finding(
        self,
        case_id,
        thread_uuid,
        *,
        expected_version,
        finding_kind=FINDING_KIND_UNIFIED,
        stable_reference_key=None,
        stable_reference=None,
        analysis_id=None,
        source_system=None,
        dedup_key=None,
        finding_id=None,
        pattern_match_id=None,
        analyst_rationale=None,
        actor,
    ):
        case = self._require_case(case_id)
        thread = self._get_thread(case.id, thread_uuid)
        finding_kind = str(finding_kind or FINDING_KIND_UNIFIED).strip()
        if finding_kind not in FINDING_KINDS:
            raise InvestigationThreadError("Invalid finding_kind")
        reference, snapshot = self._finding_reference_and_snapshot(
            case.id,
            finding_kind=finding_kind,
            stable_reference_key=stable_reference_key,
            stable_reference=stable_reference,
            analysis_id=analysis_id,
            source_system=source_system,
            dedup_key=dedup_key,
            finding_id=finding_id,
            pattern_match_id=pattern_match_id,
        )
        existing = self._finding_membership(thread, reference["stable_reference_key"])
        if existing:
            self._ensure_expected_version_current(thread, expected_version)
            return {"added": False, "version": thread.version, "finding": self._serialize_finding_membership(existing)}
        self._ensure_membership_capacity(thread, 1)
        membership = self._build_finding_membership(
            case.id,
            thread.id,
            finding_kind,
            reference,
            snapshot,
            actor,
            analyst_rationale=analyst_rationale,
        )
        db.session.add(membership)
        self._finalize_single_membership_mutation(case, thread, expected_version, actor, AuditAction.LINKED, "finding", reference)
        return {"added": True, "version": thread.version, "finding": self._serialize_finding_membership(membership)}

    def unlink_finding(self, case_id, thread_uuid, *, expected_version, stable_reference_key, actor):
        return self._unlink_membership(
            case_id,
            thread_uuid,
            expected_version=expected_version,
            stable_reference_key=stable_reference_key,
            actor=actor,
            model=InvestigationThreadFinding,
            kind="finding",
            lookup_field="stable_reference_key",
        )

    def add_note(self, case_id, thread_uuid, *, expected_version, body, actor):
        case = self._require_case(case_id)
        thread = self._get_thread(case.id, thread_uuid)
        actor_fields = self._actor_fields(actor)
        note = InvestigationThreadNote(
            case_id=case.id,
            thread_id=thread.id,
            body=self._validate_text("body", body, NOTE_MAX, required=True),
            sequence_order=self._next_sequence(InvestigationThreadNote, thread.id),
            author_user_id=actor_fields["user_id"],
            author_username=actor_fields["username"],
        )
        db.session.add(note)
        self._bump_version(thread, expected_version, actor)
        db.session.flush()
        AuditLog.log(
            **self._audit_record(
                case,
                thread,
                AuditAction.CREATED,
                actor,
                field_name="note",
                new_value={"note_uuid": note.uuid},
                details={"note_uuid": note.uuid},
            )
        )
        return {"version": thread.version, "note": self._serialize_note(note)}

    def update_note(self, case_id, thread_uuid, *, note_uuid, expected_version, body, actor):
        case = self._require_case(case_id)
        thread = self._get_thread(case.id, thread_uuid)
        note = InvestigationThreadNote.query.filter_by(case_id=case.id, thread_id=thread.id, uuid=str(note_uuid)).first()
        if note is None:
            raise InvestigationThreadNotFoundError("Note not found")
        new_body = self._validate_text("body", body, NOTE_MAX, required=True)
        if note.body == new_body:
            self._ensure_expected_version_current(thread, expected_version)
            return {"version": thread.version, "note": self._serialize_note(note)}
        old_body = note.body
        note.body = new_body
        note.updated_at = datetime.utcnow()
        self._bump_version(thread, expected_version, actor)
        db.session.flush()
        AuditLog.log(
            **self._audit_record(
                case,
                thread,
                AuditAction.UPDATED,
                actor,
                field_name="note",
                old_value=old_body,
                new_value=new_body,
                details={"note_uuid": note.uuid},
            )
        )
        return {"version": thread.version, "note": self._serialize_note(note)}

    def remove_note(self, case_id, thread_uuid, *, note_uuid, expected_version, actor):
        case = self._require_case(case_id)
        thread = self._get_thread(case.id, thread_uuid)
        note = InvestigationThreadNote.query.filter_by(case_id=case.id, thread_id=thread.id, uuid=str(note_uuid)).first()
        if note is None:
            self._ensure_expected_version_current(thread, expected_version)
            return {"removed": False, "version": thread.version}
        final_state = self._serialize_note(note)
        db.session.delete(note)
        self._bump_version(thread, expected_version, actor)
        db.session.flush()
        AuditLog.log(
            **self._audit_record(
                case,
                thread,
                AuditAction.DELETED,
                actor,
                field_name="note",
                old_value=final_state,
                details={"note_uuid": str(note_uuid)},
            )
        )
        return {"removed": True, "version": thread.version}

    def _bump_version(self, thread, expected_version, actor, extra_values=None):
        expected_version = self._parse_expected_version(expected_version)
        actor_fields = self._actor_fields(actor)
        now = datetime.utcnow()
        update_values = {
            InvestigationThread.version: expected_version + 1,
            InvestigationThread.updated_at: now,
            InvestigationThread.updated_by_user_id: actor_fields["user_id"],
            InvestigationThread.updated_by_username: actor_fields["username"],
            InvestigationThread.evidence_set_fingerprint: thread.evidence_set_fingerprint or evidence_set_fingerprint([]),
        }
        for field_name, value in (extra_values or {}).items():
            if not hasattr(InvestigationThread, field_name):
                raise InvestigationThreadError(f"Unsupported thread update field: {field_name}")
            update_values[getattr(InvestigationThread, field_name)] = value
        with db.session.no_autoflush:
            updated = (
                InvestigationThread.query.filter_by(
                    id=thread.id,
                    case_id=thread.case_id,
                    version=expected_version,
                ).update(update_values, synchronize_session=False)
            )
        if updated != 1:
            fresh = InvestigationThread.query.filter_by(id=thread.id, case_id=thread.case_id).first()
            current_version = fresh.version if fresh is not None else None
            db.session.rollback()
            raise InvestigationThreadConflictError(
                "Investigation thread was modified by another request",
                current_version=current_version,
            )
        db.session.refresh(thread)
        return thread

    def _recompute_fingerprint(self, thread):
        entries = []
        for row in InvestigationThreadEntity.query.filter_by(thread_id=thread.id).all():
            entries.append(
                membership_fingerprint_entry(
                    kind="entity",
                    stable_reference_key=row.stable_reference_key,
                    snapshot_sha256_value=row.snapshot_sha256,
                )
            )
        for row in InvestigationThreadRelationship.query.filter_by(thread_id=thread.id).all():
            entries.append(
                membership_fingerprint_entry(
                    kind="relationship",
                    stable_reference_key=row.stable_reference_key,
                    snapshot_sha256_value=row.snapshot_sha256,
                )
            )
        for row in InvestigationThreadEvidence.query.filter_by(thread_id=thread.id).all():
            entries.append(
                membership_fingerprint_entry(
                    kind="evidence",
                    stable_reference_key=row.evidence_record_key,
                    snapshot_sha256_value=row.snapshot_sha256,
                )
            )
        for row in InvestigationThreadIOC.query.filter_by(thread_id=thread.id).all():
            entries.append(
                membership_fingerprint_entry(
                    kind="ioc",
                    stable_reference_key=row.stable_reference_key,
                    snapshot_sha256_value=row.snapshot_sha256,
                )
            )
        for row in InvestigationThreadFinding.query.filter_by(thread_id=thread.id).all():
            entries.append(
                membership_fingerprint_entry(
                    kind="finding",
                    stable_reference_key=row.stable_reference_key,
                    snapshot_sha256_value=row.snapshot_sha256,
                )
            )
        return evidence_set_fingerprint(entries)

    def _membership_count(self, thread):
        return sum(self._counts(thread).values())

    def _actor_fields(self, actor):
        actor = actor or {}
        if actor.get("is_ai") or str(actor.get("actor_type") or "").strip().lower() == "ai":
            raise InvestigationThreadError("AI actors cannot author investigation threads")
        username = str(actor.get("username") or "").strip()
        if not username:
            raise InvestigationThreadError("actor.username is required")
        return {
            "user_id": actor.get("user_id"),
            "username": username[:80],
        }

    def _parse_dt(self, value):
        if value in (None, ""):
            return None
        if isinstance(value, datetime):
            return value
        if isinstance(value, str):
            text = value.strip()
            if not text:
                return None
            if text.endswith("Z"):
                text = f"{text[:-1]}+00:00"
            try:
                parsed = datetime.fromisoformat(text)
            except ValueError as exc:
                raise InvestigationThreadError("Invalid datetime") from exc
            if parsed.tzinfo is not None:
                parsed = parsed.astimezone(timezone.utc).replace(tzinfo=None)
            return parsed
        raise InvestigationThreadError("Invalid datetime")

    def _validate_text(self, field_name, value, maximum, *, required=False):
        if value is None:
            if required:
                raise InvestigationThreadError(f"{field_name} is required")
            return None
        text = str(value).strip() if required else str(value)
        if required and not text:
            raise InvestigationThreadError(f"{field_name} is required")
        if len(text) > maximum:
            raise InvestigationThreadError(f"{field_name} exceeds {maximum} characters")
        return text

    def _serialize_thread(self, thread):
        saved_view_uuid = thread.current_saved_view.uuid if thread.current_saved_view else None
        return {
            "id": thread.id,
            "uuid": thread.uuid,
            "case_id": thread.case_id,
            "title": thread.title,
            "description": thread.description,
            "analyst_conclusion": thread.analyst_conclusion,
            "status": thread.status,
            "owner_user_id": thread.owner_user_id,
            "owner_username": thread.owner_username,
            "time_start": self._iso(thread.time_start),
            "time_end": self._iso(thread.time_end),
            "include_in_report": bool(thread.include_in_report),
            "current_saved_view_uuid": saved_view_uuid,
            "evidence_set_fingerprint": thread.evidence_set_fingerprint,
            "version": thread.version,
            "created_by_user_id": thread.created_by_user_id,
            "created_by_username": thread.created_by_username,
            "created_at": self._iso(thread.created_at),
            "updated_by_user_id": thread.updated_by_user_id,
            "updated_by_username": thread.updated_by_username,
            "updated_at": self._iso(thread.updated_at),
            "counts": self._counts(thread),
        }

    def _serialize_entity_membership(self, row):
        live = None
        live_available = False
        try:
            entity, live_available = resolve_entity_reference(row.case_id, row.stable_reference_json or {})
            live = self._entity_live_dict(entity) if entity is not None else None
        except Exception:
            live = None
            live_available = False
        return {
            **self._membership_base(row),
            "entity_type": row.entity_type,
            "entity_key": row.entity_key,
            "stable_reference_key": row.stable_reference_key,
            "stable_reference": row.stable_reference_json,
            "current_graph_entity_id": row.current_graph_entity_id,
            "frozen_display_value": row.frozen_display_value,
            "frozen_canonical_value": row.frozen_canonical_value,
            "snapshot": row.snapshot_json,
            "snapshot_sha256": row.snapshot_sha256,
            "snapshot_version": row.snapshot_version,
            "live": live,
            "live_available": live_available,
        }

    def _serialize_relationship_membership(self, row):
        live = None
        live_available = False
        try:
            relationship, live_available, source, target = resolve_relationship_reference(row.case_id, row.stable_reference_json or {})
            live = self._relationship_live_dict(relationship, source, target) if relationship is not None else None
        except Exception:
            live = None
            live_available = False
        return {
            **self._membership_base(row),
            "source_entity_type": row.source_entity_type,
            "source_entity_key": row.source_entity_key,
            "relationship_type": row.relationship_type,
            "target_entity_type": row.target_entity_type,
            "target_entity_key": row.target_entity_key,
            "derivation_type": row.derivation_type,
            "stable_reference_key": row.stable_reference_key,
            "stable_reference": row.stable_reference_json,
            "current_graph_relationship_id": row.current_graph_relationship_id,
            "frozen_source_display_value": row.frozen_source_display_value,
            "frozen_source_canonical_value": row.frozen_source_canonical_value,
            "frozen_target_display_value": row.frozen_target_display_value,
            "frozen_target_canonical_value": row.frozen_target_canonical_value,
            "snapshot": row.snapshot_json,
            "snapshot_sha256": row.snapshot_sha256,
            "snapshot_version": row.snapshot_version,
            "live": live,
            "live_available": live_available,
        }

    def _serialize_evidence_membership(self, row):
        live_source_available = False
        live = None
        try:
            live = GraphQueryService().exact_evidence(row.case_id, row.evidence_record_key)
            live_source_available = True
        except Exception:
            live = None
            live_source_available = False
        return {
            "id": row.id,
            "snapshot_uuid": row.snapshot_uuid,
            "case_id": row.case_id,
            "thread_id": row.thread_id,
            "evidence_record_key": row.evidence_record_key,
            "source_table": row.source_table,
            "snapshot_available": bool(row.frozen_snapshot_json),
            "live_source_available": live_source_available,
            "source_available_at_addition": bool(row.source_available_at_addition),
            "analyst_visible_summary": row.analyst_visible_summary,
            "originating_relationship_reference_key": row.originating_relationship_reference_key,
            "originating_relationship_reference": row.originating_relationship_reference_json,
            "analyst_rationale": row.analyst_rationale,
            "sequence_order": row.sequence_order,
            "added_by_user_id": row.added_by_user_id,
            "added_by_username": row.added_by_username,
            "added_at": self._iso(row.added_at),
            "snapshot": row.frozen_snapshot_json,
            "snapshot_sha256": row.snapshot_sha256,
            "snapshot_version": row.snapshot_version,
            "live": live,
        }

    def _serialize_ioc_membership(self, row):
        ioc = IOC.query.filter_by(case_id=row.case_id, uuid=row.ioc_uuid).first()
        return {
            **self._membership_base(row),
            "ioc_uuid": row.ioc_uuid,
            "stable_reference_key": row.stable_reference_key,
            "stable_reference": row.stable_reference_json,
            "snapshot": row.snapshot_json,
            "snapshot_sha256": row.snapshot_sha256,
            "snapshot_version": row.snapshot_version,
            "live": ioc.to_dict() if ioc is not None else None,
            "live_available": ioc is not None,
        }

    def _serialize_finding_membership(self, row):
        live = None
        live_available = False
        try:
            if row.finding_kind == FINDING_KIND_UNIFIED:
                ref = row.stable_reference_json or {}
                live = self._load_unified_finding(
                    row.case_id,
                    ref.get("analysis_id"),
                    ref.get("source_system"),
                    ref.get("dedup_key"),
                    ref.get("finding_id"),
                )
                live_available = live is not None
            elif row.finding_kind == FINDING_KIND_PATTERN_MATCH:
                ref = row.stable_reference_json or {}
                match = PatternMatch.query.filter_by(case_id=row.case_id, id=ref.get("pattern_match_id")).first()
                live = match.to_dict() if match is not None else None
                live_available = match is not None
        except Exception:
            live = None
            live_available = False
        return {
            **self._membership_base(row),
            "finding_kind": row.finding_kind,
            "stable_reference_key": row.stable_reference_key,
            "stable_reference": row.stable_reference_json,
            "snapshot": row.snapshot_json,
            "snapshot_sha256": row.snapshot_sha256,
            "snapshot_version": row.snapshot_version,
            "live": live,
            "live_available": live_available,
        }

    def _membership_base(self, row):
        return {
            "id": row.id,
            "uuid": getattr(row, "uuid", None),
            "case_id": row.case_id,
            "thread_id": row.thread_id,
            "analyst_rationale": row.analyst_rationale,
            "sequence_order": row.sequence_order,
            "added_by_user_id": row.added_by_user_id,
            "added_by_username": row.added_by_username,
            "added_at": self._iso(row.added_at),
        }

    def _serialize_note(self, note):
        return {
            "id": note.id,
            "uuid": note.uuid,
            "case_id": note.case_id,
            "thread_id": note.thread_id,
            "body": note.body,
            "sequence_order": note.sequence_order,
            "author_user_id": note.author_user_id,
            "author_username": note.author_username,
            "created_at": self._iso(note.created_at),
            "updated_at": self._iso(note.updated_at),
        }

    def _build_entity_membership(self, case_id, thread_id, entity, actor, sequence_order=None, analyst_rationale=None):
        reference = entity_reference_from_graph_entity(entity)
        snapshot = entity_snapshot_from_graph_entity(entity)
        actor_fields = self._actor_fields(actor)
        return InvestigationThreadEntity(
            case_id=case_id,
            thread_id=thread_id,
            entity_type=entity.entity_type,
            entity_key=entity.entity_key,
            stable_reference_key=reference["stable_reference_key"],
            stable_reference_json=reference,
            current_graph_entity_id=entity.id,
            frozen_display_value=entity.display_value,
            frozen_canonical_value=entity.canonical_value,
            snapshot_json=snapshot,
            snapshot_sha256=snapshot_sha256(snapshot),
            analyst_rationale=self._validate_text("analyst_rationale", analyst_rationale, RATIONALE_MAX),
            sequence_order=self._sequence_or_next(InvestigationThreadEntity, thread_id, sequence_order),
            added_by_user_id=actor_fields["user_id"],
            added_by_username=actor_fields["username"],
        )

    def _build_relationship_membership(
        self,
        case_id,
        thread_id,
        relationship,
        source,
        target,
        actor,
        sequence_order=None,
        analyst_rationale=None,
    ):
        reference = relationship_reference_from_graph_relationship(relationship, source_entity=source, target_entity=target)
        snapshot = relationship_snapshot_from_graph(relationship, source_entity=source, target_entity=target)
        actor_fields = self._actor_fields(actor)
        return InvestigationThreadRelationship(
            case_id=case_id,
            thread_id=thread_id,
            source_entity_type=source.entity_type,
            source_entity_key=source.entity_key,
            relationship_type=relationship.relationship_type,
            target_entity_type=target.entity_type,
            target_entity_key=target.entity_key,
            derivation_type=relationship.derivation_type,
            stable_reference_key=reference["stable_reference_key"],
            stable_reference_json=reference,
            current_graph_relationship_id=relationship.id,
            frozen_source_display_value=source.display_value,
            frozen_source_canonical_value=source.canonical_value,
            frozen_target_display_value=target.display_value,
            frozen_target_canonical_value=target.canonical_value,
            snapshot_json=snapshot,
            snapshot_sha256=snapshot_sha256(snapshot),
            analyst_rationale=self._validate_text("analyst_rationale", analyst_rationale, RATIONALE_MAX),
            sequence_order=self._sequence_or_next(InvestigationThreadRelationship, thread_id, sequence_order),
            added_by_user_id=actor_fields["user_id"],
            added_by_username=actor_fields["username"],
        )

    def _build_evidence_membership(
        self,
        case_id,
        thread_id,
        evidence_record_key,
        actor,
        sequence_order=None,
        originating_relationship_id=None,
        analyst_visible_summary=None,
        analyst_rationale=None,
    ):
        erk = self._validate_evidence_record_key(evidence_record_key)
        reference = build_evidence_reference(case_id=case_id, evidence_record_key=erk)
        originating_reference = None
        if originating_relationship_id not in (None, ""):
            relationship, source, target = require_graph_relationship(case_id, originating_relationship_id)
            originating_reference = relationship_reference_from_graph_relationship(
                relationship,
                source_entity=source,
                target_entity=target,
            )
        event = None
        source_available = True
        live = GraphQueryService().exact_evidence(case_id, erk)
        event = live.get("event") or {}
        summary = self._validate_text("analyst_visible_summary", analyst_visible_summary, 2000)
        snapshot = build_evidence_snapshot(
            case_id=case_id,
            evidence_record_key=erk,
            event=event,
            source_table=reference["source_table"],
            source_available=source_available,
            originating_relationship_reference=originating_reference,
            analyst_visible_summary=summary,
        )
        actor_fields = self._actor_fields(actor)
        return InvestigationThreadEvidence(
            case_id=case_id,
            thread_id=thread_id,
            evidence_record_key=erk,
            source_table=reference["source_table"],
            frozen_snapshot_json=snapshot,
            snapshot_sha256=snapshot_sha256(snapshot),
            analyst_visible_summary=snapshot.get("analyst_visible_summary"),
            source_available_at_addition=source_available,
            originating_relationship_reference_key=originating_reference.get("stable_reference_key") if originating_reference else None,
            originating_relationship_reference_json=originating_reference,
            analyst_rationale=self._validate_text("analyst_rationale", analyst_rationale, RATIONALE_MAX),
            sequence_order=self._sequence_or_next(InvestigationThreadEvidence, thread_id, sequence_order),
            added_by_user_id=actor_fields["user_id"],
            added_by_username=actor_fields["username"],
        )

    def _build_ioc_membership(self, case_id, thread_id, ioc, actor, sequence_order=None, analyst_rationale=None):
        reference = build_ioc_reference(case_id=case_id, ioc_uuid=ioc.uuid)
        snapshot = ioc_snapshot_from_model(ioc)
        actor_fields = self._actor_fields(actor)
        return InvestigationThreadIOC(
            case_id=case_id,
            thread_id=thread_id,
            ioc_uuid=ioc.uuid,
            stable_reference_key=reference["stable_reference_key"],
            stable_reference_json=reference,
            snapshot_json=snapshot,
            snapshot_sha256=snapshot_sha256(snapshot),
            analyst_rationale=self._validate_text("analyst_rationale", analyst_rationale, RATIONALE_MAX),
            sequence_order=self._sequence_or_next(InvestigationThreadIOC, thread_id, sequence_order),
            added_by_user_id=actor_fields["user_id"],
            added_by_username=actor_fields["username"],
        )

    def _build_finding_membership(
        self,
        case_id,
        thread_id,
        finding_kind,
        reference,
        snapshot,
        actor,
        sequence_order=None,
        analyst_rationale=None,
    ):
        actor_fields = self._actor_fields(actor)
        return InvestigationThreadFinding(
            case_id=case_id,
            thread_id=thread_id,
            finding_kind=finding_kind,
            stable_reference_key=reference["stable_reference_key"],
            stable_reference_json=reference,
            snapshot_json=snapshot,
            snapshot_sha256=snapshot_sha256(snapshot),
            analyst_rationale=self._validate_text("analyst_rationale", analyst_rationale, RATIONALE_MAX),
            sequence_order=self._sequence_or_next(InvestigationThreadFinding, thread_id, sequence_order),
            added_by_user_id=actor_fields["user_id"],
            added_by_username=actor_fields["username"],
        )

    def _finalize_membership_mutation(self, case, thread, expected_version, actor, action, reason, counts):
        try:
            db.session.flush()
            thread.evidence_set_fingerprint = self._recompute_fingerprint(thread)
            self._bump_version(thread, expected_version, actor)
            db.session.flush()
            AuditLog.log_many(
                self._membership_audit_records(case, thread, actor, None, reason, counts, action=action)
            )
        except IntegrityError as exc:
            db.session.rollback()
            raise InvestigationThreadError("Thread membership already exists") from exc

    def _finalize_single_membership_mutation(self, case, thread, expected_version, actor, action, kind, reference):
        try:
            db.session.flush()
            thread.evidence_set_fingerprint = self._recompute_fingerprint(thread)
            self._bump_version(thread, expected_version, actor)
            db.session.flush()
            AuditLog.log(
                **self._audit_record(
                    case,
                    thread,
                    action,
                    actor,
                    field_name=kind,
                    new_value=reference if action == AuditAction.LINKED else None,
                    old_value=reference if action == AuditAction.UNLINKED else None,
                    details={"membership_kind": kind, "reference": reference},
                )
            )
        except IntegrityError as exc:
            db.session.rollback()
            raise InvestigationThreadError("Thread membership already exists") from exc

    def _unlink_membership(
        self,
        case_id,
        thread_uuid,
        *,
        expected_version,
        stable_reference_key,
        actor,
        model,
        kind,
        lookup_field,
    ):
        case = self._require_case(case_id)
        thread = self._get_thread(case.id, thread_uuid)
        stable_reference_key = str(stable_reference_key or "").strip()
        if not stable_reference_key:
            raise InvestigationThreadError(f"{lookup_field} is required")
        membership = model.query.filter_by(case_id=case.id, thread_id=thread.id, **{lookup_field: stable_reference_key}).first()
        if membership is None:
            self._ensure_expected_version_current(thread, expected_version)
            return {"removed": False, "version": thread.version, "evidence_set_fingerprint": thread.evidence_set_fingerprint}
        reference = self._membership_reference_for_audit(membership, kind)
        db.session.delete(membership)
        db.session.flush()
        thread.evidence_set_fingerprint = self._recompute_fingerprint(thread)
        self._bump_version(thread, expected_version, actor)
        db.session.flush()
        AuditLog.log(
            **self._audit_record(
                case,
                thread,
                AuditAction.UNLINKED,
                actor,
                field_name=kind,
                old_value=reference,
                details={"membership_kind": kind, "reference": reference},
            )
        )
        return {"removed": True, "version": thread.version, "evidence_set_fingerprint": thread.evidence_set_fingerprint}

    def _membership_audit_records(self, case, thread, actor, operation_id, reason, counts, *, action=AuditAction.LINKED):
        records = []
        for kind, payload in counts.items():
            added = payload.get("added", 0) if isinstance(payload, dict) else payload
            if not added:
                continue
            records.append(
                self._audit_record(
                    case,
                    thread,
                    action,
                    actor,
                    field_name=kind,
                    new_value={"added": int(added)} if action == AuditAction.LINKED else None,
                    details={"reason": reason, "membership_kind": kind, "added": int(added)},
                    operation_id=operation_id,
                    affected_count=int(added),
                )
            )
        return records

    def _load_unified_finding(self, case_id, analysis_id, source_system, dedup_key, finding_id):
        if not all(str(value or "").strip() for value in (analysis_id, source_system, dedup_key, finding_id)):
            return None
        from utils.clickhouse import get_client

        client = get_client()
        result = client.query(
            f"""
            SELECT legacy_json
            FROM {UNIFIED_FINDINGS_TABLE}
            WHERE case_id = {{case_id:UInt32}}
              AND analysis_id = {{analysis_id:String}}
              AND source_system = {{source_system:String}}
              AND dedup_key = {{dedup_key:String}}
              AND finding_id = {{finding_id:String}}
            ORDER BY synced_at DESC
            LIMIT 1
            """,
            parameters={
                "case_id": int(case_id),
                "analysis_id": str(analysis_id),
                "source_system": str(source_system),
                "dedup_key": str(dedup_key),
                "finding_id": str(finding_id),
            },
        )
        rows = list(getattr(result, "result_rows", []) or [])
        if not rows:
            return None
        try:
            return json.loads(rows[0][0] or "{}")
        except (TypeError, ValueError, json.JSONDecodeError):
            return None

    def _finding_reference_and_snapshot(
        self,
        case_id,
        *,
        finding_kind,
        stable_reference_key=None,
        stable_reference=None,
        analysis_id=None,
        source_system=None,
        dedup_key=None,
        finding_id=None,
        pattern_match_id=None,
    ):
        if finding_kind == FINDING_KIND_UNIFIED:
            ref_source = stable_reference or {}
            reference = build_unified_finding_reference(
                case_id=case_id,
                analysis_id=analysis_id or ref_source.get("analysis_id"),
                source_system=source_system or ref_source.get("source_system"),
                dedup_key=dedup_key or ref_source.get("dedup_key"),
                finding_id=finding_id or ref_source.get("finding_id"),
            )
            self._check_stable_key(stable_reference_key, reference)
            finding = self._load_unified_finding(
                case_id,
                reference["analysis_id"],
                reference["source_system"],
                reference["dedup_key"],
                reference["finding_id"],
            )
            if finding is None:
                raise InvestigationThreadError("Unified finding not found")
            snapshot = unified_finding_snapshot(
                case_id=case_id,
                analysis_id=reference["analysis_id"],
                source_system=reference["source_system"],
                dedup_key=reference["dedup_key"],
                finding_id=reference["finding_id"],
                finding=finding,
            )
            return reference, snapshot

        ref_source = stable_reference or {}
        match_id = pattern_match_id or ref_source.get("pattern_match_id")
        reference = build_pattern_match_reference(case_id=case_id, pattern_match_id=match_id)
        self._check_stable_key(stable_reference_key, reference)
        match = PatternMatch.query.filter_by(case_id=case_id, id=reference["pattern_match_id"]).first()
        if match is None:
            raise InvestigationThreadError("Pattern match not found")
        return reference, pattern_match_snapshot(match)

    def _coerce_entity_reference(self, case_id, stable_reference_key, stable_reference, entity_type, entity_key):
        source = stable_reference or {}
        reference = build_entity_reference(
            case_id=case_id,
            entity_type=entity_type or source.get("entity_type"),
            entity_key=entity_key or source.get("entity_key"),
        )
        self._check_stable_key(stable_reference_key, reference)
        return reference

    def _coerce_relationship_reference(
        self,
        case_id,
        stable_reference_key,
        stable_reference,
        source_entity_type,
        source_entity_key,
        relationship_type,
        target_entity_type,
        target_entity_key,
        derivation_type,
    ):
        source = stable_reference or {}
        reference = build_relationship_reference(
            case_id=case_id,
            source_entity_type=source_entity_type or source.get("source_entity_type"),
            source_entity_key=source_entity_key or source.get("source_entity_key"),
            relationship_type=relationship_type or source.get("relationship_type"),
            target_entity_type=target_entity_type or source.get("target_entity_type"),
            target_entity_key=target_entity_key or source.get("target_entity_key"),
            derivation_type=derivation_type or source.get("derivation_type"),
        )
        self._check_stable_key(stable_reference_key, reference)
        return reference

    def _check_stable_key(self, stable_reference_key, reference):
        if stable_reference_key not in (None, "") and str(stable_reference_key) != reference["stable_reference_key"]:
            raise InvestigationThreadError("Stable reference key does not match reference identity")

    def _validate_evidence_record_key(self, value):
        value = str(value or "").strip()
        if not EVIDENCE_RECORD_KEY_RE.fullmatch(value):
            raise InvestigationThreadError("Invalid evidence_record_key")
        return value

    def _require_case(self, case_id):
        case = Case.query.get(self._case_id(case_id))
        if case is None:
            raise InvestigationThreadNotFoundError("Case not found")
        return case

    def _case_id(self, case_id):
        try:
            parsed = int(case_id)
        except (TypeError, ValueError) as exc:
            raise InvestigationThreadError("Invalid case_id") from exc
        if parsed < 1:
            raise InvestigationThreadError("Invalid case_id")
        return parsed

    def _get_thread(self, case_id, thread_uuid):
        thread = InvestigationThread.query.filter_by(case_id=self._case_id(case_id), uuid=str(thread_uuid)).first()
        if thread is None:
            raise InvestigationThreadNotFoundError("Investigation thread not found")
        return thread

    def _require_ioc(self, case_id, ioc_uuid):
        ioc = IOC.query.filter_by(case_id=case_id, uuid=str(ioc_uuid)).first()
        if ioc is None:
            raise InvestigationThreadNotFoundError("IOC not found for this case")
        return ioc

    def _validate_status(self, status):
        status = str(status or "").strip()
        if status not in InvestigationThreadStatus.ALL:
            raise InvestigationThreadError("Invalid investigation thread status")
        return status

    def _parse_bool(self, value):
        if isinstance(value, bool):
            return value
        if value in (None, ""):
            return False
        if isinstance(value, str):
            normalized = value.strip().lower()
            if normalized in {"true", "1", "yes", "on"}:
                return True
            if normalized in {"false", "0", "no", "off"}:
                return False
        return bool(value)

    def _parse_limit(self, value):
        if value in (None, ""):
            return LIST_DEFAULT
        try:
            parsed = int(value)
        except (TypeError, ValueError) as exc:
            raise InvestigationThreadError("Invalid limit") from exc
        if parsed < 1 or parsed > LIST_MAX:
            raise InvestigationThreadError(f"limit must be between 1 and {LIST_MAX}")
        return parsed

    def _parse_offset(self, value):
        if value in (None, ""):
            return 0
        try:
            parsed = int(value)
        except (TypeError, ValueError) as exc:
            raise InvestigationThreadError("Invalid offset") from exc
        if parsed < 0:
            raise InvestigationThreadError("offset must be non-negative")
        return parsed

    def _parse_expected_version(self, value):
        try:
            parsed = int(value)
        except (TypeError, ValueError) as exc:
            raise InvestigationThreadError("Invalid expected_version") from exc
        if parsed < 1:
            raise InvestigationThreadError("Invalid expected_version")
        return parsed

    def _ensure_expected_version_current(self, thread, expected_version):
        expected_version = self._parse_expected_version(expected_version)
        if thread.version != expected_version:
            raise InvestigationThreadConflictError(
                "Investigation thread was modified by another request",
                current_version=thread.version,
            )

    def _ensure_membership_capacity(self, thread, requested_additions):
        self._ensure_membership_capacity_values(self._membership_count(thread) + int(requested_additions or 0))

    def _ensure_membership_capacity_values(self, total):
        if int(total or 0) > MEMBERSHIP_MAX:
            raise InvestigationThreadError(f"Investigation thread membership limit is {MEMBERSHIP_MAX}")

    def _counts(self, thread):
        return {
            "entities": InvestigationThreadEntity.query.filter_by(thread_id=thread.id).count(),
            "relationships": InvestigationThreadRelationship.query.filter_by(thread_id=thread.id).count(),
            "evidence": InvestigationThreadEvidence.query.filter_by(thread_id=thread.id).count(),
            "iocs": InvestigationThreadIOC.query.filter_by(thread_id=thread.id).count(),
            "findings": InvestigationThreadFinding.query.filter_by(thread_id=thread.id).count(),
        }

    def _entity_membership(self, thread, stable_reference_key):
        return InvestigationThreadEntity.query.filter_by(thread_id=thread.id, stable_reference_key=stable_reference_key).first()

    def _relationship_membership(self, thread, stable_reference_key):
        return InvestigationThreadRelationship.query.filter_by(thread_id=thread.id, stable_reference_key=stable_reference_key).first()

    def _evidence_membership(self, thread, evidence_record_key):
        return InvestigationThreadEvidence.query.filter_by(thread_id=thread.id, evidence_record_key=evidence_record_key).first()

    def _finding_membership(self, thread, stable_reference_key):
        return InvestigationThreadFinding.query.filter_by(thread_id=thread.id, stable_reference_key=stable_reference_key).first()

    def _next_sequence(self, model, thread_id):
        current = db.session.query(func.max(model.sequence_order)).filter(model.thread_id == thread_id).scalar()
        return int(current or 0) + 1

    def _sequence_or_next(self, model, thread_id, sequence_order):
        if sequence_order is None:
            return self._next_sequence(model, thread_id)
        return int(sequence_order)

    def _audit_record(
        self,
        case,
        thread,
        action,
        actor,
        *,
        field_name=None,
        old_value=None,
        new_value=None,
        details=None,
        operation_id=None,
        affected_count=None,
    ):
        return {
            "entity_type": AUDIT_ENTITY_TYPE,
            "entity_id": thread.uuid,
            "entity_name": thread.title,
            "action": action,
            "field_name": field_name,
            "old_value": old_value,
            "new_value": new_value,
            "case_uuid": case.uuid,
            "details": details,
            "operation_id": operation_id,
            "affected_count": affected_count,
            **self._actor_fields(actor),
        }

    def _membership_reference_for_audit(self, membership, kind):
        if kind == "evidence":
            return {
                "snapshot_uuid": membership.snapshot_uuid,
                "evidence_record_key": membership.evidence_record_key,
            }
        if kind == "ioc":
            return {
                "ioc_uuid": membership.ioc_uuid,
                "stable_reference_key": membership.stable_reference_key,
                "stable_reference": membership.stable_reference_json,
            }
        return {
            "stable_reference_key": membership.stable_reference_key,
            "stable_reference": getattr(membership, "stable_reference_json", None),
        }

    def _entity_live_dict(self, entity):
        return {
            "id": entity.id,
            "entity_type": entity.entity_type,
            "entity_key": entity.entity_key,
            "display_value": entity.display_value,
            "canonical_value": entity.canonical_value,
            "first_seen_at": self._iso(entity.first_seen_at),
            "last_seen_at": self._iso(entity.last_seen_at),
            "metadata": entity.metadata_json or {},
        }

    def _relationship_live_dict(self, relationship, source, target):
        return {
            "id": relationship.id,
            "source_entity_id": relationship.source_entity_id,
            "target_entity_id": relationship.target_entity_id,
            "relationship_type": relationship.relationship_type,
            "derivation_type": relationship.derivation_type,
            "validation_state": relationship.validation_state,
            "confidence": relationship.confidence,
            "first_seen_at": self._iso(relationship.first_seen_at),
            "last_seen_at": self._iso(relationship.last_seen_at),
            "metadata": relationship.metadata_json or {},
            "source_entity": self._entity_live_dict(source) if source is not None else None,
            "target_entity": self._entity_live_dict(target) if target is not None else None,
        }

    def _dedupe(self, values: Iterable[Any]):
        result = []
        seen = set()
        for value in values:
            key = str(value)
            if key in seen:
                continue
            seen.add(key)
            result.append(value)
        return result

    def _values_differ(self, old, new):
        return self._json_safe(old) != self._json_safe(new)

    def _json_safe(self, value):
        if isinstance(value, datetime):
            return value.isoformat()
        if isinstance(value, dict):
            return {str(k): self._json_safe(v) for k, v in value.items()}
        if isinstance(value, (list, tuple, set)):
            return [self._json_safe(item) for item in value]
        return value

    def _iso(self, value):
        return value.isoformat() if value is not None else None
