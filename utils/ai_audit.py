"""AI prompt/response audit helpers with versioned hash-chain support."""
from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Optional

from flask import has_app_context, has_request_context, session
from sqlalchemy import text

from models.ai_audit_log import AIAuditLog, AIAuditStatus
from models.database import db

logger = logging.getLogger(__name__)

HASH_VERSION = "v1"
EMPTY_RESPONSE_SENTINEL = ""
AI_AUDIT_CHAIN_LOCK_KEY = int.from_bytes(
    hashlib.sha256(b"ai_audit_chain").digest()[:8],
    byteorder="big",
    signed=False,
) & 0x7FFFFFFFFFFFFFFF


class AIAuditWriteError(RuntimeError):
    """Raised when strict AI audit mode blocks an AI response."""


@dataclass
class AIAuditContext:
    function: str
    mode: str
    provider_type: str
    provider_display: str
    provider_path: str
    model: str
    request_payload: str
    status: str
    response_complete: bool
    response_payload: str | None = None
    error_class: str | None = None
    error_message: str | None = None
    duration_ms: int | None = None
    usage: dict[str, Any] | None = None
    privacy: dict[str, Any] | None = None
    case_id: int | None = None
    case_uuid: str | None = None
    case_name: str | None = None
    client_id: int | None = None
    client_uuid: str | None = None
    client_name: str | None = None
    user_id: int | None = None
    username: str = "system"
    timestamp: datetime | None = None


def canonical_json(value: dict[str, Any]) -> str:
    """Serialize hash metadata with stable key order and compact separators."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def canonical_payload(value: Any) -> str:
    """Serialize arbitrary request/response payloads while preserving text verbatim."""
    if isinstance(value, str):
        return value
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def _as_utc(value: datetime | None = None) -> datetime:
    current = value or datetime.now(timezone.utc)
    if current.tzinfo is None:
        return current.replace(tzinfo=timezone.utc)
    return current.astimezone(timezone.utc)


def timestamp_for_hash(value: datetime | None = None) -> str:
    """Return timezone-explicit ISO 8601 timestamp text used by v1 hashes."""
    return _as_utc(value).isoformat().replace("+00:00", "Z")


def compute_content_hash(value: Any) -> str:
    """Return a versioned SHA-256 hash for prompt/response content."""
    payload = canonical_payload(value)
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    return f"{HASH_VERSION}:{digest}"


def build_record_metadata(
    *,
    timestamp: datetime | str,
    case_uuid: str | None,
    function: str,
    provider_type: str,
    model: str,
    user_id: int | None,
    status: str,
    response_complete: bool,
    prompt_hash: str,
    response_hash: str,
    previous_record_hash: str | None,
) -> dict[str, Any]:
    """Build the explicit v1 metadata set included in record_hash.

    Included fields: hash_version, timestamp, case_uuid, function,
    provider_type, model, user_id, status, response_complete, prompt_hash,
    response_hash, and previous_record_hash.

    Excluded fields: database id, record_hash, UI-only fields, and future
    columns unless intentionally added by a future hash version.
    """
    if isinstance(timestamp, datetime):
        timestamp_value = timestamp_for_hash(timestamp)
    else:
        timestamp_value = timestamp
    return {
        "hash_version": HASH_VERSION,
        "timestamp": timestamp_value,
        "case_uuid": case_uuid,
        "function": function,
        "provider_type": provider_type,
        "model": model,
        "user_id": user_id,
        "status": status,
        "response_complete": bool(response_complete),
        "prompt_hash": prompt_hash,
        "response_hash": response_hash,
        "previous_record_hash": previous_record_hash,
    }


def compute_record_hash(metadata: dict[str, Any]) -> str:
    """Return a versioned SHA-256 hash for canonical record metadata."""
    digest = hashlib.sha256(canonical_json(metadata).encode("utf-8")).hexdigest()
    return f"{HASH_VERSION}:{digest}"


def _json_or_none(value: Any) -> str | None:
    if value is None:
        return None
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def is_ai_audit_enabled() -> bool:
    """Return whether AI auditing is enabled in a real app context."""
    if not has_app_context():
        return False
    try:
        from models.system_settings import SettingKeys, SystemSettings

        return bool(SystemSettings.get(SettingKeys.AI_AUDIT_ENABLED, True))
    except Exception:
        logger.exception("Failed to read AI audit enabled setting")
        return True


def is_ai_audit_strict_mode() -> bool:
    """Return whether AI calls should fail when audit writes fail."""
    if not has_app_context():
        return False
    try:
        from models.system_settings import SettingKeys, SystemSettings

        return bool(SystemSettings.get(SettingKeys.AI_AUDIT_STRICT_MODE, True))
    except Exception:
        logger.exception("Failed to read AI audit strict-mode setting")
        return True


def _current_user_fields() -> tuple[int | None, str]:
    try:
        from flask_login import current_user

        if getattr(current_user, "is_authenticated", False):
            return getattr(current_user, "id", None), getattr(current_user, "username", "system") or "system"
    except Exception:
        pass
    return None, "system"


def _active_case_id_from_session() -> str | None:
    if not has_request_context():
        return None
    try:
        return session.get("active_case_uuid")
    except Exception:
        return None


def _case_context(case_id: int | None, explicit_case_uuid: str | None = None) -> dict[str, Any]:
    context = {
        "case_id": case_id,
        "case_uuid": explicit_case_uuid,
        "case_name": None,
        "client_id": None,
        "client_uuid": None,
        "client_name": None,
    }
    if not has_app_context():
        return context
    try:
        from models.case import Case

        case = None
        if case_id:
            case = Case.query.get(case_id)
        if case is None and explicit_case_uuid:
            case = Case.get_by_uuid(explicit_case_uuid)
        if case is None:
            active_case_uuid = _active_case_id_from_session()
            if active_case_uuid:
                case = Case.get_by_uuid(active_case_uuid)
        if not case:
            return context
        context.update(
            {
                "case_id": case.id,
                "case_uuid": case.uuid,
                "case_name": case.name,
            }
        )
        client = getattr(case, "client", None)
        if client:
            context.update(
                {
                    "client_id": client.id,
                    "client_uuid": client.uuid,
                    "client_name": client.name,
                }
            )
    except Exception:
        logger.exception("Failed to resolve AI audit case context")
    return context


def build_context(
    *,
    function: str,
    mode: str,
    provider,
    request_payload: Any,
    response_payload: Any = None,
    status: str,
    response_complete: bool,
    privacy_context=None,
    privacy: dict[str, Any] | None = None,
    usage: dict[str, Any] | None = None,
    duration_ms: int | None = None,
    error: BaseException | None = None,
) -> AIAuditContext:
    """Create a normalized context for an AI audit write."""
    user_id, username = _current_user_fields()
    case_context = _case_context(
        getattr(privacy_context, "case_id", None),
        explicit_case_uuid=None,
    )
    provider_type = provider.provider_type()
    provider_path = getattr(provider, "api_url", None) or getattr(provider, "API_BASE", None) or ""
    error_class = error.__class__.__name__ if error else None
    error_message = str(error) if error else None
    return AIAuditContext(
        function=function,
        mode=mode,
        provider_type=provider_type,
        provider_display=provider.get_provider_display(),
        provider_path=provider_path,
        model=getattr(provider, "model", "") or "",
        request_payload=canonical_payload(request_payload),
        response_payload=canonical_payload(response_payload) if response_payload is not None else None,
        status=status,
        response_complete=response_complete,
        error_class=error_class,
        error_message=error_message,
        duration_ms=duration_ms,
        usage=usage,
        privacy=privacy,
        user_id=user_id,
        username=username,
        **case_context,
    )


def _fallback_audit_failure(details: dict[str, Any], case_uuid: str | None = None) -> None:
    try:
        from models.audit_log import AuditAction, AuditEntityType, AuditLog

        AuditLog.log(
            entity_type=AuditEntityType.AI_AUDIT,
            entity_id=details.get("would_be_record_hash") or details.get("prompt_hash"),
            entity_name="AI audit write failed",
            action=AuditAction.AI_AUDIT_WRITE_FAILED,
            case_uuid=case_uuid,
            details=details,
        )
    except Exception:
        logger.exception("Fallback AuditLog write failed for AI audit write failure")


def write_ai_audit_record(context: AIAuditContext) -> AIAuditLog | None:
    """Write a single immutable AI audit record under a global advisory lock."""
    if not is_ai_audit_enabled():
        return None

    timestamp = _as_utc(context.timestamp)
    prompt_hash = compute_content_hash(context.request_payload)
    response_hash = compute_content_hash(context.response_payload or EMPTY_RESPONSE_SENTINEL)
    previous_record_hash: str | None = None
    would_be_record_hash: str | None = None

    try:
        if db.engine.dialect.name == "postgresql":
            db.session.execute(text("SELECT pg_advisory_xact_lock(:lock_key)"), {"lock_key": AI_AUDIT_CHAIN_LOCK_KEY})
        previous = AIAuditLog.query.order_by(AIAuditLog.id.desc()).first()
        previous_record_hash = previous.record_hash if previous else None
        metadata = build_record_metadata(
            timestamp=timestamp,
            case_uuid=context.case_uuid,
            function=context.function,
            provider_type=context.provider_type,
            model=context.model,
            user_id=context.user_id,
            status=context.status,
            response_complete=context.response_complete,
            prompt_hash=prompt_hash,
            response_hash=response_hash,
            previous_record_hash=previous_record_hash,
        )
        would_be_record_hash = compute_record_hash(metadata)
        entry = AIAuditLog(
            timestamp=timestamp,
            client_id=context.client_id,
            client_uuid=context.client_uuid,
            client_name=context.client_name,
            case_id=context.case_id,
            case_uuid=context.case_uuid,
            case_name=context.case_name,
            user_id=context.user_id,
            username=context.username,
            function=context.function,
            mode=context.mode,
            provider_type=context.provider_type,
            provider_display=context.provider_display,
            provider_path=context.provider_path,
            model=context.model,
            request_payload=context.request_payload,
            response_payload=context.response_payload,
            status=context.status,
            response_complete=context.response_complete,
            error_class=context.error_class,
            error_message=context.error_message,
            duration_ms=context.duration_ms,
            usage=_json_or_none(context.usage),
            privacy=_json_or_none(context.privacy),
            hash_version=HASH_VERSION,
            prompt_hash=prompt_hash,
            response_hash=response_hash,
            previous_record_hash=previous_record_hash,
            record_hash=would_be_record_hash,
        )
        db.session.add(entry)
        db.session.commit()
        return entry
    except Exception as exc:
        db.session.rollback()
        details = {
            "function": context.function,
            "provider_type": context.provider_type,
            "provider_display": context.provider_display,
            "model": context.model,
            "case_uuid": context.case_uuid,
            "user_id": context.user_id,
            "username": context.username,
            "error_class": exc.__class__.__name__,
            "error_message": str(exc),
            "prompt_hash": prompt_hash,
            "response_hash": response_hash,
            "previous_record_hash": previous_record_hash,
            "would_be_record_hash": would_be_record_hash,
            "timestamp": timestamp_for_hash(timestamp),
        }
        _fallback_audit_failure(details, case_uuid=context.case_uuid)
        if is_ai_audit_strict_mode():
            raise AIAuditWriteError("AI Audit write failed; strict mode blocked the AI response") from exc
        logger.exception("AI audit write failed in non-strict mode")
        return None


def record_ai_call(**kwargs) -> AIAuditLog | None:
    """Build and write an AI audit record when auditing is enabled."""
    if not is_ai_audit_enabled():
        return None
    return write_ai_audit_record(build_context(**kwargs))


def verify_ai_audit_chain(query=None) -> dict[str, Any]:
    """Walk AI audit records and report the first hash-chain inconsistency."""
    if query is None:
        query = AIAuditLog.query
    records = query.order_by(AIAuditLog.id.asc()).all()
    previous_hash = None
    first_timestamp = None
    last_timestamp = None

    for index, record in enumerate(records, start=1):
        if first_timestamp is None:
            first_timestamp = record.timestamp
        last_timestamp = record.timestamp
        expected_prompt_hash = compute_content_hash(record.request_payload)
        expected_response_hash = compute_content_hash(record.response_payload or EMPTY_RESPONSE_SENTINEL)
        metadata = build_record_metadata(
            timestamp=record.timestamp,
            case_uuid=record.case_uuid,
            function=record.function,
            provider_type=record.provider_type,
            model=record.model,
            user_id=record.user_id,
            status=record.status,
            response_complete=record.response_complete,
            prompt_hash=expected_prompt_hash,
            response_hash=expected_response_hash,
            previous_record_hash=previous_hash,
        )
        expected_record_hash = compute_record_hash(metadata)
        if (
            record.previous_record_hash != previous_hash
            or record.prompt_hash != expected_prompt_hash
            or record.response_hash != expected_response_hash
            or record.record_hash != expected_record_hash
        ):
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


def summarize_case_ai_audit_boundary(case_uuid: str) -> dict[str, Any]:
    """Return case-scoped AI Audit hash boundary data for archive manifests."""
    records = (
        AIAuditLog.query.filter_by(case_uuid=case_uuid)
        .order_by(AIAuditLog.id.asc())
        .all()
    )
    if not records:
        return {
            "record_count": 0,
            "first_record_hash": None,
            "last_record_hash": None,
            "first_record_timestamp": None,
            "last_record_timestamp": None,
            "global_live_tail_hash": (
                AIAuditLog.query.order_by(AIAuditLog.id.desc()).first().record_hash
                if AIAuditLog.query.count()
                else None
            ),
        }
    live_tail = AIAuditLog.query.order_by(AIAuditLog.id.desc()).first()
    return {
        "record_count": len(records),
        "first_record_hash": records[0].record_hash,
        "last_record_hash": records[-1].record_hash,
        "first_record_timestamp": records[0].timestamp.isoformat() if records[0].timestamp else None,
        "last_record_timestamp": records[-1].timestamp.isoformat() if records[-1].timestamp else None,
        "global_live_tail_hash": live_tail.record_hash if live_tail else None,
    }
