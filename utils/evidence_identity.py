"""Forensic-safe evidence record identity helpers.

Evidence Identity v1 is intentionally separate from the operational
``selector_key`` used by the hunting UI and mutable event state.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import date, datetime, timezone
from decimal import Decimal
from enum import Enum
from typing import Any, Dict, Mapping, Optional, Tuple


EVIDENCE_IDENTITY_VERSION = "1"
EVIDENCE_RECORD_KEY_PREFIX = f"erk:v{EVIDENCE_IDENTITY_VERSION}:"


class EvidenceIdentityQuality(str, Enum):
    """How Evidence Identity v1 located the underlying source record."""

    NATIVE = "native"
    SOURCE_IDENTIFIER = "source_identifier"
    FINGERPRINTED = "fingerprinted"
    LEGACY_FALLBACK = "legacy_fallback"


SOURCE_IDENTIFIER_KEYS = (
    "source_native_id",
    "native_id",
    "source_record_id",
    "record_identifier",
    "event_record_id",
    "row_id",
    "rowid",
    "sqlite_rowid",
    "entry_id",
    "uid",
)

MUTABLE_OR_DERIVED_KEYS = {
    "analyst_tagged",
    "analyst_tags",
    "analyst_notes",
    "noise_matched",
    "noise_rules",
    "ioc_types",
    "mitre_attack_ids",
    "mitre_attack_tactics",
    "mitre_attack_sources",
    "mitre_mapping_max_confidence",
    "field_provenance",
    "emitted_provenance",
    "provenance_source",
    "provenance_summary",
    "_provenance",
    "model_provider",
    "model_name",
    "ai_summary",
    "ai_rationale",
    "model_summary",
    "llm_summary",
    "indexed_at",
    "selector_key",
    "evidence_record_key",
    "evidence_identity_version",
    "evidence_identity_quality",
}

NORMALIZED_FINGERPRINT_FIELDS = (
    "event_id",
    "channel",
    "provider",
    "level",
    "username",
    "domain",
    "sid",
    "logon_type",
    "logon_id",
    "remote_host",
    "workstation_name",
    "auth_package",
    "logon_process",
    "elevated_token",
    "process_name",
    "process_path",
    "process_id",
    "parent_process",
    "parent_pid",
    "command_line",
    "thread_id",
    "executable_info",
    "payload_data1",
    "payload_data2",
    "payload_data3",
    "payload_data4",
    "payload_data5",
    "payload_data6",
    "target_path",
    "file_hash_md5",
    "file_hash_sha1",
    "file_hash_sha256",
    "file_size",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "reg_key",
    "reg_value",
    "reg_data",
    "search_blob",
)


@dataclass(frozen=True)
class EvidenceRecordIdentity:
    evidence_record_key: str
    evidence_identity_version: str
    evidence_identity_quality: str


@dataclass(frozen=True)
class EvidenceRecordLocator:
    """Reusable locator for normalized evidence records.

    This is not a graph edge or graph entity. It captures enough case-scoped
    source context for future provenance consumers to resolve a normalized event
    by ``evidence_record_key`` while retaining the old selector for migration.
    """

    case_id: int
    evidence_record_key: str
    source_type: str = "events"
    source_table: str = "events"
    selector_key: str = ""
    source_file: str = ""
    source_path: str = ""
    case_file_id: Optional[int] = None
    source_host: str = ""
    artifact_type: str = ""
    timestamp: Optional[str] = None
    event_id: str = ""
    record_id: Optional[Any] = None
    parser_version: str = ""
    source_native_identifier: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def canonical_json_dumps(value: Any) -> str:
    """Serialize identity inputs deterministically across process restarts."""

    return json.dumps(
        _canonicalize(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )


def build_evidence_record_identity(event: Any) -> EvidenceRecordIdentity:
    """Build Evidence Identity v1 for a ParsedEvent-like object or mapping."""

    event_map = _event_to_mapping(event)
    extra_fields = _parse_jsonish(event_map.get("extra_fields"))
    raw_payload = _parse_jsonish(event_map.get("raw_json"))

    native_record_id = _positive_int(event_map.get("record_id"))
    source_identifier = _first_source_identifier(extra_fields)

    if native_record_id is not None:
        quality = EvidenceIdentityQuality.NATIVE.value
        identity_payload = {
            "case_scope": _case_scope(event_map),
            "source_scope": _source_scope(event_map),
            "native": {
                "record_id": native_record_id,
                "event_id": _clean(event_map.get("event_id")),
                "channel": _clean(event_map.get("channel")),
                "provider": _clean(event_map.get("provider")),
            },
        }
    elif source_identifier:
        quality = EvidenceIdentityQuality.SOURCE_IDENTIFIER.value
        identity_payload = {
            "case_scope": _case_scope(event_map),
            "source_scope": _source_scope(event_map),
            "source_identifier": source_identifier,
            "artifact_type": _clean(event_map.get("artifact_type")),
        }
    else:
        quality = EvidenceIdentityQuality.FINGERPRINTED.value
        identity_payload = {
            "case_scope": _case_scope(event_map),
            "source_scope": _source_scope(event_map),
            "record_scope": {
                "artifact_type": _clean(event_map.get("artifact_type")),
                "source_host": _clean(event_map.get("source_host")),
                "event_id": _clean(event_map.get("event_id")),
                "timestamp": _timestamp_identity_value(event_map.get("timestamp")),
                "timestamp_utc": _timestamp_identity_value(event_map.get("timestamp_utc")),
                "timestamp_source_tz": _clean(event_map.get("timestamp_source_tz")),
            },
            # Prefer canonical raw source payload when a parser retained it.
            # Fall back to stable normalized fields so same-second records with
            # different source content still diverge without using mutable state.
            "source_record": _clean_identity_payload(raw_payload)
            if raw_payload not in ({}, "", None)
            else _normalized_record_payload(event_map),
            "extra_fields": _clean_identity_payload(extra_fields),
        }

    serialized = canonical_json_dumps(
        {
            "algorithm": "evidence_identity_v1",
            "quality": quality,
            "payload": identity_payload,
        }
    )
    digest = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
    return EvidenceRecordIdentity(
        evidence_record_key=f"{EVIDENCE_RECORD_KEY_PREFIX}{digest}",
        evidence_identity_version=EVIDENCE_IDENTITY_VERSION,
        evidence_identity_quality=quality,
    )


def build_evidence_record_locator(
    event: Any,
    *,
    selector_key: str = "",
    evidence_record_key: str = "",
) -> EvidenceRecordLocator:
    event_map = _event_to_mapping(event)
    extra_fields = _parse_jsonish(event_map.get("extra_fields"))
    source_identifier = _first_source_identifier(extra_fields)
    identity_key = evidence_record_key or _clean(event_map.get("evidence_record_key"))
    if not identity_key:
        identity_key = build_evidence_record_identity(event_map).evidence_record_key

    return EvidenceRecordLocator(
        case_id=int(event_map.get("case_id") or 0),
        evidence_record_key=identity_key,
        selector_key=selector_key or _clean(event_map.get("selector_key")),
        source_file=_clean(event_map.get("source_file")),
        source_path=_clean(event_map.get("source_path")),
        case_file_id=_positive_int(event_map.get("case_file_id")),
        source_host=_clean(event_map.get("source_host")),
        artifact_type=_clean(event_map.get("artifact_type")),
        timestamp=_timestamp_identity_value(event_map.get("timestamp_utc") or event_map.get("timestamp")),
        event_id=_clean(event_map.get("event_id")),
        record_id=_positive_int(event_map.get("record_id")),
        parser_version=_clean(event_map.get("parser_version")),
        source_native_identifier=source_identifier,
    )


def build_identity_from_clickhouse_row(row: Mapping[str, Any]) -> EvidenceRecordIdentity:
    """Build an identity from an existing events row for migrations/backfills."""

    identity = build_evidence_record_identity(row)
    quality = identity.evidence_identity_quality
    if not _positive_int(row.get("record_id")) and not _first_source_identifier(
        _parse_jsonish(row.get("extra_fields"))
    ):
        raw_payload = _parse_jsonish(row.get("raw_json"))
        if raw_payload in ({}, "", None) and not row.get("search_blob"):
            quality = EvidenceIdentityQuality.LEGACY_FALLBACK.value
    return EvidenceRecordIdentity(
        evidence_record_key=identity.evidence_record_key,
        evidence_identity_version=identity.evidence_identity_version,
        evidence_identity_quality=quality,
    )


def _event_to_mapping(event: Any) -> Dict[str, Any]:
    if isinstance(event, Mapping):
        return dict(event)
    return {
        name: getattr(event, name)
        for name in dir(event)
        if not name.startswith("_") and not callable(getattr(event, name))
    }


def _parse_jsonish(value: Any) -> Any:
    if value in (None, ""):
        return {}
    if isinstance(value, (dict, list)):
        return value
    if not isinstance(value, str):
        return value
    try:
        return json.loads(value)
    except (TypeError, ValueError, json.JSONDecodeError):
        return value


def _canonicalize(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {
            str(key): _canonicalize(value[key])
            for key in sorted(value.keys(), key=lambda item: str(item))
            if value[key] is not None
        }
    if isinstance(value, (list, tuple)):
        return [_canonicalize(item) for item in value]
    if isinstance(value, set):
        return sorted(_canonicalize(item) for item in value)
    if isinstance(value, datetime):
        return _timestamp_identity_value(value)
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, Decimal):
        return str(value)
    return value


def _clean(value: Any) -> str:
    normalized = str(value or "").strip()
    return "" if normalized == "-" else normalized


def _positive_int(value: Any) -> Optional[int]:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return None
    return number if number > 0 else None


def _timestamp_identity_value(value: Any) -> str:
    if value in (None, ""):
        return ""
    if isinstance(value, datetime):
        timestamp = value
        if timestamp.tzinfo is not None:
            timestamp = timestamp.astimezone(timezone.utc).replace(tzinfo=None)
        return timestamp.isoformat(timespec="microseconds")
    return str(value).strip()


def _case_scope(event_map: Mapping[str, Any]) -> Dict[str, Any]:
    return {"case_id": int(event_map.get("case_id") or 0)}


def _source_scope(event_map: Mapping[str, Any]) -> Dict[str, Any]:
    return {
        "case_file_id": _positive_int(event_map.get("case_file_id")),
        "source_file": _clean(event_map.get("source_file")),
        "source_path": _clean(event_map.get("source_path")),
        "source_host": _clean(event_map.get("source_host")),
        "parser_version": _clean(event_map.get("parser_version")),
    }


def _first_source_identifier(extra_fields: Any) -> str:
    if not isinstance(extra_fields, Mapping):
        return ""
    for key in SOURCE_IDENTIFIER_KEYS:
        value = extra_fields.get(key)
        if value not in (None, "", "-", []):
            return f"{key}:{_clean(value)}"
    return ""


def _clean_identity_payload(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {
            str(key): _clean_identity_payload(item)
            for key, item in value.items()
            if str(key) not in MUTABLE_OR_DERIVED_KEYS and item is not None
        }
    if isinstance(value, list):
        return [_clean_identity_payload(item) for item in value]
    return value


def _normalized_record_payload(event_map: Mapping[str, Any]) -> Dict[str, Any]:
    return {
        field_name: _clean_identity_payload(event_map.get(field_name))
        for field_name in NORMALIZED_FINGERPRINT_FIELDS
        if event_map.get(field_name) not in (None, "", [], {})
    }


__all__ = [
    "EVIDENCE_IDENTITY_VERSION",
    "EVIDENCE_RECORD_KEY_PREFIX",
    "EvidenceIdentityQuality",
    "EvidenceRecordIdentity",
    "EvidenceRecordLocator",
    "build_evidence_record_identity",
    "build_evidence_record_locator",
    "build_identity_from_clickhouse_row",
    "canonical_json_dumps",
]
