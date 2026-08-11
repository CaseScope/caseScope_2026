"""Forensic-safe evidence record identity helpers.

Evidence Identity v2 is intentionally separate from the operational
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


EVIDENCE_IDENTITY_VERSION = "2"
EVIDENCE_RECORD_KEY_PREFIX = f"erk:v{EVIDENCE_IDENTITY_VERSION}:"


class EvidenceIdentityQuality(str, Enum):
    """How Evidence Identity v2 located the underlying source record."""

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

SOURCE_SCOPE_IDENTIFIER_KEYS = (
    "source_evidence_sha256",
    "source_file_sha256",
    "case_file_sha256",
    "original_file_sha256",
    "archive_sha256",
    "sha256_hash",
)

NATIVE_RECORD_ID_MARKERS = (
    "native_record_id_authoritative",
    "record_id_authoritative",
    "record_id_is_native",
)

SOURCE_RECORD_IDENTIFIER_MARKERS = (
    "source_record_identifier_authoritative",
    "source_identifier_authoritative",
)

SOURCE_RECORD_IDENTIFIER_TYPE_KEYS = (
    "source_record_identifier_type",
    "source_identifier_type",
)

SOURCE_RECORD_IDENTIFIER_VALUE_KEYS = (
    "source_record_identifier_value",
    "source_identifier_value",
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
    "artifact_type",
    "timestamp_utc",
    "timestamp",
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


def _identity_json_dumps(value: Any) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )


def build_evidence_record_identity(event: Any) -> EvidenceRecordIdentity:
    """Build Evidence Identity v2 for a ParsedEvent-like object or mapping."""

    event_map = _event_to_mapping(event)
    extra_fields = _parse_jsonish(event_map.get("extra_fields"))

    native_record_id = _record_id_value(event_map.get("record_id"))
    source_identifier = _authoritative_source_identifier(event_map, extra_fields)

    if native_record_id is not None and _has_authoritative_native_record_id(event_map, extra_fields):
        quality = EvidenceIdentityQuality.NATIVE.value
        identity_payload = {
            "case_scope": _case_scope(event_map),
            "source_scope": _source_scope(event_map),
            "native": {
                "identity_type": _native_record_identity_type(event_map, extra_fields),
                "record_id": native_record_id,
            },
        }
    elif source_identifier:
        quality = EvidenceIdentityQuality.SOURCE_IDENTIFIER.value
        identity_payload = {
            "case_scope": _case_scope(event_map),
            "source_scope": _source_scope(event_map),
            "source_identifier": _identifier_payload(source_identifier),
        }
    else:
        raw_payload = _parse_jsonish(event_map.get("raw_json"))
        if _has_usable_raw_source_record(raw_payload):
            quality = EvidenceIdentityQuality.FINGERPRINTED.value
            identity_payload = {
                "case_scope": _case_scope(event_map),
                "source_scope": _source_scope(event_map),
                "raw_source_record": _canonical_raw_source_payload(raw_payload),
            }
        else:
            quality = EvidenceIdentityQuality.FINGERPRINTED.value
            identity_payload = {
                "case_scope": _case_scope(event_map),
                "source_scope": _source_scope(event_map),
                "normalized_source_record": _normalized_record_payload(event_map),
            }

    serialized = _identity_json_dumps(
        {
            "algorithm": "evidence_identity_v2",
            "version": EVIDENCE_IDENTITY_VERSION,
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
        record_id=_record_id_value(event_map.get("record_id")),
        parser_version=_clean(event_map.get("parser_version")),
        source_native_identifier=source_identifier,
    )


def build_identity_from_clickhouse_row(row: Mapping[str, Any]) -> EvidenceRecordIdentity:
    """Build an identity from an existing events row for migrations/backfills."""

    identity = build_evidence_record_identity(row)
    quality = identity.evidence_identity_quality
    extra_fields = _parse_jsonish(row.get("extra_fields"))
    if (
        not _has_authoritative_native_record_id(row, extra_fields)
        and not _authoritative_source_identifier(row, extra_fields)
    ):
        raw_payload = _parse_jsonish(row.get("raw_json"))
        if raw_payload in ({}, "", None) and not _normalized_record_payload(row):
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


def _canonicalize_raw_source(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {
            str(key): _canonicalize_raw_source(value[key])
            for key in sorted(value.keys(), key=lambda item: str(item))
        }
    if isinstance(value, (list, tuple)):
        return [_canonicalize_raw_source(item) for item in value]
    if isinstance(value, set):
        return sorted(_canonicalize_raw_source(item) for item in value)
    if isinstance(value, datetime):
        return _timestamp_identity_value(value)
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, Decimal):
        return str(value)
    return value


def _clean(value: Any) -> str:
    if value is None:
        return ""
    normalized = str(value).strip()
    return "" if normalized == "-" else normalized


def _positive_int(value: Any) -> Optional[int]:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return None
    return number if number > 0 else None


def _record_id_value(value: Any) -> Optional[int]:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _native_record_identity_type(event_map: Mapping[str, Any], extra_fields: Any) -> str:
    artifact_type = _clean(event_map.get("artifact_type")).lower()
    if artifact_type == "evtx":
        return "evtx_record_id"
    if isinstance(extra_fields, Mapping):
        explicit_type = _clean(extra_fields.get("native_record_identity_type"))
        if explicit_type:
            return explicit_type
    return "native_record_id"


def _timestamp_identity_value(value: Any) -> str:
    if value in (None, ""):
        return ""
    if isinstance(value, datetime):
        timestamp = value
        if timestamp.tzinfo is not None:
            timestamp = timestamp.astimezone(timezone.utc).replace(tzinfo=None)
        millisecond = (timestamp.microsecond // 1000) * 1000
        return timestamp.replace(microsecond=millisecond).isoformat(timespec="milliseconds")
    text = str(value).strip()
    if not text:
        return ""
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return text
    return _timestamp_identity_value(parsed)


def _case_scope(event_map: Mapping[str, Any]) -> Dict[str, Any]:
    return {"case_id": int(event_map.get("case_id") or 0)}


def _source_scope(event_map: Mapping[str, Any]) -> Dict[str, Any]:
    case_file_id = _positive_int(event_map.get("case_file_id"))
    if case_file_id is not None:
        return {"case_file_id": case_file_id}

    extra_fields = _parse_jsonish(event_map.get("extra_fields"))
    source_scope_identifier = _first_source_scope_identifier(extra_fields)
    if source_scope_identifier:
        return {"source_identifier": source_scope_identifier}

    source_file = _clean(event_map.get("source_file"))
    source_scope = {
        "source_file": source_file,
        "source_host": _clean(event_map.get("source_host")),
        "artifact_type": _clean(event_map.get("artifact_type")),
    }
    if not source_file:
        source_scope["source_path_fallback"] = _clean(event_map.get("source_path"))
    return source_scope


def _first_source_identifier(extra_fields: Any) -> str:
    if not isinstance(extra_fields, Mapping):
        return ""
    for key in SOURCE_IDENTIFIER_KEYS:
        value = extra_fields.get(key)
        if value not in (None, "", "-", []):
            return f"{key}:{_clean(value)}"
    return ""


def _identifier_payload(identifier: str) -> Dict[str, str]:
    if ":" not in identifier:
        return {"identity_type": "source_identifier", "value": _clean(identifier)}
    identity_type, value = identifier.split(":", 1)
    return {"identity_type": _clean(identity_type), "value": _clean(value)}


def _authoritative_source_identifier(event_map: Mapping[str, Any], extra_fields: Any) -> str:
    """Return explicitly authorized source-record identity material.

    Discovered fields such as row_id or uid remain useful locator metadata, but
    they are not stable hash material unless a parser/producer opts in with an
    explicit semantic type and value.
    """

    candidates = []
    if isinstance(extra_fields, Mapping):
        candidates.append(extra_fields)
    candidates.append(event_map)
    authoritative = any(
        _truthy_marker(candidate.get(marker))
        for candidate in candidates
        for marker in SOURCE_RECORD_IDENTIFIER_MARKERS
    )
    if not authoritative:
        return ""

    identity_type = ""
    identity_value: Any = None
    value_present = False
    for candidate in candidates:
        for key in SOURCE_RECORD_IDENTIFIER_TYPE_KEYS:
            identity_type = _clean(candidate.get(key))
            if identity_type:
                break
        if identity_type:
            break
    for candidate in candidates:
        for key in SOURCE_RECORD_IDENTIFIER_VALUE_KEYS:
            if key in candidate:
                identity_value = candidate.get(key)
                value_present = True
                break
        if value_present:
            break
    if not identity_type or not value_present or identity_value in (None, "", "-", []):
        return ""
    return f"{identity_type}:{_clean(identity_value)}"


def _first_source_scope_identifier(extra_fields: Any) -> str:
    if not isinstance(extra_fields, Mapping):
        return ""
    for key in SOURCE_SCOPE_IDENTIFIER_KEYS:
        value = extra_fields.get(key)
        if value not in (None, "", "-", []):
            return f"{key}:{_clean(value)}"
    return ""


def _has_authoritative_native_record_id(
    event_map: Mapping[str, Any],
    extra_fields: Any,
) -> bool:
    if _clean(event_map.get("artifact_type")).lower() == "evtx":
        return True
    for key in NATIVE_RECORD_ID_MARKERS:
        if _truthy_marker(event_map.get(key)):
            return True
    if isinstance(extra_fields, Mapping):
        for key in NATIVE_RECORD_ID_MARKERS:
            if _truthy_marker(extra_fields.get(key)):
                return True
        if _clean(extra_fields.get("record_identity_kind")).lower() == "native":
            return True
    return False


def _truthy_marker(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return _clean(value).lower() in {"1", "true", "yes", "native", "authoritative"}


def _has_usable_raw_source_record(value: Any) -> bool:
    return value not in ({}, "", None)


def _canonical_raw_source_payload(value: Any) -> Any:
    """Canonicalize retained source payload without stripping source field names."""

    return _canonicalize_raw_source(value)


def _clean_normalized_identity_payload(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {
            str(key): _clean_normalized_identity_payload(item)
            for key, item in value.items()
            if str(key) not in MUTABLE_OR_DERIVED_KEYS and item is not None
        }
    if isinstance(value, list):
        return [_clean_normalized_identity_payload(item) for item in value]
    if isinstance(value, datetime):
        return _timestamp_identity_value(value)
    return value


def _normalized_record_payload(event_map: Mapping[str, Any]) -> Dict[str, Any]:
    payload: Dict[str, Any] = {}
    for field_name in NORMALIZED_FINGERPRINT_FIELDS:
        value = event_map.get(field_name)
        if value in (None, "", [], {}):
            continue
        if field_name in {"timestamp", "timestamp_utc"}:
            payload[field_name] = _timestamp_identity_value(value)
        else:
            payload[field_name] = _clean_normalized_identity_payload(value)
    return payload


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
