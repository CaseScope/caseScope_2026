"""Deterministic Phase 1B ingest identity helpers.

The helpers in this module implement the locked ingest batch contract without
activating the manifest protocol in the current ingestion path.
"""
from __future__ import annotations

import hashlib
import json
import struct
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping, Optional, Sequence, Tuple


BATCHING_CONTRACT_VERSION = "ingest-batch:v1"
UINT32_MAX = 2**32 - 1

ROW_HASH_ALLOWED_FIELDS = (
    "case_id",
    "artifact_type",
    "source_ref_type",
    "source_ref_id",
    "source_generation",
    "ingest_batch_id",
    "ingest_row_ordinal",
    "source_file",
    "source_path",
    "source_host",
    "case_file_id",
    "timestamp",
    "timestamp_utc",
    "timestamp_source_tz",
    "event_id",
    "channel",
    "provider",
    "record_id",
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
    "rule_title",
    "rule_level",
    "rule_file",
    "mitre_tactics",
    "mitre_tags",
    "mitre_attack_ids",
    "mitre_attack_tactics",
    "mitre_attack_sources",
    "mitre_mapping_max_confidence",
    "raw_json",
    "search_blob",
    "evidence_record_key",
    "evidence_identity_version",
    "evidence_identity_quality",
)

ROW_HASH_EXCLUDED_FIELDS = frozenset(
    {
        "indexed_at",
        "selector_key",
        "ingest_attempt_id",
        "ingest_row_hash",
        "celery_task_id",
        "task_id",
        "run_id",
        "job_id",
        "analyst_tagged",
        "analyst_tags",
        "analyst_notes",
        "noise_matched",
        "noise_rules",
        "ioc_types",
        "extra_fields",
    }
)

PARSER_PROVENANCE_ALLOWED_FIELDS = (
    "parser_version",
    "native_record_id_authoritative",
    "source_record_identifier_authoritative",
    "source_record_identifier_type",
    "source_record_identifier_value",
)


@dataclass(frozen=True)
class SourceLocator:
    locator_type: str
    value: str

    def canonical(self) -> dict:
        return {"type": self.locator_type, "value": self.value}


def _canonical_json_bytes(value: Any) -> bytes:
    text = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return text.encode("utf-8")


def _sha256_hex(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def validate_uint32_ordinal(ordinal: int) -> int:
    if not isinstance(ordinal, int) or isinstance(ordinal, bool):
        raise ValueError("ingest_row_ordinal must be an integer")
    if ordinal < 0 or ordinal > UINT32_MAX:
        raise ValueError("ingest_row_ordinal must be within UInt32 bounds")
    return ordinal


def validate_zero_based_manifest_ordinals(ordinals: Iterable[int]) -> Tuple[int, ...]:
    ordered = tuple(validate_uint32_ordinal(ordinal) for ordinal in ordinals)
    if len(set(ordered)) != len(ordered):
        raise ValueError("duplicate ingest_row_ordinal values are not allowed")
    expected = tuple(range(len(ordered)))
    if ordered != expected:
        raise ValueError("ingest_row_ordinal values must be zero-based and contiguous")
    return ordered


def canonical_ingest_batch_identity(
    *,
    case_id: int,
    source_ref_type: str,
    source_ref_id: Any,
    source_generation: int,
    batch_ordinal: int,
    batching_contract_version: str = BATCHING_CONTRACT_VERSION,
) -> dict:
    if int(source_generation) < 1:
        raise ValueError("source_generation must be positive")
    if int(batch_ordinal) < 0:
        raise ValueError("batch_ordinal must be zero or greater")
    return {
        "batching_contract_version": str(batching_contract_version),
        "case_id": int(case_id),
        "source_ref_type": str(source_ref_type),
        "source_ref_id": str(source_ref_id),
        "source_generation": int(source_generation),
        "batch_ordinal": int(batch_ordinal),
    }


def deterministic_ingest_batch_id(
    *,
    case_id: int,
    source_ref_type: str,
    source_ref_id: Any,
    source_generation: int,
    batch_ordinal: int,
    batching_contract_version: str = BATCHING_CONTRACT_VERSION,
) -> str:
    canonical = canonical_ingest_batch_identity(
        case_id=case_id,
        source_ref_type=source_ref_type,
        source_ref_id=source_ref_id,
        source_generation=source_generation,
        batch_ordinal=batch_ordinal,
        batching_contract_version=batching_contract_version,
    )
    return f"{batching_contract_version}:{_sha256_hex(_canonical_json_bytes(canonical))}"


def _normalize_datetime(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    value = value.astimezone(timezone.utc)
    millisecond = value.microsecond // 1000
    return value.replace(microsecond=millisecond * 1000).strftime("%Y-%m-%dT%H:%M:%S.%f")[:23] + "Z"


def _maybe_datetime_string(value: str) -> Any:
    text = value.strip()
    if not text:
        return value
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return value
    return _normalize_datetime(parsed)


def _canonical_raw_json(value: Any) -> Any:
    if value is None:
        return None
    if isinstance(value, (dict, list, int, float, bool)):
        return value
    text = str(value)
    try:
        return json.loads(text)
    except Exception:
        return {"$raw_text": text}


def _canonical_value(field_name: str, value: Any) -> Any:
    if isinstance(value, datetime):
        return _normalize_datetime(value)
    if field_name in {"timestamp", "timestamp_utc"} and isinstance(value, str):
        return _maybe_datetime_string(value)
    if field_name == "raw_json":
        return _canonical_raw_json(value)
    if isinstance(value, tuple):
        return [_canonical_value(field_name, item) for item in value]
    if isinstance(value, list):
        return [_canonical_value(field_name, item) for item in value]
    if isinstance(value, dict):
        return {str(key): _canonical_value(str(key), val) for key, val in value.items()}
    return value


def _mapping_from_event(event: Any) -> Mapping[str, Any]:
    if isinstance(event, Mapping):
        return event
    return {
        name: getattr(event, name)
        for name in ROW_HASH_ALLOWED_FIELDS
        if hasattr(event, name)
    }


def _parser_provenance(mapping: Mapping[str, Any]) -> dict:
    provenance = mapping.get("parser_provenance")
    if not isinstance(provenance, Mapping):
        provenance = mapping
    return {
        name: _canonical_value(name, provenance[name])
        for name in PARSER_PROVENANCE_ALLOWED_FIELDS
        if name in provenance and provenance[name] is not None
    }


def canonical_ingest_row_payload(event: Any) -> dict:
    mapping = _mapping_from_event(event)
    payload = {
        field: _canonical_value(field, mapping.get(field))
        for field in ROW_HASH_ALLOWED_FIELDS
    }
    provenance = _parser_provenance(mapping)
    if provenance:
        payload["parser_provenance"] = provenance
    return payload


def ingest_row_hash(event: Any) -> str:
    payload = canonical_ingest_row_payload(event)
    return _sha256_hex(_canonical_json_bytes(payload))


def validate_sha256_hex(value: str) -> str:
    if not isinstance(value, str):
        raise ValueError("hash must be a string")
    text = value
    if len(text) != 64 or any(char not in "0123456789abcdef" for char in text):
        raise ValueError("hash must be lowercase 64-character SHA-256 hex")
    if len(bytes.fromhex(text)) != 32:
        raise ValueError("hash must decode to a 32-byte SHA-256 digest")
    return text


def _validate_batching_contract_version(version: str) -> bytes:
    if version != BATCHING_CONTRACT_VERSION:
        raise ValueError(f"batching_contract_version must be exactly {BATCHING_CONTRACT_VERSION}")
    version_bytes = version.encode("utf-8")
    if len(version_bytes) > UINT32_MAX or len(version_bytes) > 255:
        raise ValueError("batching_contract_version UTF-8 length must fit uint8")
    return version_bytes


def _binary_batch_content_payload(
    ordinal_hashes: Sequence[Tuple[int, str]],
    *,
    batching_contract_version: str = BATCHING_CONTRACT_VERSION,
) -> bytes:
    version_bytes = _validate_batching_contract_version(batching_contract_version)
    ordinals = validate_zero_based_manifest_ordinals(ordinal for ordinal, _row_hash in ordinal_hashes)
    payload = bytes([len(version_bytes)]) + version_bytes + b"\x00"
    for (ordinal, row_hash), expected_ordinal in zip(ordinal_hashes, ordinals):
        if ordinal != expected_ordinal:
            raise ValueError("ingest_row_ordinal values must be in ascending order")
        row_digest = bytes.fromhex(validate_sha256_hex(row_hash))
        payload += b"\x01" + bytes([32]) + row_digest + struct.pack(">I", ordinal)
    return payload


def batch_content_hash(
    row_hashes: Sequence[str],
    *,
    batching_contract_version: str = BATCHING_CONTRACT_VERSION,
) -> str:
    ordinal_hashes = tuple((ordinal, row_hash) for ordinal, row_hash in enumerate(row_hashes))
    return _sha256_hex(
        _binary_batch_content_payload(
            ordinal_hashes,
            batching_contract_version=batching_contract_version,
        )
    )


def batch_content_hash_for_ordinals(
    ordinal_hashes: Sequence[Tuple[int, str]],
    *,
    batching_contract_version: str = BATCHING_CONTRACT_VERSION,
) -> str:
    return _sha256_hex(
        _binary_batch_content_payload(
            tuple(ordinal_hashes),
            batching_contract_version=batching_contract_version,
        )
    )


def canonical_source_locator(
    *,
    parser_source_id: Optional[Any] = None,
    native_record_id: Optional[Any] = None,
    byte_offset: Optional[Any] = None,
    row_offset: Optional[Any] = None,
    line_offset: Optional[Any] = None,
    deterministic_ordinal: Optional[int] = None,
) -> SourceLocator:
    if parser_source_id is not None:
        return SourceLocator("parser_source_id", str(parser_source_id))
    if native_record_id is not None:
        return SourceLocator("native_record_id", str(native_record_id))
    if byte_offset is not None:
        return SourceLocator("byte_offset", str(byte_offset))
    if row_offset is not None:
        return SourceLocator("row_offset", str(row_offset))
    if line_offset is not None:
        return SourceLocator("line_offset", str(line_offset))
    if deterministic_ordinal is not None:
        return SourceLocator("deterministic_ordinal", str(validate_uint32_ordinal(deterministic_ordinal)))
    raise ValueError("at least one source locator component is required")
