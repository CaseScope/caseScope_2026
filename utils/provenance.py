"""Shared parser-to-runtime provenance helpers."""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Mapping, Optional

PROVENANCE_ORDER = {
    "ANALYST": 0,
    "SYSTEM_DERIVED": 1,
    "ARTIFACT_TAINTED": 2,
    "ELEVATED_RISK": 3,
    "MODEL_SYNTHESIZED": 4,
}

STRUCTURAL_FIELDS = {
    "artifact_type",
    "count",
    "cross_events_count",
    "cross_memory_count",
    "event_count",
    "event_id",
    "host",
    "hostname",
    "ioc_types",
    "job_id",
    "log_type",
    "memory_time",
    "pid",
    "pcap_id",
    "ppid",
    "source_host",
    "source",
    "timestamp",
    "username",
    "uid",
    "user",
}

BROWSER_PREFIXES = (
    "browser_",
    "chrome_",
    "edge_",
    "firefox_",
    "webcache_",
)


def normalize_provenance(value: Any, default: str = "ANALYST") -> str:
    """Return a known provenance label with a stable fallback."""
    normalized = str(value or "").strip().upper()
    if normalized in PROVENANCE_ORDER:
        return normalized
    return default


def max_provenance(values: Iterable[Any], default: str = "ANALYST") -> str:
    """Return the highest-risk provenance label from an iterable."""
    highest = normalize_provenance(default, default=default)
    for value in values:
        candidate = normalize_provenance(value, default=default)
        if PROVENANCE_ORDER[candidate] > PROVENANCE_ORDER[highest]:
            highest = candidate
    return highest


def provenance_for_artifact_field(artifact_type: Any, field_name: Any) -> str:
    """Classify one normalized artifact field for runtime consumption."""
    normalized_artifact_type = str(artifact_type or "").strip().lower()
    normalized_field = str(field_name or "").strip().lower()

    if normalized_field in STRUCTURAL_FIELDS:
        return "SYSTEM_DERIVED"

    if normalized_artifact_type.startswith(BROWSER_PREFIXES):
        return "ELEVATED_RISK"

    return "ARTIFACT_TAINTED"


def annotate_artifact_records(
    records: List[Dict[str, Any]],
    *,
    artifact_type_key: str = "artifact_type",
    fields: Optional[Iterable[str]] = None,
) -> List[Dict[str, Any]]:
    """Attach per-field provenance tags to normalized artifact records."""
    candidate_fields = list(fields or [])
    for record in records:
        artifact_type = record.get(artifact_type_key, "")
        if not candidate_fields:
            field_names = [key for key in record.keys() if not key.startswith("_")]
        else:
            field_names = [field for field in candidate_fields if field in record]
        field_provenance = {
            field_name: provenance_for_artifact_field(artifact_type, field_name)
            for field_name in field_names
        }
        record["field_provenance"] = field_provenance
        record["emitted_provenance"] = max_provenance(
            field_provenance.values(),
            default="SYSTEM_DERIVED",
        )
    return records


def build_record_provenance_summary(records: Iterable[Mapping[str, Any]]) -> Dict[str, Any]:
    """Summarize emitted provenance across a producer payload."""
    counts: Dict[str, int] = {}
    emitted_values = []
    for record in records:
        emitted = normalize_provenance(
            record.get("emitted_provenance"),
            default="SYSTEM_DERIVED",
        )
        emitted_values.append(emitted)
        counts[emitted] = counts.get(emitted, 0) + 1
    return {
        "record_count": len(emitted_values),
        "highest_provenance": max_provenance(
            emitted_values,
            default="SYSTEM_DERIVED",
        ),
        "counts": counts,
    }


def attach_payload_provenance(
    payload: Dict[str, Any],
    *,
    summary: Dict[str, Any],
    metadata_key: str = "_provenance",
) -> Dict[str, Any]:
    """Attach internal runtime metadata and visible provenance summary."""
    payload["provenance_summary"] = summary
    payload[metadata_key] = {
        "emitted_provenance": summary.get("highest_provenance", "SYSTEM_DERIVED"),
    }
    return payload
