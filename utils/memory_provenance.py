"""Shared provenance helpers for memory-parser outputs and records."""

from __future__ import annotations

from typing import Any, Dict, Iterable, Optional

from utils.provenance import annotate_artifact_records

MEMORY_PARSER_NAME = "memory_parser"
MEMORY_PARSER_VERSION = "1.0.1"
MEMORY_ARTIFACT_FAMILY = "memory"


def build_memory_parser_provenance(
    *,
    plugin_name: Optional[str] = None,
    source_plugin: Optional[str] = None,
    emitted_provenance: str = "ARTIFACT_TAINTED",
) -> Dict[str, Any]:
    """Return normalized provenance metadata for memory artifacts."""
    provenance: Dict[str, Any] = {
        "parser_name": MEMORY_PARSER_NAME,
        "parser_version": MEMORY_PARSER_VERSION,
        "artifact_family": MEMORY_ARTIFACT_FAMILY,
        "emitted_provenance": emitted_provenance,
    }
    if plugin_name:
        provenance["plugin_name"] = plugin_name
    if source_plugin:
        provenance["source_plugin"] = source_plugin
    return provenance


def annotate_memory_record(
    record: Dict[str, Any],
    *,
    artifact_type: str,
    fields: Optional[Iterable[str]] = None,
    source_plugin: Optional[str] = None,
    stored_provenance: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Attach parser and field provenance to a direct memory artifact record."""
    normalized = dict(record)
    normalized["_artifact_type"] = artifact_type
    annotate_artifact_records(
        [normalized],
        artifact_type_key="_artifact_type",
        fields=fields,
    )
    merged_provenance = build_memory_parser_provenance(
        source_plugin=source_plugin,
        emitted_provenance=normalized.get("emitted_provenance", "ARTIFACT_TAINTED"),
    )
    if isinstance(stored_provenance, dict):
        for key, value in stored_provenance.items():
            if value not in (None, ""):
                merged_provenance[key] = value
    normalized["_provenance"] = merged_provenance
    normalized.pop("_artifact_type", None)
    return normalized
