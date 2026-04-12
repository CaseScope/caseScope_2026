"""Stage merge helpers for deterministic and semantic IOC extraction."""

from __future__ import annotations

import json
from typing import Any, Callable, Dict, List, Optional


def merge_semantic_results(
    deterministic_extraction: Dict[str, Any],
    semantic_results: List[Dict[str, Any]],
    *,
    merge_func: Callable[[Dict[str, Any], Dict[str, Any]], Dict[str, Any]],
    merge_summary_func: Callable[[Dict[str, Any], Dict[str, Any]], Dict[str, Any]],
) -> Dict[str, Any]:
    """Merge semantic extractions into the deterministic base extraction."""
    merged = deterministic_extraction
    for semantic in semantic_results or []:
        merged = merge_func(semantic, merged)
        merged["extraction_summary"] = merge_summary_func(
            merged.get("extraction_summary", {}),
            semantic.get("extraction_summary", {}),
        )
    return merged


def merge_record_lists(*record_lists: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Merge IOC record lists by value, type, and provenance source."""
    merged: List[Dict[str, Any]] = []
    seen = set()
    for record_list in record_lists:
        for record in record_list or []:
            key = (
                str(record.get("ioc_type") or "").lower(),
                str(record.get("value") or "").strip().lower(),
                str(record.get("source") or "").lower(),
            )
            if not key[1] or key in seen:
                continue
            seen.add(key)
            merged.append(record)
    return merged


def extract_dedup_key(item: Any) -> Optional[str]:
    """Get a normalized deduplication key from IOC-like values."""
    if isinstance(item, dict):
        value = (
            item.get("value")
            or item.get("name")
            or item.get("path")
            or item.get("key")
            or ""
        )
        return value.strip().lower() if value else None
    if isinstance(item, str):
        return item.strip().lower() if item else None
    return str(item).strip().lower() if item else None


def merge_extraction_summaries(primary: Dict[str, Any], secondary: Dict[str, Any]) -> Dict[str, Any]:
    """Merge extraction summaries from multiple IOC passes."""
    merged = dict(primary or {})
    for key, value in (secondary or {}).items():
        if isinstance(value, list):
            merged[key] = dedupe_mixed_list(merged.get(key, []), value)
        elif isinstance(value, bool):
            merged[key] = bool(merged.get(key)) or value
        elif value and not merged.get(key):
            merged[key] = value
    return merged


def merge_ai_extractions(primary: Dict[str, Any], secondary: Dict[str, Any]) -> Dict[str, Any]:
    """Merge multiple normalized AI extractions before regex enrichment."""
    merged = merge_extractions(primary, secondary)
    merged["extraction_summary"] = merge_extraction_summaries(
        primary.get("extraction_summary", {}),
        secondary.get("extraction_summary", {}),
    )
    return merged


def merge_extractions(ai: Dict[str, Any], regex: Dict[str, Any]) -> Dict[str, Any]:
    """Merge AI and regex extraction results with additive raw artifacts."""
    merged = {
        "extraction_summary": ai.get("extraction_summary", {}),
        "iocs": {},
        "raw_artifacts": {},
    }

    ai_iocs = ai.get("iocs", {})
    regex_iocs = regex.get("iocs", {})
    all_keys = set(list(ai_iocs.keys()) + list(regex_iocs.keys()))

    for key in all_keys:
        ai_items = ai_iocs.get(key, [])
        regex_items = regex_iocs.get(key, [])

        if not ai_items and not regex_items:
            merged["iocs"][key] = []
            continue
        if not ai_items:
            merged["iocs"][key] = list(regex_items)
            continue
        if not regex_items:
            merged["iocs"][key] = list(ai_items)
            continue

        seen = set()
        combined = []

        for item in ai_items:
            dedup_key = extract_dedup_key(item)
            if dedup_key and dedup_key not in seen:
                seen.add(dedup_key)
                combined.append(item)
            elif not dedup_key:
                combined.append(item)

        for item in regex_items:
            dedup_key = extract_dedup_key(item)
            if dedup_key and dedup_key not in seen:
                seen.add(dedup_key)
                combined.append(item)

        merged["iocs"][key] = combined

    ai_raw = ai.get("raw_artifacts", {})
    regex_raw = regex.get("raw_artifacts", {})
    all_raw_keys = set(list(ai_raw.keys()) + list(regex_raw.keys()))
    for key in all_raw_keys:
        ai_vals = ai_raw.get(key, [])
        regex_vals = regex_raw.get(key, [])
        if isinstance(ai_vals, list) and isinstance(regex_vals, list):
            merged["raw_artifacts"][key] = dedupe_mixed_list(ai_vals, regex_vals)
        else:
            merged["raw_artifacts"][key] = ai_vals or regex_vals

    return merged


def dedupe_mixed_list(*sequences: List[Any]) -> List[Any]:
    """Deduplicate strings and dict-like values while preserving order."""
    seen = set()
    unique = []
    for sequence in sequences:
        for item in sequence or []:
            if isinstance(item, dict):
                key = json.dumps(item, sort_keys=True, default=str)
            else:
                key = str(item).strip().lower()
            if not key or key in seen:
                continue
            seen.add(key)
            unique.append(item)
    return unique
