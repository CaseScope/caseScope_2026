"""Stage merge helpers for deterministic and semantic IOC extraction."""

from __future__ import annotations

from typing import Any, Callable, Dict, List


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
