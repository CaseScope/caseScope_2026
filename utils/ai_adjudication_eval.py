"""Formatting helpers for AI adjudication dry-run evaluation output.

These helpers do not call AI providers, evaluate evidence, mutate scoring
objects, or persist anything unless the caller explicitly writes JSONL.
"""

from __future__ import annotations

import json
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List


def _list_value(value: Any) -> List[Any]:
    if isinstance(value, list):
        return list(value)
    if isinstance(value, tuple):
        return list(value)
    return []


def build_ai_adjudication_eval_record(
    *,
    pattern_id: str,
    deterministic_score: float,
    raw_payload: dict,
    ai_result: dict,
    noise_context_state: str = "",
    case_label: str = "",
) -> Dict[str, Any]:
    """Normalize one adjudication dry-run result into a JSONL-friendly record."""
    raw = deepcopy(raw_payload or {})
    result = deepcopy(ai_result or {})
    validation = result.get("adjudication_validation")
    if not isinstance(validation, dict):
        validation = {}

    return {
        "case_label": str(case_label or ""),
        "pattern_id": str(pattern_id or ""),
        "deterministic_score": float(deterministic_score or 0),
        "raw_adjustment": raw.get("confidence_adjustment"),
        "validated_adjustment": result.get("adjustment"),
        "final_score_if_available": result.get(
            "final_score_if_available",
            result.get("final_score"),
        ),
        "valid": bool(validation.get("is_valid", False)),
        "validation_errors": _list_value(validation.get("errors")),
        "validation_warnings": _list_value(validation.get("warnings")),
        "unsupported_fact_claims": _list_value(validation.get("unsupported_fact_claims")),
        "invalid_evidence_ids": _list_value(validation.get("invalid_evidence_ids")),
        "invalid_context_ids": _list_value(validation.get("invalid_context_ids")),
        "referenced_context_ids": _list_value(raw.get("referenced_context_ids")),
        "supporting_evidence_ids": _list_value(raw.get("supporting_evidence_ids")),
        "mitigating_evidence_ids": _list_value(raw.get("mitigating_evidence_ids")),
        "noise_context_state": str(noise_context_state or ""),
        "model_used": result.get("model_used") or raw.get("model_used") or raw.get("model") or "",
        "timestamp_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }


def write_eval_records_jsonl(records: List[Dict[str, Any]], path: str) -> int:
    """Write records as newline-delimited JSON and return the count written."""
    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    count = 0
    with output_path.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, sort_keys=True, default=str))
            handle.write("\n")
            count += 1
    return count
