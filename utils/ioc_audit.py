"""Chunk-level audit helpers for vendor-agnostic IOC extraction."""

from __future__ import annotations

import importlib.util
import json
import os
import re
from copy import deepcopy
from typing import Any, Dict, Iterable, List, Optional, Tuple

from utils.ai.router import invoke_json


def _load_local_module(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(
        name,
        os.path.join(os.path.dirname(__file__), filename),
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


_report_normalizer = _load_local_module("ioc_audit_report_normalizer_shared", "report_normalizer.py")

AUDIT_ITEM_TYPES = (
    "command",
    "credential",
    "cve",
    "domain",
    "email",
    "encoded_powershell",
    "file_name",
    "file_path",
    "hash",
    "hostname",
    "ipv4",
    "ipv6",
    "network_share",
    "registry_key",
    "scheduled_task",
    "screenconnect_id",
    "service",
    "sid",
    "url",
    "user",
)

AUDIT_REASON_TYPES = (
    "benign_vendor_reference",
    "duplicate_candidate",
    "normalization_fix",
    "not_an_ioc",
    "observed_activity",
    "remediation_only_reference",
)

EMPTY_AUDIT_DELTA = {
    "additions": [],
    "corrections": [],
    "drops": [],
}

IOC_AUDIT_SYSTEM_PROMPT = """Review one security report chunk and audit regex IOC candidates.

Return ONLY valid JSON with this exact shape:
{
  "additions": [
    {"chunk_id": "chunk-01", "type": "domain", "value": "evil.example", "context": "..."}
  ],
  "corrections": [
    {
      "chunk_id": "chunk-01",
      "type": "service",
      "original_value": "BadSvc",
      "corrected_value": "BadSvcUpdater",
      "reason": "normalization_fix"
    }
  ],
  "drops": [
    {
      "chunk_id": "chunk-01",
      "type": "domain",
      "value": "vendor.example.com",
      "reason": "benign_vendor_reference"
    }
  ]
}

Rules:
1. Delta only. Do not restate accepted regex candidates.
2. Every value must appear in the chunk text after normalization/defanging.
3. type must be one of: %s
4. correction reason and drop reason must be one of: %s
5. Use the supplied chunk_id exactly.
6. Prefer drops for remediation-only, benign vendor, or obviously wrong candidates.
7. Prefer corrections only when the chunk shows a more precise value than the regex candidate.
8. Keep context short and quote-free. If no additions are needed, return [].
""" % (", ".join(AUDIT_ITEM_TYPES), ", ".join(AUDIT_REASON_TYPES))

IOC_AUDIT_USER_PROMPT_TEMPLATE = """Audit this security-report chunk.

Chunk ID: {chunk_id}
Sections: {sections}

Chunk text:
{chunk_text}

Regex candidates already extracted for this chunk:
{candidates_json}
"""

_DEFANG_REPLACEMENTS = (
    (re.compile(r"hxxps?\[://\]", re.I), lambda m: "https://" if m.group(0).lower().startswith("hxxps") else "http://"),
    (re.compile(r"hxxps://", re.I), "https://"),
    (re.compile(r"hxxp://", re.I), "http://"),
    (re.compile(r"\[://\]"), "://"),
    (re.compile(r"\[:\]"), ":"),
    (re.compile(r"\[\.\]|\(\.\)|\{.\}", re.I), "."),
    (re.compile(r"\[dot\]|\(dot\)|\{dot\}|\[d0t\]|\(d0t\)", re.I), "."),
    (re.compile(r"\[at\]|\(at\)|\[@\]|\{at\}", re.I), "@"),
)


def _defang_text(value: str) -> str:
    text = str(value or "")
    for pattern, replacement in _DEFANG_REPLACEMENTS:
        text = pattern.sub(replacement, text)
    return text


def _normalized_trace_text(value: str) -> str:
    normalized = _defang_text(value or "")
    normalized = normalized.replace("\\\\", "\\")
    normalized = re.sub(r"\s+", " ", normalized).strip().lower()
    return normalized


def _clean_value(value: Any) -> str:
    return str(value or "").strip()


def _candidate_value_in_chunk(value: str, chunk_text: str) -> bool:
    candidate = _normalized_trace_text(value)
    if not candidate:
        return False
    return candidate in _normalized_trace_text(chunk_text)


def _append_candidate(
    candidates: List[Dict[str, Any]],
    *,
    item_type: str,
    value: str,
    field: str,
    context: str = "",
) -> None:
    clean_value = _clean_value(value)
    if not clean_value:
        return
    candidates.append(
        {
            "type": item_type,
            "value": clean_value,
            "field": field,
            "context": _clean_value(context),
        }
    )


def build_audit_candidates(extraction: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Flatten runtime extraction into audit candidate items."""
    candidates: List[Dict[str, Any]] = []
    iocs = extraction.get("iocs", {}) or {}
    raw_artifacts = extraction.get("raw_artifacts", {}) or {}

    for item in iocs.get("hashes", []):
        if isinstance(item, dict):
            _append_candidate(
                candidates,
                item_type="hash",
                value=item.get("value", ""),
                field="iocs.hashes",
                context=item.get("context", ""),
            )
    for item in iocs.get("ip_addresses", []):
        if not isinstance(item, dict):
            continue
        ip_type = "ipv6" if item.get("type") == "ipv6" or ":" in str(item.get("value", "")) else "ipv4"
        _append_candidate(
            candidates,
            item_type=ip_type,
            value=item.get("value", ""),
            field="iocs.ip_addresses",
            context=item.get("context", ""),
        )
    for field_name, item_type in (
        ("domains", "domain"),
        ("urls", "url"),
        ("file_names", "file_name"),
        ("email_addresses", "email"),
        ("cves", "cve"),
    ):
        for item in iocs.get(field_name, []):
            if isinstance(item, dict):
                value = item.get("value", "") or item.get("name", "") or item.get("path", "")
                context = item.get("context", "")
            else:
                value = item
                context = ""
            _append_candidate(
                candidates,
                item_type=item_type,
                value=value,
                field=f"iocs.{field_name}",
                context=context,
            )
    for item in iocs.get("file_paths", []):
        if not isinstance(item, dict):
            continue
        _append_candidate(
            candidates,
            item_type="file_path",
            value=item.get("value", ""),
            field="iocs.file_paths",
            context=item.get("context", ""),
        )
    for item in iocs.get("users", []):
        if not isinstance(item, dict):
            continue
        _append_candidate(
            candidates,
            item_type="user",
            value=item.get("value", ""),
            field="iocs.users",
            context=item.get("context", ""),
        )
    for item in iocs.get("sids", []):
        value = item.get("value", "") if isinstance(item, dict) else item
        context = item.get("context", "") if isinstance(item, dict) else ""
        _append_candidate(
            candidates,
            item_type="sid",
            value=value,
            field="iocs.sids",
            context=context,
        )
    for item in iocs.get("registry_keys", []):
        if not isinstance(item, dict):
            continue
        _append_candidate(
            candidates,
            item_type="registry_key",
            value=item.get("value", ""),
            field="iocs.registry_keys",
            context=item.get("context", ""),
        )
    for item in iocs.get("commands", []):
        if not isinstance(item, dict):
            continue
        _append_candidate(
            candidates,
            item_type="command",
            value=item.get("value", ""),
            field="iocs.commands",
            context=item.get("context", ""),
        )
    for field_name, item_type, value_key in (
        ("services", "service", "name"),
        ("scheduled_tasks", "scheduled_task", "name"),
        ("hostnames", "hostname", "value"),
        ("network_shares", "network_share", "value"),
    ):
        for item in iocs.get(field_name, []):
            if isinstance(item, dict):
                value = item.get(value_key, "") or item.get("path", "")
                context = item.get("context", "")
            else:
                value = item
                context = ""
            _append_candidate(
                candidates,
                item_type=item_type,
                value=value,
                field=f"iocs.{field_name}",
                context=context,
            )
    for item in iocs.get("credentials", []):
        if not isinstance(item, dict):
            continue
        _append_candidate(
            candidates,
            item_type="credential",
            value=item.get("value", ""),
            field="iocs.credentials",
            context=item.get("context", ""),
        )
    for raw_name, item_type in (
        ("screenconnect_ids", "screenconnect_id"),
        ("encoded_powershell", "encoded_powershell"),
    ):
        for value in raw_artifacts.get(raw_name, []):
            _append_candidate(
                candidates,
                item_type=item_type,
                value=value,
                field=f"raw_artifacts.{raw_name}",
            )

    deduped: List[Dict[str, Any]] = []
    seen = set()
    for item in candidates:
        key = (item["type"], item["value"].strip().lower())
        if not key[1] or key in seen:
            continue
        seen.add(key)
        deduped.append(item)
    return deduped


def select_chunk_candidates(
    extraction: Dict[str, Any],
    chunk_text: str,
    *,
    max_candidates: int = 64,
) -> List[Dict[str, Any]]:
    """Return regex candidates that appear in or strongly relate to a chunk."""
    chunk_candidates = [
        item
        for item in build_audit_candidates(extraction)
        if _candidate_value_in_chunk(item["value"], chunk_text)
    ]
    return chunk_candidates[:max_candidates]


def _normalize_audit_reason(reason: Any) -> str:
    cleaned = _clean_value(reason).lower().replace(" ", "_")
    return cleaned if cleaned in AUDIT_REASON_TYPES else ""


def _validated_delta_item(
    *,
    item: Dict[str, Any],
    chunk_id: str,
    chunk_text: str,
    candidate_map: Dict[Tuple[str, str], Dict[str, Any]],
    mode: str,
) -> Optional[Dict[str, Any]]:
    if not isinstance(item, dict):
        return None
    if _clean_value(item.get("chunk_id")) != chunk_id:
        return None
    item_type = _clean_value(item.get("type")).lower()
    if item_type not in AUDIT_ITEM_TYPES:
        return None

    if mode == "additions":
        value = _clean_value(item.get("value"))
        if not value or not _candidate_value_in_chunk(value, chunk_text):
            return None
        return {
            "chunk_id": chunk_id,
            "type": item_type,
            "value": value,
            "context": _clean_value(item.get("context")),
        }

    if mode == "corrections":
        original_value = _clean_value(item.get("original_value"))
        corrected_value = _clean_value(item.get("corrected_value"))
        reason = _normalize_audit_reason(item.get("reason"))
        if not original_value or not corrected_value or not reason:
            return None
        if (item_type, original_value.lower()) not in candidate_map:
            return None
        if not _candidate_value_in_chunk(corrected_value, chunk_text):
            return None
        return {
            "chunk_id": chunk_id,
            "type": item_type,
            "original_value": original_value,
            "corrected_value": corrected_value,
            "reason": reason,
        }

    value = _clean_value(item.get("value"))
    reason = _normalize_audit_reason(item.get("reason"))
    if not value or not reason:
        return None
    if (item_type, value.lower()) not in candidate_map:
        return None
    return {
        "chunk_id": chunk_id,
        "type": item_type,
        "value": value,
        "reason": reason,
    }


def validate_audit_delta(
    payload: Any,
    *,
    chunk_id: str,
    chunk_text: str,
    chunk_candidates: List[Dict[str, Any]],
) -> Tuple[Dict[str, List[Dict[str, Any]]], Dict[str, Any]]:
    """Validate a chunk-level audit response against the locked delta schema."""
    validated = deepcopy(EMPTY_AUDIT_DELTA)
    rejected: List[str] = []

    if not isinstance(payload, dict):
        return validated, {"rejected": ["payload_not_dict"]}

    candidate_map = {
        (item["type"], item["value"].strip().lower()): item
        for item in chunk_candidates
        if item.get("value")
    }

    for key in ("additions", "corrections", "drops"):
        items = payload.get(key, [])
        if not isinstance(items, list):
            rejected.append(f"{key}_not_list")
            continue
        for index, item in enumerate(items):
            validated_item = _validated_delta_item(
                item=item,
                chunk_id=chunk_id,
                chunk_text=chunk_text,
                candidate_map=candidate_map,
                mode=key,
            )
            if validated_item is None:
                rejected.append(f"{key}[{index}]")
                continue
            validated[key].append(validated_item)

    return validated, {"rejected": rejected}


def render_audit_prompt(chunk_meta: Dict[str, Any], chunk_candidates: List[Dict[str, Any]]) -> str:
    """Render the audit prompt for one generic report chunk."""
    return IOC_AUDIT_USER_PROMPT_TEMPLATE.format(
        chunk_id=chunk_meta.get("chunk_id"),
        sections=", ".join(chunk_meta.get("sections") or ["Full Report"]),
        chunk_text=chunk_meta.get("text", ""),
        candidates_json=json.dumps(chunk_candidates, indent=2, ensure_ascii=True),
    )


def _item_matches_value(item: Any, value: str, *, key: str = "value") -> bool:
    if isinstance(item, dict):
        candidate = item.get(key, "") or item.get("name", "") or item.get("path", "")
    else:
        candidate = item
    return _clean_value(candidate).lower() == _clean_value(value).lower()


def _remove_item(items: List[Any], value: str, *, key: str = "value") -> List[Any]:
    return [item for item in items if not _item_matches_value(item, value, key=key)]


def _add_flat_item(extraction: Dict[str, Any], item_type: str, value: str, context: str) -> None:
    iocs = extraction.setdefault("iocs", {})
    raw_artifacts = extraction.setdefault("raw_artifacts", {})
    summary = extraction.setdefault("extraction_summary", {})

    if item_type == "hash":
        iocs.setdefault("hashes", []).append({"value": value, "type": "sha256", "context": context})
    elif item_type in {"ipv4", "ipv6"}:
        iocs.setdefault("ip_addresses", []).append(
            {
                "value": value,
                "port": None,
                "direction": "unknown",
                "context": context,
                "type": item_type,
            }
        )
    elif item_type == "domain":
        iocs.setdefault("domains", []).append({"value": value, "context": context})
    elif item_type == "url":
        iocs.setdefault("urls", []).append({"value": value, "context": context, "type": "unknown"})
    elif item_type == "file_path":
        iocs.setdefault("file_paths", []).append({"value": value, "context": context, "action": "unknown"})
    elif item_type == "file_name":
        iocs.setdefault("file_names", []).append(value)
    elif item_type == "user":
        iocs.setdefault("users", []).append({"value": value, "context": context})
        summary.setdefault("affected_users", [])
    elif item_type == "sid":
        iocs.setdefault("sids", []).append({"value": value, "context": context})
    elif item_type == "registry_key":
        iocs.setdefault("registry_keys", []).append({"value": value, "context": context, "action": "unknown"})
    elif item_type == "command":
        iocs.setdefault("commands", []).append({"value": value, "context": context})
    elif item_type == "credential":
        iocs.setdefault("credentials", []).append({"type": "password", "value": value, "context": context})
    elif item_type == "hostname":
        iocs.setdefault("hostnames", []).append({"value": value, "context": context})
        summary.setdefault("affected_hosts", [])
    elif item_type == "service":
        iocs.setdefault("services", []).append({"name": value, "context": context, "action": "unknown"})
    elif item_type == "scheduled_task":
        iocs.setdefault("scheduled_tasks", []).append({"name": value, "context": context, "action": "unknown"})
    elif item_type == "network_share":
        iocs.setdefault("network_shares", []).append({"value": value, "context": context})
    elif item_type == "email":
        iocs.setdefault("email_addresses", []).append(value)
    elif item_type == "cve":
        iocs.setdefault("cves", []).append(value.upper())
    elif item_type == "screenconnect_id":
        raw_artifacts.setdefault("screenconnect_ids", []).append(value)
    elif item_type == "encoded_powershell":
        raw_artifacts.setdefault("encoded_powershell", []).append(value)


def _replace_flat_item(extraction: Dict[str, Any], item_type: str, original_value: str, corrected_value: str) -> None:
    _drop_flat_item(extraction, item_type, original_value)
    _add_flat_item(extraction, item_type, corrected_value, "Corrected by chunk audit")


def _drop_flat_item(extraction: Dict[str, Any], item_type: str, value: str) -> None:
    iocs = extraction.setdefault("iocs", {})
    raw_artifacts = extraction.setdefault("raw_artifacts", {})

    if item_type == "hash":
        iocs["hashes"] = _remove_item(iocs.get("hashes", []), value)
    elif item_type in {"ipv4", "ipv6"}:
        iocs["ip_addresses"] = _remove_item(iocs.get("ip_addresses", []), value)
    elif item_type == "domain":
        iocs["domains"] = _remove_item(iocs.get("domains", []), value)
    elif item_type == "url":
        iocs["urls"] = _remove_item(iocs.get("urls", []), value)
    elif item_type == "file_path":
        iocs["file_paths"] = _remove_item(iocs.get("file_paths", []), value)
    elif item_type == "file_name":
        iocs["file_names"] = [item for item in iocs.get("file_names", []) if _clean_value(item).lower() != _clean_value(value).lower()]
    elif item_type == "user":
        iocs["users"] = _remove_item(iocs.get("users", []), value)
    elif item_type == "sid":
        iocs["sids"] = _remove_item(iocs.get("sids", []), value)
    elif item_type == "registry_key":
        iocs["registry_keys"] = _remove_item(iocs.get("registry_keys", []), value)
    elif item_type == "command":
        iocs["commands"] = _remove_item(iocs.get("commands", []), value)
    elif item_type == "credential":
        iocs["credentials"] = _remove_item(iocs.get("credentials", []), value)
    elif item_type == "hostname":
        iocs["hostnames"] = _remove_item(iocs.get("hostnames", []), value)
    elif item_type == "service":
        iocs["services"] = _remove_item(iocs.get("services", []), value, key="name")
    elif item_type == "scheduled_task":
        iocs["scheduled_tasks"] = _remove_item(iocs.get("scheduled_tasks", []), value, key="name")
    elif item_type == "network_share":
        iocs["network_shares"] = _remove_item(iocs.get("network_shares", []), value)
    elif item_type == "email":
        iocs["email_addresses"] = [item for item in iocs.get("email_addresses", []) if _clean_value(item).lower() != _clean_value(value).lower()]
    elif item_type == "cve":
        iocs["cves"] = [item for item in iocs.get("cves", []) if _clean_value(item).lower() != _clean_value(value).lower()]
    elif item_type == "screenconnect_id":
        raw_artifacts["screenconnect_ids"] = [
            item for item in raw_artifacts.get("screenconnect_ids", [])
            if _clean_value(item).lower() != _clean_value(value).lower()
        ]
    elif item_type == "encoded_powershell":
        raw_artifacts["encoded_powershell"] = [
            item for item in raw_artifacts.get("encoded_powershell", [])
            if _clean_value(item).lower() != _clean_value(value).lower()
        ]


def apply_audit_deltas(
    extraction: Dict[str, Any],
    validated_deltas: Iterable[Dict[str, List[Dict[str, Any]]]],
) -> Dict[str, Any]:
    """Apply accepted audit deltas to the flat runtime extraction shape."""
    updated = deepcopy(extraction)
    for delta in validated_deltas:
        for drop in delta.get("drops", []):
            _drop_flat_item(updated, drop["type"], drop["value"])
        for correction in delta.get("corrections", []):
            _replace_flat_item(
                updated,
                correction["type"],
                correction["original_value"],
                correction["corrected_value"],
            )
        for addition in delta.get("additions", []):
            _add_flat_item(
                updated,
                addition["type"],
                addition["value"],
                addition.get("context", ""),
            )
    return updated


def run_audit_stage(
    provider: Any,
    report_text: str,
    deterministic_extraction: Dict[str, Any],
    *,
    max_chunk_chars: int,
    max_response_tokens: int,
    validate_result,
) -> Dict[str, Any]:
    """Audit regex candidates chunk-by-chunk and apply accepted deltas."""
    chunks = _report_normalizer.chunk_report_for_ai_with_metadata(report_text, max_chunk_chars)
    validated_deltas: List[Dict[str, List[Dict[str, Any]]]] = []
    task_failures: List[Dict[str, Any]] = []
    task_provenance: List[Dict[str, Any]] = []
    reviewed_chunks = 0
    audit_candidate_count = 0
    rejected_delta_count = 0

    for index, chunk_meta in enumerate(chunks, start=1):
        chunk_id = f"chunk-{index:02d}"
        chunk_meta = dict(chunk_meta)
        chunk_meta["chunk_id"] = chunk_id
        chunk_candidates = select_chunk_candidates(deterministic_extraction, chunk_meta.get("text", ""))
        if not chunk_candidates:
            continue
        audit_candidate_count += len(chunk_candidates)
        prompt = render_audit_prompt(chunk_meta, chunk_candidates)
        ai_result = invoke_json(
            function="ioc_extraction",
            prompt=prompt,
            system=IOC_AUDIT_SYSTEM_PROMPT,
            temperature=0.0,
            max_tokens=max_response_tokens,
            provider=provider,
        )
        if not ai_result.get("success"):
            task_failures.append(
                {
                    "chunk": chunk_id,
                    "sections": list(chunk_meta.get("sections") or []),
                    "error": ai_result.get("error"),
                }
            )
            continue

        validation_error = validate_result(ai_result)
        if validation_error:
            task_failures.append(
                {
                    "chunk": chunk_id,
                    "sections": list(chunk_meta.get("sections") or []),
                    "error": validation_error,
                }
            )
            continue

        validated_delta, delta_meta = validate_audit_delta(
            ai_result.get("data"),
            chunk_id=chunk_id,
            chunk_text=chunk_meta.get("text", ""),
            chunk_candidates=chunk_candidates,
        )
        rejected_delta_count += len(delta_meta.get("rejected", []))
        if any(validated_delta.values()):
            validated_deltas.append(validated_delta)
        reviewed_chunks += 1
        task_provenance.append(
            {
                "chunk": chunk_id,
                "sections": list(chunk_meta.get("sections") or []),
                "chunk_index": chunk_meta.get("chunk_index"),
                "chunk_count": chunk_meta.get("chunk_count"),
                "candidate_count": len(chunk_candidates),
                "accepted_additions": len(validated_delta.get("additions", [])),
                "accepted_corrections": len(validated_delta.get("corrections", [])),
                "accepted_drops": len(validated_delta.get("drops", [])),
                "rejected_delta_items": len(delta_meta.get("rejected", [])),
            }
        )

    audited_extraction = apply_audit_deltas(deterministic_extraction, validated_deltas)
    return {
        "audited_extraction": audited_extraction,
        "validated_deltas": validated_deltas,
        "task_failures": task_failures,
        "task_provenance": task_provenance,
        "planned_tasks": [item["chunk"] for item in task_provenance],
        "schema_reviews": 0,
        "reviewed_chunks": reviewed_chunks,
        "candidate_count": audit_candidate_count,
        "rejected_delta_count": rejected_delta_count,
    }
