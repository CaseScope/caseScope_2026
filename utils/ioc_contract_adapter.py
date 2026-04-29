"""IOC contract coercion, validation, and review-prep helpers."""

from __future__ import annotations

import importlib.util
import json
import os
import re
from collections import Counter
from copy import deepcopy
from typing import Any, Dict, List, Optional, Tuple


def _load_local_module(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(
        name,
        os.path.join(os.path.dirname(__file__), filename),
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


_ioc_contract = _load_local_module("ioc_contract_adapter_shared", "ioc_contract.py")
_ai_review = _load_local_module("ioc_contract_adapter_review_shared", "ai_review.py")
_ioc_normalizer = _load_local_module("ioc_contract_adapter_normalizer_shared", "ioc_normalizer.py")


def _as_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def coerce_ioc_contract_payload(payload: Any) -> Dict[str, Any]:
    """Coerce model output into the canonical IOC contract shape."""
    expected = _ioc_contract.build_empty_ioc_extraction()
    payload = payload if isinstance(payload, dict) else {}
    coerced: Dict[str, Any] = {}

    for key, default_value in expected.items():
        provided = payload.get(key, default_value)
        if isinstance(default_value, dict):
            provided_dict = provided if isinstance(provided, dict) else {}
            coerced[key] = {}
            for sub_key, sub_default in default_value.items():
                sub_value = provided_dict.get(sub_key, sub_default)
                if isinstance(sub_default, list):
                    coerced[key][sub_key] = _as_list(sub_value)
                elif isinstance(sub_default, dict):
                    coerced[key][sub_key] = sub_value if isinstance(sub_value, dict) else dict(sub_default)
                else:
                    coerced[key][sub_key] = sub_value if sub_value is not None else sub_default
        elif isinstance(default_value, list):
            coerced[key] = _as_list(provided)
        else:
            coerced[key] = provided if provided is not None else default_value

    return _ai_review.sanitize_review_payload(coerced)


def ioc_schema_metrics(extraction: Any) -> Dict[str, bool]:
    """Validate the top-level IOC extraction schema shape."""
    if not isinstance(extraction, dict):
        return {
            'top_level_only': False,
            'required_keys_present': False,
        }

    keys = set(extraction.keys())
    required = set(_ioc_contract.build_empty_ioc_extraction().keys())
    return {
        'top_level_only': keys.issubset(required),
        'required_keys_present': required.issubset(keys),
    }


def is_valid_ioc_schema(extraction: Any) -> bool:
    """Return True when the payload matches the expected contract keys."""
    metrics = ioc_schema_metrics(extraction)
    return metrics['top_level_only'] and metrics['required_keys_present']


def iter_contract_key_violations(
    payload: Any,
    contract: Any,
    *,
    path: str = '',
) -> List[str]:
    """Return unexpected nested keys that fall outside the IOC contract."""
    violations: List[str] = []
    if not isinstance(payload, dict) or not isinstance(contract, dict):
        return violations

    for key, value in payload.items():
        current_path = f"{path}.{key}" if path else key
        if key not in contract:
            violations.append(current_path)
            continue
        contract_value = contract.get(key)
        if isinstance(value, dict) and isinstance(contract_value, dict):
            violations.extend(
                iter_contract_key_violations(value, contract_value, path=current_path)
            )
    return violations


def _list_has_suspicious_repetition(items: List[Any], *, min_repeats: int = 3) -> bool:
    if not isinstance(items, list) or len(items) < min_repeats:
        return False

    counts: Counter[str] = Counter()
    for item in items:
        try:
            signature = json.dumps(item, sort_keys=True, default=str)
        except Exception:
            signature = str(item)
        counts[signature] += 1
        if counts[signature] >= min_repeats:
            return True
    return False


def _iter_payload_lists(payload: Any) -> List[Tuple[str, List[Any]]]:
    collected: List[Tuple[str, List[Any]]] = []

    def _walk(value: Any, path: str) -> None:
        if isinstance(value, list):
            collected.append((path, value))
            return
        if isinstance(value, dict):
            for key, child in value.items():
                child_path = f"{path}.{key}" if path else key
                _walk(child, child_path)

    _walk(payload, '')
    return collected


def find_invalid_hash_entries(payload: Any) -> List[str]:
    """Return JSON paths for hash items that fail the existing hash validators."""
    if not isinstance(payload, dict):
        return []

    invalid: List[str] = []
    hashes = (
        (payload.get('file_iocs') or {}).get('hashes', [])
        if isinstance(payload.get('file_iocs'), dict)
        else []
    )
    for index, item in enumerate(hashes):
        raw_value = ''
        if isinstance(item, dict):
            raw_value = str(item.get('value', '') or '').strip()
        else:
            raw_value = str(item or '').strip()
        if raw_value and _ioc_normalizer._normalize_ai_hash_item(item) is None:
            invalid.append(f'file_iocs.hashes[{index}]')
    return invalid


def _is_semantically_empty(value: Any) -> bool:
    if value is None:
        return True
    if isinstance(value, str):
        return not value.strip()
    if isinstance(value, (list, tuple, set)):
        return all(_is_semantically_empty(item) for item in value)
    if isinstance(value, dict):
        return all(_is_semantically_empty(item) for item in value.values())
    return False


def payload_semantic_review_reasons(
    payload: Any,
    *,
    task_name: Optional[str] = None,
    semantic_task_allowed_fields: Optional[Dict[str, Dict[str, Any]]] = None,
) -> List[str]:
    """Return semantic-quality reasons to trigger IOC payload review."""
    reasons: List[str] = []
    contract = _ioc_contract.build_empty_ioc_extraction()

    if not isinstance(payload, dict):
        return ['payload_not_dict']

    contract_violations = iter_contract_key_violations(payload, contract)
    if contract_violations:
        reasons.extend(f'unexpected_field:{path}' for path in contract_violations[:10])

    invalid_hashes = find_invalid_hash_entries(payload)
    if invalid_hashes:
        reasons.extend(f'invalid_hash:{path}' for path in invalid_hashes[:10])

    if task_name and semantic_task_allowed_fields:
        allowed = semantic_task_allowed_fields.get(task_name)
        if allowed:
            for top_level_key, value in payload.items():
                if top_level_key == 'affected_hosts':
                    continue
                if top_level_key == 'raw_artifacts':
                    if not _is_semantically_empty(value):
                        reasons.append(f'task_field_leakage:{top_level_key}')
                    continue
                if top_level_key not in allowed:
                    if not _is_semantically_empty(value):
                        reasons.append(f'task_field_leakage:{top_level_key}')
                    continue
                allowed_subfields = allowed[top_level_key]
                if allowed_subfields is None or not isinstance(value, dict):
                    continue
                for subfield, subvalue in value.items():
                    if subfield not in allowed_subfields and not _is_semantically_empty(subvalue):
                        reasons.append(f'task_field_leakage:{top_level_key}.{subfield}')

    for list_path, items in _iter_payload_lists(payload):
        if _list_has_suspicious_repetition(items):
            reasons.append(f'repeated_entries:{list_path}')

    deduped: List[str] = []
    seen = set()
    for reason in reasons:
        if reason in seen:
            continue
        seen.add(reason)
        deduped.append(reason)
    return deduped


def _has_repetitive_long_substring(text: str, *, window: int = 80, min_repeats: int = 3) -> bool:
    normalized = re.sub(r'\s+', ' ', str(text or '')).strip()
    if len(normalized) < window * min_repeats:
        return False

    long_lines = [
        line.strip()
        for line in str(text or '').splitlines()
        if len(line.strip()) >= window
    ]
    if long_lines:
        line_counts = Counter(long_lines)
        if any(count >= min_repeats for count in line_counts.values()):
            return True

    counts: Counter[str] = Counter()
    step = max(5, window // 8)
    for index in range(0, len(normalized) - window + 1, step):
        chunk = normalized[index:index + window]
        counts[chunk] += 1
        if counts[chunk] >= min_repeats:
            return True
    return False


def validate_ai_result_metadata(ai_result: Dict[str, Any]) -> Optional[str]:
    """Return a fail-fast error for empty, truncated, or repetitive AI output."""
    raw_text = str(ai_result.get('raw_response') or ai_result.get('response') or '')
    if not raw_text.strip():
        return 'empty content from provider'

    finish_reason = str(ai_result.get('finish_reason') or '').strip().lower()
    if finish_reason and finish_reason != 'stop':
        return f"finish_reason was '{finish_reason}'"

    if _has_repetitive_long_substring(raw_text):
        return 'repetitive output detected before repair'

    return None


def prepare_ai_extraction_payload(
    provider: Any,
    payload: Any,
    *,
    max_tokens: int,
    ai_review_max_tokens: int,
    task_name: Optional[str] = None,
    semantic_task_allowed_fields: Optional[Dict[str, Dict[str, Any]]] = None,
    review_structured_output=None,
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Validate and lightly repair AI JSON before normalization."""
    schema_before = ioc_schema_metrics(payload)
    semantic_review_reasons = payload_semantic_review_reasons(
        payload,
        task_name=task_name,
        semantic_task_allowed_fields=semantic_task_allowed_fields,
    )
    review_applied = (not is_valid_ioc_schema(payload)) or bool(semantic_review_reasons)
    candidate = coerce_ioc_contract_payload(payload)
    review_callable = review_structured_output or _ai_review.review_structured_output

    if review_applied:
        candidate = review_callable(
            provider,
            function='ioc_extraction',
            payload=candidate,
            review_focus=(
                "Review the JSON as a CaseScope IOC extraction pass. Preserve the IOC schema, "
                "keep only concrete indicators from the source report, and remove filler or "
                "unsupported certainty."
            ),
            max_tokens=min(max_tokens, ai_review_max_tokens),
        )
        candidate = coerce_ioc_contract_payload(candidate)

    return candidate, {
        'review_applied': review_applied,
        'schema_before': schema_before,
        'schema_after': ioc_schema_metrics(candidate),
        'semantic_review_reasons': semantic_review_reasons,
    }


def filter_semantic_payload_for_task(
    task_name: str,
    payload: Dict[str, Any],
    *,
    semantic_task_allowed_fields: Dict[str, Dict[str, Any]],
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Keep only the schema fields owned by the semantic task and report stripping."""
    meta = {
        'stripped_fields': [],
        'preserved_context_fields': [],
    }
    if task_name == 'semantic_residual_review':
        return payload, meta

    allowed = semantic_task_allowed_fields.get(task_name)
    if not allowed:
        return payload, meta

    def _collect_non_empty_paths(value: Any, prefix: str) -> List[str]:
        if _is_semantically_empty(value):
            return []
        if isinstance(value, dict):
            paths: List[str] = []
            for child_key, child_value in value.items():
                paths.extend(_collect_non_empty_paths(child_value, f'{prefix}.{child_key}'))
            return paths or [prefix]
        return [prefix]

    filtered = _ioc_contract.build_empty_ioc_extraction()
    if isinstance(payload, dict) and not _is_semantically_empty(payload.get('affected_hosts')):
        filtered['affected_hosts'] = deepcopy(payload.get('affected_hosts') or [])
        meta['preserved_context_fields'].append('affected_hosts')

    for top_level_key, value in (payload or {}).items():
        if top_level_key in {'affected_hosts'}:
            continue
        if top_level_key not in allowed and not _is_semantically_empty(value):
            meta['stripped_fields'].extend(_collect_non_empty_paths(value, top_level_key))

    for field_name, subfields in allowed.items():
        value = payload.get(field_name)
        if subfields is None:
            filtered[field_name] = deepcopy(value) if value is not None else deepcopy(filtered[field_name])
            continue

        source_dict = value if isinstance(value, dict) else {}
        target_dict = filtered.get(field_name, {})
        for source_subfield, source_subvalue in source_dict.items():
            if source_subfield not in subfields and not _is_semantically_empty(source_subvalue):
                meta['stripped_fields'].append(f'{field_name}.{source_subfield}')
        for subfield in subfields:
            if subfield in target_dict:
                target_dict[subfield] = deepcopy(source_dict.get(subfield, target_dict[subfield]))
        filtered[field_name] = target_dict
    meta['stripped_fields'] = list(dict.fromkeys(meta['stripped_fields']))
    return filtered, meta
