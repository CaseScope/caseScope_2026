"""IOC Extraction from EDR Reports

Extracts Indicators of Compromise from EDR reports using AI (Ollama)
with regex fallback. Handles deduplication and integration with 
Known Systems and Known Users.

Enhanced based on analysis of 75 real Huntress EDR reports.
"""
import re
import json
import logging
import base64
import importlib.util
import os
import sys
from collections import Counter
from copy import deepcopy
from urllib.parse import urlsplit
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any

def _load_local_module(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(
        name,
        os.path.join(os.path.dirname(__file__), filename),
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class _LazyModuleProxy:
    """Load sibling IOC modules only when a path actually needs them."""

    def __init__(self, name: str, filename: str):
        self._module_name = name
        self._filename = filename
        self._loaded_module = None
        self._module_shims = {
            module_name: sys.modules[module_name]
            for module_name in ("utils", "utils.ai", "utils.ai.router", "utils.ai_training")
            if module_name in sys.modules
        }

    def _load(self):
        if self._loaded_module is None:
            previous_modules = {
                module_name: sys.modules.get(module_name)
                for module_name in self._module_shims
            }
            try:
                for module_name, module in self._module_shims.items():
                    sys.modules[module_name] = module
                self._loaded_module = _load_local_module(self._module_name, self._filename)
            finally:
                for module_name, previous_module in previous_modules.items():
                    if previous_module is None:
                        sys.modules.pop(module_name, None)
                    else:
                        sys.modules[module_name] = previous_module
        return self._loaded_module

    def __getattr__(self, item: str):
        return getattr(self._load(), item)


_ioc_contract = _LazyModuleProxy("ioc_contract_shared", "ioc_contract.py")
_ai_review = _LazyModuleProxy("ai_review_shared", "ai_review.py")
_report_normalizer = _LazyModuleProxy("ioc_report_normalizer_shared", "report_normalizer.py")
_ioc_schema = _LazyModuleProxy("ioc_schema_shared", "ioc_schema.py")
_ioc_merge = _LazyModuleProxy("ioc_merge_shared", "ioc_merge.py")
_deterministic_stage = _LazyModuleProxy("deterministic_ioc_extractor_shared", "deterministic_ioc_extractor.py")
_semantic_stage = _LazyModuleProxy("semantic_ioc_extractor_shared", "semantic_ioc_extractor.py")
_audit_stage = _LazyModuleProxy("ioc_audit_shared", "ioc_audit.py")
_ioc_regex_extractor = _LazyModuleProxy("ioc_regex_extractor_shared", "ioc_regex_extractor.py")
_ioc_aliasing = _LazyModuleProxy("ioc_aliasing_shared", "ioc_aliasing.py")
_ioc_import_entries = _LazyModuleProxy("ioc_import_entries_shared", "ioc_import_entries.py")
_ioc_known_entities = _LazyModuleProxy("ioc_known_entities_shared", "ioc_known_entities.py")
_ioc_import_processing = _LazyModuleProxy("ioc_import_processing_shared", "ioc_import_processing.py")
_ioc_persistence = _LazyModuleProxy("ioc_persistence_shared", "ioc_persistence.py")
_ioc_text = _LazyModuleProxy("ioc_text_shared", "ioc_text.py")
_ioc_normalizer = _LazyModuleProxy("ioc_normalizer_shared", "ioc_normalizer.py")
_ioc_contract_adapter = _LazyModuleProxy("ioc_contract_adapter_shared", "ioc_contract_adapter.py")
_ai_router = _LazyModuleProxy("ai_router_shared", "ai/router.py")
_ioc_regex_catalog = _load_local_module("ioc_regex_catalog_shared", "ioc_regex_catalog.py")

logger = logging.getLogger(__name__)

__all__ = [
    "RegexIOCExtractor",
    "extract_derived_indicator_candidates",
    "run_deterministic_ioc_extraction",
    "run_ioc_pipeline_with_provider",
    "extract_iocs_with_ai",
    "process_extraction_for_import",
    "save_extracted_iocs",
    "split_edr_reports",
    "get_report_preview",
]

INVALID_HASH_PLACEHOLDERS = (
    'file is no longer on disk',
    'not available',
    'not present',
    'unknown',
    'n/a',
    'none',
)
INVALID_AI_PLACEHOLDERS = {
    '',
    '...',
    '…',
    'unknown',
    'n/a',
    'none',
    'null',
    'nil',
    'tbd',
}
COMPROMISE_EVIDENCE_HINTS = (
    'credential theft',
    'credentials stolen',
    'compromised account',
    'compromised user',
    'password observed',
    'password reset',
    'password spray',
    'unauthorized login',
    'account takeover',
    'stolen credentials',
)

SEMANTIC_TASK_ALLOWED_FIELDS = {
    'semantic_users_and_accounts': {
        'affected_users': None,
        'authentication_iocs': (
            'compromised_users',
            'created_users',
            'passwords_observed',
        ),
    },
    'semantic_process_relationships': {
        'process_iocs': (
            'commands',
            'services',
            'scheduled_tasks',
        ),
    },
    'semantic_persistence_actions': {
        'persistence_iocs': (
            'registry',
            'credential_theft_indicators',
        ),
        'vulnerability_iocs': (
            'webshells',
        ),
    },
    'semantic_credentials_and_auth': {
        'affected_users': None,
        'authentication_iocs': (
            'compromised_users',
            'created_users',
            'passwords_observed',
        ),
    },
}

SECTION_HEADER_PATTERN = re.compile(r'^[A-Za-z0-9 /()\[\]_-]+:?$')
AI_CHUNK_OVERLAP_CHARS = 400
AI_CONTEXT_CHUNK_CAP_CHARS = 160000
AI_REVIEW_MAX_TOKENS = 3000

# ============================================
# IOC Type Mappings
# ============================================

IOC_TYPE_MAP = _ioc_regex_catalog.IOC_TYPE_MAP
IOC_CATEGORY_MAP = _ioc_regex_catalog.IOC_CATEGORY_MAP


# ============================================
# Regex-based IOC Extraction (Fallback)
# ============================================

RegexIOCExtractor = _ioc_regex_extractor.RegexIOCExtractor


def extract_derived_indicator_candidates(
    ioc_value: str,
    context_values: Optional[List[str]] = None,
) -> List[Dict[str, str]]:
    """Extract related IOC candidates from the canonical IOC boundary."""
    return _ioc_regex_extractor.extract_derived_indicator_candidates(
        ioc_value=ioc_value,
        context_values=context_values,
    )


def run_deterministic_ioc_extraction(report_text: str) -> Dict[str, Any]:
    """Run the canonical deterministic IOC extraction stage."""
    return _deterministic_stage.run_deterministic_stage(
        report_text,
        RegexIOCExtractor,
    )


def _normalize_extracted_file_path(value: Any) -> Tuple[Optional[str], str]:
    """Strip Huntress remediation/status annotations from a captured file path."""
    return _ioc_text._normalize_extracted_file_path(value)


def _is_placeholder_value(value: Any) -> bool:
    """Return True for schema placeholders and model filler values."""
    return _ioc_normalizer._is_placeholder_value(value)


def _is_huntress_portal_value(value: str) -> bool:
    """Return True when the value points at Huntress portal infrastructure."""
    return _ioc_normalizer._is_huntress_portal_value(value)


def _normalize_ai_network_item(item: Any, item_type: str) -> Optional[Dict[str, Any]]:
    """Normalize AI-provided network IOC items into saveable values."""
    return _ioc_normalizer._normalize_ai_network_item(item, item_type)


def _normalize_ai_hash_item(item: Any) -> Optional[Dict[str, Any]]:
    """Drop placeholder hashes and keep only valid hash values."""
    return _ioc_normalizer._normalize_ai_hash_item(item)


def _normalize_ai_file_path_item(item: Any) -> Optional[Dict[str, Any]]:
    """Normalize AI-provided file path items."""
    return _ioc_normalizer._normalize_ai_file_path_item(item)


def _normalize_ai_file_name(value: Any) -> Optional[str]:
    """Collapse path-like file names to basenames."""
    return _ioc_normalizer._normalize_ai_file_name(value)


def _normalize_ai_user_item(item: Any, context: str = '') -> Optional[Dict[str, Any]]:
    """Map AI user objects into the importer's expected value shape."""
    return _ioc_normalizer._normalize_ai_user_item(item, context=context)


def _extract_report_urls(report_text: str) -> List[str]:
    """Extract defanged non-Huntress URLs from the source report."""
    return _ioc_normalizer._extract_report_urls(report_text)


def _reconcile_url_against_report(url_value: str, report_urls: List[str]) -> str:
    """Prefer the exact scheme and path observed in the report text."""
    return _ioc_normalizer._reconcile_url_against_report(url_value, report_urls)


def _report_supports_compromised_users(report_text: str) -> bool:
    """Require explicit compromise language before trusting compromised_users."""
    return _ioc_normalizer._report_supports_compromised_users(report_text)


def _apply_ai_guardrails(normalized: Dict[str, Any], report_text: str) -> Dict[str, Any]:
    """Apply model-family guardrails against the original report text."""
    return _ioc_normalizer._apply_ai_guardrails(normalized, report_text)


def _dedupe_mixed_list(*sequences: List[Any]) -> List[Any]:
    """Deduplicate strings and dict-like values while preserving order."""
    return _ioc_normalizer._dedupe_mixed_list(*sequences)


def _as_list(value: Any) -> List[Any]:
    """Normalize optional schema values into lists."""
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]



def _is_valid_ioc_schema(extraction: Any) -> bool:
    """Return True when the payload matches the expected contract keys."""
    return _ioc_contract_adapter.is_valid_ioc_schema(extraction)



def _list_has_suspicious_repetition(items: List[Any], *, min_repeats: int = 3) -> bool:
    """Return True when the same exact entry repeats enough to suggest degeneration."""
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
    """Collect nested list fields from a JSON-like payload."""
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



def _is_semantically_empty(value: Any) -> bool:
    """Return True when a JSON-like value contains no meaningful data."""
    if value is None:
        return True
    if isinstance(value, str):
        return not value.strip()
    if isinstance(value, (list, tuple, set)):
        return all(_is_semantically_empty(item) for item in value)
    if isinstance(value, dict):
        return all(_is_semantically_empty(item) for item in value.values())
    return False



def _has_repetitive_long_substring(text: str, *, window: int = 80, min_repeats: int = 3) -> bool:
    """Detect long repeated substrings that often indicate model looping."""
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


def _validate_ai_result_metadata(ai_result: Dict[str, Any]) -> Optional[str]:
    """Return a fail-fast error for empty, truncated, or repetitive AI output."""
    return _ioc_contract_adapter.validate_ai_result_metadata(ai_result)


def _prepare_ai_extraction_payload(
    provider: Any,
    payload: Any,
    *,
    max_tokens: int,
    task_name: Optional[str] = None,
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Validate and lightly repair AI JSON before normalization."""
    return _ioc_contract_adapter.prepare_ai_extraction_payload(
        provider,
        payload,
        max_tokens=max_tokens,
        ai_review_max_tokens=AI_REVIEW_MAX_TOKENS,
        task_name=task_name,
        semantic_task_allowed_fields=SEMANTIC_TASK_ALLOWED_FIELDS,
        review_structured_output=_ai_review.review_structured_output,
    )


def _filter_semantic_payload_for_task(task_name: str, payload: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Keep only the schema fields owned by the semantic task."""
    return _ioc_contract_adapter.filter_semantic_payload_for_task(
        task_name,
        payload,
        semantic_task_allowed_fields=SEMANTIC_TASK_ALLOWED_FIELDS,
    )


def _split_large_section_blocks(
    section_name: str,
    section_text: str,
    max_chars: int,
    overlap_chars: int = AI_CHUNK_OVERLAP_CHARS,
) -> List[Dict[str, Any]]:
    """Split oversized sections into paragraph-aware blocks with overlap."""
    return _report_normalizer.split_large_section_blocks(
        section_name,
        section_text,
        max_chars,
        overlap_chars=overlap_chars,
    )



def _chunk_report_for_ai(report_text: str, max_chars: int) -> List[str]:
    """Chunk a report for AI extraction without blunt front-only truncation."""
    return _report_normalizer.chunk_report_for_ai(report_text, max_chars)


def _resolve_ai_chunk_config(batch_config: Dict[str, Any]) -> Dict[str, int]:
    """Estimate safe input chunk sizing from the provider context window."""
    context_window = max(8192, int(batch_config.get('context_window', 16384) or 16384))
    max_response_tokens = min(8000, max(2000, int(batch_config.get('max_tokens', 6000) or 6000)))
    reserved_tokens = min(
        max(max_response_tokens + 2048, 4096),
        max(context_window // 2, 4096),
    )
    available_input_tokens = max(2000, context_window - reserved_tokens)
    chars_per_token = 3 if context_window >= 64000 else 2
    max_chunk_chars = min(
        AI_CONTEXT_CHUNK_CAP_CHARS,
        max(8000, available_input_tokens * chars_per_token),
    )
    return {
        'max_chunk_chars': max_chunk_chars,
        'max_response_tokens': max_response_tokens,
    }



def _merge_summary_dicts(primary: Dict[str, Any], secondary: Dict[str, Any]) -> Dict[str, Any]:
    """Merge extraction summaries from multiple AI chunk passes."""
    return _ioc_merge.merge_extraction_summaries(primary, secondary)


def _merge_ai_extractions(primary: Dict[str, Any], secondary: Dict[str, Any]) -> Dict[str, Any]:
    """Merge multiple normalized AI extractions before regex enrichment."""
    return _ioc_merge.merge_ai_extractions(primary, secondary)


# ============================================
# AI IOC Extraction
# ============================================

def _resolve_ioc_pipeline_mode(explicit_mode: Optional[str] = None) -> str:
    """Resolve the active IOC AI pipeline mode with a safe default."""
    mode = explicit_mode
    if not mode:
        try:
            from config import Config

            mode = getattr(Config, 'AI_IOC_PIPELINE_MODE', 'semantic')
        except Exception:
            mode = 'semantic'

    try:
        from models.system_settings import SettingKeys, SystemSettings

        mode = SystemSettings.get(SettingKeys.AI_IOC_PIPELINE_MODE, mode or 'semantic')
    except Exception:
        pass

    normalized = str(mode or 'semantic').strip().lower()
    return 'audit' if normalized == 'audit' else 'semantic'


def run_ioc_pipeline_with_provider(
    report_text: str,
    provider: Any,
    *,
    pipeline_mode: Optional[str] = None,
    model_name: Optional[str] = None,
    case_id: Optional[int] = None,
) -> Tuple[Dict[str, Any], bool]:
    """Run the configured IOC pipeline using an already resolved provider."""
    deterministic_extraction = run_deterministic_ioc_extraction(report_text)
    prepared_text = _report_normalizer.prepare_ioc_report_text(report_text)
    batch_config = provider.get_batch_config()
    chunk_config = _resolve_ai_chunk_config(batch_config)
    max_chunk_chars = chunk_config['max_chunk_chars']
    max_response_tokens = chunk_config['max_response_tokens']
    resolved_mode = _resolve_ioc_pipeline_mode(pipeline_mode)
    privacy_context = None
    if case_id:
        from utils.privacy_aliases import AIPrivacyContext
        privacy_context = AIPrivacyContext.case_content(case_id)

    if resolved_mode == 'audit':
        audit_stage = _audit_stage.run_audit_stage(
            provider,
            prepared_text,
            deterministic_extraction,
            max_chunk_chars=max_chunk_chars,
            max_response_tokens=max_response_tokens,
            validate_result=_validate_ai_result_metadata,
            privacy_context=privacy_context,
        )
        audited_extraction = _apply_ai_guardrails(
            audit_stage.get('audited_extraction', deterministic_extraction),
            report_text,
        )
        audited_extraction['deterministic_extraction'] = deepcopy(deterministic_extraction)
        audited_extraction['audit_overlay'] = {
            'validated_deltas': deepcopy(audit_stage.get('validated_deltas', [])),
            'reviewed_chunks': audit_stage.get('reviewed_chunks', 0),
            'candidate_count': audit_stage.get('candidate_count', 0),
            'rejected_delta_count': audit_stage.get('rejected_delta_count', 0),
            'task_failures': audit_stage.get('task_failures', []),
            'task_provenance': audit_stage.get('task_provenance', []),
        }
        audited_extraction.setdefault('extraction_summary', {})
        audited_extraction['extraction_summary']['audit_chunk_count'] = audit_stage.get('reviewed_chunks', 0)
        audited_extraction['extraction_summary']['audit_candidate_count'] = audit_stage.get('candidate_count', 0)
        audited_extraction['extraction_summary']['audit_rejected_delta_count'] = audit_stage.get('rejected_delta_count', 0)
        audited_extraction['extraction_summary']['audit_task_failures'] = audit_stage.get('task_failures', [])
        audited_extraction['extraction_summary']['audit_task_provenance'] = audit_stage.get('task_provenance', [])
        audited_extraction['_ioc_records'] = _ioc_merge.merge_record_lists(
            deterministic_extraction.get('_ioc_records', []),
            _ioc_schema.records_from_extraction(
                audited_extraction,
                source='llm_audit',
                trust_tier=_ioc_schema.TRUST_LOW,
            ),
        )
        audited_extraction['extraction_summary']['model'] = model_name or getattr(provider, 'model', '')
        if audited_extraction['extraction_summary'].get('audit_task_failures'):
            audited_extraction['extraction_summary']['method'] = 'deterministic_plus_audit_degraded'
            audited_extraction['extraction_summary']['method_detail'] = (
                'Extraction used deterministic parsing first, then chunk-level audit deltas. '
                'One or more audit chunks failed, so corrections or suppression may be incomplete. '
                'The pre-audit deterministic candidate set is preserved separately.'
            )
            audited_extraction['extraction_summary']['ai_degraded'] = True
        else:
            audited_extraction['extraction_summary']['method'] = 'deterministic_plus_audit'
            audited_extraction['extraction_summary']['method_detail'] = (
                'Extraction used deterministic parsing first, then vendor-agnostic chunk-level '
                'LLM auditing to add, correct, or drop candidates before final assembly. '
                'The pre-audit deterministic candidate set is preserved separately.'
            )
        used_ai = bool(audit_stage.get('reviewed_chunks'))
        return audited_extraction, used_ai

    semantic_stage = _semantic_stage.run_semantic_stage(
        provider,
        prepared_text,
        deterministic_extraction,
        max_chunk_chars=max_chunk_chars,
        max_response_tokens=max_response_tokens,
        validate_result=_validate_ai_result_metadata,
        prepare_payload=_prepare_ai_extraction_payload,
        filter_payload_for_task=_filter_semantic_payload_for_task,
        normalize_extraction=_normalize_ai_extraction,
        privacy_context=privacy_context,
    )
    normalized_chunks = semantic_stage.get('normalized_results', [])
    ai_extraction = deterministic_extraction

    if not semantic_stage.get('planned_tasks'):
        ai_extraction.setdefault('extraction_summary', {})
        ai_extraction['extraction_summary']['semantic_task_count'] = 0
        ai_extraction['extraction_summary']['semantic_task_successes'] = 0
        ai_extraction['extraction_summary']['semantic_task_failures'] = []
        ai_extraction['extraction_summary']['semantic_schema_reviews'] = 0
        ai_extraction['extraction_summary']['semantic_task_provenance'] = []

    if normalized_chunks:
        ai_extraction = _ioc_merge.merge_semantic_results(
            deterministic_extraction,
            normalized_chunks,
            merge_func=_merge_extractions,
            merge_summary_func=_merge_summary_dicts,
        )
        ai_extraction.setdefault('extraction_summary', {})
        ai_extraction['extraction_summary']['semantic_task_count'] = len(semantic_stage.get('planned_tasks', []))
        ai_extraction['extraction_summary']['semantic_task_successes'] = len(normalized_chunks)
        ai_extraction['extraction_summary']['semantic_task_failures'] = semantic_stage.get('task_failures', [])
        ai_extraction['extraction_summary']['semantic_schema_reviews'] = semantic_stage.get('schema_reviews', 0)
        ai_extraction['extraction_summary']['semantic_task_provenance'] = semantic_stage.get('task_provenance', [])
        semantic_records: List[Dict[str, Any]] = []
        for normalized_chunk in normalized_chunks:
            semantic_records = _ioc_merge.merge_record_lists(
                semantic_records,
                _ioc_schema.records_from_extraction(
                    normalized_chunk,
                    source='llm',
                    trust_tier=_ioc_schema.TRUST_LOW,
                ),
            )
        ai_extraction['_ioc_records'] = _ioc_merge.merge_record_lists(
            deterministic_extraction.get('_ioc_records', []),
            semantic_records,
        )

    ai_extraction.setdefault('extraction_summary', {})
    ai_extraction['extraction_summary']['model'] = model_name or getattr(provider, 'model', '')
    if ai_extraction['extraction_summary'].get('semantic_task_failures'):
        ai_extraction['extraction_summary']['method'] = 'deterministic_plus_semantic_degraded'
        ai_extraction['extraction_summary']['method_detail'] = (
            'Extraction used deterministic parsing plus targeted semantic passes, but one or more '
            'semantic tasks failed. Concrete artifact coverage should still be present, but some '
            'semantic IOC relationships may be incomplete.'
        )
        ai_extraction['extraction_summary']['ai_degraded'] = True
    else:
        ai_extraction['extraction_summary']['method'] = 'deterministic_plus_semantic'
        ai_extraction['extraction_summary']['method_detail'] = (
            'Extraction used deterministic parsing first, then targeted semantic analysis '
            'and a residual review pass for contextual IOC coverage.'
        )
    used_ai = bool(ai_extraction['extraction_summary'].get('semantic_task_count'))
    return ai_extraction, used_ai

def extract_iocs_with_ai(report_text: str, model: str = None, case_id: int | None = None) -> Tuple[Dict[str, Any], bool]:
    """
    Extract IOCs from report text using a hybrid AI + regex approach.

    Flow:
      1. AI disabled  -> regex only, advise user
      2. AI enabled but call fails -> regex fallback, advise user
      3. AI enabled and succeeds -> AI first, then regex, then merge; advise user

    Returns:
        Tuple of (extraction_result, used_ai_bool)
    """
    from utils.feature_availability import FeatureAvailability

    deterministic_extraction = _deterministic_stage.run_deterministic_stage(
        report_text,
        RegexIOCExtractor,
    )

    if not FeatureAvailability.is_ai_enabled():
        logger.info("AI extraction disabled, using regex only")
        result = deterministic_extraction
        result['extraction_summary']['method'] = 'regex_only'
        result['extraction_summary']['method_detail'] = (
            'AI is not currently available. Extraction used pattern matching only. '
            'Restore a valid activation and AI availability for richer contextual extraction.'
        )
        return result, False

    # --- AI is enabled, attempt the call ---
    ai_extraction = None
    resolved_model = model or ''
    try:
        provider = _ai_router.resolve_provider(
            model_override=model,
            function='ioc_extraction',
        )
        resolved_model = getattr(provider, 'model', '') or model or ''
        ai_extraction, used_ai = run_ioc_pipeline_with_provider(
            report_text,
            provider,
            model_name=resolved_model,
            case_id=case_id,
        )

    except Exception as e:
        logger.warning(f"AI extraction call failed: {e}")

    # --- AI failed entirely -> regex fallback ---
    if ai_extraction is None:
        logger.info("AI unavailable, falling back to deterministic extraction only")
        result = deterministic_extraction
        result['extraction_summary']['method'] = 'regex_fallback'
        result['extraction_summary']['method_detail'] = (
            'AI extraction failed. Fell back to pattern matching only. '
            'Check AI provider settings and connectivity.'
        )
        return result, False

    return ai_extraction, used_ai


def _merge_extractions(
    ai: Dict[str, Any],
    regex: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Merge AI and regex extraction results.

    Strategy:
      - AI is primary for semantic / contextual fields (extraction_summary,
        mitre_indicators, threat_names, commands with rich context).
      - Regex fills gaps for pattern-matchable IOCs (hashes, IPs, domains,
        URLs, file_paths, SIDs, CVEs, registry_keys, emails).
      - Deduplication by normalised value so nothing is doubled.
      - raw_artifacts are merged additively.
    """
    return _ioc_merge.merge_extractions(ai, regex)


def _extract_dedup_key(item) -> Optional[str]:
    """
    Get a normalised deduplication key from an IOC item.
    Handles dicts (with 'value', 'name', or 'path' keys) and plain strings.
    """
    return _ioc_merge.extract_dedup_key(item)


def _normalize_ai_extraction(extraction: Dict[str, Any], report_text: str = '') -> Dict[str, Any]:
    """
    Normalize AI extraction output to our expected format.
    Handles variations in AI response structure.
    """
    return _ioc_normalizer._normalize_ai_extraction(extraction, report_text)


# ============================================
# Alias Generation for Contextual Matching
# ============================================

def generate_ioc_with_aliases(value: str, ioc_type: str) -> Dict[str, Any]:
    """Generate primary IOC values and aliases for contextual matching."""
    return _ioc_aliasing.generate_ioc_with_aliases(value, ioc_type)


# ============================================
# IOC Processing and Deduplication
# ============================================

def process_extraction_for_import(
    extraction: Dict[str, Any],
    case_id: int,
    username: str,
    provenance_context: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Process extracted IOC payloads into import-ready actions."""
    return _ioc_import_processing.process_extraction_for_import(
        extraction=extraction,
        case_id=case_id,
        username=username,
        provenance_context=provenance_context,
    )


def _create_ioc_entry(
    value: str,
    ioc_type: str,
    category: str,
    context: str,
    case_id: int
) -> Optional[Dict[str, Any]]:
    """Create one IOC import entry with case-scoped duplicate metadata."""
    return _ioc_import_entries.create_ioc_entry(
        value=value,
        ioc_type=ioc_type,
        category=category,
        context=context,
        case_id=case_id,
    )


def _create_ioc_entry_with_type_awareness(
    primary_value: str,
    primary_type: str,
    aliases: List[str],
    original_type: str,
    category: str,
    context: str,
    case_id: int
) -> Optional[Dict[str, Any]]:
    """Create one IOC import entry while preserving file-vs-command semantics."""
    return _ioc_import_entries.create_ioc_entry_with_type_awareness(
        primary_value=primary_value,
        primary_type=primary_type,
        aliases=aliases,
        original_type=original_type,
        category=category,
        context=context,
        case_id=case_id,
    )


def _process_known_system(
    hostname: str,
    case_id: int,
    username: str
) -> Optional[Dict[str, Any]]:
    """Return the case-scoped known-system action implied by one hostname."""
    return _ioc_known_entities.process_known_system(
        hostname=hostname,
        case_id=case_id,
        username=username,
    )


def _process_known_user(
    username_val: str,
    sid: str,
    case_id: int,
    changed_by: str,
    context: str = ''
) -> Optional[Dict[str, Any]]:
    """Return the case-scoped known-user action implied by one user IOC."""
    return _ioc_known_entities.process_known_user(
        username_val=username_val,
        sid=sid,
        case_id=case_id,
        changed_by=changed_by,
        context=context,
    )


# ============================================
# Save Extracted IOCs
# ============================================

def save_extracted_iocs(
    iocs_data: List[Dict[str, Any]],
    case_id: int,
    username: str,
    known_systems: List[Dict[str, Any]] = None,
    known_users: List[Dict[str, Any]] = None
) -> Dict[str, int]:
    """Save extracted IOC payloads and known-entity actions."""
    return _ioc_persistence.save_extracted_iocs(
        iocs_data=iocs_data,
        case_id=case_id,
        username=username,
        known_systems=known_systems,
        known_users=known_users,
    )


# ============================================
# Report Splitting
# ============================================

def split_edr_reports(edr_report_text: str) -> List[str]:
    """
    Split EDR report text by the *** NEW REPORT *** separator
    
    Returns list of individual report texts (trimmed, non-empty)
    """
    return _report_normalizer.split_edr_reports(edr_report_text)


def get_report_preview(report_text: str, max_length: int = 200) -> str:
    """Get a preview of a report for display"""
    return _report_normalizer.get_report_preview(report_text, max_length)
