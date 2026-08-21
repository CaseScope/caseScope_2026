"""Shared AI invocation router and runtime metrics."""

from __future__ import annotations

import json
import threading
import time
from typing import Any, Dict, Generator, Optional


def _normalize_usage(usage: Optional[Dict[str, Any]]) -> Dict[str, int]:
    usage = usage if isinstance(usage, dict) else {}
    prompt_details = usage.get("prompt_tokens_details") or {}

    input_tokens = int(
        usage.get("input_tokens")
        or usage.get("prompt_tokens")
        or 0
    )
    output_tokens = int(
        usage.get("output_tokens")
        or usage.get("completion_tokens")
        or 0
    )
    total_tokens = int(
        usage.get("total_tokens")
        or (input_tokens + output_tokens)
    )
    cache_creation_input_tokens = int(
        usage.get("cache_creation_input_tokens")
        or 0
    )
    cache_read_input_tokens = int(
        usage.get("cache_read_input_tokens")
        or prompt_details.get("cached_tokens")
        or 0
    )
    stable_prefix_cache_eligible = 1 if (
        cache_creation_input_tokens > 0 or cache_read_input_tokens > 0
    ) else 0
    stable_prefix_cache_hits = 1 if cache_read_input_tokens > 0 else 0

    return {
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "total_tokens": total_tokens,
        "cache_creation_input_tokens": cache_creation_input_tokens,
        "cache_read_input_tokens": cache_read_input_tokens,
        "stable_prefix_cache_eligible": stable_prefix_cache_eligible,
        "stable_prefix_cache_hits": stable_prefix_cache_hits,
    }


class _AIRuntimeMetricsStore:
    """Process-safe enough runtime aggregate with optional Redis backing."""

    REDIS_KEY = "casescope:ai_runtime_metrics"
    REDIS_TTL = 86400

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._redis = None
        self._redis_checked = False

    def _get_redis(self):
        if self._redis_checked:
            return self._redis
        self._redis_checked = True
        try:
            import redis
            from config import Config

            self._redis = redis.Redis(
                host=Config.REDIS_HOST,
                port=Config.REDIS_PORT,
                db=Config.REDIS_DB,
                decode_responses=True,
                socket_timeout=1,
            )
            self._redis.ping()
        except Exception:
            self._redis = None
        return self._redis

    def _load(self) -> Dict[str, Any]:
        redis_client = self._get_redis()
        if redis_client:
            try:
                raw = redis_client.get(self.REDIS_KEY)
                if raw:
                    return json.loads(raw)
            except Exception:
                pass
        return {
            "totals": {},
            "by_function": {},
            "last_updated": None,
        }

    def _save(self, data: Dict[str, Any]) -> None:
        redis_client = self._get_redis()
        if redis_client:
            try:
                redis_client.setex(self.REDIS_KEY, self.REDIS_TTL, json.dumps(data))
            except Exception:
                pass

    @staticmethod
    def _blank_bucket() -> Dict[str, Any]:
        return {
            "calls": 0,
            "successes": 0,
            "failures": 0,
            "duration_ms": 0,
            "input_tokens": 0,
            "output_tokens": 0,
            "total_tokens": 0,
            "cache_creation_input_tokens": 0,
            "cache_read_input_tokens": 0,
            "stable_prefix_cache_eligible": 0,
            "stable_prefix_cache_hits": 0,
        }

    def record(
        self,
        *,
        function: str,
        mode: str,
        provider_type: str,
        model: str,
        success: bool,
        duration_ms: int,
        usage: Optional[Dict[str, Any]],
    ) -> Dict[str, Any]:
        normalized_usage = _normalize_usage(usage)
        record = {
            "function": function,
            "mode": mode,
            "provider_type": provider_type,
            "model": model,
            "success": success,
            "duration_ms": duration_ms,
            **normalized_usage,
        }

        with self._lock:
            state = self._load()
            totals = state.get("totals") or self._blank_bucket()
            state["totals"] = totals
            by_function = state.setdefault("by_function", {})
            function_bucket = by_function.get(function) or self._blank_bucket()
            by_function[function] = function_bucket

            for bucket in (totals, function_bucket):
                bucket["calls"] += 1
                bucket["duration_ms"] += duration_ms
                bucket["input_tokens"] += normalized_usage["input_tokens"]
                bucket["output_tokens"] += normalized_usage["output_tokens"]
                bucket["total_tokens"] += normalized_usage["total_tokens"]
                bucket["cache_creation_input_tokens"] += normalized_usage["cache_creation_input_tokens"]
                bucket["cache_read_input_tokens"] += normalized_usage["cache_read_input_tokens"]
                bucket["stable_prefix_cache_eligible"] += normalized_usage["stable_prefix_cache_eligible"]
                bucket["stable_prefix_cache_hits"] += normalized_usage["stable_prefix_cache_hits"]
                if success:
                    bucket["successes"] += 1
                else:
                    bucket["failures"] += 1

            state["last_updated"] = int(time.time())
            self._save(state)

        return record

    def snapshot(self) -> Dict[str, Any]:
        with self._lock:
            state = self._load()
        for bucket in [state.get("totals", {})] + list((state.get("by_function") or {}).values()):
            eligible = int(bucket.get("stable_prefix_cache_eligible") or 0)
            hits = int(bucket.get("stable_prefix_cache_hits") or 0)
            bucket["cache_hit_rate"] = round((hits / eligible), 4) if eligible else None
        return state


_METRICS = _AIRuntimeMetricsStore()
_NO_THINK_DIRECTIVE = "/no_think"


def _is_gemma_model(model_name: str) -> bool:
    """Return True for Gemma-family model names."""
    return "gemma" in str(model_name or "").strip().lower()


def _prepend_no_think_directive(content: Optional[str]) -> Optional[str]:
    """Place the Gemma no-thinking directive at the top of a prompt."""
    if content is None:
        return None
    text = str(content)
    if text.startswith(_NO_THINK_DIRECTIVE):
        return text
    stripped = text.lstrip()
    if stripped.startswith(_NO_THINK_DIRECTIVE):
        return stripped
    return f"{_NO_THINK_DIRECTIVE}\n{text}"


def _apply_ioc_gemma_prompt_directives(
    *,
    function: str,
    provider,
    prompt: str,
    system: Optional[str],
) -> tuple[str, Optional[str]]:
    """Add Gemma prompt controls only for IOC extraction calls."""
    if function != "ioc_extraction" or not _is_gemma_model(getattr(provider, "model", "")):
        return prompt, system
    return (
        _prepend_no_think_directive(prompt) or "",
        _prepend_no_think_directive(system),
    )


def _mark_resolved_provider(provider, *, function: str):
    try:
        setattr(provider, '_casescope_resolved_function', function)
        setattr(provider, '_casescope_resolved_at', time.time())
    except Exception:
        pass
    return provider


def resolve_provider(*, function: str, model_override: Optional[str] = None):
    """Return the configured provider for a function call."""
    from utils.ai_providers import get_llm_provider

    return _mark_resolved_provider(
        get_llm_provider(model_override=model_override, function=function),
        function=function,
    )


def get_provider_descriptor(
    *,
    function: str,
    model_override: Optional[str] = None,
) -> Dict[str, Any]:
    """Return stable provider metadata without leaking provider lookup to callers."""
    provider = resolve_provider(function=function, model_override=model_override)
    is_local = provider.provider_type() == "local"
    if not is_local and hasattr(provider, "_is_local_endpoint"):
        try:
            is_local = bool(provider._is_local_endpoint())
        except Exception:
            is_local = False
    return {
        "provider_type": provider.provider_type(),
        "provider_display": provider.get_provider_display(),
        "model": getattr(provider, "model", "") or "",
        "is_local": is_local,
    }


def _attach_runtime_metadata(
    result: Dict[str, Any],
    *,
    function: str,
    mode: str,
    provider,
    started_at: float,
) -> Dict[str, Any]:
    elapsed_ms = int((time.time() - started_at) * 1000)
    enriched = dict(result or {})
    provider_type = provider.provider_type()
    model_name = getattr(provider, "model", "") or enriched.get("model", "")
    usage = enriched.get("usage")
    runtime_metrics = _METRICS.record(
        function=function,
        mode=mode,
        provider_type=provider_type,
        model=model_name,
        success=bool(enriched.get("success")),
        duration_ms=elapsed_ms,
        usage=usage,
    )
    enriched.setdefault("model", model_name)
    enriched["runtime"] = {
        "function": function,
        "mode": mode,
        "provider_type": provider_type,
        "provider_display": provider.get_provider_display(),
        "duration_ms": elapsed_ms,
        "metrics": runtime_metrics,
    }
    return enriched


def _record_stream_runtime(
    *,
    function: str,
    provider,
    started_at: float,
    success: bool,
    usage: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    elapsed_ms = int((time.time() - started_at) * 1000)
    provider_type = provider.provider_type()
    model_name = getattr(provider, "model", "") or ""
    runtime_metrics = _METRICS.record(
        function=function,
        mode="stream_chat",
        provider_type=provider_type,
        model=model_name,
        success=success,
        duration_ms=elapsed_ms,
        usage=usage,
    )
    return {
        "function": function,
        "mode": "stream_chat",
        "provider_type": provider_type,
        "provider_display": provider.get_provider_display(),
        "duration_ms": elapsed_ms,
        "metrics": runtime_metrics,
    }



def _raw_text_payload(*, prompt, system) -> dict[str, Any]:
    return {"prompt": prompt, "system": system}


def _raw_chat_payload(*, messages, tools) -> dict[str, Any]:
    return {"messages": messages, "tools": tools}


REASON_E2_ENFORCEMENT_UNAVAILABLE = "e2_enforcement_unavailable"
REASON_PREFLIGHT_INFRASTRUCTURE_FAILURE = "preflight_infrastructure_failure"
_EXPLICIT_NON_CASE_SCOPES = frozenset({"non_content_admin", "test_only"})


class StrictE2PreflightUnavailable(RuntimeError):
    """Strict E2 is on but enforcement cannot run for remote/uncertain case content."""

    def __init__(self, reason: str, *, detail: str = ""):
        self.reason = str(reason)
        self.detail = str(detail or "")
        message = f"AI privacy preflight blocked remote egress: {self.reason}"
        if self.detail:
            message = f"{message} ({self.detail})"
        super().__init__(message)


def _strict_e2_enabled_from_config() -> bool:
    """Read the E2 flag at the router boundary without importing enforcement."""
    from config import Config
    return bool(getattr(Config, "PHASE1B_AI_PRIVACY_FREEZE_VERIFY_ENABLED", False))


def _explicit_non_case_scope(privacy_context) -> bool:
    if privacy_context is None:
        return False
    return getattr(privacy_context, "content_scope", None) in _EXPLICIT_NON_CASE_SCOPES


def _import_failure_metadata(*, provider, privacy_context, reason: str) -> dict[str, Any]:
    locality = "local" if _is_local_provider_fallback(provider) else "uncertain"
    return {
        "strict_e2_enabled": True,
        "provider_locality": locality,
        "verification_passed": False,
        "failure_reason": reason,
        "provider_invoked": False,
        "content_scope": None if privacy_context is None else getattr(privacy_context, "content_scope", None),
    }


def _strict_e2_preflight(*, function: str, mode: str, provider, privacy_context, raw_payload):
    """Fail closed for remote case-content before any provider method is called.

    Strict-off preserves pre-E2 behavior. Strict-on must not depend on a
    successful ``utils.ai_privacy_freeze`` import to decide that the gate is
    required. Import or infrastructure failure is fail-open only for a
    provably local provider or an explicit non-case admin/test scope.
    """
    if not _strict_e2_enabled_from_config():
        return None, {}

    try:
        from utils.ai_privacy_freeze import (
            AIPrivacyPreflightError,
            get_preflight_session,
            privacy_audit_metadata,
            require_remote_case_content_preflight,
        )
    except Exception as exc:
        if _is_local_provider_fallback(provider) or _explicit_non_case_scope(privacy_context):
            return None, _import_failure_metadata(
                provider=provider,
                privacy_context=privacy_context,
                reason=REASON_E2_ENFORCEMENT_UNAVAILABLE,
            )
        raise StrictE2PreflightUnavailable(
            REASON_E2_ENFORCEMENT_UNAVAILABLE,
            detail="enforcement_module_import_failed",
        ) from exc

    try:
        session = get_preflight_session()
        proof = require_remote_case_content_preflight(
            session=session,
            provider=provider,
            privacy_context=privacy_context,
            raw_payload=raw_payload,
            function=function,
            mode=mode,
        )
        metadata = privacy_audit_metadata(
            privacy_context=privacy_context,
            provider=provider,
            strict_enabled=True,
            verification_passed=True,
            provider_invoked=False,
        )
        return proof, metadata
    except Exception as exc:
        reason = getattr(exc, "reason", None) or REASON_PREFLIGHT_INFRASTRUCTURE_FAILURE
        try:
            metadata = privacy_audit_metadata(
                privacy_context=privacy_context,
                provider=provider,
                strict_enabled=True,
                verification_passed=False,
                failure_reason=reason,
                provider_invoked=False,
            )
        except Exception:
            metadata = {
                "strict_e2_enabled": True,
                "verification_passed": False,
                "failure_reason": reason,
                "provider_invoked": False,
            }
        try:
            _record_ai_audit(
                function=function,
                mode=mode,
                provider=provider,
                request_payload={"preflight": "blocked"},
                status="privacy_preflight_failed",
                response_complete=False,
                privacy_context=privacy_context,
                privacy=metadata,
                error=exc,
            )
        except Exception:
            pass
        if isinstance(exc, AIPrivacyPreflightError):
            raise
        raise AIPrivacyPreflightError(reason) from exc


def _finalize_e2_privacy_metadata(metadata: dict[str, Any], *sanitizer_items, outbound_payload=None):
    merged = dict(metadata or {})
    aliases_applied = 0
    enabled = False
    for item in sanitizer_items:
        if not isinstance(item, dict):
            continue
        aliases_applied += int(item.get("aliases_applied") or 0)
        enabled = enabled or bool(item.get("enabled"))
        if item.get("error"):
            merged["sanitizer_error"] = item.get("error")
    merged["aliased"] = bool(enabled or aliases_applied)
    merged["aliases_applied"] = aliases_applied
    if outbound_payload is not None:
        try:
            from utils.ai_privacy_freeze import canonical_fingerprint
            merged["final_outbound_payload_fingerprint"] = canonical_fingerprint(outbound_payload)
        except Exception:
            pass
    merged["provider_invoked"] = True
    return merged


def _sanitize_for_provider(value, *, privacy_context, provider):
    try:
        from utils.privacy_aliases import sanitize_for_ai_egress
    except Exception as exc:
        # Returning the raw value here would send unaliased case content to the
        # provider. Only a local provider, which never leaves the host, may
        # continue without the sanitizer.
        if _is_local_provider_fallback(provider):
            return _strip_presanitized_fallback(value), {
                'enabled': False,
                'error': 'privacy sanitizer unavailable',
            }
        raise RuntimeError(
            'Cloud AI egress blocked: privacy sanitizer unavailable'
        ) from exc
    sanitized = sanitize_for_ai_egress(value, context=privacy_context, provider=provider)
    return sanitized.value, sanitized.metadata


def _strip_presanitized_fallback(value):
    """Drop the pre-sanitized marker when the privacy module could not load.

    The sanitizer normally owns this, so the key is only ever seen by a
    provider if that import failed. Providers reject unknown message keys.
    """
    if isinstance(value, dict):
        return {key: _strip_presanitized_fallback(item)
                for key, item in value.items()
                if key != '_privacy_presanitized'}
    if isinstance(value, list):
        return [_strip_presanitized_fallback(item) for item in value]
    return value


def _is_local_provider_fallback(provider) -> bool:
    """Classify a provider as local without depending on the privacy module.

    Only reached when utils.privacy_aliases itself failed to import, so this
    cannot call is_local_provider. An openai_compatible endpoint is treated as
    remote here because confirming it is local requires that module.
    """
    provider_type = provider.provider_type() if hasattr(provider, 'provider_type') else None
    return str(provider_type or '').strip().lower() == 'local'


def _merge_privacy_metadata(result: Dict[str, Any], *metadata_items: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    metadata = {
        'enabled': False,
        'aliases_applied': 0,
        'entity_categories': [],
        'duration_ms': 0,
    }
    categories = set()
    for item in metadata_items:
        if not isinstance(item, dict):
            continue
        metadata['enabled'] = metadata['enabled'] or bool(item.get('enabled'))
        metadata['privacy_level'] = item.get('privacy_level', metadata.get('privacy_level'))
        metadata['case_id'] = item.get('case_id', metadata.get('case_id'))
        metadata['content_scope'] = item.get('content_scope', metadata.get('content_scope'))
        metadata['aliases_applied'] += int(item.get('aliases_applied') or 0)
        metadata['duration_ms'] += int(item.get('duration_ms') or 0)
        categories.update(item.get('entity_categories') or [])
        if item.get('error'):
            metadata['error'] = item.get('error')
        for key, value in item.items():
            if key in {
                'enabled',
                'privacy_level',
                'case_id',
                'content_scope',
                'aliases_applied',
                'duration_ms',
                'entity_categories',
                'error',
            }:
                continue
            metadata[key] = value
    metadata['entity_categories'] = sorted(categories)
    enriched = dict(result or {})
    enriched['privacy'] = metadata
    return enriched


def _audit_request_payload(**kwargs) -> Dict[str, Any]:
    return {key: value for key, value in kwargs.items() if value is not None}


def _record_ai_audit(
    *,
    function: str,
    mode: str,
    provider,
    request_payload: Any,
    response_payload: Any = None,
    status: str,
    response_complete: bool,
    privacy_context=None,
    privacy: Optional[Dict[str, Any]] = None,
    usage: Optional[Dict[str, Any]] = None,
    duration_ms: Optional[int] = None,
    error: Optional[BaseException] = None,
) -> None:
    try:
        from flask import has_app_context
    except Exception:
        return
    if not has_app_context():
        return
    from utils.ai_audit import record_ai_call

    record_ai_call(
        function=function,
        mode=mode,
        provider=provider,
        request_payload=request_payload,
        response_payload=response_payload,
        status=status,
        response_complete=response_complete,
        privacy_context=privacy_context,
        privacy=privacy,
        usage=usage,
        duration_ms=duration_ms,
        error=error,
    )


def _result_audit_status(result: Dict[str, Any]) -> tuple[str, bool]:
    try:
        from models.ai_audit_log import AIAuditStatus
    except Exception:
        class AIAuditStatus:
            SUCCESS = "success"
            PROVIDER_ERROR = "provider_error"

    success = bool((result or {}).get("success"))
    return (
        AIAuditStatus.SUCCESS if success else AIAuditStatus.PROVIDER_ERROR,
        success,
    )


def _stream_chunk_text(chunk: Dict[str, Any]) -> str:
    if not isinstance(chunk, dict):
        return ""
    message = chunk.get("message")
    if isinstance(message, dict) and isinstance(message.get("content"), str):
        return message.get("content") or ""
    delta = chunk.get("delta")
    if isinstance(delta, dict) and isinstance(delta.get("content"), str):
        return delta.get("content") or ""
    content = chunk.get("content")
    return content if isinstance(content, str) else ""

def invoke_text(
    *,
    function: str,
    prompt: str,
    system: Optional[str] = None,
    temperature: float = 0.7,
    max_tokens: int = 2000,
    model_override: Optional[str] = None,
    provider=None,
    privacy_context=None,
) -> Dict[str, Any]:
    """Invoke the configured provider for a plain-text completion."""
    resolved_provider = provider or resolve_provider(
        function=function,
        model_override=model_override,
    )
    if provider is not None:
        _mark_resolved_provider(resolved_provider, function=getattr(resolved_provider, '_casescope_resolved_function', function))
    raw_payload = _raw_text_payload(prompt=prompt, system=system)
    _e2_proof, e2_privacy = _strict_e2_preflight(
        function=function,
        mode="text",
        provider=resolved_provider,
        privacy_context=privacy_context,
        raw_payload=raw_payload,
    )
    prompt, prompt_privacy = _sanitize_for_provider(prompt, privacy_context=privacy_context, provider=resolved_provider)
    system, system_privacy = _sanitize_for_provider(system, privacy_context=privacy_context, provider=resolved_provider)
    request_payload = _audit_request_payload(
        prompt=prompt,
        system=system,
        temperature=temperature,
        max_tokens=max_tokens,
    )
    started_at = time.time()
    try:
        result = resolved_provider.generate(
            prompt=prompt,
            system=system,
            temperature=temperature,
            max_tokens=max_tokens,
        )
    except Exception as exc:
        _record_ai_audit(
            function=function,
            mode="text",
            provider=resolved_provider,
            request_payload=request_payload,
            status="provider_error",
            response_complete=False,
            privacy_context=privacy_context,
            privacy=_merge_privacy_metadata({}, prompt_privacy, system_privacy).get("privacy"),
            duration_ms=int((time.time() - started_at) * 1000),
            error=exc,
        )
        raise
    raw_result = dict(result or {})
    result = _merge_privacy_metadata(
        result,
        prompt_privacy,
        system_privacy,
        _finalize_e2_privacy_metadata(
            e2_privacy,
            prompt_privacy,
            system_privacy,
            outbound_payload={"prompt": prompt, "system": system},
        ),
    )
    audit_status, response_complete = _result_audit_status(result)
    _record_ai_audit(
        function=function,
        mode="text",
        provider=resolved_provider,
        request_payload=request_payload,
        response_payload=raw_result,
        status=audit_status,
        response_complete=response_complete,
        privacy_context=privacy_context,
        privacy=result.get("privacy"),
        usage=result.get("usage"),
        duration_ms=int((time.time() - started_at) * 1000),
    )
    return _attach_runtime_metadata(
        result,
        function=function,
        mode="text",
        provider=resolved_provider,
        started_at=started_at,
    )


def invoke_json(
    *,
    function: str,
    prompt: str,
    system: Optional[str] = None,
    temperature: float = 0.3,
    max_tokens: Optional[int] = None,
    model_override: Optional[str] = None,
    provider=None,
    privacy_context=None,
) -> Dict[str, Any]:
    """Invoke the configured provider for a JSON completion."""
    resolved_provider = provider or resolve_provider(
        function=function,
        model_override=model_override,
    )
    if provider is not None:
        _mark_resolved_provider(resolved_provider, function=getattr(resolved_provider, '_casescope_resolved_function', function))
    raw_payload = _raw_text_payload(prompt=prompt, system=system)
    _e2_proof, e2_privacy = _strict_e2_preflight(
        function=function,
        mode="json",
        provider=resolved_provider,
        privacy_context=privacy_context,
        raw_payload=raw_payload,
    )
    prompt, prompt_privacy = _sanitize_for_provider(prompt, privacy_context=privacy_context, provider=resolved_provider)
    system, system_privacy = _sanitize_for_provider(system, privacy_context=privacy_context, provider=resolved_provider)
    prompt, system = _apply_ioc_gemma_prompt_directives(
        function=function,
        provider=resolved_provider,
        prompt=prompt,
        system=system,
    )
    request_payload = _audit_request_payload(
        prompt=prompt,
        system=system,
        temperature=temperature,
        max_tokens=max_tokens,
    )
    started_at = time.time()
    try:
        result = resolved_provider.generate_json(
            prompt=prompt,
            system=system,
            temperature=temperature,
            max_tokens=max_tokens,
        )
    except Exception as exc:
        _record_ai_audit(
            function=function,
            mode="json",
            provider=resolved_provider,
            request_payload=request_payload,
            status="provider_error",
            response_complete=False,
            privacy_context=privacy_context,
            privacy=_merge_privacy_metadata({}, prompt_privacy, system_privacy).get("privacy"),
            duration_ms=int((time.time() - started_at) * 1000),
            error=exc,
        )
        raise
    raw_result = dict(result or {})
    result = _merge_privacy_metadata(
        result,
        prompt_privacy,
        system_privacy,
        _finalize_e2_privacy_metadata(
            e2_privacy,
            prompt_privacy,
            system_privacy,
            outbound_payload={"prompt": prompt, "system": system},
        ),
    )
    audit_status, response_complete = _result_audit_status(result)
    _record_ai_audit(
        function=function,
        mode="json",
        provider=resolved_provider,
        request_payload=request_payload,
        response_payload=raw_result,
        status=audit_status,
        response_complete=response_complete,
        privacy_context=privacy_context,
        privacy=result.get("privacy"),
        usage=result.get("usage"),
        duration_ms=int((time.time() - started_at) * 1000),
    )
    return _attach_runtime_metadata(
        result,
        function=function,
        mode="json",
        provider=resolved_provider,
        started_at=started_at,
    )


def stream_chat(
    *,
    function: str,
    messages: list[dict[str, Any]],
    tools: Optional[list[dict[str, Any]]] = None,
    temperature: float = 0.3,
    max_tokens: int = 4096,
    model_override: Optional[str] = None,
    provider=None,
    privacy_context=None,
) -> Generator[Dict[str, Any], None, None]:
    """Stream a chat completion through the shared provider resolver."""
    resolved_provider = provider or resolve_provider(
        function=function,
        model_override=model_override,
    )
    if provider is not None:
        _mark_resolved_provider(resolved_provider, function=getattr(resolved_provider, '_casescope_resolved_function', function))
    raw_payload = _raw_chat_payload(messages=messages, tools=tools)
    _e2_proof, e2_privacy = _strict_e2_preflight(
        function=function,
        mode="stream_chat",
        provider=resolved_provider,
        privacy_context=privacy_context,
        raw_payload=raw_payload,
    )
    messages, messages_privacy = _sanitize_for_provider(messages, privacy_context=privacy_context, provider=resolved_provider)
    tools, tools_privacy = _sanitize_for_provider(tools, privacy_context=privacy_context, provider=resolved_provider)
    messages_privacy = _finalize_e2_privacy_metadata(
        e2_privacy,
        messages_privacy,
        tools_privacy,
        outbound_payload={"messages": messages, "tools": tools},
    )
    request_payload = _audit_request_payload(
        messages=messages,
        tools=tools,
        temperature=temperature,
        max_tokens=max_tokens,
    )
    started_at = time.time()
    last_usage = None
    stream_recorded = False
    audit_recorded = False
    response_parts: list[str] = []

    try:
        for chunk in resolved_provider.stream_chat(
            messages=messages,
            tools=tools,
            temperature=temperature,
            max_tokens=max_tokens,
        ):
            enriched_chunk = dict(chunk or {})
            response_parts.append(_stream_chunk_text(enriched_chunk))
            usage = enriched_chunk.get("usage")
            if isinstance(usage, dict):
                last_usage = usage

            if enriched_chunk.get("done", False):
                enriched_chunk["privacy"] = messages_privacy

            if enriched_chunk.get("error"):
                enriched_chunk["runtime"] = _record_stream_runtime(
                    function=function,
                    provider=resolved_provider,
                    started_at=started_at,
                    success=False,
                    usage=last_usage,
                )
                _record_ai_audit(
                    function=function,
                    mode="stream_chat",
                    provider=resolved_provider,
                    request_payload=request_payload,
                    response_payload="".join(response_parts),
                    status="provider_error",
                    response_complete=False,
                    privacy_context=privacy_context,
                    privacy=messages_privacy,
                    usage=last_usage,
                    duration_ms=int((time.time() - started_at) * 1000),
                    error=RuntimeError(str(enriched_chunk.get("error"))),
                )
                audit_recorded = True
                stream_recorded = True
            elif enriched_chunk.get("done", False):
                enriched_chunk["runtime"] = _record_stream_runtime(
                    function=function,
                    provider=resolved_provider,
                    started_at=started_at,
                    success=True,
                    usage=last_usage,
                )
                _record_ai_audit(
                    function=function,
                    mode="stream_chat",
                    provider=resolved_provider,
                    request_payload=request_payload,
                    response_payload="".join(response_parts),
                    status="success",
                    response_complete=True,
                    privacy_context=privacy_context,
                    privacy=messages_privacy,
                    usage=last_usage,
                    duration_ms=int((time.time() - started_at) * 1000),
                )
                audit_recorded = True
                stream_recorded = True

            yield enriched_chunk
    except GeneratorExit as exc:
        _record_ai_audit(
            function=function,
            mode="stream_chat",
            provider=resolved_provider,
            request_payload=request_payload,
            response_payload="".join(response_parts),
            status="client_disconnected",
            response_complete=False,
            privacy_context=privacy_context,
            privacy=messages_privacy,
            usage=last_usage,
            duration_ms=int((time.time() - started_at) * 1000),
            error=exc,
        )
        audit_recorded = True
        raise
    except Exception as exc:
        _record_ai_audit(
            function=function,
            mode="stream_chat",
            provider=resolved_provider,
            request_payload=request_payload,
            response_payload="".join(response_parts),
            status="provider_error",
            response_complete=False,
            privacy_context=privacy_context,
            privacy=messages_privacy,
            usage=last_usage,
            duration_ms=int((time.time() - started_at) * 1000),
            error=exc,
        )
        audit_recorded = True
        yield {
            "error": str(exc),
            "runtime": _record_stream_runtime(
                function=function,
                provider=resolved_provider,
                started_at=started_at,
                success=False,
                usage=last_usage,
            ),
        }
        stream_recorded = True

    if not stream_recorded:
        _record_stream_runtime(
            function=function,
            provider=resolved_provider,
            started_at=started_at,
            success=True,
            usage=last_usage,
        )
        if not audit_recorded:
            _record_ai_audit(
                function=function,
                mode="stream_chat",
                provider=resolved_provider,
                request_payload=request_payload,
                response_payload="".join(response_parts),
                status="stream_interrupted",
                response_complete=False,
                privacy_context=privacy_context,
                privacy=messages_privacy,
                usage=last_usage,
                duration_ms=int((time.time() - started_at) * 1000),
            )


def get_ai_runtime_metrics() -> Dict[str, Any]:
    """Return aggregate Phase 6 runtime metrics."""
    return _METRICS.snapshot()
