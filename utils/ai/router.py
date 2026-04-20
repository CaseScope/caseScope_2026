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

            self._redis = redis.Redis(
                host="localhost",
                port=6379,
                db=0,
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


def resolve_provider(*, function: str, model_override: Optional[str] = None):
    """Return the configured provider for a function call."""
    from utils.ai_providers import get_llm_provider

    return get_llm_provider(model_override=model_override, function=function)


def get_provider_descriptor(
    *,
    function: str,
    model_override: Optional[str] = None,
) -> Dict[str, str]:
    """Return stable provider metadata without leaking provider lookup to callers."""
    provider = resolve_provider(function=function, model_override=model_override)
    return {
        "provider_type": provider.provider_type(),
        "provider_display": provider.get_provider_display(),
        "model": getattr(provider, "model", "") or "",
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


def invoke_text(
    *,
    function: str,
    prompt: str,
    system: Optional[str] = None,
    temperature: float = 0.7,
    max_tokens: int = 2000,
    model_override: Optional[str] = None,
    provider=None,
) -> Dict[str, Any]:
    """Invoke the configured provider for a plain-text completion."""
    resolved_provider = provider or resolve_provider(
        function=function,
        model_override=model_override,
    )
    started_at = time.time()
    result = resolved_provider.generate(
        prompt=prompt,
        system=system,
        temperature=temperature,
        max_tokens=max_tokens,
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
) -> Dict[str, Any]:
    """Invoke the configured provider for a JSON completion."""
    resolved_provider = provider or resolve_provider(
        function=function,
        model_override=model_override,
    )
    started_at = time.time()
    result = resolved_provider.generate_json(
        prompt=prompt,
        system=system,
        temperature=temperature,
        max_tokens=max_tokens,
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
) -> Generator[Dict[str, Any], None, None]:
    """Stream a chat completion through the shared provider resolver."""
    resolved_provider = provider or resolve_provider(
        function=function,
        model_override=model_override,
    )
    started_at = time.time()
    last_usage = None
    stream_recorded = False

    try:
        for chunk in resolved_provider.stream_chat(
            messages=messages,
            tools=tools,
            temperature=temperature,
            max_tokens=max_tokens,
        ):
            enriched_chunk = dict(chunk or {})
            usage = enriched_chunk.get("usage")
            if isinstance(usage, dict):
                last_usage = usage

            if enriched_chunk.get("error"):
                enriched_chunk["runtime"] = _record_stream_runtime(
                    function=function,
                    provider=resolved_provider,
                    started_at=started_at,
                    success=False,
                    usage=last_usage,
                )
                stream_recorded = True
            elif enriched_chunk.get("done", False):
                enriched_chunk["runtime"] = _record_stream_runtime(
                    function=function,
                    provider=resolved_provider,
                    started_at=started_at,
                    success=True,
                    usage=last_usage,
                )
                stream_recorded = True

            yield enriched_chunk
    except Exception as exc:
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


def get_ai_runtime_metrics() -> Dict[str, Any]:
    """Return aggregate Phase 6 runtime metrics."""
    return _METRICS.snapshot()
