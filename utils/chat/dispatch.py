"""Shared tool-dispatch primitives for Phase 6."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, Optional, Tuple


class ToolTier(str, Enum):
    READ_SAFE = "READ_SAFE"
    READ_SENSITIVE = "READ_SENSITIVE"
    WRITE_REVERSIBLE = "WRITE_REVERSIBLE"
    WRITE_COMMITTING = "WRITE_COMMITTING"


class Provenance(str, Enum):
    ANALYST = "ANALYST"
    SYSTEM_DERIVED = "SYSTEM_DERIVED"
    ARTIFACT_TAINTED = "ARTIFACT_TAINTED"
    ELEVATED_RISK = "ELEVATED_RISK"
    MODEL_SYNTHESIZED = "MODEL_SYNTHESIZED"


@dataclass(frozen=True)
class PermissionResult:
    allowed: bool
    category: str
    reason: str = ""
    cacheable: bool = False


@dataclass(frozen=True)
class ToolResultBlock:
    tool_name: str
    payload: Dict[str, Any]
    status: str = "completed"
    tier: ToolTier = ToolTier.READ_SAFE
    provenance: Provenance = Provenance.ANALYST
    permission: PermissionResult = field(
        default_factory=lambda: PermissionResult(
            allowed=True,
            category="allow",
            reason="auto-allow",
            cacheable=False,
        )
    )

    def to_payload(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "tool_name": self.tool_name,
            "tier": self.tier.value,
            "provenance": self.provenance.value,
            "permission": {
                "allowed": self.permission.allowed,
                "category": self.permission.category,
                "reason": self.permission.reason,
                "cacheable": self.permission.cacheable,
            },
            **self.payload,
        }

    @classmethod
    def interrupt(
        cls,
        *,
        tool_name: str,
        tier: ToolTier = ToolTier.READ_SAFE,
        provenance: Provenance = Provenance.ANALYST,
        permission: PermissionResult,
        payload: Optional[Dict[str, Any]] = None,
    ) -> "ToolResultBlock":
        return cls(
            tool_name=tool_name,
            status="interrupt",
            tier=tier,
            provenance=provenance,
            permission=permission,
            payload=payload or {"error": permission.reason or "analyst approval required"},
        )

    @classmethod
    def reject(
        cls,
        *,
        tool_name: str,
        tier: ToolTier = ToolTier.READ_SAFE,
        provenance: Provenance = Provenance.ANALYST,
        permission: PermissionResult,
        payload: Optional[Dict[str, Any]] = None,
    ) -> "ToolResultBlock":
        return cls(
            tool_name=tool_name,
            status="rejected",
            tier=tier,
            provenance=provenance,
            permission=permission,
            payload=payload or {"error": permission.reason or "tool call rejected"},
        )

    @classmethod
    def reused_result(
        cls,
        *,
        tool_name: str,
        first_tool_call_id: Optional[str],
        result_preview: str = "",
        result_payload: Optional[Dict[str, Any]] = None,
        tier: ToolTier = ToolTier.READ_SAFE,
        provenance: Provenance = Provenance.ANALYST,
    ) -> "ToolResultBlock":
        replay_payload = {}
        if isinstance(result_payload, dict):
            replay_payload = {
                key: value
                for key, value in result_payload.items()
                if key not in {"status", "tool_name", "tier", "provenance", "permission"}
            }
        return cls(
            tool_name=tool_name,
            status="completed",
            tier=tier,
            provenance=provenance,
            permission=PermissionResult(
                allowed=True,
                category="allow",
                reason=f"reused cached result for {tier.value} with {provenance.value}",
                cacheable=tier != ToolTier.WRITE_COMMITTING,
            ),
            payload={
                **replay_payload,
                "reused_result": True,
                "cache_reference": {
                    "tool_name": tool_name,
                    "first_tool_call_id": first_tool_call_id,
                    "kind": "reused_tool_result",
                    "replay": "full_payload",
                    "preview": result_preview[:500] if result_preview else "",
                },
                "result_preview": result_preview[:500] if result_preview else "",
            },
        )


class ToolDispatcher:
    """Minimal dispatcher shell for the Phase 6 state machine."""

    _NON_DATA_PAYLOAD_KEYS = {"error", "message", "status"}

    def __init__(
        self,
        executor: Callable[[str, int, Dict[str, Any]], Dict[str, Any]],
        feature_gate: Optional[Callable[[str, int, Dict[str, Any]], Optional[PermissionResult]]] = None,
    ):
        self._executor = executor
        self._feature_gate = feature_gate
        self._permission_cache: Dict[Tuple[str, int, str, str], PermissionResult] = {}
        self._session_permission_cache: Dict[Tuple[int, str], PermissionResult] = {}

    @staticmethod
    def _requires_emitted_provenance(payload: Dict[str, Any]) -> bool:
        return any(key not in ToolDispatcher._NON_DATA_PAYLOAD_KEYS for key in payload)

    @staticmethod
    def _params_fingerprint(params: Optional[Dict[str, Any]]) -> str:
        """Return a stable cache key fragment for one tool invocation."""
        return json.dumps(params or {}, sort_keys=True, default=str)

    @staticmethod
    def _payload_provenance(
        payload: Any,
        fallback: Provenance,
    ) -> Tuple[Provenance, Dict[str, Any], Optional[str]]:
        """Extract producer-emitted provenance metadata from a payload."""
        if not isinstance(payload, dict):
            return fallback, {"result": payload}, None

        normalized_payload = dict(payload)
        metadata = normalized_payload.pop("_provenance", None)
        if not isinstance(metadata, dict):
            if ToolDispatcher._requires_emitted_provenance(normalized_payload):
                return fallback, normalized_payload, "tool payload missing emitted provenance metadata"
            return fallback, normalized_payload, None

        emitted = metadata.get("emitted_provenance")
        if emitted in Provenance._value2member_map_:
            return Provenance(emitted), normalized_payload, None
        if ToolDispatcher._requires_emitted_provenance(normalized_payload):
            return fallback, normalized_payload, f"tool payload emitted invalid provenance: {emitted!r}"
        return fallback, normalized_payload, None

    def cache_permission_decision(
        self,
        *,
        tool_name: str,
        case_id: int,
        session_id: Optional[str],
        params: Optional[Dict[str, Any]],
        permission: PermissionResult,
    ) -> None:
        if not session_id or not permission.cacheable:
            return
        self._permission_cache[
            (tool_name, case_id, session_id, self._params_fingerprint(params))
        ] = permission

    def get_cached_permission(
        self,
        *,
        tool_name: str,
        case_id: int,
        session_id: Optional[str],
        params: Optional[Dict[str, Any]],
    ) -> Optional[PermissionResult]:
        if not session_id:
            return None
        return self._permission_cache.get(
            (tool_name, case_id, session_id, self._params_fingerprint(params))
        )

    def cache_session_permission_decision(
        self,
        *,
        case_id: int,
        session_id: Optional[str],
        permission: PermissionResult,
    ) -> None:
        if not session_id or not permission.cacheable:
            return
        self._session_permission_cache[(case_id, session_id)] = permission

    def get_cached_session_permission(
        self,
        *,
        case_id: int,
        session_id: Optional[str],
    ) -> Optional[PermissionResult]:
        if not session_id:
            return None
        return self._session_permission_cache.get((case_id, session_id))

    def clear_session_permissions(self, session_id: Optional[str]) -> None:
        """Drop cached permission decisions for a conversation session."""
        if not session_id:
            return
        keys_to_remove = [
            key for key in self._permission_cache
            if key[2] == session_id
        ]
        for key in keys_to_remove:
            self._permission_cache.pop(key, None)
        session_keys_to_remove = [
            key for key in self._session_permission_cache
            if key[1] == session_id
        ]
        for key in session_keys_to_remove:
            self._session_permission_cache.pop(key, None)

    def _permission_for_tier(
        self,
        *,
        tool_name: str,
        case_id: int,
        session_id: Optional[str],
        params: Dict[str, Any],
        tier: ToolTier,
        analyst_decision: Optional[str],
        analyst_reason: str,
    ) -> PermissionResult:
        if tier == ToolTier.READ_SAFE:
            return PermissionResult(
                allowed=True,
                category="allow",
                reason="READ_SAFE auto-allow",
                cacheable=False,
            )

        if not session_id:
            return PermissionResult(
                allowed=False,
                category="interrupt",
                reason=f"{tier.value} requires session-scoped analyst approval",
                cacheable=False,
            )

        session_permission = self.get_cached_session_permission(
            case_id=case_id,
            session_id=session_id,
        )
        if session_permission is not None and tier == ToolTier.READ_SENSITIVE:
            return session_permission

        cached_permission = self.get_cached_permission(
            tool_name=tool_name,
            case_id=case_id,
            session_id=session_id,
            params=params,
        )
        if cached_permission is not None:
            return cached_permission

        normalized_decision = (analyst_decision or "").strip().lower()
        if normalized_decision == "allow":
            permission = PermissionResult(
                allowed=True,
                category="allow",
                reason=analyst_reason or f"{tier.value} approved by analyst",
                cacheable=tier in {ToolTier.READ_SENSITIVE, ToolTier.WRITE_REVERSIBLE},
            )
            self.cache_permission_decision(
                tool_name=tool_name,
                case_id=case_id,
                session_id=session_id,
                params=params,
                permission=permission,
            )
            return permission

        if normalized_decision == "allow_session":
            permission = PermissionResult(
                allowed=True,
                category="session allow",
                reason=analyst_reason or f"{tier.value} approved for this chat session",
                cacheable=tier == ToolTier.READ_SENSITIVE,
            )
            self.cache_session_permission_decision(
                case_id=case_id,
                session_id=session_id,
                permission=permission,
            )
            return permission

        if normalized_decision in {"reject", "do_not_ask_reject"}:
            category = "do-not-ask reject" if normalized_decision == "do_not_ask_reject" else "reject"
            permission = PermissionResult(
                allowed=False,
                category=category,
                reason=analyst_reason or f"{tier.value} denied by analyst",
                cacheable=tier in {ToolTier.READ_SENSITIVE, ToolTier.WRITE_REVERSIBLE},
            )
            self.cache_permission_decision(
                tool_name=tool_name,
                case_id=case_id,
                session_id=session_id,
                params=params,
                permission=permission,
            )
            return permission

        return PermissionResult(
            allowed=False,
            category="interrupt",
            reason=f"{tier.value} requires analyst approval",
            cacheable=tier in {ToolTier.READ_SENSITIVE, ToolTier.WRITE_REVERSIBLE},
        )

    def execute(
        self,
        *,
        tool_name: str,
        case_id: Optional[int],
        params: Dict[str, Any],
        tier: ToolTier = ToolTier.READ_SAFE,
        provenance: Provenance = Provenance.ANALYST,
        session_id: Optional[str] = None,
        analyst_decision: Optional[str] = None,
        analyst_reason: str = "",
        hunt_run_id: Optional[int] = None,
        actor_metadata: Optional[Dict[str, Any]] = None,
        model_metadata: Optional[Dict[str, Any]] = None,
    ) -> ToolResultBlock:
        trace_step = None
        if hunt_run_id and case_id is not None:
            try:
                from utils.hunt_trace import start_step

                actor_metadata = actor_metadata or {}
                model_metadata = model_metadata or {}
                trace_step = start_step(
                    hunt_run_id=int(hunt_run_id),
                    tool_name=tool_name,
                    tool_params=params or {},
                    case_id=int(case_id),
                    created_by_type=actor_metadata.get("created_by_type", "ai"),
                    created_by=actor_metadata.get("created_by", "chat_agent"),
                    model_provider=model_metadata.get("model_provider"),
                    model_name=model_metadata.get("model_name"),
                    prompt_version=model_metadata.get("prompt_version"),
                )
            except Exception:
                trace_step = None

        if case_id is None:
            return ToolResultBlock.reject(
                tool_name=tool_name,
                tier=tier,
                provenance=provenance,
                permission=PermissionResult(
                    allowed=False,
                    category="cross-case denial",
                    reason="case_id is required",
                    cacheable=False,
                ),
                payload={"error": "case_id is required for case-scoped tool calls"},
            )

        if self._feature_gate is not None:
            gated_permission = self._feature_gate(tool_name, case_id, params)
            if gated_permission is not None and not gated_permission.allowed:
                if trace_step is not None:
                    try:
                        from utils.hunt_trace import skip_step

                        skip_step(trace_step, reason=gated_permission.reason or "Feature unavailable")
                    except Exception:
                        pass
                return ToolResultBlock.reject(
                    tool_name=tool_name,
                    tier=tier,
                    provenance=provenance,
                    permission=gated_permission,
                    payload={"error": gated_permission.reason or "Feature unavailable"},
                )

        permission = self._permission_for_tier(
            tool_name=tool_name,
            case_id=case_id,
            session_id=session_id,
            params=params,
            tier=tier,
            analyst_decision=analyst_decision,
            analyst_reason=analyst_reason,
        )
        if not permission.allowed:
            if trace_step is not None:
                try:
                    from utils.hunt_trace import skip_step

                    skip_step(trace_step, reason=permission.reason or "tool call not allowed")
                except Exception:
                    pass
            if permission.category == "interrupt":
                return ToolResultBlock.interrupt(
                    tool_name=tool_name,
                    tier=tier,
                    provenance=provenance,
                    permission=permission,
                )
            return ToolResultBlock.reject(
                tool_name=tool_name,
                tier=tier,
                provenance=provenance,
                permission=permission,
            )

        try:
            payload = self._executor(tool_name, case_id, params)
        except Exception as exc:  # noqa: BLE001
            if trace_step is not None:
                try:
                    from utils.hunt_trace import fail_step

                    fail_step(trace_step, error_message=str(exc))
                except Exception:
                    pass
            return ToolResultBlock(
                tool_name=tool_name,
                status="error",
                tier=tier,
                provenance=provenance,
                permission=permission,
                payload={"error": str(exc)},
            )

        effective_provenance, normalized_payload, provenance_error = self._payload_provenance(
            payload,
            provenance,
        )
        if provenance_error:
            if trace_step is not None:
                try:
                    from utils.hunt_trace import fail_step

                    fail_step(
                        trace_step,
                        error_message=provenance_error,
                        result_payload=normalized_payload,
                    )
                except Exception:
                    pass
            return ToolResultBlock.reject(
                tool_name=tool_name,
                tier=tier,
                provenance=provenance,
                permission=PermissionResult(
                    allowed=False,
                    category="invalid provenance",
                    reason=provenance_error,
                    cacheable=False,
                ),
                payload={"error": provenance_error},
            )
        if trace_step is not None:
            try:
                from utils.hunt_trace import complete_step

                complete_step(trace_step, result_payload=normalized_payload)
            except Exception:
                pass
        return ToolResultBlock(
            tool_name=tool_name,
            status="completed",
            tier=tier,
            provenance=effective_provenance,
            permission=PermissionResult(
                allowed=True,
                category=permission.category,
                reason=f"{permission.reason} ({effective_provenance.value})",
                cacheable=permission.cacheable,
            ),
            payload=normalized_payload,
        )
