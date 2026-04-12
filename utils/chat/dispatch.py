"""Shared tool-dispatch primitives for Phase 6."""

from __future__ import annotations

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
        tier: ToolTier = ToolTier.READ_SAFE,
        provenance: Provenance = Provenance.ANALYST,
    ) -> "ToolResultBlock":
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
                "reused_result": True,
                "cache_reference": {
                    "tool_name": tool_name,
                    "first_tool_call_id": first_tool_call_id,
                    "kind": "reused_tool_result",
                },
            },
        )


class ToolDispatcher:
    """Minimal dispatcher shell for the Phase 6 state machine."""

    def __init__(
        self,
        executor: Callable[[str, int, Dict[str, Any]], Dict[str, Any]],
        feature_gate: Optional[Callable[[str, int, Dict[str, Any]], Optional[PermissionResult]]] = None,
    ):
        self._executor = executor
        self._feature_gate = feature_gate
        self._permission_cache: Dict[Tuple[str, int, str], PermissionResult] = {}

    def cache_permission_decision(
        self,
        *,
        tool_name: str,
        case_id: int,
        session_id: Optional[str],
        permission: PermissionResult,
    ) -> None:
        if not session_id or not permission.cacheable:
            return
        self._permission_cache[(tool_name, case_id, session_id)] = permission

    def get_cached_permission(
        self,
        *,
        tool_name: str,
        case_id: int,
        session_id: Optional[str],
    ) -> Optional[PermissionResult]:
        if not session_id:
            return None
        return self._permission_cache.get((tool_name, case_id, session_id))

    def _permission_for_tier(
        self,
        *,
        tool_name: str,
        case_id: int,
        session_id: Optional[str],
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

        cached_permission = self.get_cached_permission(
            tool_name=tool_name,
            case_id=case_id,
            session_id=session_id,
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
                permission=permission,
            )
            return permission

        if not session_id:
            return PermissionResult(
                allowed=True,
                category="allow",
                reason=f"{tier.value} executed without session-scoped permission state",
                cacheable=False,
            )

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
    ) -> ToolResultBlock:
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
            tier=tier,
            analyst_decision=analyst_decision,
            analyst_reason=analyst_reason,
        )
        if not permission.allowed:
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
            return ToolResultBlock(
                tool_name=tool_name,
                status="error",
                tier=tier,
                provenance=provenance,
                permission=permission,
                payload={"error": str(exc)},
            )

        return ToolResultBlock(
            tool_name=tool_name,
            status="completed",
            tier=tier,
            provenance=provenance,
            permission=PermissionResult(
                allowed=True,
                category=permission.category,
                reason=f"{permission.reason} ({provenance.value})",
                cacheable=permission.cacheable,
            ),
            payload=payload if isinstance(payload, dict) else {"result": payload},
        )
