"""Shared tool-dispatch primitives for Phase 6."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, Optional


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
            "permission": {
                "allowed": self.permission.allowed,
                "category": self.permission.category,
                "reason": self.permission.reason,
                "cacheable": self.permission.cacheable,
            },
            **self.payload,
        }


class ToolDispatcher:
    """Minimal dispatcher shell for the Phase 6 state machine."""

    def __init__(self, executor: Callable[[str, int, Dict[str, Any]], Dict[str, Any]]):
        self._executor = executor

    def execute(
        self,
        *,
        tool_name: str,
        case_id: Optional[int],
        params: Dict[str, Any],
        tier: ToolTier = ToolTier.READ_SAFE,
        provenance: Provenance = Provenance.ANALYST,
    ) -> ToolResultBlock:
        if case_id is None:
            return ToolResultBlock(
                tool_name=tool_name,
                status="rejected",
                permission=PermissionResult(
                    allowed=False,
                    category="cross-case denial",
                    reason="case_id is required",
                    cacheable=False,
                ),
                payload={"error": "case_id is required for case-scoped tool calls"},
            )

        try:
            payload = self._executor(tool_name, case_id, params)
        except Exception as exc:  # noqa: BLE001
            return ToolResultBlock(
                tool_name=tool_name,
                status="error",
                permission=PermissionResult(
                    allowed=True,
                    category="allow",
                    reason=f"{tier.value} executed with {provenance.value}",
                    cacheable=tier != ToolTier.WRITE_COMMITTING,
                ),
                payload={"error": str(exc)},
            )

        return ToolResultBlock(
            tool_name=tool_name,
            status="completed",
            permission=PermissionResult(
                allowed=True,
                category="allow",
                reason=f"{tier.value} executed with {provenance.value}",
                cacheable=tier in {ToolTier.READ_SENSITIVE, ToolTier.WRITE_REVERSIBLE},
            ),
            payload=payload if isinstance(payload, dict) else {"result": payload},
        )
