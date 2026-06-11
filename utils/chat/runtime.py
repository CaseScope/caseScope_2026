"""Shared chat runtime primitives for Phase 6."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Dict, Iterable, List, Optional, Tuple


@dataclass(frozen=True)
class ConversationContext:
    """Frozen per-conversation runtime context."""

    license_tier: str = "unknown"
    enabled_features: Tuple[str, ...] = field(default_factory=tuple)
    enabled_ti_sources: Tuple[str, ...] = field(default_factory=tuple)
    available_agents: Tuple[str, ...] = field(default_factory=tuple)
    model_selection: str = ""
    capability_flags: Tuple[Tuple[str, Any], ...] = field(default_factory=tuple)


class AttachmentOrder(IntEnum):
    SYSTEM_REMINDER = 10
    CASE_STATIC_CONTEXT = 20
    LICENSE_CAPABILITIES = 30
    AVAILABLE_ARTIFACTS = 40
    FINDING_SUMMARY = 50
    CONVERSATION_DELTA = 60
    USER_QUERY = 70


@dataclass(frozen=True)
class Attachment:
    order: AttachmentOrder
    name: str
    content: str


class AttachmentScheduler:
    """Deterministically order turn-variable attachments."""

    def __init__(self) -> None:
        self._attachments: List[Attachment] = []

    def add(self, order: AttachmentOrder, name: str, content: Optional[str]) -> None:
        cleaned = str(content or "").strip()
        if not cleaned:
            return
        self._attachments.append(Attachment(order=order, name=name, content=cleaned))

    def build(self) -> List[Attachment]:
        return sorted(
            self._attachments,
            key=lambda attachment: (int(attachment.order), attachment.name),
        )

    def render(self) -> str:
        parts = []
        for attachment in self.build():
            parts.append(f"[{attachment.name}]\n{attachment.content}")
        return "\n\n".join(parts)


def add_cache_breakpoints(
    messages: Iterable[Dict[str, Any]],
    *,
    fork_mode: bool = False,
) -> List[Dict[str, Any]]:
    """Apply exactly one cache marker to a shallow-cloned message list."""
    cloned_messages = [dict(message) for message in messages]
    if not cloned_messages:
        return cloned_messages

    for message in cloned_messages:
        message.pop("cache_control", None)

    target_index = -2 if fork_mode and len(cloned_messages) > 1 else -1
    cloned_messages[target_index]["cache_control"] = {"type": "ephemeral"}
    return cloned_messages


def inject_tool_result_cache_refs(messages: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Annotate repeated tool results without removing the replayed payload."""
    cloned_messages = [dict(message) for message in messages]
    seen: Dict[Tuple[str, str], Dict[str, Any]] = {}

    for message in cloned_messages:
        if message.get("role") != "tool":
            continue
        tool_name = str(message.get("name") or "tool")
        content = str(message.get("content") or "")
        content_digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
        key = (tool_name, content_digest)
        if key not in seen:
            seen[key] = message
            continue

        first_message = seen[key]
        try:
            payload = json.loads(content)
            if not isinstance(payload, dict):
                payload = {"result": payload}
        except (TypeError, ValueError, json.JSONDecodeError):
            payload = {"result": content}
        payload["reused_result"] = True
        payload["cache_reference"] = {
            "tool_name": tool_name,
            "first_tool_call_id": first_message.get("tool_call_id"),
            "kind": "reused_tool_result",
            "payload_sha256": content_digest,
            "replay": "full_payload",
            "preview": content[:500],
        }
        message["content"] = json.dumps(payload, default=str)

    return cloned_messages
