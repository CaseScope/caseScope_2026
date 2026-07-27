"""Shared chat tool policy helpers for Phase 6."""

from __future__ import annotations

import importlib.util
import os
import sys
from typing import Any, Dict, Optional, Tuple

try:
    from .dispatch import PermissionResult, Provenance, ToolTier
except Exception:
    module_path = os.path.join(os.path.dirname(__file__), "dispatch.py")
    spec = importlib.util.spec_from_file_location("chat_policy_dispatch_fallback", module_path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules["chat_policy_dispatch_fallback"] = module
    spec.loader.exec_module(module)
    PermissionResult = module.PermissionResult
    Provenance = module.Provenance
    ToolTier = module.ToolTier

SENSITIVE_CHAT_TOOLS = {
    "investigate_question",
    "search_artifacts",
    "get_browser_downloads",
    "get_processes",
    "get_process_tree",
    "search_memory",
    "search_network_logs",
    "lookup_ioc",
    "lookup_threat_intel",
    "run_forensic_subagent",
}

REVERSIBLE_WRITE_CHAT_TOOLS = {
    "add_ioc",
    "save_finding",
}

# Licensed capability required before a chat tool may execute. Tools absent from
# this map only require case access. This is the single source of truth for both
# enforcement (feature_gate_chat_tool) and disclosure (tool_providers).
REQUIRED_CHAT_TOOL_FEATURES = {
    "lookup_threat_intel": "threat_intel",
    "run_forensic_subagent": "ai",
}

_FEATURE_UNAVAILABLE_REASONS = {
    "threat_intel": "Threat intelligence lookup is not currently available",
    "ai": "AI analysis features are not currently available",
}


def resolve_chat_tool_policy(tool_name: str) -> Tuple[ToolTier, Provenance]:
    """Resolve baseline dispatch policy for chat tool invocations."""
    if tool_name in REVERSIBLE_WRITE_CHAT_TOOLS:
        tier = ToolTier.WRITE_REVERSIBLE
    else:
        tier = ToolTier.READ_SENSITIVE if tool_name in SENSITIVE_CHAT_TOOLS else ToolTier.READ_SAFE
    return tier, Provenance.MODEL_SYNTHESIZED


def feature_gate_chat_tool(tool_name: str, case_id: int, params: Dict[str, Any]) -> Optional[PermissionResult]:
    """Return a structured feature gate result for licensed chat tools."""
    del case_id, params
    required_feature = REQUIRED_CHAT_TOOL_FEATURES.get(tool_name)
    if not required_feature:
        return None

    unavailable = PermissionResult(
        allowed=False,
        category="feature unavailable",
        reason=_FEATURE_UNAVAILABLE_REASONS.get(
            required_feature,
            f"{tool_name} is not currently available",
        ),
        cacheable=False,
    )

    try:
        from utils.feature_availability import FeatureAvailability

        if FeatureAvailability.is_chat_tool_feature_enabled(tool_name):
            return None
    except Exception:
        return unavailable

    return unavailable
