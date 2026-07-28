"""Internal assistant tool-provider registry.

This registry is intentionally local-first. It gives CaseScope a stable MCP-style
metadata layer without allowing arbitrary external tool execution.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List

from .dispatch import Provenance, ToolTier
from .policy import REQUIRED_CHAT_TOOL_FEATURES, resolve_chat_tool_policy


@dataclass(frozen=True)
class AssistantToolProvider:
    """Metadata for one assistant-visible tool provider."""

    name: str
    description: str
    required_feature: str
    required_settings: tuple[str, ...]
    tier: ToolTier
    provenance: Provenance
    enabled_by_default: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "required_feature": self.required_feature,
            "required_settings": list(self.required_settings),
            "tier": self.tier.value,
            "provenance": self.provenance.value,
            "enabled_by_default": self.enabled_by_default,
        }


_TOOL_DESCRIPTIONS = {
    "investigate_question": "Run an agentic multi-pivot forensic investigation.",
    "query_events": "Search normalized case event rows.",
    "count_events": "Count and group normalized case events.",
    "get_event_context": "Read the events surrounding one anchor event.",
    "get_case_coverage": "Report which evidence sources the case contains.",
    "get_findings": "Read deterministic and AI-assisted findings.",
    "search_artifacts": "Search normalized forensic artifacts.",
    "get_browser_downloads": "Review browser download artifacts.",
    "get_processes": "Review process evidence across events and memory.",
    "get_process_tree": "Reconstruct process parent-child lineage.",
    "search_memory": "Search memory-derived forensic artifacts.",
    "search_network_logs": "Search indexed PCAP and Zeek network logs.",
    "lookup_ioc": "Look up IOC sightings in the case.",
    "add_ioc": "Record an IOC against the case.",
    "save_finding": "Record an analyst finding against the case.",
    "lookup_threat_intel": "Query configured threat-intelligence integrations.",
    "run_forensic_subagent": "Delegate bounded analysis to a CaseScope forensic specialist.",
    "get_raw_event": "Retrieve one complete event record with its raw payload.",
    "get_authentication_summary": "Summarize authentication outcomes, accounts and sources.",
    "get_entity_profile": "Profile one host, account or IP address.",
    "get_hunt_findings": "Read detection findings with reasoning and rule filtering.",
    "get_persistence_artifacts": "Review persistence mechanisms in the case evidence.",
    "get_file_activity": "Review file creation, write, access and execution evidence.",
    "run_detector": "Run one behavioral detector on demand, without recording findings.",
    "search_pattern_library": "Look up known attack patterns as supporting context.",
}

_REQUIRED_SETTINGS = {
    "lookup_threat_intel": ("opencti_or_misp",),
    # Semantic pattern lookup needs the vector store and an embedding model.
    "search_pattern_library": ("qdrant_and_embeddings",),
}


def get_tool_provider(name: str) -> AssistantToolProvider:
    """Return provider metadata for one assistant-visible tool."""
    tier, provenance = resolve_chat_tool_policy(name)
    return AssistantToolProvider(
        name=name,
        description=_TOOL_DESCRIPTIONS.get(name, "Assistant-visible CaseScope tool."),
        required_feature=REQUIRED_CHAT_TOOL_FEATURES.get(name, "case_access"),
        required_settings=tuple(_REQUIRED_SETTINGS.get(name, ())),
        tier=tier,
        provenance=provenance,
    )


def list_tool_providers(tool_names: List[str] | None = None) -> List[Dict[str, Any]]:
    """Return metadata for all known assistant-visible tools."""
    names = tool_names or sorted(_TOOL_DESCRIPTIONS)
    return [get_tool_provider(name).to_dict() for name in names]

