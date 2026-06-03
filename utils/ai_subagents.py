"""CaseScope-native forensic subagent registry and execution helpers."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Iterable, List

from utils.ai.router import invoke_text
from utils.ai_training import build_role_system_prompt
from utils.privacy_aliases import AIPrivacyContext


@dataclass(frozen=True)
class ForensicSubagent:
    """Definition for a bounded, evidence-aware forensic specialist."""

    key: str
    name: str
    purpose: str
    allowed_tools: tuple[str, ...]
    route_name: str
    prompt_guidance: str
    output_schema: tuple[str, ...]
    required_feature: str = "ai"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "key": self.key,
            "name": self.name,
            "purpose": self.purpose,
            "allowed_tools": list(self.allowed_tools),
            "route_name": self.route_name,
            "output_schema": list(self.output_schema),
            "required_feature": self.required_feature,
        }


SUBAGENTS: Dict[str, ForensicSubagent] = {
    "timeline_analyst": ForensicSubagent(
        key="timeline_analyst",
        name="Timeline Analyst",
        purpose="Build chronological incident narratives from tagged events, findings, and event searches.",
        allowed_tools=("query_events", "get_findings", "lookup_ioc"),
        route_name="timeline",
        prompt_guidance=(
            "Focus on chronological order, phase boundaries, key timestamps, source artifacts, "
            "and uncertainty. Never invent missing timestamps."
        ),
        output_schema=("summary", "timeline_phases", "key_events", "gaps", "next_steps"),
    ),
    "ioc_reviewer": ForensicSubagent(
        key="ioc_reviewer",
        name="IOC Reviewer",
        purpose="Evaluate stored IOCs, case sightings, and external threat-intel context.",
        allowed_tools=("lookup_ioc", "lookup_threat_intel", "search_artifacts", "search_network_logs"),
        route_name="ioc_extraction",
        prompt_guidance=(
            "Separate confirmed case sightings from enrichment-only context. Include match locations, "
            "hosts, timestamps, and false-positive caveats."
        ),
        output_schema=("confirmed_iocs", "unconfirmed_iocs", "case_sightings", "risk", "next_steps"),
    ),
    "memory_forensics_analyst": ForensicSubagent(
        key="memory_forensics_analyst",
        name="Memory Forensics Analyst",
        purpose="Review memory-derived processes, services, modules, paths, credentials, and suspicious regions.",
        allowed_tools=("search_memory", "get_processes", "get_process_tree", "search_artifacts"),
        route_name="case_review",
        prompt_guidance=(
            "Prioritize RAM-resident evidence, process ancestry, suspicious modules, injected regions, "
            "credential artifacts, and evidence gaps."
        ),
        output_schema=("memory_findings", "suspicious_processes", "supporting_artifacts", "gaps", "next_steps"),
    ),
    "network_analyst": ForensicSubagent(
        key="network_analyst",
        name="Network Analyst",
        purpose="Analyze PCAP-derived network logs, DNS, HTTP, SSL, and network IOC context.",
        allowed_tools=("search_network_logs", "lookup_ioc", "search_artifacts"),
        route_name="case_review",
        prompt_guidance=(
            "Focus on source/destination roles, protocol evidence, data-transfer indicators, DNS/HTTP/SSL "
            "artifacts, and bounded search limitations."
        ),
        output_schema=("network_findings", "notable_connections", "ioc_context", "limitations", "next_steps"),
    ),
    "pattern_correlator": ForensicSubagent(
        key="pattern_correlator",
        name="Pattern Correlator",
        purpose="Correlate deterministic findings, AI pattern matches, RAG patterns, and MITRE context.",
        allowed_tools=("get_findings", "query_events", "count_events"),
        route_name="pattern_matching",
        prompt_guidance=(
            "Blend deterministic findings with evidence-backed reasoning. Keep rule hits, AI judgments, "
            "and hypotheses clearly separated."
        ),
        output_schema=("matched_patterns", "confidence", "supporting_events", "false_positive_notes", "next_steps"),
    ),
    "report_drafter": ForensicSubagent(
        key="report_drafter",
        name="Report Drafter",
        purpose="Draft evidence-backed report sections from approved findings and analyst notes.",
        allowed_tools=("get_findings", "query_events", "lookup_ioc"),
        route_name="report",
        prompt_guidance=(
            "Write concise DFIR report language. Cite evidence categories and limitations; do not overstate "
            "unreviewed model hypotheses."
        ),
        output_schema=("executive_summary", "findings", "evidence", "limitations", "recommendations"),
    ),
}


def list_subagents() -> List[Dict[str, Any]]:
    """Return available subagents for UI or tool discovery."""
    return [agent.to_dict() for agent in SUBAGENTS.values()]


def get_subagent(key: str) -> ForensicSubagent:
    """Return one subagent definition or raise a clear error."""
    normalized = (key or "").strip().lower()
    if normalized not in SUBAGENTS:
        available = ", ".join(sorted(SUBAGENTS))
        raise ValueError(f"Unknown subagent '{key}'. Available subagents: {available}")
    return SUBAGENTS[normalized]


def run_subagent(
    *,
    key: str,
    case_id: int,
    task: str,
    evidence: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    """Run a bounded subagent prompt through the shared audited AI router."""
    agent = get_subagent(key)
    evidence = evidence or {}
    system = build_role_system_prompt(
        agent.route_name,
        (
            f"You are the CaseScope {agent.name}. {agent.purpose}\n"
            f"Allowed tool families for follow-up investigation: {', '.join(agent.allowed_tools)}.\n"
            f"{agent.prompt_guidance}\n"
            "Return concise markdown with evidence, uncertainty, and next steps."
        ),
    )
    prompt = (
        f"Subagent task: {task}\n\n"
        f"Expected sections: {', '.join(agent.output_schema)}\n\n"
        f"Available evidence context:\n{_format_evidence(evidence)}"
    )
    result = invoke_text(
        function=agent.route_name,
        prompt=prompt,
        system=system,
        temperature=0.2,
        max_tokens=2000,
        privacy_context=AIPrivacyContext.case_content(case_id),
    )
    return {
        "subagent": agent.to_dict(),
        "task": task,
        "response": result.get("text") or result.get("response") or "",
        "usage": result.get("usage", {}),
        "runtime": result.get("runtime", {}),
    }


def _format_evidence(evidence: Dict[str, Any]) -> str:
    """Compact user/tool-provided evidence for a subagent prompt."""
    if not evidence:
        return "No explicit evidence packet supplied. Use only the task text and available case context."
    lines: List[str] = []
    for key, value in evidence.items():
        lines.append(f"- {key}: {str(value)[:1500]}")
    return "\n".join(lines)

