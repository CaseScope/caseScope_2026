"""RAG LLM Integration for CaseScope

Provides LLM integration for pattern analysis and timeline generation.
Delegates to the multi-provider abstraction layer (utils.ai_providers).
Backward-compatible: OllamaClient and get_ollama_client() still exist as
thin wrappers so existing callers keep working.
"""

import logging
import json
import threading
from typing import Dict, Any, Optional, List

from config import Config
from utils.ai.router import invoke_json, invoke_text, resolve_provider
from utils.ai_training import build_role_system_prompt

logger = logging.getLogger(__name__)

PATTERN_MATCH_SYSTEM_PROMPT = build_role_system_prompt(
    'pattern_matching',
    """Analyze the provided security events and produce concise, actionable forensic findings.
Be evidence-first, avoid guessing, and return only the fields requested by the calling route.""",
)

TIMELINE_NARRATIVE_SYSTEM_PROMPT = build_role_system_prompt(
    'timeline',
    """Focus on the attacker's observed actions, likely objective, and the artifacts that support that interpretation.
Do not invent details beyond the supplied events.""",
)


class OllamaClient:
    """Backward-compatible client that delegates to the shared AI router."""

    def __init__(self, host: str = None, model: str = None):
        self.host = host or Config.OLLAMA_HOST
        self.model = model or Config.OLLAMA_MODEL

    def generate(
        self,
        prompt: str,
        system: str = None,
        format: str = None,
        temperature: float = 0.7,
        max_tokens: int = 2000
    ) -> Dict[str, Any]:
        return invoke_text(
            function='pattern_matching',
            prompt=prompt,
            system=system,
            temperature=temperature,
            max_tokens=max_tokens,
            model_override=self.model if self.model != Config.OLLAMA_MODEL else None,
        )

    def generate_json(
        self,
        prompt: str,
        system: str = None,
        temperature: float = 0.3
    ) -> Dict[str, Any]:
        return invoke_json(
            function='pattern_matching',
            prompt=prompt,
            system=system,
            temperature=temperature,
            model_override=self.model if self.model != Config.OLLAMA_MODEL else None,
        )

    def health_check(self) -> Dict[str, Any]:
        provider = resolve_provider(
            function='pattern_matching',
            model_override=self.model if self.model != Config.OLLAMA_MODEL else None,
        )
        return provider.health_check()


_ollama_client = None
_ollama_lock = threading.Lock()


def get_ollama_client() -> OllamaClient:
    """Get or create client instance (thread-safe). Kept for backward compat."""
    global _ollama_client
    if _ollama_client is None:
        with _ollama_lock:
            if _ollama_client is None:
                _ollama_client = OllamaClient()
    return _ollama_client


def analyze_pattern_match(
    pattern_name: str,
    mitre_technique: str,
    matched_events: List[Dict],
    source_host: str = None
) -> Dict[str, Any]:
    """Use LLM to analyze a pattern match and generate summary
    
    Args:
        pattern_name: Name of the matched pattern
        mitre_technique: MITRE ATT&CK technique ID
        matched_events: List of matched event data
        source_host: Affected host
        
    Returns:
        Dict with analysis results
    """
    # Build context from events
    event_summary = []
    for e in matched_events[:10]:
        parts = []
        if e.get('timestamp'):
            parts.append(f"Time: {e['timestamp']}")
        if e.get('event_id'):
            parts.append(f"EventID: {e['event_id']}")
        if e.get('username'):
            parts.append(f"User: {e['username']}")
        if e.get('process_name'):
            parts.append(f"Process: {e['process_name']}")
        if e.get('rule_title'):
            parts.append(f"Rule: {e['rule_title']}")
        event_summary.append(" | ".join(parts))
    
    events_text = "\n".join(event_summary)
    
    prompt = f"""Analyze this security detection and provide a brief forensic summary.

Pattern: {pattern_name}
MITRE Technique: {mitre_technique}
Host: {source_host or 'Unknown'}

Matched Events:
{events_text}

Provide a JSON response with:
1. "summary": 2-3 sentence description of what happened
2. "confidence": "high", "medium", or "low"
3. "severity": "critical", "high", "medium", or "low"
4. "recommended_actions": list of 2-3 investigation steps
5. "indicators": list of key IOCs or artifacts to investigate
"""

    result = invoke_json(
        function='pattern_matching',
        prompt=prompt,
        system=PATTERN_MATCH_SYSTEM_PROMPT,
    )
    
    if result.get('success') and result.get('data'):
        return {
            'success': True,
            'analysis': result['data']
        }
    else:
        return {
            'success': False,
            'error': result.get('error', 'Analysis failed')
        }


def generate_timeline_narrative(
    phase_events: List[Dict],
    phase_number: int,
    total_phases: int,
    mitre_tactics: List[str] = None
) -> Dict[str, Any]:
    """Generate narrative description for a timeline phase
    
    Args:
        phase_events: Events in this phase
        phase_number: Phase number
        total_phases: Total number of phases
        mitre_tactics: MITRE tactics associated
        
    Returns:
        Dict with narrative
    """
    # Build event context
    event_lines = []
    for e in phase_events[:15]:
        parts = []
        if e.get('timestamp'):
            parts.append(str(e['timestamp']))
        if e.get('event_id'):
            parts.append(f"[{e['event_id']}]")
        if e.get('rule_title'):
            parts.append(e['rule_title'])
        elif e.get('channel'):
            parts.append(e['channel'])
        if e.get('username'):
            parts.append(f"User: {e['username']}")
        if e.get('source_host'):
            parts.append(f"Host: {e['source_host']}")
        event_lines.append(" ".join(parts))
    
    events_text = "\n".join(event_lines)
    tactics_text = ", ".join(mitre_tactics) if mitre_tactics else "Unknown"
    
    prompt = f"""Analyze this incident phase and provide a forensic narrative.

Phase {phase_number} of {total_phases}
MITRE Tactics: {tactics_text}
Event Count: {len(phase_events)}

Key Events:
{events_text}

Provide a JSON response with:
1. "summary": 2-3 sentence summary of this attack phase
2. "objective": What the attacker was likely trying to achieve
3. "confidence": "high", "medium", or "low" with brief justification
4. "key_indicators": List of important artifacts/IOCs from this phase
"""

    result = invoke_json(
        function='timeline',
        prompt=prompt,
        system=TIMELINE_NARRATIVE_SYSTEM_PROMPT,
    )
    
    if result.get('success') and result.get('data'):
        return {
            'success': True,
            'narrative': result['data']
        }
    else:
        # Return basic fallback
        return {
            'success': False,
            'narrative': {
                'summary': f'Phase {phase_number}: {len(phase_events)} events detected.',
                'objective': 'Unknown',
                'confidence': 'low',
                'key_indicators': []
            }
        }


def generate_executive_summary(timeline_phases: List[Dict]) -> str:
    """Generate executive summary for entire timeline
    
    Args:
        timeline_phases: List of timeline phase data
        
    Returns:
        Executive summary string
    """
    # Build phase summaries
    phase_summaries = []
    for phase in timeline_phases:
        summary = f"Phase {phase.get('phase_number', '?')}: {phase.get('summary', 'Activity detected')}"
        if phase.get('mitre_techniques'):
            summary += f" (MITRE: {', '.join(phase['mitre_techniques'][:3])})"
        phase_summaries.append(summary)
    
    phases_text = "\n".join(phase_summaries)
    
    prompt = f"""Create an executive summary for this incident timeline.

Timeline Phases:
{phases_text}

Total Phases: {len(timeline_phases)}

Write a 3-4 sentence executive summary suitable for management. 
Include: overall incident type, scope, and recommended immediate actions.
Return just the summary text, no JSON."""

    result = invoke_text(
        function='timeline',
        prompt=prompt,
        temperature=0.5,
        max_tokens=500,
    )
    
    if result.get('success'):
        return result.get('response', 'Analysis complete. Review timeline phases for details.')
    else:
        return f"Incident timeline generated with {len(timeline_phases)} phases. Review each phase for detailed findings."


def health_check() -> Dict[str, Any]:
    """Check LLM health"""
    return get_ollama_client().health_check()
