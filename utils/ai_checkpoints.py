"""AI Checkpoints for Case Analysis Pipeline

Two strategic AI intervention points in the analysis pipeline:

Checkpoint 1 - Triage (after pattern detection + IOC timeline):
    Input: Census stats, gap findings, pattern matches, attack chains, IOC timeline
    Output: Prioritized findings, investigation threads, notable observations
    Purpose: Rank what matters instead of dumping all findings equally

Checkpoint 2 - Synthesis (after enrichment, before finalize):
    Input: All findings, IOC timelines, enrichment results, triage output
    Output: Executive narrative, recommended actions, confidence assessment
    Purpose: Turn structured data into actionable investigation summary

Both checkpoints:
- Use a single LLM call each (15-30s on A2 GPU)
- Require structured JSON output
- Only run in Mode B/D (AI enabled)
- Fail gracefully (analysis continues without AI summary)
"""

import logging
import json
import time
from datetime import datetime
from typing import Dict, List, Any, Optional

from config import Config
from utils.rag_llm import OllamaClient

logger = logging.getLogger(__name__)

# Temperature for structured checkpoint output (low for reliability)
CHECKPOINT_TEMPERATURE = 0.1


class AICheckpoint:
    """Base class for AI checkpoint operations."""
    
    def __init__(self, case_id: int, analysis_id: str = None):
        self.case_id = case_id
        self.analysis_id = analysis_id
        self.client = OllamaClient()
    
    def _safe_generate(self, prompt: str, system: str, 
                       max_retries: int = 2) -> Optional[Dict]:
        """Generate JSON with safety wrapper.
        
        Returns parsed dict or None on failure.
        """
        for attempt in range(max_retries):
            try:
                result = self.client.generate_json(
                    prompt=prompt,
                    system=system,
                    temperature=CHECKPOINT_TEMPERATURE
                )
                
                if result.get('success') and result.get('data'):
                    return result['data']
                
                # Try to parse from raw response
                raw = result.get('raw_response', '')
                if raw:
                    import re
                    json_match = re.search(r'\{[\s\S]*\}', raw)
                    if json_match:
                        try:
                            return json.loads(json_match.group())
                        except json.JSONDecodeError:
                            pass
                
                logger.warning(f"[AICheckpoint] Attempt {attempt + 1} failed: "
                              f"{result.get('error', 'Unknown error')}")
                
            except Exception as e:
                logger.warning(f"[AICheckpoint] Attempt {attempt + 1} exception: {e}")
        
        return None


class TriageCheckpoint(AICheckpoint):
    """Checkpoint 1: Triage and prioritize findings.
    
    Takes the raw output from pattern detection, gap detection,
    Hayabusa correlation, and IOC timeline, then produces a
    prioritized assessment with investigation threads.
    """
    
    SYSTEM_PROMPT = """You are a senior DFIR analyst triaging case findings.
Your job is to review detection results and identify what matters most.

Respond with valid JSON only. No markdown, no explanation outside the JSON.
Focus on actionable intelligence — what should the analyst investigate first?"""
    
    def run(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Run triage checkpoint.
        
        Args:
            context: {
                'census': dict of event_id -> count,
                'gap_findings': list of finding summaries,
                'pattern_results': list of pattern match summaries,
                'attack_chains': list of chain summaries,
                'ioc_timeline': dict with entries/cross_host_links,
                'profiling_stats': dict with user/system counts
            }
            
        Returns:
            {
                'priority_findings': [
                    {'finding': str, 'severity': str, 'confidence': int, 
                     'reason': str, 'investigate_next': str}
                ],
                'investigation_threads': [
                    {'thread': str, 'description': str, 
                     'related_findings': [str], 'hosts': [str]}
                ],
                'notable_observations': [str],
                'risk_assessment': str,
                'triage_duration_ms': int
            }
        """
        start = time.time()
        
        prompt = self._build_prompt(context)
        
        logger.info(f"[Triage] Running AI triage for case {self.case_id}")
        
        result = self._safe_generate(prompt, self.SYSTEM_PROMPT)
        
        duration_ms = int((time.time() - start) * 1000)
        
        if result is None:
            logger.warning(f"[Triage] AI triage failed for case {self.case_id}")
            return self._fallback_triage(context, duration_ms)
        
        # Ensure required fields exist
        result.setdefault('priority_findings', [])
        result.setdefault('investigation_threads', [])
        result.setdefault('notable_observations', [])
        result.setdefault('risk_assessment', 'Unable to assess')
        result['triage_duration_ms'] = duration_ms
        
        logger.info(f"[Triage] Complete: {len(result['priority_findings'])} priority findings, "
                    f"{len(result['investigation_threads'])} threads, {duration_ms}ms")
        
        return result
    
    def _build_prompt(self, context: Dict) -> str:
        """Build the triage prompt from analysis context."""
        sections = []
        
        # Census summary
        census = context.get('census', {})
        if census:
            total_events = sum(census.values())
            top_events = sorted(census.items(), key=lambda x: x[1], reverse=True)[:10]
            top_str = ", ".join(f"EID {eid}: {cnt}" for eid, cnt in top_events)
            sections.append(f"EVENT CENSUS: {total_events} total events, "
                          f"{len(census)} distinct event IDs. Top: {top_str}")
        
        # Profiling stats
        stats = context.get('profiling_stats', {})
        if stats:
            sections.append(f"PROFILES: {stats.get('users_profiled', 0)} users, "
                          f"{stats.get('systems_profiled', 0)} systems profiled")
        
        # Gap findings
        gaps = context.get('gap_findings', [])
        if gaps:
            gap_summaries = []
            for g in gaps[:15]:
                if hasattr(g, 'to_dict'):
                    g = g.to_dict()
                if isinstance(g, dict):
                    gap_summaries.append(
                        f"- [{g.get('severity', '?')}] {g.get('detection_type', '?')}: "
                        f"{g.get('summary', g.get('entity_value', '?'))} "
                        f"(confidence: {g.get('confidence', '?')}%)"
                    )
            if gap_summaries:
                sections.append("GAP DETECTION FINDINGS:\n" + "\n".join(gap_summaries))
        
        # Pattern results  
        patterns = context.get('pattern_results', [])
        if patterns:
            pattern_summaries = []
            for p in patterns[:15]:
                if isinstance(p, dict):
                    pattern_summaries.append(
                        f"- [{p.get('severity', '?')}] {p.get('pattern_name', p.get('pattern_id', '?'))}: "
                        f"confidence {p.get('confidence', p.get('final_confidence', '?'))}%, "
                        f"{p.get('events_analyzed', '?')} events"
                    )
            if pattern_summaries:
                sections.append("PATTERN MATCHES:\n" + "\n".join(pattern_summaries))
        
        # Attack chains
        chains = context.get('attack_chains', [])
        if chains:
            chain_summaries = []
            for c in chains[:10]:
                if hasattr(c, 'to_dict'):
                    c = c.to_dict()
                if isinstance(c, dict):
                    chain_summaries.append(
                        f"- {c.get('chain_name', 'Chain')}: "
                        f"{c.get('tactics_observed', [])} "
                        f"on {c.get('primary_host', '?')}"
                    )
            if chain_summaries:
                sections.append("ATTACK CHAINS:\n" + "\n".join(chain_summaries))
        
        # IOC timeline
        timeline = context.get('ioc_timeline', {})
        if timeline:
            summaries = timeline.get('ioc_summaries', [])
            links = timeline.get('cross_host_links', [])
            if summaries:
                ioc_lines = []
                for s in summaries[:10]:
                    ioc_lines.append(
                        f"- {s.get('ioc_type', '?')}: {s.get('ioc_value', '?')} "
                        f"({s.get('match_count', 0)} events on {s.get('host_count', 0)} hosts)"
                    )
                sections.append("IOC TIMELINE:\n" + "\n".join(ioc_lines))
            
            if links:
                link_lines = []
                for l in links[:5]:
                    link_lines.append(
                        f"- {l.get('ioc_value', '?')}: {l.get('source_host', '?')} → "
                        f"{l.get('destination_host', '?')} "
                        f"({l.get('time_delta_seconds', 0):.0f}s apart)"
                    )
                sections.append("CROSS-HOST IOC MOVEMENT:\n" + "\n".join(link_lines))
        
        prompt = "Triage these case analysis results. Identify the most important findings, " \
                 "group related findings into investigation threads, and assess overall risk.\n\n" \
                 + "\n\n".join(sections)
        
        prompt += """

Respond with this exact JSON structure:
{
    "priority_findings": [
        {
            "finding": "Description of the finding",
            "severity": "critical|high|medium|low",
            "confidence": 85,
            "reason": "Why this is priority",
            "investigate_next": "Specific next step"
        }
    ],
    "investigation_threads": [
        {
            "thread": "Thread name",
            "description": "What this thread covers",
            "related_findings": ["finding references"],
            "hosts": ["affected hosts"]
        }
    ],
    "notable_observations": ["Observation 1", "Observation 2"],
    "risk_assessment": "Overall risk assessment in 2-3 sentences"
}"""
        
        return prompt
    
    def _fallback_triage(self, context: Dict, duration_ms: int) -> Dict:
        """Rule-based fallback when AI is unavailable."""
        # Sort findings by severity and confidence
        priority = []
        
        for g in context.get('gap_findings', []):
            if hasattr(g, 'to_dict'):
                g = g.to_dict()
            if isinstance(g, dict) and g.get('severity') in ('critical', 'high'):
                priority.append({
                    'finding': g.get('summary', g.get('detection_type', 'Unknown')),
                    'severity': g.get('severity', 'medium'),
                    'confidence': g.get('confidence', 50),
                    'reason': 'High severity gap detection finding',
                    'investigate_next': f"Review events for {g.get('entity_value', 'entity')}"
                })
        
        for p in context.get('pattern_results', []):
            if isinstance(p, dict):
                conf = p.get('confidence', p.get('final_confidence', 0))
                if conf >= 70:
                    priority.append({
                        'finding': p.get('pattern_name', p.get('pattern_id', 'Unknown')),
                        'severity': p.get('severity', 'medium'),
                        'confidence': conf,
                        'reason': 'High confidence pattern match',
                        'investigate_next': f"Review matched events"
                    })
        
        priority.sort(key=lambda x: (-x['confidence'], x['severity']))
        
        return {
            'priority_findings': priority[:10],
            'investigation_threads': [],
            'notable_observations': ['AI triage unavailable — findings sorted by confidence'],
            'risk_assessment': 'Automated risk assessment unavailable. Review priority findings manually.',
            'triage_duration_ms': duration_ms,
            'fallback': True
        }


class SynthesisCheckpoint(AICheckpoint):
    """Checkpoint 2: Synthesize narrative from all analysis results.
    
    Takes the complete analysis output (including triage, enrichment)
    and produces an executive narrative suitable for reporting.
    """
    
    SYSTEM_PROMPT = """You are a senior DFIR analyst writing an investigation summary.
Write a clear, factual narrative that a security team lead can act on.
Focus on what happened, what's affected, and what to do next.

Respond with valid JSON only. No markdown, no explanation outside the JSON."""
    
    def run(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Run synthesis checkpoint.
        
        Args:
            context: {
                'triage': dict from Checkpoint 1,
                'gap_findings': list,
                'pattern_results': list,
                'attack_chains': list,
                'ioc_timeline': dict,
                'opencti_context': dict (if available),
                'profiling_stats': dict
            }
            
        Returns:
            {
                'executive_summary': str (2-4 paragraphs),
                'key_findings': [str],
                'affected_assets': {'hosts': [str], 'users': [str]},
                'recommended_actions': [
                    {'action': str, 'priority': str, 'rationale': str}
                ],
                'confidence_assessment': str,
                'synthesis_duration_ms': int
            }
        """
        start = time.time()
        
        prompt = self._build_prompt(context)
        
        logger.info(f"[Synthesis] Running AI synthesis for case {self.case_id}")
        
        result = self._safe_generate(prompt, self.SYSTEM_PROMPT)
        
        duration_ms = int((time.time() - start) * 1000)
        
        if result is None:
            logger.warning(f"[Synthesis] AI synthesis failed for case {self.case_id}")
            return self._fallback_synthesis(context, duration_ms)
        
        # Ensure required fields
        result.setdefault('executive_summary', '')
        result.setdefault('key_findings', [])
        result.setdefault('affected_assets', {'hosts': [], 'users': []})
        result.setdefault('recommended_actions', [])
        result.setdefault('confidence_assessment', '')
        result['synthesis_duration_ms'] = duration_ms
        
        logger.info(f"[Synthesis] Complete: {len(result['key_findings'])} key findings, "
                    f"{len(result['recommended_actions'])} actions, {duration_ms}ms")
        
        return result
    
    def _build_prompt(self, context: Dict) -> str:
        """Build synthesis prompt from complete analysis context."""
        sections = []
        
        # Include triage results if available
        triage = context.get('triage', {})
        if triage and triage.get('priority_findings'):
            findings = triage['priority_findings']
            finding_lines = []
            for f in findings[:10]:
                finding_lines.append(
                    f"- [{f.get('severity', '?')}] {f.get('finding', '?')} "
                    f"(confidence: {f.get('confidence', '?')}%)"
                )
            sections.append("PRIORITY FINDINGS (from triage):\n" + "\n".join(finding_lines))
            
            if triage.get('investigation_threads'):
                thread_lines = [f"- {t.get('thread', '?')}: {t.get('description', '')}" 
                               for t in triage['investigation_threads'][:5]]
                sections.append("INVESTIGATION THREADS:\n" + "\n".join(thread_lines))
            
            if triage.get('risk_assessment'):
                sections.append(f"TRIAGE RISK ASSESSMENT: {triage['risk_assessment']}")
        
        # IOC timeline cross-host movement
        timeline = context.get('ioc_timeline', {})
        if timeline:
            links = timeline.get('cross_host_links', [])
            summaries = timeline.get('ioc_summaries', [])
            
            if links:
                link_lines = []
                for l in links[:5]:
                    lateral = " [LATERAL MOVEMENT]" if l.get('potential_lateral_movement') else ""
                    link_lines.append(
                        f"- {l.get('ioc_value', '?')}: {l.get('source_host', '?')} → "
                        f"{l.get('destination_host', '?')}{lateral}"
                    )
                sections.append("CROSS-HOST IOC MOVEMENT:\n" + "\n".join(link_lines))
            
            if summaries:
                ioc_lines = [f"- {s.get('ioc_type', '?')}: {s.get('ioc_value', '?')} "
                            f"({s.get('host_count', 0)} hosts)" 
                            for s in summaries[:8]]
                sections.append("IOC SUMMARY:\n" + "\n".join(ioc_lines))
        
        # Attack chains
        chains = context.get('attack_chains', [])
        if chains:
            chain_lines = []
            for c in chains[:5]:
                if hasattr(c, 'to_dict'):
                    c = c.to_dict()
                if isinstance(c, dict):
                    chain_lines.append(
                        f"- {c.get('chain_name', 'Chain')}: "
                        f"tactics {c.get('tactics_observed', [])} "
                        f"on {c.get('primary_host', '?')}"
                    )
            if chain_lines:
                sections.append("ATTACK CHAINS:\n" + "\n".join(chain_lines))
        
        # Profiling anomalies
        stats = context.get('profiling_stats', {})
        if stats:
            sections.append(
                f"SCOPE: {stats.get('users_profiled', 0)} users, "
                f"{stats.get('systems_profiled', 0)} systems analyzed"
            )
        
        # OpenCTI threat intelligence
        opencti = context.get('opencti_context', {})
        if opencti and opencti.get('available'):
            ti_lines = []
            actors = opencti.get('threat_actors', [])
            if actors:
                actor_names = [a['name'] for a in actors[:5]]
                ti_lines.append(f"Associated threat actors: {', '.join(actor_names)}")
            campaigns = opencti.get('campaigns', [])
            if campaigns:
                for c in campaigns[:3]:
                    ti_lines.append(f"Campaign: {c.get('name')} ({c.get('published', 'date unknown')})")
            enriched = opencti.get('ioc_enrichment', {})
            if enriched:
                ti_lines.append(f"{len(enriched)} IOCs found in threat intelligence with scoring")
            if ti_lines:
                sections.append(
                    "THREAT INTELLIGENCE (from OpenCTI):\n" + "\n".join(ti_lines) +
                    "\nNote: use 'consistent with' or 'overlaps with techniques attributed to' "
                    "language — do not state definitive attribution."
                )
        
        prompt = "Synthesize these DFIR analysis results into an executive summary. " \
                 "Focus on what happened, what assets are affected, and what actions to take.\n\n" \
                 + "\n\n".join(sections)
        
        prompt += """

Respond with this exact JSON structure:
{
    "executive_summary": "2-4 paragraph narrative of what happened",
    "key_findings": [
        "Finding 1 in plain language",
        "Finding 2 in plain language"
    ],
    "affected_assets": {
        "hosts": ["HOST-1", "HOST-2"],
        "users": ["user1", "user2"]
    },
    "recommended_actions": [
        {
            "action": "What to do",
            "priority": "immediate|high|medium|low",
            "rationale": "Why"
        }
    ],
    "confidence_assessment": "How confident are we in these findings and why"
}"""
        
        return prompt
    
    def _fallback_synthesis(self, context: Dict, duration_ms: int) -> Dict:
        """Template-based fallback when AI is unavailable."""
        # Collect affected hosts and users
        hosts = set()
        users = set()
        
        for g in context.get('gap_findings', []):
            if hasattr(g, 'to_dict'):
                g = g.to_dict()
            if isinstance(g, dict):
                if g.get('entity_type') == 'system' and g.get('entity_value'):
                    hosts.add(g['entity_value'])
                if g.get('entity_type') == 'user' and g.get('entity_value'):
                    users.add(g['entity_value'])
        
        timeline = context.get('ioc_timeline', {})
        for s in timeline.get('ioc_summaries', []):
            for h in s.get('hosts_affected', []):
                hosts.add(h)
        
        # Build actions from triage priority findings
        actions = []
        triage = context.get('triage', {})
        for f in triage.get('priority_findings', [])[:5]:
            actions.append({
                'action': f.get('investigate_next', 'Review finding'),
                'priority': 'high' if f.get('severity') in ('critical', 'high') else 'medium',
                'rationale': f.get('reason', 'Priority finding')
            })
        
        return {
            'executive_summary': 'AI synthesis unavailable. Review the priority findings '
                                'and investigation threads from the triage phase for '
                                'actionable intelligence.',
            'key_findings': [f.get('finding', '') for f in triage.get('priority_findings', [])[:5]],
            'affected_assets': {
                'hosts': sorted(list(hosts))[:20],
                'users': sorted(list(users))[:20]
            },
            'recommended_actions': actions,
            'confidence_assessment': 'Automated synthesis unavailable. '
                                    'Confidence is based on deterministic detection scores.',
            'synthesis_duration_ms': duration_ms,
            'fallback': True
        }
