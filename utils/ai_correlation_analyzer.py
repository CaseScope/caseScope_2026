"""AI-Powered Correlation Analyzer

Uses LLM to analyze candidate events and determine if they constitute 
true attack pattern matches. Uses the primary configured model (OLLAMA_MODEL)
for structured output with low temperature.

This module provides Stage 4 of the AI correlation pipeline:
1. Build analysis prompt with event context
2. Run AI inference with pattern checklist
3. Parse AI response for confidence and reasoning
4. Blend rule-based and AI scores
5. Store analysis results

Usage:
    analyzer = AICorrelationAnalyzer(
        case_id=123,
        analysis_id='uuid'
    )
    results = analyzer.analyze_pattern(
        pattern_config=PATTERN_EVENT_MAPPINGS['pass_the_hash'],
        rule_based_confidence=72.0
    )
"""

import logging
import json
import time
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple

from models.database import db
from config import Config
from utils.rag_llm import OllamaClient

logger = logging.getLogger(__name__)

AI_CORRELATION_TEMPERATURE = 0.1


class AICorrelationAnalyzer:
    """Analyzes candidate events using AI to determine pattern matches
    
    Uses local LLM (via Ollama) to:
    - Review pre-filtered candidate events
    - Apply attack pattern checklists
    - Assess confidence with reasoning
    - Identify IOCs and indicators
    - Evaluate false positive likelihood
    """
    
    # Default prompts
    SYSTEM_PROMPT = """You are a senior security analyst specializing in threat detection and digital forensics.
Your task is to analyze Windows security events and determine if they indicate specific attack patterns.

Key principles:
- Be precise and evidence-based in your analysis
- When evidence is ambiguous, reflect that in lower confidence scores
- Consider legitimate administrative activities that could cause similar events
- Identify specific indicators and IOCs from the events
- Always respond with valid JSON only, no additional text or markdown"""

    def __init__(
        self,
        case_id: int,
        analysis_id: str,
        model: str = None,
        temperature: float = None
    ):
        """Initialize analyzer
        
        Args:
            case_id: PostgreSQL case ID
            analysis_id: UUID for this analysis run
            model: Model name (optional, uses configured provider default)
            temperature: LLM temperature (lower = more consistent)
        """
        self.case_id = case_id
        self.analysis_id = analysis_id
        
        self.model = model or Config.OLLAMA_MODEL
        self.temperature = temperature or AI_CORRELATION_TEMPERATURE
        
        self.client = OllamaClient(model=self.model)
        
        from utils.ai_providers import get_llm_provider
        self._provider = get_llm_provider()
        self._batch_config = self._provider.get_batch_config()
        
        self._stats = {
            'windows_analyzed': 0,
            'ai_calls': 0,
            'total_duration_ms': 0,
            'avg_confidence': 0.0
        }
        
    def analyze_pattern(
        self,
        pattern_config: Dict,
        rule_based_confidence: float = None,
        max_events_per_window: int = None
    ) -> List[Dict[str, Any]]:
        """Analyze candidate events for a pattern using AI
        
        Processes each unique correlation key (attack window) and runs
        AI analysis to determine if the events constitute a true match.
        
        Args:
            pattern_config: Pattern definition with checklist
                Required: id, name, checklist
            rule_based_confidence: Pre-computed rule-based score (optional)
            max_events_per_window: Max events to include in context
            
        Returns:
            List of analysis results, one per correlation key:
            [
                {
                    'correlation_key': str,
                    'window_start': datetime,
                    'window_end': datetime,
                    'events_analyzed': int,
                    'rule_based_confidence': float,
                    'ai_confidence': float,
                    'final_confidence': float,
                    'ai_reasoning': str,
                    'indicators_found': list,
                    'iocs': list,
                    'false_positive_assessment': str
                }
            ]
        """
        from models.rag import CandidateEventSet, AIAnalysisResult
        
        pattern_id = pattern_config.get('id', 'unknown')
        pattern_name = pattern_config['name']
        max_events = max_events_per_window or 50
        
        logger.info(f"[AIAnalyzer] Starting analysis for {pattern_name}")
        
        # Get unique correlation keys (attack windows)
        correlation_keys = db.session.query(
            CandidateEventSet.correlation_key
        ).filter_by(
            analysis_id=self.analysis_id,
            pattern_id=pattern_id
        ).distinct().all()
        
        all_keys = [k[0] for k in correlation_keys]
        logger.info(f"[AIAnalyzer] Found {len(all_keys)} attack windows to analyze")
        
        results = []
        confidence_sum = 0.0
        
        BATCH_SIZE = self._batch_config.get('batch_size', 10)
        logger.info(f"[AIAnalyzer] Using batch_size={BATCH_SIZE} "
                    f"(tier={self._batch_config.get('tier', 'unknown')}, "
                    f"timeout={self._batch_config.get('timeout', '?')}s)")
        
        for batch_idx in range(0, len(all_keys), BATCH_SIZE):
            batch_keys = all_keys[batch_idx:batch_idx + BATCH_SIZE]
            batch_windows = []
            
            # Collect window data for this batch
            for correlation_key in batch_keys:
                candidates = CandidateEventSet.query.filter_by(
                    analysis_id=self.analysis_id,
                    pattern_id=pattern_id,
                    correlation_key=correlation_key
                ).order_by(
                    CandidateEventSet.event_timestamp.asc()
                ).limit(max_events).all()
                
                if not candidates:
                    continue
                
                timestamps = [c.event_timestamp for c in candidates]
                batch_windows.append({
                    'correlation_key': correlation_key,
                    'candidates': candidates,
                    'window_start': min(timestamps),
                    'window_end': max(timestamps)
                })
            
            if not batch_windows:
                continue
            
            # Build batched prompt
            prompt = self._build_batched_analysis_prompt(
                pattern_config=pattern_config,
                windows=batch_windows
            )
            
            # Run AI analysis for batch
            start_time = time.time()
            batch_results = self._run_batched_ai_analysis(prompt, pattern_config, len(batch_windows))
            duration_ms = int((time.time() - start_time) * 1000)
            
            self._stats['ai_calls'] += 1
            self._stats['total_duration_ms'] += duration_ms
            
            logger.info(f"[AIAnalyzer] Batch {batch_idx//BATCH_SIZE + 1}: analyzed {len(batch_windows)} windows in {duration_ms}ms")
            
            # Process each result in batch
            for i, window in enumerate(batch_windows):
                ai_result = batch_results[i] if i < len(batch_results) else {'confidence': 50}
                
                ai_confidence = ai_result.get('confidence', 50)
                final_confidence = self._blend_confidence(
                    rule_based=rule_based_confidence,
                    ai_confidence=ai_confidence
                )
                
                confidence_sum += final_confidence
                
                # Store result in database
                result_record = AIAnalysisResult(
                    case_id=self.case_id,
                    analysis_id=self.analysis_id,
                    pattern_id=pattern_id,
                    pattern_name=pattern_name,
                    correlation_key=window['correlation_key'],
                    window_start=window['window_start'],
                    window_end=window['window_end'],
                    rule_based_confidence=rule_based_confidence,
                    ai_confidence=ai_confidence,
                    ai_reasoning=ai_result.get('reasoning'),
                    ai_indicators_found=ai_result.get('indicators_found'),
                    ai_iocs=ai_result.get('iocs'),
                    ai_false_positive_assessment=ai_result.get('false_positive_assessment'),
                    final_confidence=final_confidence,
                    events_analyzed=len(window['candidates']),
                    model_used=self.model,
                    analysis_duration_ms=duration_ms // len(batch_windows)
                )
                db.session.add(result_record)
                
                results.append({
                    'correlation_key': window['correlation_key'],
                    'window_start': window['window_start'],
                    'window_end': window['window_end'],
                    'events_analyzed': len(window['candidates']),
                    'rule_based_confidence': rule_based_confidence,
                    'ai_confidence': ai_confidence,
                    'final_confidence': final_confidence,
                    'ai_reasoning': ai_result.get('reasoning'),
                'indicators_found': ai_result.get('indicators_found', []),
                'iocs': ai_result.get('iocs', []),
                'false_positive_assessment': ai_result.get('false_positive_assessment'),
                'checklist_results': ai_result.get('checklist_results', {})
            })
            
            self._stats['windows_analyzed'] += 1
        
        db.session.commit()
        
        # Calculate average confidence
        if results:
            self._stats['avg_confidence'] = confidence_sum / len(results)
        
        logger.info(
            f"[AIAnalyzer] Completed {len(results)} analyses for {pattern_name} "
            f"(avg confidence: {self._stats['avg_confidence']:.1f}%)"
        )
        
        return results
    
    def _build_analysis_prompt(
        self,
        pattern_config: Dict,
        candidates: List,  # CandidateEventSet objects
        correlation_key: str
    ) -> str:
        """Build prompt for AI analysis
        
        Creates a structured prompt with:
        - Pattern definition and checklist
        - Correlation context
        - Formatted event data
        - Analysis instructions
        - Expected response format
        
        Args:
            pattern_config: Pattern definition
            candidates: List of CandidateEventSet objects
            correlation_key: Attack window identifier
            
        Returns:
            Formatted prompt string
        """
        pattern_name = pattern_config['name']
        checklist = pattern_config.get('checklist', [])
        description = pattern_config.get('description', '')
        
        # Separate events by role
        anchor_events = []
        supporting_events = []
        context_events = []
        
        for c in candidates:
            event_line = c.event_summary
            if c.role == 'anchor':
                anchor_events.append(f"  [ANCHOR] {event_line}")
            elif c.role == 'supporting':
                supporting_events.append(f"  [SUPPORTING] {event_line}")
            else:
                context_events.append(f"  [CONTEXT] {event_line}")
        
        # Build events section
        events_section = "ANCHOR EVENTS (Primary Attack Indicators):\n"
        events_section += "\n".join(anchor_events[:25]) if anchor_events else "  None found"
        
        events_section += "\n\nSUPPORTING EVENTS (Corroborating Evidence):\n"
        events_section += "\n".join(supporting_events[:25]) if supporting_events else "  None found"
        
        if context_events:
            events_section += "\n\nCONTEXT EVENTS (Additional Information):\n"
            events_section += "\n".join(context_events[:10])
        
        # Format checklist
        checklist_text = "\n".join(f"  {i+1}. {item}" for i, item in enumerate(checklist))
        
        # Calculate time span
        timestamps = [c.event_timestamp for c in candidates]
        time_span = (max(timestamps) - min(timestamps)).total_seconds() / 60  # minutes
        
        prompt = f"""Analyze these Windows security events to determine if they indicate a **{pattern_name}** attack.

═══════════════════════════════════════════════════════════════════════════════
ATTACK PATTERN DEFINITION
═══════════════════════════════════════════════════════════════════════════════
Pattern: {pattern_name}
{description if description else ''}

DETECTION CHECKLIST - Review each item against the evidence:
{checklist_text}

═══════════════════════════════════════════════════════════════════════════════
ATTACK WINDOW CONTEXT
═══════════════════════════════════════════════════════════════════════════════
Correlation Key: {correlation_key}
Total Events: {len(candidates)}
Time Span: {time_span:.1f} minutes
First Event: {min(timestamps)}
Last Event: {max(timestamps)}

═══════════════════════════════════════════════════════════════════════════════
SECURITY EVENTS
═══════════════════════════════════════════════════════════════════════════════
{events_section}

═══════════════════════════════════════════════════════════════════════════════
ANALYSIS INSTRUCTIONS
═══════════════════════════════════════════════════════════════════════════════
1. Review ANCHOR events for definitive attack indicators
2. Check if SUPPORTING events corroborate the attack hypothesis
3. Apply each checklist item to the evidence
4. Consider legitimate activities that could cause similar events:
   - Scheduled admin tasks
   - Automated monitoring systems
   - Software deployment tools
   - IT support activities
5. Identify specific IOCs (IP addresses, hostnames, usernames, tools, processes)
6. Assess the likelihood this is a false positive

Respond with a JSON object (no markdown, no extra text):
{{
    "confidence": <0-100 integer - your confidence this is a true attack>,
    "reasoning": "<2-4 sentence explanation citing specific evidence>",
    "indicators_found": [
        "<specific indicator 1 with evidence from events>",
        "<specific indicator 2 with evidence from events>"
    ],
    "iocs": [
        "<IP address, hostname, username, tool, or hash found>"
    ],
    "false_positive_assessment": "<explanation of FP likelihood and reasoning>",
    "checklist_results": {{
        "<checklist item 1>": true/false,
        "<checklist item 2>": true/false
    }}
}}"""

        return prompt
    
    def _run_ai_analysis(
        self,
        prompt: str,
        pattern_config: Dict
    ) -> Dict[str, Any]:
        """Run AI analysis and parse response
        
        Handles:
        - API call with retry
        - JSON parsing with fallbacks
        - Error handling
        
        Args:
            prompt: Analysis prompt
            pattern_config: Pattern definition (for error context)
            
        Returns:
            Parsed analysis result dict
        """
        try:
            result = self.client.generate_json(
                prompt=prompt,
                system=self.SYSTEM_PROMPT,
                temperature=self.temperature
            )
            
            if result.get('success') and result.get('data'):
                data = result['data']
                
                # Validate required fields
                if 'confidence' not in data:
                    data['confidence'] = 50
                if 'reasoning' not in data:
                    data['reasoning'] = 'No reasoning provided'
                if 'indicators_found' not in data:
                    data['indicators_found'] = []
                if 'iocs' not in data:
                    data['iocs'] = []
                    
                # Ensure confidence is integer 0-100
                data['confidence'] = max(0, min(100, int(data['confidence'])))
                
                return data
            else:
                error_msg = result.get('error', 'Unknown error')
                logger.warning(f"[AIAnalyzer] AI analysis failed: {error_msg}")
                
                # Try to extract from raw response if JSON parsing failed
                raw = result.get('raw_response', '')
                if raw:
                    return self._parse_fallback_response(raw)
                
                return self._get_neutral_result(error_msg)
                
        except Exception as e:
            logger.error(f"[AIAnalyzer] Exception in AI analysis: {e}")
            return self._get_neutral_result(str(e))
    
    def _build_batched_analysis_prompt(
        self,
        pattern_config: Dict,
        windows: List[Dict]
    ) -> str:
        """Build prompt for batched AI analysis of multiple windows
        
        Args:
            pattern_config: Pattern definition
            windows: List of window dicts with 'correlation_key', 'candidates', etc.
            
        Returns:
            Formatted prompt string for batch analysis
        """
        pattern_name = pattern_config['name']
        checklist = pattern_config.get('checklist', [])
        description = pattern_config.get('description', '')
        
        # Build checklist section
        checklist_text = "\n".join(f"  - {item}" for item in checklist) if checklist else "  No specific checklist"
        
        # Build windows section
        windows_section = ""
        for idx, window in enumerate(windows):
            windows_section += f"\n--- WINDOW {idx + 1}: {window['correlation_key']} ---\n"
            
            anchor_events = []
            supporting_events = []
            
            for c in window['candidates'][:20]:  # Limit events per window
                event_line = c.event_summary
                if c.role == 'anchor':
                    anchor_events.append(f"  [ANCHOR] {event_line}")
                elif c.role == 'supporting':
                    supporting_events.append(f"  [SUPPORTING] {event_line}")
            
            windows_section += "ANCHORS:\n"
            windows_section += "\n".join(anchor_events[:10]) if anchor_events else "  None"
            windows_section += "\nSUPPORTING:\n"
            windows_section += "\n".join(supporting_events[:10]) if supporting_events else "  None"
            windows_section += "\n"
        
        prompt = f"""Analyze these {len(windows)} attack windows for {pattern_name} pattern.

PATTERN: {pattern_name}
DESCRIPTION: {description}

CHECKLIST (indicators to verify):
{checklist_text}

{windows_section}

For EACH window, determine if it represents a true {pattern_name} attack.

Respond with a JSON array containing one object per window, in order:
[
  {{
    "window": 1,
    "confidence": <0-100>,
    "reasoning": "<brief explanation>",
    "indicators_found": ["list", "of", "matched", "checklist", "items"],
    "iocs": ["specific", "IOCs", "found"],
    "false_positive_assessment": "<why this might be legitimate>"
  }},
  ...
]

IMPORTANT: Return ONLY valid JSON array. No markdown, no explanation outside JSON."""
        
        return prompt
    
    def _run_batched_ai_analysis(
        self,
        prompt: str,
        pattern_config: Dict,
        expected_count: int
    ) -> List[Dict[str, Any]]:
        """Run batched AI analysis and parse array response
        
        Args:
            prompt: Batched analysis prompt
            pattern_config: Pattern definition
            expected_count: Number of windows in batch
            
        Returns:
            List of parsed analysis results
        """
        try:
            result = self.client.generate_json(
                prompt=prompt,
                system=self.SYSTEM_PROMPT,
                temperature=self.temperature
            )
            
            if result.get('success') and result.get('data'):
                data = result['data']
                
                # Handle if response is wrapped in an object (e.g., {"windows": [...]})
                if isinstance(data, dict):
                    # Try to extract array from common wrapper keys
                    for key in ['windows', 'results', 'analyses', 'data', 'items']:
                        if key in data and isinstance(data[key], list):
                            data = data[key]
                            break
                    else:
                        # No array found, treat the dict as a single result
                        data = [data]
                
                if isinstance(data, list):
                    # Validate and normalize each result
                    normalized = []
                    for item in data:
                        if not isinstance(item, dict):
                            item = {}
                        item['confidence'] = max(0, min(100, int(item.get('confidence', 50))))
                        item['reasoning'] = item.get('reasoning', 'No reasoning provided')
                        item['indicators_found'] = item.get('indicators_found', [])
                        item['iocs'] = item.get('iocs', [])
                        item['false_positive_assessment'] = item.get('false_positive_assessment', '')
                        normalized.append(item)
                    
                    # Pad with neutral results if needed
                    while len(normalized) < expected_count:
                        normalized.append(self._get_neutral_result('No result for this window'))
                    
                    return normalized
                else:
                    logger.warning(f"[AIAnalyzer] Batched response not an array: {type(data)}")
                    return [self._get_neutral_result('Invalid response format')] * expected_count
            else:
                error_msg = result.get('error', 'Unknown error')
                logger.warning(f"[AIAnalyzer] Batched AI analysis failed: {error_msg}")
                return [self._get_neutral_result(error_msg)] * expected_count
                
        except Exception as e:
            logger.error(f"[AIAnalyzer] Exception in batched AI analysis: {e}")
            return [self._get_neutral_result(str(e))] * expected_count
    
    def _parse_fallback_response(self, raw_response: str) -> Dict[str, Any]:
        """Attempt to parse a malformed AI response
        
        Tries various strategies to extract useful information
        from responses that didn't parse as valid JSON.
        
        Args:
            raw_response: Raw text from AI
            
        Returns:
            Best-effort parsed result
        """
        result = self._get_neutral_result('Parsed from non-JSON response')
        
        # Try to find JSON block in response
        import re
        json_match = re.search(r'\{[\s\S]*\}', raw_response)
        if json_match:
            try:
                data = json.loads(json_match.group())
                if isinstance(data.get('confidence'), (int, float)):
                    result['confidence'] = max(0, min(100, int(data['confidence'])))
                if data.get('reasoning'):
                    result['reasoning'] = str(data['reasoning'])
                if isinstance(data.get('indicators_found'), list):
                    result['indicators_found'] = data['indicators_found']
                if isinstance(data.get('iocs'), list):
                    result['iocs'] = data['iocs']
            except json.JSONDecodeError:
                pass
        
        # Try to extract confidence from text
        if result['confidence'] == 50:
            confidence_match = re.search(r'confidence["\s:]+(\d+)', raw_response, re.I)
            if confidence_match:
                result['confidence'] = max(0, min(100, int(confidence_match.group(1))))
        
        return result
    
    def _get_neutral_result(self, error_msg: str) -> Dict[str, Any]:
        """Get neutral/uncertain result for error cases
        
        Args:
            error_msg: Error message to include
            
        Returns:
            Neutral analysis result
        """
        return {
            'confidence': 50,
            'reasoning': f'AI analysis incomplete: {error_msg}. Using neutral confidence.',
            'indicators_found': [],
            'iocs': [],
            'false_positive_assessment': 'Unable to assess due to analysis error',
            'checklist_results': {}
        }
    
    def _blend_confidence(
        self,
        rule_based: float = None,
        ai_confidence: float = 50
    ) -> float:
        """Blend rule-based and AI confidence scores
        
        Weighting strategy:
        - Very high rule-based (>85): Trust rules more (60% rule, 40% AI)
        - Low rule-based (<50): Trust AI more (30% rule, 70% AI)
        - Medium: Equal weight (50/50)
        - No rule-based: Use AI only
        
        Args:
            rule_based: Pre-computed rule-based confidence (0-100)
            ai_confidence: AI-determined confidence (0-100)
            
        Returns:
            Blended confidence score (0-100)
        """
        if rule_based is None:
            return float(ai_confidence)
        
        if rule_based > 85:
            # High rule-based confidence - rules are more specific
            blended = 0.6 * rule_based + 0.4 * ai_confidence
        elif rule_based < 50:
            # Low rule-based confidence - AI may catch nuances
            blended = 0.3 * rule_based + 0.7 * ai_confidence
        else:
            # Balanced case
            blended = 0.5 * rule_based + 0.5 * ai_confidence
        
        return round(blended, 1)
    
    def analyze_attack_chain(
        self,
        pattern_results: List[Dict],
        time_window_minutes: int = 120
    ) -> Dict[str, Any]:
        """Analyze multiple pattern matches for attack chain correlation
        
        Looks for patterns that could be part of the same attack:
        - Same user/host across patterns
        - Temporal proximity
        - MITRE tactic progression (e.g., Initial Access → Execution → Persistence)
        
        Args:
            pattern_results: List of analysis results from different patterns
            time_window_minutes: Maximum gap between related events
            
        Returns:
            Attack chain analysis
        """
        if len(pattern_results) < 2:
            return {
                'chain_detected': False,
                'reason': 'Insufficient patterns for chain analysis'
            }
        
        # Group by correlation key components (host/user)
        chains = {}
        
        for result in pattern_results:
            if result['final_confidence'] < 60:
                continue
                
            key_parts = result['correlation_key'].split('|')
            host = key_parts[0] if key_parts else 'unknown'
            user = key_parts[1] if len(key_parts) > 1 else 'unknown'
            
            chain_key = f"{host}|{user}"
            if chain_key not in chains:
                chains[chain_key] = []
            chains[chain_key].append(result)
        
        # Find chains with multiple patterns
        attack_chains = []
        for chain_key, matches in chains.items():
            if len(matches) >= 2:
                # Sort by time
                matches.sort(key=lambda x: x['window_start'])
                
                # Check temporal proximity
                valid_chain = True
                for i in range(1, len(matches)):
                    gap = (matches[i]['window_start'] - matches[i-1]['window_end']).total_seconds() / 60
                    if gap > time_window_minutes:
                        valid_chain = False
                        break
                
                if valid_chain:
                    attack_chains.append({
                        'correlation_key': chain_key,
                        'patterns': [m['pattern_name'] for m in matches],
                        'start_time': matches[0]['window_start'],
                        'end_time': matches[-1]['window_end'],
                        'avg_confidence': sum(m['final_confidence'] for m in matches) / len(matches)
                    })
        
        return {
            'chain_detected': len(attack_chains) > 0,
            'chains': attack_chains,
            'total_chains': len(attack_chains)
        }
    
    def get_stats(self) -> Dict[str, Any]:
        """Get analysis statistics
        
        Returns:
            Dict with analysis metrics
        """
        stats = self._stats.copy()
        if stats['ai_calls'] > 0:
            stats['avg_duration_ms'] = stats['total_duration_ms'] / stats['ai_calls']
        return stats
    
    def _build_behavioral_context_section(self, behavioral_context: Dict) -> str:
        """Build behavioral context section for AI prompt
        
        Args:
            behavioral_context: Behavioral analysis data
            
        Returns:
            Formatted string for prompt inclusion
        """
        if not behavioral_context:
            return ""
        
        sections = []
        
        user_ctx = behavioral_context.get('user')
        if user_ctx:
            user_section = "USER BEHAVIORAL PROFILE:\n"
            user_section += f"  - Average daily logons: {user_ctx.get('avg_daily_logons', 'N/A')}\n"
            user_section += f"  - Failure rate: {user_ctx.get('failure_rate', 'N/A')}\n"
            user_section += f"  - Off-hours activity: {user_ctx.get('off_hours_percentage', 'N/A')}\n"
            
            z_scores = user_ctx.get('z_scores', {})
            if z_scores:
                user_section += "  - Peer comparison z-scores:\n"
                for metric, z in z_scores.items():
                    deviation = "ANOMALOUS" if abs(z) >= 3 else "normal"
                    user_section += f"      {metric}: {z:.2f} ({deviation})\n"
            
            sections.append(user_section)
        
        system_ctx = behavioral_context.get('system')
        if system_ctx:
            system_section = "SYSTEM BEHAVIORAL PROFILE:\n"
            system_section += f"  - System role: {system_ctx.get('system_role', 'N/A')}\n"
            system_section += f"  - Unique users: {system_ctx.get('unique_users', 'N/A')}\n"
            
            z_scores = system_ctx.get('z_scores', {})
            if z_scores:
                system_section += "  - Peer comparison z-scores:\n"
                for metric, z in z_scores.items():
                    deviation = "ANOMALOUS" if abs(z) >= 3 else "normal"
                    system_section += f"      {metric}: {z:.2f} ({deviation})\n"
            
            sections.append(system_section)
        
        anomaly_flags = behavioral_context.get('anomaly_flags', [])
        if anomaly_flags:
            sections.append("BEHAVIORAL ANOMALIES DETECTED:\n" + 
                          "\n".join(f"  - {flag}" for flag in anomaly_flags))
        
        if not sections:
            return ""
        
        return "\n═══════════════════════════════════════════════════════════════════════════════\n" + \
               "BEHAVIORAL CONTEXT (from baseline profiling)\n" + \
               "═══════════════════════════════════════════════════════════════════════════════\n" + \
               "\n".join(sections)
    
    def analyze_with_behavioral_context(
        self,
        pattern_config: Dict,
        behavioral_context: Dict = None,
        rule_based_confidence: float = None,
        max_events_per_window: int = None
    ) -> List[Dict[str, Any]]:
        """Analyze pattern with enhanced behavioral context
        
        Same as analyze_pattern but includes behavioral context in AI prompt.
        
        Args:
            pattern_config: Pattern definition with checklist
            behavioral_context: Behavioral analysis data
            rule_based_confidence: Pre-computed rule-based score
            max_events_per_window: Max events to include
            
        Returns:
            List of analysis results with behavioral enrichment
        """
        # Store behavioral context for prompt building
        self._current_behavioral_context = behavioral_context
        
        # Run standard analysis
        results = self.analyze_pattern(
            pattern_config=pattern_config,
            rule_based_confidence=rule_based_confidence,
            max_events_per_window=max_events_per_window
        )
        
        # Apply behavioral confidence modifiers
        if behavioral_context:
            modifier = behavioral_context.get('confidence_modifier', 0)
            for result in results:
                result['behavioral_modifier'] = modifier
                result['final_confidence'] = max(0, min(100, 
                    result['final_confidence'] + modifier))
                result['behavioral_context'] = behavioral_context
        
        return results
    
    def analyze_attack_chains_with_context(
        self,
        attack_chains: List,
        behavioral_profiles: Dict = None
    ) -> List[Dict]:
        """Analyze attack chains with behavioral and AI context
        
        Args:
            attack_chains: List of AttackChain objects from attack_chain_builder
            behavioral_profiles: Dict of entity -> profile data
            
        Returns:
            List of enhanced chain analysis results
        """
        from models.rag import AIAnalysisResult
        
        results = []
        
        for chain in attack_chains:
            chain_dict = chain.to_dict() if hasattr(chain, 'to_dict') else chain
            
            # Build prompt for chain analysis
            prompt = self._build_chain_analysis_prompt(chain_dict)
            
            try:
                ai_result = self._run_ai_analysis(prompt, {'name': 'Attack Chain Analysis'})
                
                # Store result
                result_record = AIAnalysisResult(
                    case_id=self.case_id,
                    analysis_id=self.analysis_id,
                    pattern_id='attack_chain',
                    pattern_name=chain_dict.get('title', 'Attack Chain'),
                    correlation_key=chain_dict.get('chain_id', ''),
                    window_start=chain_dict.get('time_start'),
                    window_end=chain_dict.get('time_end'),
                    ai_confidence=ai_result.get('confidence', 50),
                    ai_reasoning=ai_result.get('reasoning'),
                    ai_indicators_found=ai_result.get('indicators_found'),
                    ai_iocs=ai_result.get('iocs'),
                    final_confidence=ai_result.get('confidence', 50),
                    events_analyzed=chain_dict.get('total_event_count', 0),
                    model_used=self.model
                )
                db.session.add(result_record)
                
                results.append({
                    'chain_id': chain_dict.get('chain_id'),
                    'title': chain_dict.get('title'),
                    'ai_analysis': ai_result,
                    'confidence': ai_result.get('confidence', 50)
                })
                
            except Exception as e:
                logger.error(f"Failed to analyze attack chain: {e}")
                results.append({
                    'chain_id': chain_dict.get('chain_id'),
                    'title': chain_dict.get('title'),
                    'ai_analysis': None,
                    'error': str(e)
                })
        
        db.session.commit()
        return results
    
    def _build_chain_analysis_prompt(self, chain_dict: Dict) -> str:
        """Build prompt for attack chain AI analysis"""
        
        prompt = f"""Analyze this attack chain and provide your assessment.

═══════════════════════════════════════════════════════════════════════════════
ATTACK CHAIN SUMMARY
═══════════════════════════════════════════════════════════════════════════════
Title: {chain_dict.get('title', 'Unknown')}
Severity: {chain_dict.get('severity', 'unknown')}
Time Span: {chain_dict.get('time_start')} to {chain_dict.get('time_end')}
Duration: {chain_dict.get('duration_seconds', 0)} seconds

MITRE ATT&CK Tactics: {', '.join(chain_dict.get('tactics_observed', []))}
MITRE ATT&CK Techniques: {', '.join(chain_dict.get('techniques_observed', [])[:10])}

Kill Chain Phases Covered: {', '.join(chain_dict.get('phases_covered', []))}

═══════════════════════════════════════════════════════════════════════════════
ENTITIES INVOLVED
═══════════════════════════════════════════════════════════════════════════════
Primary User: {chain_dict.get('primary_user', 'N/A')}
Primary Host: {chain_dict.get('primary_host', 'N/A')}
All Users: {', '.join(chain_dict.get('involved_users', [])[:5])}
All Hosts: {', '.join(chain_dict.get('involved_hosts', [])[:5])}
Source IPs: {', '.join(chain_dict.get('involved_ips', [])[:5])}

═══════════════════════════════════════════════════════════════════════════════
DETECTION SUMMARY
═══════════════════════════════════════════════════════════════════════════════
Detection Groups: {chain_dict.get('detection_group_count', 0)}
Total Events: {chain_dict.get('total_event_count', 0)}
"""

        # Add behavioral anomalies if present
        anomalies = chain_dict.get('behavioral_anomalies', [])
        if anomalies:
            prompt += f"""
═══════════════════════════════════════════════════════════════════════════════
BEHAVIORAL ANOMALIES
═══════════════════════════════════════════════════════════════════════════════
{chr(10).join('- ' + a for a in anomalies[:10])}
"""

        prompt += """
═══════════════════════════════════════════════════════════════════════════════
ANALYSIS INSTRUCTIONS
═══════════════════════════════════════════════════════════════════════════════
1. Assess whether this represents a real attack or potential false positive
2. Evaluate the severity based on tactics and entities involved
3. Identify the likely attack objective
4. Recommend immediate investigation steps

Respond with JSON only:
{
    "confidence": <0-100>,
    "reasoning": "<2-4 sentence analysis>",
    "attack_objective": "<likely goal of the attack>",
    "indicators_found": ["<key indicator 1>", "<key indicator 2>"],
    "iocs": ["<IOC 1>", "<IOC 2>"],
    "false_positive_assessment": "<FP likelihood and reasoning>",
    "investigation_priority": "<critical|high|medium|low>",
    "recommended_actions": ["<action 1>", "<action 2>"]
}"""
        
        return prompt


class RuleBasedAnalyzer:
    """Mode A/C analyzer: Pure rule-based analysis without AI
    
    Used when AI is disabled or unavailable. Provides structured
    findings based on pattern criteria and behavioral factors.
    """
    
    def __init__(self, case_id: int, analysis_id: str):
        self.case_id = case_id
        self.analysis_id = analysis_id
    
    def analyze_without_ai(
        self,
        candidates: list,
        pattern_config: dict,
        behavioral_context: dict = None
    ) -> dict:
        """
        Mode A/C path: Pure rule-based analysis without AI.
        
        Returns structured finding with:
        - Confidence score (calculated from criteria + behavioral factors)
        - Criteria checklist (which indicators matched)
        - Behavioral context summary
        - No AI reasoning (field set to None)
        
        Args:
            candidates: List of candidate events
            pattern_config: Pattern definition with checklist
            behavioral_context: Optional behavioral analysis data
            
        Returns:
            dict: Analysis result
        """
        pattern_name = pattern_config.get('name', 'Unknown')
        checklist = pattern_config.get('checklist', [])
        
        # Evaluate checklist items against candidates
        checklist_results = self._evaluate_checklist(candidates, checklist, pattern_config)
        
        # Calculate base confidence from checklist match rate
        matched_items = sum(1 for v in checklist_results.values() if v)
        total_items = len(checklist_results) if checklist_results else 1
        base_confidence = (matched_items / total_items) * 80  # Max 80 from rules
        
        # Apply behavioral modifier
        behavioral_modifier = 0
        if behavioral_context:
            behavioral_modifier = behavioral_context.get('confidence_modifier', 0)
        
        final_confidence = max(0, min(100, base_confidence + behavioral_modifier))
        
        # Build indicators found
        indicators_found = [
            item for item, matched in checklist_results.items() if matched
        ]
        
        # Extract IOCs from candidates
        iocs = self._extract_iocs(candidates)
        
        # Build result
        return {
            'confidence': final_confidence,
            'reasoning': None,  # No AI reasoning
            'indicators_found': indicators_found,
            'iocs': iocs,
            'false_positive_assessment': self._assess_false_positive(
                candidates, pattern_config, behavioral_context
            ),
            'checklist_results': checklist_results,
            'behavioral_context': behavioral_context,
            'analysis_mode': 'rule_based'
        }
    
    def _evaluate_checklist(
        self,
        candidates: list,
        checklist: list,
        pattern_config: dict
    ) -> dict:
        """Evaluate checklist items against candidate events"""
        results = {}
        
        # Build aggregated view of candidates
        event_ids = set()
        usernames = set()
        hosts = set()
        processes = set()
        logon_types = set()
        auth_packages = set()
        
        for c in candidates:
            if hasattr(c, 'event_id'):
                event_ids.add(str(c.event_id))
            elif isinstance(c, dict):
                event_ids.add(str(c.get('event_id', '')))
            
            if hasattr(c, 'username'):
                usernames.add(c.username)
            elif isinstance(c, dict):
                usernames.add(c.get('username', ''))
            
            if hasattr(c, 'source_host'):
                hosts.add(c.source_host)
            elif isinstance(c, dict):
                hosts.add(c.get('source_host', ''))
            
            if hasattr(c, 'process_name'):
                processes.add(c.process_name)
            elif isinstance(c, dict):
                processes.add(c.get('process_name', ''))
        
        # Simple heuristic evaluation for common checklist patterns
        for item in checklist:
            item_lower = item.lower()
            
            # Default to False
            matched = False
            
            # Check for event ID mentions
            if 'event' in item_lower or '4624' in item or '4625' in item:
                for eid in ['4624', '4625', '4768', '4769', '4776', '4672']:
                    if eid in item and eid in event_ids:
                        matched = True
                        break
            
            # Check for logon type mentions
            if 'logon type' in item_lower or 'type 3' in item_lower or 'type 9' in item_lower:
                if '3' in str(logon_types) or '9' in str(logon_types):
                    matched = True
            
            # Check for NTLM mentions
            if 'ntlm' in item_lower:
                if any('ntlm' in str(a).lower() for a in auth_packages):
                    matched = True
            
            # Check for admin/privilege mentions
            if 'admin' in item_lower or 'privilege' in item_lower:
                if any('admin' in u.lower() for u in usernames if u):
                    matched = True
            
            # Check for process mentions
            if 'process' in item_lower or 'command' in item_lower:
                if processes:
                    matched = True
            
            # If we have anchor events, assume some basic matching
            anchor_count = sum(1 for c in candidates if 
                              (hasattr(c, 'role') and c.role == 'anchor') or
                              (isinstance(c, dict) and c.get('role') == 'anchor'))
            if anchor_count > 0 and 'anchor' not in item_lower:
                # Has anchors, give benefit of doubt for generic items
                matched = True
            
            results[item] = matched
        
        return results
    
    def _extract_iocs(self, candidates: list) -> list:
        """Extract IOCs from candidate events"""
        iocs = set()
        
        for c in candidates:
            if isinstance(c, dict):
                if c.get('src_ip') and c['src_ip'] not in ['', '0.0.0.0', '::']:
                    iocs.add(c['src_ip'])
                if c.get('username') and not c['username'].endswith('$'):
                    iocs.add(c['username'])
                if c.get('source_host'):
                    iocs.add(c['source_host'])
            elif hasattr(c, 'src_ip') and c.src_ip:
                iocs.add(str(c.src_ip))
        
        return list(iocs)[:10]
    
    def _assess_false_positive(
        self,
        candidates: list,
        pattern_config: dict,
        behavioral_context: dict = None
    ) -> str:
        """Assess false positive likelihood based on patterns"""
        fp_indicators = []
        
        # Check for scheduled/automated indicators
        for c in candidates:
            summary = ''
            if isinstance(c, dict):
                summary = c.get('event_summary', '') or c.get('search_summary', '')
            elif hasattr(c, 'event_summary'):
                summary = c.event_summary or ''
            
            summary_lower = summary.lower()
            
            if 'scheduled' in summary_lower or 'task' in summary_lower:
                fp_indicators.append('Scheduled task activity detected')
            if 'backup' in summary_lower:
                fp_indicators.append('Backup process detected')
            if 'monitor' in summary_lower or 'scan' in summary_lower:
                fp_indicators.append('Monitoring/scanning activity detected')
        
        # Check behavioral context
        if behavioral_context:
            modifier = behavioral_context.get('confidence_modifier', 0)
            if modifier < -5:
                fp_indicators.append('Activity matches normal baseline')
        
        if fp_indicators:
            return f"Possible false positive: {'; '.join(fp_indicators[:3])}"
        
        return "No obvious false positive indicators"


class BatchAIAnalyzer:
    """Batch analyzer for processing multiple patterns efficiently
    
    Optimizes AI usage by:
    - Batching similar patterns
    - Caching common context
    - Parallel processing where possible
    """
    
    def __init__(
        self,
        case_id: int,
        analysis_id: str,
        model: str = None
    ):
        self.case_id = case_id
        self.analysis_id = analysis_id
        self.model = model or Config.OLLAMA_MODEL
        
    def analyze_all_patterns(
        self,
        pattern_configs: Dict[str, Dict],
        rule_based_scores: Dict[str, float] = None
    ) -> Dict[str, List[Dict]]:
        """Analyze all patterns in batch
        
        Args:
            pattern_configs: Dict of pattern_id -> pattern_config
            rule_based_scores: Optional dict of pattern_id -> rule score
            
        Returns:
            Dict of pattern_id -> list of analysis results
        """
        all_results = {}
        
        for pattern_id, config in pattern_configs.items():
            config['id'] = pattern_id
            analyzer = AICorrelationAnalyzer(
                case_id=self.case_id,
                analysis_id=self.analysis_id,
                model=self.model
            )
            
            rule_score = rule_based_scores.get(pattern_id) if rule_based_scores else None
            
            results = analyzer.analyze_pattern(
                pattern_config=config,
                rule_based_confidence=rule_score
            )
            
            all_results[pattern_id] = results
        
        return all_results
