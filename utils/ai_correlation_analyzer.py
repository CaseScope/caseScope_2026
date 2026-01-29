"""AI-Powered Correlation Analyzer

Uses LLM (DeepSeek-R1) to analyze candidate events 
and determine if they constitute true attack pattern matches.

This module provides Stage 4 of the AI correlation pipeline:
1. Build analysis prompt with event context
2. Run AI inference with pattern checklist
3. Parse AI response for confidence and reasoning
4. Blend rule-based and AI scores
5. Store analysis results

Usage:
    analyzer = AICorrelationAnalyzer(
        case_id=123,
        analysis_id='uuid',
        model='deepseek-r1:8b'
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
from utils.rag_llm import OllamaClient

logger = logging.getLogger(__name__)

# Hardcoded DeepSeek model
DEEPSEEK_MODEL = 'deepseek-r1:8b'
DEEPSEEK_TEMPERATURE = 0.3


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
            model: Ollama model name (defaults to DeepSeek)
            temperature: LLM temperature (lower = more consistent)
        """
        self.case_id = case_id
        self.analysis_id = analysis_id
        
        # Model configuration - hardcoded to DeepSeek
        self.model = model or DEEPSEEK_MODEL
        self.temperature = temperature or DEEPSEEK_TEMPERATURE
        
        # Initialize Ollama client with specified model
        self.client = OllamaClient(model=self.model)
        
        # Stats tracking
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
        
        logger.info(f"[AIAnalyzer] Found {len(correlation_keys)} attack windows to analyze")
        
        results = []
        confidence_sum = 0.0
        
        for (correlation_key,) in correlation_keys:
            # Get events for this correlation key
            candidates = CandidateEventSet.query.filter_by(
                analysis_id=self.analysis_id,
                pattern_id=pattern_id,
                correlation_key=correlation_key
            ).order_by(
                CandidateEventSet.event_timestamp.asc()
            ).limit(max_events).all()
            
            if not candidates:
                continue
            
            # Calculate time window
            timestamps = [c.event_timestamp for c in candidates]
            window_start = min(timestamps)
            window_end = max(timestamps)
            
            # Build AI analysis prompt
            prompt = self._build_analysis_prompt(
                pattern_config=pattern_config,
                candidates=candidates,
                correlation_key=correlation_key
            )
            
            # Run AI analysis
            start_time = time.time()
            ai_result = self._run_ai_analysis(prompt, pattern_config)
            duration_ms = int((time.time() - start_time) * 1000)
            
            self._stats['ai_calls'] += 1
            self._stats['total_duration_ms'] += duration_ms
            
            # Calculate final blended confidence
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
                correlation_key=correlation_key,
                window_start=window_start,
                window_end=window_end,
                rule_based_confidence=rule_based_confidence,
                ai_confidence=ai_confidence,
                ai_reasoning=ai_result.get('reasoning'),
                ai_indicators_found=ai_result.get('indicators_found'),
                ai_iocs=ai_result.get('iocs'),
                ai_false_positive_assessment=ai_result.get('false_positive_assessment'),
                final_confidence=final_confidence,
                events_analyzed=len(candidates),
                model_used=self.model,
                analysis_duration_ms=duration_ms
            )
            db.session.add(result_record)
            
            results.append({
                'correlation_key': correlation_key,
                'window_start': window_start,
                'window_end': window_end,
                'events_analyzed': len(candidates),
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
        self.model = model or DEEPSEEK_MODEL
        
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
