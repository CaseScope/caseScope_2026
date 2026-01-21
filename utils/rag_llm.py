"""RAG LLM Integration for CaseScope

Provides Ollama LLM integration for pattern analysis and timeline generation.
Includes retry logic for transient failures.
"""

import logging
import json
import time
import threading
import requests
from typing import Dict, Any, Optional, List

from config import Config

logger = logging.getLogger(__name__)


class OllamaClient:
    """Client for interacting with Ollama LLM with retry support"""
    
    def __init__(self, host: str = None, model: str = None):
        self.host = host or Config.OLLAMA_HOST
        self.model = model or Config.OLLAMA_MODEL
        self.timeout = 180  # 3 minutes for long responses
        self.max_retries = getattr(Config, 'OLLAMA_MAX_RETRIES', 3)
        self.retry_delay = getattr(Config, 'OLLAMA_RETRY_DELAY', 1.0)
    
    def _retry_request(self, func, *args, **kwargs) -> requests.Response:
        """Execute request with exponential backoff retry
        
        Args:
            func: Request function to call
            *args, **kwargs: Arguments for the function
            
        Returns:
            Response object
            
        Raises:
            Last exception if all retries fail
        """
        last_exception = None
        
        for attempt in range(self.max_retries):
            try:
                response = func(*args, **kwargs)
                response.raise_for_status()
                return response
            except requests.exceptions.Timeout as e:
                last_exception = e
                if attempt < self.max_retries - 1:
                    delay = self.retry_delay * (2 ** attempt)
                    logger.warning(f"[RAG LLM] Timeout, retrying in {delay}s (attempt {attempt + 1}/{self.max_retries})")
                    time.sleep(delay)
            except requests.exceptions.ConnectionError as e:
                last_exception = e
                if attempt < self.max_retries - 1:
                    delay = self.retry_delay * (2 ** attempt)
                    logger.warning(f"[RAG LLM] Connection error, retrying in {delay}s (attempt {attempt + 1}/{self.max_retries})")
                    time.sleep(delay)
            except requests.exceptions.HTTPError as e:
                # Don't retry on HTTP errors (4xx, 5xx)
                raise
        
        raise last_exception
    
    def generate(
        self,
        prompt: str,
        system: str = None,
        format: str = None,
        temperature: float = 0.7,
        max_tokens: int = 2000
    ) -> Dict[str, Any]:
        """Generate a response from the LLM with retry support
        
        Args:
            prompt: User prompt
            system: System prompt (optional)
            format: Response format ('json' for JSON mode)
            temperature: Sampling temperature
            max_tokens: Maximum tokens to generate
            
        Returns:
            Dict with 'response' and metadata
        """
        try:
            url = f"{self.host}/api/generate"
            
            payload = {
                'model': self.model,
                'prompt': prompt,
                'stream': False,
                'options': {
                    'temperature': temperature,
                    'num_predict': max_tokens
                }
            }
            
            if system:
                payload['system'] = system
            
            if format == 'json':
                payload['format'] = 'json'
            
            response = self._retry_request(
                requests.post,
                url,
                json=payload,
                timeout=self.timeout
            )
            
            result = response.json()
            
            return {
                'success': True,
                'response': result.get('response', ''),
                'model': result.get('model'),
                'total_duration': result.get('total_duration'),
                'eval_count': result.get('eval_count')
            }
            
        except requests.exceptions.Timeout:
            logger.error(f"[RAG LLM] Request timed out after {self.max_retries} attempts")
            return {'success': False, 'error': 'Request timed out after retries'}
        except requests.exceptions.ConnectionError:
            logger.error(f"[RAG LLM] Cannot connect to Ollama at {self.host} after {self.max_retries} attempts")
            return {'success': False, 'error': f'Cannot connect to Ollama at {self.host}'}
        except Exception as e:
            logger.error(f"[RAG LLM] Error: {e}")
            return {'success': False, 'error': str(e)}
    
    def generate_json(
        self,
        prompt: str,
        system: str = None,
        temperature: float = 0.3
    ) -> Dict[str, Any]:
        """Generate a JSON response from the LLM
        
        Args:
            prompt: User prompt
            system: System prompt
            temperature: Lower for more deterministic JSON
            
        Returns:
            Parsed JSON response or error dict
        """
        result = self.generate(
            prompt=prompt,
            system=system,
            format='json',
            temperature=temperature
        )
        
        if not result.get('success'):
            return result
        
        try:
            parsed = json.loads(result['response'])
            return {
                'success': True,
                'data': parsed,
                'model': result.get('model')
            }
        except json.JSONDecodeError as e:
            logger.warning(f"[RAG LLM] Failed to parse JSON response: {e}")
            return {
                'success': False,
                'error': 'Failed to parse JSON response',
                'raw_response': result['response']
            }
    
    def health_check(self) -> Dict[str, Any]:
        """Check Ollama health and model availability
        
        Returns:
            Dict with status info
        """
        try:
            # Check if Ollama is running
            url = f"{self.host}/api/tags"
            response = requests.get(url, timeout=5)
            response.raise_for_status()
            
            models = response.json().get('models', [])
            model_names = [m.get('name') for m in models]
            
            # Check if our model is available
            model_available = any(self.model in name for name in model_names)
            
            return {
                'status': 'healthy' if model_available else 'model_missing',
                'host': self.host,
                'model': self.model,
                'model_available': model_available,
                'available_models': model_names[:5]  # First 5
            }
            
        except requests.exceptions.ConnectionError:
            return {
                'status': 'offline',
                'host': self.host,
                'error': 'Cannot connect to Ollama'
            }
        except Exception as e:
            return {
                'status': 'error',
                'host': self.host,
                'error': str(e)
            }


# Module-level client instance with thread-safe initialization
_ollama_client = None
_ollama_lock = threading.Lock()


def get_ollama_client() -> OllamaClient:
    """Get or create Ollama client instance (thread-safe)"""
    global _ollama_client
    
    if _ollama_client is None:
        with _ollama_lock:
            # Double-check after acquiring lock
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
    client = get_ollama_client()
    
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

    system = """You are a security analyst assistant. Analyze the provided security events 
and give concise, actionable forensic insights. Be specific about what the events indicate."""

    result = client.generate_json(prompt, system=system)
    
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
    client = get_ollama_client()
    
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

    system = """You are an incident response analyst creating a timeline narrative. 
Be concise and focus on the attacker's actions and objectives."""

    result = client.generate_json(prompt, system=system)
    
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
    client = get_ollama_client()
    
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

    result = client.generate(prompt, temperature=0.5, max_tokens=500)
    
    if result.get('success'):
        return result.get('response', 'Analysis complete. Review timeline phases for details.')
    else:
        return f"Incident timeline generated with {len(timeline_phases)} phases. Review each phase for detailed findings."


def health_check() -> Dict[str, Any]:
    """Check LLM health"""
    return get_ollama_client().health_check()
