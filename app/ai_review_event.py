"""
AI Event Review Module

Provides AI-powered event analysis using Ollama (DFIR-Mistral).
Called when users click the AI review button on search results.

Author: CaseScope 2026
Version: 1.0.0
"""

import requests
import json
import logging
from typing import Dict, Any

logger = logging.getLogger(__name__)


def review_event_with_ai(event_data: dict, model: str = 'dfir-mistral:latest') -> dict:
    """
    Send event data to Ollama for AI analysis.
    
    Args:
        event_data: The event source data from OpenSearch
        model: The Ollama model to use (default: dfir-mistral:latest)
        
    Returns:
        dict: {
            'success': bool,
            'summary': str,  # AI-generated summary
            'error': str     # Error message if failed
        }
    """
    try:
        # Build a focused prompt for event analysis
        prompt = build_analysis_prompt(event_data)
        
        # Call Ollama API
        response = requests.post(
            'http://localhost:11434/api/generate',
            json={
                'model': model,
                'prompt': prompt,
                'stream': False
            },
            timeout=60  # 60 second timeout
        )
        
        if response.status_code != 200:
            return {
                'success': False,
                'error': f'Ollama API error: {response.status_code}'
            }
        
        result = response.json()
        
        if 'response' in result:
            return {
                'success': True,
                'summary': result['response'].strip()
            }
        else:
            return {
                'success': False,
                'error': f'Unexpected response format: {result}'
            }
            
    except requests.exceptions.Timeout:
        logger.error("Ollama request timed out")
        return {
            'success': False,
            'error': 'AI analysis timed out (60s limit). The model may be busy.'
        }
    except requests.exceptions.ConnectionError:
        logger.error("Could not connect to Ollama")
        return {
            'success': False,
            'error': 'Could not connect to Ollama. Is the service running?'
        }
    except Exception as e:
        logger.error(f"AI review error: {e}")
        return {
            'success': False,
            'error': str(e)
        }


def build_analysis_prompt(event_data: dict) -> str:
    """
    Build a focused analysis prompt from event data.
    
    Extracts key fields and builds a concise prompt for the AI.
    """
    # Extract key fields for analysis
    key_fields = {}
    
    # Process execution
    if 'process' in event_data:
        proc = event_data['process']
        if isinstance(proc, dict):
            key_fields['process_name'] = proc.get('name', 'N/A')
            key_fields['command_line'] = proc.get('command_line', 'N/A')
            key_fields['executable'] = proc.get('executable', 'N/A')
            
            # Parent process
            if 'parent' in proc and isinstance(proc['parent'], dict):
                key_fields['parent_name'] = proc['parent'].get('name', 'N/A')
                key_fields['parent_command'] = proc['parent'].get('command_line', 'N/A')
    
    # User context
    if 'user' in event_data:
        user = event_data['user']
        if isinstance(user, dict):
            key_fields['user_name'] = user.get('name', 'N/A')
            key_fields['user_domain'] = user.get('domain', 'N/A')
    
    # Host context
    if 'host' in event_data:
        host = event_data['host']
        if isinstance(host, dict):
            key_fields['hostname'] = host.get('hostname', 'N/A')
    
    # Computer name (top level)
    if 'normalized_computer' in event_data:
        key_fields['computer'] = event_data['normalized_computer']
    
    # Timestamp
    if 'normalized_timestamp' in event_data:
        key_fields['timestamp'] = event_data['normalized_timestamp']
    elif '@timestamp' in event_data:
        key_fields['timestamp'] = event_data['@timestamp']
    
    # Event type
    if 'source_file_type' in event_data:
        key_fields['event_type'] = event_data['source_file_type']
    
    # Build prompt
    prompt = """You are a cybersecurity analyst reviewing EDR telemetry. Analyze this event and provide a CONCISE summary.

Focus on:
1. What happened (1-2 sentences)
2. Suspicious indicators (if any)
3. Threat assessment (Low/Medium/High/Critical)
4. Recommended action (1 sentence)

Keep your response under 200 words. Be direct and actionable.

Event Data:
"""
    
    # Add key fields
    for field, value in key_fields.items():
        # Truncate long values
        if isinstance(value, str) and len(value) > 200:
            value = value[:200] + "..."
        prompt += f"\n{field}: {value}"
    
    prompt += "\n\nProvide your analysis:"
    
    return prompt


def get_available_models() -> list:
    """
    Get list of available Ollama models.
    
    Returns:
        list: Model names available for use
    """
    try:
        response = requests.get('http://localhost:11434/api/tags', timeout=5)
        if response.status_code == 200:
            data = response.json()
            return [model['name'] for model in data.get('models', [])]
        return []
    except Exception as e:
        logger.error(f"Error fetching models: {e}")
        return []

