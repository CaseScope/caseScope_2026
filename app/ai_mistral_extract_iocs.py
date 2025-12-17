#!/usr/bin/env python3
"""
AI Mistral IOC Extraction Module

Extracts IOCs from EDR reports using the Mistral AI model with a structured prompt.
This module uses the prompt template from ai_prompts/mistral/mistral_get_iocs.md.

If AI is disabled in system settings, automatically falls back to regex-based extraction.

Usage:
    from ai_mistral_extract_iocs import extract_iocs_from_edr_report
    
    result = extract_iocs_from_edr_report(case_id, report_content)
    # Returns: {'success': bool, 'iocs': dict, 'error': str (optional)}
"""

import sys
import os
import json
import subprocess
import logging
import re
from typing import Dict, List, Any
from collections import defaultdict

logger = logging.getLogger(__name__)


def is_ai_enabled() -> bool:
    """
    Check if AI is enabled in system settings.
    
    Returns:
        True if AI is enabled, False otherwise
    """
    try:
        # Import here to avoid circular dependencies
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from models import SystemSettings
        from main import db
        
        setting = db.session.query(SystemSettings).filter_by(setting_key='ai_enabled').first()
        enabled = setting and setting.setting_value == 'true'
        logger.info(f"[MISTRAL_IOC] AI enabled setting: {enabled}")
        return enabled
    except Exception as e:
        logger.warning(f"[MISTRAL_IOC] Could not check AI setting: {e}. Defaulting to False.")
        return False

# Path to the prompt template
PROMPT_FILE = '/opt/casescope/ai_prompts/mistral/mistral_get_iocs.md'
OLLAMA_MODEL = 'mistral'


def get_prompt_template() -> str:
    """Reads the prompt template from the specified file."""
    try:
        with open(PROMPT_FILE, 'r', encoding='utf-8') as f:
            return f.read()
    except FileNotFoundError:
        logger.error(f"[MISTRAL_IOC] Prompt file not found: {PROMPT_FILE}")
        raise FileNotFoundError(f"Prompt template not found: {PROMPT_FILE}")
    except Exception as e:
        logger.error(f"[MISTRAL_IOC] Failed to read prompt template: {e}")
        raise


def call_ollama(prompt_content: str, model: str = OLLAMA_MODEL, timeout: int = 300) -> str:
    """
    Calls the Ollama API to get a response.
    
    Args:
        prompt_content: The full prompt to send to the model
        model: The Ollama model to use (default: mistral)
        timeout: Request timeout in seconds (default: 300)
    
    Returns:
        The model's response as a string
    
    Raises:
        Exception: If Ollama call fails
    """
    try:
        cmd = ['ollama', 'run', model, prompt_content]
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=True,
            timeout=timeout
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        logger.error(f"[MISTRAL_IOC] Ollama command failed: {e}")
        logger.error(f"[MISTRAL_IOC] Stderr: {e.stderr}")
        raise Exception(f"Ollama command failed: {e.stderr}")
    except subprocess.TimeoutExpired:
        logger.error(f"[MISTRAL_IOC] Ollama command timed out after {timeout}s")
        raise Exception(f"Ollama command timed out after {timeout}s")
    except FileNotFoundError:
        logger.error("[MISTRAL_IOC] Ollama command not found")
        raise Exception("Ollama not found. Is Ollama installed?")
    except Exception as e:
        logger.error(f"[MISTRAL_IOC] Unexpected error calling Ollama: {e}")
        raise


def parse_and_clean_json(json_string: str) -> dict:
    """
    Parses a JSON string, attempting to fix common issues like leading/trailing text
    or markdown code blocks.
    
    Args:
        json_string: The JSON string to parse
    
    Returns:
        Parsed JSON as a dictionary
    
    Raises:
        json.JSONDecodeError: If JSON cannot be parsed
    """
    # Remove markdown code block fences if present
    if json_string.startswith('```json'):
        json_string = json_string[7:]
    elif json_string.startswith('```'):
        json_string = json_string[3:]
    
    if json_string.endswith('```'):
        json_string = json_string[:-3]
    
    # Remove any leading/trailing conversational text
    json_string = json_string.strip()
    
    # Attempt to find the first and last brace to isolate the JSON object
    first_brace = json_string.find('{')
    last_brace = json_string.rfind('}')
    
    if first_brace != -1 and last_brace != -1 and last_brace > first_brace:
        json_string = json_string[first_brace : last_brace + 1]
    
    # Fix common JSON issues:
    # 1. Unescaped backslashes in Windows paths
    json_string = json_string.replace('\\', '\\\\')
    
    # 2. Remove trailing commas before closing brackets/braces
    json_string = re.sub(r',\s*([\]}])', r'\1', json_string)
    
    return json.loads(json_string)


def aggregate_iocs(all_iocs: List[dict]) -> dict:
    """
    Aggregates IOCs from multiple dictionaries into a single dictionary.
    
    Args:
        all_iocs: List of IOC dictionaries to aggregate
    
    Returns:
        Aggregated IOC dictionary with all unique values
    """
    aggregated = defaultdict(list)
    
    # Initialize nested dicts for complex structures
    aggregated['file_hashes'] = defaultdict(list)
    aggregated['credentials'] = defaultdict(list)
    aggregated['processes'] = defaultdict(list)
    
    for ioc_set in all_iocs:
        for category, values in ioc_set.items():
            if category in ['file_hashes', 'credentials', 'processes']:
                if isinstance(values, dict):
                    for sub_category, sub_values in values.items():
                        if isinstance(sub_values, list):
                            for item in sub_values:
                                if item and item not in aggregated[category][sub_category]:
                                    aggregated[category][sub_category].append(item)
            elif isinstance(values, list):
                for item in values:
                    if item and item not in aggregated[category]:
                        aggregated[category].append(item)
    
    # Convert defaultdicts back to regular dicts for final output
    final_aggregated = {k: v for k, v in aggregated.items()}
    final_aggregated['file_hashes'] = {k: v for k, v in aggregated['file_hashes'].items()}
    final_aggregated['credentials'] = {k: v for k, v in aggregated['credentials'].items()}
    final_aggregated['processes'] = {k: v for k, v in aggregated['processes'].items()}
    
    return final_aggregated


def split_reports(report_content: str) -> List[str]:
    """
    Splits a multi-report document into individual reports.
    Reports are separated by '*** NEW REPORT ***'.
    
    Args:
        report_content: The full report content
    
    Returns:
        List of individual report strings
    """
    reports = report_content.strip().split('*** NEW REPORT ***')
    reports = [r.strip() for r in reports if r.strip()]
    return reports


def extract_iocs_from_single_report(
    report_content: str,
    max_retries: int = 2
) -> Dict[str, Any]:
    """
    Extract IOCs from a single EDR report using Mistral AI.
    
    Args:
        report_content: The report text to analyze
        max_retries: Maximum number of retry attempts on parse failure
    
    Returns:
        Dictionary containing:
        - success: bool
        - iocs: dict (if successful)
        - error: str (if failed)
    """
    prompt_template = get_prompt_template()
    full_prompt = prompt_template.replace('[PASTE REPORT HERE]', report_content)
    
    for attempt in range(1, max_retries + 1):
        try:
            logger.info(f"[MISTRAL_IOC] Calling Ollama (attempt {attempt}/{max_retries})...")
            ollama_response = call_ollama(full_prompt)
            
            logger.debug(f"[MISTRAL_IOC] Response length: {len(ollama_response)} chars")
            
            # Parse the JSON response
            ioc_dict = parse_and_clean_json(ollama_response)
            
            logger.info(f"[MISTRAL_IOC] Successfully extracted IOCs on attempt {attempt}")
            return {
                'success': True,
                'iocs': ioc_dict
            }
            
        except json.JSONDecodeError as e:
            logger.warning(f"[MISTRAL_IOC] JSON parse failed (attempt {attempt}): {e}")
            if attempt == max_retries:
                return {
                    'success': False,
                    'error': f"Failed to parse JSON after {max_retries} attempts: {str(e)}"
                }
        except Exception as e:
            logger.error(f"[MISTRAL_IOC] Extraction failed (attempt {attempt}): {e}")
            if attempt == max_retries:
                return {
                    'success': False,
                    'error': f"Extraction failed: {str(e)}"
                }
    
    return {
        'success': False,
        'error': 'Unexpected error in extraction loop'
    }


def extract_iocs_from_edr_report(
    case_id: int,
    report_content: str,
    max_retries: int = 2
) -> Dict[str, Any]:
    """
    Main entry point: Extract IOCs from EDR report(s) using Mistral AI or regex fallback.
    
    Automatically checks if AI is enabled in system settings:
    - If AI enabled: Uses Mistral AI for extraction
    - If AI disabled: Falls back to regex-based extraction
    
    Handles both single reports and multi-report documents separated by
    '*** NEW REPORT ***'.
    
    Args:
        case_id: The case ID for logging purposes
        report_content: The EDR report content (may contain multiple reports)
        max_retries: Maximum number of retry attempts per report (AI only)
    
    Returns:
        Dictionary containing:
        - success: bool
        - iocs: dict (aggregated IOCs from all reports)
        - total_reports: int (number of reports processed)
        - failed_reports: int (number of reports that failed)
        - extraction_method: str ('mistral_ai' or 'regex')
        - error: str (if completely failed)
    """
    if not report_content or not report_content.strip():
        return {
            'success': False,
            'error': 'No report content provided'
        }
    
    # Check if AI is enabled
    ai_enabled = is_ai_enabled()
    
    if not ai_enabled:
        logger.info(f"[MISTRAL_IOC] AI is disabled - falling back to regex extraction for case {case_id}")
        from ai_regex_extract_iocs import extract_iocs_regex_all_reports
        return extract_iocs_regex_all_reports(case_id, report_content)
    
    logger.info(f"[MISTRAL_IOC] AI is enabled - starting Mistral AI extraction for case {case_id}")
    
    # Split into individual reports if multi-report document
    reports = split_reports(report_content)
    logger.info(f"[MISTRAL_IOC] Processing {len(reports)} report(s)")
    
    all_extracted_iocs = []
    failed_count = 0
    
    for i, report in enumerate(reports, 1):
        report_preview = report.strip()[:200].replace('\n', ' ')[:100]
        logger.info(f"[MISTRAL_IOC] Processing report {i}/{len(reports)} ({len(report)} chars)")
        logger.info(f"[MISTRAL_IOC] Report {i} preview: {report_preview}...")
        
        result = extract_iocs_from_single_report(report, max_retries)
        
        if result['success']:
            all_extracted_iocs.append(result['iocs'])
            ioc_count = sum(len(v) if isinstance(v, list) else sum(len(sv) if isinstance(sv, list) else 0 for sv in v.values()) if isinstance(v, dict) else 0 for v in result['iocs'].values())
            logger.info(f"[MISTRAL_IOC] ✓ Report {i}/{len(reports)} processed successfully ({ioc_count} IOCs extracted)")
        else:
            failed_count += 1
            error_msg = result.get('error', 'Unknown error')
            logger.error(f"[MISTRAL_IOC] ✗ Report {i}/{len(reports)} FAILED: {error_msg}")
            logger.error(f"[MISTRAL_IOC] Failed report {i} preview: {report_preview}...")
    
    if not all_extracted_iocs:
        return {
            'success': False,
            'error': f'All {len(reports)} report(s) failed to process',
            'total_reports': len(reports),
            'failed_reports': failed_count
        }
    
    # Aggregate IOCs from all successfully processed reports
    logger.info(f"[MISTRAL_IOC] Aggregating IOCs from {len(all_extracted_iocs)} successful report(s)")
    final_iocs = aggregate_iocs(all_extracted_iocs)
    
    # Count total IOCs
    total_ioc_count = 0
    for category, items in final_iocs.items():
        if isinstance(items, list):
            total_ioc_count += len(items)
        elif isinstance(items, dict):
            for sub_items in items.values():
                if isinstance(sub_items, list):
                    total_ioc_count += len(sub_items)
    
    logger.info(f"[MISTRAL_IOC] Extraction complete: {total_ioc_count} IOCs from {len(all_extracted_iocs)}/{len(reports)} reports")
    
    return {
        'success': True,
        'iocs': final_iocs,
        'total_reports': len(reports),
        'successful_reports': len(all_extracted_iocs),
        'failed_reports': failed_count,
        'total_ioc_count': total_ioc_count,
        'extraction_method': 'mistral_ai'
    }


def get_ioc_summary(iocs: dict) -> Dict[str, Any]:
    """
    Get a summary of extracted IOCs for display in the UI.
    
    Args:
        iocs: The aggregated IOC dictionary
    
    Returns:
        Summary dictionary with counts by category
    """
    summary = {
        'total_count': 0,
        'by_category': {}
    }
    
    for category, items in iocs.items():
        if isinstance(items, list):
            count = len(items)
            if count > 0:
                summary['by_category'][category.replace('_', ' ').title()] = count
                summary['total_count'] += count
        elif isinstance(items, dict):
            for sub_category, sub_items in items.items():
                if isinstance(sub_items, list):
                    count = len(sub_items)
                    if count > 0:
                        display_name = f"{category.replace('_', ' ').title()} ({sub_category.upper()})"
                        summary['by_category'][display_name] = count
                        summary['total_count'] += count
    
    return summary

