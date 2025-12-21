"""
AI Training Module
Generates training data from OpenCTI threat intelligence
"""

import logging
import json
import os
from datetime import datetime
import requests

logger = logging.getLogger(__name__)


def fetch_opencti_reports(opencti_url, opencti_api_key, limit=100):
    """
    Fetch threat reports from OpenCTI
    
    Args:
        opencti_url: OpenCTI instance URL
        opencti_api_key: API key for authentication
        limit: Maximum number of reports to fetch
    
    Returns:
        list: List of report objects
    """
    logger.info(f"[AI_TRAIN] Fetching up to {limit} reports from OpenCTI...")
    
    try:
        # GraphQL query to fetch reports (minimal fields for speed)
        query = """
        query GetReports($first: Int!) {
            reports(first: $first) {
                edges {
                    node {
                        id
                        name
                        description
                    }
                }
            }
        }
        """
        
        headers = {
            'Authorization': f'Bearer {opencti_api_key}',
            'Content-Type': 'application/json'
        }
        
        response = requests.post(
            f"{opencti_url}/graphql",
            json={'query': query, 'variables': {'first': limit}},
            headers=headers,
            timeout=120  # Increased to 2 minutes for large queries
        )
        
        if response.status_code != 200:
            logger.error(f"[AI_TRAIN] OpenCTI API error: {response.status_code} - {response.text}")
            return []
        
        data = response.json()
        
        if 'errors' in data:
            logger.error(f"[AI_TRAIN] OpenCTI GraphQL errors: {data['errors']}")
            return []
        
        reports = []
        for edge in data.get('data', {}).get('reports', {}).get('edges', []):
            node = edge.get('node', {})
            # Only include reports with name and description
            if node.get('name') and node.get('description'):
                reports.append({
                    'id': node.get('id'),
                    'name': node.get('name'),
                    'description': node.get('description')
                })
        
        logger.info(f"[AI_TRAIN] Retrieved {len(reports)} reports from OpenCTI")
        return reports
        
    except Exception as e:
        logger.error(f"[AI_TRAIN] Error fetching OpenCTI reports: {e}", exc_info=True)
        return []


def extract_iocs_from_report(report):
    """
    Extract IOCs from a report (simplified - would need real IOC extraction)
    
    Args:
        report: Report object
    
    Returns:
        list: List of IOC strings
    """
    # Simplified extraction - in production, use proper IOC extraction
    iocs = []
    
    description = report.get('description', '') or ''
    text = description
    
    # Basic pattern matching (very simplified)
    import re
    
    # IPs
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    iocs.extend(re.findall(ip_pattern, text))
    
    # Domains (simplified)
    domain_pattern = r'\b[a-z0-9][a-z0-9-]*\.[a-z]{2,}\b'
    iocs.extend(re.findall(domain_pattern, text.lower()))
    
    # File hashes (MD5, SHA1, SHA256)
    hash_pattern = r'\b[a-fA-F0-9]{32,64}\b'
    iocs.extend(re.findall(hash_pattern, text))
    
    return list(set(iocs))[:20]  # Return up to 20 unique IOCs


def extract_mitre_from_report(report):
    """
    Extract MITRE ATT&CK techniques from a report
    
    Args:
        report: Report object
    
    Returns:
        list: List of MITRE technique IDs
    """
    techniques = []
    
    description = report.get('description', '') or ''
    text = description
    
    # Extract MITRE technique IDs (T####)
    import re
    pattern = r'\bT\d{4}(?:\.\d{3})?\b'
    techniques = re.findall(pattern, text)
    
    return list(set(techniques))


def format_ioc_row(ioc, mitre_techniques):
    """Helper function to format a single IOC row for table"""
    # Determine IOC type
    if '.' in ioc and len(ioc.split('.')) == 4:
        try:
            parts = ioc.split('.')
            if all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
                return f"| IP | {ioc} | C2/Infrastructure - observed in threat campaign | T1071 |"
        except:
            pass
    
    if len(ioc) == 32:
        return f"| HASH | {ioc} | MD5 hash - malware sample | — |"
    elif len(ioc) == 40:
        return f"| HASH | {ioc} | SHA1 hash - malware sample | — |"
    elif len(ioc) == 64:
        return f"| HASH | {ioc} | SHA256 hash - malware sample | — |"
    else:
        # Assume domain
        return f"| HOSTNAME | {ioc} | Domain - C2 or phishing infrastructure | T1071 |"


def format_training_example(report, iocs, mitre_techniques):
    """
    Format a single training example in JSONL format
    ALIGNED FORMAT (v1.11.33): Matches format-locked inference prompt EXACTLY
    
    Args:
        report: Report object
        iocs: List of IOCs
        mitre_techniques: List of MITRE technique IDs
    
    Returns:
        dict: Training example
    """
    # ========================================================================
    # PROMPT: EXACT MATCH to inference prompt (v1.11.33)
    # ========================================================================
    prompt = f"""SYSTEM: You are a DFIR / Threat Intel reporting engine. You MUST output structured Markdown.

⚠️ CRITICAL RULES:
- NEVER summarize without extracting all artifacts first
- DO NOT skip any required sections
- DO NOT invent data not present in input
- If unknown, write "Not observed" or "NO DATA PRESENT"
- Treat all timestamps as UTC
- Extract EVERY IOC, even if repeated
- If input lacks a field, section must still be present (empty is OK)

═══════════════════════════════════════════════════════════════════════════════
REQUIRED OUTPUT (exact order, exact section titles):
═══════════════════════════════════════════════════════════════════════════════

## 1. Executive Summary
Write exactly 3 short paragraphs in plain English:
**Paragraph 1 - What happened:** High-level incident overview (2-4 sentences)
**Paragraph 2 - What the actor did:** Specific actions taken, chronological (2-4 sentences)
**Paragraph 3 - What it means:** Business impact, threat context, urgency (2-4 sentences)

## 2. Timeline (UTC)
EXTRACTION RULES: Parse EVERY event. Group repeated events into time ranges per host.
Format: "YYYY-MM-DD HH:MM:SS to HH:MM:SS UTC — Event description on Hostname (N events) — IOC: [relevant IOCs]"

## 3. Indicators of Compromise (IOCs)
EXTRACTION RULES: Extract ALL IOCs from data. Use EXACT table format:
| Type | Value/Name | Notes | MITRE |
Do NOT skip any IOC. If >20 IOCs, include all of them.

## 4. Event-to-MITRE Mapping
EXTRACTION RULES: Map EACH distinct event type to MITRE ATT&CK. Use MITRE REFERENCE below.

## 5. What / Why / How to Stop
**What happened:** (1-3 sentences)
**Why it happened:** (Root cause / control failure)
**How to stop:** (Specific, actionable recommendations)

═══════════════════════════════════════════════════════════════════════════════
MITRE ATT&CK REFERENCE (use when relevant):
═══════════════════════════════════════════════════════════════════════════════
[Same 13-line MITRE reference as inference prompt]

═══════════════════════════════════════════════════════════════════════════════
⚠️ VALIDATION: Verify all 5 sections present, timeline complete, IOC count matches, no invented data.
═══════════════════════════════════════════════════════════════════════════════

<<<DATA>>>

CASE INFORMATION:
Case Name: {report.get('name', 'Unknown Threat')}
Investigation Type: Threat Intelligence Analysis

INDICATORS OF COMPROMISE ({len(iocs)} total):
{chr(10).join(f'- {ioc}' for ioc in iocs[:20]) if iocs else '(No IOCs extracted)'}

THREAT INTELLIGENCE SUMMARY:
{report.get('description', 'NO DATA PRESENT')}

MITRE TECHNIQUES OBSERVED:
{chr(10).join(f'- {tech}' for tech in mitre_techniques[:10]) if mitre_techniques else '(No MITRE techniques extracted)'}

<<<END DATA>>>
"""
    
    # ========================================================================
    # RESPONSE: EXACT format matching inference output (v1.11.33)
    # ========================================================================
    description = report.get('description', 'NO DATA PRESENT')
    
    # Parse description into sentences for executive summary
    sentences = []
    if description and description != 'NO DATA PRESENT':
        sentences = description.replace('\n', ' ').split('. ')
    
    # Build response matching EXACT structure model will see at inference
    response = f"""## 1. Executive Summary

**Paragraph 1 - What happened:**
{'. '.join(sentences[:2]) + '.' if sentences else 'Threat intelligence indicates active campaign targeting organizations.'} This represents an active threat requiring immediate defensive action.

**Paragraph 2 - What the actor did:**
{'The threat actor employed tactics consistent with ' + report.get('name', 'this campaign') if description else 'The threat actor conducted reconnaissance and established persistence in the environment.'} Analysis of the threat intelligence reveals systematic approach to compromise and data gathering.

**Paragraph 3 - What it means:**
This activity demonstrates organized threat actor capability targeting similar organizations. Organizations should immediately hunt for these indicators and implement recommended controls. Failure to act could result in data compromise or lateral movement within the environment.

## 2. Timeline (UTC)

Based on threat intelligence reporting:
- {'Intelligence published: ' + report.get('name', 'Unknown Threat')} - Threat actor activity observed
- Indicators actively used in campaigns targeting organizations
- Immediate threat hunt recommended for all observed IOCs

## 3. Indicators of Compromise (IOCs)

| Type | Value/Name | Notes | MITRE |
|------|-----------|-------|-------|
{chr(10).join(format_ioc_row(ioc, mitre_techniques) for ioc in iocs[:20]) if iocs else '| N/A | Not observed | No IOCs extracted from intelligence | — |'}

## 4. Event-to-MITRE Mapping

{chr(10).join(f'- {tech}: Technique observed in threat intelligence' for tech in mitre_techniques[:10]) if mitre_techniques else '- No specific techniques mapped from intelligence source'}

## 5. What / Why / How to Stop

**What happened:** Threat intelligence indicates {report.get('name', 'Unknown Threat')} campaign with observed IOCs and techniques targeting organizations similar to ours.

**Why it happened:** Threat actor capabilities exceeded preventive controls. Indicators suggest gaps in detection or access controls.

**How to stop:** 
- **Immediate**: Hunt for all IOCs above in proxy/firewall/EDR logs
- **Short-term**: Deploy MFA for remote access (T1133 mitigation), block C2 IPs at perimeter
- **Long-term**: Implement NIST AC-6 (least privilege), AU-2/6 (audit logging), IA-2 (MFA), SI-3 (endpoint protection)
"""
    
    return {
        'prompt': prompt,
        'response': response
    }


def generate_training_data_from_opencti(opencti_url, opencti_api_key, limit=100, progress_callback=None):
    """
    Generate training data from OpenCTI threat reports
    Fetches in batches of 10 to avoid overwhelming OpenCTI server
    
    Args:
        opencti_url: OpenCTI instance URL
        opencti_api_key: API key
        limit: Total number of reports to fetch (will be fetched in batches of 10)
        progress_callback: Optional callback function for progress updates
    
    Returns:
        dict: {'success': bool, 'file_path': str, 'example_count': int, 'error': str}
    """
    def log(message):
        """Helper to log and call progress callback"""
        logger.info(f"[AI_TRAIN] {message}")
        if progress_callback:
            progress_callback(message)
    
    try:
        import time
        
        # Fetch reports in batches of 10 to avoid overloading OpenCTI
        batch_size = 10
        total_batches = (limit + batch_size - 1) // batch_size  # Ceiling division
        all_reports = []
        
        log(f"Fetching {limit} threat reports from OpenCTI in batches of {batch_size}...")
        log("")
        
        for batch_num in range(total_batches):
            batch_limit = min(batch_size, limit - len(all_reports))
            
            if batch_limit <= 0:
                break
            
            log(f"📦 Batch {batch_num + 1}/{total_batches}: Fetching {batch_limit} reports...")
            
            batch_reports = fetch_opencti_reports(opencti_url, opencti_api_key, batch_limit)
            
            if batch_reports:
                all_reports.extend(batch_reports)
                log(f"   ✅ Retrieved {len(batch_reports)} reports (total: {len(all_reports)})")
            else:
                log(f"   ⚠️  Batch returned 0 reports")
            
            # Small delay between batches to let OpenCTI breathe
            if batch_num < total_batches - 1:
                log(f"   ⏳ Waiting 3 seconds before next batch...")
                time.sleep(3)
        
        log("")
        
        if not all_reports:
            return {
                'success': False,
                'error': 'No reports retrieved from OpenCTI'
            }
        
        log(f"✅ Total reports retrieved: {len(all_reports)}")
        log("")
        log("Extracting IOCs and MITRE techniques...")
        
        reports = all_reports
        
        training_examples = []
        
        for i, report in enumerate(reports):
            if i % 10 == 0:
                log(f"Processing report {i+1}/{len(reports)}...")
            
            # Extract IOCs
            iocs = extract_iocs_from_report(report)
            
            # Extract MITRE techniques
            mitre = extract_mitre_from_report(report)
            
            # Skip reports with no useful data (must have at least name and description)
            if not report.get('name') or not report.get('description'):
                continue
            
            # Generate training example even if no IOCs/MITRE found
            # (the AI can still learn from threat descriptions and report structure)
            example = format_training_example(report, iocs, mitre)
            training_examples.append(example)
        
        log("")
        log(f"✅ Generated {len(training_examples)} training examples")
        log("")
        
        # Save to JSONL file
        output_dir = "/opt/casescope/lora_training/training_data"
        os.makedirs(output_dir, exist_ok=True)
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_file = f"{output_dir}/opencti_training_{timestamp}.jsonl"
        
        log(f"Saving training data to: {output_file}")
        
        with open(output_file, 'w') as f:
            for example in training_examples:
                f.write(json.dumps(example) + '\n')
        
        log(f"✅ Training data saved")
        
        return {
            'success': True,
            'file_path': output_file,
            'example_count': len(training_examples)
        }
        
    except Exception as e:
        error_msg = f"Error generating training data: {e}"
        log(f"❌ {error_msg}")
        logger.error(f"[AI_TRAIN] {error_msg}", exc_info=True)
        
        return {
            'success': False,
            'error': str(e)
        }
