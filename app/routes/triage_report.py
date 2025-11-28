#!/usr/bin/env python3
"""
Triage Report Feature (v1.35.0)
================================
Allows analysts to paste EDR/MDR investigative summaries (Huntress, CrowdStrike, etc.)
and automatically extract and add:
1. IOCs (IPs, hashes, usernames, SIDs, paths, processes, domains, registry keys, commands)
2. Systems (hostnames only - NOT IPs)

Simple flow: Paste report → Extract → Add to database
No event tagging or searching.
"""

import json
import logging
import re
from typing import Dict, List
from flask import Blueprint, request, jsonify
from flask_login import login_required, current_user

logger = logging.getLogger(__name__)

triage_report_bp = Blueprint('triage_report', __name__)

# IOC type mappings for the IOC table
IOC_TYPE_MAP = {
    'ips': 'ip',
    'hashes': 'hash',
    'usernames': 'username',
    'sids': 'user_sid',
    'paths': 'filepath',
    'processes': 'filename',
    'domains': 'domain',
    'urls': 'url',
    'registry_keys': 'registry',
    'commands': 'command'
}


def extract_iocs_with_llm(summary_text: str) -> Dict:
    """
    Use LLM to extract structured IOCs from investigative summary.
    Returns dict with categorized IOCs.
    """
    import requests
    from models import SystemSettings
    
    # Get Ollama settings
    ollama_host = SystemSettings.query.filter_by(setting_key='ollama_host').first()
    ollama_model = SystemSettings.query.filter_by(setting_key='ollama_model').first()
    
    host = ollama_host.setting_value if ollama_host else 'http://localhost:11434'
    model = ollama_model.setting_value if ollama_model else 'mistral'
    
    prompt = f"""You are a security analyst. Extract ALL indicators of compromise (IOCs) from this investigative report.

Return ONLY valid JSON with these fields (use empty arrays if none found):
{{
    "usernames": ["username1", "username2"],
    "ips": ["1.2.3.4", "10.0.0.1"],
    "processes": ["malware.exe", "suspicious.exe"],
    "paths": ["C:\\\\path\\\\to\\\\file"],
    "hashes": ["sha256_or_md5_hash"],
    "hostnames": ["SERVER01", "WORKSTATION"],
    "timestamps": ["2025-09-05T06:40:02"],
    "sids": ["S-1-5-21-..."],
    "domains": ["evil.com"],
    "registry_keys": ["HKLM\\\\..."],
    "commands": ["powershell -enc ..."]
}}

IMPORTANT RULES:
- Extract EXACT values from the text
- IP addresses go in "ips" NOT "hostnames"
- Hostnames are computer names like "SERVER01", "WORKSTATION", "DC1"
- Include ALL usernames mentioned (e.g., "tabadmin")
- Include ALL IP addresses
- Include ALL process names (e.g., "WinSCP.exe", "svhost.exe")
- Include ALL file paths mentioned
- Include ALL SHA256/MD5/SHA1 hashes
- Only return the JSON, no explanations

Report text:
{summary_text}
"""
    
    try:
        response = requests.post(
            f"{host}/api/generate",
            json={"model": model, "prompt": prompt, "stream": False},
            timeout=60
        )
        
        if response.status_code == 200:
            result = response.json().get('response', '')
            
            # Try to parse JSON from response
            json_match = re.search(r'\{[\s\S]*\}', result)
            if json_match:
                try:
                    iocs = json.loads(json_match.group())
                    logger.info(f"[TRIAGE] LLM extracted IOCs: {sum(len(v) for v in iocs.values() if isinstance(v, list))} total")
                    return iocs
                except json.JSONDecodeError:
                    logger.warning("[TRIAGE] LLM returned invalid JSON, falling back to regex")
        
    except Exception as e:
        logger.warning(f"[TRIAGE] LLM extraction failed: {e}, falling back to regex")
    
    return {}


def extract_iocs_with_regex(summary_text: str) -> Dict:
    """
    Fallback: Extract IOCs using regex patterns.
    Used if LLM fails or is unavailable.
    """
    iocs = {
        'usernames': [],
        'ips': [],
        'processes': [],
        'paths': [],
        'hashes': [],
        'hostnames': [],
        'timestamps': [],
        'sids': [],
        'domains': [],
        'registry_keys': [],
        'commands': []
    }
    
    # IP addresses (validated format)
    ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    iocs['ips'] = list(set(re.findall(ip_pattern, summary_text)))
    
    # SHA256 hashes (64 hex chars)
    sha256_pattern = r'\b[a-fA-F0-9]{64}\b'
    iocs['hashes'].extend(re.findall(sha256_pattern, summary_text))
    
    # MD5 hashes (32 hex chars)
    md5_pattern = r'\b[a-fA-F0-9]{32}\b'
    iocs['hashes'].extend(re.findall(md5_pattern, summary_text))
    
    # SHA1 hashes (40 hex chars)
    sha1_pattern = r'\b[a-fA-F0-9]{40}\b'
    iocs['hashes'].extend(re.findall(sha1_pattern, summary_text))
    iocs['hashes'] = list(set(iocs['hashes']))
    
    # Windows SIDs
    sid_pattern = r'S-1-5-21-[\d-]+'
    iocs['sids'] = list(set(re.findall(sid_pattern, summary_text)))
    
    # Process names (*.exe)
    exe_pattern = r'\b[\w\-\.]+\.exe\b'
    iocs['processes'] = list(set(re.findall(exe_pattern, summary_text, re.IGNORECASE)))
    
    # Windows paths (require at least 2 path components)
    path_pattern = r'[A-Za-z]:\\(?:[^\s\\/:*?"<>|]+\\)+[^\s\\/:*?"<>|]*'
    raw_paths = list(set(re.findall(path_pattern, summary_text)))
    # Filter paths that are too short
    iocs['paths'] = [p for p in raw_paths if len(p) >= 10]
    
    # Usernames in quotes (common in reports)
    username_pattern = r'user\s*["\']([^"\']+)["\']'
    iocs['usernames'] = list(set(re.findall(username_pattern, summary_text, re.IGNORECASE)))
    
    # Timestamps (ISO format)
    timestamp_pattern = r'\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}'
    iocs['timestamps'] = list(set(re.findall(timestamp_pattern, summary_text)))
    
    # Hostnames in quotes (NOT IPs)
    hostname_pattern = r'host\s*["\']([^"\']+)["\']'
    raw_hostnames = re.findall(hostname_pattern, summary_text, re.IGNORECASE)
    # Filter out IPs from hostnames
    ip_set = set(iocs['ips'])
    iocs['hostnames'] = [h for h in set(raw_hostnames) if h not in ip_set and not re.match(ip_pattern, h)]
    
    logger.info(f"[TRIAGE] Regex extracted IOCs: {sum(len(v) for v in iocs.values())} total")
    return iocs


@triage_report_bp.route('/case/<int:case_id>/triage-report/extract', methods=['POST'])
@login_required
def extract_from_report(case_id):
    """
    Extract IOCs and hostnames from pasted report text.
    Returns extracted items for preview before processing.
    """
    if current_user.role == 'read-only':
        return jsonify({'success': False, 'error': 'Read-only users cannot use triage'}), 403
    
    from main import db
    from models import Case
    
    case = db.session.get(Case, case_id)
    if not case:
        return jsonify({'success': False, 'error': 'Case not found'}), 404
    
    report_text = request.json.get('report_text', '').strip()
    if not report_text:
        return jsonify({'success': False, 'error': 'Report text is required'}), 400
    
    if len(report_text) > 50000:  # 50KB limit
        return jsonify({'success': False, 'error': 'Report text too long (max 50KB)'}), 400
    
    # Try LLM extraction first, fall back to regex
    iocs = extract_iocs_with_llm(report_text)
    
    # If LLM returned empty or failed, use regex
    if not any(iocs.get(k) for k in iocs):
        logger.info("[TRIAGE] LLM extraction empty, using regex fallback")
        iocs = extract_iocs_with_regex(report_text)
    
    # Count total IOCs (excluding timestamps and hostnames which go to Systems)
    ioc_count = sum(len(v) for k, v in iocs.items() if isinstance(v, list) and k not in ['timestamps', 'hostnames'])
    hostname_count = len(iocs.get('hostnames', []))
    
    return jsonify({
        'success': True,
        'iocs': iocs,
        'ioc_count': ioc_count,
        'hostname_count': hostname_count
    })


@triage_report_bp.route('/case/<int:case_id>/triage-report/process', methods=['POST'])
@login_required
def process_triage_report(case_id):
    """
    Process triage report: add IOCs and systems to database.
    """
    if current_user.role == 'read-only':
        return jsonify({'success': False, 'error': 'Read-only users cannot use triage'}), 403
    
    from main import db
    from models import Case, IOC, System
    
    case = db.session.get(Case, case_id)
    if not case:
        return jsonify({'success': False, 'error': 'Case not found'}), 404
    
    report_text = request.json.get('report_text', '').strip()
    if not report_text:
        return jsonify({'success': False, 'error': 'Report text is required'}), 400
    
    # Extract IOCs
    iocs = extract_iocs_with_llm(report_text)
    if not any(iocs.get(k) for k in iocs):
        iocs = extract_iocs_with_regex(report_text)
    
    # Add IOCs to database
    iocs_added = 0
    iocs_skipped = 0
    
    for ioc_type_key, values in iocs.items():
        if not values or ioc_type_key not in IOC_TYPE_MAP:
            continue
            
        db_ioc_type = IOC_TYPE_MAP[ioc_type_key]
        
        for value in values:
            if not value or len(value) < 2:
                continue
            
            # Check if IOC exists
            existing = IOC.query.filter_by(
                case_id=case_id,
                ioc_type=db_ioc_type,
                ioc_value=value
            ).first()
            
            if existing:
                iocs_skipped += 1
                continue
            
            try:
                # SIDs start disabled (generate too many hits initially)
                is_active = False if db_ioc_type == 'user_sid' else True
                
                new_ioc = IOC(
                    case_id=case_id,
                    ioc_type=db_ioc_type,
                    ioc_value=value,
                    description=f"Auto-extracted from triage report",
                    threat_level='medium',
                    created_by=current_user.id,
                    is_active=is_active
                )
                db.session.add(new_ioc)
                iocs_added += 1
            except Exception as e:
                logger.warning(f"[TRIAGE] Failed to add IOC {value}: {e}")
    
    # Add Systems (hostnames only - NOT IPs)
    systems_added = 0
    systems_skipped = 0
    hostnames = iocs.get('hostnames', [])
    
    for hostname in hostnames:
        if not hostname or len(hostname) < 2:
            continue
        
        # Double-check it's not an IP
        if re.match(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', hostname):
            continue
        
        # Check if system exists
        existing = System.query.filter_by(
            case_id=case_id,
            system_name=hostname
        ).first()
        
        if existing:
            systems_skipped += 1
            continue
        
        try:
            new_system = System(
                case_id=case_id,
                system_name=hostname,
                system_type='workstation',  # Default
                added_by=current_user.username,
                hidden=False
            )
            db.session.add(new_system)
            systems_added += 1
        except Exception as e:
            logger.warning(f"[TRIAGE] Failed to add system {hostname}: {e}")
    
    db.session.commit()
    
    logger.info(f"[TRIAGE] Case {case_id}: Added {iocs_added} IOCs (skipped {iocs_skipped}), {systems_added} systems (skipped {systems_skipped})")
    
    return jsonify({
        'success': True,
        'iocs_added': iocs_added,
        'iocs_skipped': iocs_skipped,
        'systems_added': systems_added,
        'systems_skipped': systems_skipped
    })

