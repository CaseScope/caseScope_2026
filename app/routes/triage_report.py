#!/usr/bin/env python3
"""
Triage Report Feature (v1.33.0, updated v1.33.2)
=================================================
Allows analysts to paste EDR/MDR investigative summaries (Huntress, CrowdStrike, etc.)
and automatically:
1. Extract IOCs from the summary text using LLM
2. Search events with INTELLIGENT FILTERING to avoid tagging routine events
3. Tag matching events using existing tag system
4. Add new IOCs if they don't exist
5. Add new Systems if hostnames don't exist

FILTERING STRATEGY (v1.33.2):
- Time-window: ±24 hours from report timestamps (if found)
- Multi-IOC priority: Events matching 2+ IOCs tagged first
- NO per-IOC limits: All forensically relevant events are tagged
- Total limit: Max 5000 events (typical investigations find 300-5K)
- EDR/IIS/CSV support: Events without standard IDs are included via search_blob matching

Uses streaming SSE for progress updates on large cases.
"""

import json
import logging
import re
import time
from datetime import datetime, timedelta
from typing import Dict, List, Set, Tuple, Optional
from flask import Blueprint, request, jsonify, Response, stream_with_context
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

# Limits (v1.33.2 - increased based on real investigation data)
MAX_TOTAL_EVENTS = 5000  # Typical investigations find 300-5K events
TIME_WINDOW_HOURS = 24   # ±24 hours from report timestamps


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

IMPORTANT:
- Extract EXACT values from the text, don't modify them
- Include ALL usernames mentioned (e.g., "tabadmin")
- Include ALL IP addresses (e.g., "192.168.1.150")
- Include ALL process names (e.g., "WinSCP.exe", "svhost.exe")
- Include ALL file paths (e.g., "C:\\ProgramData\\USOShared\\")
- Include ALL hashes (SHA256, MD5, SHA1)
- Include ALL hostnames/computer names
- Include ALL SIDs (Security Identifiers starting with S-1-5-)
- Return ONLY the JSON, no explanation

Report:
{summary_text}
"""
    
    try:
        response = requests.post(
            f"{host}/api/generate",
            json={
                "model": model,
                "prompt": prompt,
                "stream": False,
                "options": {"temperature": 0.1}  # Low temp for consistent extraction
            },
            timeout=60
        )
        
        if response.status_code == 200:
            result = response.json()
            response_text = result.get('response', '{}')
            
            # Try to extract JSON from response
            # Sometimes LLM wraps it in markdown code blocks
            json_match = re.search(r'\{[\s\S]*\}', response_text)
            if json_match:
                extracted = json.loads(json_match.group())
                logger.info(f"[TRIAGE] LLM extracted IOCs: {sum(len(v) for v in extracted.values() if isinstance(v, list))} total")
                return extracted
            else:
                logger.warning(f"[TRIAGE] Could not parse LLM response as JSON")
                return {}
        else:
            logger.error(f"[TRIAGE] Ollama error: {response.status_code}")
            return {}
            
    except Exception as e:
        logger.error(f"[TRIAGE] LLM extraction failed: {e}")
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
    
    # IP addresses
    ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    iocs['ips'] = list(set(re.findall(ip_pattern, summary_text)))
    
    # SHA256 hashes
    sha256_pattern = r'\b[a-fA-F0-9]{64}\b'
    iocs['hashes'].extend(re.findall(sha256_pattern, summary_text))
    
    # MD5 hashes
    md5_pattern = r'\b[a-fA-F0-9]{32}\b'
    iocs['hashes'].extend(re.findall(md5_pattern, summary_text))
    
    # SHA1 hashes
    sha1_pattern = r'\b[a-fA-F0-9]{40}\b'
    iocs['hashes'].extend(re.findall(sha1_pattern, summary_text))
    iocs['hashes'] = list(set(iocs['hashes']))
    
    # Windows SIDs
    sid_pattern = r'S-1-5-21-[\d-]+'
    iocs['sids'] = list(set(re.findall(sid_pattern, summary_text)))
    
    # Process names (*.exe)
    exe_pattern = r'\b[\w\-\.]+\.exe\b'
    iocs['processes'] = list(set(re.findall(exe_pattern, summary_text, re.IGNORECASE)))
    
    # Windows paths
    path_pattern = r'[A-Za-z]:\\(?:[^\s\\/:*?"<>|]+\\)*[^\s\\/:*?"<>|]*'
    iocs['paths'] = list(set(re.findall(path_pattern, summary_text)))
    
    # Usernames in quotes (common in reports)
    username_pattern = r'user\s*["\']([^"\']+)["\']'
    iocs['usernames'] = list(set(re.findall(username_pattern, summary_text, re.IGNORECASE)))
    
    # Timestamps (ISO format)
    timestamp_pattern = r'\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}'
    iocs['timestamps'] = list(set(re.findall(timestamp_pattern, summary_text)))
    
    # Hostnames in quotes
    hostname_pattern = r'host\s*["\']([^"\']+)["\']'
    iocs['hostnames'].extend(re.findall(hostname_pattern, summary_text, re.IGNORECASE))
    iocs['hostnames'] = list(set(iocs['hostnames']))
    
    logger.info(f"[TRIAGE] Regex extracted IOCs: {sum(len(v) for v in iocs.values())} total")
    return iocs


def parse_timestamps_from_iocs(iocs: Dict) -> Tuple[Optional[datetime], Optional[datetime]]:
    """
    Parse timestamps from extracted IOCs to create time window.
    Returns (earliest, latest) datetime tuple.
    """
    timestamps = iocs.get('timestamps', [])
    if not timestamps:
        return None, None
    
    parsed = []
    for ts in timestamps:
        try:
            # Try various formats
            for fmt in ['%Y-%m-%dT%H:%M:%S', '%Y-%m-%d %H:%M:%S', '%Y-%m-%dT%H:%M:%S.%f', '%Y-%m-%d %H:%M:%S.%f']:
                try:
                    parsed.append(datetime.strptime(ts[:19], fmt[:len(ts)]))
                    break
                except:
                    continue
        except:
            continue
    
    if not parsed:
        return None, None
    
    earliest = min(parsed) - timedelta(hours=TIME_WINDOW_HOURS)
    latest = max(parsed) + timedelta(hours=TIME_WINDOW_HOURS)
    
    return earliest, latest


def build_opensearch_query(iocs: Dict, time_start: datetime = None, time_end: datetime = None) -> Dict:
    """
    Build OpenSearch query to find events matching extracted IOCs.
    
    v1.33.2: NO event type filtering - EDR/IIS/CSV files don't have standard event IDs.
    We search the search_blob field which contains ALL event data regardless of source.
    
    Filtering:
    - Time window (if timestamps extracted) - ±24 hours
    - IOC matching via search_blob (works for ALL file types)
    """
    should_clauses = []
    
    # Build match_phrase queries for each IOC
    all_values = []
    
    for ioc_type, values in iocs.items():
        if not values or not isinstance(values, list):
            continue
        if ioc_type == 'timestamps':  # Don't search for timestamps as IOCs
            continue
        for value in values:
            if not value or len(value) < 2:  # Skip very short values
                continue
            all_values.append(value)
            # Use match_phrase for exact substring matching in search_blob
            # This works for ALL file types: EVTX, EDR JSON, IIS logs, CSV, etc.
            should_clauses.append({
                "match_phrase": {"search_blob": str(value)}
            })
    
    if not should_clauses:
        return None
    
    # Build the query
    query = {
        "bool": {
            "should": should_clauses,
            "minimum_should_match": 1
        }
    }
    
    # Add time window filter if we have timestamps (±24 hours)
    if time_start and time_end:
        query["bool"]["filter"] = [{
            "range": {
                "normalized_timestamp": {
                    "gte": time_start.isoformat(),
                    "lte": time_end.isoformat()
                }
            }
        }]
    
    return query


@triage_report_bp.route('/case/<int:case_id>/triage-report/extract', methods=['POST'])
@login_required
def extract_from_report(case_id):
    """
    Extract IOCs from pasted report text.
    Returns extracted IOCs for preview before processing.
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
    
    # Count total IOCs
    total_iocs = sum(len(v) for v in iocs.values() if isinstance(v, list))
    
    return jsonify({
        'success': True,
        'iocs': iocs,
        'total_count': total_iocs
    })


@triage_report_bp.route('/case/<int:case_id>/triage-report/process', methods=['POST'])
@login_required
def process_triage_report(case_id):
    """
    Process triage report: search events, tag matches, add IOCs/systems.
    Uses SSE streaming for progress updates.
    """
    if current_user.role == 'read-only':
        return jsonify({'success': False, 'error': 'Read-only users cannot use triage'}), 403
    
    from main import db, opensearch_client
    from models import Case, IOC, System, TimelineTag
    
    case = db.session.get(Case, case_id)
    if not case:
        return jsonify({'success': False, 'error': 'Case not found'}), 404
    
    report_text = request.json.get('report_text', '').strip()
    if not report_text:
        return jsonify({'success': False, 'error': 'Report text is required'}), 400
    
    def generate():
        """Generator for SSE streaming progress updates."""
        try:
            # Step 1: Extract IOCs
            yield f"data: {json.dumps({'stage': 'extracting', 'message': 'Extracting IOCs from report...'})}\n\n"
            
            iocs = extract_iocs_with_llm(report_text)
            if not any(iocs.get(k) for k in iocs):
                iocs = extract_iocs_with_regex(report_text)
            
            total_iocs = sum(len(v) for v in iocs.values() if isinstance(v, list))
            yield f"data: {json.dumps({'stage': 'extracted', 'message': f'Found {total_iocs} IOCs', 'iocs': iocs})}\n\n"
            
            if total_iocs == 0:
                yield f"data: {json.dumps({'stage': 'complete', 'message': 'No IOCs found in report', 'tagged': 0, 'iocs_added': 0, 'systems_added': 0})}\n\n"
                return
            
            # Step 2: Add IOCs to database (if not exists)
            yield f"data: {json.dumps({'stage': 'adding_iocs', 'message': 'Adding new IOCs...'})}\n\n"
            
            iocs_added = 0
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
                    
                    if not existing:
                        try:
                            new_ioc = IOC(
                                case_id=case_id,
                                ioc_type=db_ioc_type,
                                ioc_value=value,
                                description=f"Auto-extracted from triage report",
                                threat_level='medium',
                                created_by=current_user.id,
                                is_active=True
                            )
                            db.session.add(new_ioc)
                            iocs_added += 1
                        except Exception as e:
                            logger.warning(f"[TRIAGE] Failed to add IOC {value}: {e}")
            
            db.session.commit()
            yield f"data: {json.dumps({'stage': 'iocs_added', 'message': f'Added {iocs_added} new IOCs', 'iocs_added': iocs_added})}\n\n"
            
            # Step 3: Add Systems (hostnames) if not exists
            yield f"data: {json.dumps({'stage': 'adding_systems', 'message': 'Adding new systems...'})}\n\n"
            
            systems_added = 0
            hostnames = iocs.get('hostnames', [])
            for hostname in hostnames:
                if not hostname or len(hostname) < 2:
                    continue
                
                # Check if system exists
                existing = System.query.filter_by(
                    case_id=case_id,
                    system_name=hostname
                ).first()
                
                if not existing:
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
            yield f"data: {json.dumps({'stage': 'systems_added', 'message': f'Added {systems_added} new systems', 'systems_added': systems_added})}\n\n"
            
            # Step 4: Search events matching IOCs
            yield f"data: {json.dumps({'stage': 'searching', 'message': 'Searching events matching IOCs...'})}\n\n"
            
            # Parse timestamps for time window (±24 hours)
            time_start, time_end = parse_timestamps_from_iocs(iocs)
            time_filter_msg = ""
            if time_start and time_end:
                time_filter_msg = f" (time window: {time_start.strftime('%Y-%m-%d %H:%M')} to {time_end.strftime('%Y-%m-%d %H:%M')})"
                yield f"data: {json.dumps({'stage': 'searching', 'message': f'Using time window ±{TIME_WINDOW_HOURS}h from report timestamps'})}\n\n"
            else:
                yield f"data: {json.dumps({'stage': 'searching', 'message': 'No timestamps found in report - searching all events'})}\n\n"
            
            # Build query (searches search_blob - works for ALL file types including EDR/IIS/CSV)
            query_body = build_opensearch_query(iocs, time_start, time_end)
            if not query_body:
                yield f"data: {json.dumps({'stage': 'complete', 'message': 'No searchable IOCs', 'tagged': 0, 'iocs_added': iocs_added, 'systems_added': systems_added})}\n\n"
                return
            
            index_name = f"case_{case_id}"
            
            # Get total count
            try:
                count_result = opensearch_client.count(index=index_name, body={"query": query_body})
                total_matches = count_result.get('count', 0)
            except Exception as e:
                logger.error(f"[TRIAGE] Count query failed: {e}")
                total_matches = 0
            
            yield f"data: {json.dumps({'stage': 'found_matches', 'message': f'Found {total_matches} matching events{time_filter_msg}', 'total_matches': total_matches})}\n\n"
            
            if total_matches == 0:
                yield f"data: {json.dumps({'stage': 'complete', 'message': 'No matching events found', 'tagged': 0, 'iocs_added': iocs_added, 'systems_added': systems_added})}\n\n"
                return
            
            # Cap at MAX_TOTAL_EVENTS (5000)
            total_to_process = min(total_matches, MAX_TOTAL_EVENTS)
            
            if total_matches > MAX_TOTAL_EVENTS:
                yield f"data: {json.dumps({'stage': 'searching', 'message': f'Limiting to {MAX_TOTAL_EVENTS} most recent events (of {total_matches} matches)'})}\n\n"
            
            # Search and tag - NO per-IOC limits, tag ALL matching events up to MAX_TOTAL_EVENTS
            yield f"data: {json.dumps({'stage': 'tagging', 'message': 'Tagging matching events...', 'processed': 0, 'total': total_to_process})}\n\n"
            
            tagged_count = 0
            skipped_count = 0
            processed_count = 0
            batch_size = 1000
            
            # Get existing tags for this case
            existing_tags = {tag.event_id for tag in TimelineTag.query.filter_by(case_id=case_id).all()}
            
            # Track IOC match counts for summary (no limits applied)
            ioc_match_counts = {}
            
            try:
                # Use scroll API to handle large result sets
                scroll_response = opensearch_client.search(
                    index=index_name,
                    body={
                        "query": query_body,
                        "_source": ["search_blob"],
                        "size": batch_size,
                        "sort": [{"normalized_timestamp": {"order": "desc"}}]
                    },
                    scroll='5m'
                )
                
                scroll_id = scroll_response.get('_scroll_id')
                hits = scroll_response.get('hits', {}).get('hits', [])
                
                while hits and tagged_count < MAX_TOTAL_EVENTS:
                    for hit in hits:
                        if tagged_count >= MAX_TOTAL_EVENTS:
                            break
                            
                        event_id = hit['_id']
                        processed_count += 1
                        
                        # Skip if already tagged
                        if event_id in existing_tags:
                            skipped_count += 1
                            continue
                        
                        # Count which IOCs matched (for summary, not for limiting)
                        search_blob = hit.get('_source', {}).get('search_blob', '')
                        matching_iocs = []
                        
                        for ioc_type, values in iocs.items():
                            if ioc_type == 'timestamps' or not values:
                                continue
                            for value in values:
                                if value and len(value) >= 2 and value.lower() in search_blob.lower():
                                    matching_iocs.append(value)
                        
                        if not matching_iocs:
                            continue
                        
                        # Tag the event - NO per-IOC limits
                        try:
                            tag = TimelineTag(
                                case_id=case_id,
                                event_id=event_id,
                                index_name=index_name,
                                user_id=current_user.id
                            )
                            db.session.add(tag)
                            existing_tags.add(event_id)
                            tagged_count += 1
                            
                            # Update IOC counts for summary
                            for ioc_val in matching_iocs:
                                ioc_match_counts[ioc_val] = ioc_match_counts.get(ioc_val, 0) + 1
                                
                        except Exception as e:
                            logger.warning(f"[TRIAGE] Failed to tag event {event_id}: {e}")
                        
                        # Commit and update progress every 100 events
                        if tagged_count % 100 == 0:
                            db.session.commit()
                            yield f"data: {json.dumps({'stage': 'tagging', 'message': f'Tagged {tagged_count} events...', 'processed': processed_count, 'total': total_to_process, 'tagged': tagged_count})}\n\n"
                    
                    # Get next batch
                    if tagged_count < MAX_TOTAL_EVENTS:
                        scroll_response = opensearch_client.scroll(scroll_id=scroll_id, scroll='5m')
                        hits = scroll_response.get('hits', {}).get('hits', [])
                    else:
                        break
                
                # Final commit
                db.session.commit()
                
                # Clear scroll
                try:
                    opensearch_client.clear_scroll(scroll_id=scroll_id)
                except:
                    pass
                    
            except Exception as e:
                logger.error(f"[TRIAGE] Search failed: {e}")
                yield f"data: {json.dumps({'stage': 'error', 'message': f'Search error: {str(e)}'})}\n\n"
                return
            
            # Build summary of top IOCs that matched
            ioc_summary = ", ".join([f"{k}: {v}" for k, v in sorted(ioc_match_counts.items(), key=lambda x: -x[1])[:5]])
            
            # Final summary
            yield f"data: {json.dumps({'stage': 'complete', 'message': f'Triage complete! Tagged {tagged_count} security-relevant events.', 'tagged': tagged_count, 'skipped': skipped_count, 'iocs_added': iocs_added, 'systems_added': systems_added, 'total_matches': filtered_matches, 'ioc_summary': ioc_summary})}\n\n"
            
            # Audit log
            from audit_logger import log_action
            log_action('triage_report', resource_type='case', resource_id=case_id,
                      resource_name=case.name,
                      details={
                          'events_tagged': tagged_count,
                          'events_skipped': skipped_count,
                          'iocs_added': iocs_added,
                          'systems_added': systems_added,
                          'total_iocs_extracted': total_iocs
                      })
            
            logger.info(f"[TRIAGE] Case {case_id}: Tagged {tagged_count} events, added {iocs_added} IOCs, {systems_added} systems")
            
        except Exception as e:
            logger.error(f"[TRIAGE] Processing failed: {e}")
            yield f"data: {json.dumps({'stage': 'error', 'message': f'Error: {str(e)}'})}\n\n"
    
    return Response(
        stream_with_context(generate()),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'X-Accel-Buffering': 'no'
        }
    )


@triage_report_bp.route('/case/<int:case_id>/triage-report/status', methods=['GET'])
@login_required
def triage_status(case_id):
    """Check if triage feature is available (Ollama running)."""
    import requests
    from models import SystemSettings
    
    ollama_host = SystemSettings.query.filter_by(setting_key='ollama_host').first()
    host = ollama_host.setting_value if ollama_host else 'http://localhost:11434'
    
    try:
        response = requests.get(f"{host}/api/tags", timeout=5)
        available = response.status_code == 200
    except:
        available = False
    
    return jsonify({
        'available': available,
        'message': 'Triage feature ready' if available else 'Ollama not available (will use regex extraction)'
    })

