"""
Hunting Routes
Automated threat hunting functionality
"""

from flask import Blueprint, render_template, session, jsonify, request
from flask_login import login_required, current_user
from models import Case, IOC, KnownSystem, KnownUser
from main import db
from audit_logger import log_action
import logging
import json
import ollama
from utils.ioc_extractor import extract_iocs as regex_extract_iocs
import re

logger = logging.getLogger(__name__)

hunting_bp = Blueprint('hunting', __name__, url_prefix='/hunting')


# ============================================================================
# USERNAME FILTERING - Exclude system accounts and groups
# ============================================================================

# Universal/system usernames to exclude (case-insensitive)
EXCLUDED_USERNAMES = {
    # System accounts
    'system', 'local service', 'network service', 'local_service', 'network_service',
    'dwa\\system', 'nt authority\\system', 'nt authority\\local service', 
    'nt authority\\network service', 'authority\\system',
    
    # Built-in Windows accounts
    'guest', 'administrator', 'defaultaccount', 'default', 'wdagutilityaccount',
    'krbtgt', 'wsiaccount', 'wsiuser', 'defaultuser', 'defaultuser0',
    
    # Windows group names (not user accounts)
    'users', 'administrators', 'guests', 'power users', 'backup operators',
    'replicator', 'network configuration operators', 'performance monitor users',
    'performance log users', 'distributed com users', 'iis_iusrs',
    'cryptographic operators', 'event log readers', 'certificate service dcom access',
    'rds remote access servers', 'rds endpoint servers', 'rds management servers',
    'hyper-v administrators', 'access control assistance operators',
    'remote management users', 'storage replica administrators',
    'domain admins', 'domain users', 'domain guests', 'domain computers',
    'domain controllers', 'schema admins', 'enterprise admins', 'group policy creator owners',
    'read-only domain controllers', 'cloneable domain controllers', 'protected users',
    'key admins', 'enterprise key admins', 'dnsadmins', 'dnsupdateproxy',
    
    # Health monitoring accounts
    'healthmailbox', 'healthmailboxc3d7722', 'healthmailbox0659e34', 
    'healthmailbox83d6781', 'healthmailbox6ded678', 'healthmailbox7108a4e',
    'healthmailbox4a58f8e', 'healthmailboxdb3a90f', 'healthmailboxfdcd4b9',
    'healthmailboxbe58608', 'healthmailboxf6f5e91', 'healthmailboxfd78d85',
    'healthmailbox968e74d', 'healthmailbox2ab6a02', 'healthmailbox57e9d8a',
    
    # Service accounts (common patterns)
    'udw', 'umfd-0', 'umfd-1', 'umfd-2', 'umfd-3', 'umfd-4', 'umfd-5',
    'dwm-1', 'dwm-2', 'dwm-3', 'dwm-4', 'dwm-5',
    'anonymous logon', 'anonymous', 'nobody',
    
    # Empty or invalid usernames
    '-', '', 'null', 'n/a', 'unknown',
    
    # Microsoft services
    'microsoft.activedirectory', 'azure ad connect', 'aad connect',
    'msol_', 'exchange online', 'o365', 'office365',
}

# Prefixes to exclude (case-insensitive)
EXCLUDED_PREFIXES = [
    'msol_',
    'healthmailbox',
    'umfd-',
    'dwm-',
    'system\\',
    'nt authority\\',
    'font driver host\\',
    'window manager\\',
]

# Patterns to exclude
EXCLUDED_PATTERNS = [
    r'^.*\$$',  # Computer accounts ending with $
    r'^S-\d+-\d+',  # SIDs that look like usernames
    r'.*_\d+[a-z]{5,}$',  # Pattern like "name_5wofrIv" (likely auto-generated/junk)
    r'^[a-z0-9]{20,}$',  # Very long random strings
    r'^[A-Z0-9]{8,}-[A-Z0-9]{4,}-',  # GUID patterns
]


def should_exclude_username(username):
    """
    Check if username should be excluded based on patterns and exclusion lists
    
    Args:
        username: Username to check
    
    Returns:
        bool: True if username should be excluded, False otherwise
    """
    if not username or not isinstance(username, str):
        return True
    
    username_lower = username.lower().strip()
    
    # Skip empty or too short
    if not username_lower or len(username_lower) < 2:
        return True
    
    # Check exact matches
    if username_lower in EXCLUDED_USERNAMES:
        return True
    
    # Check prefixes
    for prefix in EXCLUDED_PREFIXES:
        if username_lower.startswith(prefix.lower()):
            return True
    
    # Check patterns
    for pattern in EXCLUDED_PATTERNS:
        if re.match(pattern, username, re.IGNORECASE):
            return True
    
    return False


@hunting_bp.route('/api/event_stats')
@login_required
def get_event_stats():
    """
    Get event statistics for the current case
    Returns counts for file types, detections, and noise categories
    """
    try:
        case_id = session.get('selected_case_id')
        if not case_id:
            return jsonify({'error': 'No case selected'}), 400
        
        case = Case.query.get(case_id)
        if not case:
            return jsonify({'error': 'Case not found'}), 404
        
        # Verify access
        if current_user.role == 'read-only' and case.id != current_user.case_assigned:
            return jsonify({'error': 'Access denied'}), 403
        
        from opensearchpy import OpenSearch
        from config import Config
        from models import EventIOCHit, EventSigmaHit
        
        # Initialize OpenSearch client
        client = OpenSearch(
            hosts=[{'host': Config.OPENSEARCH_HOST, 'port': Config.OPENSEARCH_PORT}],
            use_ssl=Config.OPENSEARCH_USE_SSL,
            verify_certs=False,
            ssl_show_warn=False,
            timeout=30
        )
        
        index_name = f"case_{case_id}"
        
        if not client.indices.exists(index=index_name):
            return jsonify({
                'total_events': 0,
                'evtx_events': 0,
                'edr_events': 0,
                'firewall_events': 0,
                'sigma_events': 0,
                'ioc_events': 0,
                'noise_categories': []
            })
        
        # Get total event count
        total_count = client.count(index=index_name, body={"query": {"match_all": {}}})['count']
        
        # Get EVTX events count
        evtx_count = client.count(
            index=index_name,
            body={"query": {"wildcard": {"source_file": "*.evtx"}}}
        )['count']
        
        # Get EDR events count (NDJSON files)
        edr_count = client.count(
            index=index_name,
            body={
                "query": {
                    "bool": {
                        "should": [
                            {"wildcard": {"source_file": "*.ndjson"}},
                            {"wildcard": {"source_file": "*.json"}},
                            {"wildcard": {"source_file": "*.jsonl"}}
                        ]
                    }
                }
            }
        )['count']
        
        # Get Firewall events count (CSV files)
        firewall_count = client.count(
            index=index_name,
            body={"query": {"wildcard": {"source_file": "*.csv"}}}
        )['count']
        
        # Get events with SIGMA violations (from database)
        sigma_event_count = db.session.query(EventSigmaHit.opensearch_doc_id).filter_by(
            case_id=case_id
        ).distinct().count()
        
        # Get events with IOCs (from database)
        ioc_event_count = db.session.query(EventIOCHit.opensearch_doc_id).filter_by(
            case_id=case_id
        ).distinct().count()
        
        # Get noise category counts (from OpenSearch aggregation)
        noise_categories = []
        try:
            agg_result = client.search(
                index=index_name,
                body={
                    "size": 0,
                    "query": {"term": {"noise_matched": True}},
                    "aggs": {
                        "categories": {
                            "terms": {
                                "field": "noise_categories.keyword",
                                "size": 10
                            }
                        }
                    }
                }
            )
            
            if 'aggregations' in agg_result and 'categories' in agg_result['aggregations']:
                for bucket in agg_result['aggregations']['categories']['buckets']:
                    noise_categories.append({
                        'category': bucket['key'],
                        'count': bucket['doc_count']
                    })
        except Exception as e:
            logger.warning(f"Could not get noise category stats: {e}")
        
        return jsonify({
            'total_events': total_count,
            'evtx_events': evtx_count,
            'edr_events': edr_count,
            'firewall_events': firewall_count,
            'sigma_events': sigma_event_count,
            'ioc_events': ioc_event_count,
            'noise_categories': noise_categories
        })
        
    except Exception as e:
        logger.error(f"Error getting event stats: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


@hunting_bp.route('/')
@hunting_bp.route('/dashboard')
@login_required
def dashboard():
    """
    Hunting dashboard - automated threat hunting tools
    """
    # Get selected case from session
    case_id = session.get('selected_case_id')
    case = None
    
    if case_id:
        case = Case.query.get(case_id)
        
        # Check permissions for read-only users
        if current_user.role == 'read-only':
            if not case or case.id != current_user.case_assigned:
                case = None
    
    return render_template('hunting/dashboard.html', case=case)


@hunting_bp.route('/api/check_edr')
@login_required
def api_check_edr():
    """
    Check if current case has EDR reports
    """
    try:
        case_id = session.get('selected_case_id')
        if not case_id:
            return jsonify({'success': False, 'error': 'No case selected'}), 400
        
        case = Case.query.get(case_id)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404
        
        has_edr = bool(case.edr_reports and case.edr_reports.strip())
        
        if has_edr:
            # Count reports
            reports = case.edr_reports.split('*** NEW REPORT ***')
            report_count = len([r for r in reports if r.strip()])
        else:
            report_count = 0
        
        return jsonify({
            'success': True,
            'has_edr': has_edr,
            'report_count': report_count
        })
        
    except Exception as e:
        logger.error(f"Error checking EDR: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@hunting_bp.route('/api/login_events')
@login_required
def api_login_events():
    """
    Fetch login events from OpenSearch (4624 or 4625)
    """
    try:
        case_id = session.get('selected_case_id')
        if not case_id:
            return jsonify({'success': False, 'error': 'No case selected'}), 400
        
        case = Case.query.get(case_id)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404
        
        # Check permissions for read-only users
        if current_user.role == 'read-only':
            if case.id != current_user.case_assigned:
                return jsonify({'success': False, 'error': 'Access denied'}), 403
        
        # Get event ID from query parameter
        event_id = request.args.get('event_id', '4625')
        
        # Initialize OpenSearch client
        from opensearchpy import OpenSearch
        from app.config import Config
        
        client = OpenSearch(
            hosts=[{'host': Config.OPENSEARCH_HOST, 'port': Config.OPENSEARCH_PORT}],
            use_ssl=Config.OPENSEARCH_USE_SSL,
            verify_certs=False,
            ssl_show_warn=False,
            timeout=30
        )
        
        index_name = f"case_{case_id}"
        
        # Check if index exists
        if not client.indices.exists(index=index_name):
            return jsonify({
                'success': True,
                'events': [],
                'total': 0
            })
        
        # Build query for login events
        query = {
            'term': {
                'event_id': event_id
            }
        }
        
        # Use scroll API to get all results (bypasses 10K limit)
        from opensearchpy.helpers import scan
        
        # Get all matching events using scroll
        scroll_results = scan(
            client,
            index=index_name,
            query={'query': query},
            _source=[
                'normalized_timestamp', 'timestamp', 'computer', 'normalized_computer',
                'event_data', 'event_data_fields', 'event_id'
            ],
            size=1000,  # Batch size
            scroll='5m'
        )
        
        # Deduplicate events by username/computer/logon_type combination
        # This reduces tens of thousands of events to hundreds of distinct logins
        seen_combinations = set()
        distinct_logins = []
        total_events = 0
        filtered_count = 0
        
        for hit in scroll_results:
            source = hit['_source']
            total_events += 1
            
            # Try both event_data and event_data_fields (different formats)
            event_data = source.get('event_data_fields', source.get('event_data', {})) or {}
            
            # Extract relevant fields - works for both 4624 and 4625
            timestamp = source.get('normalized_timestamp', source.get('timestamp', 'N/A'))
            username = event_data.get('TargetUserName', event_data.get('SubjectUserName', 'N/A'))
            source_ip = event_data.get('IpAddress', 'N/A')
            source_hostname = event_data.get('WorkstationName', 'N/A')
            target_system = source.get('computer', source.get('normalized_computer', 'N/A'))
            
            # Extract logon type (for filtering)
            logon_type = event_data.get('LogonType', event_data.get('Logon Type', 'N/A'))
            
            # Extract failure reason for 4625 events
            status = event_data.get('Status', 'N/A')
            sub_status = event_data.get('SubStatus', 'N/A')
            
            # Filter out system accounts and groups
            if should_exclude_username(username):
                filtered_count += 1
                continue
            
            # Create unique key for deduplication
            # Include status/sub_status for failed logins to track different failure types
            if event_id == '4625':
                combo_key = (username.lower(), target_system.lower(), logon_type, sub_status)
            else:
                combo_key = (username.lower(), target_system.lower(), logon_type)
            
            # Only add if this combination hasn't been seen
            if combo_key not in seen_combinations:
                seen_combinations.add(combo_key)
                
                distinct_logins.append({
                    'timestamp': timestamp,
                    'username': username,
                    'source_ip': source_ip,
                    'source_hostname': source_hostname,
                    'target_system': target_system,
                    'logon_type': logon_type,
                    'status': status,
                    'sub_status': sub_status
                })
        
        # Sort by timestamp descending (newest first)
        distinct_logins.sort(key=lambda x: x['timestamp'], reverse=True)
        
        log_action(
            action='hunt_login_events',
            resource_type='case',
            resource_id=case_id,
            details=f'Queried event ID {event_id}: {total_events} total events, {len(distinct_logins)} distinct logins'
        )
        
        return jsonify({
            'success': True,
            'events': distinct_logins,
            'total': len(distinct_logins),
            'total_events': total_events,
            'filtered_count': filtered_count
        })
        
    except Exception as e:
        logger.error(f"Error fetching login events: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500


@hunting_bp.route('/api/extract_edr_iocs', methods=['POST'])
@login_required
def api_extract_edr_iocs():
    """
    Extract IOCs from a specific EDR report using AI
    """
    try:
        case_id = session.get('selected_case_id')
        if not case_id:
            return jsonify({'success': False, 'error': 'No case selected'}), 400
        
        case = Case.query.get(case_id)
        if not case or not case.edr_reports:
            return jsonify({'success': False, 'error': 'No EDR reports found'}), 404
        
        data = request.get_json()
        report_index = data.get('report_index', 0)
        
        # Split reports
        reports = [r.strip() for r in case.edr_reports.split('*** NEW REPORT ***') if r.strip()]
        
        if report_index >= len(reports):
            return jsonify({'success': False, 'error': 'Report index out of range'}), 400
        
        report_text = reports[report_index]
        
        # Create logs directory for IOC extraction debugging
        import os
        from datetime import datetime
        log_dir = '/opt/casescope/logs/ioc_extraction'
        os.makedirs(log_dir, exist_ok=True)
        
        # Generate log filename
        timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        log_file = os.path.join(log_dir, f'case_{case_id}_report_{report_index + 1}_{timestamp}.log')
        
        # Load IOC extraction prompt
        import os
        prompt_path = os.path.join(os.path.dirname(__file__), '../ai/ai_prompts/ioc_extraction.md')
        with open(prompt_path, 'r') as f:
            example_output = f.read()
        
        # Create the extraction prompt
        prompt = f"""You are a DFIR analyst extracting IOCs from incident reports.

YOU MUST USE THIS EXACT JSON STRUCTURE - DO NOT DEVIATE:

{example_output}

CRITICAL: Your response must have these exact top-level keys:
- extraction_summary
- network (with keys: ip_v4, ip_v6, domains, urls, emails, user_agents)
- file (with keys: md5, sha1, sha256, sha512, ssdeep, imphash, file_names, file_paths)
- host (with keys: hostnames, registry_keys, registry_values, command_lines, process_names, service_names, scheduled_tasks, mutexes, named_pipes)
- identity (with keys: usernames, sids, compromised_accounts)
- threat_intel (with keys: cves, mitre_attack, malware_families, threat_actors, yara_rules, sigma_rules)
- cryptocurrency (with keys: btc_addresses, eth_addresses, xmr_addresses)
- timeline

DO NOT create your own structure. DO NOT use "ioCs", "executables", "processes" or any other keys.
USE THE EXACT STRUCTURE SHOWN ABOVE.

EXTRACTION RULES:
1. Extract ALL IOCs that are EXPLICITLY in the text
2. Put them in the CORRECT fields (file_names not executables, command_lines not commands)
3. Include IP addresses, usernames, file paths, URLs, domains
4. Extract the full command line if present
5. DO NOT infer hostnames not explicitly stated

NOW EXTRACT IOCS FROM THIS EDR REPORT:

{report_text}

Return ONLY valid JSON matching the EXACT structure above."""

        # Query AI model with fallback to regex extraction
        from config import LLM_MODEL_CHAT
        extraction = None
        used_fallback = False
        extraction_method = 'unknown'
        
        # Start building debug log
        debug_log = []
        debug_log.append("="*80)
        debug_log.append(f"IOC EXTRACTION - {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}")
        debug_log.append(f"Case ID: {case_id}")
        debug_log.append(f"Case Name: {case.name}")
        debug_log.append(f"Report Index: {report_index + 1}")
        debug_log.append(f"Report Length: {len(report_text)} characters")
        debug_log.append("="*80)
        debug_log.append("")
        
        try:
            debug_log.append(f"AI Model: {LLM_MODEL_CHAT}")
            debug_log.append("Attempting AI extraction...")
            debug_log.append("")
            
            response = ollama.chat(
                model=LLM_MODEL_CHAT,
                messages=[
                    {
                        "role": "system",
                        "content": "You are a precise IOC extraction tool. Extract ONLY information that is explicitly present in the text. Never infer, guess, or hallucinate data. If you're unsure, omit it."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                format="json",
                options={
                    "temperature": 0,
                    "top_p": 0.1,
                    "repeat_penalty": 1.0
                }
            )
            
            extraction = json.loads(response['message']['content'])
            
            # Normalize field names - AI sometimes returns singular instead of plural
            # This ensures consistency with the expected format
            if 'file' in extraction:
                if 'file_name' in extraction['file'] and 'file_names' not in extraction['file']:
                    extraction['file']['file_names'] = extraction['file'].pop('file_name')
                if 'file_path' in extraction['file'] and 'file_paths' not in extraction['file']:
                    extraction['file']['file_paths'] = extraction['file'].pop('file_path')
            
            if 'host' in extraction:
                if 'hostname' in extraction['host'] and 'hostnames' not in extraction['host']:
                    extraction['host']['hostnames'] = extraction['host'].pop('hostname')
                if 'command_line' in extraction['host'] and 'command_lines' not in extraction['host']:
                    extraction['host']['command_lines'] = extraction['host'].pop('command_line')
                if 'process_name' in extraction['host'] and 'process_names' not in extraction['host']:
                    extraction['host']['process_names'] = extraction['host'].pop('process_name')
                if 'registry_key' in extraction['host'] and 'registry_keys' not in extraction['host']:
                    extraction['host']['registry_keys'] = extraction['host'].pop('registry_key')
                if 'registry_value' in extraction['host'] and 'registry_values' not in extraction['host']:
                    extraction['host']['registry_values'] = extraction['host'].pop('registry_value')
                if 'service_name' in extraction['host'] and 'service_names' not in extraction['host']:
                    extraction['host']['service_names'] = extraction['host'].pop('service_name')
                if 'scheduled_task' in extraction['host'] and 'scheduled_tasks' not in extraction['host']:
                    extraction['host']['scheduled_tasks'] = extraction['host'].pop('scheduled_task')
                if 'mutex' in extraction['host'] and 'mutexes' not in extraction['host']:
                    extraction['host']['mutexes'] = extraction['host'].pop('mutex')
                if 'named_pipe' in extraction['host'] and 'named_pipes' not in extraction['host']:
                    extraction['host']['named_pipes'] = extraction['host'].pop('named_pipe')
            
            if 'identity' in extraction:
                if 'username' in extraction['identity'] and 'usernames' not in extraction['identity']:
                    extraction['identity']['usernames'] = extraction['identity'].pop('username')
                if 'sid' in extraction['identity'] and 'sids' not in extraction['identity']:
                    extraction['identity']['sids'] = extraction['identity'].pop('sid')
            
            if 'network' in extraction:
                if 'domain' in extraction['network'] and 'domains' not in extraction['network']:
                    extraction['network']['domains'] = extraction['network'].pop('domain')
                if 'url' in extraction['network'] and 'urls' not in extraction['network']:
                    extraction['network']['urls'] = extraction['network'].pop('url')
                if 'email' in extraction['network'] and 'emails' not in extraction['network']:
                    extraction['network']['emails'] = extraction['network'].pop('email')
                if 'user_agent' in extraction['network'] and 'user_agents' not in extraction['network']:
                    extraction['network']['user_agents'] = extraction['network'].pop('user_agent')
            
            logger.info("Successfully extracted IOCs using AI")
            extraction_method = 'AI'
            debug_log.append("✓ AI extraction successful")
            debug_log.append("")
            debug_log.append("RAW AI RESPONSE (JSON):")
            debug_log.append("-"*80)
            import json as json_module
            debug_log.append(json_module.dumps(extraction, indent=2))
            debug_log.append("-"*80)
            debug_log.append("")
            
        except Exception as ai_error:
            logger.warning(f"AI extraction failed: {ai_error}. Falling back to regex extraction.")
            used_fallback = True
            extraction_method = 'REGEX_FALLBACK'
            
            debug_log.append(f"✗ AI extraction failed: {ai_error}")
            debug_log.append("Falling back to regex extraction...")
            debug_log.append("")
            
            # Use regex fallback
            extraction = regex_extract_iocs(report_text)
            
            # Modify extraction summary to indicate fallback was used
            if 'extraction_summary' in extraction:
                extraction['extraction_summary']['extraction_method'] = 'regex_fallback'
                extraction['extraction_summary']['extraction_notes'] = f"AI unavailable - used regex extraction. Original error: {str(ai_error)}"
            
            debug_log.append("✓ Regex extraction completed")
            debug_log.append("")
        
        if not extraction:
            debug_log.append("✗ CRITICAL: Extraction returned None/empty")
            debug_log.append("")
            # Write debug log even on failure
            with open(log_file, 'w') as f:
                f.write('\n'.join(debug_log))
            return jsonify({'success': False, 'error': 'Failed to extract IOCs'}), 500
        
        # Log extraction results
        debug_log.append("-"*80)
        debug_log.append(f"EXTRACTION METHOD: {extraction_method}")
        debug_log.append("-"*80)
        debug_log.append("")
        
        # Log extraction summary
        if 'extraction_summary' in extraction:
            debug_log.append("EXTRACTION SUMMARY:")
            for key, value in extraction['extraction_summary'].items():
                debug_log.append(f"  {key}: {value}")
            debug_log.append("")
        
        # Log all IOCs found by category
        debug_log.append("IOCS FOUND BY CATEGORY:")
        debug_log.append("")
        
        total_iocs_found = 0
        for category in ['network', 'file', 'host', 'identity', 'threat_intel', 'cryptocurrency']:
            if category not in extraction:
                continue
            
            debug_log.append(f"[{category.upper()}]")
            category_count = 0
            
            for field_name, values in extraction[category].items():
                if values and isinstance(values, list) and len(values) > 0:
                    debug_log.append(f"  {field_name}: ({len(values)} items)")
                    for val in values:
                        debug_log.append(f"    - {val}")
                    category_count += len(values)
                    total_iocs_found += len(values)
            
            if category_count == 0:
                debug_log.append("  (none)")
            debug_log.append("")
        
        debug_log.append(f"TOTAL IOCs EXTRACTED: {total_iocs_found}")
        debug_log.append("")
        
        # Process extracted IOCs and check for duplicates
        iocs_to_import = []
        processed_values = {}  # Track values in current batch: {value_lower: {'type': type, 'index': index}}
        
        # Process each category
        categories_map = {
            'network': [
                ('ip_v4', 'ipv4', 'network'),
                ('ip_v6', 'ipv6', 'network'),
                ('domains', 'domain', 'network'),
                ('urls', 'url', 'network'),
                ('emails', 'email_address', 'network')
            ],
            'file': [
                ('md5', 'md5', 'file'),
                ('sha1', 'sha1', 'file'),
                ('sha256', 'sha256', 'file'),
                ('file_names', 'filename', 'file'),
                ('file_paths', 'filepath', 'file')
            ],
            'host': [
                ('hostnames', 'hostname', 'host'),
                ('command_lines', 'command_line', 'host'),
                ('process_names', 'process_name', 'host'),
                ('registry_keys', 'registry_key', 'host'),
                ('service_names', 'service_name', 'host')
            ],
            'identity': [
                ('usernames', 'username', 'identity'),
                ('sids', 'sid', 'identity')
            ]
        }
        
        for category, mappings in categories_map.items():
            if category not in extraction:
                continue
            
            for field_name, ioc_type, ioc_category in mappings:
                values = extraction[category].get(field_name, [])
                if not isinstance(values, list):
                    continue
                
                for value in values:
                    if not value or not str(value).strip():
                        continue
                    
                    value = str(value).strip()
                    value_lower = value.lower()
                    
                    # Check for duplicates in current batch first
                    batch_duplicate = False
                    
                    # For usernames, check if domain version or base version already in batch
                    if ioc_type == 'username':
                        if '\\' in value:
                            # This is domain\user, check if base user is in batch
                            base_user = value.split('\\')[1].lower()
                            if base_user in processed_values and processed_values[base_user]['type'] == 'username':
                                # Base user already in batch, add domain version to its notes
                                idx = processed_values[base_user]['index']
                                if 'analyst_notes' in iocs_to_import[idx]:
                                    iocs_to_import[idx]['analyst_notes'] += f"\nAlso seen as: {value}"
                                else:
                                    iocs_to_import[idx]['analyst_notes'] = f"Also seen as: {value}"
                                batch_duplicate = True
                        else:
                            # This is base user, check if domain version already in batch
                            for key, info in processed_values.items():
                                if info['type'] == 'username' and '\\' in key and key.split('\\')[1].lower() == value_lower:
                                    # Domain version already in batch, add base to its notes
                                    idx = info['index']
                                    if 'analyst_notes' in iocs_to_import[idx]:
                                        iocs_to_import[idx]['analyst_notes'] += f"\nAlso seen as: {value}"
                                    else:
                                        iocs_to_import[idx]['analyst_notes'] = f"Also seen as: {value}"
                                    batch_duplicate = True
                                    break
                    
                    # Check for same value with different type in batch
                    if value_lower in processed_values and not batch_duplicate:
                        existing_type = processed_values[value_lower]['type']
                        type_preference = {
                            'filepath': 5, 'command_line': 4, 'process_name': 3, 'filename': 2, 'username': 1
                        }
                        current_priority = type_preference.get(ioc_type, 0)
                        existing_priority = type_preference.get(existing_type, 0)
                        
                        if existing_priority > current_priority:
                            # Skip this one, existing is more specific
                            batch_duplicate = True
                        elif current_priority > existing_priority:
                            # Upgrade existing to this more specific type
                            idx = processed_values[value_lower]['index']
                            iocs_to_import[idx]['type'] = ioc_type
                            iocs_to_import[idx]['category'] = ioc_category
                            if 'analyst_notes' in iocs_to_import[idx]:
                                iocs_to_import[idx]['analyst_notes'] += f"\nUpgraded from {existing_type} to {ioc_type}"
                            else:
                                iocs_to_import[idx]['analyst_notes'] = f"Upgraded from {existing_type} to {ioc_type}"
                            processed_values[value_lower]['type'] = ioc_type
                            batch_duplicate = True
                        else:
                            # Same priority, skip duplicate
                            batch_duplicate = True
                    
                    if batch_duplicate:
                        # Still add to list but mark as duplicate
                        iocs_to_import.append({
                            'type': ioc_type,
                            'value': value,
                            'category': ioc_category,
                            'threat_level': 'medium',
                            'confidence': 100,
                            'description': f'Extracted from EDR report',
                            'analyst_notes': f'Duplicate in current batch',
                            'source': 'ai_extraction',
                            'is_duplicate': True
                        })
                        continue
                    
                    # Check for duplicates and overlaps in database
                    merge_result = _check_and_merge_ioc(case_id, value, ioc_type)
                    
                    if merge_result['action'] == 'skip':
                        # Exact duplicate - show to user but mark as duplicate
                        iocs_to_import.append({
                            'type': ioc_type,
                            'value': value,
                            'category': ioc_category,
                            'threat_level': 'medium',
                            'confidence': 100,
                            'description': f'Extracted from EDR report',
                            'analyst_notes': f'Already exists in database',
                            'source': 'ai_extraction',
                            'merge_action': '📋 Duplicate - already exists',
                            'existing_ioc_id': merge_result.get('existing_ioc_id'),
                            'is_duplicate': True
                        })
                    elif merge_result['action'] == 'merge':
                        # Add to existing IOC's analyst notes
                        iocs_to_import.append({
                            'type': ioc_type,
                            'value': merge_result['value'],
                            'category': ioc_category,
                            'threat_level': 'medium',
                            'confidence': 100,
                            'description': f'Extracted from EDR report',
                            'analyst_notes': merge_result['merge_note'],
                            'source': 'ai_extraction',
                            'merge_action': merge_result['message'],
                            'existing_ioc_id': merge_result.get('existing_ioc_id'),
                            'upgrade': merge_result.get('upgrade', False)
                        })
                    else:
                        # New IOC
                        iocs_to_import.append({
                            'type': ioc_type,
                            'value': value,
                            'category': ioc_category,
                            'threat_level': 'medium',
                            'confidence': 100,
                            'description': f'Extracted from EDR report',
                            'source': 'ai_extraction'
                        })
                        # Track this value in the current batch
                        processed_values[value_lower] = {
                            'type': ioc_type,
                            'index': len(iocs_to_import) - 1
                        }
        
        # Process hostnames for known systems
        known_systems_results = []
        if 'host' in extraction and 'hostnames' in extraction['host']:
            hostnames = extraction['host'].get('hostnames', [])
            if isinstance(hostnames, list):
                for hostname in hostnames:
                    if hostname and str(hostname).strip():
                        hostname = str(hostname).strip()
                        result = _process_hostname_known_system(case_id, hostname, current_user.id)
                        known_systems_results.append(result)
        
        # Process usernames for known users
        known_users_results = []
        if 'identity' in extraction and 'usernames' in extraction['identity']:
            usernames = extraction['identity'].get('usernames', [])
            sids = extraction['identity'].get('sids', []) if 'sids' in extraction['identity'] else []
            
            if isinstance(usernames, list):
                for idx, username in enumerate(usernames):
                    if username and str(username).strip():
                        username = str(username).strip()
                        # Try to match username with corresponding SID if available
                        sid = sids[idx] if idx < len(sids) else None
                        result = _process_username_known_user(case_id, username, current_user.id, sid)
                        known_users_results.append(result)
        
        # Log IOC extraction completion including known systems and users processing
        systems_created = [r for r in known_systems_results if r['action'] == 'created']
        systems_updated = [r for r in known_systems_results if r['action'] == 'updated']
        users_created = [r for r in known_users_results if r['action'] == 'created']
        users_updated = [r for r in known_users_results if r['action'] == 'updated']
        
        log_action(
            action='ioc_extraction_with_systems_and_users',
            resource_type='case',
            resource_id=case_id,
            resource_name=case.name,
            details={
                'performed_by': current_user.username,
                'iocs_extracted': len(iocs_to_import),
                'hostnames_processed': len(known_systems_results),
                'systems_created': len(systems_created),
                'systems_updated': len(systems_updated),
                'created_systems': [{'hostname': s['message'].split(': ')[1], 'id': s['system_id']} for s in systems_created],
                'updated_systems': [{'hostname': s['message'].split(': ')[1], 'id': s['system_id']} for s in systems_updated],
                'usernames_processed': len(known_users_results),
                'users_created': len(users_created),
                'users_updated': len(users_updated),
                'created_users': [{'username': u['message'].split(': ')[1], 'id': u['user_id']} for u in users_created],
                'updated_users': [{'username': u['message'].split(': ')[1], 'id': u['user_id']} for u in users_updated]
            }
        )
        
        # Complete debug log with deduplication results
        debug_log.append("-"*80)
        debug_log.append("DEDUPLICATION RESULTS:")
        debug_log.append("-"*80)
        debug_log.append(f"Total IOCs after deduplication: {len(iocs_to_import)}")
        debug_log.append(f"New IOCs to import: {len([ioc for ioc in iocs_to_import if not ioc.get('is_duplicate', False)])}")
        debug_log.append(f"Duplicates found: {len([ioc for ioc in iocs_to_import if ioc.get('is_duplicate', False)])}")
        debug_log.append("")
        
        debug_log.append("IOCs TO IMPORT (excluding duplicates):")
        for ioc in iocs_to_import:
            if not ioc.get('is_duplicate', False):
                debug_log.append(f"  [{ioc['category']}] {ioc['type']}: {ioc['value']}")
        debug_log.append("")
        
        debug_log.append("-"*80)
        debug_log.append("KNOWN SYSTEMS/USERS PROCESSING:")
        debug_log.append("-"*80)
        debug_log.append(f"Systems processed: {len(known_systems_results)}")
        debug_log.append(f"Systems created: {len(systems_created)}")
        debug_log.append(f"Systems updated: {len(systems_updated)}")
        debug_log.append(f"Users processed: {len(known_users_results)}")
        debug_log.append(f"Users created: {len(users_created)}")
        debug_log.append(f"Users updated: {len(users_updated)}")
        debug_log.append("")
        
        debug_log.append("="*80)
        debug_log.append("END OF EXTRACTION LOG")
        debug_log.append("="*80)
        
        # Write debug log to file
        try:
            with open(log_file, 'w', encoding='utf-8') as f:
                f.write('\n'.join(debug_log))
            logger.info(f"IOC extraction debug log written to: {log_file}")
        except Exception as log_error:
            logger.error(f"Failed to write debug log: {log_error}")
        
        return jsonify({
            'success': True,
            'extraction_summary': extraction.get('extraction_summary', {}),
            'iocs_to_import': iocs_to_import,
            'full_extraction': extraction,
            'known_systems_processed': known_systems_results,
            'known_users_processed': known_users_results
        })
        
    except Exception as e:
        logger.error(f"Error extracting EDR IOCs: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500


def _process_hostname_known_system(case_id, hostname, current_user_id):
    """
    Process hostname against known systems:
    1. If not found, add as a known system with domain/IP if possible (use '-' if not available)
    2. If found, add note to existing system that it was found in EDR report
    
    Returns: dict with action and message
    """
    try:
        # Normalize hostname for comparison
        hostname_upper = hostname.strip().upper()
        
        # Check if hostname already exists in known systems (case-insensitive)
        existing_system = KnownSystem.query.filter(
            KnownSystem.case_id == case_id,
            db.func.upper(KnownSystem.hostname) == hostname_upper
        ).first()
        
        if existing_system:
            # System found - add note to analyst_notes and mark as compromised
            note = f"Found in EDR report (IOC extraction)"
            if existing_system.analyst_notes:
                # Check if this note already exists
                if note not in existing_system.analyst_notes:
                    existing_system.analyst_notes += f"\n{note}"
            else:
                existing_system.analyst_notes = note
            
            # Mark as compromised since it was found in an EDR report
            if existing_system.compromised != 'yes':
                existing_system.compromised = 'yes'
                compromised_note = "Marked as compromised - found in EDR IOC extraction"
                if existing_system.analyst_notes:
                    existing_system.analyst_notes += f"\n{compromised_note}"
                else:
                    existing_system.analyst_notes = compromised_note
            
            existing_system.updated_by = current_user_id
            db.session.commit()
            
            return {
                'action': 'updated',
                'system_id': existing_system.id,
                'message': f'Updated existing system: {existing_system.hostname}'
            }
        else:
            # System not found - create new known system
            # Try to extract domain from hostname if it's an FQDN
            domain = '-'
            base_hostname = hostname_upper
            
            if '.' in hostname and not re.match(r'^\d+\.\d+\.\d+\.\d+$', hostname):
                # Might be FQDN - split into hostname and domain
                parts = hostname.split('.', 1)
                base_hostname = parts[0].upper()
                domain = parts[1] if len(parts) > 1 else '-'
            
            # Create new known system
            new_system = KnownSystem(
                hostname=base_hostname,
                domain_name=domain,
                ip_address='-',  # Will be filled in if discovered elsewhere
                system_type='workstation',  # Default type, can be changed by analyst
                compromised='yes',  # Mark as compromised since found in EDR IOC extraction
                source='EDR',
                description='Automatically added from EDR IOC extraction',
                analyst_notes='Found in EDR report (IOC extraction) - marked as compromised',
                case_id=case_id,
                created_by=current_user_id,
                updated_by=current_user_id
            )
            
            db.session.add(new_system)
            db.session.commit()
            
            return {
                'action': 'created',
                'system_id': new_system.id,
                'message': f'Created new system: {base_hostname}'
            }
            
    except Exception as e:
        logger.error(f"Error processing hostname for known systems: {e}")
        db.session.rollback()
        return {
            'action': 'error',
            'message': f'Error: {str(e)}'
        }


def _process_username_known_user(case_id, username, current_user_id, sid=None):
    """
    Process username against known users:
    1. If not found, add as a known user with domain/SID if available (use '-' if not)
    2. If found, add note to existing user that it was found in EDR report
    
    Returns: dict with action and message
    """
    try:
        # Parse username to extract domain and base username
        domain_name = None
        base_username = username.strip()
        user_type = 'unknown'
        
        if '\\' in username:
            # Domain\Username format
            parts = username.split('\\', 1)
            domain_name = parts[0].upper()
            base_username = parts[1]
            user_type = 'domain'
        elif '@' in username:
            # user@domain format - convert to domain\user
            parts = username.split('@', 1)
            base_username = parts[0]
            domain_name = parts[1].upper()
            user_type = 'domain'
        
        # Normalize for comparison
        username_lower = base_username.lower()
        domain_lower = domain_name.lower() if domain_name else None
        
        # Check if user already exists
        # First, try to find by username and domain (exact match)
        if domain_name:
            existing_user = KnownUser.query.filter(
                KnownUser.case_id == case_id,
                db.func.lower(KnownUser.username) == username_lower,
                db.func.lower(KnownUser.domain_name) == domain_lower
            ).first()
        else:
            # For users without domain, check for domain_name = '-' OR NULL
            existing_user = KnownUser.query.filter(
                KnownUser.case_id == case_id,
                db.func.lower(KnownUser.username) == username_lower,
                db.or_(
                    KnownUser.domain_name == '-',
                    KnownUser.domain_name.is_(None)
                )
            ).first()
        
        # If we found a user with domain but this one doesn't have domain, merge
        # (e.g., we saw SL\tabadmin first, now we see tabadmin - should update the domain one)
        if not existing_user and not domain_name:
            # Check if there's a domain version of this user
            domain_version = KnownUser.query.filter(
                KnownUser.case_id == case_id,
                db.func.lower(KnownUser.username) == username_lower,
                KnownUser.domain_name != '-',
                KnownUser.domain_name.isnot(None)
            ).first()
            
            if domain_version:
                # Use the domain version instead
                existing_user = domain_version
        
        # If we're adding a domain version but found a non-domain one, update the non-domain one with domain info
        if not existing_user and domain_name:
            # Check if there's a non-domain version
            non_domain_version = KnownUser.query.filter(
                KnownUser.case_id == case_id,
                db.func.lower(KnownUser.username) == username_lower,
                db.or_(
                    KnownUser.domain_name == '-',
                    KnownUser.domain_name.is_(None)
                )
            ).first()
            
            if non_domain_version:
                # Upgrade the non-domain version with domain info
                non_domain_version.domain_name = domain_name
                non_domain_version.user_type = user_type
                if sid and non_domain_version.sid == '-':
                    non_domain_version.sid = sid
                note = f"Found in EDR report (IOC extraction) with domain: {domain_name}"
                if non_domain_version.analyst_notes:
                    if note not in non_domain_version.analyst_notes:
                        non_domain_version.analyst_notes += f"\n{note}"
                else:
                    non_domain_version.analyst_notes = note
                
                # Mark as compromised since it was found in an EDR report
                if non_domain_version.compromised != 'yes':
                    non_domain_version.compromised = 'yes'
                    compromised_note = "Marked as compromised - found in EDR IOC extraction"
                    if non_domain_version.analyst_notes:
                        non_domain_version.analyst_notes += f"\n{compromised_note}"
                    else:
                        non_domain_version.analyst_notes = compromised_note
                
                non_domain_version.updated_by = current_user_id
                db.session.commit()
                
                display_name = f"{non_domain_version.domain_name}\\{non_domain_version.username}"
                return {
                    'action': 'updated',
                    'user_id': non_domain_version.id,
                    'message': f'Updated existing user: {display_name}'
                }
        
        if existing_user:
            # User found - add note to analyst_notes and mark as compromised
            note = f"Found in EDR report (IOC extraction)"
            if existing_user.analyst_notes:
                # Check if this note already exists
                if note not in existing_user.analyst_notes:
                    existing_user.analyst_notes += f"\n{note}"
            else:
                existing_user.analyst_notes = note
            
            # Update SID if we have one and existing doesn't
            if sid and existing_user.sid == '-':
                existing_user.sid = sid
            
            # Mark as compromised since it was found in an EDR report
            if existing_user.compromised != 'yes':
                existing_user.compromised = 'yes'
                compromised_note = "Marked as compromised - found in EDR IOC extraction"
                if existing_user.analyst_notes:
                    existing_user.analyst_notes += f"\n{compromised_note}"
                else:
                    existing_user.analyst_notes = compromised_note
            
            existing_user.updated_by = current_user_id
            db.session.commit()
            
            display_name = f"{existing_user.domain_name}\\{existing_user.username}" if existing_user.domain_name and existing_user.domain_name != '-' else existing_user.username
            
            return {
                'action': 'updated',
                'user_id': existing_user.id,
                'message': f'Updated existing user: {display_name}'
            }
        else:
            # User not found - create new known user
            new_user = KnownUser(
                username=base_username,
                domain_name=domain_name if domain_name else '-',
                sid=sid if sid else '-',
                user_type=user_type,
                compromised='yes',  # Mark as compromised since found in EDR IOC extraction
                source='ioc_extraction',
                description='Automatically added from EDR IOC extraction',
                analyst_notes='Found in EDR report (IOC extraction) - marked as compromised',
                case_id=case_id,
                created_by=current_user_id,
                updated_by=current_user_id
            )
            
            db.session.add(new_user)
            db.session.commit()
            
            display_name = f"{domain_name}\\{base_username}" if domain_name else base_username
            
            return {
                'action': 'created',
                'user_id': new_user.id,
                'message': f'Created new user: {display_name}'
            }
            
    except Exception as e:
        logger.error(f"Error processing username for known users: {e}")
        db.session.rollback()
        return {
            'action': 'error',
            'message': f'Error: {str(e)}'
        }


def _check_and_merge_ioc(case_id, value, ioc_type):
    """
    Check if IOC exists and determine merge action
    Returns: dict with action ('skip', 'merge', 'create'), value, and merge_note
    """
    value_lower = value.lower()
    
    # Check for exact match with same type
    existing = IOC.query.filter(
        IOC.case_id == case_id,
        db.func.lower(IOC.value) == value_lower,
        IOC.type == ioc_type
    ).first()
    
    if existing:
        return {'action': 'skip', 'value': value}
    
    # Check for same value with different types (e.g., filename vs process_name)
    # Prefer more specific types
    type_preference = {
        'filepath': 5,      # Most specific
        'command_line': 4,
        'process_name': 3,
        'filename': 2,      # Least specific
        'username': 1       # Special handling
    }
    
    similar_iocs = IOC.query.filter(
        IOC.case_id == case_id,
        db.func.lower(IOC.value) == value_lower
    ).all()
    
    if similar_iocs:
        # Found same value with different type
        for similar in similar_iocs:
            current_priority = type_preference.get(ioc_type, 0)
            existing_priority = type_preference.get(similar.type, 0)
            
            # If existing IOC is more specific, skip this one
            if existing_priority > current_priority:
                return {
                    'action': 'skip',
                    'value': value,
                    'reason': f'More specific IOC already exists as {similar.type}'
                }
            # If this one is more specific, note to add type info to existing
            elif current_priority > existing_priority:
                return {
                    'action': 'merge',
                    'value': value,
                    'merge_note': f'Also seen as {similar.type}: {similar.value}',
                    'message': f'Upgrading from {similar.type} to {ioc_type}',
                    'existing_ioc_id': similar.id,
                    'upgrade': True
                }
    
    # Check for overlaps (e.g., username vs domain\username)
    if ioc_type == 'username' and '\\' in value:
        # Check if base username exists
        base_username = value.split('\\')[1] if '\\' in value else value
        base_existing = IOC.query.filter(
            IOC.case_id == case_id,
            IOC.type == 'username',
            db.func.lower(IOC.value) == base_username.lower()
        ).first()
        
        if base_existing:
            # Base username exists, add domain version to its notes
            return {
                'action': 'merge',
                'value': base_existing.value,
                'merge_note': f'Also seen as: {value}',
                'message': f'Merging into existing IOC "{base_existing.value}"',
                'existing_ioc_id': base_existing.id
            }
    
    if ioc_type == 'username' and '\\' not in value:
        # Check if domain\username version exists
        domain_versions = IOC.query.filter(
            IOC.case_id == case_id,
            IOC.type == 'username',
            db.func.lower(IOC.value).like(f'%\\{value_lower}')
        ).first()
        
        if domain_versions:
            # Domain version exists, use this as primary and add domain to notes
            return {
                'action': 'merge',
                'value': value,
                'merge_note': f'Also seen as: {domain_versions.value}',
                'message': f'Using "{value}" as primary, noting domain variant',
                'existing_ioc_id': domain_versions.id
            }
    
    # No duplicates or overlaps
    return {'action': 'create', 'value': value}


@hunting_bp.route('/api/save_extracted_iocs', methods=['POST'])
@login_required
def api_save_extracted_iocs():
    """
    Save extracted IOCs to the database
    """
    try:
        if current_user.role == 'read-only':
            return jsonify({'success': False, 'error': 'Insufficient permissions'}), 403
        
        case_id = session.get('selected_case_id')
        if not case_id:
            return jsonify({'success': False, 'error': 'No case selected'}), 400
        
        case = Case.query.get(case_id)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404
        
        data = request.get_json()
        iocs_data = data.get('iocs', [])
        full_extraction = data.get('full_extraction', {})  # Get full extraction data
        
        created_count = 0
        updated_count = 0
        
        for ioc_data in iocs_data:
            if 'existing_ioc_id' in ioc_data:
                # Update existing IOC
                existing_ioc = IOC.query.get(ioc_data['existing_ioc_id'])
                if existing_ioc:
                    # Check if this is an upgrade (more specific type)
                    if ioc_data.get('upgrade'):
                        # Upgrade the type to the more specific one
                        old_type = existing_ioc.type
                        existing_ioc.type = ioc_data['type']
                        if existing_ioc.analyst_notes:
                            existing_ioc.analyst_notes += f"\nUpgraded from {old_type} to {ioc_data['type']}"
                        else:
                            existing_ioc.analyst_notes = f"Upgraded from {old_type} to {ioc_data['type']}"
                    else:
                        # Just append to analyst notes
                        if existing_ioc.analyst_notes:
                            existing_ioc.analyst_notes += f"\n{ioc_data.get('analyst_notes', '')}"
                        else:
                            existing_ioc.analyst_notes = ioc_data.get('analyst_notes', '')
                    
                    existing_ioc.updated_by = current_user.id
                    updated_count += 1
            else:
                # Create new IOC
                # Store full value separately, truncate indexed value if needed
                ioc_value = ioc_data['value']
                ioc_full_value = None
                MAX_IOC_VALUE_LENGTH = 2500  # Safe limit for PostgreSQL btree index
                
                if len(ioc_value) > MAX_IOC_VALUE_LENGTH:
                    logger.warning(f"Long IOC detected ({len(ioc_value)} chars) - storing full value separately")
                    ioc_full_value = ioc_value  # Store complete value
                    ioc_value = ioc_value[:MAX_IOC_VALUE_LENGTH] + "... [TRUNCATED - see full_value]"
                    # Add note about truncation
                    truncation_note = f"Full value stored separately ({len(ioc_data['value'])} characters)"
                    if ioc_data.get('analyst_notes'):
                        ioc_data['analyst_notes'] += f"\n{truncation_note}"
                    else:
                        ioc_data['analyst_notes'] = truncation_note
                
                ioc = IOC(
                    type=ioc_data['type'],
                    value=ioc_value,  # Truncated for index
                    full_value=ioc_full_value,  # Complete value (no index limit)
                    category=ioc_data['category'],
                    threat_level=ioc_data.get('threat_level', 'medium'),
                    confidence=ioc_data.get('confidence', 100),
                    description=ioc_data.get('description'),
                    analyst_notes=ioc_data.get('analyst_notes'),
                    source=ioc_data.get('source', 'ai_extraction'),
                    case_id=case_id,
                    created_by=current_user.id,
                    updated_by=current_user.id,
                    last_seen=None  # Don't set last_seen for extracted IOCs
                )
                db.session.add(ioc)
                created_count += 1
        
        db.session.commit()
        
        # Process hostnames for known systems (if full_extraction provided)
        known_systems_results = []
        if full_extraction and 'host' in full_extraction and 'hostnames' in full_extraction['host']:
            hostnames = full_extraction['host'].get('hostnames', [])
            if isinstance(hostnames, list):
                for hostname in hostnames:
                    if hostname and str(hostname).strip():
                        hostname = str(hostname).strip()
                        result = _process_hostname_known_system(case_id, hostname, current_user.id)
                        known_systems_results.append(result)
        
        # Process usernames for known users (if full_extraction provided)
        known_users_results = []
        if full_extraction and 'identity' in full_extraction and 'usernames' in full_extraction['identity']:
            usernames = full_extraction['identity'].get('usernames', [])
            sids = full_extraction['identity'].get('sids', []) if 'sids' in full_extraction['identity'] else []
            
            if isinstance(usernames, list):
                for idx, username in enumerate(usernames):
                    if username and str(username).strip():
                        username = str(username).strip()
                        # Try to match username with corresponding SID if available
                        sid = sids[idx] if idx < len(sids) else None
                        result = _process_username_known_user(case_id, username, current_user.id, sid)
                        known_users_results.append(result)
        
        # Count created vs updated for audit log
        known_systems_created = len([r for r in known_systems_results if r['action'] == 'created'])
        known_systems_updated = len([r for r in known_systems_results if r['action'] == 'updated'])
        known_users_created = len([r for r in known_users_results if r['action'] == 'created'])
        known_users_updated = len([r for r in known_users_results if r['action'] == 'updated'])
        
        # Build detailed IOC list for audit log
        saved_ioc_details = []
        for ioc_data in iocs_data:
            saved_ioc_details.append({
                'type': ioc_data['type'],
                'value': ioc_data['value'],
                'category': ioc_data['category'],
                'threat_level': ioc_data['threat_level'],
                'action': 'updated' if ioc_data.get('existing_ioc_id') else 'created'
            })
        
        # Prepare audit log details
        systems_created = [r for r in known_systems_results if r['action'] == 'created']
        systems_updated = [r for r in known_systems_results if r['action'] == 'updated']
        users_created = [r for r in known_users_results if r['action'] == 'created']
        users_updated = [r for r in known_users_results if r['action'] == 'updated']
        
        audit_details = {
            'performed_by': current_user.username,
            'iocs_created': created_count,
            'iocs_updated': updated_count,
            'iocs_details': saved_ioc_details
        }
        
        # Add systems/users info if any were processed
        if known_systems_results:
            audit_details.update({
                'hostnames_processed': len(known_systems_results),
                'systems_created': len(systems_created),
                'systems_updated': len(systems_updated),
                'created_systems': [{'hostname': s['message'].split(': ')[1], 'id': s['system_id']} for s in systems_created] if systems_created else [],
                'updated_systems': [{'hostname': s['message'].split(': ')[1], 'id': s['system_id']} for s in systems_updated] if systems_updated else []
            })
        
        if known_users_results:
            audit_details.update({
                'usernames_processed': len(known_users_results),
                'users_created': len(users_created),
                'users_updated': len(users_updated),
                'created_users': [{'username': u['message'].split(': ')[1], 'id': u['user_id']} for u in users_created] if users_created else [],
                'updated_users': [{'username': u['message'].split(': ')[1], 'id': u['user_id']} for u in users_updated] if users_updated else []
            })
        
        # Log action with detailed information
        log_action(
            action='iocs_saved_from_edr',
            resource_type='case',
            resource_id=case.id,
            resource_name=case.name,
            details=audit_details
        )
        
        return jsonify({
            'success': True,
            'created_count': created_count,
            'updated_count': updated_count,
            'systems_created': known_systems_created,
            'systems_updated': known_systems_updated,
            'users_created': known_users_created,
            'users_updated': known_users_updated
        })
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error saving extracted IOCs: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


# ============================================================================
# IOC HUNTING
# ============================================================================

@hunting_bp.route('/api/hunt_iocs', methods=['POST'])
@login_required
def api_hunt_iocs():
    """
    Start background IOC hunt task
    """
    try:
        case_id = session.get('selected_case_id')
        if not case_id:
            return jsonify({'success': False, 'error': 'No case selected'}), 400
        
        # Check permissions
        case = Case.query.get(case_id)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404
        
        # Read-only users cannot hunt IOCs
        if current_user.role == 'read-only':
            return jsonify({'success': False, 'error': 'Insufficient permissions'}), 403
        
        # Get clear_previous option from request
        data = request.get_json() or {}
        clear_previous = data.get('clear_previous', True)
        
        # Import task
        from tasks.task_hunt_iocs import hunt_iocs
        
        # Start background task
        task = hunt_iocs.delay(case_id, current_user.id, clear_previous)
        
        log_action(
            action='ioc_hunt_started',
            resource_type='case',
            resource_id=case_id,
            resource_name=case.name,
            details={'task_id': task.id, 'clear_previous': clear_previous}
        )
        
        return jsonify({
            'success': True,
            'task_id': task.id,
            'message': 'IOC hunt started'
        })
        
    except Exception as e:
        logger.error(f"Error starting IOC hunt: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500


@hunting_bp.route('/api/hunt_iocs/status/<task_id>')
@login_required
def api_hunt_iocs_status(task_id):
    """
    Check status of IOC hunt task
    """
    try:
        from tasks.task_hunt_iocs import hunt_iocs
        from celery.result import AsyncResult
        
        task = AsyncResult(task_id, app=hunt_iocs.app)
        
        if task.state == 'PENDING':
            response = {
                'state': 'PENDING',
                'status': 'Task is queued...',
                'progress': 0
            }
        elif task.state == 'PROGRESS':
            response = {
                'state': 'PROGRESS',
                'status': task.info.get('status', ''),
                'progress': task.info.get('progress', 0),
                'events_scanned': task.info.get('events_scanned', 0),
                'total_events': task.info.get('total_events', 0),
                'events_with_hits': task.info.get('events_with_hits', 0),
                'total_hits': task.info.get('total_hits', 0),
                'current_ioc': task.info.get('current_ioc', ''),
                'ioc_count': task.info.get('ioc_count', 0)
            }
        elif task.state == 'SUCCESS':
            result = task.result
            response = {
                'state': 'SUCCESS',
                'status': 'Hunt complete!',
                'progress': 100,
                'events_scanned': result.get('events_scanned', 0),
                'events_with_hits': result.get('events_with_hits', 0),
                'total_hits': result.get('total_hits', 0),
                'by_ioc': result.get('by_ioc', {}),
                'by_threat_level': result.get('by_threat_level', {})
            }
        elif task.state == 'FAILURE':
            response = {
                'state': 'FAILURE',
                'status': 'Task failed',
                'error': str(task.info)
            }
        else:
            response = {
                'state': task.state,
                'status': str(task.info)
            }
        
        return jsonify(response)
        
    except Exception as e:
        logger.error(f"Error checking hunt status: {e}", exc_info=True)
        return jsonify({'state': 'FAILURE', 'error': str(e)}), 500


# ============================================================================
# SIGMA HUNTING
# ============================================================================

@hunting_bp.route('/api/hunt_sigma', methods=['POST'])
@login_required
def api_hunt_sigma():
    """
    Start background Sigma hunt task using Chainsaw
    """
    try:
        case_id = session.get('selected_case_id')
        if not case_id:
            return jsonify({'success': False, 'error': 'No case selected'}), 400
        
        # Check permissions
        case = Case.query.get(case_id)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404
        
        # Read-only users cannot hunt
        if current_user.role == 'readonly':
            return jsonify({'success': False, 'error': 'Insufficient permissions'}), 403
        
        # Check for existing running task
        from models import ActiveTask
        existing_task = ActiveTask.query.filter_by(
            case_id=case_id,
            task_type='sigma_hunt',
            status='running'
        ).first()
        
        if existing_task:
            logger.info(f"Reconnecting to existing SIGMA hunt task {existing_task.task_id}")
            return jsonify({
                'success': True,
                'task_id': existing_task.task_id,
                'message': 'Reconnected to existing hunt',
                'reconnecting': True
            })
        
        # Get clear_previous option from request
        data = request.get_json() or {}
        clear_previous = data.get('clear_previous', True)
        
        # Start Celery task
        from tasks.task_hunt_sigma import hunt_sigma
        task = hunt_sigma.delay(case_id, current_user.id, clear_previous)
        
        # Log action
        log_action(
            action='sigma_hunt',
            details={
                'case_id': case_id,
                'case_name': case.name,
                'clear_previous': clear_previous,
                'task_id': task.id
            }
        )
        
        return jsonify({
            'success': True,
            'task_id': task.id,
            'message': 'Sigma hunt started'
        })
        
    except Exception as e:
        logger.error(f"Error starting Sigma hunt: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500


@hunting_bp.route('/api/hunt_sigma/status/<task_id>')
@login_required
def api_hunt_sigma_status(task_id):
    """
    Check status of Sigma hunt task from ActiveTask table
    """
    try:
        from models import ActiveTask
        
        # Get task from database
        active_task = ActiveTask.query.filter_by(task_id=task_id).first()
        
        if not active_task:
            return jsonify({
                'state': 'PENDING',
                'status': 'Task queued...',
                'progress': 0
            })
        
        result_data = active_task.result_data or {}
        
        if active_task.status == 'running':
            response = {
                'state': 'PROGRESS',
                'status': active_task.progress_message or 'Processing...',
                'progress': active_task.progress_percent or 0,
                'files_checked': result_data.get('files_checked', 0),
                'events_tagged': result_data.get('events_tagged', 0),
                'total_hits': result_data.get('total_hits', 0),
                'current_zip': result_data.get('current_zip', ''),
                'current_evtx': result_data.get('current_evtx', ''),
                'current': result_data.get('files_checked', 0),
                'total': result_data.get('total_files', 0)
            }
        elif active_task.status == 'completed':
            response = {
                'state': 'SUCCESS',
                'status': 'Sigma hunt complete!',
                'progress': 100,
                'files_checked': result_data.get('files_checked', 0),
                'files_ignored': result_data.get('files_ignored', 0),
                'events_tagged': result_data.get('events_tagged', 0),
                'total_hits': result_data.get('total_hits', 0),
                'rules_matched': result_data.get('rules_matched', {})
            }
        elif active_task.status == 'failed':
            response = {
                'state': 'FAILURE',
                'status': 'Task failed',
                'error': active_task.error_message or 'Unknown error'
            }
        else:
            response = {
                'state': 'PENDING',
                'status': f'Task status: {active_task.status}',
                'progress': 0
            }
        
        return jsonify(response)
        
    except Exception as e:
        logger.error(f"Error checking Sigma hunt status: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500


# ============================================================================
# NOISE TAGGING
# ============================================================================

@hunting_bp.route('/api/tag_noise', methods=['POST'])
@login_required
def tag_noise():
    """Start noise tagging task"""
    try:
        case_id = session.get('selected_case_id')
        if not case_id:
            return jsonify({'success': False, 'error': 'No case selected'}), 400
        
        # Check permissions
        case = Case.query.get(case_id)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404
        
        # Read-only users cannot tag
        if current_user.role == 'readonly':
            return jsonify({'success': False, 'error': 'Insufficient permissions'}), 403
        
        data = request.get_json() or {}
        clear_previous = data.get('clear_previous', True)
        
        # Import the task
        from tasks.task_tag_noise import tag_noise_events
        
        # Start async task
        task = tag_noise_events.delay(case_id, current_user.id, clear_previous)
        
        log_action('start_noise_tagging', resource_type='case', resource_id=case_id,
                   details={'clear_previous': clear_previous, 'task_id': task.id})
        
        return jsonify({
            'success': True,
            'task_id': task.id,
            'message': 'Noise tagging started'
        })
        
    except Exception as e:
        logger.error(f"Error starting noise tagging: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500


@hunting_bp.route('/api/tag_noise/status/<task_id>')
@login_required
def tag_noise_status(task_id):
    """Get status of noise tagging task"""
    try:
        from celery.result import AsyncResult
        from tasks.task_tag_noise import tag_noise_events
        
        task = AsyncResult(task_id, app=tag_noise_events.app)
        
        response = {
            'state': task.state,
            'status': 'Unknown'
        }
        
        if task.state == 'PENDING':
            response['status'] = 'Task is pending...'
            response['progress'] = 0
            response['events_scanned'] = 0
            response['total_events'] = 0
            response['events_tagged'] = 0
            response['rules_matched'] = 0
        elif task.state == 'PROGRESS':
            response.update(task.info or {})
        elif task.state == 'SUCCESS':
            response.update(task.info or {})
        elif task.state == 'FAILURE':
            response['error'] = str(task.info)
            
        return jsonify(response)
        
    except Exception as e:
        logger.error(f"Error checking noise tagging status: {e}")
        return jsonify({'error': str(e), 'state': 'FAILURE'}), 500
