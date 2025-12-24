"""
AI Triage V2 - Pattern Detection Module (v1.44.0)

RAG-based pattern detection using OpenSearch aggregations.
Fast detection of: password spray, brute force, lateral movement, 
pass-the-hash, and authentication chains.

These are FAST (aggregation queries) - no LLM calls needed.
"""

import logging
import ipaddress
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Set, Optional, Any
from collections import defaultdict

logger = logging.getLogger(__name__)


# =============================================================================
# STATIC PATTERNS - Known-bad indicators for pre-tagging
# =============================================================================

# Tier 1: High confidence malicious (tag immediately, HIGH priority)
TIER1_PATTERNS = {
    'encoded_powershell': [
        '-enc', '-encodedcommand', '-e ', 'frombase64string',
        'invoke-expression', ' iex ', '[convert]::', 'decompress',
    ],
    'credential_dumping': [
        'mimikatz', 'sekurlsa', 'logonpasswords', 'lsadump',
        'procdump.*lsass', 'comsvcs.*minidump', 'sqldumper',
        'ntds.dit', 'secretsdump',
    ],
    'attack_tools': [
        'bloodhound', 'sharphound', 'adfind', 'rubeus', 'kerberoast',
        'lazagne', 'pypykatz', 'crackmapexec', 'impacket',
        'cobalt', 'beacon', 'meterpreter', 'empire',
    ],
}

# Tier 2: Strong indicators (tag, MEDIUM priority)
TIER2_PATTERNS = {
    'recon_commands': [
        'nltest', 'net group', 'net user /domain', 'net localgroup',
        'whoami /all', 'whoami /priv', 'systeminfo', 'ipconfig /all',
        'netstat -ano', 'quser', 'query user', 'arp -a',
        'dsquery', 'csvde', 'ldifde', 'adfind',
    ],
    'lateral_movement_tools': [
        'psexec', 'paexec', 'wmic /node', 'winrm', 'winrs',
        'enter-pssession', 'invoke-command', 'invoke-wmimethod',
        'smbexec', 'wmiexec', 'atexec',
    ],
    'persistence_mechanisms': [
        'schtasks /create', 'sc create', 'new-service',
        r'currentversion\\run', 'startup', 'userinit',
        'wmic startup', 'at \\\\',
    ],
}

# Tier 3: Context dependent (tag if near other indicators)
TIER3_PATTERNS = {
    'remote_access_if_unexpected': [
        'anydesk', 'teamviewer', 'screenconnect', 'splashtop',
        'logmein', 'gotoassist', 'bomgar',
    ],
    'archive_with_password': [
        '7z a -p', 'rar a -hp', 'zip -e', 'compress-archive',
    ],
    'log_clearing': [
        'wevtutil cl', 'clear-eventlog', 'del.*\\.evtx',
        'vssadmin delete shadows',
    ],
    'defense_evasion': [
        'set-mppreference -disablerealtimemonitoring',
        'sc stop', 'taskkill.*defender', 'netsh advfirewall set',
    ],
}

# AV/EDR Event IDs for malware detection
AV_DETECTION_EVENT_IDS = [
    '1116', '1117', '1118', '1119',  # Windows Defender detections
    '1006', '1007', '1008',          # Defender scan results
    '1015',                          # Behavior detection
    '5001', '5004',                  # Protection disabled/config changed
]

AV_DETECTION_KEYWORDS = [
    'threat', 'malware', 'quarantine', 'blocked', 'detected',
    'trojan', 'virus', 'ransomware', 'backdoor', 'exploit',
]


# =============================================================================
# PATTERN DETECTION FUNCTIONS (Aggregation-based - FAST)
# =============================================================================

def detect_password_spray(opensearch_client, case_id: int, exclusions: Dict = None,
                         time_window_hours: int = 24) -> Tuple[List[Dict], bool, Dict]:
    """
    Detect password spray patterns via aggregation.
    
    Pattern: Single source IP attempting authentication against multiple unique targets.
    
    Returns:
        Tuple of (events_to_tag, spray_detected, detection_info)
    """
    index_name = f"case_{case_id}"
    
    try:
        # Query for failed logon events (4625 Windows, 6273 NPS)
        # Exclude hidden events
        query = {
            "bool": {
                "should": [
                    {"term": {"normalized_event_id": "4625"}},
                    {"term": {"normalized_event_id": "6273"}},
                ],
                "minimum_should_match": 1,
                "must_not": [
                    {"term": {"is_hidden": True}}
                ]
            }
        }
        
        # Aggregate by source IP, count unique targets
        response = opensearch_client.search(
            index=index_name,
            body={
                "query": query,
                "size": 0,
                "aggs": {
                    "by_source": {
                        "terms": {"field": "source.ip.keyword", "size": 50},
                        "aggs": {
                            "unique_targets": {
                                "cardinality": {"field": "user.name.keyword"}
                            },
                            "sample_events": {
                                "top_hits": {"size": 5, "_source": True}
                            },
                            "time_range": {
                                "stats": {"field": "normalized_timestamp"}
                            }
                        }
                    }
                }
            },
            request_timeout=30
        )
        
        events_to_tag = []
        spray_detected = False
        detection_info = {
            'type': 'password_spray',
            'sources': [],
            'total_attempts': 0,
        }
        
        for bucket in response.get('aggregations', {}).get('by_source', {}).get('buckets', []):
            source_ip = bucket.get('key')
            unique_targets = bucket.get('unique_targets', {}).get('value', 0)
            attempt_count = bucket.get('doc_count', 0)
            
            # Threshold: 5+ unique targets from same source = spray
            if unique_targets >= 5:
                spray_detected = True
                detection_info['sources'].append({
                    'ip': source_ip,
                    'unique_targets': unique_targets,
                    'attempts': attempt_count,
                })
                detection_info['total_attempts'] += attempt_count
                
                # Get sample events to tag
                sample_hits = bucket.get('sample_events', {}).get('hits', {}).get('hits', [])
                events_to_tag.extend(sample_hits)
        
        if spray_detected:
            logger.info(f"[TRIAGE_PATTERNS] Password spray detected: {len(detection_info['sources'])} source(s), "
                       f"{detection_info['total_attempts']} total attempts")
        
        return events_to_tag, spray_detected, detection_info
        
    except Exception as e:
        logger.warning(f"[TRIAGE_PATTERNS] Password spray detection failed: {e}")
        return [], False, {}


def detect_brute_force(opensearch_client, case_id: int, exclusions: Dict = None,
                      threshold: int = 10) -> Tuple[List[Dict], bool, Dict]:
    """
    Detect brute force patterns via aggregation.
    
    Pattern: Multiple failed attempts against a single target account.
    
    Returns:
        Tuple of (events_to_tag, brute_force_detected, detection_info)
    """
    index_name = f"case_{case_id}"
    
    try:
        query = {
            "bool": {
                "should": [
                    {"term": {"normalized_event_id": "4625"}},
                    {"term": {"normalized_event_id": "6273"}},
                ],
                "minimum_should_match": 1,
                "must_not": [
                    {"term": {"is_hidden": True}}
                ]
            }
        }
        
        # Aggregate by target user, count attempts
        response = opensearch_client.search(
            index=index_name,
            body={
                "query": query,
                "size": 0,
                "aggs": {
                    "by_target": {
                        "terms": {"field": "user.name.keyword", "size": 50},
                        "aggs": {
                            "unique_sources": {
                                "cardinality": {"field": "source.ip.keyword"}
                            },
                            "sample_events": {
                                "top_hits": {"size": 5, "_source": True}
                            }
                        }
                    }
                }
            },
            request_timeout=30
        )
        
        events_to_tag = []
        brute_force_detected = False
        detection_info = {
            'type': 'brute_force',
            'targets': [],
            'total_attempts': 0,
        }
        
        for bucket in response.get('aggregations', {}).get('by_target', {}).get('buckets', []):
            target_user = bucket.get('key')
            attempt_count = bucket.get('doc_count', 0)
            
            # Skip noise accounts
            if not target_user or target_user.lower() in ['n/a', '-', 'system', 'anonymous']:
                continue
            
            # Threshold: 10+ failed attempts against single user = brute force
            if attempt_count >= threshold:
                brute_force_detected = True
                detection_info['targets'].append({
                    'user': target_user,
                    'attempts': attempt_count,
                    'unique_sources': bucket.get('unique_sources', {}).get('value', 0),
                })
                detection_info['total_attempts'] += attempt_count
                
                sample_hits = bucket.get('sample_events', {}).get('hits', {}).get('hits', [])
                events_to_tag.extend(sample_hits)
        
        if brute_force_detected:
            logger.info(f"[TRIAGE_PATTERNS] Brute force detected: {len(detection_info['targets'])} target(s), "
                       f"{detection_info['total_attempts']} total attempts")
        
        return events_to_tag, brute_force_detected, detection_info
        
    except Exception as e:
        logger.warning(f"[TRIAGE_PATTERNS] Brute force detection failed: {e}")
        return [], False, {}


def detect_lateral_movement(opensearch_client, case_id: int, known_systems: Set[str],
                           exclusions: Dict = None) -> Tuple[List[Dict], bool, Dict]:
    """
    Detect lateral movement patterns via aggregation.
    
    Pattern: Single user authenticating to multiple systems in short time window.
    
    Returns:
        Tuple of (events_to_tag, lateral_detected, detection_info)
    """
    index_name = f"case_{case_id}"
    
    try:
        # Query for successful logons (4624) with LogonType 3 (Network) or 10 (RDP)
        # Exclude hidden events
        query = {
            "bool": {
                "must": [
                    {"term": {"normalized_event_id": "4624"}},
                ],
                "should": [
                    {"match": {"search_blob": "logon type: 3"}},
                    {"match": {"search_blob": "logon type: 10"}},
                    {"match": {"search_blob": "logontype.*3"}},
                    {"match": {"search_blob": "logontype.*10"}},
                ],
                "minimum_should_match": 0,  # LogonType filter is best-effort
                "must_not": [
                    {"term": {"is_hidden": True}}
                ]
            }
        }
        
        # Aggregate by username, then by target system
        response = opensearch_client.search(
            index=index_name,
            body={
                "query": query,
                "size": 0,
                "aggs": {
                    "by_user": {
                        "terms": {"field": "user.name.keyword", "size": 50},
                        "aggs": {
                            "unique_systems": {
                                "cardinality": {"field": "normalized_computer.keyword"}
                            },
                            "systems": {
                                "terms": {"field": "normalized_computer.keyword", "size": 20}
                            },
                            "sample_events": {
                                "top_hits": {"size": 10, "_source": True}
                            }
                        }
                    }
                }
            },
            request_timeout=30
        )
        
        events_to_tag = []
        lateral_detected = False
        detection_info = {
            'type': 'lateral_movement',
            'users': [],
        }
        
        for bucket in response.get('aggregations', {}).get('by_user', {}).get('buckets', []):
            username = bucket.get('key')
            unique_systems = bucket.get('unique_systems', {}).get('value', 0)
            
            # Skip noise accounts
            if not username or username.lower() in ['system', 'anonymous', '-', 'n/a']:
                continue
            if username.endswith('$'):  # Machine accounts
                continue
            
            # Threshold: 3+ unique systems = lateral movement
            if unique_systems >= 3:
                lateral_detected = True
                
                systems_list = [b['key'] for b in bucket.get('systems', {}).get('buckets', [])]
                
                detection_info['users'].append({
                    'user': username,
                    'systems_count': unique_systems,
                    'systems': systems_list[:10],
                })
                
                sample_hits = bucket.get('sample_events', {}).get('hits', {}).get('hits', [])
                events_to_tag.extend(sample_hits)
        
        if lateral_detected:
            logger.info(f"[TRIAGE_PATTERNS] Lateral movement detected: {len(detection_info['users'])} user(s) "
                       f"moving across multiple systems")
        
        return events_to_tag, lateral_detected, detection_info
        
    except Exception as e:
        logger.warning(f"[TRIAGE_PATTERNS] Lateral movement detection failed: {e}")
        return [], False, {}


def detect_auth_chains(opensearch_client, case_id: int, known_systems: Set[str],
                      tolerance_seconds: int = 2) -> Tuple[List[Dict], bool, Dict]:
    """
    Detect authentication chains (NPS → DC → Target).
    
    Pattern: Same-timestamp events across 6272 (NPS) + 4776 (DC) + 4624 (Target)
    with unknown workstation source.
    
    Returns:
        Tuple of (events_to_tag, chains_detected, detection_info)
    """
    index_name = f"case_{case_id}"
    
    try:
        # First, get all auth events (exclude hidden)
        query = {
            "bool": {
                "should": [
                    {"term": {"normalized_event_id": "6272"}},  # NPS granted
                    {"term": {"normalized_event_id": "4776"}},  # Credential validation
                    {"term": {"normalized_event_id": "4624"}},  # Logon success
                ],
                "minimum_should_match": 1,
                "must_not": [
                    {"term": {"is_hidden": True}}
                ]
            }
        }
        
        response = opensearch_client.search(
            index=index_name,
            body={
                "query": query,
                "size": 1000,
                "sort": [{"normalized_timestamp": "asc"}],
                "_source": True
            },
            request_timeout=30
        )
        
        hits = response.get('hits', {}).get('hits', [])
        
        # Group events by timestamp (rounded to tolerance)
        events_by_time = defaultdict(list)
        for hit in hits:
            source = hit.get('_source', {})
            ts = source.get('normalized_timestamp', '')
            if ts:
                # Round to nearest second for grouping
                ts_key = ts[:19]  # YYYY-MM-DDTHH:MM:SS
                events_by_time[ts_key].append(hit)
        
        events_to_tag = []
        chains_detected = False
        detection_info = {
            'type': 'auth_chain',
            'chains': [],
            'unknown_workstations': [],
        }
        
        for ts_key, events in events_by_time.items():
            if len(events) < 2:
                continue
            
            # Check if we have auth chain components
            event_ids = set()
            workstation = None
            
            for event in events:
                source = event.get('_source', {})
                event_id = str(source.get('normalized_event_id', ''))
                event_ids.add(event_id)
                
                # Extract workstation from 4624 event
                if event_id == '4624':
                    # Try various field names
                    ws = (source.get('WorkstationName') or 
                          source.get('forensic_WorkstationName') or
                          source.get('source', {}).get('hostname'))
                    if ws and ws not in ['-', 'N/A', '']:
                        workstation = ws.upper().split('.')[0]
            
            # Check for auth chain pattern
            has_chain = ('4624' in event_ids and 
                        ('4776' in event_ids or '6272' in event_ids))
            
            if has_chain:
                # Check if workstation is unknown
                unknown_source = False
                if workstation:
                    normalized_ws = workstation.upper()
                    if normalized_ws not in known_systems:
                        unknown_source = True
                        if normalized_ws not in detection_info['unknown_workstations']:
                            detection_info['unknown_workstations'].append(normalized_ws)
                
                if unknown_source or len(event_ids) >= 2:
                    chains_detected = True
                    detection_info['chains'].append({
                        'timestamp': ts_key,
                        'event_ids': list(event_ids),
                        'workstation': workstation,
                        'unknown_source': unknown_source,
                    })
                    events_to_tag.extend(events)
        
        if chains_detected:
            unknown_count = len(detection_info['unknown_workstations'])
            logger.info(f"[TRIAGE_PATTERNS] Auth chains detected: {len(detection_info['chains'])} chain(s), "
                       f"{unknown_count} unknown workstation(s)")
        
        return events_to_tag, chains_detected, detection_info
        
    except Exception as e:
        logger.warning(f"[TRIAGE_PATTERNS] Auth chain detection failed: {e}")
        return [], False, {}


def detect_pass_the_hash(opensearch_client, case_id: int) -> Tuple[List[Dict], bool, Dict]:
    """
    Detect pass-the-hash patterns.
    
    Pattern: 4624 with LogonType 9 (NewCredentials) or 4648 (Explicit credentials)
    
    Returns:
        Tuple of (events_to_tag, pth_detected, detection_info)
    """
    index_name = f"case_{case_id}"
    
    try:
        # Query for PTH indicators (exclude hidden)
        query = {
            "bool": {
                "should": [
                    # LogonType 9 = NewCredentials (runas /netonly, PTH)
                    {"bool": {
                        "must": [
                            {"term": {"normalized_event_id": "4624"}},
                            {"match": {"search_blob": "logon type: 9"}},
                        ]
                    }},
                    # 4648 = Explicit credentials
                    {"term": {"normalized_event_id": "4648"}},
                ],
                "minimum_should_match": 1,
                "must_not": [
                    {"term": {"is_hidden": True}}
                ]
            }
        }
        
        response = opensearch_client.search(
            index=index_name,
            body={
                "query": query,
                "size": 100,
                "_source": True
            },
            request_timeout=30
        )
        
        hits = response.get('hits', {}).get('hits', [])
        total = response.get('hits', {}).get('total', {}).get('value', 0)
        
        pth_detected = total > 0
        detection_info = {
            'type': 'pass_the_hash',
            'event_count': total,
        }
        
        if pth_detected:
            logger.info(f"[TRIAGE_PATTERNS] Pass-the-hash indicators detected: {total} event(s)")
        
        return hits, pth_detected, detection_info
        
    except Exception as e:
        logger.warning(f"[TRIAGE_PATTERNS] PTH detection failed: {e}")
        return [], False, {}


def search_av_detections(opensearch_client, case_id: int) -> Tuple[List[Dict], List[Dict]]:
    """
    Search for AV/EDR malware detection events.
    
    Returns:
        Tuple of (events_to_tag, malware_iocs)
    """
    index_name = f"case_{case_id}"
    
    try:
        # Build query for AV events
        should_clauses = []
        
        # Event ID based
        for event_id in AV_DETECTION_EVENT_IDS:
            should_clauses.append({"term": {"normalized_event_id": event_id}})
        
        # Keyword based
        for keyword in AV_DETECTION_KEYWORDS:
            should_clauses.append({"match": {"search_blob": keyword}})
        
        query = {
            "bool": {
                "should": should_clauses,
                "minimum_should_match": 1,
                "must_not": [
                    {"term": {"is_hidden": True}}
                ]
            }
        }
        
        response = opensearch_client.search(
            index=index_name,
            body={
                "query": query,
                "size": 100,
                "_source": True
            },
            request_timeout=30
        )
        
        hits = response.get('hits', {}).get('hits', [])
        
        # Extract IOCs from detections
        malware_iocs = []
        seen_values = set()
        
        for hit in hits:
            source = hit.get('_source', {})
            blob = source.get('search_blob', '').lower()
            
            # Try to extract malware name/threat name
            # Common patterns in Defender events
            import re
            
            # Pattern: "Threat Name: XXX" or "Name: XXX"
            threat_match = re.search(r'(?:threat\s*name|name)\s*[:\s]+([^\s,;]+)', blob)
            if threat_match:
                threat_name = threat_match.group(1)
                if threat_name not in seen_values and len(threat_name) > 3:
                    malware_iocs.append({
                        'type': 'malware',
                        'value': threat_name,
                        'source': 'av_detection'
                    })
                    seen_values.add(threat_name)
            
            # Pattern: file path
            path_match = re.search(r'([a-z]:\\[^\s,;]+\.(exe|dll|ps1|bat|vbs|js))', blob, re.IGNORECASE)
            if path_match:
                file_path = path_match.group(1)
                if file_path not in seen_values:
                    malware_iocs.append({
                        'type': 'filepath',
                        'value': file_path,
                        'source': 'av_detection'
                    })
                    seen_values.add(file_path)
        
        if hits:
            logger.info(f"[TRIAGE_PATTERNS] Found {len(hits)} AV detection events, extracted {len(malware_iocs)} IOCs")
        
        return hits, malware_iocs
        
    except Exception as e:
        logger.warning(f"[TRIAGE_PATTERNS] AV detection search failed: {e}")
        return [], []


def run_all_pattern_detection(opensearch_client, case_id: int, 
                             known_systems: Set[str] = None) -> Dict:
    """
    Run all pattern detection and return consolidated results.
    
    Returns:
        Dict with all detection results
    """
    if known_systems is None:
        known_systems = set()
    
    results = {
        'events_to_tag': [],
        'iocs_discovered': [],
        'patterns_detected': [],
        'detection_details': {},
    }
    
    seen_event_ids = set()
    
    # Password Spray
    events, detected, info = detect_password_spray(opensearch_client, case_id)
    if detected:
        results['patterns_detected'].append('password_spray')
        results['detection_details']['password_spray'] = info
        for e in events:
            if e['_id'] not in seen_event_ids:
                results['events_to_tag'].append(e)
                seen_event_ids.add(e['_id'])
        # Add source IPs as IOCs
        for source in info.get('sources', []):
            results['iocs_discovered'].append({
                'type': 'ip',
                'value': source['ip'],
                'source': 'password_spray',
                'priority': 'HIGH'
            })
    
    # Brute Force
    events, detected, info = detect_brute_force(opensearch_client, case_id)
    if detected:
        results['patterns_detected'].append('brute_force')
        results['detection_details']['brute_force'] = info
        for e in events:
            if e['_id'] not in seen_event_ids:
                results['events_to_tag'].append(e)
                seen_event_ids.add(e['_id'])
    
    # Lateral Movement
    events, detected, info = detect_lateral_movement(opensearch_client, case_id, known_systems)
    if detected:
        results['patterns_detected'].append('lateral_movement')
        results['detection_details']['lateral_movement'] = info
        for e in events:
            if e['_id'] not in seen_event_ids:
                results['events_to_tag'].append(e)
                seen_event_ids.add(e['_id'])
    
    # Auth Chains
    events, detected, info = detect_auth_chains(opensearch_client, case_id, known_systems)
    if detected:
        results['patterns_detected'].append('auth_chain')
        results['detection_details']['auth_chain'] = info
        for e in events:
            if e['_id'] not in seen_event_ids:
                results['events_to_tag'].append(e)
                seen_event_ids.add(e['_id'])
        # Add unknown workstations as IOCs
        for ws in info.get('unknown_workstations', []):
            results['iocs_discovered'].append({
                'type': 'hostname',
                'value': ws,
                'source': 'auth_chain',
                'priority': 'HIGH'
            })
    
    # Pass-the-Hash
    events, detected, info = detect_pass_the_hash(opensearch_client, case_id)
    if detected:
        results['patterns_detected'].append('pass_the_hash')
        results['detection_details']['pass_the_hash'] = info
        for e in events:
            if e['_id'] not in seen_event_ids:
                results['events_to_tag'].append(e)
                seen_event_ids.add(e['_id'])
    
    logger.info(f"[TRIAGE_PATTERNS] Pattern detection complete: {len(results['patterns_detected'])} patterns, "
               f"{len(results['events_to_tag'])} events to tag, {len(results['iocs_discovered'])} IOCs discovered")
    
    return results

