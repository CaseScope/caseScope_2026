"""
Login Analysis Module
Analyzes Windows logon events (Event ID 4624 and 4625) and provides distinct user/computer combinations
"""
import logging
from typing import List, Dict, Optional
from datetime import datetime

logger = logging.getLogger(__name__)

# Windows Logon Type mapping (for Event ID 4624/4625)
LOGON_TYPE_DESCRIPTIONS = {
    '0': 'System - Internal system account startup',
    '1': 'Special Logon - Privileged logon (Run as Administrator)',
    '2': 'Interactive (Console) - Physical keyboard/mouse login',
    '3': 'Network - Accessing shared resources (no RDP)',
    '4': 'Batch - Scheduled tasks',
    '5': 'Service - Windows service started',
    '6': 'Proxy - Legacy proxy logon (rare)',
    '7': 'Unlock - Workstation unlocked',
    '8': 'NetworkCleartext - Credentials in cleartext (bad)',
    '9': 'NewCredentials - RunAs with different credentials',
    '10': 'Remote Desktop (RDP) - Remote Desktop logon',
    '11': 'CachedInteractive - Cached domain credentials',
    '12': 'RemoteInteractive - Azure/WinRM/modern remote methods'
}


def get_logins_by_event_id(opensearch_client, case_id: int, event_id: str, 
                           date_range: str = 'all',
                           custom_date_start: Optional[datetime] = None,
                           custom_date_end: Optional[datetime] = None,
                           latest_event_timestamp: Optional[datetime] = None) -> Dict:
    """
    Query OpenSearch for specific Windows logon Event IDs
    Returns distinct username/computer combinations
    
    Args:
        opensearch_client: OpenSearch client instance
        case_id: Case ID to search within
        event_id: Event ID to search for (e.g., '4624', '4625')
        date_range: Time range ('all', '24h', '7d', '30d', 'custom')
        custom_date_start: Start datetime for custom range
        custom_date_end: End datetime for custom range
        latest_event_timestamp: Latest event timestamp for relative ranges
        
    Returns:
        Dict with 'logins' list and 'total_events' count
    """
    try:
        index_pattern = f"case_{case_id}"
        
        # Build date filter
        date_filter = None
        if date_range == 'custom' and custom_date_start and custom_date_end:
            date_filter = {
                "range": {
                    "normalized_timestamp": {
                        "gte": custom_date_start.isoformat(),
                        "lte": custom_date_end.isoformat()
                    }
                }
            }
        elif date_range in ['24h', '7d', '30d'] and latest_event_timestamp:
            hours_map = {'24h': 24, '7d': 168, '30d': 720}
            hours = hours_map.get(date_range, 0)
            from datetime import timedelta
            start_time = latest_event_timestamp - timedelta(hours=hours)
            date_filter = {
                "range": {
                    "normalized_timestamp": {
                        "gte": start_time.isoformat()
                    }
                }
            }
        
        # Build OpenSearch query for specified Event ID
        # Check multiple possible field locations
        event_id_int = int(event_id)
        must_conditions = [
            {
                "bool": {
                    "should": [
                        {"term": {"normalized_event_id": event_id}},
                        {"term": {"System.EventID": event_id_int}},
                        {"term": {"System.EventID.#text": event_id}},
                        {"term": {"Event.System.EventID": event_id_int}},
                        {"term": {"Event.System.EventID.#text": event_id}}
                    ],
                    "minimum_should_match": 1
                }
            }
        ]
        
        if date_filter:
            must_conditions.append(date_filter)
        
        # Use Scroll API for unlimited results (bypasses 10,000 limit)
        query = {
            "_source": [
                "normalized_timestamp",
                "normalized_event_id",
                "normalized_computer_name",
                "System.Computer",
                "System.EventID",
                "Event.System.Computer",
                "Event.System.EventID",
                "Event.EventData",  # v1.13.9: EventData is a JSON string, fetch entire field
                "EventData"  # v1.13.9: EventData is a JSON string, fetch entire field
            ],
            "query": {
                "bool": {
                    "must": must_conditions
                }
            },
            "sort": [{"normalized_timestamp": {"order": "desc"}}]
        }
        
        logger.info(f"[LOGIN_ANALYSIS] Searching for Event ID {event_id} in case {case_id}")
        
        # Use scroll API to get all results
        scroll_id = None
        all_hits = []
        try:
            result = opensearch_client.search(
                index=index_pattern, 
                body=query,
                scroll='2m',  # Keep scroll context alive for 2 minutes
                size=1000  # Batch size per scroll
            )
            
            total_events = result['hits']['total']['value']
            logger.info(f"[LOGIN_ANALYSIS] Found {total_events} Event ID {event_id} events")
            
            scroll_id = result['_scroll_id']
            all_hits.extend(result['hits']['hits'])
            
            # Continue scrolling until no more results
            while len(result['hits']['hits']) > 0:
                result = opensearch_client.scroll(scroll_id=scroll_id, scroll='2m')
                scroll_id = result['_scroll_id']
                all_hits.extend(result['hits']['hits'])
                if len(result['hits']['hits']) == 0:
                    break
            
            logger.info(f"[LOGIN_ANALYSIS] Retrieved {len(all_hits)} total events via scroll")
        finally:
            # Clean up scroll context
            if scroll_id:
                try:
                    opensearch_client.clear_scroll(scroll_id=scroll_id)
                except:
                    pass
        
        # Process results to extract distinct username/computer pairs
        seen_combinations = set()  # (username, computer) tuples
        distinct_logins = []
        filtered_count = 0  # Track how many filtered out
        
        for hit in all_hits:
            source = hit['_source']
            
            # Extract computer name
            computer = _extract_computer_name(source)
            
            # Extract username (TargetUserName is the logged-in user)
            username = _extract_username(source)
            
            # Track filtering
            if username and not _is_valid_username(username):
                filtered_count += 1
            
            # Extract LogonType for 4624 events
            logon_type = _extract_logon_type(source)
            
            if username and computer:
                # Create unique key (include logon_type for better deduplication)
                combo_key = (username.lower(), computer.lower(), logon_type)
                
                # Only add if this combination hasn't been seen
                if combo_key not in seen_combinations:
                    seen_combinations.add(combo_key)
                    
                    # Get timestamp
                    timestamp = source.get('normalized_timestamp', 'Unknown')
                    if timestamp != 'Unknown':
                        try:
                            dt = datetime.fromisoformat(timestamp)
                            timestamp = dt.strftime('%Y-%m-%d %H:%M:%S')
                        except:
                            pass
                    
                    # Get LogonType description
                    logon_type_desc = LOGON_TYPE_DESCRIPTIONS.get(logon_type, f'{logon_type} - Unknown')
                    
                    distinct_logins.append({
                        'username': username,
                        'computer': computer,
                        'first_seen': timestamp,
                        'logon_type': logon_type,
                        'logon_type_description': logon_type_desc
                    })
        
        logger.info(f"[LOGIN_ANALYSIS] Found {len(distinct_logins)} distinct username/computer combinations")
        logger.info(f"[LOGIN_ANALYSIS] Filtered out {filtered_count} machine/system accounts")
        
        # Enrich with Known User and IOC data
        from known_user_utils import enrich_login_records
        enriched_logins = enrich_login_records(distinct_logins, case_id)
        
        return {
            'success': True,
            'logins': enriched_logins,
            'total_events': total_events,
            'distinct_count': len(enriched_logins),
            'filtered_count': filtered_count
        }
        
    except Exception as e:
        logger.error(f"[LOGIN_ANALYSIS] Error analyzing logins: {e}", exc_info=True)
        return {
            'success': False,
            'error': str(e),
            'logins': [],
            'total_events': 0,
            'distinct_count': 0
        }


def get_successful_logins(opensearch_client, case_id: int, date_range: str = 'all',
                          custom_date_start: Optional[datetime] = None,
                          custom_date_end: Optional[datetime] = None,
                          latest_event_timestamp: Optional[datetime] = None) -> Dict:
    """
    Query OpenSearch for Event ID 4624 (successful Windows logons)
    Returns distinct username/computer combinations
    """
    return get_logins_by_event_id(
        opensearch_client, case_id, '4624', date_range,
        custom_date_start, custom_date_end, latest_event_timestamp
    )


def get_failed_logins(opensearch_client, case_id: int, date_range: str = 'all',
                      custom_date_start: Optional[datetime] = None,
                      custom_date_end: Optional[datetime] = None,
                      latest_event_timestamp: Optional[datetime] = None) -> Dict:
    """
    Query OpenSearch for Event ID 4625 (failed Windows logons)
    Returns distinct username/computer combinations
    """
    return get_logins_by_event_id(
        opensearch_client, case_id, '4625', date_range,
        custom_date_start, custom_date_end, latest_event_timestamp
    )


def get_console_logins(opensearch_client, case_id: int, date_range: str = 'all',
                       custom_date_start: Optional[datetime] = None,
                       custom_date_end: Optional[datetime] = None,
                       latest_event_timestamp: Optional[datetime] = None) -> Dict:
    """
    Query OpenSearch for Event ID 4624 with LogonType = 2 (interactive console logins)
    Returns distinct username/computer combinations
    """
    try:
        index_pattern = f"case_{case_id}"
        
        # Build date filter (same logic as other login functions)
        date_filter = None
        if date_range == 'custom' and custom_date_start and custom_date_end:
            date_filter = {
                "range": {
                    "normalized_timestamp": {
                        "gte": custom_date_start.isoformat(),
                        "lte": custom_date_end.isoformat()
                    }
                }
            }
        elif date_range in ['24h', '7d', '30d'] and latest_event_timestamp:
            hours_map = {'24h': 24, '7d': 168, '30d': 720}
            hours = hours_map.get(date_range, 0)
            from datetime import timedelta
            start_time = latest_event_timestamp - timedelta(hours=hours)
            date_filter = {
                "range": {
                    "normalized_timestamp": {
                        "gte": start_time.isoformat()
                    }
                }
            }
        
        # Build OpenSearch query for Event ID 4624
        # v1.13.9 FIX: EventData is now a JSON string, can't filter by nested LogonType
        # Solution: Fetch all 4624 events, filter by LogonType=2 in Python after parsing
        must_conditions = [
            # Event ID 4624
            {
                "bool": {
                    "should": [
                        {"term": {"normalized_event_id": "4624"}},
                        {"term": {"System.EventID": 4624}},
                        {"term": {"System.EventID.#text": "4624"}},
                        {"term": {"Event.System.EventID": 4624}},
                        {"term": {"Event.System.EventID.#text": "4624"}}
                    ],
                    "minimum_should_match": 1
                }
            }
            # NOTE: LogonType filter removed - applied in Python after EventData parsing
        ]
        
        if date_filter:
            must_conditions.append(date_filter)
        
        # Use Scroll API for unlimited results (bypasses 10,000 limit)
        query = {
            "_source": [
                "normalized_timestamp",
                "normalized_event_id",
                "normalized_computer_name",
                "System.Computer",
                "System.EventID",
                "Event.System.Computer",
                "Event.System.EventID",
                "Event.EventData",  # v1.13.9: EventData is a JSON string, fetch entire field
                "EventData"  # v1.13.9: EventData is a JSON string, fetch entire field
            ],
            "query": {
                "bool": {
                    "must": must_conditions
                }
            },
            "sort": [{"normalized_timestamp": {"order": "desc"}}]
        }
        
        logger.info(f"[CONSOLE_LOGINS] Searching for Event ID 4624 with LogonType=2 in case {case_id}")
        
        # Use scroll API to get all results
        scroll_id = None
        all_hits = []
        try:
            result = opensearch_client.search(
                index=index_pattern, 
                body=query,
                scroll='2m',
                size=1000
            )
            
            total_events = result['hits']['total']['value']
            logger.info(f"[CONSOLE_LOGINS] Found {total_events} Event ID 4624 events")
            
            scroll_id = result['_scroll_id']
            all_hits.extend(result['hits']['hits'])
            
            while len(result['hits']['hits']) > 0:
                result = opensearch_client.scroll(scroll_id=scroll_id, scroll='2m')
                scroll_id = result['_scroll_id']
                all_hits.extend(result['hits']['hits'])
                if len(result['hits']['hits']) == 0:
                    break
            
            logger.info(f"[CONSOLE_LOGINS] Retrieved {len(all_hits)} total events via scroll")
        finally:
            if scroll_id:
                try:
                    opensearch_client.clear_scroll(scroll_id=scroll_id)
                except:
                    pass
        
        # Process results to extract distinct username/computer pairs
        seen_combinations = set()  # (username, computer) tuples
        distinct_logins = []
        
        for hit in all_hits:
            source = hit['_source']
            
            # v1.13.9 FIX: Filter by LogonType=2 in Python (EventData is JSON string)
            logon_type = _extract_logon_type(source)
            if logon_type != '2':
                continue  # Skip non-console logins
            
            # Extract computer name (same as other login functions)
            computer = _extract_computer_name(source)
            
            # Extract username (TargetUserName)
            username = _extract_username(source)
            
            if username and computer:
                # Create unique key
                combo_key = (username.lower(), computer.lower())
                
                # Only add if this combination hasn't been seen
                if combo_key not in seen_combinations:
                    seen_combinations.add(combo_key)
                    
                    # Get timestamp
                    timestamp = source.get('normalized_timestamp', 'Unknown')
                    if timestamp != 'Unknown':
                        try:
                            dt = datetime.fromisoformat(timestamp)
                            timestamp = dt.strftime('%Y-%m-%d %H:%M:%S')
                        except:
                            pass
                    
                    distinct_logins.append({
                        'username': username,
                        'computer': computer,
                        'first_seen': timestamp
                    })
        
        logger.info(f"[CONSOLE_LOGINS] Found {len(distinct_logins)} distinct console login username/computer combinations")
        
        # Enrich with Known User and IOC data
        from known_user_utils import enrich_login_records
        enriched_logins = enrich_login_records(distinct_logins, case_id)
        
        return {
            'success': True,
            'logins': enriched_logins,
            'total_events': total_events,
            'distinct_count': len(enriched_logins)
        }
        
    except Exception as e:
        logger.error(f"[CONSOLE_LOGINS] Error analyzing console logins: {e}", exc_info=True)
        return {
            'success': False,
            'error': str(e),
            'logins': [],
            'total_events': 0,
            'distinct_count': 0
        }


def get_rdp_connections(opensearch_client, case_id: int, date_range: str = 'all',
                        custom_date_start: Optional[datetime] = None,
                        custom_date_end: Optional[datetime] = None,
                        latest_event_timestamp: Optional[datetime] = None) -> Dict:
    """
    Query OpenSearch for Event ID 1149 (RDP connections - TerminalServices-RemoteConnectionManager)
    Returns distinct username/computer combinations
    
    Note: Uses different field for username (Event.UserData.EventXML.Param1)
    """
    try:
        index_pattern = f"case_{case_id}"
        
        # Build date filter (same logic as other login functions)
        date_filter = None
        if date_range == 'custom' and custom_date_start and custom_date_end:
            date_filter = {
                "range": {
                    "normalized_timestamp": {
                        "gte": custom_date_start.isoformat(),
                        "lte": custom_date_end.isoformat()
                    }
                }
            }
        elif date_range in ['24h', '7d', '30d'] and latest_event_timestamp:
            hours_map = {'24h': 24, '7d': 168, '30d': 720}
            hours = hours_map.get(date_range, 0)
            from datetime import timedelta
            start_time = latest_event_timestamp - timedelta(hours=hours)
            date_filter = {
                "range": {
                    "normalized_timestamp": {
                        "gte": start_time.isoformat()
                    }
                }
            }
        
        # Build OpenSearch query for Event ID 1149
        event_id = '1149'
        event_id_int = 1149
        must_conditions = [
            {
                "bool": {
                    "should": [
                        {"term": {"normalized_event_id": event_id}},
                        {"term": {"System.EventID": event_id_int}},
                        {"term": {"System.EventID.#text": event_id}},
                        {"term": {"Event.System.EventID": event_id_int}},
                        {"term": {"Event.System.EventID.#text": event_id}}
                    ],
                    "minimum_should_match": 1
                }
            }
        ]
        
        if date_filter:
            must_conditions.append(date_filter)
        
        # Use Scroll API for unlimited results (bypasses 10,000 limit)
        query = {
            "_source": [
                "normalized_timestamp",
                "normalized_event_id",
                "normalized_computer_name",
                "System.Computer",
                "System.EventID",
                "Event.System.Computer",
                "Event.System.EventID",
                "Event.UserData",  # v1.13.9: UserData is a JSON string, fetch entire field
                "UserData"  # v1.13.9: UserData is a JSON string, fetch entire field
            ],
            "query": {
                "bool": {
                    "must": must_conditions
                }
            },
            "sort": [{"normalized_timestamp": {"order": "desc"}}]
        }
        
        logger.info(f"[RDP_ANALYSIS] Searching for Event ID 1149 in case {case_id}")
        
        # Use scroll API to get all results
        scroll_id = None
        all_hits = []
        try:
            result = opensearch_client.search(
                index=index_pattern, 
                body=query,
                scroll='2m',
                size=1000
            )
            
            total_events = result['hits']['total']['value']
            logger.info(f"[RDP_ANALYSIS] Found {total_events} Event ID 1149 events")
            
            scroll_id = result['_scroll_id']
            all_hits.extend(result['hits']['hits'])
            
            while len(result['hits']['hits']) > 0:
                result = opensearch_client.scroll(scroll_id=scroll_id, scroll='2m')
                scroll_id = result['_scroll_id']
                all_hits.extend(result['hits']['hits'])
                if len(result['hits']['hits']) == 0:
                    break
            
            logger.info(f"[RDP_ANALYSIS] Retrieved {len(all_hits)} total events via scroll")
        finally:
            if scroll_id:
                try:
                    opensearch_client.clear_scroll(scroll_id=scroll_id)
                except:
                    pass
        
        # Process results to extract distinct username/computer pairs
        seen_combinations = set()  # (username, computer) tuples
        distinct_connections = []
        
        for hit in all_hits:
            source = hit['_source']
            
            # Extract computer name (same as other login functions)
            computer = _extract_computer_name(source)
            
            # Extract RDP username from Event.UserData.EventXML.Param1
            username = _extract_rdp_username(source)
            
            if username and computer:
                # Create unique key
                combo_key = (username.lower(), computer.lower())
                
                # Only add if this combination hasn't been seen
                if combo_key not in seen_combinations:
                    seen_combinations.add(combo_key)
                    
                    # Get timestamp
                    timestamp = source.get('normalized_timestamp', 'Unknown')
                    if timestamp != 'Unknown':
                        try:
                            dt = datetime.fromisoformat(timestamp)
                            timestamp = dt.strftime('%Y-%m-%d %H:%M:%S')
                        except:
                            pass
                    
                    distinct_connections.append({
                        'username': username,
                        'computer': computer,
                        'first_seen': timestamp
                    })
        
        logger.info(f"[RDP_ANALYSIS] Found {len(distinct_connections)} distinct RDP username/computer combinations")
        
        # Enrich with Known User and IOC data
        from known_user_utils import enrich_login_records
        enriched_connections = enrich_login_records(distinct_connections, case_id)
        
        return {
            'success': True,
            'logins': enriched_connections,
            'total_events': total_events,
            'distinct_count': len(enriched_connections)
        }
        
    except Exception as e:
        logger.error(f"[RDP_ANALYSIS] Error analyzing RDP connections: {e}", exc_info=True)
        return {
            'success': False,
            'error': str(e),
            'logins': [],
            'total_events': 0,
            'distinct_count': 0
        }


def _extract_computer_name(source: Dict) -> Optional[str]:
    """Extract computer name from event source (handles multiple field locations)"""
    # Try normalized field first
    if 'normalized_computer_name' in source and source['normalized_computer_name']:
        return source['normalized_computer_name']
    
    # Try System.Computer
    if 'System' in source and isinstance(source['System'], dict):
        computer = source['System'].get('Computer')
        if computer:
            return computer
    
    # Try Event.System.Computer
    if 'Event' in source and isinstance(source['Event'], dict):
        if 'System' in source['Event'] and isinstance(source['Event']['System'], dict):
            computer = source['Event']['System'].get('Computer')
            if computer:
                return computer
    
    return None


def _extract_username(source: Dict) -> Optional[str]:
    """Extract username from event source (TargetUserName is the logged-in user)"""
    import json
    
    # Try Event.EventData.TargetUserName (most common for EVTX->JSON)
    if 'Event' in source and isinstance(source['Event'], dict):
        event_data = source['Event'].get('EventData')
        # v1.13.9+: EventData might be a JSON string
        if isinstance(event_data, str):
            try:
                event_data = json.loads(event_data)
            except:
                pass
        if isinstance(event_data, dict):
            username = event_data.get('TargetUserName')
            if username and _is_valid_username(username):
                return username
    
    # Try EventData.TargetUserName (direct structure)
    event_data = source.get('EventData')
    # v1.13.9+: EventData might be a JSON string
    if isinstance(event_data, str):
        try:
            event_data = json.loads(event_data)
        except:
            pass
    if isinstance(event_data, dict):
        username = event_data.get('TargetUserName')
        if username and _is_valid_username(username):
            return username
    
    # Fallback to SubjectUserName if TargetUserName not found
    if 'Event' in source and isinstance(source['Event'], dict):
        event_data = source['Event'].get('EventData')
        # v1.13.9+: EventData might be a JSON string
        if isinstance(event_data, str):
            try:
                event_data = json.loads(event_data)
            except:
                pass
        if isinstance(event_data, dict):
            username = event_data.get('SubjectUserName')
            if username and _is_valid_username(username):
                return username
    
    event_data = source.get('EventData')
    # v1.13.9+: EventData might be a JSON string
    if isinstance(event_data, str):
        try:
            event_data = json.loads(event_data)
        except:
            pass
    if isinstance(event_data, dict):
        username = event_data.get('SubjectUserName')
        if username and _is_valid_username(username):
            return username
    
    return None


def _extract_rdp_username(source: Dict) -> Optional[str]:
    """Extract RDP username from Event ID 1149 (Event.UserData.EventXML.Param1)"""
    import json
    
    # Try Event.UserData.EventXML.Param1 (RDP connection username)
    if 'Event' in source and isinstance(source['Event'], dict):
        user_data = source['Event'].get('UserData')
        # v1.13.9+: UserData might be a JSON string
        if isinstance(user_data, str):
            try:
                user_data = json.loads(user_data)
            except:
                pass
        if isinstance(user_data, dict):
            event_xml = user_data.get('EventXML')
            # EventXML might also be a JSON string!
            if isinstance(event_xml, str):
                try:
                    event_xml = json.loads(event_xml)
                except:
                    pass
            if isinstance(event_xml, dict):
                username = event_xml.get('Param1')
                if username and _is_valid_username(username):
                    return username
    
    # Try UserData.EventXML.Param1 (direct structure)
    user_data = source.get('UserData')
    # v1.13.9+: UserData might be a JSON string
    if isinstance(user_data, str):
        try:
            user_data = json.loads(user_data)
        except:
            pass
    if isinstance(user_data, dict):
        event_xml = user_data.get('EventXML')
        # EventXML might also be a JSON string!
        if isinstance(event_xml, str):
            try:
                event_xml = json.loads(event_xml)
            except:
                pass
        if isinstance(event_xml, dict):
            username = event_xml.get('Param1')
            if username and _is_valid_username(username):
                return username
    
    return None


def _is_valid_username(username: str) -> bool:
    """
    Check if username is valid (not a system account or special account)
    
    Filters out:
    - System accounts: SYSTEM, ANONYMOUS LOGON, etc.
    - Machine accounts: accounts ending with $
    - Windows system accounts: DWM-*, UMFD-*
    """
    if not username:
        return False
    
    # Filter out explicit system accounts
    if username in ['-', 'SYSTEM', 'ANONYMOUS LOGON', '$']:
        return False
    
    # Filter out machine accounts (ending with $)
    if username.endswith('$'):
        return False
    
    # Filter out Desktop Window Manager accounts (DWM-*)
    if username.upper().startswith('DWM-'):
        return False
    
    # Filter out User Mode Font Driver accounts (UMFD-*)
    if username.upper().startswith('UMFD-'):
        return False
    
    return True


def get_vpn_authentications(opensearch_client, case_id: int, firewall_ip: str,
                            date_range: str = 'all',
                            custom_date_start: Optional[datetime] = None,
                            custom_date_end: Optional[datetime] = None,
                            latest_event_timestamp: Optional[datetime] = None) -> Dict:
    """
    Query OpenSearch for VPN authentications (Event ID 4624 or 6272 with specific firewall IP)
    Returns ALL events (NO deduplication) - every authentication attempt
    
    Args:
        opensearch_client: OpenSearch client instance
        case_id: Case ID to search within
        firewall_ip: IP address of the firewall to filter by
        date_range: Time range ('all', '24h', '7d', '30d', 'custom')
        custom_date_start: Start datetime for custom range
        custom_date_end: End datetime for custom range
        latest_event_timestamp: Latest event timestamp for relative ranges
        
    Returns:
        Dict with 'authentications' list (ALL events, no deduplication)
    """
    try:
        index_pattern = f"case_{case_id}"
        
        # Build date filter
        date_filter = None
        if date_range == 'custom' and custom_date_start and custom_date_end:
            date_filter = {
                "range": {
                    "normalized_timestamp": {
                        "gte": custom_date_start.isoformat(),
                        "lte": custom_date_end.isoformat()
                    }
                }
            }
        elif date_range in ['24h', '7d', '30d'] and latest_event_timestamp:
            hours_map = {'24h': 24, '7d': 168, '30d': 720}
            hours = hours_map.get(date_range, 0)
            from datetime import timedelta
            start_time = latest_event_timestamp - timedelta(hours=hours)
            date_filter = {
                "range": {
                    "normalized_timestamp": {
                        "gte": start_time.isoformat()
                    }
                }
            }
        
        # v1.32.0 FIX: Search for BOTH Event ID 4624 AND 6272 with firewall IP
        # - 4624 = Windows logon event (has IpAddress field)
        # - 6272 = NPS granted access (VPN/RDP Gateway)
        must_conditions = [
            # Event ID 4624 OR 6272
            {
                "bool": {
                    "should": [
                        # Event ID 4624 (Windows logon)
                        {"term": {"normalized_event_id": "4624"}},
                        {"term": {"normalized_event_id": 4624}},
                        {"term": {"System.EventID": 4624}},
                        {"term": {"System.EventID.#text": "4624"}},
                        {"term": {"Event.System.EventID": 4624}},
                        {"term": {"Event.System.EventID.#text": "4624"}},
                        # Event ID 6272 (NPS granted access)
                        {"term": {"normalized_event_id": "6272"}},
                        {"term": {"normalized_event_id": 6272}},
                        {"term": {"System.EventID": 6272}},
                        {"term": {"System.EventID.#text": "6272"}},
                        {"term": {"Event.System.EventID": 6272}},
                        {"term": {"Event.System.EventID.#text": "6272"}}
                    ],
                    "minimum_should_match": 1
                }
            },
            # Filter by firewall IP address
            # Note: EventData is stored as JSON string, forensic_IpAddress is extracted field
            {
                "bool": {
                    "should": [
                        # forensic_IpAddress field (extracted during indexing)
                        {"term": {"forensic_IpAddress": firewall_ip}},
                        {"term": {"forensic_IpAddress.keyword": firewall_ip}},
                        # Search within Event.EventData JSON string
                        {"match_phrase": {"Event.EventData": firewall_ip}},
                        # Search within search_blob
                        {"match_phrase": {"search_blob": firewall_ip}},
                        # Fallback: nested EventData if it exists as object
                        {"term": {"EventData.IpAddress": firewall_ip}},
                        {"term": {"EventData.IpAddress.keyword": firewall_ip}},
                    ],
                    "minimum_should_match": 1
                }
            }
        ]
        
        if date_filter:
            must_conditions.append(date_filter)
        
        # Use Scroll API for unlimited results (bypasses 10,000 limit)
        query = {
            "_source": [
                "normalized_timestamp",
                "normalized_event_id",
                "Event.EventData",  # v1.13.9: EventData is a JSON string, fetch entire field
                "EventData",  # v1.13.9: EventData is a JSON string, fetch entire field
                "forensic_IpAddress",  # v1.32.0: Extracted IP field
                "forensic_TargetUserName"  # v1.32.0: Extracted username field
            ],
            "query": {
                "bool": {
                    "must": must_conditions
                }
            },
            "sort": [{"normalized_timestamp": {"order": "desc"}}]
        }
        
        logger.info(f"[VPN_AUTHS] Searching for Event ID 4624 or 6272 with IpAddress={firewall_ip} in case {case_id}")
        
        # Use scroll API to get all results
        scroll_id = None
        all_hits = []
        try:
            result = opensearch_client.search(
                index=index_pattern, 
                body=query,
                scroll='2m',
                size=1000
            )
            
            total_events = result['hits']['total']['value']
            logger.info(f"[VPN_AUTHS] Found {total_events} VPN authentication events")
            
            scroll_id = result['_scroll_id']
            all_hits.extend(result['hits']['hits'])
            
            while len(result['hits']['hits']) > 0:
                result = opensearch_client.scroll(scroll_id=scroll_id, scroll='2m')
                scroll_id = result['_scroll_id']
                all_hits.extend(result['hits']['hits'])
                if len(result['hits']['hits']) == 0:
                    break
            
            logger.info(f"[VPN_AUTHS] Retrieved {len(all_hits)} total events via scroll")
        finally:
            if scroll_id:
                try:
                    opensearch_client.clear_scroll(scroll_id=scroll_id)
                except:
                    pass
        
        result = {'hits': {'hits': all_hits, 'total': {'value': len(all_hits)}}}
        
        total_events = result['hits']['total']['value']
        logger.info(f"[VPN_AUTHS] Found {total_events} VPN authentication events")
        
        # Process ALL results (NO deduplication)
        authentications = []
        
        for hit in result['hits']['hits']:
            source = hit['_source']
            
            # Extract username (TargetUserName for 4624, SubjectUserName for 6272)
            # v1.17.3 FIX: Parse EventData if it's a JSON string
            import json
            username = None
            
            # Try Event.EventData first
            if 'Event' in source and 'EventData' in source['Event']:
                event_data = source['Event']['EventData']
                # Parse JSON string if needed
                if isinstance(event_data, str):
                    try:
                        event_data = json.loads(event_data)
                    except:
                        pass
                if isinstance(event_data, dict):
                    username = event_data.get('TargetUserName') or event_data.get('SubjectUserName')
            
            # Try EventData directly
            if not username and 'EventData' in source:
                event_data = source['EventData']
                # Parse JSON string if needed
                if isinstance(event_data, str):
                    try:
                        event_data = json.loads(event_data)
                    except:
                        pass
                if isinstance(event_data, dict):
                    username = event_data.get('TargetUserName') or event_data.get('SubjectUserName')
            
            # Extract workstation name (WorkstationName for 4624, ClientName for 6272)
            # v1.17.3 FIX: Parse EventData if it's a JSON string
            workstation_name = None
            
            # Try Event.EventData first
            if 'Event' in source and 'EventData' in source['Event']:
                event_data = source['Event']['EventData']
                # Parse JSON string if needed
                if isinstance(event_data, str):
                    try:
                        event_data = json.loads(event_data)
                    except:
                        pass
                if isinstance(event_data, dict):
                    workstation_name = event_data.get('WorkstationName') or event_data.get('ClientName')
            
            # Try EventData directly
            if not workstation_name and 'EventData' in source:
                event_data = source['EventData']
                # Parse JSON string if needed
                if isinstance(event_data, str):
                    try:
                        event_data = json.loads(event_data)
                    except:
                        pass
                if isinstance(event_data, dict):
                    workstation_name = event_data.get('WorkstationName') or event_data.get('ClientName')
            
            # Extract AuthenticationServer (NPS server that granted/denied access) - v1.17.4
            auth_server = None
            
            # Try Event.EventData first
            if 'Event' in source and 'EventData' in source['Event']:
                event_data = source['Event']['EventData']
                # Parse JSON string if needed
                if isinstance(event_data, str):
                    try:
                        event_data = json.loads(event_data)
                    except:
                        pass
                if isinstance(event_data, dict):
                    auth_server = event_data.get('AuthenticationServer')
            
            # Try EventData directly
            if not auth_server and 'EventData' in source:
                event_data = source['EventData']
                # Parse JSON string if needed
                if isinstance(event_data, str):
                    try:
                        event_data = json.loads(event_data)
                    except:
                        pass
                if isinstance(event_data, dict):
                    auth_server = event_data.get('AuthenticationServer')
            
            # Get timestamp
            timestamp = source.get('normalized_timestamp', 'N/A')
            
            # Get event ID and index for linking to event details
            event_id = hit.get('_id')
            event_index = hit.get('_index')
            
            # Add ALL events (no filtering, no deduplication)
            if username:
                authentications.append({
                    'username': username,
                    'workstation_name': workstation_name or 'N/A',
                    'auth_server': auth_server or 'N/A',  # v1.17.4: Show which NPS server
                    'timestamp': timestamp,
                    'event_id': event_id,
                    'event_index': event_index
                })
        
        logger.info(f"[VPN_AUTHS] Returning {len(authentications)} VPN authentication events")
        
        # Enrich with Known User and IOC data
        from known_user_utils import enrich_login_records
        enriched_auths = enrich_login_records(authentications, case_id)
        
        return {
            'success': True,
            'authentications': enriched_auths
        }
    
    except Exception as e:
        logger.error(f"[VPN_AUTHS] Error analyzing VPN authentications: {e}", exc_info=True)
        return {
            'success': False,
            'error': str(e),
            'authentications': []
        }


def _extract_logon_type(source: Dict) -> str:
    """Extract LogonType from Event ID 4624 event"""
    import json
    
    # Try Event.EventData.LogonType (most common for EVTX->JSON)
    if 'Event' in source and isinstance(source['Event'], dict):
        event_data = source['Event'].get('EventData')
        # v1.13.9+: EventData might be a JSON string
        if isinstance(event_data, str):
            try:
                event_data = json.loads(event_data)
            except:
                pass
        if isinstance(event_data, dict):
            logon_type = event_data.get('LogonType')
            if logon_type:
                return str(logon_type)
    
    # Try EventData.LogonType (direct structure)
    event_data = source.get('EventData')
    # v1.13.9+: EventData might be a JSON string
    if isinstance(event_data, str):
        try:
            event_data = json.loads(event_data)
        except:
            pass
    if isinstance(event_data, dict):
        logon_type = event_data.get('LogonType')
        if logon_type:
            return str(logon_type)
    
    return 'Unknown'


def get_failed_vpn_attempts(opensearch_client, case_id: int, firewall_ip: str,
                            date_range: str = 'all',
                            custom_date_start: Optional[datetime] = None,
                            custom_date_end: Optional[datetime] = None,
                            latest_event_timestamp: Optional[datetime] = None) -> Dict:
    """
    Query OpenSearch for failed VPN attempts (Event ID 4625 or 6273 with specific firewall IP)
    Returns ALL events (NO deduplication) - every failed authentication attempt
    
    Args:
        opensearch_client: OpenSearch client instance
        case_id: Case ID to search within
        firewall_ip: IP address of the firewall to filter by
        date_range: Time range ('all', '24h', '7d', '30d', 'custom')
        custom_date_start: Start datetime for custom range
        custom_date_end: End datetime for custom range
        latest_event_timestamp: Latest event timestamp for relative ranges
        
    Returns:
        Dict with 'attempts' list (ALL events, no deduplication)
    """
    try:
        index_pattern = f"case_{case_id}"
        
        # Build date filter
        date_filter = None
        if date_range == 'custom' and custom_date_start and custom_date_end:
            date_filter = {
                "range": {
                    "normalized_timestamp": {
                        "gte": custom_date_start.isoformat(),
                        "lte": custom_date_end.isoformat()
                    }
                }
            }
        elif date_range in ['24h', '7d', '30d'] and latest_event_timestamp:
            hours_map = {'24h': 24, '7d': 168, '30d': 720}
            hours = hours_map.get(date_range, 0)
            from datetime import timedelta
            start_time = latest_event_timestamp - timedelta(hours=hours)
            date_filter = {
                "range": {
                    "normalized_timestamp": {
                        "gte": start_time.isoformat()
                    }
                }
            }
        
        # v1.32.0 FIX: Search for BOTH Event ID 4625 AND 6273 with firewall IP
        # - 4625 = Windows failed logon event (has IpAddress field)
        # - 6273 = NPS denied access (VPN/RDP Gateway)
        must_conditions = [
            # Event ID 4625 OR 6273
            {
                "bool": {
                    "should": [
                        # Event ID 4625 (Windows failed logon)
                        {"term": {"normalized_event_id": "4625"}},
                        {"term": {"normalized_event_id": 4625}},
                        {"term": {"System.EventID": 4625}},
                        {"term": {"System.EventID.#text": "4625"}},
                        {"term": {"Event.System.EventID": 4625}},
                        {"term": {"Event.System.EventID.#text": "4625"}},
                        # Event ID 6273 (NPS denied access)
                        {"term": {"normalized_event_id": "6273"}},
                        {"term": {"normalized_event_id": 6273}},
                        {"term": {"System.EventID": 6273}},
                        {"term": {"System.EventID.#text": "6273"}},
                        {"term": {"Event.System.EventID": 6273}},
                        {"term": {"Event.System.EventID.#text": "6273"}}
                    ],
                    "minimum_should_match": 1
                }
            },
            # Filter by firewall IP address
            # Note: EventData is stored as JSON string, forensic_IpAddress is extracted field
            {
                "bool": {
                    "should": [
                        # forensic_IpAddress field (extracted during indexing)
                        {"term": {"forensic_IpAddress": firewall_ip}},
                        {"term": {"forensic_IpAddress.keyword": firewall_ip}},
                        # Search within Event.EventData JSON string
                        {"match_phrase": {"Event.EventData": firewall_ip}},
                        # Search within search_blob
                        {"match_phrase": {"search_blob": firewall_ip}},
                        # Fallback: nested EventData if it exists as object
                        {"term": {"EventData.IpAddress": firewall_ip}},
                        {"term": {"EventData.IpAddress.keyword": firewall_ip}},
                    ],
                    "minimum_should_match": 1
                }
            }
        ]
        
        if date_filter:
            must_conditions.append(date_filter)
        
        # Use Scroll API for unlimited results (bypasses 10,000 limit)
        query = {
            "_source": [
                "normalized_timestamp",
                "normalized_event_id",
                "Event.EventData",  # v1.13.9: EventData is a JSON string, fetch entire field
                "EventData",  # v1.13.9: EventData is a JSON string, fetch entire field
                "forensic_IpAddress",  # v1.32.0: Extracted IP field
                "forensic_TargetUserName"  # v1.32.0: Extracted username field
            ],
            "query": {
                "bool": {
                    "must": must_conditions
                }
            },
            "sort": [{"normalized_timestamp": {"order": "desc"}}]
        }
        
        logger.info(f"[FAILED_VPN] Searching for Event ID 4625 or 6273 with IP {firewall_ip} in case {case_id}")
        
        # Use scroll API to get all results
        scroll_id = None
        all_hits = []
        try:
            result = opensearch_client.search(
                index=index_pattern, 
                body=query,
                scroll='2m',
                size=1000
            )
            
            total_events = result['hits']['total']['value']
            logger.info(f"[FAILED_VPN] Found {total_events} failed VPN attempt events")
            
            scroll_id = result['_scroll_id']
            all_hits.extend(result['hits']['hits'])
            
            while len(result['hits']['hits']) > 0:
                result = opensearch_client.scroll(scroll_id=scroll_id, scroll='2m')
                scroll_id = result['_scroll_id']
                all_hits.extend(result['hits']['hits'])
                if len(result['hits']['hits']) == 0:
                    break
            
            logger.info(f"[FAILED_VPN] Retrieved {len(all_hits)} total events via scroll")
        finally:
            if scroll_id:
                try:
                    opensearch_client.clear_scroll(scroll_id=scroll_id)
                except:
                    pass
        
        result = {'hits': {'hits': all_hits, 'total': {'value': len(all_hits)}}}
        
        total_events = result['hits']['total']['value']
        logger.info(f"[FAILED_VPN] Found {total_events} failed VPN attempt events")
        
        # Process ALL results (NO deduplication)
        attempts = []
        
        for hit in result['hits']['hits']:
            source = hit['_source']
            
            # Extract username (TargetUserName for 4625, SubjectUserName for 6273)
            # v1.17.3 FIX: Parse EventData if it's a JSON string
            import json
            username = None
            
            # Try Event.EventData first
            if 'Event' in source and 'EventData' in source['Event']:
                event_data = source['Event']['EventData']
                # Parse JSON string if needed
                if isinstance(event_data, str):
                    try:
                        event_data = json.loads(event_data)
                    except:
                        pass
                if isinstance(event_data, dict):
                    username = event_data.get('TargetUserName') or event_data.get('SubjectUserName')
            
            # Try EventData directly
            if not username and 'EventData' in source:
                event_data = source['EventData']
                # Parse JSON string if needed
                if isinstance(event_data, str):
                    try:
                        event_data = json.loads(event_data)
                    except:
                        pass
                if isinstance(event_data, dict):
                    username = event_data.get('TargetUserName') or event_data.get('SubjectUserName')
            
            # Extract workstation name (WorkstationName for 4625, ClientName for 6273)
            # v1.17.3 FIX: Parse EventData if it's a JSON string
            workstation_name = None
            
            # Try Event.EventData first
            if 'Event' in source and 'EventData' in source['Event']:
                event_data = source['Event']['EventData']
                # Parse JSON string if needed
                if isinstance(event_data, str):
                    try:
                        event_data = json.loads(event_data)
                    except:
                        pass
                if isinstance(event_data, dict):
                    workstation_name = event_data.get('WorkstationName') or event_data.get('ClientName')
            
            # Try EventData directly
            if not workstation_name and 'EventData' in source:
                event_data = source['EventData']
                # Parse JSON string if needed
                if isinstance(event_data, str):
                    try:
                        event_data = json.loads(event_data)
                    except:
                        pass
                if isinstance(event_data, dict):
                    workstation_name = event_data.get('WorkstationName') or event_data.get('ClientName')
            
            # Extract AuthenticationServer (NPS server that granted/denied access) - v1.17.4
            auth_server = None
            
            # Try Event.EventData first
            if 'Event' in source and 'EventData' in source['Event']:
                event_data = source['Event']['EventData']
                # Parse JSON string if needed
                if isinstance(event_data, str):
                    try:
                        event_data = json.loads(event_data)
                    except:
                        pass
                if isinstance(event_data, dict):
                    auth_server = event_data.get('AuthenticationServer')
            
            # Try EventData directly
            if not auth_server and 'EventData' in source:
                event_data = source['EventData']
                # Parse JSON string if needed
                if isinstance(event_data, str):
                    try:
                        event_data = json.loads(event_data)
                    except:
                        pass
                if isinstance(event_data, dict):
                    auth_server = event_data.get('AuthenticationServer')
            
            # Get timestamp
            timestamp = source.get('normalized_timestamp', 'N/A')
            
            # Get event ID and index for linking to event details
            event_id = hit.get('_id')
            event_index = hit.get('_index')
            
            # Add ALL events (no filtering, no deduplication)
            if username:
                attempts.append({
                    'username': username,
                    'workstation_name': workstation_name or 'N/A',
                    'auth_server': auth_server or 'N/A',  # v1.17.4: Show which NPS server
                    'timestamp': timestamp,
                    'event_id': event_id,
                    'event_index': event_index
                })
        
        logger.info(f"[FAILED_VPN] Returning {len(attempts)} failed VPN attempt events")
        
        # Enrich with Known User and IOC data
        from known_user_utils import enrich_login_records
        enriched_attempts = enrich_login_records(attempts, case_id)
        
        return {
            'success': True,
            'attempts': enriched_attempts
        }
    
    except Exception as e:
        logger.error(f"[FAILED_VPN] Error analyzing failed VPN attempts: {e}", exc_info=True)
        return {
            'success': False,
            'error': str(e),
            'attempts': []
        }
