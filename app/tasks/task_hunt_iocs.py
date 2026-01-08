"""
IOC Hunting Task - Background task to search for IOCs in events
Handles large datasets (30M+ events) with progress tracking
Uses parallel slicing for 4-8x speedup
"""

import os
import sys
import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor

# Add app directory to Python path for imports
app_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if app_dir not in sys.path:
    sys.path.insert(0, app_dir)

logger = logging.getLogger(__name__)

from celery_app import celery


def get_source_fields(index_type):
    """Get appropriate source fields based on index type"""
    if index_type == 'browser':
        return [
            '@timestamp', 'event_type', 'url', 'title',
            'browser', 'file_path', 'domain', 'source_file'
        ]
    else:
        return [
            'event_record_id', 'event_id', 'normalized_timestamp',
            'normalized_computer', 'computer', 'event_data_fields', 'event_data'
        ]


def build_smart_ioc_query_from_data(ioc_data, index_type='main'):
    """
    Build intelligent OpenSearch query based on IOC data dict and index type
    Thread-safe version that doesn't require DB access
    
    Args:
        ioc_data: Dict with keys: id, value, type, category, threat_level
        index_type: 'main' for case_X index, 'browser' for case_X_browser index
    """
    ioc_value = ioc_data['value']
    ioc_type = ioc_data['type']
    
    queries = []
    
    # Browser index - different field structure
    if index_type == 'browser':
        if ioc_type == 'domain':
            queries.append({'wildcard': {'url': f'*{ioc_value}*'}})
            queries.append({'match_phrase': {'domain': ioc_value}})
        elif ioc_type == 'url':
            queries.append({'wildcard': {'url': f'*{ioc_value}*'}})
            queries.append({'match_phrase': {'url': ioc_value}})
        elif ioc_type in ['md5', 'sha1', 'sha256', 'file_hash']:
            queries.append({'match_phrase': {'file_path': ioc_value.lower()}})
        elif ioc_type in ['file_name', 'filename']:
            queries.append({'wildcard': {'file_path': f'*{ioc_value}*'}})
            queries.append({'match_phrase': {'title': ioc_value}})
        elif ioc_type in ['file_path', 'filepath']:
            queries.append({'match_phrase': {'file_path': ioc_value}})
        else:
            queries.append({
                'multi_match': {
                    'query': ioc_value,
                    'fields': ['url', 'title', 'file_path'],
                    'type': 'phrase'
                }
            })
        
        return {
            'bool': {
                'should': queries,
                'minimum_should_match': 1
            }
        }
    
    # Main index (EVTX) - original logic
    if ioc_type == 'ipv4':
        queries.append({
            'multi_match': {
                'query': ioc_value,
                'fields': [
                    'event_data_fields.IpAddress^3',
                    'event_data_fields.SourceAddress^3',
                    'event_data_fields.DestAddress^3',
                    'event_data_fields.ClientIPAddress^3',
                    'src_ip^3',
                    'dst_ip^3',
                    'extracted_ips^3',
                    'normalized_source_ip^3',
                    'normalized_dest_ip^3',
                    'search_blob'
                ],
                'type': 'phrase'
            }
        })
    elif ioc_type in ['md5', 'sha1', 'sha256', 'file_hash']:
        queries.append({
            'multi_match': {
                'query': ioc_value.lower(),
                'fields': [
                    'event_data_fields.Hashes^3',
                    'event_data_fields.Hash^3',
                    'event_data_fields.MD5^3',
                    'event_data_fields.SHA1^3',
                    'event_data_fields.SHA256^3',
                    'search_blob'
                ],
                'type': 'phrase'
            }
        })
    elif ioc_type == 'domain':
        queries.append({
            'multi_match': {
                'query': ioc_value,
                'fields': [
                    'event_data_fields.DestinationHostname^3',
                    'event_data_fields.QueryName^3',
                    'event_data_fields.TargetServerName^3',
                    'search_blob'
                ],
                'type': 'phrase'
            }
        })
    elif ioc_type in ['file_name', 'filename', 'process_name']:
        queries.append({
            'multi_match': {
                'query': ioc_value,
                'fields': [
                    'event_data_fields.TargetFilename^3',
                    'event_data_fields.ImagePath^3',
                    'event_data_fields.FileName^3',
                    'event_data_fields.Image^3',
                    'event_data_fields.ProcessName^3',
                    'search_blob'
                ],
                'type': 'phrase'
            }
        })
    elif ioc_type in ['file_path', 'filepath']:
        queries.append({
            'multi_match': {
                'query': ioc_value,
                'fields': [
                    'event_data_fields.TargetFilename^3',
                    'event_data_fields.ImagePath^3',
                    'event_data_fields.Image^3',
                    'event_data_fields.CommandLine^2',
                    'search_blob'
                ],
                'type': 'phrase'
            }
        })
    elif ioc_type == 'url':
        queries.append({
            'multi_match': {
                'query': ioc_value,
                'fields': [
                    'event_data_fields.Url^3',
                    'event_data_fields.RequestUrl^3',
                    'search_blob'
                ],
                'type': 'phrase'
            }
        })
    elif ioc_type == 'email':
        queries.append({
            'multi_match': {
                'query': ioc_value,
                'fields': [
                    'event_data_fields.EmailAddress^3',
                    'event_data_fields.Sender^3',
                    'event_data_fields.Recipient^3',
                    'search_blob'
                ],
                'type': 'phrase'
            }
        })
    elif ioc_type in ['command', 'command_line']:
        queries.append({
            'multi_match': {
                'query': ioc_value,
                'fields': [
                    'event_data_fields.CommandLine^3',
                    'event_data_fields.ProcessCommandLine^3',
                    'search_blob'
                ],
                'type': 'phrase'
            }
        })
    elif ioc_type in ['username', 'user']:
        queries.append({
            'multi_match': {
                'query': ioc_value,
                'fields': [
                    'event_data_fields.TargetUserName^3',
                    'event_data_fields.SubjectUserName^3',
                    'event_data_fields.User^3',
                    'event_data_fields.AccountName^3',
                    'search_blob'
                ],
                'type': 'phrase'
            }
        })
    elif ioc_type in ['sid', 'security_identifier']:
        queries.append({
            'multi_match': {
                'query': ioc_value,
                'fields': [
                    'event_data_fields.TargetUserSid^3',
                    'event_data_fields.SubjectUserSid^3',
                    'event_data_fields.UserSid^3',
                    'search_blob'
                ],
                'type': 'phrase'
            }
        })
    elif ioc_type in ['hostname', 'computer']:
        queries.append({
            'multi_match': {
                'query': ioc_value,
                'fields': [
                    'normalized_computer^3',
                    'computer^3',
                    'event_data_fields.WorkstationName^3',
                    'event_data_fields.SourceHostname^3',
                    'event_data_fields.DestinationHostname^3',
                    'search_blob'
                ],
                'type': 'phrase'
            }
        })
    else:
        queries.append({
            'multi_match': {
                'query': ioc_value,
                'fields': ['search_blob'],
                'type': 'phrase'
            }
        })
    
    return {
        'bool': {
            'should': queries,
            'minimum_should_match': 1
        }
    }


def determine_match_field_from_data(event_doc, ioc_data, index_type='main'):
    """
    Try to determine which field contained the IOC match
    Thread-safe version that works with IOC data dict
    
    Args:
        event_doc: The event document from OpenSearch
        ioc_data: Dict with IOC data (value, type, etc.)
        index_type: 'main' or 'browser'
    """
    ioc_value_lower = ioc_data['value'].lower()
    ioc_type = ioc_data['type']
    
    # Browser events have a simpler structure
    if index_type == 'browser':
        if 'url' in event_doc and ioc_value_lower in str(event_doc.get('url', '')).lower():
            return 'url'
        if 'title' in event_doc and ioc_value_lower in str(event_doc.get('title', '')).lower():
            return 'title'
        if 'file_path' in event_doc and ioc_value_lower in str(event_doc.get('file_path', '')).lower():
            return 'file_path'
        if 'domain' in event_doc and ioc_value_lower in str(event_doc.get('domain', '')).lower():
            return 'domain'
        return 'browser_event'
    
    # Main index (EVTX)
    event_data = event_doc.get('event_data_fields', event_doc.get('event_data', {})) or {}
    
    # Check common fields based on IOC type
    field_candidates = []
    
    if ioc_type == 'ipv4':
        field_candidates = ['IpAddress', 'SourceAddress', 'DestAddress', 'ClientIPAddress']
    elif ioc_type in ['md5', 'sha1', 'sha256', 'file_hash']:
        field_candidates = ['Hashes', 'Hash', 'MD5', 'SHA1', 'SHA256']
    elif ioc_type == 'domain':
        field_candidates = ['DestinationHostname', 'QueryName', 'TargetServerName']
    elif ioc_type in ['file_name', 'filename', 'process_name']:
        field_candidates = ['TargetFilename', 'ImagePath', 'FileName', 'Image', 'ProcessName']
    elif ioc_type in ['file_path', 'filepath']:
        field_candidates = ['TargetFilename', 'ImagePath', 'Image', 'CommandLine']
    elif ioc_type in ['command', 'command_line']:
        field_candidates = ['CommandLine', 'ProcessCommandLine']
    elif ioc_type in ['username', 'user']:
        field_candidates = ['TargetUserName', 'SubjectUserName', 'User', 'AccountName']
    elif ioc_type in ['sid', 'security_identifier']:
        field_candidates = ['TargetUserSid', 'SubjectUserSid', 'UserSid']
    elif ioc_type in ['hostname', 'computer']:
        if 'normalized_computer' in event_doc and ioc_value_lower in str(event_doc.get('normalized_computer', '')).lower():
            return 'normalized_computer'
        if 'computer' in event_doc and ioc_value_lower in str(event_doc.get('computer', '')).lower():
            return 'computer'
        field_candidates = ['WorkstationName', 'SourceHostname', 'DestinationHostname']
    
    # Check each candidate field
    for field in field_candidates:
        value = event_data.get(field, '')
        if value and ioc_value_lower in str(value).lower():
            return f'event_data_fields.{field}'
    
    # Default to search_blob
    return 'search_blob'


def build_smart_ioc_query(ioc, index_type='main'):
    """
    Build intelligent OpenSearch query based on IOC type and index
    
    Args:
        ioc: IOC object to search for
        index_type: 'main' for case_X index, 'browser' for case_X_browser index
    
    Uses structured fields first, falls back to search_blob
    """
    ioc_value = ioc.value
    ioc_type = ioc.type
    
    queries = []
    
    # Browser index - different field structure
    if index_type == 'browser':
        if ioc_type == 'domain':
            # Domain in URL
            queries.append({
                'wildcard': {
                    'url': f'*{ioc_value}*'
                }
            })
            queries.append({
                'match_phrase': {
                    'domain': ioc_value
                }
            })
        
        elif ioc_type == 'url':
            # URL matching
            queries.append({
                'wildcard': {
                    'url': f'*{ioc_value}*'
                }
            })
            queries.append({
                'match_phrase': {
                    'url': ioc_value
                }
            })
        
        elif ioc_type in ['md5', 'sha1', 'sha256', 'file_hash']:
            # File hash in download path or cache
            queries.append({
                'match_phrase': {
                    'file_path': ioc_value.lower()
                }
            })
        
        elif ioc_type in ['file_name', 'filename']:
            # Filename in download path
            queries.append({
                'wildcard': {
                    'file_path': f'*{ioc_value}*'
                }
            })
            queries.append({
                'match_phrase': {
                    'title': ioc_value
                }
            })
        
        elif ioc_type in ['file_path', 'filepath']:
            # File path in downloads
            queries.append({
                'match_phrase': {
                    'file_path': ioc_value
                }
            })
        
        else:
            # Generic - search URL and title
            queries.append({
                'multi_match': {
                    'query': ioc_value,
                    'fields': ['url', 'title', 'file_path'],
                    'type': 'phrase'
                }
            })
        
        return {
            'bool': {
                'should': queries,
                'minimum_should_match': 1
            }
        }
    
    # Main index (EVTX) - original logic
    if ioc_type == 'ipv4':
        # IP address - search specific fields (EVTX + firewall logs)
        queries.append({
            'multi_match': {
                'query': ioc_value,
                'fields': [
                    'event_data_fields.IpAddress^3',
                    'event_data_fields.SourceAddress^3',
                    'event_data_fields.DestAddress^3',
                    'event_data_fields.ClientIPAddress^3',
                    'src_ip^3',  # Firewall logs
                    'dst_ip^3',  # Firewall logs
                    'extracted_ips^3',  # Firewall logs - array of IPs
                    'normalized_source_ip^3',  # Normalized field
                    'normalized_dest_ip^3',  # Normalized field
                    'search_blob'
                ],
                'type': 'phrase'
            }
        })
    
    elif ioc_type in ['md5', 'sha1', 'sha256', 'file_hash']:
        # File hash - case insensitive exact match
        queries.append({
            'multi_match': {
                'query': ioc_value.lower(),
                'fields': [
                    'event_data_fields.Hashes^3',
                    'event_data_fields.Hash^3',
                    'event_data_fields.MD5^3',
                    'event_data_fields.SHA1^3',
                    'event_data_fields.SHA256^3',
                    'search_blob'
                ],
                'type': 'phrase'
            }
        })
    
    elif ioc_type == 'domain':
        # Domain name
        queries.append({
            'multi_match': {
                'query': ioc_value,
                'fields': [
                    'event_data_fields.DestinationHostname^3',
                    'event_data_fields.QueryName^3',
                    'event_data_fields.TargetServerName^3',
                    'search_blob'
                ],
                'type': 'phrase'
            }
        })
    
    elif ioc_type in ['file_name', 'filename', 'process_name']:
        # Filename or process name - search file and process fields
        queries.append({
            'multi_match': {
                'query': ioc_value,
                'fields': [
                    'event_data_fields.TargetFilename^3',
                    'event_data_fields.ImagePath^3',
                    'event_data_fields.FileName^3',
                    'event_data_fields.Image^3',
                    'event_data_fields.ProcessName^3',
                    'search_blob'
                ],
                'type': 'phrase'
            }
        })
    
    elif ioc_type in ['file_path', 'filepath']:
        # File path - tokenize and search
        # Try exact phrase first
        queries.append({
            'multi_match': {
                'query': ioc_value,
                'fields': [
                    'event_data_fields.TargetFilename^3',
                    'event_data_fields.ImagePath^3',
                    'event_data_fields.Image^3',
                    'event_data_fields.CommandLine^2',
                    'search_blob'
                ],
                'type': 'phrase'
            }
        })
    
    elif ioc_type == 'url':
        # URL - phrase search
        queries.append({
            'multi_match': {
                'query': ioc_value,
                'fields': [
                    'event_data_fields.Url^3',
                    'event_data_fields.RequestUrl^3',
                    'search_blob'
                ],
                'type': 'phrase'
            }
        })
    
    elif ioc_type == 'email':
        # Email address
        queries.append({
            'multi_match': {
                'query': ioc_value,
                'fields': [
                    'event_data_fields.EmailAddress^3',
                    'event_data_fields.Sender^3',
                    'event_data_fields.Recipient^3',
                    'search_blob'
                ],
                'type': 'phrase'
            }
        })
    
    elif ioc_type in ['command', 'command_line']:
        # Command line
        queries.append({
            'multi_match': {
                'query': ioc_value,
                'fields': [
                    'event_data_fields.CommandLine^3',
                    'event_data_fields.ProcessCommandLine^3',
                    'search_blob'
                ],
                'type': 'phrase'
            }
        })
    
    elif ioc_type in ['username', 'user']:
        # Username
        queries.append({
            'multi_match': {
                'query': ioc_value,
                'fields': [
                    'event_data_fields.TargetUserName^3',
                    'event_data_fields.SubjectUserName^3',
                    'event_data_fields.User^3',
                    'event_data_fields.AccountName^3',
                    'search_blob'
                ],
                'type': 'phrase'
            }
        })
    
    elif ioc_type in ['sid', 'security_identifier']:
        # Security Identifier (SID)
        queries.append({
            'multi_match': {
                'query': ioc_value,
                'fields': [
                    'event_data_fields.TargetUserSid^3',
                    'event_data_fields.SubjectUserSid^3',
                    'event_data_fields.UserSid^3',
                    'search_blob'
                ],
                'type': 'phrase'
            }
        })
    
    elif ioc_type in ['hostname', 'computer']:
        # Hostname/Computer name
        queries.append({
            'multi_match': {
                'query': ioc_value,
                'fields': [
                    'normalized_computer^3',
                    'computer^3',
                    'event_data_fields.WorkstationName^3',
                    'event_data_fields.SourceHostname^3',
                    'event_data_fields.DestinationHostname^3',
                    'search_blob'
                ],
                'type': 'phrase'
            }
        })
    
    else:
        # Generic - search everywhere
        queries.append({
            'multi_match': {
                'query': ioc_value,
                'fields': ['search_blob'],
                'type': 'phrase'
            }
        })
    
    return {
        'bool': {
            'should': queries,
            'minimum_should_match': 1
        }
    }


def determine_match_field(event_doc, ioc, index_type='main'):
    """
    Try to determine which field contained the IOC match
    
    Args:
        event_doc: The event document from OpenSearch
        ioc: IOC object that matched
        index_type: 'main' or 'browser'
    """
    ioc_value_lower = ioc.value.lower()
    
    # Browser events have a simpler structure
    if index_type == 'browser':
        # Check browser-specific fields
        if 'url' in event_doc and ioc_value_lower in str(event_doc.get('url', '')).lower():
            return 'url'
        if 'title' in event_doc and ioc_value_lower in str(event_doc.get('title', '')).lower():
            return 'title'
        if 'file_path' in event_doc and ioc_value_lower in str(event_doc.get('file_path', '')).lower():
            return 'file_path'
        if 'domain' in event_doc and ioc_value_lower in str(event_doc.get('domain', '')).lower():
            return 'domain'
        return 'browser_event'
    
    # Main index (EVTX) - original logic
    event_data = event_doc.get('event_data_fields', event_doc.get('event_data', {})) or {}
    
    # Check common fields based on IOC type
    field_candidates = []
    
    if ioc.type == 'ipv4':
        field_candidates = ['IpAddress', 'SourceAddress', 'DestAddress', 'ClientIPAddress']
    elif ioc.type in ['md5', 'sha1', 'sha256', 'file_hash']:
        field_candidates = ['Hashes', 'Hash', 'MD5', 'SHA1', 'SHA256']
    elif ioc.type == 'domain':
        field_candidates = ['DestinationHostname', 'QueryName', 'TargetServerName']
    elif ioc.type in ['file_name', 'filename', 'process_name']:
        field_candidates = ['TargetFilename', 'ImagePath', 'FileName', 'Image', 'ProcessName']
    elif ioc.type in ['file_path', 'filepath']:
        field_candidates = ['TargetFilename', 'ImagePath', 'Image', 'CommandLine']
    elif ioc.type in ['command', 'command_line']:
        field_candidates = ['CommandLine', 'ProcessCommandLine']
    elif ioc.type in ['username', 'user']:
        field_candidates = ['TargetUserName', 'SubjectUserName', 'User', 'AccountName']
    elif ioc.type in ['sid', 'security_identifier']:
        field_candidates = ['TargetUserSid', 'SubjectUserSid', 'UserSid']
    elif ioc.type in ['hostname', 'computer']:
        # Check top-level fields too
        if 'normalized_computer' in event_doc and ioc_value_lower in str(event_doc.get('normalized_computer', '')).lower():
            return 'normalized_computer'
        if 'computer' in event_doc and ioc_value_lower in str(event_doc.get('computer', '')).lower():
            return 'computer'
        field_candidates = ['WorkstationName', 'SourceHostname', 'DestinationHostname']
    
    # Check each candidate field
    for field in field_candidates:
        value = event_data.get(field, '')
        if value and ioc_value_lower in str(value).lower():
            return f'event_data_fields.{field}'
    
    # Default to search_blob
    return 'search_blob'


@celery.task(bind=True, name='tasks.hunt_iocs')
def hunt_iocs(self, case_id, user_id, clear_previous=True):
    """
    Hunt for all IOCs in case events with parallel processing
    Uses OpenSearch slicing for 4-8x speedup
    
    Args:
        case_id: Case ID to hunt in
        user_id: User who initiated the hunt
        clear_previous: If True, clear previous IOC hits before scanning (default: True)
    
    Returns:
        dict: Statistics about the hunt
    """
    from main import app, db
    from models import Case, IOC, EventIOCHit
    from opensearchpy import OpenSearch
    from opensearchpy.helpers import bulk
    from config import Config
    from utils.parallel_config import get_parallel_slice_count
    
    with app.app_context():
        try:
            # Update task state to PROGRESS
            self.update_state(state='PROGRESS', meta={
                'status': 'Initializing IOC hunt...',
                'progress': 0,
                'events_scanned': 0,
                'events_with_hits': 0,
                'total_hits': 0
            })
            
            # Get parallel processing config
            num_slices = get_parallel_slice_count()
            logger.info(f"Starting IOC hunt for case {case_id} with {num_slices} parallel slices")
            
            # Clear previous IOC hits if requested
            if clear_previous:
                logger.info(f"Clearing previous IOC hits for case {case_id}")
                deleted_count = EventIOCHit.query.filter_by(case_id=case_id).delete()
                db.session.commit()
                logger.info(f"Cleared {deleted_count} previous IOC hits")
            
            # Get case
            case = Case.query.get(case_id)
            if not case:
                raise ValueError(f'Case {case_id} not found')
            
            # Get all active, non-hidden IOCs for this case
            iocs = IOC.query.filter_by(
                case_id=case_id,
                is_hidden=False,
                is_active=True
            ).all()
            
            if not iocs:
                return {
                    'success': True,
                    'events_scanned': 0,
                    'events_with_hits': 0,
                    'total_hits': 0,
                    'message': 'No active IOCs to hunt for'
                }
            
            # Serialize IOCs for thread-safe passing (avoid DB queries in threads)
            iocs_data = [{
                'id': ioc.id,
                'value': ioc.value,
                'type': ioc.type,
                'category': ioc.category,
                'threat_level': ioc.threat_level
            } for ioc in iocs]
            
            self.update_state(state='PROGRESS', meta={
                'status': f'Found {len(iocs_data)} IOCs, scanning with {num_slices} parallel threads...',
                'progress': 5,
                'ioc_count': len(iocs_data)
            })
            
            # Initialize OpenSearch client
            client = OpenSearch(
                hosts=[{'host': Config.OPENSEARCH_HOST, 'port': Config.OPENSEARCH_PORT}],
                use_ssl=Config.OPENSEARCH_USE_SSL,
                verify_certs=False,
                ssl_show_warn=False,
                timeout=30
            )
            
            # Determine which indices to search
            indices_to_search = []
            
            main_index = f"case_{case_id}"
            if client.indices.exists(index=main_index):
                indices_to_search.append(('main', main_index))
            
            browser_index = f"case_{case_id}_browser"
            if client.indices.exists(index=browser_index):
                indices_to_search.append(('browser', browser_index))
            
            if not indices_to_search:
                return {
                    'success': True,
                    'events_scanned': 0,
                    'events_with_hits': 0,
                    'total_hits': 0,
                    'message': 'No events indexed for this case'
                }
            
            # Get total event count for progress tracking
            total_events = 0
            for index_type, index_name in indices_to_search:
                total_events += client.count(index=index_name)['count']
            
            logger.info(f"Total events to scan: {total_events:,}")
            
            # Shared progress tracking across threads
            progress_data = {
                'events_scanned': 0,
                'events_with_hits_set': set(),  # Thread-safe set for unique events
                'total_hits': 0,
                'by_ioc': {},
                'by_threat_level': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0},
                'lock': threading.Lock(),
                'task_ref': self
            }
            
            # Initialize by_ioc counters
            for ioc_data in iocs_data:
                progress_data['by_ioc'][ioc_data['value']] = 0
            
            def process_slice(slice_id):
                """Process events for a specific slice - hunts ALL IOCs in this slice"""
                slice_scanned = 0
                slice_hits = 0
                slice_events_with_hits = set()
                slice_by_ioc = {ioc['value']: 0 for ioc in iocs_data}
                slice_by_threat = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
                
                # Create thread-local app context and DB session
                from main import app
                from models import EventIOCHit
                
                # Each thread needs its own app context
                with app.app_context():
                    try:
                        # Process each index
                        for index_type, index_name in indices_to_search:
                            logger.info(f"Slice {slice_id}/{num_slices}: Processing {index_name}")
                            
                            # For each IOC, search this slice
                            for ioc_data in iocs_data:
                                query = build_smart_ioc_query_from_data(ioc_data, index_type=index_type)
                                
                                # Add slice to query
                                search_body = {
                                    'query': query,
                                    'size': 1000,
                                    'slice': {
                                        'id': slice_id,
                                        'max': num_slices
                                    },
                                    '_source': get_source_fields(index_type)
                                }
                                
                                # Search with scroll
                                result = client.search(index=index_name, body=search_body, scroll='5m')
                                scroll_id = result['_scroll_id']
                                hits = result['hits']['hits']
                                
                                while hits:
                                    # Batch insert hits to DB
                                    batch_hits = []
                                    
                                    for hit in hits:
                                        slice_scanned += 1
                                        doc_id = hit['_id']
                                        event_doc = hit['_source']
                                        
                                        # Track this hit
                                        event_key = f"{index_name}:{doc_id}"
                                        slice_events_with_hits.add(event_key)
                                        slice_hits += 1
                                        slice_by_ioc[ioc_data['value']] += 1
                                        slice_by_threat[ioc_data['threat_level']] += 1
                                        
                                        # Extract event metadata
                                        if index_type == 'browser':
                                            timestamp = event_doc.get('@timestamp')
                                            computer = None
                                            event_id_val = event_doc.get('event_type')
                                            event_record_id = None
                                        else:
                                            timestamp = event_doc.get('normalized_timestamp', event_doc.get('timestamp'))
                                            computer = event_doc.get('normalized_computer', event_doc.get('computer'))
                                            event_id_val = event_doc.get('event_id', event_doc.get('normalized_event_id'))
                                            event_record_id = event_doc.get('event_record_id')
                                        
                                        # Create hit record
                                        hit_record = EventIOCHit(
                                            case_id=case_id,
                                            opensearch_doc_id=doc_id,
                                            source_index=index_name,
                                            event_record_id=event_record_id,
                                            event_id=event_id_val,
                                            event_timestamp=timestamp,
                                            computer=computer,
                                            ioc_id=ioc_data['id'],
                                            ioc_value=ioc_data['value'],
                                            ioc_type=ioc_data['type'],
                                            ioc_category=ioc_data['category'],
                                            threat_level=ioc_data['threat_level'],
                                            matched_in_field=determine_match_field_from_data(event_doc, ioc_data, index_type),
                                            detected_by=user_id
                                        )
                                        batch_hits.append(hit_record)
                                        
                                        # Commit in batches
                                        if len(batch_hits) >= 100:
                                            db.session.bulk_save_objects(batch_hits)
                                            db.session.commit()
                                            batch_hits = []
                                        
                                        # Update shared progress periodically
                                        if slice_scanned % 100 == 0:
                                            with progress_data['lock']:
                                                progress_data['events_scanned'] += 100
                                    
                                    # Commit remaining batch
                                    if batch_hits:
                                        db.session.bulk_save_objects(batch_hits)
                                        db.session.commit()
                                    
                                    # Get next batch
                                    result = client.scroll(scroll_id=scroll_id, scroll='5m')
                                    scroll_id = result['_scroll_id']
                                    hits = result['hits']['hits']
                                
                                # Clear scroll
                                try:
                                    client.clear_scroll(scroll_id=scroll_id)
                                except:
                                    pass
                        
                        # Merge slice results into shared progress
                        with progress_data['lock']:
                            progress_data['total_hits'] += slice_hits
                            progress_data['events_with_hits_set'].update(slice_events_with_hits)
                            
                            for ioc_val, count in slice_by_ioc.items():
                                progress_data['by_ioc'][ioc_val] += count
                            
                            for threat_level, count in slice_by_threat.items():
                                progress_data['by_threat_level'][threat_level] += count
                        
                        logger.info(f"Slice {slice_id}/{num_slices} complete: {slice_scanned} events scanned, {slice_hits} hits")
                        return slice_scanned
                        
                    except Exception as e:
                        logger.error(f"Error processing slice {slice_id}: {e}", exc_info=True)
                        raise
            
            # Process slices in parallel
            logger.info(f"Starting {num_slices} parallel threads...")
            with ThreadPoolExecutor(max_workers=num_slices) as executor:
                futures = [executor.submit(process_slice, i) for i in range(num_slices)]
                
                # Poll for progress while threads are running
                while any(not f.done() for f in futures):
                    time.sleep(2)  # Check every 2 seconds
                    
                    # Update Celery progress from main thread
                    with progress_data['lock']:
                        if progress_data['events_scanned'] > 0:
                            progress_pct = min(99, int((progress_data['events_scanned'] / total_events) * 100))
                            self.update_state(
                                state='PROGRESS',
                                meta={
                                    'progress': progress_pct,
                                    'status': f'Hunting IOCs: {progress_data["events_scanned"]:,}/{total_events:,} events scanned',
                                    'events_scanned': progress_data['events_scanned'],
                                    'total_events': total_events,
                                    'events_with_hits': len(progress_data['events_with_hits_set']),
                                    'total_hits': progress_data['total_hits']
                                }
                            )
                
                # Wait for all threads to complete
                for future in futures:
                    future.result()  # This will raise any exceptions from threads
            
            # Final stats
            final_stats = {
                'success': True,
                'events_scanned': total_events,
                'events_with_hits': len(progress_data['events_with_hits_set']),
                'total_hits': progress_data['total_hits'],
                'by_ioc': progress_data['by_ioc'],
                'by_threat_level': progress_data['by_threat_level']
            }
            
            logger.info(f"IOC hunt complete: {final_stats['events_scanned']:,} events, {final_stats['total_hits']:,} hits")
            
            return final_stats
            
        except Exception as e:
            logger.error(f"IOC hunt failed: {e}", exc_info=True)
            return {
                'success': False,
                'error': str(e)
            }


