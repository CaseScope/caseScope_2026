"""
IOC Hunting Task - Background task to search for IOCs in events
Handles large datasets (30M+ events) with progress tracking
"""

import os
import sys
import logging

# Add app directory to Python path for imports
app_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if app_dir not in sys.path:
    sys.path.insert(0, app_dir)

logger = logging.getLogger(__name__)

from celery_app import celery


def build_smart_ioc_query(ioc):
    """
    Build intelligent OpenSearch query based on IOC type
    Uses structured fields first, falls back to search_blob
    """
    ioc_value = ioc.value
    ioc_type = ioc.type
    
    queries = []
    
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


def determine_match_field(event_doc, ioc):
    """
    Try to determine which field contained the IOC match
    """
    ioc_value_lower = ioc.value.lower()
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
    Hunt for all IOCs in case events with progress tracking
    
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
    from opensearchpy.helpers import scan
    from config import Config
    
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
            
            self.update_state(state='PROGRESS', meta={
                'status': f'Found {len(iocs)} IOCs to hunt for...',
                'progress': 5,
                'ioc_count': len(iocs)
            })
            
            # Initialize OpenSearch client
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
                return {
                    'success': True,
                    'events_scanned': 0,
                    'events_with_hits': 0,
                    'total_hits': 0,
                    'message': 'No events indexed for this case'
                }
            
            # Get total event count for progress tracking
            total_events = client.count(index=index_name)['count']
            
            self.update_state(state='PROGRESS', meta={
                'status': f'Scanning {total_events:,} events...',
                'progress': 10,
                'total_events': total_events,
                'ioc_count': len(iocs)
            })
            
            # Statistics
            stats = {
                'events_scanned': 0,
                'events_with_hits': 0,
                'total_hits': 0,
                'by_ioc': {},
                'by_threat_level': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
            }
            
            # Track which events already have hits
            events_with_hits = set()
            
            # Hunt each IOC
            for ioc_idx, ioc in enumerate(iocs):
                ioc_progress = 10 + (80 * (ioc_idx / len(iocs)))
                
                self.update_state(state='PROGRESS', meta={
                    'status': f'Hunting IOC {ioc_idx + 1}/{len(iocs)}: {ioc.value[:50]}...',
                    'progress': int(ioc_progress),
                    'current_ioc': ioc.value,
                    'events_scanned': stats['events_scanned'],
                    'total_events': total_events,
                    'events_with_hits': len(events_with_hits),
                    'total_hits': stats['total_hits']
                })
                
                # Build query for this IOC
                query = build_smart_ioc_query(ioc)
                
                # Search with scroll for large result sets
                search_body = {
                    'query': query,
                    '_source': [
                        'event_record_id', 'event_id', 'normalized_timestamp',
                        'normalized_computer', 'computer', 'event_data_fields', 'event_data'
                    ]
                }
                
                ioc_hit_count = 0
                
                try:
                    # Use scan for efficient iteration
                    for hit in scan(
                        client,
                        index=index_name,
                        query=search_body,
                        size=1000,
                        scroll='5m'
                    ):
                        doc_id = hit['_id']
                        event_doc = hit['_source']
                        
                        stats['events_scanned'] += 1
                        
                        # Check if this event-IOC pair already exists
                        existing = EventIOCHit.query.filter_by(
                            opensearch_doc_id=doc_id,
                            ioc_id=ioc.id
                        ).first()
                        
                        if existing:
                            # Count existing hit
                            ioc_hit_count += 1
                            events_with_hits.add(doc_id)
                            stats['by_threat_level'][ioc.threat_level] += 1
                        else:
                            # Create new hit record
                            hit_record = EventIOCHit(
                                case_id=case_id,
                                opensearch_doc_id=doc_id,
                                event_record_id=event_doc.get('event_record_id'),
                                event_id=event_doc.get('event_id', event_doc.get('normalized_event_id')),
                                event_timestamp=event_doc.get('normalized_timestamp', event_doc.get('timestamp')),
                                computer=event_doc.get('normalized_computer', event_doc.get('computer')),
                                ioc_id=ioc.id,
                                ioc_value=ioc.value,
                                ioc_type=ioc.type,
                                ioc_category=ioc.category,
                                threat_level=ioc.threat_level,
                                matched_in_field=determine_match_field(event_doc, ioc),
                                detected_by=user_id
                            )
                            db.session.add(hit_record)
                            
                            ioc_hit_count += 1
                            events_with_hits.add(doc_id)
                            stats['by_threat_level'][ioc.threat_level] += 1
                            
                            # Commit every 100 records to avoid memory issues
                            if stats['total_hits'] % 100 == 0:
                                db.session.commit()
                        
                        # Count total hits (new + existing)
                        stats['total_hits'] += 1
                    
                    stats['by_ioc'][ioc.value] = ioc_hit_count
                    
                except Exception as e:
                    logger.error(f"Error hunting IOC {ioc.value}: {e}")
                    continue
            
            # Final commit
            db.session.commit()
            
            stats['events_with_hits'] = len(events_with_hits)
            
            # Final update
            self.update_state(state='PROGRESS', meta={
                'status': 'Hunt complete!',
                'progress': 100,
                'events_scanned': total_events,
                'events_with_hits': stats['events_with_hits'],
                'total_hits': stats['total_hits']
            })
            
            return {
                'success': True,
                'events_scanned': total_events,
                'events_with_hits': stats['events_with_hits'],
                'total_hits': stats['total_hits'],
                'by_ioc': stats['by_ioc'],
                'by_threat_level': stats['by_threat_level']
            }
            
        except Exception as e:
            logger.error(f"IOC hunt failed: {e}", exc_info=True)
            return {
                'success': False,
                'error': str(e)
            }


