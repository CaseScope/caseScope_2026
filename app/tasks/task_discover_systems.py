"""
System Discovery Task - Extract systems from OpenSearch using aggregations
Based on the proven approach from old_site/app/routes/systems.py
"""

import os
import sys
import logging
import re
from datetime import datetime

# Add app directory to Python path for imports
app_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if app_dir not in sys.path:
    sys.path.insert(0, app_dir)

logger = logging.getLogger(__name__)

# Import celery instance
from celery_app import celery


def get_opensearch_client(config):
    """Create OpenSearch client"""
    from opensearchpy import OpenSearch
    return OpenSearch(
        hosts=[{'host': config.OPENSEARCH_HOST, 'port': config.OPENSEARCH_PORT}],
        http_auth=None,
        use_ssl=config.OPENSEARCH_USE_SSL,
        verify_certs=False,
        ssl_show_warn=False,
        timeout=30
    )


def guess_system_type(hostname):
    """Categorize system based on naming patterns"""
    if not hostname:
        return 'other'
    
    hostname_lower = hostname.lower()
    
    # Server patterns
    if re.search(r'srv|server|dc\d+|ad\d+|sql|exchange|file|print|backup|web|app|dc-|ad-|fs-|ps-|ws-|db-|ex-|sql-', hostname_lower):
        return 'server'
    
    # Router/Firewall patterns
    if re.search(r'fw|firewall|router|rtr|fortigate|palo\s*alto|checkpoint|sonicwall|asa|juniper|vyos|fw-|ngfw-|ips-|utm-|rtr-', hostname_lower):
        return 'router'
    
    # Switch patterns
    if re.search(r'sw|switch|cisco|arista|nexus|catalyst|dell\s*switch|sw-|switch-|core-|dist-|access-', hostname_lower):
        return 'switch'
    
    # Printer patterns
    if re.search(r'print|printer|copier|mfp|hp\s*laser|ricoh|xerox|konica|pr-|print-|mfp-|copier-', hostname_lower):
        return 'printer'
    
    # WAP patterns
    if re.search(r'wap|ap-|wifi|wireless|accesspoint', hostname_lower):
        return 'wap'
    
    # Threat Actor patterns
    if re.search(r'attacker|threat|actor|malicious|external|suspicious|unknown|unauth|rogue|badguy', hostname_lower):
        return 'threat_actor'
    
    # Default to workstation
    return 'workstation'


@celery.task(bind=True, name='tasks.discover_systems_from_logs')
def discover_systems_from_logs(self, case_id, user_id):
    """
    Discover systems from OpenSearch using aggregations (efficient approach)
    
    Args:
        case_id: Case ID to search
        user_id: User ID triggering the discovery
    
    Returns:
        dict with results
    """
    # Import Flask app and create context
    from main import app, db
    from models import KnownSystem, Case
    from config import Config
    
    with app.app_context():
        try:
            # Update progress
            self.update_state(state='PROGRESS', meta={'status': 'Initializing...', 'progress': 0})
            
            # Get case
            case = Case.query.get(case_id)
            if not case:
                return {'status': 'error', 'message': 'Case not found'}
            
            if not case.opensearch_index:
                return {'status': 'error', 'message': 'Case has no OpenSearch index'}
            
            logger.info(f"Starting system discovery for case {case_id} (index: {case.opensearch_index})")
            
            # Update progress
            self.update_state(state='PROGRESS', meta={'status': 'Connecting to OpenSearch...', 'progress': 5})
            
            # Get OpenSearch client
            client = get_opensearch_client(Config)
            
            # Check if index exists
            if not client.indices.exists(index=case.opensearch_index):
                return {'status': 'error', 'message': f'Index {case.opensearch_index} does not exist'}
            
            # Update progress
            self.update_state(state='PROGRESS', meta={'status': 'Counting events...', 'progress': 10})
            
            # Get total event count
            count_result = client.count(index=case.opensearch_index)
            total_events = count_result['count']
            
            logger.info(f"Found {total_events} events to process")
            
            if total_events == 0:
                return {'status': 'success', 'message': 'No events found in case', 'systems_found': 0, 'systems_created': 0}
            
            # Update progress
            self.update_state(state='PROGRESS', meta={'status': f'Extracting systems from {total_events} events...', 'progress': 15})
            
            # Discovered systems dictionary
            discovered_systems = {}
            
            # Fields to search for system names (prioritize normalized_computer)
            system_fields = [
                'normalized_computer',  # Primary field - CaseScope's normalized hostname (NDJSON)
                'computer',  # EVTX raw field (may be FQDN like "ATN64025.DWTEMPS.local")
                'Computer', 'ComputerName', 'Hostname', 'System', 'WorkstationName',
                'host.name', 'hostname', 'computername', 'source_name',
                'SourceHostname', 'DestinationHostname', 'src_host', 'dst_host'
            ]
            
            from opensearchpy import Search
            
            # Extract systems using aggregations (MUCH faster than scrolling)
            for idx, field in enumerate(system_fields):
                try:
                    progress = 15 + int((idx / len(system_fields)) * 60)
                    self.update_state(state='PROGRESS', meta={'status': f'Scanning field: {field}...', 'progress': progress})
                    
                    s = Search(using=client, index=case.opensearch_index)
                    s = s.filter('exists', field=field)
                    s = s[:0]  # Don't return documents
                    
                    # Use .keyword only if field is not already keyword type
                    # normalized_computer, computer are keyword fields, don't need .keyword suffix
                    agg_field = field if field in ['normalized_computer', 'computer'] else f'{field}.keyword'
                    s.aggs.bucket('systems', 'terms', field=agg_field, size=1000)
                    
                    response = s.execute()
                    
                    if response.aggregations and hasattr(response.aggregations, 'systems'):
                        for bucket in response.aggregations.systems.buckets:
                            system_name = bucket.key
                            doc_count = bucket.doc_count
                            
                            # Clean system name
                            system_name = system_name.strip()
                            if not system_name or system_name == '-' or len(system_name) < 2:
                                continue
                            
                            # Skip IPs (they're not hostnames)
                            if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', system_name):
                                continue
                            
                            # Strip FQDN to get just hostname (avoid duplicates)
                            # Examples: CM-DC01.cm.local -> CM-DC01, server.domain.com -> server
                            if '.' in system_name:
                                parts = system_name.split('.')
                                # If first part is a hostname and rest looks like domain
                                if len(parts) >= 2 and len(parts[0]) >= 2:
                                    # Keep just the hostname part
                                    hostname_only = parts[0].upper()
                                    system_name = hostname_only
                            
                            # Normalize to uppercase for consistent matching
                            system_name = system_name.upper()
                            
                            # Track highest doc count per system
                            if system_name not in discovered_systems or doc_count > discovered_systems[system_name]['count']:
                                discovered_systems[system_name] = {
                                    'name': system_name,
                                    'count': doc_count,
                                    'field': field
                                }
                        
                        logger.debug(f"Found {len(response.aggregations.systems.buckets)} systems in field '{field}'")
                
                except Exception as e:
                    logger.warning(f"Error scanning field '{field}': {e}")
                    continue
            
            logger.info(f"Discovered {len(discovered_systems)} unique systems from OpenSearch fields")
            
            # Note: Filename extraction removed for new app (different file model)
            # The normalized_computer field already captures the primary hostname
            
            logger.info(f"Total unique systems: {len(discovered_systems)}")
            
            # Get domains for discovered systems
            self.update_state(state='PROGRESS', meta={'status': 'Extracting domains...', 'progress': 75})
            
            system_domains = {}
            
            # Try host.domain for NDJSON
            try:
                s = Search(using=client, index=case.opensearch_index)
                s = s.filter('exists', field='host.domain')
                s = s[:0]
                
                # Get hostname and domain together
                # host.name is text field with .keyword subfield
                s.aggs.bucket('by_hostname', 'terms', field='host.name.keyword', size=1000) \
                      .metric('top_domain', 'top_hits', size=1, _source=['host.domain'])
                
                response = s.execute()
                
                if response.aggregations and hasattr(response.aggregations, 'by_hostname'):
                    for bucket in response.aggregations.by_hostname.buckets:
                        hostname = bucket.key.upper()
                        if bucket.top_domain.hits.hits:
                            domain = bucket.top_domain.hits.hits[0]['_source'].get('host', {}).get('domain')
                            if domain and domain != hostname:
                                system_domains[hostname] = domain
                                logger.debug(f"{hostname} -> domain: {domain}")
                
                logger.info(f"Found domains for {len(system_domains)} systems from host.domain")
            except Exception as e:
                logger.warning(f"Could not extract host.domain: {e}")
            
            # Try event_data_fields.SubjectDomainName for EVTX
            try:
                s = Search(using=client, index=case.opensearch_index)
                s = s.filter('exists', field='event_data_fields.SubjectDomainName')
                s = s.filter('exists', field='computer')
                s = s[:0]
                
                # Get computer and domain together
                # computer is already keyword type
                s.aggs.bucket('by_computer', 'terms', field='computer', size=1000) \
                      .metric('top_domain', 'top_hits', size=1, _source=['event_data_fields'])
                
                response = s.execute()
                
                if response.aggregations and hasattr(response.aggregations, 'by_computer'):
                    for bucket in response.aggregations.by_computer.buckets:
                        computer = bucket.key
                        # Strip FQDN if present
                        if '.' in computer:
                            computer = computer.split('.')[0]
                        computer = computer.upper()
                        
                        if bucket.top_domain.hits.hits:
                            event_data = bucket.top_domain.hits.hits[0]['_source'].get('event_data_fields', {})
                            domain = event_data.get('SubjectDomainName')
                            if domain and domain not in ['-', computer] and computer not in system_domains:
                                system_domains[computer] = domain
                                logger.debug(f"{computer} -> domain: {domain} (from EVTX)")
                
                logger.info(f"Found domains for {len(system_domains)} total systems after EVTX")
            except Exception as e:
                logger.warning(f"Could not extract EVTX domains: {e}")
            
            # Get IP addresses for discovered systems
            self.update_state(state='PROGRESS', meta={'status': 'Resolving IP addresses...', 'progress': 80})
            
            system_ips = {}
            
            try:
                s = Search(using=client, index=case.opensearch_index)
                s = s.filter('exists', field='normalized_computer')
                s = s.filter('exists', field='host.ip')
                s = s[:0]  # Don't return documents
                
                # Aggregate by computer name, get most common IP (top_hits)
                # normalized_computer is already keyword type, don't add .keyword
                s.aggs.bucket('by_computer', 'terms', field='normalized_computer', size=1000) \
                      .metric('top_ip', 'top_hits', size=1, _source=['host.ip'])
                
                response = s.execute()
                
                if response.aggregations and hasattr(response.aggregations, 'by_computer'):
                    for bucket in response.aggregations.by_computer.buckets:
                        computer_name = bucket.key
                        
                        # Normalize hostname (strip FQDN, uppercase)
                        if '.' in computer_name:
                            computer_name = computer_name.split('.')[0]
                        computer_name = computer_name.upper()
                        
                        if bucket.top_ip.hits.hits:
                            ip = bucket.top_ip.hits.hits[0]['_source'].get('host', {}).get('ip')
                            if ip and not system_ips.get(computer_name):
                                system_ips[computer_name] = ip
                                logger.debug(f"{computer_name} -> {ip}")
                
                logger.info(f"Resolved IPs for {len(system_ips)} systems")
            except Exception as e:
                logger.warning(f"Could not resolve IPs: {e}")
            
            # Categorize and save systems
            self.update_state(state='PROGRESS', meta={'status': 'Creating system entries...', 'progress': 90})
            
            new_systems_count = 0
            updated_systems_count = 0
            
            # Get existing systems for deduplication
            existing_systems = KnownSystem.query.filter_by(case_id=case_id).all()
            existing_map = {s.hostname.upper(): s for s in existing_systems if s.hostname}
            
            for sys_name, sys_data in discovered_systems.items():
                # Check if already exists
                existing = existing_map.get(sys_name)
                
                # Get IP address and domain for this system
                ip_address = system_ips.get(sys_name)
                domain_name = system_domains.get(sys_name)
                
                if not existing:
                    # Categorize system type
                    system_type = guess_system_type(sys_name)
                    
                    new_system = KnownSystem(
                        hostname=sys_name,
                        domain_name=domain_name,
                        ip_address=ip_address,
                        system_type=system_type,
                        compromised='unknown',
                        source='logs',
                        description=f"Auto-discovered from logs. Found in {sys_data['count']} events.",
                        case_id=case_id,
                        created_by=user_id,
                        updated_by=user_id
                    )
                    db.session.add(new_system)
                    new_systems_count += 1
                    
                    logger.debug(f"New system: {sys_name} (type: {system_type}, domain: {domain_name}, IP: {ip_address}, events: {sys_data['count']})")
                else:
                    # Update IP address and domain if we found them and they're not already set
                    if ip_address and not existing.ip_address:
                        existing.ip_address = ip_address
                        logger.debug(f"Updated IP for {sys_name}: {ip_address}")
                    if domain_name and not existing.domain_name:
                        existing.domain_name = domain_name
                        logger.debug(f"Updated domain for {sys_name}: {domain_name}")
                    updated_systems_count += 1
            
            # Commit all changes
            db.session.commit()
            
            logger.info(f"System discovery complete: {new_systems_count} created, {updated_systems_count} updated")
            
            # Log the completion with detailed results
            from audit_logger import log_action
            from models import User
            
            user = User.query.get(user_id)
            username = user.username if user else 'Unknown'
            
            # Build summary of systems
            new_systems_list = []
            updated_systems_list = []
            
            for sys_name, sys_data in discovered_systems.items():
                existing = existing_map.get(sys_name)
                system_info = {
                    'hostname': sys_name,
                    'domain': system_domains.get(sys_name, '-'),
                    'ip': system_ips.get(sys_name, '-'),
                    'event_count': sys_data['count']
                }
                
                if not existing:
                    system_info['type'] = guess_system_type(sys_name)
                    new_systems_list.append(system_info)
                else:
                    updated_systems_list.append(system_info)
            
            log_action(
                action='system_discovery_completed',
                resource_type='case',
                resource_id=case.id,
                resource_name=case.name,
                details={
                    'performed_by': username,
                    'total_events_scanned': total_events,
                    'systems_found': len(discovered_systems),
                    'new_systems': new_systems_count,
                    'updated_systems': updated_systems_count,
                    'new_systems_list': new_systems_list,
                    'updated_systems_list': updated_systems_list
                }
            )
            
            return {
                'status': 'success',
                'message': 'Discovery complete',
                'systems_found': len(discovered_systems),
                'systems_created': new_systems_count,
                'systems_updated': updated_systems_count,
                'events_processed': total_events
            }
            
        except Exception as e:
            logger.error(f"Error in system discovery: {e}", exc_info=True)
            db.session.rollback()
            return {
                'status': 'error',
                'message': str(e)
            }
