"""
User Discovery Task - Extract users from OpenSearch using aggregations
Similar to system discovery but focused on usernames from EVTX and NDJSON
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
    
    # Computer accounts (ending with $)
    # These will be filtered by pattern, not by exact name
    
    # Empty or invalid usernames
    '-', '', 'null', 'n/a', 'unknown',
    
    # Microsoft services
    'microsoft.activedirectory', 'azure ad connect', 'aad connect',
    'msol_', 'exchange online', 'o365', 'office365',
    
    # Common service prefixes (will check with startswith)
    # Listed separately below
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


def classify_user_type(username, domain=None):
    """
    Classify user as domain, local, or unknown
    
    Args:
        username: Username string
        domain: Optional domain name
    
    Returns:
        str: 'domain', 'local', or 'unknown'
    """
    if domain and domain != '-' and domain.upper() not in ['LOCAL', 'WORKGROUP', 'NT AUTHORITY']:
        return 'domain'
    
    if '\\' in username:
        # Extract domain from username
        domain_part = username.split('\\')[0].upper()
        if domain_part not in ['LOCAL', 'WORKGROUP', 'NT AUTHORITY', 'FONT DRIVER HOST', 'WINDOW MANAGER']:
            return 'domain'
        else:
            return 'local'
    
    if '@' in username:
        # email format - assume domain
        return 'domain'
    
    # Default to unknown
    return 'unknown'


@celery.task(bind=True, name='tasks.discover_users_from_logs')
def discover_users_from_logs(self, case_id, user_id):
    """
    Discover users from OpenSearch using aggregations (efficient approach)
    
    Args:
        case_id: Case ID to search
        user_id: User ID triggering the discovery
    
    Returns:
        dict with results
    """
    # Import Flask app and create context
    from main import app, db
    from models import KnownUser, Case
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
            
            logger.info(f"Starting user discovery for case {case_id} (index: {case.opensearch_index})")
            
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
                return {'status': 'success', 'message': 'No events found in case', 'users_found': 0, 'users_created': 0}
            
            # Update progress
            self.update_state(state='PROGRESS', meta={'status': f'Extracting users from {total_events} events...', 'progress': 15})
            
            # Discovered users dictionary
            discovered_users = {}
            
            # Fields to search for usernames
            # EVTX fields
            evtx_username_fields = [
                'event_data_fields.TargetUserName',
                'event_data_fields.SubjectUserName',
                'event_data_fields.User',
                'event_data_fields.AccountName',
            ]
            
            # NDJSON fields
            ndjson_username_fields = [
                'user.name',
                'user.id',
                'source.user.name',
                'destination.user.name',
                'related.user',
            ]
            
            all_username_fields = evtx_username_fields + ndjson_username_fields
            
            from opensearchpy import Search
            
            # Extract users using aggregations (MUCH faster than scrolling)
            for idx, field in enumerate(all_username_fields):
                try:
                    progress = 15 + int((idx / len(all_username_fields)) * 50)
                    self.update_state(state='PROGRESS', meta={'status': f'Scanning field: {field}...', 'progress': progress})
                    
                    s = Search(using=client, index=case.opensearch_index)
                    s = s.filter('exists', field=field)
                    s = s[:0]  # Don't return documents
                    
                    # Use .keyword for aggregation
                    agg_field = f'{field}.keyword' if not field.endswith('.keyword') else field
                    s.aggs.bucket('users', 'terms', field=agg_field, size=2000)
                    
                    response = s.execute()
                    
                    if response.aggregations and hasattr(response.aggregations, 'users'):
                        for bucket in response.aggregations.users.buckets:
                            username = bucket.key
                            doc_count = bucket.doc_count
                            
                            # Clean username
                            username = username.strip() if isinstance(username, str) else str(username)
                            
                            # Check if should be excluded
                            if should_exclude_username(username):
                                continue
                            
                            # Normalize username for comparison
                            username_key = username.lower()
                            
                            # Track highest doc count per user
                            if username_key not in discovered_users or doc_count > discovered_users[username_key]['count']:
                                discovered_users[username_key] = {
                                    'username': username,  # Keep original case
                                    'count': doc_count,
                                    'field': field
                                }
                        
                        logger.debug(f"Found {len(response.aggregations.users.buckets)} users in field '{field}'")
                
                except Exception as e:
                    logger.warning(f"Error scanning field '{field}': {e}")
                    continue
            
            logger.info(f"Discovered {len(discovered_users)} unique users from OpenSearch fields")
            
            # Get domains and SIDs for discovered users
            self.update_state(state='PROGRESS', meta={'status': 'Extracting domains and SIDs...', 'progress': 65})
            
            user_domains = {}
            user_sids = {}
            
            # Try to get domain from EVTX SubjectDomainName or TargetDomainName
            try:
                s = Search(using=client, index=case.opensearch_index)
                s = s.filter('exists', field='event_data_fields.TargetUserName')
                s = s.filter('exists', field='event_data_fields.TargetDomainName')
                s = s[:0]
                
                s.aggs.bucket('by_username', 'terms', field='event_data_fields.TargetUserName.keyword', size=2000) \
                      .metric('top_domain', 'top_hits', size=1, _source=['event_data_fields.TargetDomainName', 'event_data_fields.TargetUserSid'])
                
                response = s.execute()
                
                if response.aggregations and hasattr(response.aggregations, 'by_username'):
                    for bucket in response.aggregations.by_username.buckets:
                        username = bucket.key
                        username_lower = username.lower()
                        
                        if bucket.top_domain.hits.hits:
                            event_data = bucket.top_domain.hits.hits[0]['_source'].get('event_data_fields', {})
                            domain = event_data.get('TargetDomainName')
                            sid = event_data.get('TargetUserSid')
                            
                            if domain and domain != '-' and username_lower not in user_domains:
                                user_domains[username_lower] = domain
                            if sid and sid != '-' and username_lower not in user_sids:
                                user_sids[username_lower] = sid
                
                logger.info(f"Found domains/SIDs for {len(user_domains)} users from EVTX TargetUserName")
            except Exception as e:
                logger.warning(f"Could not extract EVTX TargetUserName domains: {e}")
            
            # Try SubjectUserName as well
            try:
                s = Search(using=client, index=case.opensearch_index)
                s = s.filter('exists', field='event_data_fields.SubjectUserName')
                s = s.filter('exists', field='event_data_fields.SubjectDomainName')
                s = s[:0]
                
                s.aggs.bucket('by_username', 'terms', field='event_data_fields.SubjectUserName.keyword', size=2000) \
                      .metric('top_domain', 'top_hits', size=1, _source=['event_data_fields.SubjectDomainName', 'event_data_fields.SubjectUserSid'])
                
                response = s.execute()
                
                if response.aggregations and hasattr(response.aggregations, 'by_username'):
                    for bucket in response.aggregations.by_username.buckets:
                        username = bucket.key
                        username_lower = username.lower()
                        
                        if bucket.top_domain.hits.hits:
                            event_data = bucket.top_domain.hits.hits[0]['_source'].get('event_data_fields', {})
                            domain = event_data.get('SubjectDomainName')
                            sid = event_data.get('SubjectUserSid')
                            
                            if domain and domain != '-' and username_lower not in user_domains:
                                user_domains[username_lower] = domain
                            if sid and sid != '-' and username_lower not in user_sids:
                                user_sids[username_lower] = sid
                
                logger.info(f"Found domains/SIDs for {len(user_domains)} total users after SubjectUserName")
            except Exception as e:
                logger.warning(f"Could not extract EVTX SubjectUserName domains: {e}")
            
            # Try user.domain from NDJSON
            try:
                s = Search(using=client, index=case.opensearch_index)
                s = s.filter('exists', field='user.name')
                s = s.filter('exists', field='user.domain')
                s = s[:0]
                
                s.aggs.bucket('by_username', 'terms', field='user.name.keyword', size=2000) \
                      .metric('top_domain', 'top_hits', size=1, _source=['user.domain', 'user.id'])
                
                response = s.execute()
                
                if response.aggregations and hasattr(response.aggregations, 'by_username'):
                    for bucket in response.aggregations.by_username.buckets:
                        username = bucket.key
                        username_lower = username.lower()
                        
                        if bucket.top_domain.hits.hits:
                            user_data = bucket.top_domain.hits.hits[0]['_source'].get('user', {})
                            domain = user_data.get('domain')
                            user_id = user_data.get('id')
                            
                            if domain and domain != '-' and username_lower not in user_domains:
                                user_domains[username_lower] = domain
                            if user_id and user_id != '-' and username_lower not in user_sids:
                                user_sids[username_lower] = user_id
                
                logger.info(f"Found domains for {len(user_domains)} total users after NDJSON")
            except Exception as e:
                logger.warning(f"Could not extract NDJSON user domains: {e}")
            
            # Create/update user entries
            self.update_state(state='PROGRESS', meta={'status': 'Creating user entries...', 'progress': 80})
            
            new_users_count = 0
            updated_users_count = 0
            
            # Get existing users for deduplication
            existing_users = KnownUser.query.filter_by(case_id=case_id).all()
            existing_map = {}
            for u in existing_users:
                key = f"{u.domain_name or '-'}\\{u.username}".lower()
                existing_map[key] = u
            
            new_users_list = []
            updated_users_list = []
            
            for username_key, user_data in discovered_users.items():
                username = user_data['username']
                
                # Get domain and SID for this user
                domain = user_domains.get(username_key, '-')
                sid = user_sids.get(username_key, '-')
                
                # Parse username if it contains domain
                if '\\' in username:
                    parts = username.split('\\', 1)
                    domain = parts[0]
                    username = parts[1]
                elif '@' in username:
                    parts = username.split('@', 1)
                    username = parts[0]
                    if domain == '-':
                        domain = parts[1]
                
                # Classify user type
                user_type = classify_user_type(username, domain)
                
                # Check if already exists
                lookup_key = f"{domain}\\{username}".lower()
                existing = existing_map.get(lookup_key)
                
                # Also check without domain
                if not existing:
                    lookup_key_no_domain = f"-\\{username}".lower()
                    existing = existing_map.get(lookup_key_no_domain)
                
                if not existing:
                    # Create new user
                    new_user = KnownUser(
                        username=username,
                        domain_name=domain if domain and domain != '-' else '-',
                        sid=sid if sid and sid != '-' else '-',
                        user_type=user_type,
                        compromised='no',
                        source='logs',
                        description=f"Auto-discovered from logs. Found in {user_data['count']} events.",
                        analyst_notes=f"Discovered from field: {user_data['field']}",
                        case_id=case_id,
                        created_by=user_id,
                        updated_by=user_id
                    )
                    db.session.add(new_user)
                    new_users_count += 1
                    
                    new_users_list.append({
                        'username': username,
                        'domain': domain if domain != '-' else 'None',
                        'sid': sid if sid != '-' else 'None',
                        'type': user_type,
                        'event_count': user_data['count']
                    })
                    
                    logger.debug(f"New user: {domain}\\{username} (type: {user_type}, SID: {sid}, events: {user_data['count']})")
                else:
                    # Update if we have new information
                    updated = False
                    if sid and sid != '-' and (not existing.sid or existing.sid == '-'):
                        existing.sid = sid
                        updated = True
                    if domain and domain != '-' and (not existing.domain_name or existing.domain_name == '-'):
                        existing.domain_name = domain
                        updated = True
                    
                    if updated:
                        existing.updated_by = user_id
                        updated_users_count += 1
                        updated_users_list.append({
                            'username': username,
                            'domain': domain if domain != '-' else 'None',
                            'sid': sid if sid != '-' else 'None',
                            'type': user_type,
                            'event_count': user_data['count']
                        })
                        logger.debug(f"Updated user: {domain}\\{username}")
            
            # Commit all changes
            db.session.commit()
            
            logger.info(f"User discovery complete: {new_users_count} created, {updated_users_count} updated")
            
            # Log the completion with detailed results
            from audit_logger import log_action
            from models import User
            
            user = User.query.get(user_id)
            username_performer = user.username if user else 'Unknown'
            
            log_action(
                action='user_discovery_completed',
                resource_type='case',
                resource_id=case.id,
                resource_name=case.name,
                details={
                    'performed_by': username_performer,
                    'total_events_scanned': total_events,
                    'users_found': len(discovered_users),
                    'new_users': new_users_count,
                    'updated_users': updated_users_count,
                    'new_users_list': new_users_list,
                    'updated_users_list': updated_users_list
                }
            )
            
            return {
                'status': 'success',
                'message': 'Discovery complete',
                'users_found': len(discovered_users),
                'users_created': new_users_count,
                'users_updated': updated_users_count,
                'events_processed': total_events
            }
            
        except Exception as e:
            logger.error(f"Error in user discovery: {e}", exc_info=True)
            db.session.rollback()
            return {
                'status': 'error',
                'message': str(e)
            }

