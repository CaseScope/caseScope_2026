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
    
    # Built-in Windows system accounts (NOT generic "admin" or "user")
    'guest', 'defaultaccount', 'default', 'wdagutilityaccount',
    'krbtgt', 'wsiaccount', 'wsiuser', 'defaultuser', 'defaultuser0',
    
    # IIS service accounts (specific)
    'iusr', 'iwam', 'iis_iusrs', 'defaultapppool', 'iis apppool',
    'network service', 'aspnet', 'iis_wpg', 'iis_wpr',
    
    # System virtual accounts
    'localsystem', 'local system', 'nt authority\\localsystem',
    
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
    'anonymous logon', 'anonymous', 'nobody', 'basic',
    
    # Common service account names (SQL, Tableau, etc.)
    'sqlserveragent', 'sqlserver', 'mssql', 'sqlagent',
    'service', 'svc', 'svcaccount', 'tabsvc',
    
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
    'iis apppool\\',
    'virtual machines\\',
    'default app pool',
]

# Patterns to exclude (ONLY system/service accounts, NOT generic user names)
EXCLUDED_PATTERNS = [
    r'\$$',  # Computer accounts ending with $ (CRITICAL)
    r'^S-\d+-\d+',  # SIDs that look like usernames
    r'.*_\d+[a-z]{5,}$',  # Pattern like "name_5wofrIv" (likely auto-generated/junk)
    r'^[a-z0-9]{20,}$',  # Very long random strings
    r'^[A-Z0-9]{8,}-[A-Z0-9]{4,}-',  # GUID patterns
    r'^svc[_-]?\w+',  # Service accounts starting with svc
    r'^\w*serviceuser\d+$',  # Pattern: qbdataserviceuser28, dataserviceuser5, etc.
    r'localsystem',  # Local system account (any case)
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
    original_username = username.strip()
    
    # Skip empty only (allow short usernames - they might be real)
    if not username_lower or len(username_lower) < 1:
        return True
    
    # CRITICAL: Computer accounts ending with $ (check BEFORE normalization)
    if original_username.endswith('$'):
        return True
    
    # IIS AppPool accounts (various formats)
    if 'apppool' in username_lower or 'iis' in username_lower:
        return True
    
    # Check for domain-qualified service accounts
    if '\\' in username_lower:
        parts = username_lower.split('\\')
        domain_part = parts[0]
        user_part = parts[1] if len(parts) > 1 else ''
        
        # Check if domain is a service domain
        if domain_part in ['iis apppool', 'nt authority', 'font driver host', 'window manager', 'nt service']:
            return True
        
        # Check if username part should be excluded
        if user_part in EXCLUDED_USERNAMES or user_part.endswith('$'):
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
        if re.match(pattern, original_username, re.IGNORECASE):
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
    # Service/system domains
    SERVICE_DOMAINS = [
        'LOCAL', 'WORKGROUP', 'NT AUTHORITY', 'FONT DRIVER HOST', 
        'WINDOW MANAGER', 'IIS APPPOOL', 'NT SERVICE', 'VIRTUAL MACHINES'
    ]
    
    if domain and domain != '-' and domain.upper() not in SERVICE_DOMAINS:
        return 'domain'
    
    if '\\' in username:
        # Extract domain from username
        domain_part = username.split('\\')[0].upper()
        if domain_part not in SERVICE_DOMAINS:
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
                            
                            # DEBUG: Log every username we see
                            logger.info(f"[DEBUG] Processing username from field {field}: '{username}' (len={len(username)}, last_char='{username[-1] if username else 'N/A'}', ends_with_$={username.endswith('$')})")
                            
                            # CRITICAL: Aggressive filtering before any processing
                            # 1. Computer accounts (ending with $) - Must check first!
                            if username.endswith('$'):
                                logger.info(f"[FILTER] ✓ Excluded computer account: {username}")
                                continue
                            
                            # 2. Known service account patterns (quick inline check)
                            username_lower = username.lower()
                            if 'serviceuser' in username_lower or 'apppool' in username_lower or username_lower == 'localsystem':
                                logger.info(f"[FILTER] Excluded service account: {username}")
                                continue
                            
                            # 3. Check comprehensive exclusion list
                            if should_exclude_username(username):
                                logger.info(f"[FILTER] Excluded by filter: {username}")
                                continue
                            
                            # If we got here, it's a valid username
                            logger.debug(f"[FILTER] KEEPING username: {username}")
                            
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
            
            # DEBUG: Check if any computer accounts slipped through
            computer_accounts_in_dict = [u['username'] for u in discovered_users.values() if u['username'].endswith('$')]
            if computer_accounts_in_dict:
                logger.error(f"[BUG] Computer accounts in discovered_users AFTER filtering: {computer_accounts_in_dict}")
            else:
                logger.info(f"[SUCCESS] No computer accounts in discovered_users dict")
            
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
            
            # Create/update user entries using auto-merge
            self.update_state(state='PROGRESS', meta={'status': 'Creating user entries...', 'progress': 80})
            
            new_users_count = 0
            merged_users_count = 0
            
            # Import auto-merge helper
            from utils.merge_helpers import find_or_merge_user, normalize_username
            
            # Build map of existing users for tracking new vs merged
            existing_users = KnownUser.query.filter_by(case_id=case_id).all()
            existing_map = {}
            for u in existing_users:
                # Track by normalized username AND SID (to detect different users)
                norm_username = normalize_username(u.username)
                if u.sid:
                    key = f"{norm_username}::{u.sid}"
                else:
                    key = norm_username
                existing_map[key] = u
            
            new_users_list = []
            updated_users_list = []
            
            for username_key, user_data in discovered_users.items():
                username = user_data['username']
                
                # CRITICAL: Explicit computer account check (safety #1)
                if username.endswith('$'):
                    logger.info(f"[SAFETY] Blocked computer account before creation: {username}")
                    continue
                
                # Double-check exclusion (safety check #2)
                if should_exclude_username(username):
                    logger.info(f"[SAFETY] Excluded by filter before creation: {username}")
                    continue
                
                # Get domain and SID for this user
                domain = user_domains.get(username_key)
                if domain == '-':
                    domain = None
                    
                sid = user_sids.get(username_key)
                if sid == '-':
                    sid = None
                
                # Classify user type
                user_type = classify_user_type(username, domain)
                
                # Skip if classified as service account domain
                if domain and domain.upper() in ['IIS APPPOOL', 'NT SERVICE', 'VIRTUAL MACHINES']:
                    logger.debug(f"Excluding service domain user: {domain}\\{username}")
                    continue
                
                # Check if existed before merge (for tracking)
                norm_check = normalize_username(username)
                existed_before = any(norm_check in k for k in existing_map.keys())
                
                # Use auto-merge logic (with SID validation)
                user = find_or_merge_user(
                    db=db,
                    case_id=case_id,
                    username=username,  # May include domain prefix
                    domain_name=domain,
                    sid=sid,
                    user_type=user_type,
                    compromised='no',
                    source='logs',
                    description=f"Auto-discovered from logs. Found in {user_data['count']} events.",
                    analyst_notes=f"Discovered from field: {user_data['field']}",
                    created_by=user_id,
                    updated_by=user_id,
                    logger=logger
                )
                
                if user:
                    user_info = {
                        'username': user.username,
                        'domain': user.domain_name or 'None',
                        'sid': user.sid or 'None',
                        'type': user.user_type,
                        'event_count': user_data['count']
                    }
                    
                    if existed_before:
                        merged_users_count += 1
                        updated_users_list.append(user_info)
                    else:
                        new_users_count += 1
                        new_users_list.append(user_info)
                        # Add to map for tracking
                        if user.sid:
                            key = f"{normalize_username(user.username)}::{user.sid}"
                        else:
                            key = normalize_username(user.username)
                        existing_map[key] = user
            
            # Commit all changes
            db.session.commit()
            
            logger.info(f"User discovery complete: {new_users_count} created, {merged_users_count} merged")
            
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
                    'merged_users': merged_users_count,
                    'new_users_list': new_users_list,
                    'updated_users_list': updated_users_list
                }
            )
            
            return {
                'status': 'success',
                'message': f'Discovery complete: {new_users_count} new, {merged_users_count} merged',
                'users_found': len(discovered_users),
                'users_created': new_users_count,
                'users_merged': merged_users_count,
                'events_processed': total_events
            }
            
        except Exception as e:
            logger.error(f"Error in user discovery: {e}", exc_info=True)
            db.session.rollback()
            return {
                'status': 'error',
                'message': str(e)
            }

