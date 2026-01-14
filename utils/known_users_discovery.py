"""Known Users Discovery Module

Modular function to discover and populate known users from artifacts.
Can be called from:
1. File ingestion process (after files are ingested)
2. UI button click ("Find in Artifacts")
"""
import logging
from datetime import datetime
from typing import Dict, List, Tuple, Optional
from sqlalchemy.exc import IntegrityError

from models.database import db
from models.known_user import (
    KnownUser, KnownUserAlias, KnownUserEmail,
    KnownUserAudit, KnownUserCase
)
from config import Config

logger = logging.getLogger(__name__)

# Built-in/System accounts to exclude from discovery
SYSTEM_ACCOUNTS = {
    'SYSTEM', 'LOCAL SERVICE', 'NETWORK SERVICE', 'ANONYMOUS LOGON',
    'NT AUTHORITY', 'BUILTIN', 'WINDOW MANAGER', 'FONT DRIVER HOST',
    'DWMWINDOWHOST', '-', '', 'N/A', 'NA', 'NONE', 'NULL', 'UNKNOWN',
    'IUSR', 'IWAM', 'ASPNET', 'DEFAULTACCOUNT', 'CONTEXT', 'CONTEXT:',
    'GUEST', 'DEFAULTUSER0', 'WDAGUTILITYACCOUNT', '-\\-',
}

# Well-known SIDs to exclude
SYSTEM_SIDS_EXACT = {
    'S-1-0-0',   # Nobody - null SID
    'S-1-5-4',   # Interactive
    'S-1-5-18',  # Local System
    'S-1-5-19',  # Local Service  
    'S-1-5-20',  # Network Service
    'S-1-5-7',   # Anonymous Logon
    'S-1-5-6',   # Service
    'S-1-5-2',   # Network
    'S-1-5-3',   # Batch
    'S-1-1-0',   # Everyone
    'S-1-5-32',  # Builtin
}

# Patterns for system account prefixes (will match UMFD-0 through UMFD-99, DWM-1 through DWM-99, etc.)
SYSTEM_ACCOUNT_PREFIXES = ('UMFD-', 'DWM-', 'WINRM ', 'FONT DRIVER HOST\\')


# SID prefixes to exclude
SYSTEM_SID_PREFIXES = (
    'S-1-5-90-',   # Window Manager (DWM)
    'S-1-5-96-',   # Font Driver Host (UMFD)
    'S-1-5-80-',   # NT Service accounts
    'S-1-5-82-',   # IIS AppPool accounts
    'S-1-5-83-',   # Virtual Machine accounts
    'S-1-5-32-',   # Builtin domain
)


def clean_username(username: str) -> str:
    """Clean and normalize a username, stripping prefixes and garbage
    
    Returns cleaned username or None if it's garbage
    """
    if not username:
        return None
    
    username = username.strip()
    
    # Strip common prefixes from Hayabusa/event parsing
    prefixes_to_strip = [
        'CONTEXT:', 'CONTEXT ', 
        'TARGET:', 'TARGET ',
        'SOURCE:', 'SOURCE ',
        'USER:', 'USER ',
        'SUBJECT:', 'SUBJECT ',
    ]
    
    upper = username.upper()
    for prefix in prefixes_to_strip:
        if upper.startswith(prefix):
            username = username[len(prefix):].strip()
            upper = username.upper()
            # Check again in case there are nested prefixes
            break
    
    # Check for garbled/corrupted Unicode (non-ASCII characters that aren't valid)
    # Valid usernames should be mostly ASCII with maybe some extended Latin chars
    try:
        # Count non-ASCII characters
        non_ascii = sum(1 for c in username if ord(c) > 127)
        if non_ascii > 0:
            # If more than 20% non-ASCII or has weird Unicode ranges, it's garbage
            if non_ascii / len(username) > 0.2:
                return None
            # Check for specific garbage Unicode ranges
            for c in username:
                code = ord(c)
                # Filter out: control chars, private use, surrogates, unusual scripts
                if code > 255 and code not in range(0x100, 0x180):  # Extended Latin OK
                    return None
    except Exception:
        return None
    
    if not username or len(username) < 2:
        return None
    
    return username


def init_user_discovery_progress(case_uuid: str, total: int):
    """Initialize users discovery progress using unified progress module"""
    from utils.progress import set_phase
    set_phase(case_uuid, 'users', total=total)


def update_user_discovery_progress(case_uuid: str, processed: int, created: int, updated: int, current: str = ''):
    """Update users discovery progress using unified progress module"""
    from utils.progress import set_current_item
    # Only update current item, increment is called per-item now
    set_current_item(case_uuid, current)


def complete_user_discovery_progress(case_uuid: str, results: dict):
    """Mark users discovery as complete"""
    from utils.progress import get_redis_client
    
    try:
        client = get_redis_client()
        key = f"processing_progress:{case_uuid}"
        client.hset(key, 'status', 'complete')
    except Exception as e:
        logger.warning(f"Failed to set user discovery complete status: {e}")


def get_user_discovery_progress(case_uuid: str) -> Optional[dict]:
    """Get current discovery progress from unified progress module"""
    from utils.progress import get_progress
    progress = get_progress(case_uuid)
    if progress and progress.get('phase') == 'users':
        return {
            'status': 'running' if progress.get('status') == 'discovering_users' else progress.get('status'),
            'total': progress['users']['total'],
            'processed': progress['users']['completed'],
            'created': 0,  # Not tracked in unified progress
            'updated': 0,
            'current_user': progress.get('current_item', '')
        }
    return None


def is_system_account(username: str, sid: str = None) -> bool:
    """Check if account is a system/built-in account to exclude"""
    if not username and not sid:
        return True
    
    # Check username against system accounts
    if username:
        # Clean the username first
        cleaned = clean_username(username)
        if not cleaned:
            return True  # Garbage username
        
        username_upper = cleaned.upper()
        
        # Skip empty or very short usernames
        if len(username_upper) < 2:
            return True
        
        # Direct match
        if username_upper in SYSTEM_ACCOUNTS:
            return True
        
        # Check for system account prefixes (UMFD-*, DWM-*, etc.)
        for prefix in SYSTEM_ACCOUNT_PREFIXES:
            if username_upper.startswith(prefix):
                return True
        
        # Check for DOMAIN\SYSTEM pattern
        if '\\' in username_upper:
            user_part = username_upper.split('\\', 1)[1]
            if user_part in SYSTEM_ACCOUNTS:
                return True
            for prefix in SYSTEM_ACCOUNT_PREFIXES:
                if user_part.startswith(prefix):
                    return True
        
        # Check for machine account (ends with $)
        if username_upper.endswith('$'):
            return True
        
        # Check if username is actually a SID (starts with S-1-)
        if username_upper.startswith('S-1-'):
            # This is a SID in the username field - check if it's a system SID
            if username_upper in SYSTEM_SIDS_EXACT:
                return True
            for prefix in SYSTEM_SID_PREFIXES:
                if username_upper.startswith(prefix):
                    return True
        
        # Check for hex-encoded SIDs (long hex strings starting with 0103 or 0105)
        # These are binary SID representations, not real usernames
        if len(username_upper) > 20 and username_upper.startswith(('0103', '0105', '0101')):
            # Check if it's mostly hex characters
            if all(c in '0123456789ABCDEF' for c in username_upper):
                return True
        
        # Exclude pure numeric "usernames" (like "2", "123")
        if username_upper.isdigit():
            return True
    
    # Check SID against system SIDs
    if sid:
        sid_upper = sid.strip().upper()
        
        # Direct match of well-known SIDs
        if sid_upper in SYSTEM_SIDS_EXACT:
            return True
        
        # Check for system SID prefixes
        for prefix in SYSTEM_SID_PREFIXES:
            if sid_upper.startswith(prefix):
                return True
        
        # Check for hex-encoded SIDs in the SID field too
        if len(sid_upper) > 20 and sid_upper.startswith(('0103', '0105', '0101')):
            if all(c in '0123456789ABCDEF' for c in sid_upper):
                return True
    
    return False


def discover_known_users(case_id: int, case_uuid: str, username: str = 'system', track_progress: bool = False) -> Dict:
    """Discover and populate known users from artifacts for a case
    
    Sources:
    1. ClickHouse events - username, sid, domain fields
    2. Logon events, SMB connections, process execution
    
    Args:
        case_id: PostgreSQL case.id (also used for ClickHouse)
        case_uuid: Case UUID for progress tracking
        username: User performing the discovery (for audit)
        track_progress: Whether to track progress in Redis
    
    Returns:
        Dict with discovery results
    """
    results = {
        'success': True,
        'users_created': 0,
        'users_updated': 0,
        'aliases_added': 0,
        'emails_added': 0,
        'case_links_added': 0,
        'users_processed': 0,
        'errors': []
    }
    
    try:
        # Collect user stats from all sources
        # Format: {key: {'username': X, 'sid': Y, 'domain': Z, 'count': N, 'last_seen': datetime}}
        
        # Source 1: ClickHouse events - all user-related fields
        user_stats = _get_users_from_events(case_id)
        logger.info(f"Found {len(user_stats)} unique users from events")
        
        total_users = len(user_stats)
        results['users_processed'] = total_users
        logger.info(f"Processing {total_users} total unique users")
        
        # Initialize progress tracking
        if track_progress:
            init_user_discovery_progress(case_uuid, total_users)
        
        # Process each user with their stats
        processed = 0
        for key, stats in user_stats.items():
            try:
                created, updated, alias_added, email_added = _process_user(
                    username=stats.get('username'),
                    sid=stats.get('sid'),
                    domain=stats.get('domain'),
                    case_id=case_id,
                    added_by=username,
                    artifact_count=stats['count'],
                    last_seen=stats['last_seen'],
                    alias_formats=stats.get('alias_formats', set()),
                    sources=list(stats.get('sources', set()))
                )
                
                if created:
                    results['users_created'] += 1
                if updated:
                    results['users_updated'] += 1
                if alias_added:
                    results['aliases_added'] += 1
                if email_added:
                    results['emails_added'] += 1
                
                processed += 1
                
                # Update progress atomically
                if track_progress:
                    from utils.progress import increment_phase, set_current_item
                    increment_phase(case_uuid, 'users')
                    # Update current item every 10 users to reduce Redis calls
                    if processed % 10 == 0 or processed == total_users:
                        set_current_item(case_uuid, stats.get('username', stats.get('sid', '')))
                    
            except IntegrityError:
                # Race condition - another process created this user
                db.session.rollback()
                try:
                    created, updated, alias_added, email_added = _process_user(
                        username=stats.get('username'),
                        sid=stats.get('sid'),
                        domain=stats.get('domain'),
                        case_id=case_id,
                        added_by=username,
                        artifact_count=stats['count'],
                        last_seen=stats['last_seen'],
                        alias_formats=stats.get('alias_formats', set()),
                        sources=list(stats.get('sources', set()))
                    )
                    if updated:
                        results['users_updated'] += 1
                    if alias_added:
                        results['aliases_added'] += 1
                    processed += 1
                except Exception as e2:
                    logger.warning(f"Retry failed for user: {e2}")
                    
            except Exception as e:
                logger.error(f"Error processing user '{stats}': {e}")
                results['errors'].append(f"Error with user: {str(e)}")
                db.session.rollback()  # Rollback to allow subsequent users to process
                processed += 1
        
        # Commit all changes
        try:
            db.session.commit()
        except Exception as commit_err:
            logger.warning(f"Final commit failed (some users may not have been saved): {commit_err}")
            db.session.rollback()
        
        # Count case links added
        results['case_links_added'] = KnownUserCase.query.filter_by(case_id=case_id).count()
        
        # Mark progress complete
        if track_progress:
            complete_user_discovery_progress(case_uuid, results)
        
    except Exception as e:
        logger.exception("Error in discover_known_users")
        results['success'] = False
        results['errors'].append(str(e))
        db.session.rollback()
    
    return results


def _get_users_from_events(case_id: int) -> dict:
    """Get user stats from ClickHouse events table
    
    Extracts users from:
    - username field (logon events, process execution)
    - sid field (Windows events)
    - domain field (for context)
    
    Returns dict: {key: {'username': X, 'sid': Y, 'domain': Z, 'count': N, 'last_seen': datetime, 'sources': set}}
    """
    from utils.clickhouse import get_client
    
    user_stats = {}
    
    try:
        client = get_client()
        
        # Query for unique username/SID combinations with counts and artifact types
        result = client.query(
            """SELECT 
                username, 
                sid, 
                domain,
                artifact_type,
                count() as cnt, 
                max(timestamp) as last_ts
               FROM events 
               WHERE case_id = {case_id:UInt32} 
                 AND (username != '' OR sid != '')
               GROUP BY username, sid, domain, artifact_type
               LIMIT 100000""",
            parameters={'case_id': case_id}
        )
        
        for row in result.result_rows:
            raw_username = row[0].strip() if row[0] else None
            sid = row[1].strip() if row[1] else None
            domain = row[2].strip() if row[2] else None
            artifact_type = row[3].strip().lower() if row[3] else 'unknown'
            count = row[4]
            last_ts = row[5]
            
            # Clean the username (strip Context: prefix, filter garbage)
            username = clean_username(raw_username) if raw_username else None
            
            # If username looks like a SID (S-1-5-...), treat it as the SID
            if username and username.upper().startswith('S-1-') and not sid:
                sid = username.upper()
                username = None
            
            # Skip system accounts
            if is_system_account(username, sid):
                continue
            
            # Normalize username to get consistent key
            # DOMAIN\user -> user is the username, DOMAIN\user becomes an alias
            normalized_username = None
            original_format = None  # Store original format for alias
            extracted_domain = None
            
            if username:
                # Check if it's domain\user format
                if '\\' in username:
                    original_format = username.upper()  # JAMESMFG\SBRUNNER
                
                normalized_username, extracted_domain = KnownUser.normalize_username(username)
                if extracted_domain and not domain:
                    domain = extracted_domain
            
            # Create unique key for dedup within this query
            # Use SID as primary key if available, otherwise normalized username
            if sid:
                key = f"SID:{sid.upper()}"
            elif normalized_username:
                key = f"USER:{normalized_username}"
            else:
                continue
            
            # Merge stats for same key
            if key in user_stats:
                user_stats[key]['count'] += count
                # Track artifact types as sources
                user_stats[key]['sources'].add(artifact_type)
                if last_ts and (not user_stats[key]['last_seen'] or last_ts > user_stats[key]['last_seen']):
                    user_stats[key]['last_seen'] = last_ts
                # Update username if we have it now but didn't before
                if normalized_username and not user_stats[key].get('username'):
                    user_stats[key]['username'] = normalized_username
                # Update SID if we have it now but didn't before
                if sid and not user_stats[key].get('sid'):
                    user_stats[key]['sid'] = sid.upper()
                # Update domain if we have it now but didn't before
                if domain and not user_stats[key].get('domain'):
                    user_stats[key]['domain'] = domain
                # Track domain\user formats as aliases
                if original_format:
                    if 'alias_formats' not in user_stats[key]:
                        user_stats[key]['alias_formats'] = set()
                    user_stats[key]['alias_formats'].add(original_format)
            else:
                user_stats[key] = {
                    'username': normalized_username,
                    'sid': sid.upper() if sid else None,
                    'domain': domain,
                    'count': count,
                    'last_seen': last_ts,
                    'sources': {artifact_type},
                    'alias_formats': {original_format} if original_format else set()
                }
                
    except Exception as e:
        logger.warning(f"Error querying ClickHouse for users: {e}")
    
    return user_stats


def _process_user(username: str, sid: str, domain: str, case_id: int, added_by: str,
                  artifact_count: int = 1, last_seen: datetime = None,
                  alias_formats: set = None, sources: List[str] = None) -> Tuple[bool, bool, bool, bool]:
    """Process a single user through deduplication logic
    
    Matching logic:
    1. Check if username already exists
    2. Check if SID matches another known user
    3. Check if username exists in aliases
    4. Check if email prefix matches username or alias
    5. If no match, create new user
    
    Args:
        username: The username to process (normalized, without domain)
        sid: Windows SID if available
        domain: Domain if available
        case_id: Case ID for linking
        added_by: User performing discovery
        artifact_count: Number of artifacts referencing this user
        last_seen: Timestamp of most recent artifact with this user
        alias_formats: Set of DOMAIN\\USER format strings to add as aliases
        sources: List of data sources (evtx, ndjson, etc.)
    
    Returns: (created, updated, alias_added, email_added)
    """
    if alias_formats is None:
        alias_formats = set()
    if sources is None:
        sources = []
    created = False
    updated = False
    alias_added = False
    email_added = False
    
    # Normalize username
    normalized_username = None
    if username:
        normalized_username, _ = KnownUser.normalize_username(username)
    
    # Find existing user
    user, match_type = KnownUser.find_by_username_sid_alias_or_email(
        username=username,
        sid=sid,
        email=None  # We don't have email from events directly
    )
    
    if user:
        # Update existing user
        updated = True
        
        # Update last_seen to artifact timestamp (not now)
        if last_seen:
            # Handle timezone comparison
            user_ls = user.last_seen
            compare_ls = last_seen
            if compare_ls and hasattr(compare_ls, 'tzinfo') and compare_ls.tzinfo:
                compare_ls = compare_ls.replace(tzinfo=None)
            if user_ls and hasattr(user_ls, 'tzinfo') and user_ls.tzinfo:
                user_ls = user_ls.replace(tzinfo=None)
            if not user_ls or compare_ls > user_ls:
                user.last_seen = last_seen
        
        # Update artifact count
        user.artifacts_with_user = artifact_count
        
        # Update SID if we have it now but didn't before
        if sid and not user.sid:
            user.sid = sid.upper()
            KnownUserAudit.log_change(
                user_id=user.id,
                changed_by=added_by,
                field_name='sid',
                action='update',
                old_value=None,
                new_value=sid.upper()
            )
        
        # Update username if we have it now but didn't before
        if normalized_username and not user.username:
            user.username = normalized_username
            KnownUserAudit.log_change(
                user_id=user.id,
                changed_by=added_by,
                field_name='username',
                action='update',
                old_value=None,
                new_value=normalized_username
            )
        
        # Add all domain\user formats as aliases
        for alias_format in alias_formats:
            if alias_format and alias_format != user.username:
                if user.add_alias(alias_format):
                    alias_added = True
                    KnownUserAudit.log_change(
                        user_id=user.id,
                        changed_by=added_by,
                        field_name='aliases',
                        action='create',
                        new_value=alias_format
                    )
        
        # Add domain\username format as alias if not already in alias_formats
        if domain and normalized_username:
            domain_user = f"{domain}\\{normalized_username}".upper()
            if domain_user not in alias_formats and user.add_alias(domain_user):
                alias_added = True
                KnownUserAudit.log_change(
                    user_id=user.id,
                    changed_by=added_by,
                    field_name='aliases',
                    action='create',
                    new_value=domain_user
                )
        
        # Add data sources
        for source in sources:
            user.add_source(source)
        
        # Link to case
        user.link_to_case(case_id)
        
    else:
        # Create new user
        if not normalized_username and not sid:
            # Need at least username or SID to create a user
            return created, updated, alias_added, email_added
        
        created = True
        
        user = KnownUser(
            username=normalized_username,
            sid=sid.upper() if sid else None,
            artifacts_with_user=artifact_count,
            added_on=datetime.utcnow(),
            added_by=added_by,
            last_seen=last_seen if last_seen else datetime.utcnow(),
            sources=sources  # Track data sources
        )
        db.session.add(user)
        db.session.flush()  # Get the ID
        
        # Log creation
        KnownUserAudit.log_change(
            user_id=user.id,
            changed_by=added_by,
            field_name='user',
            action='create',
            new_value=normalized_username or sid
        )
        
        # Add all domain\user formats as aliases
        for alias_format in alias_formats:
            if alias_format:
                if user.add_alias(alias_format):
                    alias_added = True
                    KnownUserAudit.log_change(
                        user_id=user.id,
                        changed_by=added_by,
                        field_name='aliases',
                        action='create',
                        new_value=alias_format
                    )
        
        # Add domain\username format as alias if not already in alias_formats
        if domain and normalized_username:
            domain_user = f"{domain}\\{normalized_username}".upper()
            if domain_user not in alias_formats and user.add_alias(domain_user):
                alias_added = True
                KnownUserAudit.log_change(
                    user_id=user.id,
                    changed_by=added_by,
                    field_name='aliases',
                    action='create',
                    new_value=domain_user
                )
        
        # Link to case
        user.link_to_case(case_id)
    
    return created, updated, alias_added, email_added


def add_email_to_user(user_id: int, email: str, changed_by: str) -> bool:
    """Add an email address to a user with audit logging"""
    user = KnownUser.query.get(user_id)
    if not user:
        return False
    
    if user.add_email(email):
        KnownUserAudit.log_change(
            user_id=user_id,
            changed_by=changed_by,
            field_name='emails',
            action='create',
            new_value=email
        )
        db.session.commit()
        return True
    return False


def add_alias_to_user(user_id: int, alias: str, changed_by: str) -> bool:
    """Add an alias to a user with audit logging"""
    user = KnownUser.query.get(user_id)
    if not user:
        return False
    
    if user.add_alias(alias):
        KnownUserAudit.log_change(
            user_id=user_id,
            changed_by=changed_by,
            field_name='aliases',
            action='create',
            new_value=alias
        )
        db.session.commit()
        return True
    return False


def update_user_field(user_id: int, field_name: str, new_value, changed_by: str) -> bool:
    """Update a user field with audit logging
    
    Allowed fields: username, sid, email, notes, compromised
    """
    allowed_fields = ['username', 'sid', 'email', 'notes', 'compromised']
    
    if field_name not in allowed_fields:
        return False
    
    user = KnownUser.query.get(user_id)
    if not user:
        return False
    
    old_value = getattr(user, field_name)
    
    # Don't log if value hasn't changed
    if old_value == new_value:
        return True
    
    # Normalize username/sid if provided
    if field_name == 'username' and new_value:
        new_value, _ = KnownUser.normalize_username(new_value)
    elif field_name == 'sid' and new_value:
        new_value = new_value.strip().upper()
    elif field_name == 'email' and new_value:
        new_value = new_value.strip().lower()
    
    setattr(user, field_name, new_value)
    
    KnownUserAudit.log_change(
        user_id=user_id,
        changed_by=changed_by,
        field_name=field_name,
        action='update',
        old_value=old_value,
        new_value=new_value
    )
    
    db.session.commit()
    return True


def get_users_for_case(case_id: int) -> List[Dict]:
    """Get all known users linked to a case"""
    users = []
    
    links = KnownUserCase.query.filter_by(case_id=case_id).all()
    
    for link in links:
        user = KnownUser.query.get(link.user_id)
        if user:
            user_dict = user.to_dict()
            user_dict['first_seen_in_case'] = link.first_seen_in_case.isoformat() if link.first_seen_in_case else None
            users.append(user_dict)
    
    return users


def get_user_audit_history(user_id: int) -> List[Dict]:
    """Get audit history for a user"""
    audits = KnownUserAudit.query.filter_by(
        user_id=user_id
    ).order_by(KnownUserAudit.changed_on.desc()).all()
    
    return [audit.to_dict() for audit in audits]
