"""Known Users Discovery Module

Modular function to discover and populate known users from artifacts.
Can be called from:
1. File ingestion process (after files are ingested)
2. UI button click ("Find in Artifacts")
"""
import logging
import redis
import json
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

# Redis client for progress tracking
_redis_client = None

# Built-in/System accounts to exclude from discovery
SYSTEM_ACCOUNTS = {
    'SYSTEM', 'LOCAL SERVICE', 'NETWORK SERVICE', 'ANONYMOUS LOGON',
    'NT AUTHORITY', 'BUILTIN', 'WINDOW MANAGER', 'FONT DRIVER HOST',
    'DWMWINDOWHOST', '-', '', 'N/A', 'NA', 'NONE', 'NULL', 'UNKNOWN',
    'IUSR', 'IWAM', 'ASPNET', 'DEFAULTACCOUNT', 'CONTEXT', 'CONTEXT:',
    'GUEST', 'DEFAULTUSER0', 'WDAGUTILITYACCOUNT',
}

# Patterns for system account prefixes (will match UMFD-0 through UMFD-99, DWM-1 through DWM-99, etc.)
SYSTEM_ACCOUNT_PREFIXES = ('UMFD-', 'DWM-', 'WINRM ', 'FONT DRIVER HOST\\')

# System SIDs to exclude (well-known SIDs)
SYSTEM_SIDS = {
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

# SID prefixes to exclude
SYSTEM_SID_PREFIXES = (
    'S-1-5-90-',   # Window Manager (DWM)
    'S-1-5-96-',   # Font Driver Host (UMFD)
    'S-1-5-80-',   # NT Service accounts
    'S-1-5-82-',   # IIS AppPool accounts
    'S-1-5-83-',   # Virtual Machine accounts
    'S-1-5-32-',   # Builtin domain
)


def get_redis():
    """Get Redis client for progress tracking"""
    global _redis_client
    if _redis_client is None:
        _redis_client = redis.Redis(
            host=Config.REDIS_HOST,
            port=Config.REDIS_PORT,
            db=Config.REDIS_DB,
            decode_responses=True
        )
    return _redis_client


def init_user_discovery_progress(case_uuid: str, total: int):
    """Initialize discovery progress in Redis"""
    r = get_redis()
    key = f"user_discovery:{case_uuid}"
    r.hset(key, mapping={
        'status': 'running',
        'total': total,
        'processed': 0,
        'created': 0,
        'updated': 0,
        'current_user': ''
    })
    r.expire(key, 3600)  # 1 hour TTL


def update_user_discovery_progress(case_uuid: str, processed: int, created: int, updated: int, current: str = ''):
    """Update discovery progress in Redis"""
    r = get_redis()
    key = f"user_discovery:{case_uuid}"
    r.hset(key, mapping={
        'processed': processed,
        'created': created,
        'updated': updated,
        'current_user': current
    })


def complete_user_discovery_progress(case_uuid: str, results: dict):
    """Mark discovery as complete"""
    r = get_redis()
    key = f"user_discovery:{case_uuid}"
    r.hset(key, mapping={
        'status': 'complete',
        'processed': results.get('users_processed', 0),
        'created': results.get('users_created', 0),
        'updated': results.get('users_updated', 0),
        'current_user': ''
    })
    r.expire(key, 300)  # Keep for 5 minutes after completion


def get_user_discovery_progress(case_uuid: str) -> Optional[dict]:
    """Get current discovery progress"""
    r = get_redis()
    key = f"user_discovery:{case_uuid}"
    data = r.hgetall(key)
    if data:
        return {
            'status': data.get('status', 'unknown'),
            'total': int(data.get('total', 0)),
            'processed': int(data.get('processed', 0)),
            'created': int(data.get('created', 0)),
            'updated': int(data.get('updated', 0)),
            'current_user': data.get('current_user', '')
        }
    return None


def is_system_account(username: str, sid: str = None) -> bool:
    """Check if account is a system/built-in account to exclude"""
    if not username and not sid:
        return True
    
    # Check username against system accounts
    if username:
        username_upper = username.strip().upper()
        
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
            if username_upper in SYSTEM_SIDS:
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
        if sid_upper in SYSTEM_SIDS:
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
                    last_seen=stats['last_seen']
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
                
                # Update progress every 10 users or on last one
                if track_progress and (processed % 10 == 0 or processed == total_users):
                    update_user_discovery_progress(
                        case_uuid, processed,
                        results['users_created'],
                        results['users_updated'],
                        stats.get('username', stats.get('sid', ''))
                    )
                    
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
                        last_seen=stats['last_seen']
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
                processed += 1
        
        # Commit all changes
        db.session.commit()
        
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
    
    Returns dict: {key: {'username': X, 'sid': Y, 'domain': Z, 'count': N, 'last_seen': datetime}}
    """
    from utils.clickhouse import get_client
    
    user_stats = {}
    
    try:
        client = get_client()
        
        # Query for unique username/SID combinations with counts
        result = client.query(
            """SELECT 
                username, 
                sid, 
                domain,
                count() as cnt, 
                max(timestamp) as last_ts
               FROM events 
               WHERE case_id = {case_id:UInt32} 
                 AND (username != '' OR sid != '')
               GROUP BY username, sid, domain
               LIMIT 50000""",
            parameters={'case_id': case_id}
        )
        
        for row in result.result_rows:
            username = row[0].strip() if row[0] else None
            sid = row[1].strip() if row[1] else None
            domain = row[2].strip() if row[2] else None
            count = row[3]
            last_ts = row[4]
            
            # If username looks like a SID (S-1-5-...), treat it as the SID
            if username and username.upper().startswith('S-1-') and not sid:
                sid = username.upper()
                username = None
            
            # Skip system accounts
            if is_system_account(username, sid):
                continue
            
            # Create unique key for dedup within this query
            # Use SID as primary key if available, otherwise username
            if sid:
                key = f"SID:{sid.upper()}"
            elif username:
                normalized, _ = KnownUser.normalize_username(username)
                if not normalized:
                    continue
                key = f"USER:{normalized}"
            else:
                continue
            
            # Merge stats for same key
            if key in user_stats:
                user_stats[key]['count'] += count
                if last_ts and (not user_stats[key]['last_seen'] or last_ts > user_stats[key]['last_seen']):
                    user_stats[key]['last_seen'] = last_ts
                # Update username if we have it now but didn't before
                if username and not user_stats[key].get('username'):
                    user_stats[key]['username'] = username
                # Update domain if we have it now but didn't before
                if domain and not user_stats[key].get('domain'):
                    user_stats[key]['domain'] = domain
            else:
                user_stats[key] = {
                    'username': username,
                    'sid': sid,
                    'domain': domain,
                    'count': count,
                    'last_seen': last_ts
                }
                
    except Exception as e:
        logger.warning(f"Error querying ClickHouse for users: {e}")
    
    return user_stats


def _process_user(username: str, sid: str, domain: str, case_id: int, added_by: str,
                  artifact_count: int = 1, last_seen: datetime = None) -> Tuple[bool, bool, bool, bool]:
    """Process a single user through deduplication logic
    
    Matching logic:
    1. Check if username already exists
    2. Check if SID matches another known user
    3. Check if username exists in aliases
    4. Check if email prefix matches username or alias
    5. If no match, create new user
    
    Args:
        username: The username to process
        sid: Windows SID if available
        domain: Domain if available
        case_id: Case ID for linking
        added_by: User performing discovery
        artifact_count: Number of artifacts referencing this user
        last_seen: Timestamp of most recent artifact with this user
    
    Returns: (created, updated, alias_added, email_added)
    """
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
        
        # Add original username format as alias if different
        if username and normalized_username and normalized_username != user.username:
            if user.add_alias(normalized_username):
                alias_added = True
                KnownUserAudit.log_change(
                    user_id=user.id,
                    changed_by=added_by,
                    field_name='aliases',
                    action='create',
                    new_value=normalized_username
                )
        
        # Add domain\username format as alias
        if domain and normalized_username:
            domain_user = f"{domain}\\{normalized_username}"
            if user.add_alias(domain_user):
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
            last_seen=last_seen if last_seen else datetime.utcnow()
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
        
        # Add domain\username format as alias
        if domain and normalized_username:
            domain_user = f"{domain}\\{normalized_username}"
            if user.add_alias(domain_user):
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
