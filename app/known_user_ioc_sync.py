"""
Known User ↔ IOC Integration Module
Version: 1.24.0
Date: November 23, 2025

PURPOSE:
Automatically synchronize Known Users and IOCs to maintain consistency:

USERNAME SYNC (v1.21.0):
- When a Known User is marked as compromised → Create username IOC (active)
- When a username IOC is created → Create Known User entry (if doesn't exist)

USER SID SYNC (v1.24.0):
- When a Known User is marked as compromised → Create user_sid IOC (inactive, for reference)
- When a user_sid IOC is created → Create Known User with SID as username (if SID not found)
- CSV upload logic: Match SIDs to update usernames, merge missing fields

This ensures analysts don't have to manually manage both systems separately.
"""

from models import KnownUser, IOC
from main import db
import logging

logger = logging.getLogger('app')


def sync_user_to_ioc(case_id, username, user_id, current_user_id, description=None, user_sid=None):
    """
    Create USERNAME IOC when user is marked as compromised (v1.21.0)
    Also creates USER_SID IOC if SID is available (v1.24.0)
    
    Args:
        case_id: Case ID
        username: Username to create IOC for
        user_id: KnownUser ID (for logging/reference)
        current_user_id: CaseScope user performing the action
        description: Optional description for the IOC
        user_sid: Optional User SID (v1.24.0) - if provided, creates inactive user_sid IOC
    
    Returns:
        (success: bool, ioc_id: int or None, message: str)
    """
    try:
        # Check if IOC already exists
        existing_ioc = IOC.query.filter_by(
            case_id=case_id,
            ioc_type='username',
            ioc_value=username
        ).first()
        
        if existing_ioc:
            logger.info(f"[KNOWN USER → IOC] IOC already exists for username '{username}' (IOC ID: {existing_ioc.id})")
            return (True, existing_ioc.id, 'IOC already exists')
        
        # Create new IOC
        ioc = IOC(
            case_id=case_id,
            ioc_type='username',
            ioc_value=username,
            description=description or f'Auto-created from compromised Known User (ID: {user_id})',
            threat_level='high',  # Compromised users are high threat
            is_active=True,
            created_by=current_user_id
        )
        
        db.session.add(ioc)
        db.session.flush()  # Get IOC ID before commit
        
        username_ioc_id = ioc.id
        logger.info(f"[KNOWN USER → IOC] Created username IOC (ID: {username_ioc_id}) for compromised user '{username}' (Known User ID: {user_id})")
        
        # v1.24.0: If user_sid provided, create INACTIVE user_sid IOC for reference
        sid_ioc_id = None
        if user_sid:
            sid_ioc_created = sync_user_sid_to_ioc(
                case_id=case_id,
                user_sid=user_sid,
                username=username,
                user_id=user_id,
                current_user_id=current_user_id
            )
            if sid_ioc_created[0]:
                sid_ioc_id = sid_ioc_created[1]
        
        db.session.commit()
        
        message = 'Username IOC created'
        if sid_ioc_id:
            message += f' + User SID IOC created (inactive)'
        
        return (True, username_ioc_id, message)
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"[KNOWN USER → IOC] Failed to create IOC for username '{username}': {e}")
        return (False, None, str(e))


def sync_ioc_to_user(case_id, username, ioc_id, current_user_id, threat_level='medium'):
    """
    Create Known User when username IOC is added
    
    Args:
        case_id: Case ID
        username: Username from IOC
        ioc_id: IOC ID (for logging/reference)
        current_user_id: CaseScope user performing the action
        threat_level: IOC threat level (used to set compromised status)
    
    Returns:
        (success: bool, user_id: int or None, message: str)
    """
    try:
        # Check if Known User already exists (case-insensitive)
        existing_user = KnownUser.query.filter(
            KnownUser.case_id == case_id,
            db.func.lower(KnownUser.username) == username.lower()
        ).first()
        
        if existing_user:
            # User exists - update compromised status if needed
            # v1.21.1: Username IOCs should ALWAYS mark user as compromised (regardless of threat level)
            if not existing_user.compromised:
                existing_user.compromised = True
                db.session.commit()
                logger.info(f"[IOC → KNOWN USER] Updated user '{username}' (ID: {existing_user.id}) to compromised (from IOC ID: {ioc_id})")
                return (True, existing_user.id, 'Known User updated to compromised')
            else:
                logger.info(f"[IOC → KNOWN USER] Known User already exists for username '{username}' (ID: {existing_user.id})")
                return (True, existing_user.id, 'Known User already exists')
        
        # Create new Known User
        # Type is 'unknown' since we don't know if domain/local/invalid from just the IOC
        # User can manually update the type later
        known_user = KnownUser(
            case_id=case_id,
            username=username,
            user_type='unknown',  # v1.21.0: Don't assume domain/local without evidence
            user_sid=None,  # No SID from IOC alone
            compromised=True,  # v1.21.1: Username IOCs ALWAYS indicate compromise
            active=True,  # Assume active unless evidence otherwise
            added_method='ioc_sync',  # v1.21.0: Track that this came from IOC
            added_by=current_user_id
        )
        
        db.session.add(known_user)
        db.session.commit()
        
        logger.info(f"[IOC → KNOWN USER] Created Known User (ID: {known_user.id}) for username IOC '{username}' (IOC ID: {ioc_id})")
        return (True, known_user.id, 'Known User created successfully')
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"[IOC → KNOWN USER] Failed to create Known User for username '{username}': {e}")
        return (False, None, str(e))


def unsync_user_from_ioc(case_id, username, user_id):
    """
    Remove IOC when user is unmarked as compromised
    
    Args:
        case_id: Case ID
        username: Username to remove IOC for
        user_id: KnownUser ID (for logging)
    
    Returns:
        (success: bool, message: str)
    
    Note: This is OPTIONAL behavior. Some orgs may want to keep the IOC even if user 
    is unmarked as compromised. This function is provided but not automatically called.
    """
    try:
        ioc = IOC.query.filter_by(
            case_id=case_id,
            ioc_type='username',
            ioc_value=username
        ).first()
        
        if not ioc:
            return (True, 'No IOC found to remove')
        
        # Check if IOC was auto-created by this system
        if 'Auto-created from compromised Known User' in (ioc.description or ''):
            db.session.delete(ioc)
            db.session.commit()
            logger.info(f"[KNOWN USER ← IOC] Removed auto-created IOC (ID: {ioc.id}) for user '{username}' (Known User ID: {user_id})")
            return (True, 'IOC removed successfully')
        else:
            # IOC was manually created, don't auto-delete it
            logger.info(f"[KNOWN USER ← IOC] IOC (ID: {ioc.id}) for '{username}' was manually created, not auto-removing")
            return (True, 'IOC was manually created, preserved')
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"[KNOWN USER ← IOC] Failed to remove IOC for username '{username}': {e}")
        return (False, str(e))


def get_sync_status(case_id, username):
    """
    Get synchronization status between Known User and IOC
    
    Returns:
        {
            'has_known_user': bool,
            'has_ioc': bool,
            'known_user_id': int or None,
            'ioc_id': int or None,
            'known_user_compromised': bool or None,
            'ioc_active': bool or None,
            'in_sync': bool
        }
    """
    known_user = KnownUser.query.filter(
        KnownUser.case_id == case_id,
        db.func.lower(KnownUser.username) == username.lower()
    ).first()
    
    ioc = IOC.query.filter_by(
        case_id=case_id,
        ioc_type='username',
        ioc_value=username
    ).first()
    
    has_user = known_user is not None
    has_ioc = ioc is not None
    
    # "In sync" means: if user is compromised, IOC exists; if IOC exists, user is compromised
    in_sync = True
    if has_user and known_user.compromised and not has_ioc:
        in_sync = False  # Compromised user but no IOC
    if has_ioc and ioc.is_active and (not has_user or not known_user.compromised):
        in_sync = False  # Active IOC but user not marked compromised
    
    return {
        'has_known_user': has_user,
        'has_ioc': has_ioc,
        'known_user_id': known_user.id if has_user else None,
        'ioc_id': ioc.id if has_ioc else None,
        'known_user_compromised': known_user.compromised if has_user else None,
        'ioc_active': ioc.is_active if has_ioc else None,
        'in_sync': in_sync
    }


# ============================================================================
# USER SID SYNCHRONIZATION (v1.24.0)
# ============================================================================

def sync_user_sid_to_ioc(case_id, user_sid, username, user_id, current_user_id):
    """
    Create INACTIVE user_sid IOC when user is marked as compromised (v1.24.0)
    
    User SID IOCs are created as INACTIVE for reference purposes only.
    They are not actively searched/hunted but provide forensic context.
    
    Args:
        case_id: Case ID
        user_sid: User SID to create IOC for
        username: Username associated with this SID
        user_id: KnownUser ID (for logging/reference)
        current_user_id: CaseScope user performing the action
    
    Returns:
        (success: bool, ioc_id: int or None, message: str)
    """
    try:
        # Check if user_sid IOC already exists
        existing_ioc = IOC.query.filter_by(
            case_id=case_id,
            ioc_type='user_sid',
            ioc_value=user_sid
        ).first()
        
        if existing_ioc:
            logger.info(f"[KNOWN USER → SID IOC] User SID IOC already exists for '{user_sid}' (IOC ID: {existing_ioc.id})")
            return (True, existing_ioc.id, 'User SID IOC already exists')
        
        # Create INACTIVE user_sid IOC
        ioc = IOC(
            case_id=case_id,
            ioc_type='user_sid',
            ioc_value=user_sid,
            description=f'SID for username: {username} (auto-created from Known User ID: {user_id})',
            threat_level='high',  # Compromised user SID
            is_active=False,  # INACTIVE - for reference only, not actively searched
            created_by=current_user_id
        )
        
        db.session.add(ioc)
        # Don't commit here - let caller commit
        
        logger.info(f"[KNOWN USER → SID IOC] Created INACTIVE user_sid IOC for '{user_sid}' (username: {username}, Known User ID: {user_id})")
        return (True, ioc.id, 'User SID IOC created (inactive)')
        
    except Exception as e:
        logger.error(f"[KNOWN USER → SID IOC] Failed to create user_sid IOC for '{user_sid}': {e}")
        return (False, None, str(e))


def sync_sid_ioc_to_user(case_id, user_sid, ioc_id, current_user_id):
    """
    Create Known User when user_sid IOC is added (v1.24.0)
    
    When a user_sid IOC is created:
    1. Check if a Known User with this SID already exists
    2. If not found, create new Known User with SID as username
    3. User can later update the username via CSV upload or manual edit
    
    Args:
        case_id: Case ID
        user_sid: User SID from IOC
        ioc_id: IOC ID (for logging/reference)
        current_user_id: CaseScope user performing the action
    
    Returns:
        (success: bool, user_id: int or None, message: str)
    """
    try:
        # Check if Known User with this SID already exists
        existing_user_by_sid = KnownUser.query.filter(
            KnownUser.case_id == case_id,
            KnownUser.user_sid == user_sid
        ).first()
        
        if existing_user_by_sid:
            logger.info(f"[SID IOC → KNOWN USER] Known User already exists with SID '{user_sid}' (ID: {existing_user_by_sid.id}, username: {existing_user_by_sid.username})")
            return (True, existing_user_by_sid.id, 'Known User with this SID already exists')
        
        # Check if Known User with SID as username exists (case-insensitive)
        # This handles the case where the SID was used as a placeholder username
        existing_user_by_name = KnownUser.query.filter(
            KnownUser.case_id == case_id,
            db.func.lower(KnownUser.username) == user_sid.lower()
        ).first()
        
        if existing_user_by_name:
            # Update the user_sid field if it's missing
            if not existing_user_by_name.user_sid:
                existing_user_by_name.user_sid = user_sid
                db.session.commit()
                logger.info(f"[SID IOC → KNOWN USER] Updated Known User (ID: {existing_user_by_name.id}) with SID '{user_sid}'")
            return (True, existing_user_by_name.id, 'Known User updated with SID')
        
        # Create new Known User with SID as username (placeholder until real username is known)
        known_user = KnownUser(
            case_id=case_id,
            username=user_sid,  # Use SID as username placeholder
            user_type='unknown',  # Don't assume type
            user_sid=user_sid,  # Store the actual SID
            compromised=True,  # User SID IOC indicates compromise
            active=True,  # Assume active
            added_method='ioc_sync',  # Track that this came from IOC
            added_by=current_user_id
        )
        
        db.session.add(known_user)
        db.session.commit()
        
        logger.info(f"[SID IOC → KNOWN USER] Created Known User (ID: {known_user.id}) for user_sid IOC '{user_sid}' (IOC ID: {ioc_id})")
        return (True, known_user.id, 'Known User created with SID as username')
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"[SID IOC → KNOWN USER] Failed to create Known User for SID '{user_sid}': {e}")
        return (False, None, str(e))


def update_known_user_from_csv_by_sid(case_id, username, user_sid, user_type=None, compromised=None, active=None):
    """
    Update Known User when CSV contains matching SID (v1.24.0)
    
    CSV Upload Logic:
    1. If username exists → Update missing fields only
    2. If SID exists with SID-as-username → Update username field and merge other fields
    3. If neither exists → Create new user
    
    Args:
        case_id: Case ID
        username: Username from CSV
        user_sid: User SID from CSV
        user_type: User type from CSV (optional)
        compromised: Compromised status from CSV (optional)
        active: Active status from CSV (optional)
    
    Returns:
        (action: str, user_id: int, message: str)
        action: 'created', 'updated_by_username', 'updated_by_sid', 'no_change'
    """
    try:
        # Strategy 1: Try to find by username (case-insensitive)
        user_by_name = KnownUser.query.filter(
            KnownUser.case_id == case_id,
            db.func.lower(KnownUser.username) == username.lower()
        ).first()
        
        if user_by_name:
            # Username exists - update missing fields only
            updated_fields = []
            
            if user_sid and not user_by_name.user_sid:
                user_by_name.user_sid = user_sid
                updated_fields.append('user_sid')
            
            if user_type and user_by_name.user_type == 'unknown':
                user_by_name.user_type = user_type
                updated_fields.append('user_type')
            
            # Note: Don't update compromised status from CSV (preserve existing state)
            # Note: Don't update active status from CSV (preserve existing state)
            
            if updated_fields:
                db.session.commit()
                logger.info(f"[CSV UPDATE] Updated Known User (ID: {user_by_name.id}) '{username}' - fields: {', '.join(updated_fields)}")
                return ('updated_by_username', user_by_name.id, f'Updated missing fields: {", ".join(updated_fields)}')
            else:
                return ('no_change', user_by_name.id, 'No missing fields to update')
        
        # Strategy 2: Try to find by SID
        if user_sid:
            user_by_sid = KnownUser.query.filter(
                KnownUser.case_id == case_id,
                KnownUser.user_sid == user_sid
            ).first()
            
            if user_by_sid:
                # SID exists - check if username is the SID itself (placeholder)
                updated_fields = []
                
                if user_by_sid.username == user_sid:
                    # Username is SID placeholder - update with real username
                    user_by_sid.username = username
                    updated_fields.append('username (from SID placeholder)')
                
                if user_type and user_by_sid.user_type == 'unknown':
                    user_by_sid.user_type = user_type
                    updated_fields.append('user_type')
                
                if updated_fields:
                    db.session.commit()
                    logger.info(f"[CSV UPDATE] Updated Known User (ID: {user_by_sid.id}) by SID '{user_sid}' - fields: {', '.join(updated_fields)}")
                    return ('updated_by_sid', user_by_sid.id, f'Updated by SID match: {", ".join(updated_fields)}')
                else:
                    return ('no_change', user_by_sid.id, 'SID matched but no fields to update')
        
        # Strategy 3: User doesn't exist - caller should create it
        return ('not_found', None, 'User not found, should create new entry')
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"[CSV UPDATE] Failed to update Known User for '{username}' (SID: {user_sid}): {e}")
        return ('error', None, str(e))

