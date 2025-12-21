"""
Case Lock Manager (v1.25.0)
Manages case locking to prevent multiple users from working on the same case simultaneously
"""

from models import CaseLock, Case, User
from main import db
from datetime import datetime, timedelta
from flask import session
import logging

logger = logging.getLogger('app')

# Configuration
LOCK_TIMEOUT_HOURS = 4  # Release locks after 4 hours of inactivity
HEARTBEAT_INTERVAL_SECONDS = 60  # Update activity every 60 seconds


def acquire_case_lock(case_id, user_id, session_id, force=False):
    """
    Attempt to acquire a lock on a case
    
    Args:
        case_id: Case ID to lock
        user_id: User requesting the lock
        session_id: Flask session ID
        force: If True, forcibly acquire lock even if already locked (admin override)
    
    Returns:
        (success: bool, lock: CaseLock or None, message: str, locked_by: User or None)
    """
    try:
        # Check if case exists
        case = db.session.get(Case, case_id)
        if not case:
            return (False, None, 'Case not found', None)
        
        # Check for existing lock
        existing_lock = CaseLock.query.filter_by(case_id=case_id).first()
        
        if existing_lock:
            # Check if lock is stale
            if existing_lock.is_stale(LOCK_TIMEOUT_HOURS):
                logger.info(f"[CASE LOCK] Releasing stale lock on case {case_id} (user {existing_lock.user_id}, inactive for {LOCK_TIMEOUT_HOURS}+ hours)")
                db.session.delete(existing_lock)
                db.session.commit()
                existing_lock = None
            # Check if same user/session
            elif existing_lock.user_id == user_id and existing_lock.session_id == session_id:
                # Same user, same session - just update activity
                existing_lock.update_activity()
                db.session.commit()
                logger.info(f"[CASE LOCK] Refreshed existing lock on case {case_id} for user {user_id}")
                return (True, existing_lock, 'Lock refreshed', None)
            # Check if same user, different session
            elif existing_lock.user_id == user_id:
                # Same user, different session (opened in new tab/browser)
                # Transfer lock to new session
                logger.info(f"[CASE LOCK] Transferring lock on case {case_id} to new session for user {user_id}")
                existing_lock.session_id = session_id
                existing_lock.update_activity()
                db.session.commit()
                return (True, existing_lock, 'Lock transferred to this session', None)
            # Different user has lock
            elif not force:
                locked_by = db.session.get(User, existing_lock.user_id)
                logger.warning(f"[CASE LOCK] Case {case_id} is locked by user {existing_lock.user_id} (requested by user {user_id})")
                return (False, None, f'Case is currently being worked on by {locked_by.username if locked_by else "another user"}', locked_by)
            # Force override (admin)
            else:
                logger.warning(f"[CASE LOCK] Force acquiring lock on case {case_id} for user {user_id} (was locked by user {existing_lock.user_id})")
                db.session.delete(existing_lock)
                db.session.commit()
                existing_lock = None
        
        # Create new lock
        if not existing_lock:
            lock = CaseLock(
                case_id=case_id,
                user_id=user_id,
                session_id=session_id,
                locked_at=datetime.utcnow(),
                last_activity=datetime.utcnow()
            )
            db.session.add(lock)
            db.session.commit()
            logger.info(f"[CASE LOCK] Acquired lock on case {case_id} for user {user_id}")
            return (True, lock, 'Lock acquired', None)
    
    except Exception as e:
        db.session.rollback()
        logger.error(f"[CASE LOCK] Error acquiring lock on case {case_id}: {e}")
        return (False, None, f'Error acquiring lock: {str(e)}', None)


def release_case_lock(case_id, user_id=None, session_id=None):
    """
    Release a lock on a case
    
    Args:
        case_id: Case ID to unlock
        user_id: User releasing the lock (optional, for validation)
        session_id: Session ID (optional, for validation)
    
    Returns:
        (success: bool, message: str)
    """
    try:
        lock = CaseLock.query.filter_by(case_id=case_id).first()
        
        if not lock:
            return (True, 'No lock to release')
        
        # Validate ownership if user_id provided
        if user_id and lock.user_id != user_id:
            return (False, 'Lock belongs to another user')
        
        # Validate session if session_id provided
        if session_id and lock.session_id != session_id:
            # Allow release even if session differs (user might have logged in again)
            logger.warning(f"[CASE LOCK] Releasing lock with mismatched session (case {case_id}, user {user_id})")
        
        db.session.delete(lock)
        db.session.commit()
        logger.info(f"[CASE LOCK] Released lock on case {case_id} (user {lock.user_id})")
        return (True, 'Lock released')
    
    except Exception as e:
        db.session.rollback()
        logger.error(f"[CASE LOCK] Error releasing lock on case {case_id}: {e}")
        return (False, f'Error releasing lock: {str(e)}')


def update_lock_activity(case_id, user_id, session_id):
    """
    Update last activity timestamp for a lock (heartbeat)
    
    Args:
        case_id: Case ID
        user_id: User ID (for validation)
        session_id: Session ID (for validation)
    
    Returns:
        (success: bool, message: str)
    """
    try:
        lock = CaseLock.query.filter_by(case_id=case_id, user_id=user_id, session_id=session_id).first()
        
        if not lock:
            # Lock doesn't exist or doesn't belong to this user/session
            return (False, 'Lock not found or invalid')
        
        lock.update_activity()
        db.session.commit()
        return (True, 'Activity updated')
    
    except Exception as e:
        db.session.rollback()
        logger.error(f"[CASE LOCK] Error updating activity for case {case_id}: {e}")
        return (False, f'Error updating activity: {str(e)}')


def get_case_lock_info(case_id):
    """
    Get information about who has a case locked
    
    Args:
        case_id: Case ID
    
    Returns:
        {
            'is_locked': bool,
            'locked_by_user_id': int or None,
            'locked_by_username': str or None,
            'locked_at': datetime or None,
            'last_activity': datetime or None,
            'is_stale': bool,
            'can_force_unlock': bool  # True if lock is stale
        }
    """
    lock = CaseLock.query.filter_by(case_id=case_id).first()
    
    if not lock:
        return {
            'is_locked': False,
            'locked_by_user_id': None,
            'locked_by_username': None,
            'locked_at': None,
            'last_activity': None,
            'is_stale': False,
            'can_force_unlock': False
        }
    
    user = db.session.get(User, lock.user_id)
    is_stale = lock.is_stale(LOCK_TIMEOUT_HOURS)
    
    return {
        'is_locked': True,
        'locked_by_user_id': lock.user_id,
        'locked_by_username': user.username if user else 'Unknown',
        'locked_at': lock.locked_at,
        'last_activity': lock.last_activity,
        'is_stale': is_stale,
        'can_force_unlock': is_stale
    }


def cleanup_stale_locks():
    """
    Remove all stale locks (locks with no activity for LOCK_TIMEOUT_HOURS)
    Should be run periodically (e.g., hourly cron job or background task)
    
    Returns:
        (count: int, message: str)
    """
    try:
        cutoff_time = datetime.utcnow() - timedelta(hours=LOCK_TIMEOUT_HOURS)
        stale_locks = CaseLock.query.filter(CaseLock.last_activity < cutoff_time).all()
        
        count = len(stale_locks)
        if count > 0:
            for lock in stale_locks:
                logger.info(f"[CASE LOCK CLEANUP] Removing stale lock on case {lock.case_id} (user {lock.user_id}, last activity: {lock.last_activity})")
                db.session.delete(lock)
            
            db.session.commit()
            return (count, f'Removed {count} stale lock(s)')
        else:
            return (0, 'No stale locks found')
    
    except Exception as e:
        db.session.rollback()
        logger.error(f"[CASE LOCK CLEANUP] Error cleaning up stale locks: {e}")
        return (0, f'Error during cleanup: {str(e)}')


def release_all_user_locks(user_id):
    """
    Release all locks held by a specific user (e.g., on logout)
    
    Args:
        user_id: User ID
    
    Returns:
        (count: int, message: str)
    """
    try:
        user_locks = CaseLock.query.filter_by(user_id=user_id).all()
        count = len(user_locks)
        
        if count > 0:
            for lock in user_locks:
                logger.info(f"[CASE LOCK] Releasing lock on case {lock.case_id} for user {user_id} (logout/cleanup)")
                db.session.delete(lock)
            
            db.session.commit()
            return (count, f'Released {count} lock(s)')
        else:
            return (0, 'No locks to release')
    
    except Exception as e:
        db.session.rollback()
        logger.error(f"[CASE LOCK] Error releasing locks for user {user_id}: {e}")
        return (0, f'Error releasing locks: {str(e)}')


def release_session_locks(session_id):
    """
    Release all locks held by a specific session (e.g., on session expiry)
    
    Args:
        session_id: Flask session ID
    
    Returns:
        (count: int, message: str)
    """
    try:
        session_locks = CaseLock.query.filter_by(session_id=session_id).all()
        count = len(session_locks)
        
        if count > 0:
            for lock in session_locks:
                logger.info(f"[CASE LOCK] Releasing lock on case {lock.case_id} for session {session_id} (session expiry)")
                db.session.delete(lock)
            
            db.session.commit()
            return (count, f'Released {count} lock(s)')
        else:
            return (0, 'No locks to release')
    
    except Exception as e:
        db.session.rollback()
        logger.error(f"[CASE LOCK] Error releasing locks for session {session_id}: {e}")
        return (0, f'Error releasing locks: {str(e)}')

