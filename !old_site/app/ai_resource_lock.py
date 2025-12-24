"""
AI Resource Lock Module
Prevents concurrent AI operations (report generation + training)
"""

import logging
from datetime import datetime
from models import SystemSettings
from main import db

logger = logging.getLogger(__name__)


def acquire_ai_lock(operation_type, user_id, operation_details=""):
    """
    Try to acquire AI resource lock
    
    Args:
        operation_type: 'training' or 'report_generation'
        user_id: ID of user requesting the operation
        operation_details: Optional description (e.g., "Case #5", "OpenCTI training")
    
    Returns:
        (success: bool, message: str)
    """
    try:
        # Check if AI is already locked
        lock = db.session.query(SystemSettings).filter_by(setting_key='ai_resource_lock').first()
        
        if lock and lock.setting_value != 'unlocked':
            # AI is busy - parse lock data
            try:
                import json
                lock_data = json.loads(lock.setting_value)
                
                locked_by_user_id = lock_data.get('user_id')
                locked_operation = lock_data.get('operation')
                locked_details = lock_data.get('details', '')
                locked_at = lock_data.get('started_at', 'Unknown time')
                
                # Get username
                from models import User
                locked_by_user = db.session.get(User, locked_by_user_id)
                username = locked_by_user.username if locked_by_user else f"User #{locked_by_user_id}"
                
                # Calculate elapsed time
                try:
                    start_time = datetime.fromisoformat(locked_at.replace('Z', '+00:00'))
                    elapsed = datetime.now() - start_time
                    elapsed_str = f"{int(elapsed.total_seconds() / 60)} minutes ago"
                except:
                    elapsed_str = "recently"
                
                message = (
                    f"AI resources are currently in use.\n\n"
                    f"Operation: {locked_operation}\n"
                    f"Details: {locked_details}\n"
                    f"Started by: {username}\n"
                    f"Started: {elapsed_str}\n\n"
                    f"Please wait for the current operation to complete."
                )
                
                return (False, message)
                
            except Exception as e:
                logger.error(f"[AI Lock] Error parsing lock data: {e}")
                return (False, "AI resources are currently in use. Please try again later.")
        
        # AI is free - acquire lock
        import json
        from models import User
        user = db.session.get(User, user_id)
        username = user.username if user else f"User #{user_id}"
        
        lock_data = {
            'operation': operation_type,
            'details': operation_details,
            'user_id': user_id,
            'username': username,
            'started_at': datetime.utcnow().isoformat() + 'Z'
        }
        
        if lock:
            lock.setting_value = json.dumps(lock_data)
        else:
            lock = SystemSettings(
                setting_key='ai_resource_lock',
                setting_value=json.dumps(lock_data),
                description='AI resource lock to prevent concurrent operations'
            )
            db.session.add(lock)
        
        db.session.commit()
        
        logger.info(f"[AI Lock] Acquired by {username} for {operation_type}: {operation_details}")
        return (True, "Lock acquired")
        
    except Exception as e:
        logger.error(f"[AI Lock] Error acquiring lock: {e}")
        db.session.rollback()
        return (False, f"Error acquiring AI lock: {str(e)}")


def release_ai_lock():
    """Release AI resource lock"""
    try:
        lock = db.session.query(SystemSettings).filter_by(setting_key='ai_resource_lock').first()
        
        if lock:
            lock.setting_value = 'unlocked'
            db.session.commit()
            logger.info("[AI Lock] Released")
            return True
        
        return True
        
    except Exception as e:
        logger.error(f"[AI Lock] Error releasing lock: {e}")
        db.session.rollback()
        return False


def check_ai_lock_status():
    """
    Check current AI lock status
    
    Returns:
        (is_locked: bool, lock_data: dict or None)
    """
    try:
        lock = db.session.query(SystemSettings).filter_by(setting_key='ai_resource_lock').first()
        
        if not lock or lock.setting_value == 'unlocked':
            return (False, None)
        
        import json
        lock_data = json.loads(lock.setting_value)
        
        # Get username
        from models import User
        user_id = lock_data.get('user_id')
        user = db.session.get(User, user_id)
        lock_data['username'] = user.username if user else f"User #{user_id}"
        
        return (True, lock_data)
        
    except Exception as e:
        logger.error(f"[AI Lock] Error checking lock status: {e}")
        return (False, None)


def force_release_ai_lock():
    """
    Force release AI lock (admin only, for when tasks crash)
    
    Returns:
        bool: Success
    """
    try:
        lock = db.session.query(SystemSettings).filter_by(setting_key='ai_resource_lock').first()
        
        if lock:
            old_value = lock.setting_value
            lock.setting_value = 'unlocked'
            db.session.commit()
            logger.warning(f"[AI Lock] Force released by admin. Previous value: {old_value}")
            return True
        
        return True
        
    except Exception as e:
        logger.error(f"[AI Lock] Error force releasing lock: {e}")
        db.session.rollback()
        return False

