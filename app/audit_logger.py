"""
Audit Logger - Reusable module for logging security-sensitive actions
Simple to use: just import and call log_action()
"""

from datetime import datetime
from flask import request
from flask_login import current_user
import json
import logging

logger = logging.getLogger(__name__)


def log_action(action, resource_type=None, resource_id=None, resource_name=None, 
               details=None, status='success'):
    """
    Log a security-sensitive action to the audit trail.
    
    Args:
        action: Action performed (e.g., 'login', 'create_case', 'delete_file', 'modify_user')
        resource_type: Type of resource affected (e.g., 'case', 'file', 'user', 'ioc')
        resource_id: ID of the resource
        resource_name: Human-readable name of resource
        details: Dict or string with additional context (will be JSON-ified)
        status: 'success', 'failed', or 'error'
    
    Example:
        from audit_logger import log_action
        
        # Simple usage:
        log_action('login', status='success')
        
        # With resource:
        log_action('delete_case', resource_type='case', resource_id=123, 
                   resource_name='Acme Breach Investigation')
        
        # With details:
        log_action('modify_user', resource_type='user', resource_id=5,
                   resource_name='john.doe',
                   details={'changes': {'role': 'analyst', 'active': False}})
    """
    
    try:
        from main import db
        from models import AuditLog
        
        # Get current user info
        user_id = None
        username = 'system'
        
        if current_user and current_user.is_authenticated:
            user_id = current_user.id
            username = current_user.username
        
        # Get request info
        ip_address = None
        user_agent = None
        
        if request:
            ip_address = request.remote_addr
            user_agent = request.headers.get('User-Agent', '')[:500]  # Truncate
        
        # Convert details to JSON if it's a dict
        if details and isinstance(details, dict):
            details = json.dumps(details)
        elif details:
            details = str(details)
        
        # Create audit log entry
        audit_entry = AuditLog(
            timestamp=datetime.utcnow(),
            user_id=user_id,
            username=username,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            resource_name=resource_name,
            ip_address=ip_address,
            user_agent=user_agent,
            details=details,
            status=status
        )
        
        db.session.add(audit_entry)
        db.session.commit()
        
        logger.info(f"[AUDIT] {username} - {action} - {resource_type}:{resource_id} - {status}")
        
    except Exception as e:
        logger.error(f"[AUDIT] Failed to log action '{action}': {e}")
        # Don't raise - audit logging failures shouldn't break the app
