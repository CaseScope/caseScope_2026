#!/usr/bin/env python3
"""
CaseScope 2026 - Audit Logging Utility
Tracks user actions for security and compliance
"""

from flask import request
from flask_login import current_user
from datetime import datetime
import json
import logging

logger = logging.getLogger(__name__)


def log_action(action, resource_type=None, resource_id=None, resource_name=None, 
               details=None, status='success'):
    """
    Log a user action to the audit trail
    
    Args:
        action: Action performed (e.g., 'login', 'create_case', 'delete_file')
        resource_type: Type of resource affected (e.g., 'case', 'file', 'user')
        resource_id: ID of the affected resource
        resource_name: Name/description of the resource
        details: Additional details (dict will be JSON serialized)
        status: 'success', 'failed', or 'error'
    """
    try:
        from main import db
        from models import AuditLog
        
        # Get user info
        user_id = current_user.id if current_user.is_authenticated else None
        username = current_user.username if current_user.is_authenticated else 'anonymous'
        
        # Get request info - check for proxy headers first
        ip_address = None
        if request:
            # Check X-Forwarded-For header (most common proxy header)
            # Format: "client_ip, proxy1_ip, proxy2_ip"
            forwarded_for = request.headers.get('X-Forwarded-For', '')
            if forwarded_for:
                # Take the first IP (original client)
                ip_address = forwarded_for.split(',')[0].strip()
            else:
                # Check X-Real-IP header (alternative proxy header)
                ip_address = request.headers.get('X-Real-IP', None)
            
            # Fallback to remote_addr if no proxy headers found
            if not ip_address:
                ip_address = request.remote_addr
            
            user_agent = request.headers.get('User-Agent', '')[:500]
        else:
            user_agent = None
        
        # Serialize details if dict
        if isinstance(details, dict):
            details = json.dumps(details)
        
        # Create audit log entry
        audit_entry = AuditLog(
            user_id=user_id,
            username=username,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            resource_name=resource_name,
            details=details,
            ip_address=ip_address,
            user_agent=user_agent,
            status=status,
            created_at=datetime.utcnow()
        )
        
        db.session.add(audit_entry)
        db.session.commit()
        
        logger.debug(f"[AUDIT] {username} - {action} - {resource_type}:{resource_id} - {status}")
        
    except Exception as e:
        logger.error(f"[AUDIT] Failed to log action: {e}")
        # Don't raise - audit logging should not break the application


def log_login(username, success=True, details=None):
    """Log a login attempt"""
    status = 'success' if success else 'failed'
    log_action('login', resource_type='auth', resource_name=username, 
               details=details, status=status)


def log_logout(username):
    """Log a logout"""
    log_action('logout', resource_type='auth', resource_name=username)


def log_case_action(action, case_id, case_name, details=None):
    """Log a case-related action"""
    log_action(action, resource_type='case', resource_id=case_id, 
               resource_name=case_name, details=details)


def log_file_action(action, file_id, filename, details=None):
    """Log a file-related action"""
    log_action(action, resource_type='file', resource_id=file_id, 
               resource_name=filename, details=details)


def log_user_action(action, user_id, username_affected, details=None):
    """Log a user management action"""
    log_action(action, resource_type='user', resource_id=user_id, 
               resource_name=username_affected, details=details)


def log_ioc_action(action, ioc_id, ioc_value, details=None):
    """Log an IOC-related action"""
    log_action(action, resource_type='ioc', resource_id=ioc_id, 
               resource_name=ioc_value, details=details)


def log_settings_action(action, details=None):
    """Log a settings change"""
    log_action(action, resource_type='settings', details=details)


def log_search(query, filters=None):
    """Log a search query"""
    details = {'query': query}
    if filters:
        details['filters'] = filters
    log_action('search', resource_type='search', details=details)

