"""
Known User Utilities
Provides functions to check usernames against the Known Users database and IOCs
"""
import logging
from typing import Dict, Optional

logger = logging.getLogger(__name__)


def check_ioc_match(username: str, case_id: Optional[int] = None) -> Dict[str, any]:
    """
    Check if a username matches a USERNAME type IOC in the database
    
    Args:
        username: Username to check (case-insensitive)
        case_id: Optional case ID to filter IOCs (if None, checks all cases)
        
    Returns:
        Dict with:
            - 'is_ioc': bool (True if username matches a USERNAME type IOC)
            - 'threat_level': str ('low', 'medium', 'high', 'critical')
    """
    try:
        from models import IOC
        
        # Build query - only check active IOCs
        query = IOC.query.filter(
            IOC.ioc_type == 'username',
            IOC.ioc_value.ilike(username),
            IOC.is_active == True
        )
        
        # Filter by case if provided
        if case_id is not None:
            query = query.filter(IOC.case_id == case_id)
        
        # Get first matching IOC
        ioc = query.first()
        
        if ioc:
            return {
                'is_ioc': True,
                'threat_level': ioc.threat_level if hasattr(ioc, 'threat_level') else 'medium'
            }
        else:
            return {
                'is_ioc': False,
                'threat_level': None
            }
    
    except Exception as e:
        logger.error(f"[IOC_CHECK] Error checking username '{username}': {e}")
        return {
            'is_ioc': False,
            'threat_level': None
        }


def check_known_user(username: str, case_id: int) -> Dict[str, any]:
    """
    Check if a username exists in the Known Users database for a specific case
    
    Args:
        username: Username to check (case-insensitive)
        case_id: Case ID to filter by (required)
        
    Returns:
        Dict with:
            - 'is_known': bool (True if user exists in database for this case)
            - 'compromised': bool (True if user is marked as compromised)
            - 'user_type': str ('domain', 'local', or '-')
            - 'active': bool (True if user is currently active) # v1.20.0
    """
    try:
        from models import KnownUser
        
        # Case-insensitive lookup within specific case
        known_user = KnownUser.query.filter(
            KnownUser.case_id == case_id,
            KnownUser.username.ilike(username)
        ).first()
        
        if known_user:
            return {
                'is_known': True,
                'compromised': known_user.compromised,
                'user_type': known_user.user_type,
                'active': known_user.active  # v1.20.0
            }
        else:
            return {
                'is_known': False,
                'compromised': False,
                'user_type': None,
                'active': None  # v1.20.0
            }
    
    except Exception as e:
        logger.error(f"[KNOWN_USER_CHECK] Error checking username '{username}' for case {case_id}: {e}")
        return {
            'is_known': False,
            'compromised': False,
            'user_type': None,
            'active': None  # v1.20.0
        }


def enrich_login_records(login_records: list, case_id: int) -> list:
    """
    Enrich login records with Known User and IOC information
    
    Args:
        login_records: List of dicts with 'username' key
        case_id: Case ID (required) for filtering Known Users and IOCs
        
    Returns:
        Same list with added keys:
            - 'is_known_user': bool
            - 'is_compromised': bool
            - 'user_type': str or None
            - 'is_active': bool or None  # v1.20.0
            - 'is_ioc': bool
            - 'ioc_threat_level': str or None
    """
    try:
        if case_id is None:
            logger.warning("[KNOWN_USER_ENRICH] case_id is None, skipping enrichment")
            return login_records
        
        enriched = []
        
        for record in login_records:
            username = record.get('username', '')
            
            # Check against Known Users database (case-specific)
            user_info = check_known_user(username, case_id)
            
            # Check against IOCs (case-specific)
            ioc_info = check_ioc_match(username, case_id)
            
            # Add enrichment data to record
            enriched_record = record.copy()
            enriched_record['is_known_user'] = user_info['is_known']
            enriched_record['is_compromised'] = user_info['compromised']
            enriched_record['user_type'] = user_info['user_type']
            enriched_record['is_active'] = user_info['active']  # v1.20.0
            enriched_record['is_ioc'] = ioc_info['is_ioc']
            enriched_record['ioc_threat_level'] = ioc_info['threat_level']
            
            enriched.append(enriched_record)
        
        # Log summary
        total = len(enriched)
        known = sum(1 for r in enriched if r['is_known_user'])
        compromised = sum(1 for r in enriched if r['is_compromised'])
        iocs = sum(1 for r in enriched if r['is_ioc'])
        active = sum(1 for r in enriched if r['is_active'])  # v1.20.0
        
        logger.info(f"[KNOWN_USER_ENRICH] Enriched {total} records for case {case_id}: {known} known users ({active} active), {compromised} compromised, {iocs} IOCs")
        
        return enriched
    
    except Exception as e:
        logger.error(f"[KNOWN_USER_ENRICH] Error enriching records for case {case_id}: {e}")
        # Return original records without enrichment on error
        return login_records

