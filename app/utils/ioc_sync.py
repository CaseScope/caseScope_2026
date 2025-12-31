"""
IOC Sync Utilities
Auto-create IOCs when systems/users are marked as compromised
"""

import logging
from datetime import datetime

logger = logging.getLogger(__name__)


def create_ioc_from_system(db, system, current_user_id):
    """
    Create IOC from compromised system
    
    Args:
        db: Database session
        system: KnownSystem object
        current_user_id: User ID creating the IOC
        
    Returns:
        IOC object or None
    """
    from models import IOC
    
    # Determine IOC type and value
    ioc_value = None
    ioc_type = None
    
    # Prefer hostname, fallback to IP
    if system.hostname:
        ioc_value = system.hostname
        ioc_type = 'hostname'
    elif system.ip_address:
        ioc_value = system.ip_address
        ioc_type = 'ipv4'
    else:
        logger.warning(f"Cannot create IOC for system {system.id} - no hostname or IP")
        return None
    
    # Check if IOC already exists
    existing_ioc = IOC.query.filter(
        IOC.case_id == system.case_id,
        db.func.lower(IOC.value) == ioc_value.lower(),
        IOC.type == ioc_type
    ).first()
    
    if existing_ioc:
        logger.info(f"IOC already exists for system {system.hostname or system.ip_address}")
        return existing_ioc
    
    # Build description from system data
    description_parts = []
    if system.hostname:
        description_parts.append(f"Hostname: {system.hostname}")
    if system.domain_name:
        description_parts.append(f"Domain: {system.domain_name}")
    if system.ip_address:
        description_parts.append(f"IP: {system.ip_address}")
    if system.system_type:
        description_parts.append(f"Type: {system.system_type}")
    
    description = "Compromised system. " + "; ".join(description_parts)
    
    # Copy analyst notes
    analyst_notes = f"Auto-created from compromised system (ID: {system.id})"
    if system.description:
        analyst_notes += f"\n\nSystem Description:\n{system.description}"
    if system.analyst_notes:
        analyst_notes += f"\n\nSystem Analyst Notes:\n{system.analyst_notes}"
    
    # Create IOC
    new_ioc = IOC(
        type=ioc_type,
        value=ioc_value,
        category='host',
        threat_level='high',  # Compromised systems are high threat
        confidence=90,  # High confidence since it's confirmed compromised
        source='known_system',
        source_reference=f'KnownSystem ID: {system.id}',
        description=description,
        analyst_notes=analyst_notes,
        case_id=system.case_id,
        created_by=current_user_id,
        updated_by=current_user_id,
        is_active=True,
        is_whitelisted=False
    )
    
    db.session.add(new_ioc)
    db.session.flush()
    
    logger.info(f"Created IOC {ioc_type}:{ioc_value} from compromised system {system.id}")
    
    return new_ioc


def create_ioc_from_user(db, user, current_user_id):
    """
    Create IOC from compromised user
    
    Args:
        db: Database session
        user: KnownUser object
        current_user_id: User ID creating the IOC
        
    Returns:
        IOC object or None
    """
    from models import IOC
    
    # Use username as IOC value
    ioc_value = user.username
    ioc_type = 'username'
    
    # Check if IOC already exists
    existing_ioc = IOC.query.filter(
        IOC.case_id == user.case_id,
        db.func.lower(IOC.value) == ioc_value.lower(),
        IOC.type == ioc_type
    ).first()
    
    if existing_ioc:
        logger.info(f"IOC already exists for user {user.username}")
        return existing_ioc
    
    # Build description from user data
    description_parts = []
    if user.username:
        description_parts.append(f"Username: {user.username}")
    if user.domain_name:
        description_parts.append(f"Domain: {user.domain_name}")
    if user.sid:
        description_parts.append(f"SID: {user.sid}")
    if user.user_type:
        description_parts.append(f"Type: {user.user_type}")
    
    description = "Compromised user account. " + "; ".join(description_parts)
    
    # Copy analyst notes
    analyst_notes = f"Auto-created from compromised user (ID: {user.id})"
    if user.description:
        analyst_notes += f"\n\nUser Description:\n{user.description}"
    if user.analyst_notes:
        analyst_notes += f"\n\nUser Analyst Notes:\n{user.analyst_notes}"
    
    # Create IOC
    new_ioc = IOC(
        type=ioc_type,
        value=ioc_value,
        category='identity',
        threat_level='high',  # Compromised accounts are high threat
        confidence=90,  # High confidence since it's confirmed compromised
        source='known_user',
        source_reference=f'KnownUser ID: {user.id}',
        description=description,
        analyst_notes=analyst_notes,
        case_id=user.case_id,
        created_by=current_user_id,
        updated_by=current_user_id,
        is_active=True,
        is_whitelisted=False
    )
    
    db.session.add(new_ioc)
    db.session.flush()
    
    logger.info(f"Created IOC username:{ioc_value} from compromised user {user.id}")
    
    return new_ioc

