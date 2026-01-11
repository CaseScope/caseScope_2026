"""Known Systems Discovery Module

Modular function to discover and populate known systems from artifacts.
Can be called from:
1. File ingestion process (after files are ingested)
2. UI button click ("Find in Artifacts")
"""
import logging
from datetime import datetime
from typing import Dict, List, Tuple, Optional

from models.database import db
from models.known_system import (
    KnownSystem, KnownSystemIP, KnownSystemAlias, 
    KnownSystemAudit, KnownSystemCase
)

logger = logging.getLogger(__name__)


def discover_known_systems(case_id: int, case_uuid: str, username: str = 'system') -> Dict:
    """Discover and populate known systems from artifacts for a case
    
    Sources:
    1. case_files table - hostname field
    2. ClickHouse events - hostname field
    
    Args:
        case_id: PostgreSQL case.id (also used for ClickHouse)
        case_uuid: Case UUID for querying case_files
        username: User performing the discovery (for audit)
    
    Returns:
        Dict with discovery results
    """
    results = {
        'success': True,
        'systems_created': 0,
        'systems_updated': 0,
        'aliases_added': 0,
        'ips_added': 0,
        'case_links_added': 0,
        'hostnames_processed': 0,
        'errors': []
    }
    
    try:
        # Collect hostnames from all sources
        all_hostnames = set()
        
        # Source 1: case_files table
        file_hostnames = _get_hostnames_from_case_files(case_uuid)
        all_hostnames.update(file_hostnames)
        logger.info(f"Found {len(file_hostnames)} unique hostnames from case_files")
        
        # Source 2: ClickHouse events
        event_hostnames = _get_hostnames_from_events(case_id)
        all_hostnames.update(event_hostnames)
        logger.info(f"Found {len(event_hostnames)} unique hostnames from events")
        
        # Remove empty/None values
        all_hostnames.discard(None)
        all_hostnames.discard('')
        
        results['hostnames_processed'] = len(all_hostnames)
        logger.info(f"Processing {len(all_hostnames)} total unique hostnames")
        
        # Process each hostname
        for hostname in all_hostnames:
            try:
                created, updated, alias_added = _process_hostname(
                    hostname, case_id, username
                )
                
                if created:
                    results['systems_created'] += 1
                if updated:
                    results['systems_updated'] += 1
                if alias_added:
                    results['aliases_added'] += 1
                    
            except Exception as e:
                logger.error(f"Error processing hostname '{hostname}': {e}")
                results['errors'].append(f"Error with '{hostname}': {str(e)}")
        
        # Commit all changes
        db.session.commit()
        
        # Count case links added
        results['case_links_added'] = KnownSystemCase.query.filter_by(case_id=case_id).count()
        
    except Exception as e:
        logger.exception("Error in discover_known_systems")
        results['success'] = False
        results['errors'].append(str(e))
        db.session.rollback()
    
    return results


def _get_hostnames_from_case_files(case_uuid: str) -> set:
    """Get unique hostnames from case_files table"""
    from models.case_file import CaseFile
    
    hostnames = set()
    
    # Query unique non-null hostnames for this case
    rows = db.session.query(CaseFile.hostname).filter(
        CaseFile.case_uuid == case_uuid,
        CaseFile.hostname.isnot(None),
        CaseFile.hostname != ''
    ).distinct().all()
    
    for row in rows:
        if row[0]:
            hostnames.add(row[0].strip())
    
    return hostnames


def _get_hostnames_from_events(case_id: int) -> set:
    """Get unique hostnames from ClickHouse events table"""
    from utils.clickhouse import get_client
    
    hostnames = set()
    
    try:
        client = get_client()
        
        # Query unique hostnames from events
        result = client.query(
            """SELECT DISTINCT hostname 
               FROM events 
               WHERE case_id = {case_id:UInt32} 
                 AND hostname != ''
               LIMIT 10000""",
            parameters={'case_id': case_id}
        )
        
        for row in result.result_rows:
            if row[0]:
                hostnames.add(row[0].strip())
                
    except Exception as e:
        logger.warning(f"Error querying ClickHouse for hostnames: {e}")
    
    return hostnames


def _process_hostname(hostname: str, case_id: int, username: str) -> Tuple[bool, bool, bool]:
    """Process a single hostname through deduplication logic
    
    Returns: (created, updated, alias_added)
    """
    created = False
    updated = False
    alias_added = False
    
    # Extract NETBIOS name
    netbios, fqdn = KnownSystem.extract_netbios_name(hostname)
    
    if not netbios:
        return created, updated, alias_added
    
    # Find existing system
    system, match_type = KnownSystem.find_by_hostname_or_alias(hostname)
    
    if system:
        # Update existing system
        updated = True
        
        # Update last_seen
        system.last_seen = datetime.utcnow()
        
        # Increment artifact count
        system.artifacts_with_hostname += 1
        
        # Add FQDN as alias if different from hostname
        if fqdn and fqdn != system.hostname.upper():
            if system.add_alias(fqdn):
                alias_added = True
                KnownSystemAudit.log_change(
                    system_id=system.id,
                    changed_by=username,
                    field_name='aliases',
                    action='create',
                    new_value=fqdn
                )
        
        # Also add the original hostname as alias if different
        if hostname.upper() != system.hostname.upper() and hostname.upper() != fqdn:
            if system.add_alias(hostname.upper()):
                alias_added = True
                KnownSystemAudit.log_change(
                    system_id=system.id,
                    changed_by=username,
                    field_name='aliases',
                    action='create',
                    new_value=hostname.upper()
                )
        
        # Link to case
        system.link_to_case(case_id)
        
    else:
        # Create new system with NETBIOS name as hostname
        created = True
        
        system = KnownSystem(
            hostname=netbios,
            artifacts_with_hostname=1,
            added_on=datetime.utcnow(),
            last_seen=datetime.utcnow()
        )
        db.session.add(system)
        db.session.flush()  # Get the ID
        
        # Log creation
        KnownSystemAudit.log_change(
            system_id=system.id,
            changed_by=username,
            field_name='system',
            action='create',
            new_value=netbios
        )
        
        # Add FQDN as alias if we had one
        if fqdn:
            system.add_alias(fqdn)
            alias_added = True
            KnownSystemAudit.log_change(
                system_id=system.id,
                changed_by=username,
                field_name='aliases',
                action='create',
                new_value=fqdn
            )
        
        # Link to case
        system.link_to_case(case_id)
    
    return created, updated, alias_added


def add_ip_to_system(system_id: int, ip_address: str, username: str) -> bool:
    """Add an IP address to a system with audit logging"""
    system = KnownSystem.query.get(system_id)
    if not system:
        return False
    
    if system.add_ip_address(ip_address):
        KnownSystemAudit.log_change(
            system_id=system_id,
            changed_by=username,
            field_name='ip_addresses',
            action='create',
            new_value=ip_address
        )
        db.session.commit()
        return True
    return False


def add_share_to_system(system_id: int, share_name: str, share_path: str, username: str) -> bool:
    """Add a share to a system with audit logging"""
    system = KnownSystem.query.get(system_id)
    if not system:
        return False
    
    if system.add_share(share_name, share_path):
        KnownSystemAudit.log_change(
            system_id=system_id,
            changed_by=username,
            field_name='shares',
            action='create',
            new_value=f"{share_name} ({share_path})" if share_path else share_name
        )
        db.session.commit()
        return True
    return False


def update_system_field(system_id: int, field_name: str, new_value, username: str) -> bool:
    """Update a system field with audit logging
    
    Allowed fields: os_type, os_version, system_type, notes, compromised
    """
    allowed_fields = ['os_type', 'os_version', 'system_type', 'notes', 'compromised']
    
    if field_name not in allowed_fields:
        return False
    
    system = KnownSystem.query.get(system_id)
    if not system:
        return False
    
    old_value = getattr(system, field_name)
    
    # Don't log if value hasn't changed
    if old_value == new_value:
        return True
    
    setattr(system, field_name, new_value)
    
    KnownSystemAudit.log_change(
        system_id=system_id,
        changed_by=username,
        field_name=field_name,
        action='update',
        old_value=old_value,
        new_value=new_value
    )
    
    db.session.commit()
    return True


def get_systems_for_case(case_id: int) -> List[Dict]:
    """Get all known systems linked to a case"""
    systems = []
    
    links = KnownSystemCase.query.filter_by(case_id=case_id).all()
    
    for link in links:
        system = KnownSystem.query.get(link.system_id)
        if system:
            system_dict = system.to_dict()
            system_dict['first_seen_in_case'] = link.first_seen_in_case.isoformat() if link.first_seen_in_case else None
            systems.append(system_dict)
    
    return systems


def get_system_audit_history(system_id: int) -> List[Dict]:
    """Get audit history for a system"""
    audits = KnownSystemAudit.query.filter_by(
        system_id=system_id
    ).order_by(KnownSystemAudit.changed_on.desc()).all()
    
    return [audit.to_dict() for audit in audits]
