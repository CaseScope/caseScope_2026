"""Known Systems Discovery Module

Modular function to discover and populate known systems from artifacts.
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
from models.known_system import (
    KnownSystem, KnownSystemIP, KnownSystemAlias, 
    KnownSystemAudit, KnownSystemCase
)
from config import Config

logger = logging.getLogger(__name__)

# Redis client for progress tracking
_redis_client = None

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


def init_discovery_progress(case_uuid: str, total: int):
    """Initialize discovery progress in Redis"""
    r = get_redis()
    key = f"discovery:{case_uuid}"
    r.hset(key, mapping={
        'status': 'running',
        'total': total,
        'processed': 0,
        'created': 0,
        'updated': 0,
        'current_hostname': ''
    })
    r.expire(key, 3600)  # 1 hour TTL


def update_discovery_progress(case_uuid: str, processed: int, created: int, updated: int, current: str = ''):
    """Update discovery progress in Redis"""
    r = get_redis()
    key = f"discovery:{case_uuid}"
    r.hset(key, mapping={
        'processed': processed,
        'created': created,
        'updated': updated,
        'current_hostname': current
    })


def complete_discovery_progress(case_uuid: str, results: dict):
    """Mark discovery as complete"""
    r = get_redis()
    key = f"discovery:{case_uuid}"
    r.hset(key, mapping={
        'status': 'complete',
        'processed': results.get('hostnames_processed', 0),
        'created': results.get('systems_created', 0),
        'updated': results.get('systems_updated', 0),
        'current_hostname': ''
    })
    r.expire(key, 300)  # Keep for 5 minutes after completion


def get_discovery_progress(case_uuid: str) -> Optional[dict]:
    """Get current discovery progress"""
    r = get_redis()
    key = f"discovery:{case_uuid}"
    data = r.hgetall(key)
    if data:
        return {
            'status': data.get('status', 'unknown'),
            'total': int(data.get('total', 0)),
            'processed': int(data.get('processed', 0)),
            'created': int(data.get('created', 0)),
            'updated': int(data.get('updated', 0)),
            'current_hostname': data.get('current_hostname', '')
        }
    return None


def discover_known_systems(case_id: int, case_uuid: str, username: str = 'system', track_progress: bool = False) -> Dict:
    """Discover and populate known systems from artifacts for a case
    
    Sources:
    1. case_files table - hostname field
    2. ClickHouse events - hostname field
    
    Args:
        case_id: PostgreSQL case.id (also used for ClickHouse)
        case_uuid: Case UUID for querying case_files
        username: User performing the discovery (for audit)
        track_progress: Whether to track progress in Redis
    
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
        # Collect hostname stats from all sources
        # Format: {hostname: {'count': N, 'last_seen': datetime}}
        
        # Source 1: case_files table
        file_stats = _get_hostnames_from_case_files(case_uuid)
        logger.info(f"Found {len(file_stats)} unique hostnames from case_files")
        
        # Source 2: ClickHouse events
        event_stats = _get_hostnames_from_events(case_id)
        logger.info(f"Found {len(event_stats)} unique hostnames from events")
        
        # Merge stats: combine counts and take latest last_seen
        all_hostname_stats = {}
        for hostname, stats in file_stats.items():
            if hostname:
                all_hostname_stats[hostname] = {
                    'count': stats['count'],
                    'last_seen': stats['last_seen']
                }
        
        for hostname, stats in event_stats.items():
            if hostname:
                if hostname in all_hostname_stats:
                    # Add counts together
                    all_hostname_stats[hostname]['count'] += stats['count']
                    # Take the later last_seen
                    if stats['last_seen'] and (
                        not all_hostname_stats[hostname]['last_seen'] or 
                        stats['last_seen'] > all_hostname_stats[hostname]['last_seen']
                    ):
                        all_hostname_stats[hostname]['last_seen'] = stats['last_seen']
                else:
                    all_hostname_stats[hostname] = {
                        'count': stats['count'],
                        'last_seen': stats['last_seen']
                    }
        
        total_hostnames = len(all_hostname_stats)
        results['hostnames_processed'] = total_hostnames
        logger.info(f"Processing {total_hostnames} total unique hostnames")
        
        # Initialize progress tracking
        if track_progress:
            init_discovery_progress(case_uuid, total_hostnames)
        
        # Process each hostname with its stats
        processed = 0
        for hostname, stats in all_hostname_stats.items():
            try:
                created, updated, alias_added = _process_hostname(
                    hostname, case_id, username,
                    artifact_count=stats['count'],
                    last_seen=stats['last_seen']
                )
                
                if created:
                    results['systems_created'] += 1
                if updated:
                    results['systems_updated'] += 1
                if alias_added:
                    results['aliases_added'] += 1
                
                processed += 1
                
                # Update progress every 10 hostnames or on last one
                if track_progress and (processed % 10 == 0 or processed == total_hostnames):
                    update_discovery_progress(
                        case_uuid, processed,
                        results['systems_created'],
                        results['systems_updated'],
                        hostname
                    )
                    
            except IntegrityError:
                # Race condition - another process created this system
                # This is expected and safe - just rollback and retry as update
                db.session.rollback()
                try:
                    created, updated, alias_added = _process_hostname(
                        hostname, case_id, username
                    )
                    if updated:
                        results['systems_updated'] += 1
                    if alias_added:
                        results['aliases_added'] += 1
                    processed += 1
                except Exception as e2:
                    logger.warning(f"Retry failed for '{hostname}': {e2}")
                    
            except Exception as e:
                logger.error(f"Error processing hostname '{hostname}': {e}")
                results['errors'].append(f"Error with '{hostname}': {str(e)}")
                processed += 1
        
        # Commit all changes
        db.session.commit()
        
        # Count case links added
        results['case_links_added'] = KnownSystemCase.query.filter_by(case_id=case_id).count()
        
        # Mark progress complete
        if track_progress:
            complete_discovery_progress(case_uuid, results)
        
    except Exception as e:
        logger.exception("Error in discover_known_systems")
        results['success'] = False
        results['errors'].append(str(e))
        db.session.rollback()
    
    return results


def _get_hostnames_from_case_files(case_uuid: str) -> dict:
    """Get hostname stats from case_files table
    
    Returns dict: {hostname: {'count': N, 'last_seen': datetime}}
    """
    from models.case_file import CaseFile
    from sqlalchemy import func
    
    hostname_stats = {}
    
    # Query hostname with count and max uploaded_at
    rows = db.session.query(
        CaseFile.hostname,
        func.count(CaseFile.id).label('count'),
        func.max(CaseFile.uploaded_at).label('last_seen')
    ).filter(
        CaseFile.case_uuid == case_uuid,
        CaseFile.hostname.isnot(None),
        CaseFile.hostname != ''
    ).group_by(CaseFile.hostname).all()
    
    for row in rows:
        if row[0]:
            hostname_stats[row[0].strip()] = {
                'count': row[1],
                'last_seen': row[2]
            }
    
    return hostname_stats


def _get_hostnames_from_events(case_id: int) -> dict:
    """Get hostname stats from ClickHouse events table
    
    Returns dict: {hostname: {'count': N, 'last_seen': datetime}}
    """
    from utils.clickhouse import get_client
    
    hostname_stats = {}
    
    try:
        client = get_client()
        
        # Query source_host with count and max timestamp
        result = client.query(
            """SELECT source_host, count() as cnt, max(timestamp) as last_ts
               FROM events 
               WHERE case_id = {case_id:UInt32} 
                 AND source_host != ''
               GROUP BY source_host
               LIMIT 10000""",
            parameters={'case_id': case_id}
        )
        
        for row in result.result_rows:
            if row[0]:
                hostname_stats[row[0].strip()] = {
                    'count': row[1],
                    'last_seen': row[2]
                }
                
    except Exception as e:
        logger.warning(f"Error querying ClickHouse for hostnames: {e}")
    
    return hostname_stats


def _process_hostname(hostname: str, case_id: int, username: str,
                      artifact_count: int = 1, last_seen: datetime = None) -> Tuple[bool, bool, bool]:
    """Process a single hostname through deduplication logic
    
    Args:
        hostname: The hostname to process
        case_id: Case ID for linking
        username: User performing discovery
        artifact_count: Number of artifacts referencing this hostname
        last_seen: Timestamp of most recent artifact with this hostname
    
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
        
        # Update last_seen to artifact timestamp (not now)
        if last_seen:
            if not system.last_seen or last_seen > system.last_seen:
                system.last_seen = last_seen
        
        # Set artifact count to actual value found in this case
        # Note: For multi-case, this shows most recent case's count
        system.artifacts_with_hostname = artifact_count
        
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
            artifacts_with_hostname=artifact_count,
            added_on=datetime.utcnow(),
            last_seen=last_seen if last_seen else datetime.utcnow()
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
