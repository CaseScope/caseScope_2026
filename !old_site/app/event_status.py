"""
Event Status Management Module

Unified event status tracking system that replaces the fragmented
is_hidden, TimelineTag, and TagExclusion systems.

Statuses:
- new: Fresh event, just indexed (default)
- noise: Flagged by known-good/noise processes, excluded from searches
- hunted: Tagged by Phase 3 triage as potentially interesting
- confirmed: Analyst reviewed and confirmed as relevant

Usage:
    from event_status import get_status, set_status, bulk_set_status
    
    # Get status for an event
    status = get_status(case_id, event_id)
    
    # Set status for an event
    set_status(case_id, event_id, 'hunted', user_id=1)
    
    # Bulk set status
    bulk_set_status(case_id, event_ids, 'noise', user_id=None)  # System action

Event Status Synchronization (v1.47.0):
    - PostgreSQL EventStatus table: Source of truth for status data
    - OpenSearch event_status field: Synced for fast filtering/search
    - All status changes automatically sync to both systems
"""

import logging
from typing import List, Dict, Set, Optional, Any
from datetime import datetime

logger = logging.getLogger(__name__)

# Status constants
STATUS_NEW = 'new'
STATUS_NOISE = 'noise'
STATUS_HUNTED = 'hunted'
STATUS_CONFIRMED = 'confirmed'
VALID_STATUSES = [STATUS_NEW, STATUS_NOISE, STATUS_HUNTED, STATUS_CONFIRMED]

# Default statuses to show in search (excludes noise)
DEFAULT_VISIBLE_STATUSES = [STATUS_NEW, STATUS_HUNTED, STATUS_CONFIRMED]


# ============================================================================
# OPENSEARCH SYNCHRONIZATION
# ============================================================================

def sync_status_to_opensearch(case_id: int, event_id: str, status: str) -> bool:
    """
    Sync a single event's status to OpenSearch.
    
    Updates the event_status field in the OpenSearch document to match the database.
    This enables fast filtering in search without database lookups.
    
    Args:
        case_id: Case ID
        event_id: OpenSearch document _id
        status: Status value (new, noise, hunted, confirmed)
    
    Returns:
        True if successful, False otherwise
    """
    from main import opensearch_client
    
    index_name = f"case_{case_id}"
    
    try:
        # Update the document's event_status field
        opensearch_client.update(
            index=index_name,
            id=event_id,
            body={
                "doc": {
                    "event_status": status
                }
            },
            refresh=False  # Don't force immediate refresh for performance
        )
        logger.debug(f"[EVENT_STATUS] Synced to OpenSearch: {event_id[:8]} -> {status}")
        return True
        
    except Exception as e:
        logger.warning(f"[EVENT_STATUS] Failed to sync status to OpenSearch for {event_id[:8]}: {e}")
        # Don't fail the operation if OpenSearch sync fails - database is source of truth
        return False


def bulk_sync_status_to_opensearch(case_id: int, event_ids: List[str], status: str) -> Dict[str, int]:
    """
    Sync multiple events' statuses to OpenSearch using bulk API.
    
    Updates event_status field for multiple documents efficiently.
    
    Args:
        case_id: Case ID
        event_ids: List of OpenSearch document _ids
        status: Status value (new, noise, hunted, confirmed)
    
    Returns:
        Dict with 'synced' and 'failed' counts
    """
    from main import opensearch_client
    
    if not event_ids:
        return {'synced': 0, 'failed': 0}
    
    index_name = f"case_{case_id}"
    
    # Build bulk update operations
    # OpenSearch bulk format: { "update": {...} }\n{ "doc": {...} }\n
    BATCH_SIZE = 5000  # Process in batches to avoid memory issues
    total_synced = 0
    total_failed = 0
    
    try:
        for i in range(0, len(event_ids), BATCH_SIZE):
            batch = event_ids[i:i + BATCH_SIZE]
            
            bulk_body = []
            for event_id in batch:
                bulk_body.append({"update": {"_index": index_name, "_id": event_id}})
                bulk_body.append({"doc": {"event_status": status}})
            
            # Execute bulk update
            response = opensearch_client.bulk(body=bulk_body, refresh=False)
            
            # Count successes/failures
            if response.get('errors'):
                for item in response.get('items', []):
                    if 'update' in item:
                        if item['update'].get('status') in [200, 201]:
                            total_synced += 1
                        else:
                            total_failed += 1
                            logger.debug(f"[EVENT_STATUS] Bulk sync failed for event: {item['update'].get('error', 'Unknown error')}")
            else:
                total_synced += len(batch)
            
            if (i + BATCH_SIZE) < len(event_ids):
                logger.debug(f"[EVENT_STATUS] Bulk sync progress: {total_synced:,}/{len(event_ids):,}")
        
        logger.info(f"[EVENT_STATUS] Bulk synced {total_synced:,} events to OpenSearch as '{status}' ({total_failed} failed)")
        
        return {'synced': total_synced, 'failed': total_failed}
        
    except Exception as e:
        logger.error(f"[EVENT_STATUS] Bulk sync to OpenSearch failed: {e}", exc_info=True)
        return {'synced': 0, 'failed': len(event_ids)}


# ============================================================================
# STATUS MANAGEMENT
# ============================================================================

def get_status(case_id: int, event_id: str) -> str:
    """Get the status of a single event. Returns 'new' if not found."""
    from models import EventStatus
    
    record = EventStatus.query.filter_by(
        case_id=case_id,
        event_id=event_id
    ).first()
    
    return record.status if record else STATUS_NEW


def get_statuses(case_id: int, event_ids: List[str]) -> Dict[str, str]:
    """Get statuses for multiple events. Returns dict of event_id -> status."""
    from models import EventStatus
    
    if not event_ids:
        return {}
    
    records = EventStatus.query.filter(
        EventStatus.case_id == case_id,
        EventStatus.event_id.in_(event_ids)
    ).all()
    
    status_map = {r.event_id: r.status for r in records}
    
    # Default to 'new' for events without status records
    for event_id in event_ids:
        if event_id not in status_map:
            status_map[event_id] = STATUS_NEW
    
    return status_map


def get_event_ids_by_status(case_id: int, statuses: List[str]) -> Set[str]:
    """Get all event IDs that have one of the specified statuses."""
    from models import EventStatus
    
    if not statuses:
        return set()
    
    records = EventStatus.query.filter(
        EventStatus.case_id == case_id,
        EventStatus.status.in_(statuses)
    ).all()
    
    return {r.event_id for r in records}


def set_status(case_id: int, event_id: str, status: str, 
               user_id: Optional[int] = None, notes: Optional[str] = None,
               sync_opensearch: bool = True) -> bool:
    """
    Set the status of a single event.
    
    Args:
        case_id: Case ID
        event_id: OpenSearch document _id
        status: One of: new, noise, hunted, confirmed
        user_id: User making the change (None for system actions)
        notes: Optional notes about the status change
        sync_opensearch: Whether to sync status to OpenSearch (default: True)
    
    Returns:
        True if successful, False otherwise
    """
    from models import EventStatus, db
    
    if status not in VALID_STATUSES:
        logger.error(f"[EVENT_STATUS] Invalid status: {status}")
        return False
    
    try:
        # Check if record exists
        record = EventStatus.query.filter_by(
            case_id=case_id,
            event_id=event_id
        ).first()
        
        if record:
            # Update existing
            record.status = status
            record.updated_by = user_id
            record.updated_at = datetime.utcnow()
            if notes is not None:
                record.notes = notes
        else:
            # Create new
            record = EventStatus(
                case_id=case_id,
                event_id=event_id,
                status=status,
                updated_by=user_id,
                notes=notes
            )
            db.session.add(record)
        
        db.session.commit()
        
        # Sync to OpenSearch (v1.47.0)
        if sync_opensearch:
            sync_status_to_opensearch(case_id, event_id, status)
        
        return True
        
    except Exception as e:
        logger.error(f"[EVENT_STATUS] Failed to set status: {e}")
        db.session.rollback()
        return False


def bulk_set_status(case_id: int, event_ids: List[str], status: str,
                    user_id: Optional[int] = None, notes: Optional[str] = None,
                    db_session=None, sync_opensearch: bool = True) -> Dict[str, int]:
    """
    Set status for multiple events efficiently with batching for large lists.
    
    Args:
        case_id: Case ID
        event_ids: List of OpenSearch document _ids
        status: One of: new, noise, hunted, confirmed
        user_id: User making the change (None for system actions)
        notes: Optional notes about the status change
        db_session: Optional database session (for Celery workers)
        sync_opensearch: Whether to sync statuses to OpenSearch (default: True)
    
    Returns:
        Dict with 'updated', 'created', 'synced', and 'sync_failed' counts
    """
    from models import EventStatus
    
    # Use provided session or get from main app
    if db_session is None:
        from main import db
        db_session = db.session
    
    if status not in VALID_STATUSES:
        logger.error(f"[EVENT_STATUS] Invalid status: {status}")
        return {'updated': 0, 'created': 0, 'synced': 0, 'sync_failed': 0, 'error': 'Invalid status'}
    
    if not event_ids:
        return {'updated': 0, 'created': 0, 'synced': 0, 'sync_failed': 0}
    
    # CRITICAL: Batch processing for large lists (v1.46.1)
    # PostgreSQL IN clause has limits, and session.add() for 800k records will fail
    # Process in chunks of 10,000 to avoid memory/performance issues
    BATCH_SIZE = 10000
    total_updated = 0
    total_created = 0
    
    try:
        now = datetime.utcnow()
        
        # Process in batches
        for i in range(0, len(event_ids), BATCH_SIZE):
            batch = event_ids[i:i + BATCH_SIZE]
            
            # Get existing records for this batch
            existing = db_session.query(EventStatus).filter(
                EventStatus.case_id == case_id,
                EventStatus.event_id.in_(batch)
            ).all()
            
            existing_ids = {r.event_id: r for r in existing}
            
            updated_count = 0
            created_count = 0
            
            for event_id in batch:
                if event_id in existing_ids:
                    # Update existing
                    record = existing_ids[event_id]
                    if record.status != status:  # Only update if different
                        record.status = status
                        record.updated_by = user_id
                        record.updated_at = now
                        if notes is not None:
                            record.notes = notes
                        updated_count += 1
                else:
                    # Create new
                    record = EventStatus(
                        case_id=case_id,
                        event_id=event_id,
                        status=status,
                        updated_by=user_id,
                        updated_at=now,
                        notes=notes
                    )
                    db_session.add(record)
                    created_count += 1
            
            # Commit this batch
            db_session.commit()
            total_updated += updated_count
            total_created += created_count
            
            if (i + BATCH_SIZE) < len(event_ids):
                logger.debug(f"[EVENT_STATUS] Batch {i//BATCH_SIZE + 1}: {updated_count} updated, {created_count} created")
        
        logger.info(f"[EVENT_STATUS] Bulk set {len(event_ids):,} events to '{status}': {total_updated:,} updated, {total_created:,} created")
        
        # Sync to OpenSearch (v1.47.0)
        sync_result = {'synced': 0, 'failed': 0}
        if sync_opensearch:
            sync_result = bulk_sync_status_to_opensearch(case_id, event_ids, status)
        
        return {
            'updated': total_updated,
            'created': total_created,
            'synced': sync_result['synced'],
            'sync_failed': sync_result['failed']
        }
        
    except Exception as e:
        logger.error(f"[EVENT_STATUS] Bulk set failed: {e}", exc_info=True)
        db_session.rollback()
        return {'updated': 0, 'created': 0, 'synced': 0, 'sync_failed': 0, 'error': str(e)}


def get_status_counts(case_id: int) -> Dict[str, int]:
    """Get count of events in each status for a case."""
    from models import EventStatus, db
    from sqlalchemy import func
    
    try:
        counts = db.session.query(
            EventStatus.status,
            func.count(EventStatus.id)
        ).filter(
            EventStatus.case_id == case_id
        ).group_by(EventStatus.status).all()
        
        result = {status: 0 for status in VALID_STATUSES}
        for status, count in counts:
            result[status] = count
        
        return result
        
    except Exception as e:
        logger.error(f"[EVENT_STATUS] Failed to get counts: {e}")
        return {status: 0 for status in VALID_STATUSES}


def get_noise_event_ids(case_id: int) -> Set[str]:
    """Get all event IDs marked as noise for a case."""
    return get_event_ids_by_status(case_id, [STATUS_NOISE])


def get_hunted_event_ids(case_id: int) -> Set[str]:
    """Get all event IDs marked as hunted for a case."""
    return get_event_ids_by_status(case_id, [STATUS_HUNTED])


def get_confirmed_event_ids(case_id: int) -> Set[str]:
    """Get all event IDs marked as confirmed for a case."""
    return get_event_ids_by_status(case_id, [STATUS_CONFIRMED])


def is_noise(case_id: int, event_id: str) -> bool:
    """Check if an event is marked as noise."""
    return get_status(case_id, event_id) == STATUS_NOISE


def mark_as_noise(case_id: int, event_ids: List[str], user_id: Optional[int] = None) -> Dict[str, int]:
    """Mark events as noise (convenience function)."""
    return bulk_set_status(case_id, event_ids, STATUS_NOISE, user_id, notes="Auto-marked as noise")


def mark_as_hunted(case_id: int, event_ids: List[str], user_id: Optional[int] = None, 
                   reason: Optional[str] = None) -> Dict[str, int]:
    """Mark events as hunted (convenience function)."""
    return bulk_set_status(case_id, event_ids, STATUS_HUNTED, user_id, notes=reason)


def mark_as_confirmed(case_id: int, event_id: str, user_id: int, notes: Optional[str] = None) -> bool:
    """Mark a single event as confirmed (analyst action)."""
    return set_status(case_id, event_id, STATUS_CONFIRMED, user_id, notes)


def clear_status(case_id: int, event_id: str) -> bool:
    """Reset an event back to 'new' status."""
    from models import EventStatus, db
    
    try:
        record = EventStatus.query.filter_by(
            case_id=case_id,
            event_id=event_id
        ).first()
        
        if record:
            db.session.delete(record)
            db.session.commit()
        
        return True
        
    except Exception as e:
        logger.error(f"[EVENT_STATUS] Failed to clear status: {e}")
        db.session.rollback()
        return False


def get_event_details(case_id: int, event_id: str) -> Optional[Dict[str, Any]]:
    """Get full status details for an event."""
    from models import EventStatus, User
    
    record = EventStatus.query.filter_by(
        case_id=case_id,
        event_id=event_id
    ).first()
    
    if not record:
        return {
            'event_id': event_id,
            'status': STATUS_NEW,
            'updated_by': None,
            'updated_at': None,
            'notes': None
        }
    
    user = User.query.get(record.updated_by) if record.updated_by else None
    
    return {
        'event_id': record.event_id,
        'status': record.status,
        'updated_by': user.username if user else 'System',
        'updated_at': record.updated_at.isoformat() if record.updated_at else None,
        'notes': record.notes
    }

