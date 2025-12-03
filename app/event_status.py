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
               user_id: Optional[int] = None, notes: Optional[str] = None) -> bool:
    """
    Set the status of a single event.
    
    Args:
        case_id: Case ID
        event_id: OpenSearch document _id
        status: One of: new, noise, hunted, confirmed
        user_id: User making the change (None for system actions)
        notes: Optional notes about the status change
    
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
        return True
        
    except Exception as e:
        logger.error(f"[EVENT_STATUS] Failed to set status: {e}")
        db.session.rollback()
        return False


def bulk_set_status(case_id: int, event_ids: List[str], status: str,
                    user_id: Optional[int] = None, notes: Optional[str] = None) -> Dict[str, int]:
    """
    Set status for multiple events efficiently.
    
    Args:
        case_id: Case ID
        event_ids: List of OpenSearch document _ids
        status: One of: new, noise, hunted, confirmed
        user_id: User making the change (None for system actions)
        notes: Optional notes about the status change
    
    Returns:
        Dict with 'updated' and 'created' counts
    """
    from models import EventStatus, db
    
    if status not in VALID_STATUSES:
        logger.error(f"[EVENT_STATUS] Invalid status: {status}")
        return {'updated': 0, 'created': 0, 'error': 'Invalid status'}
    
    if not event_ids:
        return {'updated': 0, 'created': 0}
    
    try:
        # Get existing records
        existing = EventStatus.query.filter(
            EventStatus.case_id == case_id,
            EventStatus.event_id.in_(event_ids)
        ).all()
        
        existing_ids = {r.event_id: r for r in existing}
        
        updated_count = 0
        created_count = 0
        now = datetime.utcnow()
        
        for event_id in event_ids:
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
                db.session.add(record)
                created_count += 1
        
        db.session.commit()
        logger.info(f"[EVENT_STATUS] Bulk set {len(event_ids)} events to '{status}': {updated_count} updated, {created_count} created")
        
        return {'updated': updated_count, 'created': created_count}
        
    except Exception as e:
        logger.error(f"[EVENT_STATUS] Bulk set failed: {e}")
        db.session.rollback()
        return {'updated': 0, 'created': 0, 'error': str(e)}


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

