"""
Event Deduplication Module
Generates deterministic OpenSearch document IDs to prevent duplicate events
"""

import hashlib
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)


def generate_event_document_id(
    case_id: int,
    event: Dict[str, Any]
) -> str:
    """
    Generate deterministic OpenSearch document _id for event deduplication
    
    Strategy: EventData Hash + Normalized Fields (HIGH ACCURACY ~99%+)
    
    Uses EventData hash instead of EventRecordID because:
    - EventRecordID is unique per log file, not globally → causes false positives
    - EventData hash ensures same event content = same ID across all files
    - v1.32.0: Uses milliseconds precision to avoid false deduplication on high-frequency logs
    
    This ensures:
    - Same event from different files gets same _id → OpenSearch deduplicates automatically
    - Works across all indices in a case
    - Backward compatible (can be enabled/disabled)
    - High accuracy: ~99%+ (very few false positives/negatives)
    
    Args:
        case_id: Case ID
        event: Event dictionary (should have normalized fields)
    
    Returns:
        Deterministic document ID string
    """
    import json
    
    # Get normalized fields (should be added by normalize_event())
    normalized_ts = event.get('normalized_timestamp', '')
    # v1.32.0 FIX: Use milliseconds precision to avoid false deduplication
    # Previous: truncated to seconds caused ~25% event loss on high-frequency logs
    # Now: use full timestamp with milliseconds (first 23 chars = YYYY-MM-DDTHH:MM:SS.mmm)
    normalized_ts_ms = normalized_ts[:23] if normalized_ts and len(normalized_ts) >= 23 else (normalized_ts[:19] if normalized_ts and len(normalized_ts) >= 19 else (normalized_ts or 'unknown'))
    normalized_computer = event.get('normalized_computer', 'unknown')
    normalized_event_id = event.get('normalized_event_id', 'unknown')
    
    # Extract EventData (core event content - this is what makes events unique)
    event_data = {}
    try:
        # Priority 1: Direct EventData field
        if 'EventData' in event:
            event_data = event['EventData']
        # Priority 2: Event.EventData (nested structure)
        elif 'Event' in event and isinstance(event['Event'], dict):
            event_data = event['Event'].get('EventData', {})
        # Priority 3: For CSV/IIS/non-Windows events, use all event fields except metadata
        elif event.get('source_file_type') in ['CSV', 'IIS']:
            # For CSV and IIS, exclude metadata fields and use content fields
            # v1.14.0: IIS logs also exclude 'System' block (artificially added for timestamp normalization)
            exclude_fields = {'source_file', 'source_file_type', 'normalized_timestamp', 
                            'normalized_computer', 'normalized_event_id', 'indexed_at', 
                            'System', 'row_number', 'file_id', 'opensearch_key', 
                            'has_ioc', 'has_sigma'}
            event_data = {k: v for k, v in event.items() if k not in exclude_fields}
    except Exception as e:
        logger.debug(f"[DEDUP] Could not extract EventData: {e}")
    
    # Create normalized hash of EventData
    # Sort keys for consistency (same data = same hash regardless of field order)
    try:
        if event_data:
            event_data_json = json.dumps(event_data, sort_keys=True, default=str)
            event_data_hash = hashlib.sha256(event_data_json.encode()).hexdigest()[:16]
        else:
            # Fallback: hash of normalized fields if no EventData
            fallback_str = f"{normalized_ts_ms}|{normalized_computer}|{normalized_event_id}"
            event_data_hash = hashlib.sha256(fallback_str.encode()).hexdigest()[:16]
    except Exception as e:
        logger.warning(f"[DEDUP] Error creating EventData hash: {e}")
        # Final fallback: hash of entire event (less accurate but safe)
        event_str = json.dumps(event, sort_keys=True, default=str)
        event_data_hash = hashlib.sha256(event_str.encode()).hexdigest()[:16]
    
    # Build deterministic ID: case + event_id + computer + normalized_timestamp + event_data_hash
    id_parts = [
        f"case_{case_id}",
        f"evt_{normalized_event_id}",
        normalized_computer,
        normalized_ts_ms,  # v1.32.0: Now uses milliseconds precision
        event_data_hash
    ]
    doc_id = '_'.join(str(p) for p in id_parts if p)
    
    # Sanitize for OpenSearch _id (no special chars, max 512 bytes)
    doc_id = doc_id.replace('/', '_').replace('\\', '_').replace(':', '_').replace(' ', '_')
    doc_id = doc_id[:200]  # Well within OpenSearch 512 byte limit
    
    return doc_id


def should_deduplicate_events(case_id: Optional[int] = None) -> bool:
    """
    Check if event deduplication should be enabled
    
    Can be configured per-case or globally via:
    - Case model: deduplicate_events field (if added)
    - Config: DEDUPLICATE_EVENTS setting
    - Default: False (backward compatible)
    
    Args:
        case_id: Optional case ID to check case-specific setting
    
    Returns:
        True if deduplication should be enabled
    """
    # TODO: Add Case.deduplicate_events field if needed
    # For now, can be enabled via config or environment variable
    try:
        from config import Config
        return getattr(Config, 'DEDUPLICATE_EVENTS', False)
    except:
        return False

