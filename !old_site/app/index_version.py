"""
Index Version Tracking and Compatibility Checking

This module tracks the schema version of OpenSearch indices and detects
when code changes require a full re-index due to mapping conflicts.

v1.19.8 - Added to prevent mapping conflicts when code structure changes
"""

import logging
from typing import Dict, Tuple, Optional

logger = logging.getLogger('index_version')

# Current index schema version - increment when EventData/UserData structure changes
CURRENT_INDEX_VERSION = "1.19.8"

# Version history with breaking changes
VERSION_HISTORY = {
    "1.19.8": "EventData/UserData normalized + forensic fields extracted",
    "1.19.3": "Forensic field extraction added",
    "1.13.9": "EventData/UserData converted to JSON strings",
    "1.13.4": "Event structure normalization added",
}


def check_index_compatibility(opensearch_client, case_id: int) -> Tuple[bool, Optional[str], Optional[str]]:
    """
    Check if index is compatible with current code version.
    
    Args:
        opensearch_client: OpenSearch client
        case_id: Case ID to check
        
    Returns:
        Tuple of (is_compatible, current_version, required_version)
        - is_compatible: True if index can be used, False if full re-index needed
        - current_version: Version the index was created with (or None)
        - required_version: Current code version
    """
    from utils import make_index_name
    
    index_name = make_index_name(case_id)
    
    try:
        # Check if index exists
        if not opensearch_client.indices.exists(index=index_name):
            # No index exists - compatible (will be created fresh)
            return True, None, CURRENT_INDEX_VERSION
        
        # Get index settings to check version
        settings = opensearch_client.indices.get_settings(index=index_name)
        index_settings = settings.get(index_name, {}).get('settings', {}).get('index', {})
        stored_version = index_settings.get('casescope_version', None)
        
        if stored_version is None:
            # Old index without version tracking - incompatible
            logger.warning(f"[INDEX VERSION] Index {index_name} has no version - created before v1.19.8")
            return False, "pre-1.19.8", CURRENT_INDEX_VERSION
        
        if stored_version != CURRENT_INDEX_VERSION:
            # Different version - check if breaking change
            logger.warning(f"[INDEX VERSION] Index {index_name} version mismatch: {stored_version} (index) vs {CURRENT_INDEX_VERSION} (code)")
            return False, stored_version, CURRENT_INDEX_VERSION
        
        # Same version - compatible
        return True, stored_version, CURRENT_INDEX_VERSION
        
    except Exception as e:
        logger.error(f"[INDEX VERSION] Error checking compatibility: {e}")
        # On error, assume incompatible to be safe
        return False, "unknown", CURRENT_INDEX_VERSION


def set_index_version(opensearch_client, case_id: int) -> bool:
    """
    Set the schema version on an index after creation.
    
    Args:
        opensearch_client: OpenSearch client
        case_id: Case ID
        
    Returns:
        bool: True if version was set successfully
    """
    from utils import make_index_name
    
    index_name = make_index_name(case_id)
    
    try:
        # Wait for index to be created (it's created on first document insert)
        if opensearch_client.indices.exists(index=index_name):
            opensearch_client.indices.put_settings(
                index=index_name,
                body={
                    "index.casescope_version": CURRENT_INDEX_VERSION
                }
            )
            logger.info(f"[INDEX VERSION] Set version {CURRENT_INDEX_VERSION} on index {index_name}")
            return True
        return False
    except Exception as e:
        logger.error(f"[INDEX VERSION] Error setting version: {e}")
        return False


def get_compatibility_warning(current_version: Optional[str], required_version: str) -> Dict[str, str]:
    """
    Generate user-friendly warning message about version incompatibility.
    
    Args:
        current_version: Version the index was created with
        required_version: Current code version
        
    Returns:
        Dict with 'title' and 'message' for display
    """
    if current_version is None or current_version == "pre-1.19.8":
        reason = "Index created before version tracking was implemented"
    elif current_version == "unknown":
        reason = "Unable to determine index version"
    else:
        current_desc = VERSION_HISTORY.get(current_version, "Unknown changes")
        required_desc = VERSION_HISTORY.get(required_version, "Current version")
        reason = f"Index structure changed:\n• Index version: {current_version} ({current_desc})\n• Code version: {required_version} ({required_desc})"
    
    return {
        'title': 'Index Version Mismatch Detected',
        'message': f"""⚠️ The OpenSearch index for this case is out of sync with the current code version.

{reason}

**Why this matters:**
When code changes how events are structured (like EventData/UserData formatting), existing indices may have incompatible field mappings that prevent new events from indexing correctly.

**Your options:**
1. **Full Re-Index** (Recommended): Re-index ALL files in this case to rebuild the index with the correct structure
2. **Cancel**: Keep existing index (files may fail to index or have partial data)

**Note**: This is not an error - it just means the index was created with an older code version and needs to be rebuilt for compatibility."""
    }

