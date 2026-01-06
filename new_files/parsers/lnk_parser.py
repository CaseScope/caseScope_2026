"""
Windows LNK (Shortcut) Parser
==============================
Parses Windows shortcut (.lnk) files
Routes to: case_X_execution index

Uses LnkParse3 library

Extracts:
- Target file path
- Working directory
- Command line arguments
- Creation, modification, access times
- File attributes
- Drive information
"""

import os
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

try:
    from LnkParse3 import lnk_file
    LNK_AVAILABLE = True
except ImportError:
    logger.warning("LnkParse3 not available - LNK parsing will be skipped")
    LNK_AVAILABLE = False


def parse_lnk_file(file_path):
    """
    Parse Windows LNK (shortcut) file
    
    Yields events from LNK file
    """
    if not LNK_AVAILABLE:
        logger.error("LnkParse3 not available - cannot parse LNK")
        return
    
    if not os.path.exists(file_path):
        logger.error(f"LNK file not found: {file_path}")
        return
    
    filename = os.path.basename(file_path)
    
    try:
        # Parse LNK file
        with open(file_path, 'rb') as f:
            lnk = lnk_file(f)
        
        # Extract basic information
        event = {
            'event_type': 'lnk_shortcut',
            'artifact_type': 'lnk',
            'source_file': filename
        }
        
        # Get header information
        if hasattr(lnk, 'header'):
            header = lnk.header
            
            # Timestamps (check if they're methods or attributes)
            if hasattr(header, 'creation_time'):
                ct = header.creation_time() if callable(header.creation_time) else header.creation_time
                if ct:
                    event['creation_time'] = ct.isoformat()
                    event['@timestamp'] = ct.isoformat()
            
            if hasattr(header, 'modification_time'):
                mt = header.modification_time() if callable(header.modification_time) else header.modification_time
                if mt:
                    event['modification_time'] = mt.isoformat()
            
            if hasattr(header, 'access_time'):
                at = header.access_time() if callable(header.access_time) else header.access_time
                if at:
                    event['access_time'] = at.isoformat()
            
            # File attributes (check if methods or properties)
            if hasattr(header, 'file_size'):
                fs = header.file_size() if callable(header.file_size) else header.file_size
                if fs is not None:
                    event['target_file_size'] = fs
            
            if hasattr(header, 'icon_index'):
                ii = header.icon_index() if callable(header.icon_index) else header.icon_index
                if ii is not None:
                    event['icon_index'] = ii
        
        # Get link target information
        if hasattr(lnk, 'link_info') and lnk.link_info:
            link_info = lnk.link_info
            
            if hasattr(link_info, 'local_base_path') and link_info.local_base_path:
                event['target_path'] = link_info.local_base_path
            
            if hasattr(link_info, 'location_info') and link_info.location_info:
                loc = link_info.location_info
                if hasattr(loc, 'local_volume') and loc.local_volume:
                    vol = loc.local_volume
                    event['drive_type'] = vol.drive_type if hasattr(vol, 'drive_type') else None
                    event['drive_serial'] = vol.drive_serial_number if hasattr(vol, 'drive_serial_number') else None
                    event['volume_label'] = vol.volume_label if hasattr(vol, 'volume_label') else None
        
        # Get string data (paths, arguments, etc.)
        if hasattr(lnk, 'string_data') and lnk.string_data:
            string_data = lnk.string_data
            
            # Check if methods or attributes, and call accordingly
            def get_string_value(obj, attr_name):
                if hasattr(obj, attr_name):
                    val = getattr(obj, attr_name)
                    return val() if callable(val) else val
                return None
            
            name_val = get_string_value(string_data, 'name_string')
            if name_val:
                event['name'] = name_val
            
            rel_path = get_string_value(string_data, 'relative_path')
            if rel_path:
                event['relative_path'] = rel_path
            
            work_dir = get_string_value(string_data, 'working_directory')
            if work_dir:
                event['working_directory'] = work_dir
            
            args = get_string_value(string_data, 'command_line_arguments')
            if args:
                event['arguments'] = args
            
            icon_loc = get_string_value(string_data, 'icon_location')
            if icon_loc:
                event['icon_location'] = icon_loc
        
        # Get extra data (tracker info, etc.)
        if hasattr(lnk, 'extras'):
            extras = lnk.extras
            
            # Distributed Link Tracker
            if hasattr(extras, 'DISTRIBUTED_LINK_TRACKER_BLOCK') and extras.DISTRIBUTED_LINK_TRACKER_BLOCK:
                tracker = extras.DISTRIBUTED_LINK_TRACKER_BLOCK
                if hasattr(tracker, 'machine_identifier'):
                    event['machine_identifier'] = tracker.machine_identifier
                if hasattr(tracker, 'droid_volume_identifier'):
                    event['droid_volume_id'] = tracker.droid_volume_identifier
                if hasattr(tracker, 'droid_file_identifier'):
                    event['droid_file_id'] = tracker.droid_file_identifier
        
        # Set default timestamp if not set
        if '@timestamp' not in event:
            event['@timestamp'] = datetime.utcnow().isoformat()
        
        logger.info(f"Parsed LNK: {filename}")
        
        yield event
    
    except Exception as e:
        logger.error(f"Error parsing LNK {file_path}: {e}")
        import traceback
        traceback.print_exc()

