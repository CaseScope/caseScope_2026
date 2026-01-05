"""
Parser Routing Utility
======================
Maps parser types to OpenSearch indices and determines parsing logic
"""

# Index routing for each parser type
PARSER_INDEX_MAP = {
    # Main events index (case_X)
    'evtx': 'events',
    'ndjson': 'events',
    'edr': 'events',
    'firewall': 'events',
    'wmi': 'events',
    'pst': 'events',
    'notifications': 'events',
    'schtasks': 'events',
    'teams_skype': 'events',
    
    # Browser index (case_X_browser)
    'browser_history': 'browser',
    'webcache': 'browser',
    
    # Execution index (case_X_execution)
    'prefetch': 'execution',
    'activities': 'execution',
    'jumplist': 'execution',
    'lnk': 'execution',
    
    # Filesystem index (case_X_filesystem)
    'mft': 'filesystem',
    'thumbcache': 'filesystem',
    'winsearch': 'filesystem',
    'rdp_cache': 'filesystem',
    
    # Network index (case_X_network)
    'bits': 'network',
    'srum': 'network',  # SRUM has both network and execution, network is primary
    
    # Devices index (case_X_devices)
    'usb': 'devices',
    'setupapi': 'devices',
    
    # Cloud index (case_X_cloud)
    'onedrive': 'cloud',
}


def get_index_name(parser_type: str, case_id: int) -> str:
    """
    Get the full index name for a parser type
    
    Args:
        parser_type: Parser type (e.g., 'thumbcache', 'bits')
        case_id: Case ID number
    
    Returns:
        Full index name (e.g., 'case_4_filesystem')
    """
    index_suffix = PARSER_INDEX_MAP.get(parser_type, 'events')
    
    if index_suffix == 'events':
        return f'case_{case_id}'
    else:
        return f'case_{case_id}_{index_suffix}'


def get_parser_info(parser_type: str) -> dict:
    """
    Get information about a parser
    
    Returns:
        dict with index_suffix, description, etc.
    """
    descriptions = {
        # Existing parsers
        'evtx': 'Windows Event Logs',
        'ndjson': 'EDR/NDJSON Logs',
        'firewall': 'Firewall Logs',
        'browser_history': 'Browser History',
        'webcache': 'WebCache (IE/Edge)',
        'prefetch': 'Prefetch Files',
        'srum': 'SRUM Database',
        'mft': 'Master File Table',
        'jumplist': 'Jump Lists',
        'lnk': 'LNK Shortcuts',
        'setupapi': 'SetupAPI Device Logs',
        
        # New parsers
        'thumbcache': 'Thumbnail Cache',
        'bits': 'BITS Transfers',
        'winsearch': 'Windows Search Index',
        'activities': 'Windows Timeline',
        'notifications': 'Windows Notifications',
        'rdp_cache': 'RDP Bitmap Cache',
        'wmi': 'WMI Persistence',
        'pst': 'Outlook PST/OST',
        'schtasks': 'Scheduled Tasks',
        'teams_skype': 'Teams/Skype',
        'usb': 'USB Device History',
        'onedrive': 'OneDrive Sync',
    }
    
    return {
        'index_suffix': PARSER_INDEX_MAP.get(parser_type, 'events'),
        'description': descriptions.get(parser_type, 'Unknown'),
        'parser_type': parser_type
    }


__all__ = ['PARSER_INDEX_MAP', 'get_index_name', 'get_parser_info']

