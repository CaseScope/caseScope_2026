"""
CaseScope Parsers Module
========================
Collection of forensic artifact parsers for Windows evidence.

All parsers follow the same interface:
- parse_<type>_file(file_path) -> Generator[dict]
- Each yields events with @timestamp and source_file fields

EXISTING PARSERS:
- evtx_parser: Windows Event Logs
- eztools_evtx_parser: EVTX via EZ Tools
- eztools_mft_parser: MFT via EZ Tools
- eztools_jumplist_parser: Jump Lists via EZ Tools
- eztools_lnk_parser: LNK files via EZ Tools
- dissect_prefetch_parser: Prefetch files
- browser_history_parser: Chrome/Firefox/Edge history
- webcache_parser: IE/Edge WebCache ESE
- srum_parser: SRUM database
- setupapi_parser: setupapi.dev.log
- lnk_parser: LNK shortcut files
- firewall_csv_parser: Firewall CSV logs
- ndjson_parser: EDR NDJSON logs

NEW PARSERS (v2.0):
- thumbcache_parser: Windows thumbnail cache
- bits_parser: BITS background transfer database
- winsearch_parser: Windows Search (Windows.edb)
- activities_parser: Windows Timeline (ActivitiesCache.db)
- notifications_parser: Windows Push Notifications
- rdp_cache_parser: RDP Bitmap Cache
- wmi_parser: WMI Repository persistence
- pst_parser: Outlook PST/OST email archives
- schtasks_parser: Scheduled Tasks XML
- teams_skype_parser: Teams/Skype communications
- usb_history_parser: USB device history
- onedrive_parser: OneDrive sync logs/databases
"""

# Parser mapping for auto-detection (lazy imports to avoid circular dependencies)
PARSER_MAP = {
    'evtx': 'evtx_parser.parse_evtx_file',
    'prefetch': 'dissect_prefetch_parser.parse_prefetch_file',
    'mft': 'eztools_mft_parser.parse_mft_with_eztools',
    'jumplist': 'eztools_jumplist_parser.parse_jumplist_with_eztools',
    'lnk': 'lnk_parser.parse_lnk_file',
    'thumbcache': 'thumbcache_parser.parse_thumbcache_file',
    'browser_history': 'browser_history_parser.parse_browser_history_file',
    'webcache': 'webcache_parser.parse_webcache_file',
    'srum': 'srum_parser.parse_srum_file',
    'bits': 'bits_parser.parse_bits_file',
    'winsearch': 'winsearch_parser.parse_windows_search_file',
    'activities': 'activities_parser.parse_activities_cache_file',
    'notifications': 'notifications_parser.parse_notifications_file',
    'rdp_cache': 'rdp_cache_parser.parse_rdp_cache_file',
    'pst': 'pst_parser.parse_pst_file',
    'teams_skype': 'teams_skype_parser.parse_teams_skype_file',
    'onedrive': 'onedrive_parser.parse_onedrive_file',
    'wmi': 'wmi_parser.parse_wmi_file',
    'schtasks': 'schtasks_parser.parse_scheduled_task_file',
    'setupapi': 'setupapi_parser.parse_setupapi_file',
    'usb': 'usb_history_parser.parse_usb_file',
    'firewall': 'firewall_csv_parser.parse_firewall_csv_file',
    'ndjson': 'ndjson_parser.parse_ndjson_file',
    'edr': 'ndjson_parser.parse_ndjson_file',
}


def get_parser(parser_type: str):
    """
    Get parser function by type name (lazy loading)
    
    Args:
        parser_type: Parser type string
    
    Returns:
        Parser function or None if not found
    """
    import importlib
    
    parser_path = PARSER_MAP.get(parser_type.lower())
    if not parser_path:
        return None
    
    module_name, func_name = parser_path.rsplit('.', 1)
    
    try:
        module = importlib.import_module(f'.{module_name}', package='parsers')
        return getattr(module, func_name)
    except (ImportError, AttributeError) as e:
        import logging
        logging.getLogger(__name__).error(f"Failed to load parser {parser_type}: {e}")
        return None


def detect_parser_type(filename: str, parent_dir: str = '') -> str:
    """
    Detect parser type from filename and path
    
    Args:
        filename: File name
        parent_dir: Parent directory name (for context)
    
    Returns:
        Parser type string
    """
    filename_lower = filename.lower()
    parent_lower = parent_dir.lower() if parent_dir else ''
    
    # Event logs
    if filename_lower.endswith('.evtx'):
        return 'evtx'
    
    # Prefetch
    if filename_lower.endswith('.pf'):
        return 'prefetch'
    
    # Jump Lists
    if filename_lower.endswith('.automaticdestinations-ms') or filename_lower.endswith('.customdestinations-ms'):
        return 'jumplist'
    
    # LNK files
    if filename_lower.endswith('.lnk'):
        return 'lnk'
    
    # Thumbcache
    if 'thumbcache' in filename_lower and filename_lower.endswith('.db'):
        return 'thumbcache'
    
    # Browser history
    if filename_lower == 'history' or filename_lower == 'places.sqlite':
        return 'browser_history'
    
    # WebCache
    if 'webcache' in filename_lower and filename_lower.endswith('.dat'):
        return 'webcache'
    
    # SRUM
    if 'srudb' in filename_lower and filename_lower.endswith('.dat'):
        return 'srum'
    
    # BITS
    if filename_lower == 'qmgr.db' or filename_lower in ['qmgr0.dat', 'qmgr1.dat']:
        return 'bits'
    
    # Windows Search
    if filename_lower == 'windows.edb':
        return 'winsearch'
    
    # Activities Cache (Windows Timeline)
    if 'activitiescache' in filename_lower and filename_lower.endswith('.db'):
        return 'activities'
    
    # Notifications
    if 'wpndatabase' in filename_lower and filename_lower.endswith('.db'):
        return 'notifications'
    
    # RDP Cache
    if filename_lower.startswith('cache') and filename_lower.endswith('.bin'):
        return 'rdp_cache'
    if filename_lower.endswith('.bmc') or 'bcache' in filename_lower:
        return 'rdp_cache'
    
    # PST/OST
    if filename_lower.endswith('.pst') or filename_lower.endswith('.ost'):
        return 'pst'
    
    # Teams/Skype
    if 'skype' in parent_lower and filename_lower == 'main.db':
        return 'teams_skype'
    if 'teams' in parent_lower and (filename_lower.endswith('.db') or filename_lower.endswith('.ldb')):
        return 'teams_skype'
    
    # OneDrive
    if 'onedrive' in parent_lower or filename_lower.endswith('.odl') or filename_lower.endswith('.odlgz'):
        return 'onedrive'
    
    # WMI
    if filename_lower == 'objects.data' or filename_lower == 'index.btr':
        return 'wmi'
    
    # Scheduled Tasks (XML without extension often)
    if 'tasks' in parent_lower and '.' not in filename_lower:
        return 'schtasks'
    if filename_lower.endswith('.xml') and 'task' in parent_lower:
        return 'schtasks'
    
    # USB/Device history
    if 'setupapi' in filename_lower:
        return 'usb'
    
    # Generic detections
    if filename_lower.endswith('.csv'):
        return 'firewall'
    if filename_lower.endswith(('.ndjson', '.jsonl')):
        return 'ndjson'
    
    return 'unknown'


__all__ = [
    'PARSER_MAP',
    'get_parser',
    'detect_parser_type',
]
