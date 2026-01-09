"""CaseScope Parsers Package

Provides modular artifact parsing with automatic type detection.

Usage:
    from parsers import get_registry, process_file, process_directory
    
    # Auto-detect and process a single file
    result = process_file('/path/to/Security.evtx', case_id=123)
    
    # Process all files in a directory
    results = process_directory('/path/to/artifacts/', case_id=123)
    
    # Manual parser usage
    registry = get_registry()
    parser = registry.get_parser_for_file('/path/to/file.evtx', case_id=123)
    for event in parser.parse('/path/to/file.evtx'):
        print(event)

Available Parsers:
    - evtx: Windows Event Logs (Hayabusa with Sigma detection)
    - prefetch: Windows Prefetch files
    - registry: Windows Registry hives
    - lnk: Windows LNK shortcuts
    - jumplist: Windows Jump Lists
    - mft: NTFS MFT entries
    - srum: Windows SRUM database
    - iis: IIS Web Server logs
    - firewall: Firewall/syslog format logs
    - huntress: Huntress EDR exports
    - json_log: Generic JSON/NDJSON logs
    - csv_log: Generic CSV logs
    - browser: Browser SQLite databases (Firefox, Chrome, Edge)
      - History (places.sqlite, History)
      - Cookies
      - Downloads
      - Form data / Autofill
      - Logins
    - firefox_session: Firefox JSONLZ4 compressed files
      - Session data (tabs, windows)
      - Search engines
      - Extensions/Addons
      - Protocol handlers
    - scheduled_task: Windows Task Scheduler XML files
      - Task definitions (triggers, actions, commands)
      - Persistence analysis
    - activities_cache: Windows Timeline ActivitiesCache.db
      - Application usage history
      - File access history
      - Focus time data
    - webcache: IE/Edge WebCache ESE database
      - Browsing history
      - Cookies, downloads, cache
"""

from parsers.base import BaseParser, ParsedEvent, ParseResult
from parsers.registry import (
    ParserRegistry,
    get_registry,
    process_file,
    process_directory,
    BatchProcessor,
    FileTypeMapping,
)

__all__ = [
    # Base classes
    'BaseParser',
    'ParsedEvent',
    'ParseResult',
    
    # Registry
    'ParserRegistry',
    'get_registry',
    'FileTypeMapping',
    
    # Processing functions
    'process_file',
    'process_directory',
    'BatchProcessor',
]

# Version
__version__ = '1.0.0'
