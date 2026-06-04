"""Parser Registry for CaseScope

Central registry that manages all parsers and provides:
- Automatic file type detection
- Parser routing
- Batch processing support
- ClickHouse insertion
"""
import os
import logging
import time
from datetime import datetime
from typing import Dict, List, Type, Optional, Tuple, Generator
from pathlib import Path
from dataclasses import dataclass, field

from parsers.catalog import PARSER_CAPABILITIES_BY_KEY, get_parser_capability_rows
from parsers.base import BaseParser, ParsedEvent, ParseResult

logger = logging.getLogger(__name__)


@dataclass
class FileTypeMapping:
    """Mapping between file patterns and parsers"""
    artifact_type: str
    parser_class: Type[BaseParser]
    extensions: List[str] = field(default_factory=list)
    magic_bytes: List[bytes] = field(default_factory=list)
    filename_patterns: List[str] = field(default_factory=list)
    priority: int = 100  # Lower = higher priority


class ParserRegistry:
    """Central registry for all artifact parsers
    
    Handles:
    - Parser registration
    - File type detection
    - Parser instantiation
    - Batch processing with ClickHouse insertion
    """
    
    def __init__(self):
        self._parsers: Dict[str, FileTypeMapping] = {}
        self._register_default_parsers()
    
    def _register_default_parsers(self):
        """Register all built-in parsers"""
        
        # EVTX Parser
        # Use EvtxECmdParser (EZ Tools + Hayabusa) for full parsing with detection enrichment
        # Falls back to EvtxFallbackParser (pyevtx-rs) if EvtxECmd not installed
        try:
            from parsers.evtx_parser import EvtxECmdParser
            self.register(FileTypeMapping(
                artifact_type='evtx',
                parser_class=EvtxECmdParser,
                extensions=['.evtx'],
                magic_bytes=[b'ElfFile\x00'],
                priority=10,
            ))
            logger.info("Registered EvtxECmdParser for EVTX parsing")
        except (ImportError, FileNotFoundError) as e:
            logger.warning(f"EvtxECmd not available, trying fallback: {e}")
            try:
                from parsers.evtx_parser import EvtxFallbackParser
                self.register(FileTypeMapping(
                    artifact_type='evtx',
                    parser_class=EvtxFallbackParser,
                    extensions=['.evtx'],
                    magic_bytes=[b'ElfFile\x00'],
                    priority=20,
                ))
                logger.info("Registered EvtxFallbackParser for EVTX parsing")
            except ImportError:
                logger.warning("No EVTX parser available")
        
        # Dissect-based parsers
        try:
            from parsers.dissect_parsers import PrefetchParser
            self.register(FileTypeMapping(
                artifact_type='prefetch',
                parser_class=PrefetchParser,
                extensions=['.pf'],
                magic_bytes=[b'SCCA', b'MAM\x04'],
                priority=10,
            ))
        except ImportError as e:
            logger.warning(f"Could not register Prefetch parser: {e}")
        
        try:
            from parsers.dissect_parsers import RegistryParser
            self.register(FileTypeMapping(
                artifact_type='registry',
                parser_class=RegistryParser,
                extensions=['.dat', '.hve', '.hiv'],
                magic_bytes=[b'regf'],
                # Use exact base filenames only (must match the whole filename or filename without extension)
                # This avoids matching substrings like "system" in "SystemSoundsService"
                filename_patterns=[],  # Don't use substring matching for registry
                priority=10,
            ))
        except ImportError as e:
            logger.warning(f"Could not register Registry parser: {e}")
        
        try:
            from parsers.dissect_parsers import LnkParser
            self.register(FileTypeMapping(
                artifact_type='lnk',
                parser_class=LnkParser,
                extensions=['.lnk'],
                magic_bytes=[b'\x4c\x00\x00\x00'],
                priority=10,
            ))
        except ImportError as e:
            logger.warning(f"Could not register LNK parser: {e}")
        
        try:
            from parsers.dissect_parsers import JumpListParser
            self.register(FileTypeMapping(
                artifact_type='jumplist',
                parser_class=JumpListParser,
                extensions=['.automaticdestinations-ms', '.customdestinations-ms'],
                filename_patterns=['customdestinations-ms', 'automaticdestinations-ms'],
                priority=10,
            ))
        except ImportError as e:
            logger.warning(f"Could not register JumpList parser: {e}")
        
        try:
            from parsers.dissect_parsers import MFTParser
            self.register(FileTypeMapping(
                artifact_type='mft',
                parser_class=MFTParser,
                magic_bytes=[b'FILE'],
                filename_patterns=['$mft', 'mft'],
                priority=10,
            ))
        except ImportError as e:
            logger.warning(f"Could not register MFT parser: {e}")

        try:
            from parsers.dissect_parsers import USNParser
            self.register(FileTypeMapping(
                artifact_type='usn',
                parser_class=USNParser,
                filename_patterns=['$usnjrnl:$j', '$extend/$usnjrnl', '$extend\\$usnjrnl', '$j', 'usnjrnl'],
                priority=10,
            ))
        except ImportError as e:
            logger.warning(f"Could not register USN parser: {e}")
        
        try:
            from parsers.dissect_parsers import SRUMParser
            self.register(FileTypeMapping(
                artifact_type='srum',
                parser_class=SRUMParser,
                filename_patterns=['srudb.dat', 'sru.dat'],
                priority=10,
            ))
        except ImportError as e:
            logger.warning(f"Could not register SRUM parser: {e}")
        
        # Log parsers
        try:
            from parsers.log_parsers import IISLogParser
            self.register(FileTypeMapping(
                artifact_type='iis',
                parser_class=IISLogParser,
                filename_patterns=['u_ex', 'w3svc'],
                priority=20,
            ))
        except ImportError as e:
            logger.warning(f"Could not register IIS parser: {e}")
        
        try:
            from parsers.log_parsers import FirewallLogParser
            self.register(FileTypeMapping(
                artifact_type='firewall',
                parser_class=FirewallLogParser,
                filename_patterns=['firewall', 'sonicwall', 'pfsense', 'fw_'],
                priority=30,
            ))
        except ImportError as e:
            logger.warning(f"Could not register Firewall parser: {e}")
        
        try:
            from parsers.log_parsers import HuntressParser
            self.register(FileTypeMapping(
                artifact_type='huntress',
                parser_class=HuntressParser,
                filename_patterns=['huntress'],
                extensions=['.ndjson', '.jsonl'],
                priority=20,
            ))
        except ImportError as e:
            logger.warning(f"Could not register Huntress parser: {e}")
        
        try:
            from parsers.log_parsers import GenericJSONParser
            self.register(FileTypeMapping(
                artifact_type='json_log',
                parser_class=GenericJSONParser,
                extensions=['.json', '.ndjson', '.jsonl'],
                priority=90,  # Low priority - fallback
            ))
        except ImportError as e:
            logger.warning(f"Could not register Generic JSON parser: {e}")

        try:
            from parsers.log_parsers import PowerShellHistoryParser
            self.register(FileTypeMapping(
                artifact_type='powershell_history',
                parser_class=PowerShellHistoryParser,
                filename_patterns=['consolehost_history.txt', '/psreadline/', '\\psreadline\\'],
                priority=15,
            ))
        except ImportError as e:
            logger.warning(f"Could not register PowerShell history parser: {e}")

        try:
            from parsers.log_parsers import HostsFileParser
            self.register(FileTypeMapping(
                artifact_type='hosts',
                parser_class=HostsFileParser,
                filename_patterns=['/drivers/etc/hosts', '\\drivers\\etc\\hosts'],
                priority=10,
            ))
        except ImportError as e:
            logger.warning(f"Could not register hosts parser: {e}")

        try:
            from parsers.log_parsers import SetupApiLogParser
            self.register(FileTypeMapping(
                artifact_type='setupapi',
                parser_class=SetupApiLogParser,
                filename_patterns=['setupapi.dev.log'],
                priority=15,
            ))
        except ImportError as e:
            logger.warning(f"Could not register SetupAPI parser: {e}")
        
        try:
            from parsers.log_parsers import SonicWallCSVParser
            self.register(FileTypeMapping(
                artifact_type='sonicwall',
                parser_class=SonicWallCSVParser,
                extensions=['.csv'],
                filename_patterns=['sonicwall', '_log_'],
                priority=15,  # Higher priority than generic CSV
            ))
        except ImportError as e:
            logger.warning(f"Could not register SonicWall CSV parser: {e}")
        
        try:
            from parsers.log_parsers import CSVLogParser
            self.register(FileTypeMapping(
                artifact_type='csv_log',
                parser_class=CSVLogParser,
                extensions=['.csv'],
                priority=90,  # Low priority - fallback
            ))
        except ImportError as e:
            logger.warning(f"Could not register CSV parser: {e}")

        # Vendor-specific parsers
        vendor_parsers = [
            ('defender_av', 'DefenderAvParser', ['.csv', '.json', '.jsonl', '.ndjson'], ['defender', 'threat'], 18),
            # Do not use bare 'mde' — it matches substrings inside e.g. customdestinations-ms
            ('mde_xdr', 'MdeXdrParser', ['.csv', '.json', '.jsonl', '.ndjson'],
             ['advancedhunting', 'mdexdr', 'defender_xdr', 'microsoft_defender'], 18),
            ('palo_alto', 'PaloAltoParser', ['.csv'], ['palo_alto', 'palo-alto', 'paloalto', 'panos', 'pan-os', 'pan_', 'panw'], 18),
            ('fortigate', 'FortiGateParser', ['.log', '.txt'], ['fortigate', 'fortinet'], 18),
            ('sonicwall_syslog', 'SonicWallSyslogParser', ['.log', '.txt'], ['sonicwall'], 18),
            ('pfsense', 'PfSenseParser', ['.log', '.txt'], ['pfsense', 'opnsense', 'filterlog'], 18),
            ('cisco_asa', 'CiscoAsaParser', ['.log', '.txt'], ['cisco', 'ftd'], 18),
            ('suricata', 'SuricataEveParser', ['.json', '.jsonl', '.ndjson'], ['eve', 'suricata'], 18),
            ('velociraptor', 'VelociraptorParser', ['.csv', '.json', '.jsonl', '.ndjson'], ['velociraptor'], 18),
            ('plaso', 'PlasoParser', ['.csv', '.json', '.jsonl', '.ndjson'], ['plaso', 'log2timeline', 'l2t'], 18),
            ('crowdstrike', 'CrowdStrikeParser', ['.csv', '.json', '.jsonl', '.ndjson'], ['crowdstrike', 'falcon'], 18),
            ('sentinelone', 'SentinelOneParser', ['.csv', '.json', '.jsonl', '.ndjson'], ['sentinelone'], 18),
            ('sophos', 'SophosParser', ['.csv', '.json', '.jsonl', '.ndjson'], ['sophos', 'interceptx'], 18),
        ]
        for artifact_type, class_name, extensions, filename_patterns, priority in vendor_parsers:
            try:
                import parsers.vendor_parsers as vendor_module
                parser_class = getattr(vendor_module, class_name)
                self.register(FileTypeMapping(
                    artifact_type=artifact_type,
                    parser_class=parser_class,
                    extensions=extensions,
                    filename_patterns=filename_patterns,
                    priority=priority,
                ))
            except ImportError as e:
                logger.warning(f"Could not register {artifact_type} parser: {e}")
        
        # Browser parsers
        try:
            from parsers.browser_parsers import BrowserSQLiteParser
            self.register(FileTypeMapping(
                artifact_type='browser',
                parser_class=BrowserSQLiteParser,
                extensions=['.sqlite', '.sqlite3', '.db'],
                filename_patterns=[
                    'places.sqlite', 'cookies.sqlite', 'formhistory.sqlite',
                    'permissions.sqlite', 'downloads.sqlite', 'favicons.sqlite',
                    'history', 'cookies', 'login data', 'web data', 'top sites',
                ],
                priority=15,  # Higher priority than generic SQLite
            ))
        except ImportError as e:
            logger.warning(f"Could not register Browser SQLite parser: {e}")
        
        try:
            from parsers.browser_parsers import FirefoxJSONLZ4Parser
            self.register(FileTypeMapping(
                artifact_type='firefox_session',
                parser_class=FirefoxJSONLZ4Parser,
                extensions=['.jsonlz4', '.mozlz4', '.baklz4'],
                magic_bytes=[b'mozLz40\x00'],
                priority=10,
            ))
        except ImportError as e:
            logger.warning(f"Could not register Firefox JSONLZ4 parser: {e}")
        
        try:
            from parsers.browser_parsers import FirefoxJSONParser
            self.register(FileTypeMapping(
                artifact_type='firefox_json',
                parser_class=FirefoxJSONParser,
                # Uses path-based detection for Firefox profile directories
                filename_patterns=[
                    'handlers.json', 'extensions.json', 'logins.json',
                    'containers.json', 'permissions.json', 'addons.json',
                    'times.json', 'xulstore.json', 'search.json',
                    'signedinuser.json', 'protections.json',
                    'state.json', 'sessioncheckpoints.json',
                    'extension-preferences.json', 'extension-store.json',
                ],
                priority=12,  # Between JSONLZ4 (10) and GenericJSON (90)
            ))
        except ImportError as e:
            logger.warning(f"Could not register Firefox JSON parser: {e}")
        
        # Windows artifact parsers
        try:
            from parsers.windows_parsers import ScheduledTaskParser
            self.register(FileTypeMapping(
                artifact_type='scheduled_task',
                parser_class=ScheduledTaskParser,
                filename_patterns=['/tasks/', '\\tasks\\'],  # Match both path separators
                priority=5,  # High priority - must match before registry for files in Tasks folder
            ))
        except ImportError as e:
            logger.warning(f"Could not register ScheduledTask parser: {e}")
        
        try:
            from parsers.windows_parsers import ActivitiesCacheParser
            self.register(FileTypeMapping(
                artifact_type='activities_cache',
                parser_class=ActivitiesCacheParser,
                filename_patterns=['activitiescache.db'],
                priority=10,
            ))
        except ImportError as e:
            logger.warning(f"Could not register ActivitiesCache parser: {e}")
        
        try:
            from parsers.windows_parsers import WebCacheParser
            self.register(FileTypeMapping(
                artifact_type='webcache',
                parser_class=WebCacheParser,
                filename_patterns=['webcachev01.dat', 'webcachev24.dat'],
                priority=10,
            ))
        except ImportError as e:
            logger.warning(f"Could not register WebCache parser: {e}")

        # KAPE gap parsers: metadata/security events for artifacts not covered above.
        kape_gap_parsers = [
            (
                'recycle_bin', 'RecycleBinParser', [], [],
                ['/$recycle.bin/', '\\$recycle.bin\\', '$i'], 12,
            ),
            (
                'kape_log', 'KapeLogParser', ['.csv'], [],
                ['_copylog', '_skiplog'], 12,
            ),
            (
                'office_autosave', 'OfficeAutosaveParser', ['.asd', '.wbk'], [],
                ['office', 'word', 'autosave'], 25,
            ),
            (
                'windows_search_db', 'WindowsSearchDbParser', ['.db'], [],
                ['/microsoft/search/data/applications/windows/', '\\microsoft\\search\\data\\applications\\windows\\'], 20,
            ),
            (
                'diagnostic_log', 'DiagnosticLogParser',
                ['.etl', '.etlgz', '.odl', '.odlgz', '.loggz', '.aodl', '.odlsent'],
                [], [], 35,
            ),
            (
                'ntfs_metadata', 'NtfsMetadataParser', [], [],
                ['$logfile', '$boot', '$secure_$sds', '$rmmetadata', '$txflog'], 18,
            ),
            (
                'ntfs_log_tracker_export', 'NtfsLogTrackerExportParser',
                ['.csv', '.db', '.sqlite', '.sqlite3'], [],
                ['ntfs_log_tracker', 'ntfs-log-tracker', 'ntfslogtracker', 'ntfs_logfile_events', 'logfile'], 14,
            ),
            (
                'windows_error_report', 'WerReportParser', ['.wer'], [],
                ['/wer/reportarchive/', '/wer/reportqueue/', '\\wer\\reportarchive\\', '\\wer\\reportqueue\\'], 16,
            ),
            (
                'crash_dump_triage', 'CrashDumpTriageParser', ['.dmp'], [b'MDMP', b'PAGE'],
                ['/crashdumps/', '\\crashdumps\\', '/wer/', '\\wer\\'], 30,
            ),
            (
                'wbem_repository', 'WbemRepositoryParser', ['.data', '.btr', '.map'], [],
                ['/wbem/repository/', '\\wbem\\repository\\', 'objects.data', 'index.btr', 'mapping1.map'], 18,
            ),
            (
                'browser_state', 'BrowserStateParser', [], [],
                [
                    '/chrome/user data/', '\\chrome\\user data\\',
                    '/edge/user data/', '\\edge\\user data\\',
                    'preferences', 'bookmarks', 'downloadmetadata',
                    'network persistent state', 'session_', 'tabs_',
                ],
                28,
            ),
            (
                'cloud_metadata', 'CloudMetadataParser', ['.ini', '.txt', '.keystore', '.otc', '.cookie'], [],
                ['/microsoft/onedrive/', '\\microsoft\\onedrive\\'], 28,
            ),
            (
                'transaction_sidecar', 'TransactionSidecarParser',
                ['.log1', '.log2', '.db-wal', '.db-shm', '.db-journal', '.otc-wal', '.otc-shm', '.jfm', '.chk'],
                [], [], 60,
            ),
            (
                'file_triage', 'PayloadTriageParser',
                [
                    '.exe', '.dll', '.sys', '.com', '.scr', '.cpl', '.ocx',
                    '.msi', '.ps1', '.psm1', '.bat', '.cmd', '.vbs', '.vbe',
                    '.js', '.jse', '.wsf', '.hta', '.jar', '.zip', '.7z',
                    '.rar', '.raw', '.bin',
                ],
                [b'MZ', b'PK\x03\x04', b'7z\xbc\xaf'], [], 80,
            ),
        ]
        for artifact_type, class_name, extensions, magic_bytes, filename_patterns, priority in kape_gap_parsers:
            try:
                import parsers.kape_gap_parsers as kape_module
                parser_class = getattr(kape_module, class_name)
                self.register(FileTypeMapping(
                    artifact_type=artifact_type,
                    parser_class=parser_class,
                    extensions=extensions,
                    magic_bytes=magic_bytes,
                    filename_patterns=filename_patterns,
                    priority=priority,
                ))
            except ImportError as e:
                logger.warning(f"Could not register {artifact_type} parser: {e}")
    
    def register(self, mapping: FileTypeMapping):
        """Register a parser mapping"""
        self._parsers[mapping.artifact_type] = mapping
        logger.debug(f"Registered parser: {mapping.artifact_type} -> {mapping.parser_class.__name__}")

    def _collect_candidates(self, file_path: str) -> List[Tuple[int, int, str]]:
        """Return scored parser candidates for a file."""
        if not os.path.isfile(file_path):
            return []

        filename = os.path.basename(file_path).lower()
        extension = os.path.splitext(filename)[1].lower()
        path_lower = file_path.lower()

        if extension in self.EXCLUDED_EXTENSIONS:
            return []
        if filename in self.EXCLUDED_FILENAMES:
            return []

        magic = b''
        try:
            with open(file_path, 'rb') as f:
                magic = f.read(8)
        except Exception:
            pass

        candidates = []
        for artifact_type, mapping in self._parsers.items():
            score = 0

            for mb in mapping.magic_bytes:
                if magic.startswith(mb):
                    score += 100
                    break

            for pattern in mapping.filename_patterns:
                pattern_lower = pattern.lower()
                if pattern_lower in filename or pattern_lower in path_lower:
                    score += 50
                    break

            if extension in mapping.extensions:
                score += 30

            if score > 0:
                candidates.append((score, mapping.priority, artifact_type))

        candidates.sort(key=lambda x: (-x[0], x[1]))
        return candidates
    
    # Files that should never be parsed (transaction logs, temp files, etc.)
    # Note: .log is NOT excluded - IIS logs use .log extension and need to be parsed
    EXCLUDED_EXTENSIONS = {
        '.blf', '.regtrans-ms', '.tmp', '.bak',
        '.map', '.smap', '.tkape', '.mkape',
    }
    
    # Specific filenames to exclude (not registry hives despite magic/extension)
    EXCLUDED_FILENAMES = {'sa.dat'}  # Scheduled Tasks state file
    
    # Path patterns that indicate files should NOT be parsed as registry
    EXCLUDED_PATH_PATTERNS = ['/tasks/', '\\tasks\\']  # Scheduled Task XML files
    
    def detect_type(self, file_path: str) -> Optional[str]:
        """Detect the artifact type of a file
        
        Args:
            file_path: Path to the file
            
        Returns:
            Artifact type string or None if unknown
        """
        candidates = self._collect_candidates(file_path)
        return candidates[0][2] if candidates else None
    
    def get_parser(self, artifact_type: str, case_id: int, source_host: str = '', 
                   case_file_id: Optional[int] = None, case_tz: str = 'UTC',
                   **kwargs) -> Optional[BaseParser]:
        """Get a parser instance for the given artifact type
        
        Args:
            artifact_type: The artifact type to get parser for
            case_id: ClickHouse case_id
            source_host: Hostname
            case_file_id: Optional FK to case_files
            case_tz: Case timezone (IANA identifier) for ambiguous timestamp sources
            **kwargs: Additional parser-specific arguments
            
        Returns:
            Parser instance or None
        """
        mapping = self._parsers.get(artifact_type)
        if not mapping:
            logger.warning(f"No parser registered for artifact type: {artifact_type}")
            return None
        
        try:
            return mapping.parser_class(
                case_id=case_id,
                source_host=source_host,
                case_file_id=case_file_id,
                case_tz=case_tz,
                **kwargs
            )
        except Exception as e:
            logger.error(f"Failed to instantiate parser for {artifact_type}: {e}")
            return None
    
    def get_parser_for_file(self, file_path: str, case_id: int, source_host: str = '',
                           case_file_id: Optional[int] = None, case_tz: str = 'UTC',
                           parser_hints: Optional[List[str]] = None,
                           **kwargs) -> Optional[BaseParser]:
        """Auto-detect file type and get appropriate parser
        
        Args:
            file_path: Path to the file
            case_id: ClickHouse case_id
            source_host: Hostname
            case_file_id: Optional FK to case_files
            case_tz: Case timezone (IANA identifier) for ambiguous timestamp sources
            **kwargs: Additional parser-specific arguments
            
        Returns:
            Parser instance or None
        """
        _artifact_type, parser = self.resolve_parser_for_file(
            file_path=file_path,
            case_id=case_id,
            source_host=source_host,
            case_file_id=case_file_id,
            case_tz=case_tz,
            parser_hints=parser_hints,
            **kwargs
        )
        return parser

    def resolve_parser_for_file(self, file_path: str, case_id: int, source_host: str = '',
                                case_file_id: Optional[int] = None, case_tz: str = 'UTC',
                                parser_hints: Optional[List[str]] = None,
                                **kwargs) -> Tuple[Optional[str], Optional[BaseParser]]:
        """Resolve the first parser candidate that actually accepts the file."""
        hinted_artifact_types: List[str] = []
        seen = set()
        for artifact_type in parser_hints or []:
            if artifact_type in self._parsers and artifact_type not in seen:
                hinted_artifact_types.append(artifact_type)
                seen.add(artifact_type)

        detected_candidates = self._collect_candidates(file_path)
        candidates = []
        for artifact_type in hinted_artifact_types:
            mapping = self._parsers[artifact_type]
            candidates.append((1000, mapping.priority, artifact_type))

        for score, priority, artifact_type in detected_candidates:
            if artifact_type in seen:
                continue
            candidates.append((score, priority, artifact_type))
            seen.add(artifact_type)

        if not candidates:
            logger.warning(f"Could not detect type for file: {file_path}")
            return None, None

        for _score, _priority, artifact_type in candidates:
            parser = self.get_parser(
                artifact_type=artifact_type,
                case_id=case_id,
                source_host=source_host,
                case_file_id=case_file_id,
                case_tz=case_tz,
                **kwargs
            )
            if parser and parser.can_parse(file_path):
                return artifact_type, parser

        logger.warning(
            "No parser accepted %s after candidate detection: %s",
            file_path,
            ', '.join(candidate[2] for candidate in candidates),
        )
        return None, None
    
    def list_parsers(self) -> Dict[str, str]:
        """List all registered parsers
        
        Returns:
            Dict mapping artifact_type to parser class name
        """
        return {k: v.parser_class.__name__ for k, v in self._parsers.items()}

    def list_parser_capabilities(self) -> List[Dict[str, object]]:
        """Return parser metadata aligned with the hunt and storage model."""
        rows = []
        for row in get_parser_capability_rows():
            parser_key = row['parser_key']
            mapping = self._parsers.get(parser_key)
            if mapping:
                row = dict(row)
                row['parser_class'] = mapping.parser_class.__name__
                row['extensions'] = list(mapping.extensions)
                row['filename_patterns'] = list(mapping.filename_patterns)
                row['priority'] = mapping.priority
            rows.append(row)

        for parser_key, mapping in self._parsers.items():
            if parser_key not in PARSER_CAPABILITIES_BY_KEY:
                rows.append({
                    'parser_key': parser_key,
                    'display_name': parser_key.replace('_', ' ').title(),
                    'upload_lane': 'standard',
                    'storage_model': 'events',
                    'default_hunt_tab': 'other',
                    'timezone_behavior': 'utc',
                    'artifact_types': [parser_key],
                    'artifact_types_csv': parser_key,
                    'category': 'other',
                    'user_selectable': False,
                    'upload_label': '',
                    'upload_hint_artifact_types': [],
                    'upload_aliases': [],
                    'parser_class': mapping.parser_class.__name__,
                    'extensions': list(mapping.extensions),
                    'filename_patterns': list(mapping.filename_patterns),
                    'priority': mapping.priority,
                })
        return rows
    
    def parse_file(self, file_path: str, case_id: int, source_host: str = '',
                   case_file_id: Optional[int] = None, case_tz: str = 'UTC',
                   parser_hints: Optional[List[str]] = None,
                   **kwargs) -> Tuple[Optional[str], Generator[ParsedEvent, None, None]]:
        """Parse a file and yield events
        
        Args:
            file_path: Path to the file
            case_id: ClickHouse case_id
            source_host: Hostname
            case_file_id: Optional FK to case_files
            case_tz: Case timezone (IANA identifier) for ambiguous timestamp sources
            
        Returns:
            Tuple of (artifact_type, event generator) or (None, empty generator)
        """
        parser = self.get_parser_for_file(
            file_path=file_path,
            case_id=case_id,
            source_host=source_host,
            case_file_id=case_file_id,
            case_tz=case_tz,
            parser_hints=parser_hints,
            **kwargs
        )
        
        if not parser:
            def empty_gen():
                return
                yield  # Make it a generator
            return None, empty_gen()
        
        return parser.artifact_type, parser.parse(file_path)


class BatchProcessor:
    """Handles batch processing and ClickHouse insertion"""
    
    DEFAULT_BATCH_SIZE = 10000
    
    def __init__(self, clickhouse_client, batch_size: int = None, use_buffer: bool = True):
        """Initialize batch processor
        
        Args:
            clickhouse_client: ClickHouse client instance
            batch_size: Number of events per insert batch
            use_buffer: Use events_buffer table for faster ingestion
        """
        self.client = clickhouse_client
        self.batch_size = batch_size or self.DEFAULT_BATCH_SIZE
        self.table = 'events_buffer' if use_buffer else 'events'
        
        self._batch: List[Tuple] = []
        self._columns = ParsedEvent.clickhouse_columns()
        self._total_inserted = 0
        self._alias_candidates = {}
    
    def add_event(self, event: ParsedEvent):
        """Add an event to the batch
        
        Args:
            event: ParsedEvent to add
        """
        try:
            from utils.privacy_aliases import (
                _merge_candidate_maps,
                extract_alias_candidates_from_event_rows,
            )
            row = {name: getattr(event, name, None) for name in ParsedEvent.clickhouse_columns()}
            candidates = extract_alias_candidates_from_event_rows([row])
            _merge_candidate_maps(self._alias_candidates, candidates)
        except Exception as exc:
            logger.debug("Privacy alias ingest discovery skipped for event: %s", exc)

        self._batch.append(event.to_clickhouse_row())
        
        if len(self._batch) >= self.batch_size:
            self.flush()
    
    def flush(self):
        """Flush current batch to ClickHouse"""
        if not self._batch:
            return
        
        try:
            self.client.insert(
                self.table,
                self._batch,
                column_names=self._columns
            )
            self._total_inserted += len(self._batch)
            if self._alias_candidates:
                try:
                    from utils.privacy_aliases import upsert_alias_candidates

                    case_ids = {row[self._columns.index('case_id')] for row in self._batch if row}
                    if len(case_ids) == 1:
                        upsert_alias_candidates(
                            int(next(iter(case_ids))),
                            self._alias_candidates,
                            source='ingest_structured',
                            commit_every=0,
                        )
                    else:
                        logger.debug("Privacy alias ingest discovery skipped for mixed-case batch")
                except Exception as exc:
                    logger.warning("Privacy alias ingest discovery failed: %s", exc)
                finally:
                    self._alias_candidates = {}
            logger.debug(f"Inserted {len(self._batch)} events (total: {self._total_inserted})")
        except Exception as e:
            logger.error(f"Failed to insert batch: {e}")
            raise
        finally:
            self._batch = []
            if not self._batch:
                self._alias_candidates = {}
    
    @property
    def total_inserted(self) -> int:
        """Total events inserted"""
        return self._total_inserted
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is None:
            self.flush()


_registry_instance = None

def _get_registry():
    """Return a cached ParserRegistry singleton to avoid re-registering parsers per file."""
    global _registry_instance
    if _registry_instance is None:
        _registry_instance = ParserRegistry()
    return _registry_instance


def process_file(file_path: str, case_id: int, source_host: str = '',
                case_file_id: Optional[int] = None, clickhouse_client=None,
                batch_size: int = 10000, case_tz: str = 'UTC',
                parser_hints: Optional[List[str]] = None) -> ParseResult:
    """Process a single file and insert events into ClickHouse
    
    Args:
        file_path: Path to the file
        case_id: ClickHouse case_id
        source_host: Hostname
        case_file_id: Optional FK to case_files
        clickhouse_client: ClickHouse client (optional, uses default if None)
        batch_size: Events per batch
        case_tz: Case timezone (IANA identifier) for ambiguous timestamp sources
        
    Returns:
        ParseResult with processing status
    """
    start_time = time.time()
    registry = _get_registry()
    
    artifact_type, parser = registry.resolve_parser_for_file(
        file_path=file_path,
        case_id=case_id,
        source_host=source_host,
        case_file_id=case_file_id,
        case_tz=case_tz,
        parser_hints=parser_hints,
    )

    if not parser or not artifact_type:
        detected_type = registry.detect_type(file_path)
        if not detected_type:
            return ParseResult(
                success=False,
                file_path=file_path,
                artifact_type='unknown',
                errors=['Could not detect file type'],
                duration_seconds=time.time() - start_time
            )
        return ParseResult(
            success=True,  # Not an error - just no parser for this specific file
            file_path=file_path,
            artifact_type=None,  # Indicates no parser handled it
            events_count=0,
            errors=[],
            warnings=[f'No parser available for this file (detected as {detected_type} but all candidates rejected)'],
            duration_seconds=time.time() - start_time
        )
    
    # Get ClickHouse client
    if clickhouse_client is None:
        from utils.clickhouse import get_fresh_client
        clickhouse_client = get_fresh_client()
    
    # Process file
    events_count = 0
    errors = []
    warnings = []
    
    try:
        with BatchProcessor(clickhouse_client, batch_size=batch_size) as processor:
            for event in parser.parse(file_path):
                processor.add_event(event)
                events_count += 1
        
        # Get total after with block exits (flush is called in __exit__)
        events_count = processor.total_inserted
        errors = parser.errors
        warnings = parser.warnings
        success = len(errors) == 0
        
    except Exception as e:
        logger.exception(f"Error processing file {file_path}")
        if case_file_id:
            try:
                from utils.clickhouse import delete_file_events
                delete_file_events(case_file_id, wait=True)
            except Exception as cleanup_error:
                logger.warning(f"Failed to clean partial ClickHouse rows for case_file_id={case_file_id}: {cleanup_error}")
        if parser and hasattr(parser, 'format_exception'):
            errors.append(parser.format_exception(e))
        else:
            exc_type = e.__class__.__name__
            detail = str(e).strip()
            errors.append(f'{exc_type}: {detail}' if detail else exc_type)
        success = False
    
    return ParseResult(
        success=success,
        file_path=file_path,
        artifact_type=artifact_type,
        events_count=events_count,
        errors=errors,
        warnings=warnings,
        duration_seconds=time.time() - start_time
    )


def process_directory(dir_path: str, case_id: int, source_host: str = '',
                     clickhouse_client=None, recursive: bool = True,
                     file_extensions: List[str] = None) -> List[ParseResult]:
    """Process all files in a directory
    
    Args:
        dir_path: Directory path
        case_id: ClickHouse case_id
        source_host: Hostname
        clickhouse_client: ClickHouse client
        recursive: Process subdirectories
        file_extensions: Filter by extensions (e.g., ['.evtx', '.pf'])
        
    Returns:
        List of ParseResult for each file
    """
    results = []
    
    if clickhouse_client is None:
        from utils.clickhouse import get_fresh_client
        clickhouse_client = get_fresh_client()
    
    # Collect files
    files = []
    if recursive:
        for root, _, filenames in os.walk(dir_path):
            for filename in filenames:
                files.append(os.path.join(root, filename))
    else:
        files = [os.path.join(dir_path, f) for f in os.listdir(dir_path) 
                 if os.path.isfile(os.path.join(dir_path, f))]
    
    # Filter by extension if specified
    if file_extensions:
        ext_set = set(e.lower() for e in file_extensions)
        files = [f for f in files if os.path.splitext(f)[1].lower() in ext_set]
    
    # Process each file
    for file_path in files:
        result = process_file(
            file_path=file_path,
            case_id=case_id,
            source_host=source_host,
            clickhouse_client=clickhouse_client
        )
        results.append(result)
        
        if result.success:
            logger.info(f"Processed {file_path}: {result.events_count} events")
        else:
            logger.warning(f"Failed to process {file_path}: {result.errors}")
    
    return results


# Global registry instance
_registry = None

def get_registry() -> ParserRegistry:
    """Get global parser registry instance"""
    global _registry
    if _registry is None:
        _registry = ParserRegistry()
    return _registry
