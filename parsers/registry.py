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
from typing import Dict, List, Type, Optional, Tuple, Any
from pathlib import Path
from dataclasses import dataclass, field

from parsers.base import BaseParser, ParsedEvent, ParseResult
from utils.ingest_fence import (
    IngestAdmissionDenied,
    IngestExclusiveTimeout,
    IngestFenceLost,
    IngestFenceUnavailable,
    shared_ingest_admission,
)
from utils.ingest_metrics import emit_metric, estimate_rows_bytes, timed_stage

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
            from parsers.log_parsers import GenericWeblogParser
            self.register(FileTypeMapping(
                artifact_type='generic_weblog',
                parser_class=GenericWeblogParser,
                extensions=['.log'],
                filename_patterns=['access_log', 'access.log', 'access-log'],
                priority=40,
            ))
        except ImportError as e:
            logger.warning(f"Could not register generic weblog parser: {e}")
        
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

        try:
            from parsers.sum_parser import SumParser
            self.register(FileTypeMapping(
                artifact_type='sum',
                parser_class=SumParser,
                extensions=['.mdb'],
                filename_patterns=['systemidentity.mdb', 'current.mdb', '/logfiles/sum/', '\\logfiles\\sum\\'],
                priority=9,
            ))
        except ImportError as e:
            logger.warning(f"Could not register SUM parser: {e}")

        try:
            from parsers import rmm_parsers
            for artifact_type, class_name, patterns in [
                ('rmm_anydesk', 'AnyDeskTraceParser', ['anydesk', 'ad.trace', 'ad_svc.trace', 'connection_trace.txt']),
                ('rmm_teamviewer', 'TeamViewerLogParser', ['teamviewer', 'connections_incoming.txt', 'teamviewer_logfile']),
                ('rmm_screenconnect', 'ScreenConnectLogParser', ['screenconnect', 'connectwise control', 'connectwisecontrol']),
            ]:
                self.register(FileTypeMapping(
                    artifact_type=artifact_type,
                    parser_class=getattr(rmm_parsers, class_name),
                    extensions=['.log', '.txt', '.trace'],
                    filename_patterns=patterns,
                    priority=12,
                ))
        except ImportError as e:
            logger.warning(f"Could not register RMM parsers: {e}")

        try:
            from parsers import av_artifact_parsers
            for artifact_type, class_name, extensions, patterns in [
                ('defender_detectionhistory', 'DefenderDetectionHistoryParser', [], ['/detectionhistory/', '\\detectionhistory\\']),
                ('defender_mplog', 'MpLogParser', ['.log', '.txt'], ['mplog']),
            ]:
                self.register(FileTypeMapping(
                    artifact_type=artifact_type,
                    parser_class=getattr(av_artifact_parsers, class_name),
                    extensions=extensions,
                    filename_patterns=patterns,
                    priority=12,
                ))
        except ImportError as e:
            logger.warning(f"Could not register Defender artifact parsers: {e}")

        try:
            from parsers import windows_artifact_parsers as win_gap
            windows_gap_parsers = [
                ('pca_execution', 'PcaParser', ['.txt'], ['pcaapplaunchdic.txt', 'pcageneraldb', '/appcompat/pca/', '\\appcompat\\pca\\'], 10),
                ('notepad_tabstate', 'NotepadTabStateParser', ['.bin'], ['/tabstate/', '\\tabstate\\'], 10),
                ('powershell_transcript', 'PowerShellTranscriptParser', ['.txt'], ['powershell_transcript'], 10),
                ('windows_notifications', 'WindowsNotificationsParser', ['.db'], ['wpndatabase.db'], 10),
                ('eventtranscript', 'EventTranscriptDbParser', ['.db'], ['eventtranscript.db'], 10),
                ('copilot_recall', 'CopilotRecallParser', ['.db', '.sqlite'], ['recall', '/coreai/', '\\coreai\\'], 12),
                ('bits_queue', 'BitsParser', ['.db', '.dat'], ['qmgr.db', 'qmgr0.dat', 'qmgr1.dat'], 10),
                ('recentfilecache', 'RecentFileCacheParser', ['.bcf'], ['recentfilecache.bcf'], 10),
                ('schedlgu', 'SchedLgUParser', ['.txt'], ['schedlgu.txt'], 10),
                ('startupinfo', 'StartupInfoParser', ['.xml'], ['/startupinfo/', '\\startupinfo\\'], 10),
                ('netclr_usage', 'NetClrUsageLogParser', ['.log'], ['/usage logs/', '\\usage logs\\', 'clr_v'], 10),
                ('thumb_icon_cache', 'ThumbcacheIconcacheParser', ['.db'], ['thumbcache_', 'iconcache_'], 10),
                ('rdp_bitmap_cache', 'RdpBitmapCacheParser', ['.bin'], ['terminal server client/cache', 'terminal server client\\cache'], 10),
                ('registry_pol', 'RegistryPolParser', ['.pol'], ['registry.pol'], 10),
                ('mof_file', 'MofParser', ['.mof'], ['/wbem/mof', '\\wbem\\mof'], 10),
                ('shim_database', 'SdbParser', ['.sdb'], ['.sdb'], 10),
                ('sensitive_windows_file', 'SensitiveWindowsFileParser', ['.dit', '.sys'], ['ntds.dit', 'hiberfil.sys', 'pagefile.sys', 'swapfile.sys'], 6),
                ('windows_server_log', 'WindowsServerLogParser', ['.log'], ['exchange', 'dns.log', 'dhcp'], 22),
            ]
            for artifact_type, class_name, extensions, patterns, priority in windows_gap_parsers:
                self.register(FileTypeMapping(
                    artifact_type=artifact_type,
                    parser_class=getattr(win_gap, class_name),
                    extensions=extensions,
                    filename_patterns=patterns,
                    priority=priority,
                ))
        except ImportError as e:
            logger.warning(f"Could not register Windows gap parsers: {e}")

        try:
            from parsers import linux_parsers
            linux_gap_parsers = [
                ('linux_syslog', 'LinuxSyslogAuthParser', ['.log'], ['auth.log', '/var/log/secure', '/var/log/syslog', '/var/log/messages'], 20),
                ('linux_utmp', 'LinuxUtmpParser', [], ['wtmp', 'btmp', 'utmp', 'lastlog'], 10),
                ('linux_journal', 'LinuxJournalParser', ['.journal'], ['.journal'], 10),
                ('linux_cron', 'LinuxCronParser', [], ['/cron.', '/cron/', '/spool/cron/', 'crontab'], 10),
                ('linux_ssh', 'LinuxSshArtifactParser', [], ['/.ssh/', 'authorized_keys', 'known_hosts', 'sshd_config', 'ssh_config'], 10),
                ('linux_shell_history', 'LinuxShellHistoryParser', [], ['.bash_history', '.zsh_history', '.sh_history', 'bash_history', 'zsh_history'], 10),
            ]
            for artifact_type, class_name, extensions, patterns, priority in linux_gap_parsers:
                self.register(FileTypeMapping(
                    artifact_type=artifact_type,
                    parser_class=getattr(linux_parsers, class_name),
                    extensions=extensions,
                    filename_patterns=patterns,
                    priority=priority,
                ))
        except ImportError as e:
            logger.warning(f"Could not register Linux parsers: {e}")

        try:
            from parsers import macos_parsers
            macos_gap_parsers = [
                ('macos_plist', 'MacPlistParser', ['.plist'], ['.plist', '/launchagents/', '/launchdaemons/', '/startupitems/'], 10),
                ('macos_fsevents', 'MacFseventsdParser', [], ['/.fseventsd/'], 10),
                ('macos_asl', 'MacAslParser', ['.asl', '.tracev3'], ['.asl', '.tracev3'], 10),
            ]
            for artifact_type, class_name, extensions, patterns, priority in macos_gap_parsers:
                self.register(FileTypeMapping(
                    artifact_type=artifact_type,
                    parser_class=getattr(macos_parsers, class_name),
                    extensions=extensions,
                    filename_patterns=patterns,
                    priority=priority,
                ))
        except ImportError as e:
            logger.warning(f"Could not register macOS parsers: {e}")

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
            parser_kwargs = dict(kwargs)
            if artifact_type == 'evtx':
                try:
                    from config import Config

                    parser_kwargs.setdefault('hayabusa_profile', Config.HAYABUSA_PROFILE)
                except Exception as config_error:
                    logger.debug(f"EVTX parser config defaults unavailable: {config_error}")
            return mapping.parser_class(
                case_id=case_id,
                source_host=source_host,
                case_file_id=case_file_id,
                case_tz=case_tz,
                **parser_kwargs
            )
        except Exception as e:
            logger.error(f"Failed to instantiate parser for {artifact_type}: {e}")
            return None
    
    def get_parser_for_file(self, file_path: str, case_id: int, source_host: str = '',
                           case_file_id: Optional[int] = None, case_tz: str = 'UTC',
                           parser_hints: Optional[List[str]] = None,
                           force_parser: bool = False,
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
            force_parser=force_parser,
            **kwargs
        )
        return parser

    def resolve_parser_for_file(self, file_path: str, case_id: int, source_host: str = '',
                                case_file_id: Optional[int] = None, case_tz: str = 'UTC',
                                parser_hints: Optional[List[str]] = None,
                                force_parser: bool = False,
                                **kwargs) -> Tuple[Optional[str], Optional[BaseParser]]:
        """Resolve the first parser candidate that actually accepts the file."""
        hinted_artifact_types: List[str] = []
        seen = set()
        for artifact_type in parser_hints or []:
            if artifact_type in self._parsers and artifact_type not in seen:
                hinted_artifact_types.append(artifact_type)
                seen.add(artifact_type)

        candidates = []
        for artifact_type in hinted_artifact_types:
            mapping = self._parsers[artifact_type]
            candidates.append((1000, mapping.priority, artifact_type))

        if not force_parser:
            detected_candidates = self._collect_candidates(file_path)
            for score, priority, artifact_type in detected_candidates:
                if artifact_type in seen:
                    continue
                candidates.append((score, priority, artifact_type))
                seen.add(artifact_type)

        if not candidates:
            if force_parser:
                logger.warning(f"No parser hints available for forced parser selection: {file_path}")
            else:
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
            "No parser accepted %s after %s parser resolution: %s",
            file_path,
            "forced" if force_parser else "candidate",
            ', '.join(candidate[2] for candidate in candidates),
        )
        return None, None
    
    def list_parsers(self) -> Dict[str, str]:
        """List all registered parsers
        
        Returns:
            Dict mapping artifact_type to parser class name
        """
        return {k: v.parser_class.__name__ for k, v in self._parsers.items()}


class BatchProcessor:
    """Handles batch processing and ClickHouse insertion"""
    
    DEFAULT_BATCH_SIZE = 10000
    
    def __init__(self, clickhouse_client, batch_size: int = None, use_buffer: bool = False):
        """Initialize batch processor
        
        Args:
            clickhouse_client: ClickHouse client instance
            batch_size: Number of events per insert batch
            use_buffer: Legacy Buffer destination. Production inserts target
                ``events`` directly under shared ingest admission.
        """
        self.client = clickhouse_client
        self.batch_size = batch_size or self.DEFAULT_BATCH_SIZE
        self.table = 'events_buffer' if use_buffer else 'events'
        
        self._batch: List[Tuple] = []
        self._columns = ParsedEvent.clickhouse_columns()
        self._total_inserted = 0
        self._alias_candidates = {}
        self._batch_count = 0
        self._alias_extract_duration_ms = 0.0

    @staticmethod
    def _alias_candidate_counts(candidates) -> Tuple[int, int]:
        """Return observation and unique counts for Phase 0A alias metrics."""
        observation_count = 0
        for candidate in candidates.values():
            observation_count += int(getattr(candidate, 'seen_count', None) or 1)
        return observation_count, len(candidates)
    
    def add_event(self, event: ParsedEvent):
        """Add an event to the batch.

        Privacy alias extraction is intentionally absent from this hot path.
        File-grained alias population runs after rows land via
        ``populate_case_privacy_aliases(case_id, case_file_id=...)``.
        """
        self._batch.append(event.to_clickhouse_row())
        
        if len(self._batch) >= self.batch_size:
            self.flush()
    
    def flush(self):
        """Flush current batch to ClickHouse"""
        if not self._batch:
            return
        
        row_count = len(self._batch)
        estimated_bytes = estimate_rows_bytes(self._batch)
        alias_candidate_count, unique_alias_candidate_count = self._alias_candidate_counts(
            self._alias_candidates
        )
        alias_extract_duration_ms = self._alias_extract_duration_ms
        batch_started = time.perf_counter()
        try:
            case_id = None
            try:
                case_id = int(self._batch[0][0])
            except (TypeError, ValueError, IndexError):
                case_id = None
            with shared_ingest_admission(
                'events_insert',
                case_id=case_id,
                source_ref=f'table:{self.table}',
            ):
                self.client.insert(
                    self.table,
                    self._batch,
                    column_names=self._columns
                )
            insert_duration_ms = (time.perf_counter() - batch_started) * 1000.0
            self._total_inserted += row_count
            self._batch_count += 1
            emit_metric(
                "clickhouse_insert_batch",
                destination_table=self.table,
                batch_row_count=row_count,
                batch_count=self._batch_count,
                estimated_bytes=estimated_bytes,
                insert_duration_ms=insert_duration_ms,
                rows_per_second=(row_count / (insert_duration_ms / 1000.0)) if insert_duration_ms > 0 else None,
                mb_per_second=((estimated_bytes / (1024 * 1024)) / (insert_duration_ms / 1000.0)) if insert_duration_ms > 0 else None,
                alias_candidate_count=alias_candidate_count,
                unique_alias_candidate_count=unique_alias_candidate_count,
                alias_extract_duration_ms=alias_extract_duration_ms,
            )
            logger.debug(f"Inserted {row_count} events (total: {self._total_inserted})")
        except Exception as e:
            emit_metric(
                "clickhouse_insert_batch_failed",
                destination_table=self.table,
                batch_row_count=row_count,
                estimated_bytes=estimated_bytes,
                error_type=e.__class__.__name__,
            )
            logger.error(f"Failed to insert batch: {e}")
            raise
        finally:
            self._batch = []
            self._alias_extract_duration_ms = 0.0
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


def _populate_file_privacy_aliases(
    *,
    case_id: int,
    case_file_id: int,
    events_count: int,
    clickhouse_client=None,
) -> None:
    """Run file-grained alias population after durable current-architecture insert."""
    try:
        from utils.privacy_aliases import populate_case_privacy_aliases

        populate_case_privacy_aliases(
            case_id,
            case_file_id=int(case_file_id),
            generation=None,
            source='ingest_structured',
            client=clickhouse_client,
        )
    except Exception as exc:
        logger.warning(
            "Privacy alias file-scoped population failed for case_file_id=%s (%s events): %s",
            case_file_id,
            events_count,
            exc,
        )


def _cleanup_evtx_group_events_strict(
    members: List[Any],
    *,
    clickhouse_client=None,
    context: str = "evtx_group_cleanup",
) -> List[int]:
    """Synchronously remove grouped EVTX rows or raise before any retry/fallback.

    This helper is intentionally scoped to grouped EVTX ingest. Legacy
    single-file cleanup keeps its existing best-effort behavior.
    """
    from utils.clickhouse import delete_file_events
    from utils.evtx_directory_mode import DirectoryModeError

    cleaned_case_file_ids: List[int] = []
    seen = set()
    for member in members:
        case_file_id = (
            getattr(member, "case_file_id", None)
            if not isinstance(member, dict)
            else member.get("case_file_id")
        )
        if not case_file_id or case_file_id in seen:
            continue
        seen.add(case_file_id)
        try:
            with timed_stage(context, case_file_id=case_file_id):
                delete_file_events(case_file_id, wait=True, client=clickhouse_client)
        except (IngestFenceUnavailable, IngestAdmissionDenied, IngestExclusiveTimeout, IngestFenceLost):
            logger.warning(
                "EVTX group cleanup blocked by ingest fence for case_file_id=%s",
                case_file_id,
            )
            raise
        except Exception as cleanup_error:
            logger.error(
                "Strict EVTX group cleanup failed for case_file_id=%s: %s",
                case_file_id,
                cleanup_error,
            )
            raise DirectoryModeError(
                "group_cleanup_failed",
                f"EVTX group cleanup failed for case_file_id={case_file_id}: {cleanup_error}",
            ) from cleanup_error
        cleaned_case_file_ids.append(int(case_file_id))
    return cleaned_case_file_ids


def process_file(file_path: str, case_id: int, source_host: str = '',
                case_file_id: Optional[int] = None, clickhouse_client=None,
                batch_size: int = 10000, case_tz: str = 'UTC',
                parser_hints: Optional[List[str]] = None,
                force_parser: bool = False) -> ParseResult:
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
    file_size = os.path.getsize(file_path) if os.path.exists(file_path) else None
    with timed_stage("parser_registry_init", case_id=case_id, case_file_id=case_file_id):
        registry = _get_registry()

    with timed_stage("parser_resolution", case_id=case_id, case_file_id=case_file_id):
        artifact_type, parser = registry.resolve_parser_for_file(
            file_path=file_path,
            case_id=case_id,
            source_host=source_host,
            case_file_id=case_file_id,
            case_tz=case_tz,
            parser_hints=parser_hints,
            force_parser=force_parser,
        )

    if not parser or not artifact_type:
        detected_type = registry.detect_type(file_path)
        if not detected_type:
            if force_parser:
                return ParseResult(
                    success=True,
                    file_path=file_path,
                    artifact_type=None,
                    events_count=0,
                    errors=[],
                    warnings=['Selected parser family could not parse this file'],
                    duration_seconds=time.time() - start_time
                )
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
            warnings=[
                'Selected parser family could not parse this file'
                if force_parser
                else f'No parser available for this file (detected as {detected_type} but all candidates rejected)'
            ],
            duration_seconds=time.time() - start_time
        )
    
    # Get ClickHouse client
    if clickhouse_client is None:
        from utils.clickhouse import get_fresh_client
        with timed_stage("clickhouse_client_init", case_id=case_id, case_file_id=case_file_id):
            clickhouse_client = get_fresh_client()
    
    # Process file
    events_count = 0
    errors = []
    warnings = []
    
    try:
        with BatchProcessor(clickhouse_client, batch_size=batch_size) as processor:
            with timed_stage(
                "parser_stream",
                case_id=case_id,
                case_file_id=case_file_id,
                artifact_type=artifact_type,
                source_file_size=file_size,
            ) as stream_metric:
                for event in parser.parse(file_path):
                    processor.add_event(event)
                    events_count += 1
                stream_metric["events_parsed"] = events_count
        
        # Get total after with block exits (flush is called in __exit__)
        events_count = processor.total_inserted
        errors = parser.errors
        warnings = parser.warnings
        success = len(errors) == 0
        if events_count > 0 and case_file_id:
            _populate_file_privacy_aliases(
                case_id=case_id,
                case_file_id=case_file_id,
                events_count=events_count,
                clickhouse_client=clickhouse_client,
            )
        
    except (IngestFenceUnavailable, IngestAdmissionDenied, IngestExclusiveTimeout, IngestFenceLost):
        raise
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
    
    duration_seconds = time.time() - start_time
    emit_metric(
        "process_file_total",
        case_id=case_id,
        case_file_id=case_file_id,
        artifact_type=artifact_type,
        source_file_size=file_size,
        events_inserted=events_count,
        duration_ms=duration_seconds * 1000.0,
        events_per_second=(events_count / duration_seconds) if duration_seconds > 0 else None,
        mb_per_second=((file_size or 0) / (1024 * 1024) / duration_seconds) if duration_seconds > 0 else None,
        success=success,
    )

    return ParseResult(
        success=success,
        file_path=file_path,
        artifact_type=artifact_type,
        events_count=events_count,
        errors=errors,
        warnings=warnings,
        duration_seconds=duration_seconds
    )


def process_evtx_group(members: List[Any], case_id: int, clickhouse_client=None,
                       batch_size: int = 10000, case_tz: str = 'UTC') -> List[ParseResult]:
    """Parse a bounded EVTX group with directory-mode tools, with per-file fallback.

    This is a parser/tool execution optimization. CaseFile lifecycle is unchanged:
    each member keeps its case_file_id, source_host, and source_file. Directory
    failures fall back to process_file so unrelated valid files are not marked
    failed merely because one group member is bad.
    """
    from utils.evtx_directory_mode import DirectoryModeError, EvtxGroupMember

    group: List[EvtxGroupMember] = []
    for item in members:
        if isinstance(item, EvtxGroupMember):
            group.append(item)
        else:
            group.append(EvtxGroupMember(
                file_path=item['file_path'],
                case_file_id=item.get('case_file_id'),
                source_host=item.get('source_host') or '',
                source_file=item.get('source_file') or '',
            ))
    if len(group) <= 1:
        results = []
        for member in group:
            results.append(process_file(
                file_path=member.file_path,
                case_id=case_id,
                source_host=member.source_host,
                case_file_id=member.case_file_id,
                clickhouse_client=clickhouse_client,
                batch_size=batch_size,
                case_tz=case_tz,
                parser_hints=['evtx'],
                force_parser=True,
            ))
        return results

    if clickhouse_client is None:
        from utils.clickhouse import get_fresh_client
        clickhouse_client = get_fresh_client()

    start_time = time.perf_counter()
    parser = _get_registry().get_parser(
        'evtx',
        case_id=case_id,
        source_host='',
        case_file_id=None,
        case_tz=case_tz,
    )
    if parser is None or not hasattr(parser, 'parse_directory_group'):
        results = []
        for member in group:
            results.append(process_file(
                file_path=member.file_path,
                case_id=case_id,
                source_host=member.source_host,
                case_file_id=member.case_file_id,
                clickhouse_client=clickhouse_client,
                batch_size=batch_size,
                case_tz=case_tz,
                parser_hints=['evtx'],
                force_parser=True,
            ))
        return results
    counts = {member.case_file_id: 0 for member in group}
    first_event_at = None
    first_insert_at = None
    try:
        with BatchProcessor(clickhouse_client, batch_size=batch_size) as processor:
            with timed_stage(
                "parser_stream_directory_group",
                case_id=case_id,
                artifact_type='evtx',
                group_size=len(group),
            ) as stream_metric:
                last_case_file_id = None
                for event in parser.parse_directory_group(group):
                    if first_event_at is None:
                        first_event_at = time.perf_counter()
                    # Flush at source-file boundaries so the first file becomes
                    # searchable without waiting for the rest of the group JSONL.
                    if last_case_file_id is not None and event.case_file_id != last_case_file_id:
                        processor.flush()
                        if first_insert_at is None and processor.total_inserted > 0:
                            first_insert_at = time.perf_counter()
                    last_case_file_id = event.case_file_id
                    processor.add_event(event)
                    if first_insert_at is None and processor.total_inserted > 0:
                        first_insert_at = time.perf_counter()
                    if event.case_file_id in counts:
                        counts[event.case_file_id] += 1
                    else:
                        counts[event.case_file_id] = 1
                stream_metric["events_parsed"] = sum(counts.values())
            if first_insert_at is None and processor.total_inserted > 0:
                first_insert_at = time.perf_counter()
        for member in group:
            inserted = counts.get(member.case_file_id, 0)
            if inserted > 0 and member.case_file_id:
                _populate_file_privacy_aliases(
                    case_id=case_id,
                    case_file_id=int(member.case_file_id),
                    events_count=inserted,
                    clickhouse_client=clickhouse_client,
                )
        duration = time.perf_counter() - start_time
        emit_metric(
            "process_evtx_group_total",
            case_id=case_id,
            events_inserted=sum(counts.values()),
            duration_ms=duration * 1000.0,
            group_size=len(group),
            first_event_ms=None if first_event_at is None else (first_event_at - start_time) * 1000.0,
            first_insert_ms=None if first_insert_at is None else (first_insert_at - start_time) * 1000.0,
            success=len(parser.errors) == 0,
            directory_mode=True,
        )
        results = []
        for member in group:
            results.append(ParseResult(
                success=len(parser.errors) == 0,
                file_path=member.file_path,
                artifact_type='evtx',
                events_count=counts.get(member.case_file_id, 0),
                errors=list(parser.errors),
                warnings=list(parser.warnings),
                duration_seconds=duration,
            ))
        return results
    except (IngestFenceUnavailable, IngestAdmissionDenied, IngestExclusiveTimeout, IngestFenceLost):
        raise
    except DirectoryModeError as exc:
        logger.warning(
            "EVTX directory mode failed (%s); falling back to per-file for %s members: %s",
            exc.reason,
            len(group),
            exc,
        )
        if first_insert_at is not None:
            _cleanup_evtx_group_events_strict(
                group,
                clickhouse_client=clickhouse_client,
                context="evtx_group_fallback_cleanup",
            )
        results = []
        for member in group:
            result = process_file(
                file_path=member.file_path,
                case_id=case_id,
                source_host=member.source_host,
                case_file_id=member.case_file_id,
                clickhouse_client=clickhouse_client,
                batch_size=batch_size,
                case_tz=case_tz,
                parser_hints=['evtx'],
                force_parser=True,
            )
            result.warnings.append(
                f"Directory-mode fallback ({exc.reason}): {exc}"
            )
            results.append(result)
        emit_metric(
            "process_evtx_group_fallback",
            case_id=case_id,
            group_size=len(group),
            reason=exc.reason,
            success=all(item.success for item in results),
        )
        return results
    except Exception as exc:
        logger.exception("EVTX directory group failed; falling back to per-file")
        wrapped = DirectoryModeError('tool_crash', str(exc)[:500])
        if first_insert_at is not None:
            _cleanup_evtx_group_events_strict(
                group,
                clickhouse_client=clickhouse_client,
                context="evtx_group_fallback_cleanup",
            )
        results = []
        for member in group:
            result = process_file(
                file_path=member.file_path,
                case_id=case_id,
                source_host=member.source_host,
                case_file_id=member.case_file_id,
                clickhouse_client=clickhouse_client,
                batch_size=batch_size,
                case_tz=case_tz,
                parser_hints=['evtx'],
                force_parser=True,
            )
            result.warnings.append(f"Directory-mode fallback (tool_crash): {exc}")
            results.append(result)
        return results


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

    from utils.evtx_directory_mode import EvtxGroupMember, is_evtx_path, plan_evtx_parse_units

    evtx_members = []
    other_files = []
    for file_path in files:
        if is_evtx_path(file_path):
            evtx_members.append(EvtxGroupMember(
                file_path=file_path,
                case_file_id=None,
                source_host=source_host,
            ))
        else:
            other_files.append(file_path)

    for unit in plan_evtx_parse_units(evtx_members):
        if unit.mode == "per_file":
            result = process_file(
                file_path=unit.members[0].file_path,
                case_id=case_id,
                source_host=source_host,
                clickhouse_client=clickhouse_client,
            )
            results.append(result)
        else:
            results.extend(process_evtx_group(
                list(unit.members),
                case_id=case_id,
                clickhouse_client=clickhouse_client,
            ))

    for file_path in other_files:
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
