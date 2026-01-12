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
    
    def register(self, mapping: FileTypeMapping):
        """Register a parser mapping"""
        self._parsers[mapping.artifact_type] = mapping
        logger.debug(f"Registered parser: {mapping.artifact_type} -> {mapping.parser_class.__name__}")
    
    # Files that should never be parsed (transaction logs, temp files, etc.)
    EXCLUDED_EXTENSIONS = {'.log', '.log1', '.log2', '.blf', '.regtrans-ms', '.tmp', '.bak'}
    
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
        if not os.path.isfile(file_path):
            return None
        
        filename = os.path.basename(file_path).lower()
        extension = os.path.splitext(filename)[1].lower()
        path_lower = file_path.lower()
        
        # Check for excluded extensions (registry transaction logs, etc.)
        # These should be marked as no_parser, not matched to a parser
        if extension in self.EXCLUDED_EXTENSIONS:
            return None
        
        # Check for excluded filenames
        if filename in self.EXCLUDED_FILENAMES:
            return None
        
        # Check path patterns that indicate non-registry files
        for pattern in self.EXCLUDED_PATH_PATTERNS:
            if pattern in path_lower:
                # Files in /tasks/ should go to scheduled_task parser, not registry
                # But only exclude from registry detection, let other parsers handle
                break
        
        # Read magic bytes
        magic = b''
        try:
            with open(file_path, 'rb') as f:
                magic = f.read(8)
        except Exception:
            pass
        
        # Find matching parsers and sort by priority
        candidates = []
        
        for artifact_type, mapping in self._parsers.items():
            score = 0
            
            # Check magic bytes (highest confidence)
            for mb in mapping.magic_bytes:
                if magic.startswith(mb):
                    score += 100
                    break
            
            # Check filename patterns (check both filename and full path for path-based patterns)
            for pattern in mapping.filename_patterns:
                pattern_lower = pattern.lower()
                if pattern_lower in filename or pattern_lower in path_lower:
                    score += 50
                    break
            
            # Check extensions
            if extension in mapping.extensions:
                score += 30
            
            if score > 0:
                candidates.append((score, mapping.priority, artifact_type))
        
        if not candidates:
            return None
        
        # Sort by score (descending) then priority (ascending)
        candidates.sort(key=lambda x: (-x[0], x[1]))
        return candidates[0][2]
    
    def get_parser(self, artifact_type: str, case_id: int, source_host: str = '', 
                   case_file_id: Optional[int] = None, **kwargs) -> Optional[BaseParser]:
        """Get a parser instance for the given artifact type
        
        Args:
            artifact_type: The artifact type to get parser for
            case_id: ClickHouse case_id
            source_host: Hostname
            case_file_id: Optional FK to case_files
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
                **kwargs
            )
        except Exception as e:
            logger.error(f"Failed to instantiate parser for {artifact_type}: {e}")
            return None
    
    def get_parser_for_file(self, file_path: str, case_id: int, source_host: str = '',
                           case_file_id: Optional[int] = None, **kwargs) -> Optional[BaseParser]:
        """Auto-detect file type and get appropriate parser
        
        Args:
            file_path: Path to the file
            case_id: ClickHouse case_id
            source_host: Hostname
            case_file_id: Optional FK to case_files
            **kwargs: Additional parser-specific arguments
            
        Returns:
            Parser instance or None
        """
        artifact_type = self.detect_type(file_path)
        if not artifact_type:
            logger.warning(f"Could not detect type for file: {file_path}")
            return None
        
        parser = self.get_parser(
            artifact_type=artifact_type,
            case_id=case_id,
            source_host=source_host,
            case_file_id=case_file_id,
            **kwargs
        )
        
        # Verify parser can actually handle the file
        if parser and parser.can_parse(file_path):
            return parser
        
        return None
    
    def list_parsers(self) -> Dict[str, str]:
        """List all registered parsers
        
        Returns:
            Dict mapping artifact_type to parser class name
        """
        return {k: v.parser_class.__name__ for k, v in self._parsers.items()}
    
    def parse_file(self, file_path: str, case_id: int, source_host: str = '',
                   case_file_id: Optional[int] = None, **kwargs) -> Tuple[Optional[str], Generator[ParsedEvent, None, None]]:
        """Parse a file and yield events
        
        Args:
            file_path: Path to the file
            case_id: ClickHouse case_id
            source_host: Hostname
            case_file_id: Optional FK to case_files
            
        Returns:
            Tuple of (artifact_type, event generator) or (None, empty generator)
        """
        parser = self.get_parser_for_file(
            file_path=file_path,
            case_id=case_id,
            source_host=source_host,
            case_file_id=case_file_id,
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
    
    def add_event(self, event: ParsedEvent):
        """Add an event to the batch
        
        Args:
            event: ParsedEvent to add
        """
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
            logger.debug(f"Inserted {len(self._batch)} events (total: {self._total_inserted})")
        except Exception as e:
            logger.error(f"Failed to insert batch: {e}")
            raise
        finally:
            self._batch = []
    
    @property
    def total_inserted(self) -> int:
        """Total events inserted"""
        return self._total_inserted
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.flush()


def process_file(file_path: str, case_id: int, source_host: str = '',
                case_file_id: Optional[int] = None, clickhouse_client=None,
                batch_size: int = 10000) -> ParseResult:
    """Process a single file and insert events into ClickHouse
    
    Args:
        file_path: Path to the file
        case_id: ClickHouse case_id
        source_host: Hostname
        case_file_id: Optional FK to case_files
        clickhouse_client: ClickHouse client (optional, uses default if None)
        batch_size: Events per batch
        
    Returns:
        ParseResult with processing status
    """
    start_time = time.time()
    registry = ParserRegistry()
    
    # Detect type
    artifact_type = registry.detect_type(file_path)
    if not artifact_type:
        return ParseResult(
            success=False,
            file_path=file_path,
            artifact_type='unknown',
            errors=['Could not detect file type'],
            duration_seconds=time.time() - start_time
        )
    
    # Get parser
    parser = registry.get_parser(
        artifact_type=artifact_type,
        case_id=case_id,
        source_host=source_host,
        case_file_id=case_file_id
    )
    
    if not parser:
        return ParseResult(
            success=False,
            file_path=file_path,
            artifact_type=artifact_type,
            errors=[f'No parser available for {artifact_type}'],
            duration_seconds=time.time() - start_time
        )
    
    # Verify parser can actually handle this file
    # If can_parse returns False, treat as no_parser (not an error)
    if not parser.can_parse(file_path):
        return ParseResult(
            success=True,  # Not an error - just no parser for this specific file
            file_path=file_path,
            artifact_type=None,  # Indicates no parser handled it
            events_count=0,
            errors=[],
            warnings=[f'No parser available for this file (detected as {artifact_type} but rejected)'],
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
        errors.append(str(e))
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
    registry = ParserRegistry()
    
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
