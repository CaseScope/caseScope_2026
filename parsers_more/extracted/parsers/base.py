"""Base Parser Class for CaseScope

All artifact parsers inherit from this base class.
Provides common interface for parsing, normalization, and ClickHouse insertion.
"""
import os
import json
import logging
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Generator, Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field, asdict

logger = logging.getLogger(__name__)


@dataclass
class ParsedEvent:
    """Standardized event structure for all parsers
    
    All parsers must convert their output to this format
    for insertion into ClickHouse.
    """
    # Required fields
    case_id: int
    artifact_type: str
    timestamp: datetime
    source_file: str
    source_host: str
    
    # Optional source tracking
    source_path: str = ''
    case_file_id: Optional[int] = None
    
    # Event metadata
    event_id: Optional[str] = None
    channel: Optional[str] = None
    provider: Optional[str] = None
    record_id: Optional[int] = None
    level: Optional[str] = None
    
    # Actor/User
    username: Optional[str] = None
    domain: Optional[str] = None
    sid: Optional[str] = None
    logon_type: Optional[int] = None
    
    # Process
    process_name: Optional[str] = None
    process_path: Optional[str] = None
    process_id: Optional[int] = None
    parent_process: Optional[str] = None
    parent_pid: Optional[int] = None
    command_line: Optional[str] = None
    
    # File
    target_path: Optional[str] = None
    file_hash_md5: Optional[str] = None
    file_hash_sha1: Optional[str] = None
    file_hash_sha256: Optional[str] = None
    file_size: Optional[int] = None
    
    # Network
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    
    # Registry
    reg_key: Optional[str] = None
    reg_value: Optional[str] = None
    reg_data: Optional[str] = None
    
    # Detection (Hayabusa/Sigma)
    rule_title: Optional[str] = None
    rule_level: Optional[str] = None
    rule_file: Optional[str] = None
    mitre_tactics: List[str] = field(default_factory=list)
    mitre_tags: List[str] = field(default_factory=list)
    
    # Flexible storage
    raw_json: str = '{}'
    search_blob: str = ''
    extra_fields: str = '{}'
    
    # Metadata
    parser_version: str = ''
    
    def to_clickhouse_row(self) -> Tuple:
        """Convert to tuple for ClickHouse insertion"""
        return (
            self.case_id,
            self.artifact_type,
            self.timestamp,
            self.source_file,
            self.source_path,
            self.source_host,
            self.case_file_id,
            self.event_id,
            self.channel,
            self.provider,
            self.record_id,
            self.level,
            self.username,
            self.domain,
            self.sid,
            self.logon_type,
            self.process_name,
            self.process_path,
            self.process_id,
            self.parent_process,
            self.parent_pid,
            self.command_line,
            self.target_path,
            self.file_hash_md5,
            self.file_hash_sha1,
            self.file_hash_sha256,
            self.file_size,
            self.src_ip,
            self.dst_ip,
            self.src_port,
            self.dst_port,
            self.reg_key,
            self.reg_value,
            self.reg_data,
            self.rule_title,
            self.rule_level,
            self.rule_file,
            self.mitre_tactics,
            self.mitre_tags,
            self.raw_json,
            self.search_blob,
            self.extra_fields,
            self.parser_version,
        )
    
    @staticmethod
    def clickhouse_columns() -> List[str]:
        """Column names matching to_clickhouse_row order"""
        return [
            'case_id', 'artifact_type', 'timestamp', 'source_file', 'source_path',
            'source_host', 'case_file_id', 'event_id', 'channel', 'provider',
            'record_id', 'level', 'username', 'domain', 'sid', 'logon_type',
            'process_name', 'process_path', 'process_id', 'parent_process',
            'parent_pid', 'command_line', 'target_path', 'file_hash_md5',
            'file_hash_sha1', 'file_hash_sha256', 'file_size', 'src_ip', 'dst_ip',
            'src_port', 'dst_port', 'reg_key', 'reg_value', 'reg_data',
            'rule_title', 'rule_level', 'rule_file', 'mitre_tactics', 'mitre_tags',
            'raw_json', 'search_blob', 'extra_fields', 'parser_version',
        ]


@dataclass
class ParseResult:
    """Result of parsing a single file"""
    success: bool
    file_path: str
    artifact_type: str
    events_count: int = 0
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    duration_seconds: float = 0.0
    
    def to_dict(self) -> Dict:
        return asdict(self)


class BaseParser(ABC):
    """Abstract base class for all artifact parsers
    
    Subclasses must implement:
    - parse(): Generator yielding ParsedEvent objects
    - can_parse(): Check if this parser handles a file
    - artifact_type: Property returning the artifact type string
    """
    
    VERSION = '1.0.0'
    
    def __init__(self, case_id: int, source_host: str = '', case_file_id: Optional[int] = None):
        """Initialize parser with case context
        
        Args:
            case_id: ClickHouse case_id (PostgreSQL cases.id)
            source_host: Hostname the artifact came from
            case_file_id: Optional FK to PostgreSQL case_files.id
        """
        self.case_id = case_id
        self.source_host = source_host
        self.case_file_id = case_file_id
        self.errors: List[str] = []
        self.warnings: List[str] = []
    
    @property
    @abstractmethod
    def artifact_type(self) -> str:
        """Return the artifact type identifier (e.g., 'evtx', 'prefetch')"""
        pass
    
    @property
    def parser_version(self) -> str:
        """Return parser version string"""
        return f"{self.__class__.__name__}-{self.VERSION}"
    
    @abstractmethod
    def can_parse(self, file_path: str) -> bool:
        """Check if this parser can handle the given file
        
        Args:
            file_path: Path to the file to check
            
        Returns:
            True if this parser can handle the file
        """
        pass
    
    @abstractmethod
    def parse(self, file_path: str) -> Generator[ParsedEvent, None, None]:
        """Parse the file and yield ParsedEvent objects
        
        Args:
            file_path: Path to the file to parse
            
        Yields:
            ParsedEvent objects for each event found
        """
        pass
    
    def build_search_blob(self, data: Dict[str, Any], exclude_keys: List[str] = None) -> str:
        """Build searchable text blob from dictionary
        
        Flattens all values into a space-separated string for full-text search.
        
        Args:
            data: Dictionary of field names and values
            exclude_keys: Keys to exclude from the blob
            
        Returns:
            Space-separated string of key:value pairs
        """
        exclude = set(exclude_keys or [])
        parts = []
        
        def flatten(obj, prefix=''):
            if isinstance(obj, dict):
                for k, v in obj.items():
                    if k not in exclude and v is not None:
                        flatten(v, f"{prefix}{k}:")
            elif isinstance(obj, list):
                for item in obj:
                    flatten(item, prefix)
            else:
                val = str(obj).strip()
                if val and val != '-' and val != 'None':
                    if prefix:
                        parts.append(f"{prefix}{val}")
                    else:
                        parts.append(val)
        
        flatten(data)
        return ' '.join(parts)
    
    def extract_hostname(self, file_path: str, data: Dict = None) -> str:
        """Extract hostname from file path or data
        
        Tries multiple strategies:
        1. Use provided source_host
        2. Extract from data (Computer field)
        3. Extract from path patterns (CyLR format)
        
        Args:
            file_path: Path to the artifact file
            data: Parsed data that might contain hostname
            
        Returns:
            Hostname string or 'unknown'
        """
        # Use provided source_host if set
        if self.source_host:
            return self.source_host
        
        # Try to get from data
        if data:
            for key in ['Computer', 'computer', 'hostname', 'Hostname', 'MachineName']:
                if key in data and data[key]:
                    return str(data[key])
        
        # Try to extract from CyLR-style path
        # Pattern: .../hostname/C/Windows/...
        path_parts = file_path.replace('\\', '/').split('/')
        for i, part in enumerate(path_parts):
            if part.upper() in ('C', 'D', 'E') and i > 0:
                potential_host = path_parts[i - 1]
                if potential_host and not potential_host.startswith('.'):
                    return potential_host
        
        return 'unknown'
    
    def parse_timestamp(self, value: Any, formats: List[str] = None) -> Optional[datetime]:
        """Parse timestamp from various formats
        
        Args:
            value: Timestamp value (string, datetime, or None)
            formats: List of strptime format strings to try
            
        Returns:
            datetime object or None if parsing fails
        """
        if value is None:
            return None
        
        if isinstance(value, datetime):
            return value
        
        if not isinstance(value, str):
            value = str(value)
        
        # Default formats to try
        if formats is None:
            formats = [
                '%Y-%m-%dT%H:%M:%S.%f%z',      # ISO with microseconds and tz
                '%Y-%m-%dT%H:%M:%S%z',          # ISO with tz
                '%Y-%m-%dT%H:%M:%S.%f',         # ISO with microseconds
                '%Y-%m-%dT%H:%M:%S',            # ISO basic
                '%Y-%m-%d %H:%M:%S.%f',         # Space-separated with microseconds
                '%Y-%m-%d %H:%M:%S',            # Space-separated basic
                '%m/%d/%Y %H:%M:%S',            # US format
                '%d/%m/%Y %H:%M:%S',            # EU format
            ]
        
        for fmt in formats:
            try:
                return datetime.strptime(value.strip(), fmt)
            except ValueError:
                continue
        
        # Try parsing ISO format with dateutil as fallback
        try:
            from dateutil.parser import parse as dateutil_parse
            return dateutil_parse(value)
        except Exception:
            pass
        
        self.warnings.append(f"Could not parse timestamp: {value}")
        return None
    
    def safe_int(self, value: Any, default: int = None) -> Optional[int]:
        """Safely convert value to integer"""
        if value is None:
            return default
        try:
            return int(value)
        except (ValueError, TypeError):
            return default
    
    def safe_str(self, value: Any, default: str = None) -> Optional[str]:
        """Safely convert value to string, handling None and empty"""
        if value is None:
            return default
        s = str(value).strip()
        return s if s and s != '-' else default
    
    def validate_ip(self, value: str) -> Optional[str]:
        """Validate and return IP address or None"""
        if not value or value == '-':
            return None
        
        # Basic validation
        import re
        ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        if re.match(ipv4_pattern, value):
            parts = value.split('.')
            if all(0 <= int(p) <= 255 for p in parts):
                return value
        
        return None
