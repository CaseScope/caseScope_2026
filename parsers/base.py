"""Base Parser Class for CaseScope

All artifact parsers inherit from this base class.
Provides common interface for parsing, normalization, and ClickHouse insertion.
"""
import os
import json
import logging
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Generator, Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field, asdict

logger = logging.getLogger(__name__)

UINT16_MAX = 65535
UINT32_MAX = 4294967295
UINT64_MAX = 18446744073709551615

# A parser that reports one message per line turns a file with a million
# unparseable rows into a million strings, all of which are joined into a
# single Postgres column. One file in this deployment reached 3.9 MB.
MAX_PARSER_MESSAGES = 100


class BoundedMessageList(list):
    """A message list that discards duplicates and stops growing.

    Diagnostics only need to say what went wrong and roughly how often, so
    repeats are counted rather than stored and the list stops accepting new
    entries once it has enough distinct examples to be useful.
    """

    def __init__(self, max_messages: int = MAX_PARSER_MESSAGES):
        super().__init__()
        self._max_messages = max_messages
        self._seen: set = set()
        self._suppressed = 0
        self._capped = False

    @property
    def suppressed_count(self) -> int:
        return self._suppressed

    def append(self, message: Any) -> None:
        text = str(message).strip()
        if not text or text in self._seen:
            self._suppressed += 1
            return
        if self._capped:
            self._suppressed += 1
            return
        if len(self) >= self._max_messages:
            self._capped = True
            self._suppressed += 1
            super().append(
                f'Further messages suppressed after {self._max_messages} distinct entries'
            )
            return
        self._seen.add(text)
        super().append(text)

    def extend(self, messages: Any) -> None:
        for message in messages:
            self.append(message)


def to_naive_utc(value: Optional[datetime]) -> Optional[datetime]:
    """Return a datetime that can be compared with any other normalised one.

    Timestamps arrive both aware (ISO strings carrying an offset, dissect's
    FILETIME helpers) and naive (strptime, utcfromtimestamp), and comparing
    the two raises TypeError. Every bound check and interval calculation goes
    through here so the mix cannot reach an operator.
    """
    if value is None:
        return None
    if value.tzinfo is None:
        return value
    return value.astimezone(timezone.utc).replace(tzinfo=None)


def _clamp_uint(value: Any, maximum: int) -> Optional[int]:
    """Drop an integer that the destination UInt column cannot hold.

    ClickHouse rejects the entire batch when a value is negative or oversized,
    and a rejected batch marks the file failed and removes the rows already
    stored for it. Losing one field is far cheaper than losing the file, so an
    out-of-range value becomes NULL. A parent PID of -1 is the common case.
    """
    if value is None:
        return None
    try:
        number = int(value)
    except (TypeError, ValueError):
        return None
    return number if 0 <= number <= maximum else None


@dataclass
class ParsedEvent:
    """Standardized event structure for all parsers
    
    All parsers must convert their output to this format
    for insertion into ClickHouse.
    
    Note: String fields use empty string defaults (not None)
    to match ClickHouse schema which uses non-nullable strings
    with DEFAULT '' for index compatibility.
    
    Timestamp fields:
    - timestamp: Original timestamp as parsed (for forensic integrity)
    - timestamp_utc: Normalized UTC timestamp for sorting/filtering/display
    - timestamp_source_tz: IANA timezone identifier assumed for source
    """
    # Required fields
    case_id: int
    artifact_type: str
    timestamp: datetime
    timestamp_utc: datetime = None  # Set by parser or compute_utc_timestamp()
    timestamp_source_tz: str = 'UTC'  # IANA timezone identifier
    
    # Source tracking (required but with defaults)
    source_file: str = ''
    source_host: str = ''
    source_path: str = ''
    case_file_id: Optional[int] = None
    
    # Event metadata
    event_id: str = ''
    channel: str = ''
    provider: str = ''
    record_id: Optional[int] = None
    level: str = ''
    
    # Actor/User
    username: str = ''
    domain: str = ''
    sid: str = ''
    logon_type: Optional[int] = None
    logon_id: str = ''  # Target logon ID for session correlation
    
    # Logon Details (from EVTX EventData)
    remote_host: str = ''  # EvtxECmd RemoteHost (IP/hostname of source)
    workstation_name: str = ''  # Source workstation name
    auth_package: str = ''  # NTLM, Kerberos, Negotiate, etc.
    logon_process: str = ''  # Logon process name (Advapi, User32, etc.)
    key_length: Optional[int] = None  # Windows logon KeyLength EventData
    elevated_token: str = ''  # Elevated token indicator
    
    # Process
    process_name: str = ''
    process_path: str = ''
    process_id: Optional[int] = None
    parent_process: str = ''
    parent_pid: Optional[int] = None
    command_line: str = ''
    thread_id: Optional[int] = None  # Thread ID from System
    executable_info: str = ''  # EvtxECmd ExecutableInfo (Maps-normalized)
    
    # EvtxECmd Maps Payload Summary
    payload_data1: str = ''  # Maps-extracted field 1
    payload_data2: str = ''  # Maps-extracted field 2
    payload_data3: str = ''  # Maps-extracted field 3
    payload_data4: str = ''  # Maps-extracted field 4
    payload_data5: str = ''  # Maps-extracted field 5
    payload_data6: str = ''  # Maps-extracted field 6
    
    # File
    target_path: str = ''
    file_hash_md5: str = ''
    file_hash_sha1: str = ''
    file_hash_sha256: str = ''
    file_size: Optional[int] = None
    
    # Network
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    
    # Registry
    reg_key: str = ''
    reg_value: str = ''
    reg_data: str = ''
    
    # Detection (Hayabusa/Sigma)
    rule_title: str = ''
    rule_level: str = ''
    rule_file: str = ''
    mitre_tactics: List[str] = field(default_factory=list)
    mitre_tags: List[str] = field(default_factory=list)
    mitre_attack_ids: List[str] = field(default_factory=list)
    mitre_attack_tactics: List[str] = field(default_factory=list)
    mitre_attack_sources: List[str] = field(default_factory=list)
    mitre_mapping_max_confidence: int = 0
    
    # Flexible storage
    raw_json: str = '{}'
    search_blob: str = ''
    extra_fields: str = '{}'
    
    # Metadata
    parser_version: str = ''
    evidence_record_key: str = ''
    evidence_identity_version: str = ''
    evidence_identity_quality: str = ''
    native_record_id_authoritative: bool = False
    source_record_identifier_authoritative: bool = False
    source_record_identifier_type: str = ''
    source_record_identifier_value: str = ''

    _PROVENANCE_SKIP_FIELDS = {
        'case_id',
        'raw_json',
        'search_blob',
        'extra_fields',
        'parser_version',
        'evidence_record_key',
        'evidence_identity_version',
        'evidence_identity_quality',
        'key_length',
    }

    @staticmethod
    def _has_meaningful_value(value: Any) -> bool:
        if value is None:
            return False
        if isinstance(value, str):
            return bool(value.strip())
        if isinstance(value, (list, tuple, set, dict)):
            return bool(value)
        return True

    def _parser_field_names(self) -> List[str]:
        field_names: List[str] = []
        for field_name in self.clickhouse_columns():
            if field_name in self._PROVENANCE_SKIP_FIELDS:
                continue
            if self._has_meaningful_value(getattr(self, field_name, None)):
                field_names.append(field_name)
        return field_names

    def _build_parser_provenance(self) -> Dict[str, Any]:
        try:
            from utils.provenance import max_provenance, provenance_for_artifact_field
        except Exception:
            def provenance_for_artifact_field(artifact_type: Any, field_name: Any) -> str:
                structural_fields = {
                    'artifact_type',
                    'count',
                    'cross_events_count',
                    'cross_memory_count',
                    'event_count',
                    'event_id',
                    'host',
                    'hostname',
                    'ioc_types',
                    'job_id',
                    'log_type',
                    'memory_time',
                    'pid',
                    'pcap_id',
                    'ppid',
                    'source_host',
                    'source',
                    'timestamp',
                    'timestamp_utc',
                    'timestamp_source_tz',
                    'username',
                    'uid',
                    'user',
                }
                browser_prefixes = ('browser_', 'chrome_', 'edge_', 'firefox_', 'webcache_')
                normalized_artifact_type = str(artifact_type or '').strip().lower()
                normalized_field = str(field_name or '').strip().lower()
                if normalized_field in structural_fields:
                    return 'SYSTEM_DERIVED'
                if normalized_artifact_type.startswith(browser_prefixes):
                    return 'ELEVATED_RISK'
                return 'ARTIFACT_TAINTED'

            def max_provenance(values: List[Any], default: str = 'SYSTEM_DERIVED') -> str:
                order = {
                    'ANALYST': 0,
                    'SYSTEM_DERIVED': 1,
                    'ARTIFACT_TAINTED': 2,
                    'ELEVATED_RISK': 3,
                    'MODEL_SYNTHESIZED': 4,
                }
                highest = default
                for value in values:
                    candidate = str(value or default).strip().upper()
                    if candidate not in order:
                        candidate = default
                    if order[candidate] > order[highest]:
                        highest = candidate
                return highest

        field_provenance = {
            field_name: provenance_for_artifact_field(self.artifact_type, field_name)
            for field_name in self._parser_field_names()
        }
        return {
            'field_provenance': field_provenance,
            'emitted_provenance': max_provenance(
                list(field_provenance.values()),
                default='SYSTEM_DERIVED',
            ),
            'provenance_source': 'parser_emitted',
        }

    def _serialized_extra_fields(self) -> str:
        payload: Dict[str, Any]
        try:
            payload = json.loads(self.extra_fields) if self.extra_fields else {}
            if not isinstance(payload, dict):
                payload = {}
        except (TypeError, ValueError, json.JSONDecodeError):
            payload = {}

        parser_provenance = self._build_parser_provenance()
        existing_field_provenance = payload.get('field_provenance')
        if not isinstance(existing_field_provenance, dict):
            existing_field_provenance = {}
        if self.native_record_id_authoritative:
            payload['native_record_id_authoritative'] = True
            payload.setdefault('record_identity_kind', 'native')
        if self.source_record_identifier_authoritative:
            payload['source_record_identifier_authoritative'] = True
            payload['source_record_identifier_type'] = self.source_record_identifier_type
            payload['source_record_identifier_value'] = self.source_record_identifier_value
        payload['field_provenance'] = {
            **parser_provenance.get('field_provenance', {}),
            **existing_field_provenance,
        }
        payload['emitted_provenance'] = (
            payload.get('emitted_provenance')
            or parser_provenance.get('emitted_provenance')
            or 'SYSTEM_DERIVED'
        )
        payload['provenance_source'] = payload.get('provenance_source') or 'parser_emitted'
        self.extra_fields = json.dumps(payload, default=str)
        return self.extra_fields
    
    def compute_utc_timestamp(self):
        """Compute timestamp_utc if not already set
        
        Uses timestamp_source_tz to convert timestamp to UTC.
        Should be called before to_clickhouse_row() if timestamp_utc wasn't
        set explicitly by the parser.
        """
        if self.timestamp_utc is None and self.timestamp is not None:
            from utils.timezone import to_utc
            self.timestamp_utc = to_utc(self.timestamp, self.timestamp_source_tz)

        # An aware timestamp already carries its own offset and to_utc honours
        # it, so the source timezone was correctly ignored above. Strip the
        # offset now to keep every stored value naive UTC.
        if self.timestamp is not None and self.timestamp.tzinfo is not None:
            self.timestamp = self.timestamp.astimezone(timezone.utc).replace(tzinfo=None)
        if self.timestamp_utc is not None and self.timestamp_utc.tzinfo is not None:
            self.timestamp_utc = self.timestamp_utc.astimezone(timezone.utc).replace(tzinfo=None)
    
    def to_clickhouse_row(self) -> Tuple:
        """Convert to tuple for ClickHouse insertion"""
        # Ensure timestamp_utc is computed
        self.compute_utc_timestamp()
        if not self.evidence_record_key:
            from utils.evidence_identity import build_evidence_record_identity

            identity = build_evidence_record_identity(self)
            self.evidence_record_key = identity.evidence_record_key
            self.evidence_identity_version = identity.evidence_identity_version
            self.evidence_identity_quality = identity.evidence_identity_quality
        extra_fields = self._serialized_extra_fields()
        
        return (
            self.case_id,
            self.artifact_type,
            self.timestamp,
            self.timestamp_utc if self.timestamp_utc else self.timestamp,
            self.timestamp_source_tz,
            self.source_file,
            self.source_path,
            self.source_host,
            _clamp_uint(self.case_file_id, UINT32_MAX),
            self.event_id,
            self.channel,
            self.provider,
            _clamp_uint(self.record_id, UINT64_MAX),
            self.level,
            self.username,
            self.domain,
            self.sid,
            _clamp_uint(self.logon_type, UINT16_MAX),
            self.logon_id,
            self.remote_host,
            self.workstation_name,
            self.auth_package,
            self.logon_process,
            _clamp_uint(self.key_length, UINT16_MAX),
            self.elevated_token,
            self.process_name,
            self.process_path,
            _clamp_uint(self.process_id, UINT64_MAX),
            self.parent_process,
            _clamp_uint(self.parent_pid, UINT64_MAX),
            self.command_line,
            _clamp_uint(self.thread_id, UINT64_MAX),
            self.executable_info,
            self.payload_data1,
            self.payload_data2,
            self.payload_data3,
            self.payload_data4,
            self.payload_data5,
            self.payload_data6,
            self.target_path,
            self.file_hash_md5,
            self.file_hash_sha1,
            self.file_hash_sha256,
            _clamp_uint(self.file_size, UINT64_MAX),
            self.src_ip,
            self.dst_ip,
            _clamp_uint(self.src_port, UINT16_MAX),
            _clamp_uint(self.dst_port, UINT16_MAX),
            self.reg_key,
            self.reg_value,
            self.reg_data,
            self.rule_title,
            self.rule_level,
            self.rule_file,
            self.mitre_tactics,
            self.mitre_tags,
            self.mitre_attack_ids,
            self.mitre_attack_tactics,
            self.mitre_attack_sources,
            self.mitre_mapping_max_confidence,
            self.raw_json,
            self.search_blob,
            extra_fields,
            self.parser_version,
            self.evidence_record_key,
            self.evidence_identity_version,
            self.evidence_identity_quality,
        )
    
    @staticmethod
    def clickhouse_columns() -> List[str]:
        """Column names matching to_clickhouse_row order"""
        return [
            'case_id', 'artifact_type', 'timestamp', 'timestamp_utc', 'timestamp_source_tz',
            'source_file', 'source_path',
            'source_host', 'case_file_id', 'event_id', 'channel', 'provider',
            'record_id', 'level', 'username', 'domain', 'sid', 'logon_type',
            'logon_id', 'remote_host', 'workstation_name', 'auth_package',
            'logon_process', 'key_length', 'elevated_token',
            'process_name', 'process_path', 'process_id', 'parent_process',
            'parent_pid', 'command_line', 'thread_id', 'executable_info',
            'payload_data1', 'payload_data2', 'payload_data3', 'payload_data4',
            'payload_data5', 'payload_data6',
            'target_path', 'file_hash_md5', 'file_hash_sha1', 'file_hash_sha256',
            'file_size', 'src_ip', 'dst_ip', 'src_port', 'dst_port',
            'reg_key', 'reg_value', 'reg_data',
            'rule_title', 'rule_level', 'rule_file', 'mitre_tactics', 'mitre_tags',
            'mitre_attack_ids', 'mitre_attack_tactics', 'mitre_attack_sources',
            'mitre_mapping_max_confidence',
            'raw_json', 'search_blob', 'extra_fields', 'parser_version',
            'evidence_record_key', 'evidence_identity_version', 'evidence_identity_quality',
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
    supports_manifest_protocol = False
    manifest_ordering_contract = None
    
    def __init__(self, case_id: int, source_host: str = '', case_file_id: Optional[int] = None,
                 case_tz: str = 'UTC'):
        """Initialize parser with case context
        
        Args:
            case_id: ClickHouse case_id (PostgreSQL cases.id)
            source_host: Hostname the artifact came from
            case_file_id: Optional FK to PostgreSQL case_files.id
            case_tz: Case timezone (IANA identifier) for ambiguous timestamp sources
        """
        self.case_id = case_id
        self.source_host = source_host
        self.case_file_id = case_file_id
        self.case_tz = case_tz  # Used for ambiguous timestamp sources
        self.errors: List[str] = BoundedMessageList()
        self.warnings: List[str] = BoundedMessageList()
        self._timestamp_fallback_warnings = set()
    
    @property
    @abstractmethod
    def artifact_type(self) -> str:
        """Return the artifact type identifier (e.g., 'evtx', 'prefetch')"""
        pass
    
    @property
    def parser_version(self) -> str:
        """Return parser version string"""
        return f"{self.__class__.__name__}-{self.VERSION}"
    
    def get_source_tz(self) -> str:
        """Get the source timezone for this artifact type
        
        Returns 'UTC' for artifacts with known UTC timestamps,
        or case_tz for ambiguous sources.
        """
        from utils.timezone import get_source_tz_for_artifact
        return get_source_tz_for_artifact(self.artifact_type, self.case_tz)
    
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
        # Also handles: .../hostname.zip_hash/C/Windows/... (reindex paths)
        path_parts = file_path.replace('\\', '/').split('/')
        for i, part in enumerate(path_parts):
            if part.upper() in ('C', 'D', 'E') and i > 0:
                potential_host = path_parts[i - 1]
                if potential_host and not potential_host.startswith('.'):
                    # Strip .zip_* suffix from reindexed archive paths
                    # e.g., "PANEL-APP.zip_722e232a" -> "PANEL-APP"
                    import re
                    cleaned = re.sub(r'\.zip_[a-f0-9]+$', '', potential_host, flags=re.IGNORECASE)
                    return cleaned if cleaned else potential_host
        
        return 'unknown'
    
    def parse_timestamp(self, value: Any, formats: List[str] = None,
                        warn: bool = True) -> Optional[datetime]:
        """Parse timestamp from various formats
        
        Args:
            value: Timestamp value (string, datetime, or None)
            formats: List of strptime format strings to try
            warn: Record a warning when the value cannot be parsed. Callers
                that try every column looking for a date should pass False,
                because a miss there is the expected outcome, not a fault.
            
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
        
        if warn:
            self.warnings.append(f"Could not parse timestamp: {value}")
        return None

    def probe_timestamp(self, value: Any, formats: List[str] = None) -> Optional[datetime]:
        """Try to read a timestamp without treating a miss as a fault."""
        return self.parse_timestamp(value, formats=formats, warn=False)

    def fallback_timestamp(self, file_path: str = '', reason: str = '') -> datetime:
        """Return a consistent fallback timestamp with a single warning per reason.

        Preference order:
        1. Source file modification time when available
        2. Current UTC time as a last resort
        """
        fallback = None
        fallback_source = 'current_utc_time'

        # The fallback is UTC by construction. It is returned timezone aware so
        # that an ambiguous-source parser labelling its events with the case
        # timezone cannot shift it a second time.
        if file_path and os.path.exists(file_path):
            try:
                fallback = datetime.fromtimestamp(
                    os.path.getmtime(file_path),
                    tz=timezone.utc,
                )
                fallback_source = 'file_mtime_utc'
            except OSError:
                pass

        if fallback is None:
            fallback = datetime.now(timezone.utc)

        warning_key = (file_path or '', reason or fallback_source)
        if warning_key not in self._timestamp_fallback_warnings:
            details = reason or 'missing or invalid event timestamp'
            self.warnings.append(
                f"Using {fallback_source} fallback for {details}"
            )
            self._timestamp_fallback_warnings.add(warning_key)

        return fallback

    def first_timestamp(self, *timestamps: Optional[datetime], file_path: str = '', reason: str = '') -> datetime:
        """Return the first non-null timestamp, otherwise use the shared fallback policy."""
        for ts in timestamps:
            if ts is not None:
                return ts
        return self.fallback_timestamp(file_path=file_path, reason=reason)
    
    def safe_int(self, value: Any, default: int = None) -> Optional[int]:
        """Safely convert value to integer"""
        if value is None:
            return default
        try:
            return int(value)
        except (ValueError, TypeError):
            return default
    
    def safe_uint8(self, value: Any, default: int = None) -> Optional[int]:
        """Safely convert value to UInt8 (0-255), returning default if out of range"""
        if value is None:
            return default
        try:
            val = int(value)
            return val if 0 <= val <= 255 else default
        except (ValueError, TypeError):
            return default
    
    # KAPE targets, EvtxECmd maps and similar tool configuration files travel
    # with the evidence and name vendors and artifacts in plain text, so a
    # parser sniffing for its own vendor name readily mistakes them for logs.
    TOOL_CONFIGURATION_EXTENSIONS = (
        '.tkape', '.mkape', '.map', '.reb', '.ps1xml', '.chm',
        '.dll', '.exe', '.pdb', '.sys', '.mui',
    )

    def is_tool_configuration(self, file_path: str) -> bool:
        """True when the file defines how a tool runs rather than being evidence."""
        return os.path.basename(file_path).lower().endswith(self.TOOL_CONFIGURATION_EXTENSIONS)

    def safe_uint16(self, value: Any, default: int = None) -> Optional[int]:
        """Safely convert to UInt16 (ports, logon type), else return default"""
        converted = _clamp_uint(value, UINT16_MAX)
        return default if converted is None else converted

    def safe_uint32(self, value: Any, default: int = None) -> Optional[int]:
        """Safely convert to UInt32, else return default"""
        converted = _clamp_uint(value, UINT32_MAX)
        return default if converted is None else converted

    def safe_uint64(self, value: Any, default: int = None) -> Optional[int]:
        """Safely convert to UInt64 (record ids, PIDs, sizes), else return default"""
        converted = _clamp_uint(value, UINT64_MAX)
        return default if converted is None else converted

    def safe_str(self, value: Any, default: str = '') -> str:
        """Safely convert value to string, handling None and empty
        
        Returns empty string instead of None for ClickHouse compatibility.
        """
        if value is None:
            return default
        s = str(value).strip()
        return s if s and s != '-' else default
    
    def validate_ip(self, value: str) -> Optional[str]:
        """Validate and return IP address or None"""
        if not value or value == '-':
            return None

        try:
            import ipaddress
            return str(ipaddress.ip_address(str(value).strip()))
        except ValueError:
            pass

        return None

    def validate_ipv4(self, value: str) -> Optional[str]:
        """Validate and return IPv4 addresses only.

        ClickHouse stores `src_ip` and `dst_ip` as IPv4 today, so callers that
        write into those columns should use this helper and preserve non-IPv4
        values in string fields or extra metadata instead.
        """
        normalized = self.validate_ip(value)
        if not normalized:
            return None

        try:
            import ipaddress
            ip_obj = ipaddress.ip_address(normalized)
            return normalized if ip_obj.version == 4 else None
        except ValueError:
            return None

    def normalize_ip_for_storage(self, value: Any) -> Tuple[Optional[str], Optional[str]]:
        """Return an IPv4-safe value plus any valid raw IP that could not be stored.

        This keeps parsers aligned with the current ClickHouse `Nullable(IPv4)`
        contract while still preserving IPv6 values for search/detail surfaces.
        """
        raw_value = self.safe_str(value)
        if not raw_value:
            return None, None

        normalized_ipv4 = self.validate_ipv4(raw_value)
        if normalized_ipv4:
            return normalized_ipv4, None

        if self.validate_ip(raw_value):
            return None, raw_value

        return None, None

    def format_exception(self, exc: Exception, context: str = '') -> str:
        """Return a stable, human-readable exception message."""
        exc_type = exc.__class__.__name__ if exc else 'Error'
        detail = str(exc).strip() if exc else ''
        message = f'{exc_type}: {detail}' if detail else exc_type
        return f'{context}: {message}' if context else message
