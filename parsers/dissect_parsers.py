"""Dissect-based Parsers for CaseScope

Uses the Dissect framework (https://docs.dissect.tools/) for parsing
various Windows forensic artifacts:

- Prefetch files (.pf)
- Registry hives
- LNK/Shortcut files
- Jump Lists
- SRUM database
- Amcache
- Shellbags

Dissect provides:
- Pure Python parsing (no external binaries)
- Cross-platform support
- Well-tested forensic parsing
- Unified interfaces
"""
import os
import json
import logging
from datetime import datetime
from typing import Generator, Dict, List, Any, Optional
from pathlib import Path

from parsers.base import BaseParser, ParsedEvent

logger = logging.getLogger(__name__)


class PrefetchParser(BaseParser):
    """Parser for Windows Prefetch files using dissect.target
    
    Extracts execution timestamps, loaded files, and run counts from
    Windows Prefetch files (.pf).
    """
    
    VERSION = '2.0.0'
    ARTIFACT_TYPE = 'prefetch'
    
    def __init__(self, case_id: int, source_host: str = '', case_file_id: Optional[int] = None):
        super().__init__(case_id, source_host, case_file_id)
        
        try:
            from dissect.target.plugins.os.windows.prefetch import Prefetch
            self._prefetch_class = Prefetch
        except ImportError:
            raise ImportError("dissect.target not installed. Install with: pip install dissect.target")
    
    @property
    def artifact_type(self) -> str:
        return self.ARTIFACT_TYPE
    
    def can_parse(self, file_path: str) -> bool:
        """Check if file is a Prefetch file"""
        if not os.path.isfile(file_path):
            return False
        
        # Check extension
        if file_path.lower().endswith('.pf'):
            return True
        
        # Check magic bytes (SCCA or MAM for different versions)
        try:
            with open(file_path, 'rb') as f:
                magic = f.read(4)
                return magic in (b'SCCA', b'MAM\x04')
        except Exception:
            return False
    
    def parse(self, file_path: str) -> Generator[ParsedEvent, None, None]:
        """Parse Prefetch file using dissect.target"""
        if not self.can_parse(file_path):
            self.errors.append(f"Cannot parse file: {file_path}")
            return
        
        source_file = os.path.basename(file_path)
        hostname = self.extract_hostname(file_path)
        
        try:
            from dissect.target.plugins.os.windows.prefetch import Prefetch
            
            with open(file_path, 'rb') as fh:
                pf = Prefetch(fh)
                
                # Extract executable name from header or filename
                exe_name = ''
                if hasattr(pf, 'header') and hasattr(pf.header, 'name'):
                    # Decode UTF-16LE name from header
                    try:
                        exe_name = pf.header.name.decode('utf-16-le').rstrip('\x00')
                    except:
                        pass
                
                if not exe_name:
                    # Fallback: extract from filename (PROGRAM.EXE-HASH.pf)
                    exe_name = source_file.rsplit('-', 1)[0] if '-' in source_file else source_file
                    exe_name = exe_name.replace('.pf', '').replace('.PF', '')
                
                # Get all run times
                run_times = []
                if hasattr(pf, 'latest_timestamp') and pf.latest_timestamp:
                    run_times.append(pf.latest_timestamp)
                if hasattr(pf, 'previous_timestamps') and pf.previous_timestamps:
                    run_times.extend(pf.previous_timestamps)
                
                # Get run count from fn structure
                run_count = 0
                if hasattr(pf, 'fn') and hasattr(pf.fn, 'run_count'):
                    run_count = pf.fn.run_count
                if run_count == 0:
                    run_count = len(run_times)
                
                # Get loaded files from metrics
                loaded_files = []
                if hasattr(pf, 'metrics'):
                    try:
                        loaded_files = list(pf.metrics)
                    except:
                        pass
                
                # Get prefetch version
                pf_version = pf.version if hasattr(pf, 'version') else 0
                
                # Create an event for each execution time
                for i, run_time in enumerate(run_times):
                    timestamp = run_time if isinstance(run_time, datetime) else self.parse_timestamp(str(run_time))
                    if not timestamp:
                        timestamp = datetime.now()
                    
                    raw_data = {
                        'executable': exe_name,
                        'run_count': run_count,
                        'run_index': i + 1,
                        'total_runs': len(run_times),
                        'prefetch_version': pf_version,
                        'loaded_files': loaded_files[:50],
                        'loaded_file_count': len(loaded_files),
                    }
                    
                    # Build search blob with loaded files
                    search_parts = [exe_name] + loaded_files[:30]
                    
                    yield ParsedEvent(
                        case_id=self.case_id,
                        artifact_type=self.artifact_type,
                        timestamp=timestamp,
                        source_file=source_file,
                        source_path=file_path,
                        source_host=hostname,
                        case_file_id=self.case_file_id,
                        process_name=exe_name,
                        raw_json=json.dumps(raw_data, default=str),
                        search_blob=' '.join(search_parts),
                        extra_fields=json.dumps({
                            'run_count': run_count,
                            'run_index': i + 1,
                            'total_runs': len(run_times),
                            'prefetch_version': pf_version,
                            'loaded_files': loaded_files[:100],
                        }, default=str),
                        parser_version=self.parser_version,
                    )
                
                # If no run times, create a single event with current time
                if not run_times:
                    raw_data = {
                        'executable': exe_name,
                        'run_count': run_count,
                        'prefetch_version': pf_version,
                        'loaded_files': loaded_files[:50],
                        'loaded_file_count': len(loaded_files),
                    }
                    
                    search_parts = [exe_name] + loaded_files[:30]
                    
                    yield ParsedEvent(
                        case_id=self.case_id,
                        artifact_type=self.artifact_type,
                        timestamp=datetime.now(),
                        source_file=source_file,
                        source_path=file_path,
                        source_host=hostname,
                        case_file_id=self.case_file_id,
                        process_name=exe_name,
                        raw_json=json.dumps(raw_data, default=str),
                        search_blob=' '.join(search_parts),
                        extra_fields=json.dumps({
                            'run_count': run_count,
                            'prefetch_version': pf_version,
                            'loaded_files': loaded_files[:100],
                        }, default=str),
                        parser_version=self.parser_version,
                    )
                
        except Exception as e:
            self.errors.append(f"Failed to parse {file_path}: {e}")
            logger.exception(f"Prefetch parse error: {e}")


class RegistryParser(BaseParser):
    """Parser for Windows Registry hives using dissect.regf
    
    Parses SAM, SECURITY, SOFTWARE, SYSTEM, NTUSER.DAT, USRCLASS.DAT, and Amcache.
    Extracts registry keys and values as individual events for granular searching.
    """
    
    VERSION = '2.0.0'
    ARTIFACT_TYPE = 'registry'
    
    # Registry hive signatures
    REGISTRY_MAGIC = b'regf'
    
    # Known hive names for identification
    HIVE_NAMES = {
        'sam': 'SAM',
        'security': 'SECURITY', 
        'software': 'SOFTWARE',
        'system': 'SYSTEM',
        'ntuser.dat': 'NTUSER.DAT',
        'usrclass.dat': 'USRCLASS.DAT',
        'amcache.hve': 'AMCACHE',
    }
    
    # High-value keys to extract
    INTERESTING_KEYS = [
        # Run keys (persistence)
        r'Microsoft\Windows\CurrentVersion\Run',
        r'Microsoft\Windows\CurrentVersion\RunOnce',
        r'Microsoft\Windows\CurrentVersion\RunServices',
        r'Microsoft\Windows\CurrentVersion\Policies\Explorer\Run',
        # Services
        r'ControlSet001\Services',
        r'ControlSet002\Services',
        # USB devices
        r'ControlSet001\Enum\USB',
        r'ControlSet001\Enum\USBSTOR',
        # Network
        r'Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles',
        # User assist
        r'Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist',
        # Recent docs
        r'Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs',
        # Shell bags
        r'Software\Microsoft\Windows\Shell\BagMRU',
        r'Software\Microsoft\Windows\Shell\Bags',
    ]
    
    def __init__(self, case_id: int, source_host: str = '', case_file_id: Optional[int] = None,
                 extract_all: bool = False):
        """Initialize Registry parser
        
        Args:
            case_id: ClickHouse case_id
            source_host: Hostname
            case_file_id: Optional FK to case_files
            extract_all: If True, extract all keys. If False, only interesting keys.
        """
        super().__init__(case_id, source_host, case_file_id)
        self.extract_all = extract_all
        
        try:
            from dissect.regf import RegistryHive
            self._registry_class = RegistryHive
        except ImportError:
            raise ImportError("dissect.regf not installed. Install with: pip install dissect.regf")
    
    @property
    def artifact_type(self) -> str:
        return self.ARTIFACT_TYPE
    
    def can_parse(self, file_path: str) -> bool:
        """Check if file is a Registry hive"""
        if not os.path.isfile(file_path):
            return False
        
        # Check known names
        filename_lower = os.path.basename(file_path).lower()
        if filename_lower in self.HIVE_NAMES:
            return True
        
        # Check extension
        if filename_lower.endswith(('.dat', '.hve', '.hiv')):
            pass  # Continue to magic byte check
        
        # Check magic bytes
        try:
            with open(file_path, 'rb') as f:
                magic = f.read(4)
                return magic == self.REGISTRY_MAGIC
        except Exception:
            return False
    
    def parse(self, file_path: str) -> Generator[ParsedEvent, None, None]:
        """Parse Registry hive"""
        if not self.can_parse(file_path):
            self.errors.append(f"Cannot parse file: {file_path}")
            return
        
        source_file = os.path.basename(file_path)
        hostname = self.extract_hostname(file_path)
        
        # Identify hive type
        hive_type = self.HIVE_NAMES.get(source_file.lower(), 'UNKNOWN')
        
        try:
            from dissect.regf import RegistryHive
            
            with open(file_path, 'rb') as fh:
                hive = RegistryHive(fh)
                
                def process_key(key, depth=0, max_depth=10):
                    """Recursively process registry keys, yielding one event per value"""
                    if depth > max_depth:
                        return
                    
                    try:
                        # Get key timestamp
                        timestamp = key.timestamp if hasattr(key, 'timestamp') else datetime.now()
                        if not isinstance(timestamp, datetime):
                            timestamp = self.parse_timestamp(str(timestamp)) or datetime.now()
                        
                        key_path = str(key.path) if hasattr(key, 'path') else str(key)
                        
                        # Process each value as a separate event
                        try:
                            for value in key.values():
                                value_name = value.name or '(Default)'
                                value_type = ''
                                value_data = ''
                                
                                try:
                                    # Get value type
                                    if hasattr(value, 'type'):
                                        value_type = str(value.type.name) if hasattr(value.type, 'name') else str(value.type)
                                    
                                    # Get value data
                                    raw_value = value.value
                                    if raw_value is None:
                                        value_data = ''
                                    elif isinstance(raw_value, bytes):
                                        # Try to decode, fallback to hex
                                        try:
                                            value_data = raw_value.decode('utf-16-le').rstrip('\x00')
                                        except:
                                            try:
                                                value_data = raw_value.decode('utf-8', errors='replace')
                                            except:
                                                value_data = raw_value.hex()
                                    elif isinstance(raw_value, (list, tuple)):
                                        value_data = ', '.join(str(v) for v in raw_value)
                                    else:
                                        value_data = str(raw_value)
                                    
                                    # Limit data size
                                    value_data = value_data[:2000]
                                    
                                except Exception as e:
                                    value_data = f'<error: {e}>'
                                
                                raw_data = {
                                    'hive_type': hive_type,
                                    'key_path': key_path,
                                    'value_name': value_name,
                                    'value_type': value_type,
                                    'value_data': value_data,
                                }
                                
                                # Build search blob
                                search_parts = [key_path, value_name, value_data]
                                
                                yield ParsedEvent(
                                    case_id=self.case_id,
                                    artifact_type=self.artifact_type,
                                    timestamp=timestamp,
                                    source_file=source_file,
                                    source_path=file_path,
                                    source_host=hostname,
                                    case_file_id=self.case_file_id,
                                    reg_key=self.safe_str(key_path),
                                    reg_value=self.safe_str(value_name),
                                    reg_data=self.safe_str(value_data),
                                    raw_json=json.dumps(raw_data, default=str),
                                    search_blob=' '.join(str(p) for p in search_parts if p),
                                    extra_fields=json.dumps({
                                        'hive_type': hive_type,
                                        'value_type': value_type,
                                    }, default=str),
                                    parser_version=self.parser_version,
                                )
                        except Exception as e:
                            self.warnings.append(f"Error reading values for {key_path}: {e}")
                        
                        # Process subkeys
                        try:
                            for subkey in key.subkeys():
                                yield from process_key(subkey, depth + 1, max_depth)
                        except:
                            pass
                            
                    except Exception as e:
                        self.warnings.append(f"Error processing key: {e}")
                
                # Start from root
                root = hive.root()
                if self.extract_all:
                    yield from process_key(root)
                else:
                    # Only extract interesting keys
                    for key_pattern in self.INTERESTING_KEYS:
                        try:
                            key = hive.open(key_pattern)
                            if key:
                                yield from process_key(key, max_depth=3)
                        except:
                            pass
                        
        except Exception as e:
            self.errors.append(f"Failed to parse {file_path}: {e}")
            logger.exception(f"Registry parse error: {e}")


class LnkParser(BaseParser):
    """Parser for Windows LNK/Shortcut files using dissect.shellitem
    
    Extracts target path, timestamps, arguments, and other metadata from
    Windows shortcut files.
    """
    
    VERSION = '2.0.0'
    ARTIFACT_TYPE = 'lnk'
    
    def __init__(self, case_id: int, source_host: str = '', case_file_id: Optional[int] = None):
        super().__init__(case_id, source_host, case_file_id)
        
        try:
            from dissect.shellitem.lnk import Lnk
            self._lnk_class = Lnk
        except ImportError:
            raise ImportError("dissect.shellitem not installed. Install with: pip install dissect.shellitem")
    
    @property
    def artifact_type(self) -> str:
        return self.ARTIFACT_TYPE
    
    def can_parse(self, file_path: str) -> bool:
        """Check if file is a LNK file"""
        if not os.path.isfile(file_path):
            return False
        
        if file_path.lower().endswith('.lnk'):
            return True
        
        # LNK magic: 4C 00 00 00 (little-endian CLSID)
        try:
            with open(file_path, 'rb') as f:
                magic = f.read(4)
                return magic == b'\x4c\x00\x00\x00'
        except Exception:
            return False
    
    def _convert_wintime(self, wintime) -> Optional[datetime]:
        """Convert Windows FILETIME to datetime"""
        if not wintime or wintime == 0:
            return None
        try:
            from dissect.util import ts
            return ts.wintimestamp(wintime)
        except Exception:
            return None
    
    def parse(self, file_path: str) -> Generator[ParsedEvent, None, None]:
        """Parse LNK file using dissect.shellitem"""
        if not self.can_parse(file_path):
            self.errors.append(f"Cannot parse file: {file_path}")
            return
        
        source_file = os.path.basename(file_path)
        hostname = self.extract_hostname(file_path)
        
        try:
            from dissect.shellitem.lnk import Lnk
            
            with open(file_path, 'rb') as fh:
                lnk = Lnk(fh)
                
                # === Extract target path from linkinfo ===
                target_path = None
                if lnk.linkinfo:
                    if hasattr(lnk.linkinfo, 'local_base_path') and lnk.linkinfo.local_base_path:
                        target_path = lnk.linkinfo.local_base_path
                        if isinstance(target_path, bytes):
                            target_path = target_path.decode('utf-8', errors='replace')
                    elif hasattr(lnk.linkinfo, 'local_base_path_unicode') and lnk.linkinfo.local_base_path_unicode:
                        target_path = str(lnk.linkinfo.local_base_path_unicode)
                
                # === Extract string data (relative path, arguments, etc.) ===
                relative_path = None
                arguments = None
                working_dir = None
                icon_location = None
                
                if lnk.stringdata and hasattr(lnk.stringdata, 'string_data'):
                    sd = lnk.stringdata.string_data
                    if isinstance(sd, dict):
                        if 'relative_path' in sd:
                            relative_path = sd['relative_path'].string
                        if 'command_line_arguments' in sd:
                            arguments = sd['command_line_arguments'].string
                        if 'working_dir' in sd:
                            working_dir = sd['working_dir'].string
                        if 'icon_location' in sd:
                            icon_location = sd['icon_location'].string
                
                # Fall back to relative path if no absolute target
                if not target_path and relative_path:
                    target_path = relative_path
                
                # === Extract timestamps from link_header ===
                creation_time = None
                access_time = None
                write_time = None
                file_size = None
                
                if lnk.link_header:
                    hdr = lnk.link_header
                    creation_time = self._convert_wintime(getattr(hdr, 'creation_time', None))
                    access_time = self._convert_wintime(getattr(hdr, 'access_time', None))
                    write_time = self._convert_wintime(getattr(hdr, 'write_time', None))
                    file_size = getattr(hdr, 'filesize', None)
                
                # Use access time as primary (most recent interaction)
                timestamp = access_time or write_time or creation_time
                if not timestamp:
                    timestamp = datetime.now()
                
                # === Extract tracker data (machine ID) from extradata ===
                machine_id = None
                mac_address = None
                volume_droid = None
                file_droid = None
                
                if lnk.extradata and hasattr(lnk.extradata, 'extradata'):
                    ed_dict = lnk.extradata.extradata
                    if isinstance(ed_dict, dict):
                        # TRACKER_PROPS contains machine ID and file tracking info
                        tracker = ed_dict.get('TRACKER_PROPS')
                        if tracker:
                            if hasattr(tracker, 'machine_id'):
                                mid = tracker.machine_id
                                if isinstance(mid, bytes):
                                    machine_id = mid.decode('utf-8', errors='replace').rstrip('\x00')
                                else:
                                    machine_id = str(mid)
                            if hasattr(tracker, 'volume_droid'):
                                volume_droid = str(tracker.volume_droid)
                            if hasattr(tracker, 'file_droid'):
                                file_droid = str(tracker.file_droid)
                
                # === Extract process name from target ===
                process_name = ''
                if target_path:
                    # Get filename from path
                    process_name = os.path.basename(target_path.replace('\\', '/'))
                
                # === Build raw data ===
                raw_data = {
                    'lnk_file': source_file,
                    'target_path': target_path,
                    'relative_path': relative_path,
                    'arguments': arguments,
                    'working_directory': working_dir,
                    'icon_location': icon_location,
                    'creation_time': str(creation_time) if creation_time else None,
                    'access_time': str(access_time) if access_time else None,
                    'write_time': str(write_time) if write_time else None,
                    'file_size': file_size,
                    'machine_id': machine_id,
                    'volume_droid': volume_droid,
                    'file_droid': file_droid,
                }
                # Remove None values
                raw_data = {k: v for k, v in raw_data.items() if v is not None}
                
                # === Build search blob ===
                search_parts = [source_file]
                if target_path:
                    search_parts.append(target_path)
                if relative_path and relative_path != target_path:
                    search_parts.append(relative_path)
                if arguments:
                    search_parts.append(arguments)
                if working_dir:
                    search_parts.append(working_dir)
                if machine_id:
                    search_parts.append(machine_id)
                
                # === Build extra fields ===
                extra = {
                    'relative_path': relative_path,
                    'working_directory': working_dir,
                    'icon_location': icon_location,
                    'creation_time': str(creation_time) if creation_time else None,
                    'write_time': str(write_time) if write_time else None,
                    'file_size': file_size,
                    'machine_id': machine_id,
                    'volume_droid': volume_droid,
                    'file_droid': file_droid,
                }
                extra = {k: v for k, v in extra.items() if v is not None}
                
                yield ParsedEvent(
                    case_id=self.case_id,
                    artifact_type=self.artifact_type,
                    timestamp=timestamp,
                    source_file=source_file,
                    source_path=file_path,
                    source_host=hostname,
                    case_file_id=self.case_file_id,
                    process_name=process_name,
                    target_path=target_path,
                    command_line=arguments,
                    file_size=file_size,
                    raw_json=json.dumps(raw_data, default=str),
                    search_blob=' '.join(str(p) for p in search_parts if p),
                    extra_fields=json.dumps(extra, default=str),
                    parser_version=self.parser_version,
                )
            
        except Exception as e:
            self.errors.append(f"Failed to parse {file_path}: {e}")
            logger.exception(f"LNK parse error: {e}")


class JumpListParser(BaseParser):
    """Parser for Windows Jump List files using dissect.ole
    
    Parses AutomaticDestinations-ms and CustomDestinations-ms files
    which contain LNK entries for recently accessed files.
    """
    
    VERSION = '2.0.0'
    ARTIFACT_TYPE = 'jumplist'
    
    def __init__(self, case_id: int, source_host: str = '', case_file_id: Optional[int] = None):
        super().__init__(case_id, source_host, case_file_id)
        
        try:
            from dissect.ole import OLE
            from dissect.shellitem.lnk import Lnk
            self._ole_class = OLE
            self._lnk_class = Lnk
        except ImportError as e:
            raise ImportError(f"dissect.ole or dissect.shellitem not installed: {e}")
    
    @property
    def artifact_type(self) -> str:
        return self.ARTIFACT_TYPE
    
    def can_parse(self, file_path: str) -> bool:
        """Check if file is a Jump List"""
        if not os.path.isfile(file_path):
            return False
        
        filename = os.path.basename(file_path).lower()
        return filename.endswith(('.automaticdestinations-ms', '.customdestinations-ms'))
    
    def _convert_wintime(self, wintime) -> Optional[datetime]:
        """Convert Windows FILETIME to datetime"""
        if not wintime or wintime == 0:
            return None
        try:
            from dissect.util import ts
            return ts.wintimestamp(wintime)
        except Exception:
            return None
    
    def parse(self, file_path: str) -> Generator[ParsedEvent, None, None]:
        """Parse Jump List file using dissect.ole"""
        if not self.can_parse(file_path):
            self.errors.append(f"Cannot parse file: {file_path}")
            return
        
        source_file = os.path.basename(file_path)
        hostname = self.extract_hostname(file_path)
        
        # Extract AppID from filename (hash before .automaticDestinations-ms)
        app_id = source_file.split('.')[0] if '.' in source_file else source_file
        
        try:
            from dissect.ole import OLE
            from dissect.shellitem.lnk import Lnk
            import io
            
            with open(file_path, 'rb') as fh:
                ole = OLE(fh)
                
                # List all streams in the OLE file
                entries = list(ole.root.listdir())
                
                for entry_name in entries:
                    # Skip DestList (metadata) stream
                    if entry_name == 'DestList':
                        continue
                    
                    try:
                        entry = ole.get(entry_name)
                        data = entry.open().read()
                        
                        # LNK magic: 4C 00 00 00
                        if len(data) < 4 or data[:4] != b'\x4c\x00\x00\x00':
                            continue
                        
                        lnk = Lnk(io.BytesIO(data))
                        
                        # === Extract target path from linkinfo ===
                        target_path = None
                        if lnk.linkinfo:
                            if hasattr(lnk.linkinfo, 'local_base_path') and lnk.linkinfo.local_base_path:
                                target_path = lnk.linkinfo.local_base_path
                                if isinstance(target_path, bytes):
                                    target_path = target_path.decode('utf-8', errors='replace')
                        
                        # === Extract from stringdata ===
                        relative_path = None
                        arguments = None
                        
                        if lnk.stringdata and hasattr(lnk.stringdata, 'string_data'):
                            sd = lnk.stringdata.string_data
                            if isinstance(sd, dict):
                                if 'relative_path' in sd:
                                    relative_path = sd['relative_path'].string
                                if 'command_line_arguments' in sd:
                                    arguments = sd['command_line_arguments'].string
                        
                        # Fall back to relative path
                        if not target_path and relative_path:
                            target_path = relative_path
                        
                        # === Extract timestamps ===
                        creation_time = None
                        access_time = None
                        write_time = None
                        file_size = None
                        
                        if lnk.link_header:
                            hdr = lnk.link_header
                            creation_time = self._convert_wintime(getattr(hdr, 'creation_time', None))
                            access_time = self._convert_wintime(getattr(hdr, 'access_time', None))
                            write_time = self._convert_wintime(getattr(hdr, 'write_time', None))
                            file_size = getattr(hdr, 'filesize', None)
                        
                        # Use access time as primary timestamp
                        timestamp = access_time or write_time or creation_time
                        if not timestamp:
                            timestamp = datetime.now()
                        
                        # === Extract tracker data ===
                        machine_id = None
                        volume_droid = None
                        file_droid = None
                        
                        if lnk.extradata and hasattr(lnk.extradata, 'extradata'):
                            ed_dict = lnk.extradata.extradata
                            if isinstance(ed_dict, dict):
                                tracker = ed_dict.get('TRACKER_PROPS')
                                if tracker:
                                    if hasattr(tracker, 'machine_id'):
                                        mid = tracker.machine_id
                                        if isinstance(mid, bytes):
                                            machine_id = mid.decode('utf-8', errors='replace').rstrip('\x00')
                                        else:
                                            machine_id = str(mid)
                                    if hasattr(tracker, 'volume_droid'):
                                        volume_droid = str(tracker.volume_droid)
                                    if hasattr(tracker, 'file_droid'):
                                        file_droid = str(tracker.file_droid)
                        
                        # === Extract process name ===
                        process_name = ''
                        if target_path:
                            process_name = os.path.basename(target_path.replace('\\', '/'))
                        
                        # === Build raw data ===
                        raw_data = {
                            'jumplist_file': source_file,
                            'app_id': app_id,
                            'entry_id': entry_name,
                            'target_path': target_path,
                            'relative_path': relative_path,
                            'arguments': arguments,
                            'creation_time': str(creation_time) if creation_time else None,
                            'access_time': str(access_time) if access_time else None,
                            'write_time': str(write_time) if write_time else None,
                            'file_size': file_size,
                            'machine_id': machine_id,
                            'volume_droid': volume_droid,
                            'file_droid': file_droid,
                        }
                        raw_data = {k: v for k, v in raw_data.items() if v is not None}
                        
                        # === Build search blob ===
                        search_parts = [source_file, app_id]
                        if target_path:
                            search_parts.append(target_path)
                        if relative_path and relative_path != target_path:
                            search_parts.append(relative_path)
                        if arguments:
                            search_parts.append(arguments)
                        if machine_id:
                            search_parts.append(machine_id)
                        
                        # === Build extra fields ===
                        extra = {
                            'app_id': app_id,
                            'entry_id': entry_name,
                            'relative_path': relative_path,
                            'creation_time': str(creation_time) if creation_time else None,
                            'write_time': str(write_time) if write_time else None,
                            'file_size': file_size,
                            'machine_id': machine_id,
                            'volume_droid': volume_droid,
                            'file_droid': file_droid,
                        }
                        extra = {k: v for k, v in extra.items() if v is not None}
                        
                        yield ParsedEvent(
                            case_id=self.case_id,
                            artifact_type=self.artifact_type,
                            timestamp=timestamp,
                            source_file=source_file,
                            source_path=file_path,
                            source_host=hostname,
                            case_file_id=self.case_file_id,
                            process_name=self.safe_str(process_name),
                            target_path=self.safe_str(target_path),
                            command_line=self.safe_str(arguments),
                            file_size=file_size,
                            raw_json=json.dumps(raw_data, default=str),
                            search_blob=' '.join(str(p) for p in search_parts if p),
                            extra_fields=json.dumps(extra, default=str),
                            parser_version=self.parser_version,
                        )
                        
                    except Exception as e:
                        self.warnings.append(f"Error parsing entry {entry_name}: {e}")
                
        except Exception as e:
            self.errors.append(f"Failed to parse {file_path}: {e}")
            logger.exception(f"JumpList parse error: {e}")


class MFTParser(BaseParser):
    """Parser for NTFS MFT ($MFT) files using dissect.ntfs
    
    Extracts file metadata including all MACB timestamps, file sizes,
    and directory structure from the Master File Table.
    """
    
    VERSION = '2.0.0'
    ARTIFACT_TYPE = 'mft'
    
    def __init__(self, case_id: int, source_host: str = '', case_file_id: Optional[int] = None,
                 max_entries: int = 100000):
        """Initialize MFT parser
        
        Args:
            case_id: ClickHouse case_id
            source_host: Hostname
            case_file_id: Optional FK to case_files
            max_entries: Maximum MFT entries to process (MFT can be huge)
        """
        super().__init__(case_id, source_host, case_file_id)
        self.max_entries = max_entries
        
        try:
            from dissect.ntfs import Mft
            self._mft_class = Mft
        except ImportError:
            raise ImportError("dissect.ntfs not installed. Install with: pip install dissect.ntfs")
    
    @property
    def artifact_type(self) -> str:
        return self.ARTIFACT_TYPE
    
    def can_parse(self, file_path: str) -> bool:
        """Check if file is an MFT"""
        if not os.path.isfile(file_path):
            return False
        
        filename = os.path.basename(file_path).lower()
        if filename in ('$mft', 'mft', '$mft_mirr'):
            return True
        
        # Check for FILE signature
        try:
            with open(file_path, 'rb') as f:
                magic = f.read(4)
                return magic == b'FILE'
        except Exception:
            return False
    
    def parse(self, file_path: str) -> Generator[ParsedEvent, None, None]:
        """Parse MFT file using dissect.ntfs"""
        if not self.can_parse(file_path):
            self.errors.append(f"Cannot parse file: {file_path}")
            return
        
        source_file = os.path.basename(file_path)
        hostname = self.extract_hostname(file_path)
        
        try:
            from dissect.ntfs import Mft
            from dissect.ntfs.attr import ATTRIBUTE_TYPE_CODE
            
            with open(file_path, 'rb') as fh:
                mft = Mft(fh)
                count = 0
                
                for record in mft.segments():
                    if count >= self.max_entries:
                        self.warnings.append(f"Reached max entries limit ({self.max_entries})")
                        break
                    
                    try:
                        # Get filename
                        filename = record.filename
                        if not filename:
                            continue
                        
                        # Get record number
                        record_number = record.segment if hasattr(record, 'segment') else None
                        
                        # Determine if file or directory
                        is_directory = record.is_dir()
                        
                        # Get file size
                        file_size = None
                        try:
                            file_size = record.size()
                        except:
                            file_size = 0
                        
                        # Get STANDARD_INFORMATION timestamps
                        si_created = None
                        si_modified = None
                        si_accessed = None
                        si_changed = None
                        
                        si_col = record.attributes.get(ATTRIBUTE_TYPE_CODE.STANDARD_INFORMATION)
                        if si_col:
                            si = si_col[0]
                            si_created = si.creation_time if hasattr(si, 'creation_time') else None
                            si_modified = si.last_modification_time if hasattr(si, 'last_modification_time') else None
                            si_accessed = si.last_access_time if hasattr(si, 'last_access_time') else None
                            si_changed = si.last_change_time if hasattr(si, 'last_change_time') else None
                        
                        # Use modification time as primary timestamp
                        timestamp = si_modified or si_created or si_accessed or datetime.now()
                        if not isinstance(timestamp, datetime):
                            timestamp = self.parse_timestamp(str(timestamp)) or datetime.now()
                        
                        # Build raw data with all timestamps
                        raw_data = {
                            'filename': filename,
                            'record_number': record_number,
                            'is_directory': is_directory,
                            'file_size': file_size,
                            'si_created': str(si_created) if si_created else None,
                            'si_modified': str(si_modified) if si_modified else None,
                            'si_accessed': str(si_accessed) if si_accessed else None,
                            'si_changed': str(si_changed) if si_changed else None,
                        }
                        raw_data = {k: v for k, v in raw_data.items() if v is not None}
                        
                        # Build extra fields
                        extra = {
                            'record_number': record_number,
                            'is_directory': is_directory,
                            'si_created': str(si_created) if si_created else None,
                            'si_accessed': str(si_accessed) if si_accessed else None,
                            'si_changed': str(si_changed) if si_changed else None,
                        }
                        extra = {k: v for k, v in extra.items() if v is not None}
                        
                        # Search blob
                        search_parts = [filename]
                        if record_number:
                            search_parts.append(str(record_number))
                        
                        yield ParsedEvent(
                            case_id=self.case_id,
                            artifact_type=self.artifact_type,
                            timestamp=timestamp,
                            source_file=source_file,
                            source_path=file_path,
                            source_host=hostname,
                            case_file_id=self.case_file_id,
                            target_path=self.safe_str(filename),
                            file_size=file_size,
                            raw_json=json.dumps(raw_data, default=str),
                            search_blob=' '.join(str(p) for p in search_parts if p),
                            extra_fields=json.dumps(extra, default=str),
                            parser_version=self.parser_version,
                        )
                        
                        count += 1
                        
                    except Exception as e:
                        self.warnings.append(f"Error processing MFT record: {e}")
                        
        except Exception as e:
            self.errors.append(f"Failed to parse {file_path}: {e}")
            logger.exception(f"MFT parse error: {e}")


class SRUMParser(BaseParser):
    """Parser for Windows SRUM (System Resource Usage Monitor) database"""
    
    VERSION = '1.0.0'
    ARTIFACT_TYPE = 'srum'
    
    def __init__(self, case_id: int, source_host: str = '', case_file_id: Optional[int] = None):
        super().__init__(case_id, source_host, case_file_id)
        
        try:
            from dissect.esedb import EseDB
            self._esedb_class = EseDB
        except ImportError:
            raise ImportError("dissect.esedb not installed. Install with: pip install dissect.esedb")
    
    @property
    def artifact_type(self) -> str:
        return self.ARTIFACT_TYPE
    
    def can_parse(self, file_path: str) -> bool:
        """Check if file is a SRUM database"""
        if not os.path.isfile(file_path):
            return False
        
        filename = os.path.basename(file_path).lower()
        return filename in ('srudb.dat', 'sru.dat')
    
    def parse(self, file_path: str) -> Generator[ParsedEvent, None, None]:
        """Parse SRUM database"""
        if not self.can_parse(file_path):
            self.errors.append(f"Cannot parse file: {file_path}")
            return
        
        source_file = os.path.basename(file_path)
        hostname = self.extract_hostname(file_path)
        
        try:
            from dissect.esedb import EseDB
            
            db = EseDB(open(file_path, 'rb'))
            
            # Process known SRUM tables
            tables_of_interest = [
                '{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}',  # Application Resource Usage
                '{973F5D5C-1D90-4944-BE8E-24B94231A174}',  # Network Connectivity
                '{DD6636C4-8929-4683-974E-22C046A43763}',  # Network Data Usage
            ]
            
            for table_name in db.tables():
                if str(table_name) not in tables_of_interest:
                    continue
                
                try:
                    table = db.table(table_name)
                    
                    for record in table.records():
                        try:
                            record_dict = {}
                            for column in table.columns():
                                try:
                                    value = record.value(column.name)
                                    if value is not None:
                                        record_dict[column.name] = str(value)
                                except:
                                    pass
                            
                            # Get timestamp
                            timestamp = datetime.now()
                            for ts_field in ['TimeStamp', 'ConnectStartTime', 'StartTime']:
                                if ts_field in record_dict:
                                    ts = self.parse_timestamp(record_dict[ts_field])
                                    if ts:
                                        timestamp = ts
                                        break
                            
                            raw_data = {
                                'table': str(table_name),
                                'record': record_dict,
                            }
                            
                            # Extract app name if available
                            app_name = record_dict.get('AppId', record_dict.get('App', ''))
                            
                            yield ParsedEvent(
                                case_id=self.case_id,
                                artifact_type=self.artifact_type,
                                timestamp=timestamp,
                                source_file=source_file,
                                source_path=file_path,
                                source_host=hostname,
                                case_file_id=self.case_file_id,
                                process_name=app_name if app_name else None,
                                raw_json=json.dumps(raw_data, default=str),
                                search_blob=' '.join(str(v) for v in record_dict.values()),
                                parser_version=self.parser_version,
                            )
                            
                        except Exception as e:
                            self.warnings.append(f"Error processing record: {e}")
                            
                except Exception as e:
                    self.warnings.append(f"Error processing table {table_name}: {e}")
                    
        except Exception as e:
            self.errors.append(f"Failed to parse {file_path}: {e}")
            logger.exception(f"SRUM parse error: {e}")
