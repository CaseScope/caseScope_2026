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
    
    def __init__(self, case_id: int, source_host: str = '', case_file_id: Optional[int] = None,
                 case_tz: str = 'UTC', **kwargs):
        super().__init__(case_id, source_host, case_file_id, case_tz=case_tz)
        
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
                    timestamp = self.first_timestamp(
                        run_time if isinstance(run_time, datetime) else self.parse_timestamp(str(run_time)),
                        file_path=file_path,
                        reason='prefetch run timestamp missing or invalid',
                    )
                    
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
                        timestamp=self.fallback_timestamp(
                            file_path=file_path,
                            reason='prefetch file missing execution timestamps',
                        ),
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
                 case_tz: str = 'UTC', extract_all: bool = False, **kwargs):
        """Initialize Registry parser
        
        Args:
            case_id: ClickHouse case_id
            source_host: Hostname
            case_file_id: Optional FK to case_files
            case_tz: Case timezone (not used - registry timestamps are UTC/FILETIME)
            extract_all: If True, extract all keys. If False, only interesting keys.
        """
        super().__init__(case_id, source_host, case_file_id, case_tz=case_tz)
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
        
        filename_lower = os.path.basename(file_path).lower()
        
        # Exclude transaction log files - they have registry magic but aren't parseable hives
        if filename_lower.endswith(('.log', '.log1', '.log2', '.blf', '.regtrans-ms')):
            return False
        
        # Exclude SA.DAT (Scheduled Tasks state file, not a registry hive)
        if filename_lower == 'sa.dat':
            return False
        
        # Check known hive names
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
                        raw_timestamp = key.timestamp if hasattr(key, 'timestamp') else None
                        parsed_timestamp = raw_timestamp if isinstance(raw_timestamp, datetime) else (
                            self.parse_timestamp(str(raw_timestamp)) if raw_timestamp is not None else None
                        )
                        timestamp = self.first_timestamp(
                            parsed_timestamp,
                            file_path=file_path,
                            reason='registry key missing last-write timestamp',
                        )
                        
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
    
    Handles special cases:
    - Shell folder shortcuts (Control Panel items, etc.)
    - URI scheme shortcuts (ms-settings:, etc.)
    - Standard file shortcuts
    """
    
    VERSION = '2.1.0'
    ARTIFACT_TYPE = 'lnk'
    
    def __init__(self, case_id: int, source_host: str = '', case_file_id: Optional[int] = None,
                 case_tz: str = 'UTC', **kwargs):
        super().__init__(case_id, source_host, case_file_id, case_tz=case_tz)
        
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
        """Parse LNK file using dissect.shellitem
        
        Handles shell/URI shortcuts gracefully by extracting available metadata
        and marking as partial rather than failing completely.
        """
        if not self.can_parse(file_path):
            self.errors.append(f"Cannot parse file: {file_path}")
            return
        
        source_file = os.path.basename(file_path)
        hostname = self.extract_hostname(file_path)
        
        try:
            from dissect.shellitem.lnk import Lnk
            
            with open(file_path, 'rb') as fh:
                lnk = Lnk(fh)
                
                # Track if this is a partial parse (shell folder, URI, etc.)
                is_partial = False
                
                # === Extract target path from linkinfo ===
                target_path = None
                try:
                    if lnk.linkinfo:
                        if hasattr(lnk.linkinfo, 'local_base_path') and lnk.linkinfo.local_base_path:
                            target_path = lnk.linkinfo.local_base_path
                            if isinstance(target_path, bytes):
                                target_path = target_path.decode('utf-8', errors='replace')
                        elif hasattr(lnk.linkinfo, 'local_base_path_unicode') and lnk.linkinfo.local_base_path_unicode:
                            target_path = str(lnk.linkinfo.local_base_path_unicode)
                except Exception as e:
                    self.warnings.append(f"Could not extract linkinfo from {source_file}: {e}")
                    is_partial = True
                
                # === Extract string data (relative path, arguments, etc.) ===
                relative_path = None
                arguments = None
                working_dir = None
                icon_location = None
                name_string = None
                
                try:
                    if lnk.stringdata:
                        # Handle different stringdata structures safely
                        sd = None
                        if hasattr(lnk.stringdata, 'string_data'):
                            sd = lnk.stringdata.string_data
                        
                        if sd is not None and isinstance(sd, dict):
                            if 'relative_path' in sd and sd['relative_path']:
                                try:
                                    relative_path = sd['relative_path'].string
                                except (AttributeError, TypeError):
                                    pass
                            if 'command_line_arguments' in sd and sd['command_line_arguments']:
                                try:
                                    arguments = sd['command_line_arguments'].string
                                except (AttributeError, TypeError):
                                    pass
                            if 'working_dir' in sd and sd['working_dir']:
                                try:
                                    working_dir = sd['working_dir'].string
                                except (AttributeError, TypeError):
                                    pass
                            if 'icon_location' in sd and sd['icon_location']:
                                try:
                                    icon_location = sd['icon_location'].string
                                except (AttributeError, TypeError):
                                    pass
                            if 'name_string' in sd and sd['name_string']:
                                try:
                                    name_string = sd['name_string'].string
                                except (AttributeError, TypeError):
                                    pass
                except Exception as e:
                    logger.debug(f"Could not extract stringdata from {source_file}: {e}")
                    is_partial = True
                
                # Fall back to relative path if no absolute target
                if not target_path and relative_path:
                    target_path = relative_path
                
                # For shell/URI shortcuts, use the name or filename as identifier
                if not target_path:
                    if name_string:
                        target_path = name_string
                    else:
                        target_path = source_file.replace('.lnk', '').replace('.LNK', '')
                    is_partial = True
                    logger.debug(f"Shell/URI shortcut with no file target: {source_file}")
                
                # === Extract timestamps from link_header ===
                creation_time = None
                access_time = None
                write_time = None
                file_size = None
                
                try:
                    if lnk.link_header:
                        hdr = lnk.link_header
                        creation_time = self._convert_wintime(getattr(hdr, 'creation_time', None))
                        access_time = self._convert_wintime(getattr(hdr, 'access_time', None))
                        write_time = self._convert_wintime(getattr(hdr, 'write_time', None))
                        file_size = getattr(hdr, 'filesize', None)
                except Exception as e:
                    self.warnings.append(f"Could not extract timestamps from {source_file}: {e}")
                    is_partial = True
                
                # Use access time as primary (most recent interaction)
                timestamp = self.first_timestamp(
                    access_time,
                    write_time,
                    creation_time,
                    file_path=file_path,
                    reason='lnk entry missing header timestamps',
                )
                
                # === Extract tracker data (machine ID) from extradata ===
                machine_id = None
                volume_droid = None
                file_droid = None
                
                try:
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
                except Exception as e:
                    self.warnings.append(f"Could not extract extradata from {source_file}: {e}")
                    is_partial = True
                
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
                    'name_string': name_string,
                    'creation_time': str(creation_time) if creation_time else None,
                    'access_time': str(access_time) if access_time else None,
                    'write_time': str(write_time) if write_time else None,
                    'file_size': file_size,
                    'machine_id': machine_id,
                    'volume_droid': volume_droid,
                    'file_droid': file_droid,
                    'is_shell_link': is_partial,
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
                if name_string:
                    search_parts.append(name_string)
                
                # === Build extra fields ===
                extra = {
                    'relative_path': relative_path,
                    'working_directory': working_dir,
                    'icon_location': icon_location,
                    'name_string': name_string,
                    'creation_time': str(creation_time) if creation_time else None,
                    'write_time': str(write_time) if write_time else None,
                    'file_size': file_size,
                    'machine_id': machine_id,
                    'volume_droid': volume_droid,
                    'file_droid': file_droid,
                    'is_shell_link': is_partial,
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
                    process_name=process_name or '',
                    target_path=target_path or '',
                    command_line=arguments or '',
                    file_size=file_size,
                    raw_json=json.dumps(raw_data, default=str),
                    search_blob=' '.join(str(p) for p in search_parts if p),
                    extra_fields=json.dumps(extra, default=str),
                    parser_version=self.parser_version,
                )
            
        except Exception as e:
            # For any remaining errors, log as warning and try to create minimal event
            self.warnings.append(f"Partial parse of {source_file}: {e}")
            logger.warning(f"LNK partial parse for {file_path}: {e}")
            
            # Try to yield a minimal event with just the filename
            try:
                yield ParsedEvent(
                    case_id=self.case_id,
                    artifact_type=self.artifact_type,
                    timestamp=self.fallback_timestamp(
                        file_path=file_path,
                        reason='lnk partial parse fallback event',
                    ),
                    source_file=source_file,
                    source_path=file_path,
                    source_host=hostname,
                    case_file_id=self.case_file_id,
                    process_name=source_file.replace('.lnk', '').replace('.LNK', ''),
                    target_path=source_file.replace('.lnk', '').replace('.LNK', ''),
                    raw_json=json.dumps({'lnk_file': source_file, 'error': str(e), 'is_shell_link': True}, default=str),
                    search_blob=source_file,
                    extra_fields=json.dumps({'is_shell_link': True, 'parse_error': str(e)}),
                    parser_version=self.parser_version,
                )
            except Exception:
                # If even that fails, add to errors
                self.errors.append(f"Failed to parse {file_path}: {e}")


class JumpListParser(BaseParser):
    """Parser for Windows Jump List files using dissect.ole
    
    Parses AutomaticDestinations-ms and CustomDestinations-ms files
    which contain LNK entries for recently accessed files.
    
    Handles corrupt/empty OLE files gracefully.
    """
    
    VERSION = '2.1.0'
    ARTIFACT_TYPE = 'jumplist'
    
    def __init__(self, case_id: int, source_host: str = '', case_file_id: Optional[int] = None,
                 case_tz: str = 'UTC', **kwargs):
        super().__init__(case_id, source_host, case_file_id, case_tz=case_tz)
        
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
        """Parse Jump List file using dissect.ole
        
        Handles corrupt/empty OLE files gracefully by marking as partial
        rather than failing completely.
        """
        if not self.can_parse(file_path):
            self.errors.append(f"Cannot parse file: {file_path}")
            return
        
        source_file = os.path.basename(file_path)
        hostname = self.extract_hostname(file_path)
        
        # Extract AppID from filename (hash before .automaticDestinations-ms)
        app_id = source_file.split('.')[0] if '.' in source_file else source_file
        
        # Check if file is empty or too small
        try:
            file_size = os.path.getsize(file_path)
            if file_size < 512:  # OLE header is at least 512 bytes
                self.warnings.append(f"JumpList file too small ({file_size} bytes): {source_file}")
                # Yield a minimal event for tracking
                yield ParsedEvent(
                    case_id=self.case_id,
                    artifact_type=self.artifact_type,
                    timestamp=self.fallback_timestamp(
                        file_path=file_path,
                        reason='jumplist file too small fallback event',
                    ),
                    source_file=source_file,
                    source_path=file_path,
                    source_host=hostname,
                    case_file_id=self.case_file_id,
                    raw_json=json.dumps({'jumplist_file': source_file, 'app_id': app_id, 'status': 'empty_or_corrupt', 'file_size': file_size}, default=str),
                    search_blob=f"{source_file} {app_id} jumplist empty",
                    extra_fields=json.dumps({'app_id': app_id, 'status': 'empty_or_corrupt'}),
                    parser_version=self.parser_version,
                )
                return
        except Exception:
            pass
        
        entries_parsed = 0
        
        try:
            from dissect.ole import OLE
            from dissect.shellitem.lnk import Lnk
            import io
            
            with open(file_path, 'rb') as fh:
                ole = OLE(fh)
                
                # List all streams in the OLE file
                try:
                    entries = list(ole.root.listdir())
                except Exception as e:
                    self.warnings.append(f"Could not list OLE entries in {source_file}: {e}")
                    # Yield minimal event for corrupted OLE
                    yield ParsedEvent(
                        case_id=self.case_id,
                        artifact_type=self.artifact_type,
                        timestamp=self.fallback_timestamp(
                            file_path=file_path,
                            reason='jumplist corrupt structure fallback event',
                        ),
                        source_file=source_file,
                        source_path=file_path,
                        source_host=hostname,
                        case_file_id=self.case_file_id,
                        raw_json=json.dumps({'jumplist_file': source_file, 'app_id': app_id, 'status': 'corrupt_structure', 'error': str(e)}, default=str),
                        search_blob=f"{source_file} {app_id} jumplist corrupt",
                        extra_fields=json.dumps({'app_id': app_id, 'status': 'corrupt_structure'}),
                        parser_version=self.parser_version,
                    )
                    return
                
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
                        try:
                            if lnk.linkinfo:
                                if hasattr(lnk.linkinfo, 'local_base_path') and lnk.linkinfo.local_base_path:
                                    target_path = lnk.linkinfo.local_base_path
                                    if isinstance(target_path, bytes):
                                        target_path = target_path.decode('utf-8', errors='replace')
                        except Exception:
                            pass
                        
                        # === Extract from stringdata ===
                        relative_path = None
                        arguments = None
                        
                        try:
                            if lnk.stringdata and hasattr(lnk.stringdata, 'string_data'):
                                sd = lnk.stringdata.string_data
                                if sd is not None and isinstance(sd, dict):
                                    if 'relative_path' in sd and sd['relative_path']:
                                        try:
                                            relative_path = sd['relative_path'].string
                                        except (AttributeError, TypeError):
                                            pass
                                    if 'command_line_arguments' in sd and sd['command_line_arguments']:
                                        try:
                                            arguments = sd['command_line_arguments'].string
                                        except (AttributeError, TypeError):
                                            pass
                        except Exception:
                            pass
                        
                        # Fall back to relative path
                        if not target_path and relative_path:
                            target_path = relative_path
                        
                        # === Extract timestamps ===
                        creation_time = None
                        access_time = None
                        write_time = None
                        lnk_file_size = None
                        
                        try:
                            if lnk.link_header:
                                hdr = lnk.link_header
                                creation_time = self._convert_wintime(getattr(hdr, 'creation_time', None))
                                access_time = self._convert_wintime(getattr(hdr, 'access_time', None))
                                write_time = self._convert_wintime(getattr(hdr, 'write_time', None))
                                lnk_file_size = getattr(hdr, 'filesize', None)
                        except Exception:
                            pass
                        
                        # Use access time as primary timestamp
                        timestamp = self.first_timestamp(
                            access_time,
                            write_time,
                            creation_time,
                            file_path=file_path,
                            reason='jumplist lnk entry missing timestamps',
                        )
                        
                        # === Extract tracker data ===
                        machine_id = None
                        volume_droid = None
                        file_droid = None
                        
                        try:
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
                        except Exception:
                            pass
                        
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
                            'file_size': lnk_file_size,
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
                            'file_size': lnk_file_size,
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
                            file_size=lnk_file_size,
                            raw_json=json.dumps(raw_data, default=str),
                            search_blob=' '.join(str(p) for p in search_parts if p),
                            extra_fields=json.dumps(extra, default=str),
                            parser_version=self.parser_version,
                        )
                        
                        entries_parsed += 1
                        
                    except Exception as e:
                        self.warnings.append(f"Error parsing entry {entry_name}: {e}")
                
                # If no entries were parsed, yield a minimal event
                if entries_parsed == 0:
                    self.warnings.append(f"No valid LNK entries found in {source_file}")
                    yield ParsedEvent(
                        case_id=self.case_id,
                        artifact_type=self.artifact_type,
                        timestamp=self.fallback_timestamp(
                            file_path=file_path,
                            reason='jumplist file missing valid entries',
                        ),
                        source_file=source_file,
                        source_path=file_path,
                        source_host=hostname,
                        case_file_id=self.case_file_id,
                        raw_json=json.dumps({'jumplist_file': source_file, 'app_id': app_id, 'status': 'no_valid_entries'}, default=str),
                        search_blob=f"{source_file} {app_id} jumplist empty",
                        extra_fields=json.dumps({'app_id': app_id, 'status': 'no_valid_entries'}),
                        parser_version=self.parser_version,
                    )
                
        except Exception as e:
            error_msg = str(e).lower()
            # Invalid OLE signature = empty/corrupt file, handle gracefully
            if 'ole' in error_msg or 'signature' in error_msg or 'invalid' in error_msg or 'endofchain' in error_msg or 'dif' in error_msg:
                self.warnings.append(f"Corrupt or empty JumpList {source_file}: {e}")
                logger.debug(f"JumpList skipped (corrupt OLE): {e}")
                # Yield minimal event for corrupt files
                yield ParsedEvent(
                    case_id=self.case_id,
                    artifact_type=self.artifact_type,
                    timestamp=self.fallback_timestamp(
                        file_path=file_path,
                        reason='jumplist corrupt ole fallback event',
                    ),
                    source_file=source_file,
                    source_path=file_path,
                    source_host=hostname,
                    case_file_id=self.case_file_id,
                    raw_json=json.dumps({'jumplist_file': source_file, 'app_id': app_id, 'status': 'corrupt_ole', 'error': str(e)}, default=str),
                    search_blob=f"{source_file} {app_id} jumplist corrupt",
                    extra_fields=json.dumps({'app_id': app_id, 'status': 'corrupt_ole'}),
                    parser_version=self.parser_version,
                )
            else:
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
                 case_tz: str = 'UTC', max_entries: int = None, **kwargs):
        """Initialize MFT parser
        
        Args:
            case_id: ClickHouse case_id
            source_host: Hostname
            case_file_id: Optional FK to case_files
            case_tz: Case timezone (not used - MFT timestamps are UTC/FILETIME)
            max_entries: Maximum MFT entries to process (None = no limit, process all)
        """
        super().__init__(case_id, source_host, case_file_id, case_tz=case_tz)
        self.max_entries = max_entries  # None = no limit for complete DFIR analysis
        
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
                    if self.max_entries and count >= self.max_entries:
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
                        raw_timestamp = si_modified or si_created or si_accessed
                        parsed_timestamp = raw_timestamp if isinstance(raw_timestamp, datetime) else (
                            self.parse_timestamp(str(raw_timestamp)) if raw_timestamp is not None else None
                        )
                        timestamp = self.first_timestamp(
                            parsed_timestamp,
                            file_path=file_path,
                            reason='mft record missing standard information timestamps',
                        )
                        
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
                            record_id=record_number,
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
    """Parser for Windows SRUM (System Resource Usage Monitor) database
    
    Parses ESE database containing resource usage data:
    - Application Resource Usage (CPU, memory, network bytes)
    - Network Connectivity (interface connect/disconnect)
    - Network Data Usage (per-app network bytes)
    - Energy Usage
    - Push Notifications
    """
    
    VERSION = '1.1.0'
    ARTIFACT_TYPE = 'srum'
    
    # Known SRUM table GUIDs and descriptions
    SRUM_TABLES = {
        '{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}': 'Application Resource Usage',
        '{D10CA2FE-6FCF-4F6D-848E-B2E99266FA86}': 'Application Resource Usage (Push)',
        '{973F5D5C-1D90-4944-BE8E-24B94231A174}': 'Network Connectivity',
        '{DD6636C4-8929-4683-974E-22C046A43763}': 'Network Data Usage',
        '{FEE4E14F-02A9-4550-B5CE-5FA2DA202E37}': 'Energy Usage',
        '{DA73FB89-2BEA-4DDC-86B8-6E048C6DA477}': 'Push Notifications',
        '{5C8CF1C7-7257-4F13-B223-970EF5939312}': 'vfuprov',
        '{7ACBBAA3-D029-4BE4-9A7A-0885927F1D8F}': 'App Timeline',
        '{B6D82AF1-F780-4E17-8077-6CB9AD8A6FC4}': 'SDL Storage Provider',
    }
    
    def __init__(self, case_id: int, source_host: str = '', case_file_id: Optional[int] = None,
                 case_tz: str = 'UTC', **kwargs):
        super().__init__(case_id, source_host, case_file_id, case_tz=case_tz)
        self._id_map = {}  # Cache for SruDbIdMapTable lookups
        
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
    
    def _load_id_map(self, db) -> Dict[int, str]:
        """Load SruDbIdMapTable to resolve AppId and UserId references"""
        id_map = {}
        try:
            for table in db.tables():
                if table.name == 'SruDbIdMapTable':
                    for record in table.records():
                        try:
                            id_index = None
                            id_blob = None
                            for col in table.columns:
                                try:
                                    val = record.get(col.name)
                                    if col.name == 'IdIndex':
                                        id_index = val
                                    elif col.name == 'IdBlob':
                                        id_blob = val
                                except:
                                    pass
                            
                            if id_index is not None and id_blob is not None:
                                # IdBlob can be a SID or application path
                                if isinstance(id_blob, bytes):
                                    try:
                                        # Try UTF-16LE decode for paths
                                        decoded = id_blob.decode('utf-16-le').rstrip('\x00')
                                        id_map[id_index] = decoded
                                    except:
                                        # Fall back to hex
                                        id_map[id_index] = id_blob.hex()
                                else:
                                    id_map[id_index] = str(id_blob)
                        except Exception as e:
                            pass
                    break
        except Exception as e:
            self.warnings.append(f"Could not load SruDbIdMapTable: {e}")
        
        return id_map
    
    def _resolve_id(self, value: Any) -> str:
        """Resolve AppId/UserId to actual name from IdMap"""
        if value is None:
            return ''
        
        try:
            id_int = int(value)
            if id_int in self._id_map:
                return self._id_map[id_int]
        except (ValueError, TypeError):
            pass
        
        return str(value)
    
    def _parse_srum_timestamp(self, value: Any) -> Optional[datetime]:
        """Parse SRUM timestamp (OLE Automation Date stored as int64)
        
        SRUM stores timestamps as OLE Automation dates - doubles representing
        days since December 30, 1899. The int64 value is the binary representation
        of this double.
        """
        import struct
        from datetime import timedelta
        
        if value is None:
            return None
        
        try:
            # Convert int64 to its binary representation, then interpret as double
            int_val = int(value)
            if int_val <= 0:
                return None
            
            # Pack as little-endian int64, unpack as little-endian double
            bytes_repr = struct.pack('<q', int_val)
            double_val = struct.unpack('<d', bytes_repr)[0]
            
            # Sanity check: OLE dates should be roughly in range 30000-50000 for 1980-2035
            if double_val <= 0 or double_val > 100000:
                return None
            
            # OLE Automation Date epoch: December 30, 1899
            ole_epoch = datetime(1899, 12, 30)
            result = ole_epoch + timedelta(days=double_val)
            
            # Sanity check result is in reasonable range (1990-2040)
            if result.year < 1990 or result.year > 2040:
                return None
            
            return result
        except (ValueError, TypeError, struct.error, OverflowError):
            pass
        
        # Fall back to regular timestamp parsing for string values
        if isinstance(value, str):
            return self.parse_timestamp(value)
        
        return None
    
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
            
            # Load ID mapping table for resolving AppId/UserId
            self._id_map = self._load_id_map(db)
            logger.info(f"Loaded {len(self._id_map)} entries from SruDbIdMapTable")
            
            # Process SRUM data tables (iterate over Table objects)
            for table in db.tables():
                table_name = table.name
                
                # Skip system tables and ID mapping table
                if not table_name.startswith('{'):
                    continue
                
                # Get table description
                table_desc = self.SRUM_TABLES.get(table_name, 'Unknown')
                
                try:
                    # table.columns is a list, not a method
                    columns = table.columns
                    column_names = [c.name for c in columns]
                    
                    for record in table.records():
                        try:
                            record_dict = {}
                            for col in columns:
                                try:
                                    # Use record.get() to get column value
                                    value = record.get(col.name)
                                    if value is not None:
                                        # Handle bytes
                                        if isinstance(value, bytes):
                                            try:
                                                value = value.decode('utf-16-le').rstrip('\x00')
                                            except:
                                                try:
                                                    value = value.decode('utf-8', errors='replace')
                                                except:
                                                    value = value.hex()
                                        record_dict[col.name] = str(value)
                                except Exception as e:
                                    pass
                            
                            # Get timestamp - SRUM stores as OLE Automation Date
                            timestamp = None
                            for ts_field in ['TimeStamp', 'ConnectStartTime', 'StartTime', 'EndTime']:
                                if ts_field in record_dict:
                                    ts = self._parse_srum_timestamp(record_dict[ts_field])
                                    if ts:
                                        timestamp = ts
                                        break
                            
                            # Default to now if no valid timestamp found
                            if not timestamp:
                                timestamp = self.fallback_timestamp(
                                    file_path=file_path,
                                    reason='srum record missing timestamp fields',
                                )
                            
                            # Resolve AppId and UserId using ID map
                            app_id_raw = record_dict.get('AppId', '')
                            user_id_raw = record_dict.get('UserId', '')
                            
                            app_name = self._resolve_id(app_id_raw)
                            user_name = self._resolve_id(user_id_raw)
                            
                            # Build enriched record with resolved names
                            enriched_record = record_dict.copy()
                            if app_name and app_name != app_id_raw:
                                enriched_record['AppName'] = app_name
                            if user_name and user_name != user_id_raw:
                                enriched_record['UserName'] = user_name
                            
                            raw_data = {
                                'table': table_name,
                                'table_description': table_desc,
                                'record': enriched_record,
                            }
                            
                            # Build search blob with key values
                            search_parts = [table_desc, app_name, user_name]
                            search_parts.extend(str(v) for v in record_dict.values() if v)
                            
                            # Extract process name from app path
                            process_name = ''
                            if app_name:
                                # Get filename from path
                                process_name = os.path.basename(app_name.replace('\\', '/'))
                            
                            yield ParsedEvent(
                                case_id=self.case_id,
                                artifact_type=self.artifact_type,
                                timestamp=timestamp,
                                source_file=source_file,
                                source_path=file_path,
                                source_host=hostname,
                                case_file_id=self.case_file_id,
                                process_name=self.safe_str(process_name),
                                username=self.safe_str(user_name),
                                raw_json=json.dumps(raw_data, default=str),
                                search_blob=' '.join(str(p) for p in search_parts if p),
                                extra_fields=json.dumps({
                                    'table': table_name,
                                    'table_description': table_desc,
                                    'app_id': app_id_raw,
                                    'app_name': app_name,
                                    'user_id': user_id_raw,
                                    'user_name': user_name,
                                }, default=str),
                                parser_version=self.parser_version,
                            )
                            
                        except Exception as e:
                            self.warnings.append(f"Error processing record in {table_name}: {e}")
                            
                except Exception as e:
                    self.warnings.append(f"Error processing table {table_name}: {e}")
                    
        except Exception as e:
            self.errors.append(f"Failed to parse {file_path}: {e}")
            logger.exception(f"SRUM parse error: {e}")
