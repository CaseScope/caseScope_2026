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
    """Parser for Windows Prefetch files using dissect.prefetch"""
    
    VERSION = '1.0.0'
    ARTIFACT_TYPE = 'prefetch'
    
    def __init__(self, case_id: int, source_host: str = '', case_file_id: Optional[int] = None):
        super().__init__(case_id, source_host, case_file_id)
        
        try:
            from dissect.target.plugins.os.windows.prefetch import PrefetchFile
            self._prefetch_class = PrefetchFile
        except ImportError:
            try:
                # Alternative import path
                from dissect.prefetch import Prefetch
                self._prefetch_class = Prefetch
            except ImportError:
                raise ImportError("dissect.prefetch not installed. Install with: pip install dissect.target")
    
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
        """Parse Prefetch file"""
        if not self.can_parse(file_path):
            self.errors.append(f"Cannot parse file: {file_path}")
            return
        
        source_file = os.path.basename(file_path)
        hostname = self.extract_hostname(file_path)
        
        try:
            from dissect.prefetch import Prefetch
            
            pf = Prefetch(open(file_path, 'rb'))
            
            # Extract executable name from prefetch filename
            # Format: PROGRAM.EXE-HASH.pf
            exe_name = source_file.rsplit('-', 1)[0] if '-' in source_file else source_file
            exe_name = exe_name.replace('.pf', '').replace('.PF', '')
            
            # Get all run times
            run_times = list(pf.timestamps) if hasattr(pf, 'timestamps') else []
            run_count = pf.run_count if hasattr(pf, 'run_count') else len(run_times)
            
            # Get loaded files/volumes
            loaded_files = []
            if hasattr(pf, 'filenames'):
                loaded_files = list(pf.filenames)
            elif hasattr(pf, 'files'):
                loaded_files = [f.path for f in pf.files]
            
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
                    'loaded_files': loaded_files[:50],  # Limit to first 50
                    'loaded_file_count': len(loaded_files),
                }
                
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
                    search_blob=f"{exe_name} {' '.join(loaded_files[:20])}",
                    extra_fields=json.dumps({
                        'run_count': run_count,
                        'loaded_files': loaded_files[:100],
                    }, default=str),
                    parser_version=self.parser_version,
                )
            
            # If no run times, create a single event with current time
            if not run_times:
                raw_data = {
                    'executable': exe_name,
                    'run_count': run_count,
                    'loaded_files': loaded_files[:50],
                    'loaded_file_count': len(loaded_files),
                }
                
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
                    search_blob=f"{exe_name} {' '.join(loaded_files[:20])}",
                    parser_version=self.parser_version,
                )
                
        except Exception as e:
            self.errors.append(f"Failed to parse {file_path}: {e}")
            logger.exception(f"Prefetch parse error: {e}")


class RegistryParser(BaseParser):
    """Parser for Windows Registry hives using dissect.regf"""
    
    VERSION = '1.0.0'
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
            
            hive = RegistryHive(open(file_path, 'rb'))
            
            def process_key(key, depth=0, max_depth=10):
                """Recursively process registry keys"""
                if depth > max_depth:
                    return
                
                try:
                    # Get key timestamp
                    timestamp = key.timestamp if hasattr(key, 'timestamp') else datetime.now()
                    if not isinstance(timestamp, datetime):
                        timestamp = self.parse_timestamp(str(timestamp)) or datetime.now()
                    
                    key_path = str(key.path) if hasattr(key, 'path') else str(key)
                    
                    # Process values
                    values = {}
                    try:
                        for value in key.values():
                            value_name = value.name or '(Default)'
                            try:
                                value_data = value.value
                                if isinstance(value_data, bytes):
                                    # Try to decode, fallback to hex
                                    try:
                                        value_data = value_data.decode('utf-16-le').rstrip('\x00')
                                    except:
                                        value_data = value_data.hex()
                                values[value_name] = str(value_data)[:1000]  # Limit value size
                            except:
                                values[value_name] = '<error reading value>'
                    except:
                        pass
                    
                    if values:  # Only yield if there are values
                        raw_data = {
                            'hive_type': hive_type,
                            'key_path': key_path,
                            'values': values,
                            'value_count': len(values),
                        }
                        
                        yield ParsedEvent(
                            case_id=self.case_id,
                            artifact_type=self.artifact_type,
                            timestamp=timestamp,
                            source_file=source_file,
                            source_path=file_path,
                            source_host=hostname,
                            case_file_id=self.case_file_id,
                            reg_key=key_path,
                            raw_json=json.dumps(raw_data, default=str),
                            search_blob=f"{key_path} {' '.join(str(v) for v in values.values())}",
                            extra_fields=json.dumps({'hive_type': hive_type}, default=str),
                            parser_version=self.parser_version,
                        )
                    
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
    """Parser for Windows LNK/Shortcut files using dissect.shellitem"""
    
    VERSION = '1.0.0'
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
    
    def parse(self, file_path: str) -> Generator[ParsedEvent, None, None]:
        """Parse LNK file"""
        if not self.can_parse(file_path):
            self.errors.append(f"Cannot parse file: {file_path}")
            return
        
        source_file = os.path.basename(file_path)
        hostname = self.extract_hostname(file_path)
        
        try:
            from dissect.shellitem.lnk import Lnk
            
            lnk = Lnk(open(file_path, 'rb'))
            
            # Extract target path
            target_path = None
            if hasattr(lnk, 'target_path'):
                target_path = str(lnk.target_path)
            elif hasattr(lnk, 'local_base_path'):
                target_path = str(lnk.local_base_path)
            
            # Extract timestamps
            creation_time = None
            modification_time = None
            access_time = None
            
            if hasattr(lnk, 'creation_time'):
                creation_time = lnk.creation_time
            if hasattr(lnk, 'modification_time'):
                modification_time = lnk.modification_time
            if hasattr(lnk, 'access_time'):
                access_time = lnk.access_time
            
            # Use modification time as primary timestamp
            timestamp = modification_time or creation_time or access_time
            if timestamp and not isinstance(timestamp, datetime):
                timestamp = self.parse_timestamp(str(timestamp))
            if not timestamp:
                timestamp = datetime.now()
            
            # Extract other metadata
            working_dir = str(lnk.working_directory) if hasattr(lnk, 'working_directory') and lnk.working_directory else None
            arguments = str(lnk.command_line_arguments) if hasattr(lnk, 'command_line_arguments') and lnk.command_line_arguments else None
            icon_location = str(lnk.icon_location) if hasattr(lnk, 'icon_location') and lnk.icon_location else None
            
            # Machine ID (if available)
            machine_id = None
            if hasattr(lnk, 'tracker_data') and lnk.tracker_data:
                machine_id = str(lnk.tracker_data.machine_id) if hasattr(lnk.tracker_data, 'machine_id') else None
            
            raw_data = {
                'lnk_file': source_file,
                'target_path': target_path,
                'working_directory': working_dir,
                'arguments': arguments,
                'icon_location': icon_location,
                'creation_time': str(creation_time) if creation_time else None,
                'modification_time': str(modification_time) if modification_time else None,
                'access_time': str(access_time) if access_time else None,
                'machine_id': machine_id,
            }
            
            # Build search blob
            search_parts = [source_file]
            if target_path:
                search_parts.append(target_path)
            if arguments:
                search_parts.append(arguments)
            if working_dir:
                search_parts.append(working_dir)
            
            yield ParsedEvent(
                case_id=self.case_id,
                artifact_type=self.artifact_type,
                timestamp=timestamp,
                source_file=source_file,
                source_path=file_path,
                source_host=hostname,
                case_file_id=self.case_file_id,
                target_path=target_path,
                command_line=arguments,
                raw_json=json.dumps(raw_data, default=str),
                search_blob=' '.join(search_parts),
                parser_version=self.parser_version,
            )
            
        except Exception as e:
            self.errors.append(f"Failed to parse {file_path}: {e}")
            logger.exception(f"LNK parse error: {e}")


class JumpListParser(BaseParser):
    """Parser for Windows Jump List files"""
    
    VERSION = '1.0.0'
    ARTIFACT_TYPE = 'jumplist'
    
    def __init__(self, case_id: int, source_host: str = '', case_file_id: Optional[int] = None):
        super().__init__(case_id, source_host, case_file_id)
        
        try:
            from dissect.shellitem.lnk import Lnk
            self._lnk_class = Lnk
        except ImportError:
            raise ImportError("dissect.shellitem not installed")
    
    @property
    def artifact_type(self) -> str:
        return self.ARTIFACT_TYPE
    
    def can_parse(self, file_path: str) -> bool:
        """Check if file is a Jump List"""
        if not os.path.isfile(file_path):
            return False
        
        filename = os.path.basename(file_path).lower()
        return filename.endswith(('.automaticdestinations-ms', '.customdestinations-ms'))
    
    def parse(self, file_path: str) -> Generator[ParsedEvent, None, None]:
        """Parse Jump List file"""
        if not self.can_parse(file_path):
            self.errors.append(f"Cannot parse file: {file_path}")
            return
        
        source_file = os.path.basename(file_path)
        hostname = self.extract_hostname(file_path)
        
        try:
            # Jump lists are OLE compound files containing LNK entries
            import olefile
            
            if olefile.isOleFile(file_path):
                ole = olefile.OleFileIO(file_path)
                
                for entry in ole.listdir():
                    entry_path = '/'.join(entry)
                    
                    try:
                        stream = ole.openstream(entry)
                        data = stream.read()
                        
                        # Try to parse as LNK
                        if data[:4] == b'\x4c\x00\x00\x00':
                            from dissect.shellitem.lnk import Lnk
                            import io
                            
                            lnk = Lnk(io.BytesIO(data))
                            
                            target_path = None
                            if hasattr(lnk, 'target_path'):
                                target_path = str(lnk.target_path)
                            
                            timestamp = datetime.now()
                            if hasattr(lnk, 'modification_time') and lnk.modification_time:
                                timestamp = lnk.modification_time
                            
                            raw_data = {
                                'jumplist_file': source_file,
                                'entry_path': entry_path,
                                'target_path': target_path,
                            }
                            
                            yield ParsedEvent(
                                case_id=self.case_id,
                                artifact_type=self.artifact_type,
                                timestamp=timestamp if isinstance(timestamp, datetime) else datetime.now(),
                                source_file=source_file,
                                source_path=file_path,
                                source_host=hostname,
                                case_file_id=self.case_file_id,
                                target_path=target_path,
                                raw_json=json.dumps(raw_data, default=str),
                                search_blob=f"{source_file} {entry_path} {target_path or ''}",
                                parser_version=self.parser_version,
                            )
                    except Exception as e:
                        self.warnings.append(f"Error parsing entry {entry_path}: {e}")
                
                ole.close()
            else:
                self.errors.append(f"Not a valid OLE file: {file_path}")
                
        except ImportError:
            self.errors.append("olefile not installed. Install with: pip install olefile")
        except Exception as e:
            self.errors.append(f"Failed to parse {file_path}: {e}")
            logger.exception(f"JumpList parse error: {e}")


class MFTParser(BaseParser):
    """Parser for NTFS MFT ($MFT) files using dissect.ntfs"""
    
    VERSION = '1.0.0'
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
            from dissect.ntfs import MFT
            self._mft_class = MFT
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
        """Parse MFT file"""
        if not self.can_parse(file_path):
            self.errors.append(f"Cannot parse file: {file_path}")
            return
        
        source_file = os.path.basename(file_path)
        hostname = self.extract_hostname(file_path)
        
        try:
            from dissect.ntfs import MFT
            
            mft = MFT(open(file_path, 'rb'))
            count = 0
            
            for entry in mft.entries():
                if count >= self.max_entries:
                    self.warnings.append(f"Reached max entries limit ({self.max_entries})")
                    break
                
                try:
                    if not entry.is_file() and not entry.is_dir():
                        continue
                    
                    # Get filename
                    filename = None
                    for fn in entry.filenames():
                        if fn.namespace != 2:  # Skip DOS names
                            filename = str(fn.filename)
                            break
                    
                    if not filename:
                        continue
                    
                    # Get path if available
                    full_path = None
                    try:
                        full_path = str(entry.path())
                    except:
                        full_path = filename
                    
                    # Get timestamps
                    si_timestamps = {}
                    fn_timestamps = {}
                    
                    if hasattr(entry, 'standard_information') and entry.standard_information():
                        si = entry.standard_information()
                        si_timestamps = {
                            'si_created': si.creation_time,
                            'si_modified': si.modification_time,
                            'si_accessed': si.access_time,
                            'si_changed': si.change_time,
                        }
                    
                    # Use modification time as primary
                    timestamp = si_timestamps.get('si_modified') or datetime.now()
                    if not isinstance(timestamp, datetime):
                        timestamp = self.parse_timestamp(str(timestamp)) or datetime.now()
                    
                    # Get size
                    file_size = None
                    if hasattr(entry, 'data_size'):
                        file_size = entry.data_size()
                    
                    raw_data = {
                        'filename': filename,
                        'full_path': full_path,
                        'entry_number': entry.entry_number if hasattr(entry, 'entry_number') else None,
                        'is_directory': entry.is_dir(),
                        'file_size': file_size,
                        'timestamps': {k: str(v) for k, v in si_timestamps.items() if v},
                    }
                    
                    yield ParsedEvent(
                        case_id=self.case_id,
                        artifact_type=self.artifact_type,
                        timestamp=timestamp,
                        source_file=source_file,
                        source_path=file_path,
                        source_host=hostname,
                        case_file_id=self.case_file_id,
                        target_path=full_path,
                        file_size=file_size,
                        raw_json=json.dumps(raw_data, default=str),
                        search_blob=f"{filename} {full_path or ''}",
                        parser_version=self.parser_version,
                    )
                    
                    count += 1
                    
                except Exception as e:
                    self.warnings.append(f"Error processing MFT entry: {e}")
                    
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
