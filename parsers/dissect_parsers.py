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
import hashlib
import codecs
import struct
from datetime import datetime, timedelta
from typing import Generator, Dict, List, Any, Optional
from pathlib import Path

from parsers.base import BaseParser, ParsedEvent

logger = logging.getLogger(__name__)


def _windows_filetime_to_datetime(value: int) -> Optional[datetime]:
    """Convert a Windows FILETIME integer to a naive UTC datetime."""
    if not value:
        return None
    try:
        return datetime(1601, 1, 1) + timedelta(microseconds=value / 10)
    except Exception:
        return None


class PrefetchParser(BaseParser):
    """Parser for Windows Prefetch files using dissect.target
    
    Extracts execution timestamps, loaded files, and run counts from
    Windows Prefetch files (.pf).
    """
    
    VERSION = '2.1.0'
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

    def _filename_executable(self, source_file: str) -> str:
        exe_name = source_file.rsplit('-', 1)[0] if '-' in source_file else source_file
        return exe_name.replace('.pf', '').replace('.PF', '')

    def _hash_file(self, file_path: str) -> Dict[str, str]:
        hashes = {
            'md5': hashlib.md5(),
            'sha1': hashlib.sha1(),
            'sha256': hashlib.sha256(),
        }
        with open(file_path, 'rb') as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b''):
                for digest in hashes.values():
                    digest.update(chunk)
        return {name: digest.hexdigest() for name, digest in hashes.items()}

    def _triage_event(
        self,
        file_path: str,
        source_file: str,
        hostname: str,
        reason: str,
        exc: Exception,
    ) -> ParsedEvent:
        hashes = self._hash_file(file_path)
        exe_name = self._filename_executable(source_file)
        raw_data = {
            'executable': exe_name,
            'file_size': os.path.getsize(file_path),
            'hashes': hashes,
            'triage_reason': reason,
            'parse_error': self.format_exception(exc),
            'parser_note': 'Prefetch metadata emitted because full Dissect parsing failed',
        }
        return ParsedEvent(
            case_id=self.case_id,
            artifact_type=self.artifact_type,
            timestamp=self.fallback_timestamp(file_path=file_path, reason='prefetch triage uses file mtime'),
            source_file=source_file,
            source_path=file_path,
            source_host=hostname,
            case_file_id=self.case_file_id,
            process_name=exe_name,
            target_path=file_path,
            file_hash_md5=hashes['md5'],
            file_hash_sha1=hashes['sha1'],
            file_hash_sha256=hashes['sha256'],
            file_size=raw_data['file_size'],
            raw_json=json.dumps(raw_data, default=str),
            search_blob=f"{source_file} {exe_name} {file_path} {hashes['sha256']} {reason}",
            extra_fields=json.dumps({'triage_reason': reason}),
            parser_version=self.parser_version,
        )
    
    def parse(self, file_path: str) -> Generator[ParsedEvent, None, None]:
        """Parse Prefetch file using dissect.target"""
        if not self.can_parse(file_path):
            self.errors.append(f"Cannot parse file: {file_path}")
            return
        
        source_file = os.path.basename(file_path)
        hostname = self.extract_hostname(file_path)
        
        try:
            with open(file_path, 'rb') as fh:
                pf = self._prefetch_class(fh)
                
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
                    exe_name = self._filename_executable(source_file)
                
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
                
        except NotImplementedError as e:
            message = self.format_exception(
                e,
                context=f'Unsupported Prefetch variant for {file_path}',
            )
            self.warnings.append(message)
            logger.warning(message)
            yield self._triage_event(file_path, source_file, hostname, 'unsupported_prefetch_variant', e)
        except Exception as e:
            message = self.format_exception(e, context=f'Failed to parse {file_path}')
            self.warnings.append(message)
            logger.warning(message)
            yield self._triage_event(file_path, source_file, hostname, 'prefetch_parse_failed', e)


class RegistryParser(BaseParser):
    """Parser for Windows Registry hives using dissect.regf
    
    Parses SAM, SECURITY, SOFTWARE, SYSTEM, NTUSER.DAT, USRCLASS.DAT, and Amcache.
    Extracts registry keys and values as individual events for granular searching.
    """
    
    VERSION = '2.1.0'
    ARTIFACT_TYPE = 'registry'
    DEFAULT_EXTRACT_ALL = True
    KEY_EVENT_VALUE_NAME = '(Key)'
    SUMMARY_VALUE_LIMIT = 512
    SEARCH_VALUE_LIMIT = 1024
    
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
    
    # High-value keys shared across multiple hives
    COMMON_INTERESTING_KEYS = [
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

    # Hive-specific keys to improve coverage without dumping the full hive.
    HIVE_INTERESTING_KEYS = {
        'SYSTEM': [
            r'ControlSet001\Control\Session Manager\AppCompatCache',
            r'ControlSet002\Control\Session Manager\AppCompatCache',
            r'ControlSet001\Control\ComputerName\ComputerName',
            r'ControlSet002\Control\ComputerName\ComputerName',
        ],
        'SOFTWARE': [
            r'Microsoft\Windows\CurrentVersion\Uninstall',
            r'Microsoft\Windows\CurrentVersion\Installer\UserData',
            r'Microsoft\Windows NT\CurrentVersion\ProfileList',
            r'Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks',
            r'Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree',
            r'Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run',
            r'Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder',
        ],
        'SAM': [
            r'SAM\Domains\Account\Users',
            r'SAM\Domains\Builtin\Aliases',
        ],
        'SECURITY': [
            r'Policy\Accounts',
            r'Policy\PolAdtEv',
            r'Policy\Secrets',
            r'Cache',
        ],
        'NTUSER.DAT': [
            r'Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU',
            r'Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths',
            r'Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery',
            r'Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2',
            r'Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU',
            r'Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU',
            r'Software\Microsoft\Terminal Server Client\Servers',
            r'Software\Microsoft\Terminal Server Client\Default',
        ],
        'USRCLASS.DAT': [
            r'Local Settings\Software\Microsoft\Windows\Shell\BagMRU',
            r'Local Settings\Software\Microsoft\Windows\Shell\Bags',
            r'Local Settings\Software\Microsoft\Windows\Shell\MuiCache',
        ],
        'AMCACHE': [
            r'Root\File',
            r'Root\Programs',
            r'Root\InventoryApplication',
            r'Root\InventoryApplicationFile',
            r'Root\InventoryDriverBinary',
            r'Root\InventoryDeviceContainer',
        ],
    }
    
    def __init__(self, case_id: int, source_host: str = '', case_file_id: Optional[int] = None,
                 case_tz: str = 'UTC', extract_all: bool = DEFAULT_EXTRACT_ALL, **kwargs):
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

    def _interesting_keys_for_hive(self, hive_type: str) -> List[str]:
        """Return shared plus hive-specific key patterns."""
        keys = list(self.COMMON_INTERESTING_KEYS)
        keys.extend(self.HIVE_INTERESTING_KEYS.get(hive_type, []))
        # Preserve order but drop accidental duplicates.
        return list(dict.fromkeys(keys))

    @staticmethod
    def _stringify_registry_type(value_type: Any) -> str:
        if value_type is None:
            return ''
        return str(value_type.name) if hasattr(value_type, 'name') else str(value_type)

    @staticmethod
    def _coerce_clickhouse_text(value: Any) -> str:
        if value is None:
            return ''
        return str(value)

    def _bounded_summary(self, value: Any, *, limit: int) -> str:
        text = self._coerce_clickhouse_text(value).replace('\x00', '')
        text = ' '.join(text.split())
        if len(text) <= limit:
            return text
        return f"{text[:limit]}...[truncated {len(text) - limit} chars]"

    def _key_path(self, key: Any, hive_type: str) -> str:
        try:
            key_path = str(key.path) if hasattr(key, 'path') else str(key)
        except Exception:
            key_path = ''
        return key_path or hive_type or 'ROOT'

    def _key_timestamp(self, key: Any, *, file_path: str) -> datetime:
        raw_timestamp = key.timestamp if hasattr(key, 'timestamp') else None
        parsed_timestamp = raw_timestamp if isinstance(raw_timestamp, datetime) else (
            self.parse_timestamp(str(raw_timestamp)) if raw_timestamp is not None else None
        )
        return self.first_timestamp(
            parsed_timestamp,
            file_path=file_path,
            reason='registry key missing last-write timestamp',
        )

    def _serialize_registry_payload(self, raw_value: Any) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            'storage_kind': type(raw_value).__name__ if raw_value is not None else 'NoneType',
            'decoded_as': 'none',
        }

        if raw_value is None:
            payload['text'] = ''
            payload['data_length'] = 0
            payload['search_text'] = ''
            return payload

        if isinstance(raw_value, bytes):
            hex_value = raw_value.hex()
            decoded_text = None
            decoded_as = 'hex'

            for encoding in ('utf-16-le', 'utf-8'):
                try:
                    candidate = raw_value.decode(encoding)
                    candidate = candidate.rstrip('\x00')
                    if candidate:
                        decoded_text = candidate
                        decoded_as = encoding
                        break
                except Exception:
                    continue

            payload.update({
                'storage_kind': 'bytes',
                'decoded_as': decoded_as,
                'byte_length': len(raw_value),
                'hex': hex_value,
                'text': decoded_text or '',
                'data_length': len(decoded_text or hex_value),
                'search_text': decoded_text or hex_value,
            })
            return payload

        if isinstance(raw_value, (list, tuple)):
            items = [self._coerce_clickhouse_text(item) for item in raw_value]
            joined = ', '.join(items)
            payload.update({
                'storage_kind': 'sequence',
                'decoded_as': 'sequence',
                'items': items,
                'item_count': len(items),
                'text': joined,
                'data_length': len(joined),
                'search_text': joined,
            })
            return payload

        if isinstance(raw_value, dict):
            normalized = {
                self._coerce_clickhouse_text(key): self._coerce_clickhouse_text(value)
                for key, value in raw_value.items()
            }
            rendered = json.dumps(normalized, sort_keys=True)
            payload.update({
                'storage_kind': 'mapping',
                'decoded_as': 'json',
                'mapping': normalized,
                'text': rendered,
                'data_length': len(rendered),
                'search_text': rendered,
            })
            return payload

        rendered = self._coerce_clickhouse_text(raw_value)
        payload.update({
            'storage_kind': type(raw_value).__name__,
            'decoded_as': 'string',
            'text': rendered,
            'data_length': len(rendered),
            'search_text': rendered,
        })
        return payload

    def _build_key_event(
        self,
        *,
        timestamp: datetime,
        hive_type: str,
        source_file: str,
        file_path: str,
        hostname: str,
        key_path: str,
        value_count: int,
    ) -> ParsedEvent:
        raw_data = {
            'registry_record_kind': 'key',
            'hive_type': hive_type,
            'key_path': key_path,
            'value_count': value_count,
        }
        extra = {
            'registry_record_kind': 'key',
            'hive_type': hive_type,
        }
        return ParsedEvent(
            case_id=self.case_id,
            artifact_type=self.artifact_type,
            timestamp=timestamp,
            source_file=source_file,
            source_path=file_path,
            source_host=hostname,
            case_file_id=self.case_file_id,
            reg_key=key_path,
            reg_value=self.KEY_EVENT_VALUE_NAME,
            reg_data='',
            raw_json=json.dumps(raw_data, default=str),
            search_blob=self._bounded_summary(
                f"{key_path} {self.KEY_EVENT_VALUE_NAME}",
                limit=self.SEARCH_VALUE_LIMIT,
            ),
            extra_fields=json.dumps(extra, default=str),
            parser_version=self.parser_version,
        )

    def _build_value_event(
        self,
        *,
        timestamp: datetime,
        hive_type: str,
        source_file: str,
        file_path: str,
        hostname: str,
        key_path: str,
        value_name: str,
        value_type: str,
        serialized_payload: Dict[str, Any],
    ) -> ParsedEvent:
        summary_text = self._bounded_summary(
            serialized_payload.get('search_text', ''),
            limit=self.SUMMARY_VALUE_LIMIT,
        )
        raw_data = {
            'registry_record_kind': 'value',
            'hive_type': hive_type,
            'key_path': key_path,
            'value_name': value_name,
            'value_type': value_type,
            'value_data': serialized_payload,
        }
        extra = {
            'registry_record_kind': 'value',
            'hive_type': hive_type,
            'value_type': value_type,
            'storage_kind': serialized_payload.get('storage_kind', ''),
            'decoded_as': serialized_payload.get('decoded_as', ''),
            'data_length': serialized_payload.get('data_length', 0),
            'byte_length': serialized_payload.get('byte_length', 0),
            'summary_truncated': summary_text != serialized_payload.get('search_text', ''),
        }
        return ParsedEvent(
            case_id=self.case_id,
            artifact_type=self.artifact_type,
            timestamp=timestamp,
            source_file=source_file,
            source_path=file_path,
            source_host=hostname,
            case_file_id=self.case_file_id,
            reg_key=key_path,
            reg_value=value_name,
            reg_data=summary_text,
            raw_json=json.dumps(raw_data, default=str),
            search_blob=self._bounded_summary(
                f"{key_path} {value_name} {value_type} {summary_text}",
                limit=self.SEARCH_VALUE_LIMIT,
            ),
            extra_fields=json.dumps(extra, default=str),
            parser_version=self.parser_version,
        )

    def _build_decoded_registry_event(
        self,
        *,
        artifact_type: str,
        timestamp: datetime,
        source_file: str,
        file_path: str,
        hostname: str,
        payload: Dict[str, Any],
        target_path: str = '',
        event_id: str = '',
    ) -> ParsedEvent:
        return ParsedEvent(
            case_id=self.case_id,
            artifact_type=artifact_type,
            timestamp=timestamp,
            source_file=source_file,
            source_path=file_path,
            source_host=hostname,
            case_file_id=self.case_file_id,
            event_id=event_id,
            target_path=target_path or payload.get('path', '') or payload.get('name', ''),
            process_path=payload.get('path', '') or payload.get('executable_path', ''),
            process_name=os.path.basename(payload.get('path', '') or payload.get('executable_path', '') or ''),
            reg_key=payload.get('registry_key', ''),
            reg_value=payload.get('value_name', ''),
            reg_data=payload.get('summary', ''),
            raw_json=json.dumps(payload, default=str),
            search_blob=self.build_search_blob(payload),
            extra_fields=json.dumps({'registry_decode': artifact_type}, default=str),
            parser_version=self.parser_version,
        )

    def _iter_ez_registry_rows(
        self,
        *,
        binary_path: str,
        args: List[str],
        file_path: str,
    ) -> List[Dict[str, str]]:
        try:
            from utils.ez_tools import run_tool_for_csv
            return run_tool_for_csv(binary_path, args)
        except FileNotFoundError:
            return []
        except Exception as exc:
            self.warnings.append(f"Registry decode helper failed for {file_path}: {exc}")
            return []

    def _timestamp_from_row(self, row: Dict[str, Any], file_path: str) -> datetime:
        for key in (
            'LastModifiedTimeUTC', 'LastWriteTime', 'LastWriteTimestamp',
            'LastModified', 'ModifiedTime', 'Timestamp', 'LastExecuted',
            'LastRun', 'CreatedOn', 'Created', 'SourceCreated',
        ):
            if row.get(key):
                parsed = self.parse_timestamp(row.get(key))
                if parsed:
                    return parsed
        return self.fallback_timestamp(file_path=file_path, reason='decoded registry event missing timestamp')

    def _iter_shimcache_events(
        self,
        *,
        parse_path: str,
        source_file: str,
        file_path: str,
        hostname: str,
    ) -> Generator[ParsedEvent, None, None]:
        rows = self._iter_ez_registry_rows(
            binary_path='/opt/casescope/bin/appcompatcacheparser',
            args=['-f', parse_path],
            file_path=file_path,
        )
        for row in rows:
            path = row.get('Path') or row.get('Name') or row.get('FileName') or ''
            payload = {
                'parser': 'AppCompatCacheParser',
                'path': path,
                'executed': row.get('Executed') or row.get('SourceFile') or '',
                **row,
            }
            yield self._build_decoded_registry_event(
                artifact_type='registry_shimcache',
                timestamp=self._timestamp_from_row(row, file_path),
                source_file=source_file,
                file_path=file_path,
                hostname=hostname,
                payload=payload,
                target_path=path,
                event_id='shimcache_entry',
            )

    def _iter_shellbag_events(
        self,
        *,
        parse_path: str,
        source_file: str,
        file_path: str,
        hostname: str,
    ) -> Generator[ParsedEvent, None, None]:
        rows = self._iter_ez_registry_rows(
            binary_path='/opt/casescope/bin/sbecmd',
            args=['-f', parse_path],
            file_path=file_path,
        )
        for row in rows:
            path = row.get('AbsolutePath') or row.get('Path') or row.get('Value') or ''
            payload = {
                'parser': 'SBECmd',
                'path': path,
                'registry_key': row.get('RegistryKey') or row.get('KeyPath') or '',
                **row,
            }
            yield self._build_decoded_registry_event(
                artifact_type='registry_shellbags',
                timestamp=self._timestamp_from_row(row, file_path),
                source_file=source_file,
                file_path=file_path,
                hostname=hostname,
                payload=payload,
                target_path=path,
                event_id='shellbag_entry',
            )

    def _decode_userassist_value(self, value: Any) -> Dict[str, Any]:
        raw_value = getattr(value, 'value', b'')
        name = self._coerce_clickhouse_text(getattr(value, 'name', '') or '')
        decoded_name = codecs.decode(name, 'rot_13') if name else ''
        payload = {
            'value_name': name,
            'decoded_name': decoded_name,
            'summary': decoded_name or name,
        }
        if isinstance(raw_value, bytes):
            payload['byte_length'] = len(raw_value)
            if len(raw_value) >= 8:
                try:
                    payload['session_id'] = struct.unpack_from('<I', raw_value, 0)[0]
                    payload['run_count'] = struct.unpack_from('<I', raw_value, 4)[0]
                except struct.error:
                    pass
            if len(raw_value) >= 16:
                try:
                    payload['focus_time_ms'] = struct.unpack_from('<I', raw_value, 8)[0]
                    payload['focus_count'] = struct.unpack_from('<I', raw_value, 12)[0]
                except struct.error:
                    pass
            if len(raw_value) >= 68:
                try:
                    filetime = struct.unpack_from('<Q', raw_value, 60)[0]
                    payload['last_run_filetime'] = filetime
                    if filetime:
                        payload['last_run_utc'] = str(_windows_filetime_to_datetime(filetime))
                except struct.error:
                    pass
        return payload

    def _iter_userassist_events(
        self,
        *,
        hive: Any,
        source_file: str,
        file_path: str,
        hostname: str,
    ) -> Generator[ParsedEvent, None, None]:
        try:
            root = hive.open(r'Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist')
        except Exception:
            return

        stack = [root]
        while stack:
            key = stack.pop()
            key_path = self._key_path(key, 'NTUSER.DAT')
            try:
                values = list(key.values())
            except Exception:
                values = []
            for value in values:
                payload = self._decode_userassist_value(value)
                payload['registry_key'] = key_path
                last_run = self.parse_timestamp(payload.get('last_run_utc', '')) if payload.get('last_run_utc') else None
                yield self._build_decoded_registry_event(
                    artifact_type='registry_userassist',
                    timestamp=self.first_timestamp(last_run, self._key_timestamp(key, file_path=file_path), file_path=file_path),
                    source_file=source_file,
                    file_path=file_path,
                    hostname=hostname,
                    payload=payload,
                    target_path=payload.get('decoded_name', ''),
                    event_id='userassist_entry',
                )
            try:
                stack.extend(list(key.subkeys()))
            except Exception:
                continue

    def _iter_capability_access_events(
        self,
        *,
        hive: Any,
        source_file: str,
        file_path: str,
        hostname: str,
    ) -> Generator[ParsedEvent, None, None]:
        try:
            root = hive.open(r'Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore')
        except Exception:
            return

        stack = [root]
        while stack:
            key = stack.pop()
            key_path = self._key_path(key, 'SOFTWARE')
            values = {}
            try:
                for value in key.values():
                    values[self._coerce_clickhouse_text(getattr(value, 'name', ''))] = getattr(value, 'value', None)
            except Exception:
                values = {}

            if values:
                timestamps = []
                for name in ('LastUsedTimeStart', 'LastUsedTimeStop'):
                    value = values.get(name)
                    if isinstance(value, int):
                        timestamps.append(_windows_filetime_to_datetime(value))
                    elif value:
                        timestamps.append(self.parse_timestamp(value))
                payload = {
                    'registry_key': key_path,
                    'capability': key_path.split('\\')[-2] if '\\' in key_path else '',
                    'application': key_path.split('\\')[-1],
                    'values': {k: self._coerce_clickhouse_text(v) for k, v in values.items()},
                    'summary': key_path,
                }
                yield self._build_decoded_registry_event(
                    artifact_type='registry_capability_access',
                    timestamp=self.first_timestamp(*timestamps, self._key_timestamp(key, file_path=file_path), file_path=file_path),
                    source_file=source_file,
                    file_path=file_path,
                    hostname=hostname,
                    payload=payload,
                    target_path=payload.get('application', ''),
                    event_id='capability_access',
                )
            try:
                stack.extend(list(key.subkeys()))
            except Exception:
                continue
    
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
            from utils.hive_replay import replayed_hive_path
        except Exception:
            replayed_hive_path = None

        try:
            replay_context = replayed_hive_path(file_path) if replayed_hive_path else None
            if replay_context is None:
                parse_path = file_path
                replay_cm = None
            else:
                replay_cm = replay_context
                parse_path = replay_cm.__enter__()

            with open(parse_path, 'rb') as fh:
                hive = self._registry_class(fh)

                def iter_subkeys(key: Any) -> List[Any]:
                    try:
                        return list(key.subkeys())
                    except Exception as exc:
                        self.warnings.append(f"Error reading subkeys for {self._key_path(key, hive_type)}: {exc}")
                        return []

                def emit_key(key: Any) -> Generator[ParsedEvent, None, None]:
                    key_path = self._key_path(key, hive_type)
                    timestamp = self._key_timestamp(key, file_path=file_path)
                    values = []

                    try:
                        values = list(key.values())
                    except Exception as exc:
                        self.warnings.append(f"Error reading values for {key_path}: {exc}")

                    yield self._build_key_event(
                        timestamp=timestamp,
                        hive_type=hive_type,
                        source_file=source_file,
                        file_path=file_path,
                        hostname=hostname,
                        key_path=key_path,
                        value_count=len(values),
                    )

                    for value in values:
                        value_name = self._coerce_clickhouse_text(getattr(value, 'name', '') or '(Default)')
                        value_type = self._stringify_registry_type(getattr(value, 'type', ''))
                        serialized_payload = self._serialize_registry_payload(getattr(value, 'value', None))
                        yield self._build_value_event(
                            timestamp=timestamp,
                            hive_type=hive_type,
                            source_file=source_file,
                            file_path=file_path,
                            hostname=hostname,
                            key_path=key_path,
                            value_name=value_name,
                            value_type=value_type,
                            serialized_payload=serialized_payload,
                        )

                visited_paths = set()

                if self.extract_all:
                    stack = [hive.root()]
                    while stack:
                        key = stack.pop()
                        key_path = self._key_path(key, hive_type)
                        if key_path in visited_paths:
                            continue
                        visited_paths.add(key_path)

                        try:
                            yield from emit_key(key)
                        except Exception as exc:
                            self.warnings.append(f"Error processing key {key_path}: {exc}")

                        subkeys = iter_subkeys(key)
                        for subkey in reversed(subkeys):
                            stack.append(subkey)
                else:
                    for key_pattern in self._interesting_keys_for_hive(hive_type):
                        try:
                            key = hive.open(key_pattern)
                            if not key:
                                continue
                        except Exception:
                            continue

                        stack = [(key, 0)]
                        while stack:
                            current, depth = stack.pop()
                            key_path = self._key_path(current, hive_type)
                            if key_path in visited_paths:
                                continue
                            visited_paths.add(key_path)

                            try:
                                yield from emit_key(current)
                            except Exception as exc:
                                self.warnings.append(f"Error processing key {key_path}: {exc}")

                            subkeys = iter_subkeys(current)
                            if depth >= 3:
                                continue
                            for subkey in reversed(subkeys):
                                stack.append((subkey, depth + 1))

                if hive_type == 'SYSTEM':
                    yield from self._iter_shimcache_events(
                        parse_path=parse_path,
                        source_file=source_file,
                        file_path=file_path,
                        hostname=hostname,
                    )
                if hive_type in ('NTUSER.DAT', 'USRCLASS.DAT'):
                    if hive_type == 'NTUSER.DAT':
                        yield from self._iter_userassist_events(
                            hive=hive,
                            source_file=source_file,
                            file_path=file_path,
                            hostname=hostname,
                        )
                    yield from self._iter_shellbag_events(
                        parse_path=parse_path,
                        source_file=source_file,
                        file_path=file_path,
                        hostname=hostname,
                    )
                if hive_type == 'SOFTWARE':
                    yield from self._iter_capability_access_events(
                        hive=hive,
                        source_file=source_file,
                        file_path=file_path,
                        hostname=hostname,
                    )
        except Exception as e:
            self.errors.append(f"Failed to parse {file_path}: {e}")
            logger.exception(f"Registry parse error: {e}")
        finally:
            try:
                if 'replay_cm' in locals() and replay_cm is not None:
                    replay_cm.__exit__(None, None, None)
            except Exception:
                pass


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
                        if not any((target_path, relative_path, arguments, machine_id)) and not lnk_file_size:
                            continue
                        
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


class USNParser(BaseParser):
    """Parser for NTFS USN Journal ($UsnJrnl:$J) files using dissect.ntfs."""

    VERSION = '1.0.0'
    ARTIFACT_TYPE = 'usn'
    FILE_CANDIDATES = {'$j', '$usnjrnl', '$usnjrnl:$j', 'usnjrnl', 'usnjrnl.bin'}

    def __init__(self, case_id: int, source_host: str = '', case_file_id: Optional[int] = None,
                 case_tz: str = 'UTC', **kwargs):
        super().__init__(case_id, source_host, case_file_id, case_tz=case_tz)

        try:
            from dissect.ntfs.usnjrnl import UsnJrnl
            from dissect.ntfs.c_ntfs import c_ntfs
            self._usnjrnl_class = UsnJrnl
            self._ntfs_constants = c_ntfs
        except ImportError:
            raise ImportError("dissect.ntfs not installed. Install with: pip install dissect.ntfs")

    @property
    def artifact_type(self) -> str:
        return self.ARTIFACT_TYPE

    def _matches_usn_name(self, file_path: str) -> bool:
        normalized_path = file_path.replace('\\', '/').lower()
        filename = os.path.basename(normalized_path)
        if filename in self.FILE_CANDIDATES:
            return True
        return '$extend/$usnjrnl' in normalized_path or '$usnjrnl:$j' in normalized_path

    def _probe_records(self, file_path: str):
        with open(file_path, 'rb') as fh:
            journal = self._usnjrnl_class(fh)
            return next(journal.records(), None)

    def can_parse(self, file_path: str) -> bool:
        """Check if file looks like an NTFS USN journal stream."""
        if not os.path.isfile(file_path):
            return False

        if not self._matches_usn_name(file_path):
            return False

        try:
            return self._probe_records(file_path) is not None
        except Exception:
            return False

    def _flag_names(self, flag_enum: Any, value: Any, *, zero_name: str = '') -> List[str]:
        try:
            numeric_value = int(value)
        except (TypeError, ValueError):
            numeric_value = 0

        names = []
        for name in dir(flag_enum):
            if not name.isupper():
                continue
            try:
                candidate_value = int(getattr(flag_enum, name))
            except (TypeError, ValueError):
                continue
            if candidate_value == 0:
                continue
            if numeric_value & candidate_value:
                names.append(name)

        if not names and numeric_value == 0 and zero_name:
            names.append(zero_name)
        return names

    def parse(self, file_path: str) -> Generator[ParsedEvent, None, None]:
        """Parse a USN journal stream into one event per USN record."""
        if not self.can_parse(file_path):
            self.errors.append(f"Cannot parse file: {file_path}")
            return

        source_file = os.path.basename(file_path)
        hostname = self.extract_hostname(file_path)
        source_tz = self.get_source_tz()

        try:
            with open(file_path, 'rb') as fh:
                journal = self._usnjrnl_class(fh)
                for record in journal.records():
                    try:
                        timestamp = self.first_timestamp(
                            getattr(record, 'timestamp', None),
                            file_path=file_path,
                            reason='usn record missing timestamp',
                        )
                        target_path = getattr(record, 'full_path', '') or getattr(record, 'filename', '') or ''
                        filename = getattr(record, 'filename', '') or ''
                        process_name = os.path.basename(target_path.replace('\\', '/')) if target_path else filename
                        reasons = self._flag_names(
                            self._ntfs_constants.USN_REASON,
                            getattr(record, 'Reason', 0),
                        )
                        source_flags = self._flag_names(
                            self._ntfs_constants.USN_SOURCE,
                            getattr(record, 'SourceInfo', 0),
                            zero_name='NORMAL',
                        )
                        file_attributes = self._flag_names(
                            self._ntfs_constants.FILE_ATTRIBUTE,
                            getattr(record, 'FileAttributes', 0),
                        )

                        raw_data = {
                            'usn': int(getattr(record, 'Usn', 0)),
                            'filename': filename,
                            'full_path': target_path,
                            'timestamp': str(timestamp),
                            'reason_flags': reasons,
                            'source_flags': source_flags,
                            'file_attributes': file_attributes,
                            'security_id': self.safe_int(getattr(record, 'SecurityId', None)),
                            'major_version': self.safe_int(getattr(record.header, 'MajorVersion', None)),
                            'minor_version': self.safe_int(getattr(record.header, 'MinorVersion', None)),
                            'file_reference_number': str(getattr(record, 'FileReferenceNumber', '')),
                            'parent_file_reference_number': str(getattr(record, 'ParentFileReferenceNumber', '')),
                        }

                        search_parts = [target_path, filename]
                        search_parts.extend(reasons)
                        search_parts.extend(source_flags)
                        search_parts.extend(file_attributes)

                        yield ParsedEvent(
                            case_id=self.case_id,
                            artifact_type=self.artifact_type,
                            timestamp=timestamp,
                            timestamp_source_tz=source_tz,
                            source_file=source_file,
                            source_path=file_path,
                            source_host=hostname,
                            case_file_id=self.case_file_id,
                            event_id='|'.join(reasons),
                            provider='NTFS USN Journal',
                            record_id=self.safe_int(getattr(record, 'Usn', None)),
                            process_name=self.safe_str(process_name),
                            target_path=self.safe_str(target_path),
                            raw_json=json.dumps(raw_data, default=str),
                            search_blob=' '.join(str(part) for part in search_parts if part),
                            extra_fields=json.dumps({
                                'filename': filename,
                                'reason_flags': reasons,
                                'source_flags': source_flags,
                                'file_attributes': file_attributes,
                                'security_id': self.safe_int(getattr(record, 'SecurityId', None)),
                                'major_version': self.safe_int(getattr(record.header, 'MajorVersion', None)),
                                'minor_version': self.safe_int(getattr(record.header, 'MinorVersion', None)),
                                'file_reference_number': str(getattr(record, 'FileReferenceNumber', '')),
                                'parent_file_reference_number': str(getattr(record, 'ParentFileReferenceNumber', '')),
                            }, default=str),
                            parser_version=self.parser_version,
                        )
                    except Exception as e:
                        self.warnings.append(f"Error processing USN record: {e}")
        except Exception as e:
            self.errors.append(f"Failed to parse {file_path}: {e}")
            logger.exception(f"USN parse error: {e}")


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
