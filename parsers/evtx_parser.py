"""Hayabusa EVTX Parser for CaseScope

Uses Hayabusa (https://github.com/Yamato-Security/hayabusa) for parsing
Windows Event Log files with built-in Sigma detection.

Hayabusa provides:
- Fast Rust-based EVTX parsing
- 4000+ Sigma detection rules
- MITRE ATT&CK mapping
- Field normalization (Details object)
- Multiple output profiles
"""
import os
import json
import subprocess
import tempfile
import logging
from datetime import datetime
from typing import Generator, Dict, List, Any, Optional
from pathlib import Path

from parsers.base import BaseParser, ParsedEvent, ParseResult

logger = logging.getLogger(__name__)


class HayabusaParser(BaseParser):
    """Parser for Windows Event Log files using Hayabusa
    
    Uses Hayabusa's json-timeline command with all-field-info profile
    to get both normalized Details and raw AllFieldInfo.
    """
    
    VERSION = '1.0.0'
    ARTIFACT_TYPE = 'evtx'
    
    # Hayabusa binary and rules location
    HAYABUSA_BIN = '/opt/casescope/bin/hayabusa'
    HAYABUSA_RULES = '/opt/casescope/rules/hayabusa-rules'
    
    # Output profile - all-field-info gives us Details + AllFieldInfo
    DEFAULT_PROFILE = 'all-field-info'
    
    # Minimum detection level to include
    MIN_LEVEL = 'informational'  # informational, low, medium, high, critical
    
    # Level mapping for normalization
    LEVEL_MAP = {
        'informational': 'info',
        'info': 'info',
        'low': 'low',
        'medium': 'med',
        'med': 'med',
        'high': 'high',
        'critical': 'crit',
        'crit': 'crit',
    }
    
    def __init__(self, case_id: int, source_host: str = '', case_file_id: Optional[int] = None,
                 hayabusa_bin: str = None, rules_dir: str = None, profile: str = None,
                 min_level: str = None):
        """Initialize Hayabusa parser
        
        Args:
            case_id: ClickHouse case_id
            source_host: Hostname the EVTX came from
            case_file_id: Optional FK to case_files
            hayabusa_bin: Path to Hayabusa binary (default: /opt/casescope/bin/hayabusa)
            rules_dir: Path to Hayabusa rules directory
            profile: Output profile (default: all-field-info)
            min_level: Minimum detection level to include
        """
        super().__init__(case_id, source_host, case_file_id)
        
        self.hayabusa_bin = hayabusa_bin or self.HAYABUSA_BIN
        self.rules_dir = rules_dir or self.HAYABUSA_RULES
        self.profile = profile or self.DEFAULT_PROFILE
        self.min_level = min_level or self.MIN_LEVEL
        
        # Verify Hayabusa exists
        if not os.path.isfile(self.hayabusa_bin):
            raise FileNotFoundError(f"Hayabusa binary not found: {self.hayabusa_bin}")
    
    @property
    def artifact_type(self) -> str:
        return self.ARTIFACT_TYPE
    
    def can_parse(self, file_path: str) -> bool:
        """Check if file is an EVTX file"""
        if not os.path.isfile(file_path):
            return False
        
        # Check extension
        if file_path.lower().endswith('.evtx'):
            return True
        
        # Check magic bytes (EVTX signature: "ElfFile\x00")
        try:
            with open(file_path, 'rb') as f:
                magic = f.read(8)
                return magic == b'ElfFile\x00'
        except Exception:
            return False
    
    def parse(self, file_path: str) -> Generator[ParsedEvent, None, None]:
        """Parse EVTX file using Hayabusa and yield events
        
        Args:
            file_path: Path to the EVTX file
            
        Yields:
            ParsedEvent objects for each event
        """
        if not self.can_parse(file_path):
            self.errors.append(f"Cannot parse file: {file_path}")
            return
        
        # Create temp file for output
        with tempfile.NamedTemporaryFile(mode='w', suffix='.jsonl', delete=False) as tmp:
            output_path = tmp.name
        
        try:
            # Run Hayabusa
            cmd = [
                self.hayabusa_bin, 'json-timeline',
                '-f', file_path,
                '-o', output_path,
                '-L',                    # JSONL format
                '-w',                    # Skip wizard
                '-q',                    # Quiet mode
                '--no-color',
                '-p', self.profile,
                '--min-level', self.min_level,
                '-U',                    # UTC timestamps
            ]
            
            # Add rules directory if it exists
            if os.path.isdir(self.rules_dir):
                cmd.extend(['-r', self.rules_dir])
            
            logger.info(f"Running Hayabusa: {' '.join(cmd)}")
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=3600  # 1 hour timeout for large files
            )
            
            if result.returncode != 0:
                error_msg = result.stderr or result.stdout or 'Unknown error'
                self.errors.append(f"Hayabusa failed: {error_msg}")
                logger.error(f"Hayabusa error for {file_path}: {error_msg}")
                return
            
            # Parse output file
            if not os.path.exists(output_path):
                self.errors.append("Hayabusa produced no output")
                return
            
            # Extract source filename and try to get hostname
            source_file = os.path.basename(file_path)
            
            with open(output_path, 'r', encoding='utf-8', errors='replace') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue
                    
                    try:
                        event_data = json.loads(line)
                        parsed_event = self._transform_event(event_data, file_path, source_file)
                        if parsed_event:
                            yield parsed_event
                    except json.JSONDecodeError as e:
                        self.warnings.append(f"JSON parse error on line {line_num}: {e}")
                    except Exception as e:
                        self.warnings.append(f"Error processing event on line {line_num}: {e}")
        
        finally:
            # Cleanup temp file
            try:
                os.unlink(output_path)
            except Exception:
                pass
    
    def _transform_event(self, event: Dict[str, Any], file_path: str, source_file: str) -> Optional[ParsedEvent]:
        """Transform Hayabusa JSON event to ParsedEvent
        
        Args:
            event: Hayabusa JSON event
            file_path: Original file path
            source_file: Source filename
            
        Returns:
            ParsedEvent or None if transformation fails
        """
        try:
            # Get timestamp
            timestamp = self.parse_timestamp(event.get('Timestamp'))
            if not timestamp:
                timestamp = datetime.now()
            
            # Get computer/hostname
            computer = event.get('Computer', '')
            hostname = self.extract_hostname(file_path, {'Computer': computer})
            
            # Get channel (abbreviated in Hayabusa)
            channel = event.get('Channel', '')
            
            # Get event ID
            event_id = str(event.get('EventID', ''))
            
            # Get detection info
            rule_title = event.get('RuleTitle')
            rule_level = self.LEVEL_MAP.get(
                str(event.get('Level', '')).lower(), 
                event.get('Level')
            )
            rule_file = event.get('RuleFile')
            
            # Get MITRE info (arrays)
            mitre_tactics = event.get('MitreTactics') or []
            mitre_tags = event.get('MitreTags') or []
            
            # Ensure they're lists
            if isinstance(mitre_tactics, str):
                mitre_tactics = [mitre_tactics] if mitre_tactics else []
            if isinstance(mitre_tags, str):
                mitre_tags = [mitre_tags] if mitre_tags else []
            
            # Get Details (normalized fields from Hayabusa)
            details = event.get('Details', {})
            if isinstance(details, str):
                try:
                    details = json.loads(details)
                except:
                    details = {}
            
            # Get AllFieldInfo (raw EventData)
            all_fields = event.get('AllFieldInfo', {})
            if isinstance(all_fields, str):
                try:
                    all_fields = json.loads(all_fields)
                except:
                    all_fields = {}
            
            # Extract normalized fields from Details and AllFieldInfo
            username = (
                details.get('TgtUser') or 
                details.get('User') or
                all_fields.get('TargetUserName') or 
                all_fields.get('SubjectUserName') or
                all_fields.get('User')
            )
            
            domain = (
                details.get('TgtDom') or
                details.get('Domain') or
                all_fields.get('TargetDomainName') or
                all_fields.get('SubjectDomainName')
            )
            
            sid = (
                all_fields.get('TargetUserSid') or
                all_fields.get('SubjectUserSid') or
                all_fields.get('UserSid')
            )
            
            logon_type = self.safe_int(
                details.get('Type') or 
                all_fields.get('LogonType')
            )
            
            # Process fields
            process_name = (
                details.get('Proc') or
                all_fields.get('NewProcessName') or
                all_fields.get('ProcessName') or
                all_fields.get('Image')
            )
            if process_name:
                process_name = os.path.basename(process_name.replace('\\', '/'))
            
            process_path = (
                all_fields.get('NewProcessName') or
                all_fields.get('ProcessName') or
                all_fields.get('Image')
            )
            
            process_id = self.safe_int(
                details.get('PID') or
                all_fields.get('NewProcessId') or
                all_fields.get('ProcessId')
            )
            
            parent_process = all_fields.get('ParentProcessName') or all_fields.get('ParentImage')
            if parent_process:
                parent_process = os.path.basename(parent_process.replace('\\', '/'))
            
            parent_pid = self.safe_int(
                all_fields.get('ParentProcessId') or
                all_fields.get('ParentPID')
            )
            
            command_line = (
                details.get('Cmd') or
                all_fields.get('CommandLine') or
                all_fields.get('ProcessCommandLine')
            )
            
            # Target path
            target_path = (
                details.get('Path') or
                all_fields.get('TargetFilename') or
                all_fields.get('ObjectName') or
                all_fields.get('TargetObject')
            )
            
            # Network fields
            src_ip = self.validate_ip(
                details.get('SrcIP') or
                all_fields.get('IpAddress') or
                all_fields.get('SourceAddress') or
                all_fields.get('ClientAddress')
            )
            
            dst_ip = self.validate_ip(
                details.get('DstIP') or
                all_fields.get('DestAddress') or
                all_fields.get('DestinationAddress')
            )
            
            src_port = self.safe_int(
                details.get('SrcPort') or
                all_fields.get('IpPort') or
                all_fields.get('SourcePort')
            )
            
            dst_port = self.safe_int(
                details.get('DstPort') or
                all_fields.get('DestPort') or
                all_fields.get('DestinationPort')
            )
            
            # Hash fields
            hashes = all_fields.get('Hashes', '')
            file_hash_md5 = None
            file_hash_sha1 = None
            file_hash_sha256 = None
            
            if hashes:
                # Format: MD5=xxx,SHA1=xxx,SHA256=xxx
                for part in str(hashes).split(','):
                    if '=' in part:
                        algo, value = part.split('=', 1)
                        algo = algo.strip().upper()
                        value = value.strip()
                        if algo == 'MD5':
                            file_hash_md5 = value
                        elif algo == 'SHA1':
                            file_hash_sha1 = value
                        elif algo == 'SHA256':
                            file_hash_sha256 = value
            
            # Build search blob from all available data
            search_data = {**details, **all_fields}
            search_data['Computer'] = computer
            search_data['Channel'] = channel
            search_data['EventID'] = event_id
            if rule_title:
                search_data['RuleTitle'] = rule_title
            
            search_blob = self.build_search_blob(search_data)
            
            # Build raw JSON (combine Details and AllFieldInfo)
            raw_data = {
                'Details': details,
                'AllFieldInfo': all_fields,
                'RecordID': event.get('RecordID'),
                'Provider': event.get('Provider'),
            }
            
            return ParsedEvent(
                case_id=self.case_id,
                artifact_type=self.artifact_type,
                timestamp=timestamp,
                source_file=source_file,
                source_path=file_path,
                source_host=hostname,
                case_file_id=self.case_file_id,
                event_id=event_id,
                channel=channel,
                provider=event.get('Provider'),
                record_id=self.safe_int(event.get('RecordID')),
                level=rule_level,
                username=self.safe_str(username),
                domain=self.safe_str(domain),
                sid=self.safe_str(sid),
                logon_type=logon_type,
                process_name=self.safe_str(process_name),
                process_path=self.safe_str(process_path),
                process_id=process_id,
                parent_process=self.safe_str(parent_process),
                parent_pid=parent_pid,
                command_line=self.safe_str(command_line),
                target_path=self.safe_str(target_path),
                file_hash_md5=file_hash_md5,
                file_hash_sha1=file_hash_sha1,
                file_hash_sha256=file_hash_sha256,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                rule_title=rule_title,
                rule_level=rule_level,
                rule_file=rule_file,
                mitre_tactics=mitre_tactics,
                mitre_tags=mitre_tags,
                raw_json=json.dumps(raw_data, default=str),
                search_blob=search_blob,
                parser_version=self.parser_version,
            )
            
        except Exception as e:
            self.warnings.append(f"Error transforming event: {e}")
            logger.exception(f"Event transformation error: {e}")
            return None
    
    @classmethod
    def update_rules(cls, rules_dir: str = None) -> bool:
        """Update Hayabusa rules
        
        Args:
            rules_dir: Rules directory (default: cls.HAYABUSA_RULES)
            
        Returns:
            True if update succeeded
        """
        rules_dir = rules_dir or cls.HAYABUSA_RULES
        hayabusa_bin = cls.HAYABUSA_BIN
        
        try:
            cmd = [hayabusa_bin, 'update-rules', '-r', rules_dir]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            return result.returncode == 0
        except Exception as e:
            logger.error(f"Failed to update Hayabusa rules: {e}")
            return False


class EvtxFallbackParser(BaseParser):
    """Fallback EVTX parser using pyevtx-rs
    
    Used when Hayabusa is not available or fails.
    Provides raw parsing without detection rules.
    """
    
    VERSION = '1.0.0'
    ARTIFACT_TYPE = 'evtx'
    
    def __init__(self, case_id: int, source_host: str = '', case_file_id: Optional[int] = None):
        super().__init__(case_id, source_host, case_file_id)
        
        # Try to import evtx
        try:
            from evtx import PyEvtxParser
            self._parser_class = PyEvtxParser
        except ImportError:
            raise ImportError("pyevtx-rs not installed. Install with: pip install evtx")
    
    @property
    def artifact_type(self) -> str:
        return self.ARTIFACT_TYPE
    
    def can_parse(self, file_path: str) -> bool:
        """Check if file is an EVTX file"""
        if not os.path.isfile(file_path):
            return False
        
        if file_path.lower().endswith('.evtx'):
            return True
        
        try:
            with open(file_path, 'rb') as f:
                magic = f.read(8)
                return magic == b'ElfFile\x00'
        except Exception:
            return False
    
    def parse(self, file_path: str) -> Generator[ParsedEvent, None, None]:
        """Parse EVTX using pyevtx-rs"""
        if not self.can_parse(file_path):
            self.errors.append(f"Cannot parse file: {file_path}")
            return
        
        source_file = os.path.basename(file_path)
        
        try:
            parser = self._parser_class(file_path)
            
            for record in parser.records_json():
                try:
                    data = json.loads(record['data'])
                    event = data.get('Event', {})
                    system = event.get('System', {})
                    event_data = event.get('EventData', {})
                    
                    # Get timestamp
                    time_created = system.get('TimeCreated', {})
                    timestamp = self.parse_timestamp(
                        time_created.get('SystemTime') or record.get('timestamp')
                    )
                    if not timestamp:
                        timestamp = datetime.now()
                    
                    # Get hostname
                    computer = system.get('Computer', '')
                    hostname = self.extract_hostname(file_path, {'Computer': computer})
                    
                    # Extract EventID (can be nested)
                    event_id_raw = system.get('EventID', '')
                    if isinstance(event_id_raw, dict):
                        event_id = str(event_id_raw.get('#text', event_id_raw.get('Value', '')))
                    else:
                        event_id = str(event_id_raw)
                    
                    # Build search blob
                    search_blob = self.build_search_blob(event_data)
                    
                    yield ParsedEvent(
                        case_id=self.case_id,
                        artifact_type=self.artifact_type,
                        timestamp=timestamp,
                        source_file=source_file,
                        source_path=file_path,
                        source_host=hostname,
                        case_file_id=self.case_file_id,
                        event_id=event_id,
                        channel=system.get('Channel'),
                        provider=system.get('Provider', {}).get('Name'),
                        record_id=self.safe_int(system.get('EventRecordID')),
                        level=system.get('Level'),
                        username=self.safe_str(
                            event_data.get('TargetUserName') or 
                            event_data.get('SubjectUserName')
                        ),
                        domain=self.safe_str(
                            event_data.get('TargetDomainName') or
                            event_data.get('SubjectDomainName')
                        ),
                        sid=self.safe_str(event_data.get('TargetUserSid')),
                        logon_type=self.safe_int(event_data.get('LogonType')),
                        process_name=self.safe_str(
                            event_data.get('NewProcessName') or
                            event_data.get('ProcessName')
                        ),
                        process_id=self.safe_int(event_data.get('NewProcessId')),
                        command_line=self.safe_str(event_data.get('CommandLine')),
                        src_ip=self.validate_ip(event_data.get('IpAddress')),
                        raw_json=record['data'],
                        search_blob=search_blob,
                        parser_version=self.parser_version,
                    )
                    
                except Exception as e:
                    self.warnings.append(f"Error processing record: {e}")
                    
        except Exception as e:
            self.errors.append(f"Failed to parse {file_path}: {e}")
            logger.exception(f"EVTX parse error: {e}")
