"""EVTX Parser for CaseScope using Eric Zimmerman's EvtxECmd + Hayabusa

Uses EvtxECmd (EZ Tools) for complete EVTX parsing:
- Parses ALL events (not just detections)
- Uses Maps for field normalization per EventID
- Consistent JSON output schema
- Runs on Linux via .NET runtime

Hayabusa provides Sigma detection enrichment for matched events.

References:
- https://www.sans.org/blog/running-ez-tools-natively-on-linux-a-step-by-step-guide
- https://github.com/EricZimmerman/evtx
- https://ericzimmerman.github.io/
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


class EvtxECmdParser(BaseParser):
    """Parser for Windows Event Log files using EvtxECmd + Hayabusa
    
    EvtxECmd provides:
    - Complete event extraction (ALL events, not just matches)
    - Field normalization via Maps (per-EventID field mapping)
    - Consistent output schema
    - Linux support via .NET runtime
    
    Hayabusa enrichment adds Sigma detection context to matching events.
    """
    
    VERSION = '2.0.0'
    ARTIFACT_TYPE = 'evtx'
    
    # Tool paths - wrapper scripts handle .NET
    EVTXECMD_BIN = '/opt/casescope/bin/evtxecmd'
    EVTXECMD_MAPS = '/opt/casescope/bin/EvtxECmd/EvtxeCmd/Maps'
    HAYABUSA_BIN = '/opt/casescope/bin/hayabusa'
    HAYABUSA_RULES = '/opt/casescope/rules/hayabusa-rules'
    
    # Level mapping for Hayabusa detections
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
                 evtxecmd_bin: str = None, maps_dir: str = None,
                 hayabusa_bin: str = None, rules_dir: str = None,
                 enrich_detections: bool = True):
        """Initialize EvtxECmd + Hayabusa parser
        
        Args:
            case_id: ClickHouse case_id
            source_host: Hostname the EVTX came from
            case_file_id: Optional FK to case_files
            evtxecmd_bin: Path to EvtxECmd wrapper script
            maps_dir: Path to EvtxECmd Maps directory
            hayabusa_bin: Path to Hayabusa binary (for detection enrichment)
            rules_dir: Path to Hayabusa rules
            enrich_detections: Run Hayabusa for Sigma detection enrichment
        """
        super().__init__(case_id, source_host, case_file_id)
        
        self.evtxecmd_bin = evtxecmd_bin or self.EVTXECMD_BIN
        self.maps_dir = maps_dir or self.EVTXECMD_MAPS
        self.hayabusa_bin = hayabusa_bin or self.HAYABUSA_BIN
        self.rules_dir = rules_dir or self.HAYABUSA_RULES
        self.enrich_detections = enrich_detections
        
        # Verify EvtxECmd exists
        if not os.path.isfile(self.evtxecmd_bin):
            raise FileNotFoundError(
                f"EvtxECmd not found: {self.evtxecmd_bin}\n"
                "Install with: sudo /opt/casescope/bin/install_eztools.sh"
            )
        
        # Check Hayabusa availability
        self._hayabusa_available = (
            self.enrich_detections and 
            os.path.isfile(self.hayabusa_bin)
        )
        if self._hayabusa_available:
            logger.info("Hayabusa available for detection enrichment")
        else:
            logger.info("Hayabusa not available, detection enrichment disabled")
    
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
        """Parse EVTX file - ALL events with optional detection enrichment
        
        Args:
            file_path: Path to the EVTX file
            
        Yields:
            ParsedEvent objects for EVERY event in the file
        """
        if not self.can_parse(file_path):
            self.errors.append(f"Cannot parse file: {file_path}")
            return
        
        source_file = os.path.basename(file_path)
        
        # Step 1: Get Hayabusa detections for enrichment (keyed by RecordID)
        detections = {}
        if self._hayabusa_available:
            detections = self._get_hayabusa_detections(file_path)
            if detections:
                logger.info(f"Hayabusa found {len(detections)} detections for enrichment")
        
        # Step 2: Parse ALL events with EvtxECmd
        yield from self._parse_with_evtxecmd(file_path, source_file, detections)
    
    def _get_hayabusa_detections(self, file_path: str) -> Dict[str, Dict]:
        """Run Hayabusa and index detections by RecordID for enrichment
        
        Returns:
            Dict mapping "Channel:RecordID" to detection info
        """
        detections = {}
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.jsonl', delete=False) as tmp:
            output_path = tmp.name
        
        try:
            cmd = [
                self.hayabusa_bin, 'json-timeline',
                '-f', file_path,
                '-o', output_path,
                '-L',                    # JSONL format
                '-w',                    # Skip wizard
                '-q',                    # Quiet
                '--no-color',
                '-p', 'all-field-info',  # Get all fields for context
                '--min-level', 'informational',
                '-U',                    # UTC timestamps
            ]
            
            if os.path.isdir(self.rules_dir):
                cmd.extend(['-r', self.rules_dir])
            
            logger.info(f"Running Hayabusa for detection enrichment...")
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=3600
            )
            
            # Hayabusa may return non-zero even on success with no matches
            if os.path.exists(output_path) and os.path.getsize(output_path) > 0:
                with open(output_path, 'r', encoding='utf-8', errors='replace') as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            event = json.loads(line)
                            # Key by Channel + RecordID for correlation
                            channel = event.get('Channel', '')
                            record_id = event.get('RecordID')
                            if record_id:
                                key = f"{channel}:{record_id}"
                                
                                # Handle array fields
                                mitre_tactics = event.get('MitreTactics') or []
                                mitre_tags = event.get('MitreTags') or []
                                if isinstance(mitre_tactics, str):
                                    mitre_tactics = [mitre_tactics] if mitre_tactics else []
                                if isinstance(mitre_tags, str):
                                    mitre_tags = [mitre_tags] if mitre_tags else []
                                
                                detections[key] = {
                                    'rule_title': event.get('RuleTitle'),
                                    'rule_level': self.LEVEL_MAP.get(
                                        str(event.get('Level', '')).lower(),
                                        event.get('Level')
                                    ),
                                    'rule_file': event.get('RuleFile'),
                                    'mitre_tactics': mitre_tactics,
                                    'mitre_tags': mitre_tags,
                                }
                        except json.JSONDecodeError:
                            pass
            else:
                logger.debug("No Hayabusa detections for this file")
                            
        except subprocess.TimeoutExpired:
            self.warnings.append("Hayabusa timed out after 1 hour")
        except Exception as e:
            self.warnings.append(f"Hayabusa error: {e}")
            logger.warning(f"Hayabusa error: {e}")
        finally:
            try:
                os.unlink(output_path)
            except:
                pass
        
        return detections
    
    def _parse_with_evtxecmd(self, file_path: str, source_file: str,
                            detections: Dict) -> Generator[ParsedEvent, None, None]:
        """Parse using EvtxECmd with Maps for field normalization"""
        
        # Create temp output directory
        with tempfile.TemporaryDirectory() as temp_dir:
            output_file = 'evtx_output.json'
            output_path = os.path.join(temp_dir, output_file)
            
            # Build EvtxECmd command
            cmd = [
                self.evtxecmd_bin,
                '-f', file_path,
                '--json', temp_dir,
                '--jsonf', output_file,
            ]
            
            logger.info(f"Running EvtxECmd: {' '.join(cmd)}")
            
            try:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=3600,
                )
                
                if result.returncode != 0:
                    error_msg = result.stderr or result.stdout or 'Unknown error'
                    self.errors.append(f"EvtxECmd failed: {error_msg[:500]}")
                    logger.error(f"EvtxECmd error: {error_msg}")
                    return
                
                # Parse JSON output
                if not os.path.exists(output_path):
                    self.errors.append("EvtxECmd produced no output")
                    return
                
                # Handle UTF-8 BOM that EvtxECmd adds
                with open(output_path, 'r', encoding='utf-8-sig', errors='replace') as f:
                    for line_num, line in enumerate(f, 1):
                        line = line.strip()
                        if not line:
                            continue
                        
                        try:
                            event = json.loads(line)
                            parsed_event = self._transform_evtxecmd_event(
                                event, file_path, source_file, detections
                            )
                            if parsed_event:
                                yield parsed_event
                        except json.JSONDecodeError as e:
                            self.warnings.append(f"JSON error line {line_num}: {e}")
                        except Exception as e:
                            self.warnings.append(f"Error processing line {line_num}: {e}")
                            
            except subprocess.TimeoutExpired:
                self.errors.append("EvtxECmd timed out after 1 hour")
            except Exception as e:
                self.errors.append(f"EvtxECmd execution error: {e}")
                logger.exception(f"EvtxECmd error: {e}")
    
    def _transform_evtxecmd_event(self, event: Dict[str, Any], file_path: str,
                                  source_file: str, detections: Dict) -> Optional[ParsedEvent]:
        """Transform EvtxECmd JSON output to ParsedEvent
        
        EvtxECmd JSON schema (with Maps applied):
        - TimeCreated: timestamp
        - EventId: event ID
        - Channel: log channel
        - Computer: hostname
        - RecordNumber: record ID
        - Provider: provider name
        - Level: event level
        - PayloadData1-6: mapped fields from Maps
        - MapDescription: what the Maps extracted
        - UserName: normalized username
        - Payload: raw XML payload as JSON string
        """
        try:
            # Get timestamp
            timestamp = self.parse_timestamp(event.get('TimeCreated'))
            if not timestamp:
                timestamp = datetime.now()
            
            # Get basic fields
            computer = event.get('Computer', '')
            hostname = self.extract_hostname(file_path, {'Computer': computer})
            channel = event.get('Channel', '')
            event_id = str(event.get('EventId', ''))
            record_id = event.get('RecordNumber')
            
            # Check for Hayabusa detection enrichment
            detection_key = f"{channel}:{record_id}"
            detection = detections.get(detection_key, {})
            
            # Parse the Payload JSON to extract EventData fields
            event_data = {}
            payload_str = event.get('Payload', '')
            if payload_str:
                try:
                    payload = json.loads(payload_str)
                    # Extract EventData fields
                    ed = payload.get('EventData', {})
                    data_items = ed.get('Data', [])
                    if isinstance(data_items, list):
                        for item in data_items:
                            if isinstance(item, dict) and '@Name' in item:
                                event_data[item['@Name']] = item.get('#text', '')
                except:
                    pass
            
            # Extract normalized fields from EvtxECmd output + Payload
            username = (
                event.get('UserName') or
                event_data.get('TargetUserName') or
                event_data.get('SubjectUserName') or
                event_data.get('User')
            )
            # Clean up username (remove SID suffix if present)
            if username and ' (' in username:
                username = username.split(' (')[0]
            
            domain = (
                event_data.get('TargetDomainName') or
                event_data.get('SubjectDomainName') or
                event_data.get('Domain')
            )
            
            sid = (
                event_data.get('TargetUserSid') or
                event_data.get('SubjectUserSid') or
                event_data.get('TargetSid')
            )
            
            # Process info - from PayloadData or EventData
            process_name = (
                event_data.get('NewProcessName') or
                event_data.get('ProcessName') or
                event_data.get('CallerProcessName') or
                event.get('PayloadData3')  # Often CallerProcessName in Maps
            )
            if process_name:
                process_path = process_name
                process_name = os.path.basename(process_name.replace('\\', '/'))
            else:
                process_path = None
            
            command_line = (
                event_data.get('CommandLine') or
                event_data.get('ProcessCommandLine')
            )
            
            process_id = self.safe_int(
                event_data.get('NewProcessId') or
                event_data.get('ProcessId') or
                event_data.get('CallerProcessId') or
                event.get('ProcessId')
            )
            
            parent_process = event_data.get('ParentProcessName')
            if parent_process:
                parent_process = os.path.basename(parent_process.replace('\\', '/'))
            
            parent_pid = self.safe_int(event_data.get('ParentProcessId'))
            
            # Target path (files, registry, etc)
            target_path = (
                event_data.get('TargetFilename') or
                event_data.get('ObjectName') or
                event_data.get('TargetObject') or
                event.get('PayloadData1')
            )
            
            # Network fields
            src_ip = self.validate_ip(
                event_data.get('IpAddress') or
                event_data.get('SourceAddress') or
                event_data.get('ClientAddress')
            )
            dst_ip = self.validate_ip(
                event_data.get('DestAddress') or
                event_data.get('DestinationAddress')
            )
            src_port = self.safe_int(
                event_data.get('SourcePort') or
                event_data.get('IpPort')
            )
            dst_port = self.safe_int(
                event_data.get('DestinationPort') or
                event_data.get('DestPort')
            )
            
            # Logon type for logon events
            logon_type = self.safe_int(event_data.get('LogonType'))
            
            # Hash extraction
            hashes = event_data.get('Hashes', '')
            hash_md5, hash_sha1, hash_sha256 = None, None, None
            if hashes:
                for part in str(hashes).split(','):
                    if '=' in part:
                        algo, value = part.split('=', 1)
                        algo = algo.strip().upper()
                        value = value.strip()
                        if algo == 'MD5':
                            hash_md5 = value
                        elif algo == 'SHA1':
                            hash_sha1 = value
                        elif algo == 'SHA256':
                            hash_sha256 = value
            
            # Build search blob from key fields
            search_parts = [
                computer, channel, event_id,
                username or '', domain or '',
                process_name or '', command_line or '',
                target_path or '', src_ip or '', dst_ip or '',
                event.get('MapDescription', ''),
                event.get('PayloadData1', ''),
                event.get('PayloadData2', ''),
                event.get('PayloadData3', ''),
                event.get('PayloadData4', ''),
                event.get('Keywords', ''),
                detection.get('rule_title', ''),
            ]
            search_blob = ' '.join(str(p) for p in search_parts if p)
            
            # Add Payload content for full-text search (truncated)
            if payload_str and len(payload_str) < 3000:
                search_blob += f" {payload_str}"
            
            # Build raw JSON (include key fields, exclude large Payload)
            raw_data = {
                k: v for k, v in event.items() 
                if k not in ('Payload',) and v is not None and v != ''
            }
            # Add parsed EventData
            if event_data:
                raw_data['EventData'] = event_data
            
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
                record_id=self.safe_int(record_id),
                level=detection.get('rule_level') or event.get('Level'),
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
                file_hash_md5=hash_md5 or '',
                file_hash_sha1=hash_sha1 or '',
                file_hash_sha256=hash_sha256 or '',
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                # Detection enrichment from Hayabusa
                rule_title=detection.get('rule_title'),
                rule_level=detection.get('rule_level'),
                rule_file=detection.get('rule_file'),
                mitre_tactics=detection.get('mitre_tactics', []),
                mitre_tags=detection.get('mitre_tags', []),
                raw_json=json.dumps(raw_data, default=str),
                search_blob=search_blob,
                extra_fields=json.dumps({
                    'map_description': event.get('MapDescription'),
                    'keywords': event.get('Keywords'),
                    'has_detection': bool(detection),
                }, default=str),
                parser_version=self.parser_version,
            )
            
        except Exception as e:
            self.warnings.append(f"Error transforming event: {e}")
            logger.exception(f"Event transformation error: {e}")
            return None


class EvtxFallbackParser(BaseParser):
    """Fallback EVTX parser using pyevtx-rs
    
    Used when EvtxECmd is not available.
    Provides raw parsing without Maps field normalization or detection enrichment.
    """
    
    VERSION = '1.0.0'
    ARTIFACT_TYPE = 'evtx'
    
    def __init__(self, case_id: int, source_host: str = '', case_file_id: Optional[int] = None):
        super().__init__(case_id, source_host, case_file_id)
        
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


# Backwards compatibility aliases
HayabusaParser = EvtxECmdParser
