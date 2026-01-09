"""Log File Parsers for CaseScope

Parsers for various text-based log formats:
- IIS Web Server logs
- SonicWall/Firewall syslog
- Generic text logs
- JSON/NDJSON logs (Huntress, EDR exports)
"""
import os
import re
import json
import csv
import logging
from datetime import datetime
from typing import Generator, Dict, List, Any, Optional
from pathlib import Path

from parsers.base import BaseParser, ParsedEvent

logger = logging.getLogger(__name__)


class IISLogParser(BaseParser):
    """Parser for IIS (Internet Information Services) web server logs
    
    Supports W3C Extended Log Format (most common IIS format)
    """
    
    VERSION = '1.0.0'
    ARTIFACT_TYPE = 'iis'
    
    # W3C field mappings
    FIELD_MAP = {
        'date': 'date',
        'time': 'time',
        's-ip': 'server_ip',
        'cs-method': 'method',
        'cs-uri-stem': 'uri_stem',
        'cs-uri-query': 'uri_query',
        's-port': 'server_port',
        'cs-username': 'username',
        'c-ip': 'client_ip',
        'cs(User-Agent)': 'user_agent',
        'cs(Referer)': 'referer',
        'sc-status': 'status_code',
        'sc-substatus': 'substatus',
        'sc-win32-status': 'win32_status',
        'time-taken': 'time_taken',
        'sc-bytes': 'bytes_sent',
        'cs-bytes': 'bytes_received',
        'cs-host': 'host',
    }
    
    def __init__(self, case_id: int, source_host: str = '', case_file_id: Optional[int] = None):
        super().__init__(case_id, source_host, case_file_id)
        self.fields = []
    
    @property
    def artifact_type(self) -> str:
        return self.ARTIFACT_TYPE
    
    def can_parse(self, file_path: str) -> bool:
        """Check if file is an IIS log"""
        if not os.path.isfile(file_path):
            return False
        
        filename = os.path.basename(file_path).lower()
        
        # Check common IIS log patterns
        if filename.startswith(('u_ex', 'w3svc')) or filename.endswith('.log'):
            try:
                with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                    for line in f:
                        line = line.strip()
                        if line.startswith('#Software: Microsoft Internet Information Services'):
                            return True
                        if line.startswith('#Fields:'):
                            return True
                        if line and not line.startswith('#'):
                            break
            except:
                pass
        
        return False
    
    def parse(self, file_path: str) -> Generator[ParsedEvent, None, None]:
        """Parse IIS log file"""
        if not self.can_parse(file_path):
            self.errors.append(f"Cannot parse file: {file_path}")
            return
        
        source_file = os.path.basename(file_path)
        hostname = self.extract_hostname(file_path)
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                fields = []
                
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    
                    if not line:
                        continue
                    
                    # Parse directives
                    if line.startswith('#'):
                        if line.startswith('#Fields:'):
                            fields = line[8:].strip().split()
                        continue
                    
                    if not fields:
                        self.warnings.append(f"No #Fields directive found before data at line {line_num}")
                        continue
                    
                    try:
                        values = line.split()
                        if len(values) != len(fields):
                            self.warnings.append(f"Field count mismatch at line {line_num}")
                            continue
                        
                        record = dict(zip(fields, values))
                        
                        # Parse timestamp
                        date_str = record.get('date', '')
                        time_str = record.get('time', '')
                        timestamp = self.parse_timestamp(f"{date_str} {time_str}")
                        if not timestamp:
                            timestamp = datetime.now()
                        
                        # Extract normalized fields
                        client_ip = record.get('c-ip', '-')
                        if client_ip == '-':
                            client_ip = None
                        
                        server_ip = record.get('s-ip', '-')
                        if server_ip == '-':
                            server_ip = None
                        
                        username = record.get('cs-username', '-')
                        if username == '-':
                            username = None
                        
                        # Build URI
                        uri = record.get('cs-uri-stem', '')
                        query = record.get('cs-uri-query', '-')
                        if query and query != '-':
                            uri = f"{uri}?{query}"
                        
                        raw_data = {k: v for k, v in record.items() if v != '-'}
                        
                        search_parts = [
                            record.get('cs-method', ''),
                            uri,
                            client_ip or '',
                            username or '',
                            record.get('cs(User-Agent)', ''),
                            record.get('sc-status', ''),
                        ]
                        
                        yield ParsedEvent(
                            case_id=self.case_id,
                            artifact_type=self.artifact_type,
                            timestamp=timestamp,
                            source_file=source_file,
                            source_path=file_path,
                            source_host=hostname,
                            case_file_id=self.case_file_id,
                            username=self.safe_str(username),
                            src_ip=self.validate_ip(client_ip) if client_ip else None,
                            dst_ip=self.validate_ip(server_ip) if server_ip else None,
                            dst_port=self.safe_int(record.get('s-port')),
                            target_path=uri,
                            raw_json=json.dumps(raw_data, default=str),
                            search_blob=' '.join(str(p) for p in search_parts if p),
                            extra_fields=json.dumps({
                                'method': record.get('cs-method'),
                                'status_code': record.get('sc-status'),
                                'user_agent': record.get('cs(User-Agent)'),
                            }, default=str),
                            parser_version=self.parser_version,
                        )
                        
                    except Exception as e:
                        self.warnings.append(f"Error parsing line {line_num}: {e}")
                        
        except Exception as e:
            self.errors.append(f"Failed to parse {file_path}: {e}")
            logger.exception(f"IIS parse error: {e}")


class FirewallLogParser(BaseParser):
    """Parser for firewall/syslog format logs (SonicWall, pfSense, etc.)
    
    Handles common syslog formats with key=value pairs
    """
    
    VERSION = '1.0.0'
    ARTIFACT_TYPE = 'firewall'
    
    # Regex patterns for different formats
    SYSLOG_PATTERN = re.compile(
        r'^(?P<timestamp>\w{3}\s+\d+\s+\d+:\d+:\d+)\s+'
        r'(?P<host>\S+)\s+'
        r'(?P<program>\S+?)(?:\[(?P<pid>\d+)\])?:\s*'
        r'(?P<message>.*)$'
    )
    
    # Key=value pattern
    KV_PATTERN = re.compile(r'(\w+)=("[^"]*"|\S+)')
    
    # SonicWall specific patterns
    SONICWALL_PATTERN = re.compile(
        r'id=(\S+)\s+sn=(\S+)\s+time="([^"]+)"'
    )
    
    def __init__(self, case_id: int, source_host: str = '', case_file_id: Optional[int] = None):
        super().__init__(case_id, source_host, case_file_id)
    
    @property
    def artifact_type(self) -> str:
        return self.ARTIFACT_TYPE
    
    def can_parse(self, file_path: str) -> bool:
        """Check if file is a firewall/syslog format"""
        if not os.path.isfile(file_path):
            return False
        
        filename = os.path.basename(file_path).lower()
        
        # Check common patterns
        if any(x in filename for x in ['firewall', 'sonicwall', 'pfsense', 'syslog', 'fw']):
            return True
        
        # Check content for syslog patterns
        try:
            with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                for i, line in enumerate(f):
                    if i > 10:  # Check first 10 lines
                        break
                    line = line.strip()
                    if not line:
                        continue
                    
                    # Look for syslog timestamp pattern
                    if self.SYSLOG_PATTERN.match(line):
                        return True
                    
                    # Look for key=value patterns (common in firewall logs)
                    if self.KV_PATTERN.findall(line):
                        return True
        except:
            pass
        
        return False
    
    def parse(self, file_path: str) -> Generator[ParsedEvent, None, None]:
        """Parse firewall log file"""
        if not self.can_parse(file_path):
            self.errors.append(f"Cannot parse file: {file_path}")
            return
        
        source_file = os.path.basename(file_path)
        hostname = self.extract_hostname(file_path)
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue
                    
                    try:
                        event = self._parse_line(line)
                        if not event:
                            continue
                        
                        # Get timestamp
                        timestamp = None
                        for ts_field in ['timestamp', 'time', 'datetime', 'date']:
                            if ts_field in event:
                                timestamp = self.parse_timestamp(event[ts_field])
                                if timestamp:
                                    break
                        
                        if not timestamp:
                            timestamp = datetime.now()
                        
                        # Extract network fields
                        src_ip = self.validate_ip(
                            event.get('src') or event.get('srcip') or 
                            event.get('src_ip') or event.get('source_ip')
                        )
                        dst_ip = self.validate_ip(
                            event.get('dst') or event.get('dstip') or 
                            event.get('dst_ip') or event.get('dest_ip')
                        )
                        src_port = self.safe_int(
                            event.get('srcport') or event.get('src_port') or 
                            event.get('sport')
                        )
                        dst_port = self.safe_int(
                            event.get('dstport') or event.get('dst_port') or 
                            event.get('dport')
                        )
                        
                        # Get action/message
                        action = event.get('action') or event.get('fw_action') or event.get('msg')
                        
                        yield ParsedEvent(
                            case_id=self.case_id,
                            artifact_type=self.artifact_type,
                            timestamp=timestamp,
                            source_file=source_file,
                            source_path=file_path,
                            source_host=event.get('host') or hostname,
                            case_file_id=self.case_file_id,
                            src_ip=src_ip,
                            dst_ip=dst_ip,
                            src_port=src_port,
                            dst_port=dst_port,
                            raw_json=json.dumps(event, default=str),
                            search_blob=self.build_search_blob(event),
                            extra_fields=json.dumps({
                                'action': action,
                                'protocol': event.get('proto') or event.get('protocol'),
                            }, default=str),
                            parser_version=self.parser_version,
                        )
                        
                    except Exception as e:
                        self.warnings.append(f"Error parsing line {line_num}: {e}")
                        
        except Exception as e:
            self.errors.append(f"Failed to parse {file_path}: {e}")
            logger.exception(f"Firewall parse error: {e}")
    
    def _parse_line(self, line: str) -> Optional[Dict[str, Any]]:
        """Parse a single log line into key-value pairs"""
        result = {}
        
        # Try syslog format first
        match = self.SYSLOG_PATTERN.match(line)
        if match:
            result['timestamp'] = match.group('timestamp')
            result['host'] = match.group('host')
            result['program'] = match.group('program')
            if match.group('pid'):
                result['pid'] = match.group('pid')
            message = match.group('message')
        else:
            message = line
        
        # Parse key=value pairs from message
        for key, value in self.KV_PATTERN.findall(message):
            # Remove quotes from value
            value = value.strip('"')
            result[key.lower()] = value
        
        # If no KV pairs found, store raw message
        if len(result) <= 4:  # Only syslog header fields
            result['message'] = message
        
        return result if result else None


class HuntressParser(BaseParser):
    """Parser for Huntress EDR NDJSON exports
    
    Handles JSON/NDJSON formatted Huntress detection and telemetry data
    """
    
    VERSION = '1.0.0'
    ARTIFACT_TYPE = 'huntress'
    
    def __init__(self, case_id: int, source_host: str = '', case_file_id: Optional[int] = None):
        super().__init__(case_id, source_host, case_file_id)
    
    @property
    def artifact_type(self) -> str:
        return self.ARTIFACT_TYPE
    
    def can_parse(self, file_path: str) -> bool:
        """Check if file is a Huntress NDJSON export"""
        if not os.path.isfile(file_path):
            return False
        
        filename = os.path.basename(file_path).lower()
        
        # Check filename patterns
        if 'huntress' in filename:
            return True
        
        if not filename.endswith(('.json', '.ndjson', '.jsonl')):
            return False
        
        # Check content for Huntress markers
        try:
            with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                for i, line in enumerate(f):
                    if i > 5:
                        break
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                        # Look for Huntress-specific fields
                        if any(k in obj for k in ['huntress_', 'agent_id', 'organization_id', 'incident_report']):
                            return True
                    except json.JSONDecodeError:
                        pass
        except:
            pass
        
        return False
    
    def parse(self, file_path: str) -> Generator[ParsedEvent, None, None]:
        """Parse Huntress NDJSON file"""
        if not self.can_parse(file_path):
            self.errors.append(f"Cannot parse file: {file_path}")
            return
        
        source_file = os.path.basename(file_path)
        hostname = self.extract_hostname(file_path)
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue
                    
                    try:
                        event = json.loads(line)
                        
                        # Get timestamp
                        timestamp = None
                        for ts_field in ['timestamp', 'created_at', 'detected_at', 'event_time', '@timestamp']:
                            if ts_field in event:
                                timestamp = self.parse_timestamp(event[ts_field])
                                if timestamp:
                                    break
                        
                        if not timestamp:
                            timestamp = datetime.now()
                        
                        # Extract host
                        host = (
                            event.get('hostname') or 
                            event.get('computer_name') or 
                            event.get('agent_hostname') or
                            hostname
                        )
                        
                        # Extract normalized fields
                        username = event.get('username') or event.get('user') or event.get('account_name')
                        process_name = event.get('process_name') or event.get('image') or event.get('exe')
                        command_line = event.get('command_line') or event.get('cmdline')
                        
                        # Detection info
                        rule_title = event.get('detection_name') or event.get('rule_name') or event.get('alert_name')
                        rule_level = event.get('severity') or event.get('risk_level')
                        
                        # MITRE mapping
                        mitre_tactics = []
                        mitre_tags = []
                        
                        if 'mitre' in event:
                            mitre = event['mitre']
                            if isinstance(mitre, dict):
                                mitre_tactics = mitre.get('tactics', [])
                                mitre_tags = mitre.get('techniques', [])
                        
                        if 'tactics' in event:
                            mitre_tactics = event['tactics'] if isinstance(event['tactics'], list) else [event['tactics']]
                        if 'techniques' in event:
                            mitre_tags = event['techniques'] if isinstance(event['techniques'], list) else [event['techniques']]
                        
                        yield ParsedEvent(
                            case_id=self.case_id,
                            artifact_type=self.artifact_type,
                            timestamp=timestamp,
                            source_file=source_file,
                            source_path=file_path,
                            source_host=host,
                            case_file_id=self.case_file_id,
                            username=self.safe_str(username),
                            process_name=self.safe_str(process_name),
                            command_line=self.safe_str(command_line),
                            process_id=self.safe_int(event.get('pid') or event.get('process_id')),
                            parent_process=self.safe_str(event.get('parent_process') or event.get('parent_image')),
                            parent_pid=self.safe_int(event.get('ppid') or event.get('parent_pid')),
                            target_path=self.safe_str(event.get('target_path') or event.get('file_path')),
                            src_ip=self.validate_ip(event.get('src_ip') or event.get('source_ip')),
                            dst_ip=self.validate_ip(event.get('dst_ip') or event.get('dest_ip')),
                            rule_title=rule_title,
                            rule_level=rule_level,
                            mitre_tactics=mitre_tactics,
                            mitre_tags=mitre_tags,
                            raw_json=line,
                            search_blob=self.build_search_blob(event),
                            parser_version=self.parser_version,
                        )
                        
                    except json.JSONDecodeError as e:
                        self.warnings.append(f"JSON parse error on line {line_num}: {e}")
                    except Exception as e:
                        self.warnings.append(f"Error processing line {line_num}: {e}")
                        
        except Exception as e:
            self.errors.append(f"Failed to parse {file_path}: {e}")
            logger.exception(f"Huntress parse error: {e}")


class GenericJSONParser(BaseParser):
    """Generic parser for JSON/NDJSON log files
    
    Fallback parser for JSON-formatted logs that don't match specific parsers
    """
    
    VERSION = '1.0.0'
    ARTIFACT_TYPE = 'json_log'
    
    def __init__(self, case_id: int, source_host: str = '', case_file_id: Optional[int] = None,
                 artifact_type_override: str = None):
        super().__init__(case_id, source_host, case_file_id)
        self._artifact_type = artifact_type_override or self.ARTIFACT_TYPE
    
    @property
    def artifact_type(self) -> str:
        return self._artifact_type
    
    def can_parse(self, file_path: str) -> bool:
        """Check if file is a JSON/NDJSON file"""
        if not os.path.isfile(file_path):
            return False
        
        filename = os.path.basename(file_path).lower()
        
        if not filename.endswith(('.json', '.ndjson', '.jsonl')):
            return False
        
        # Verify it's valid JSON
        try:
            with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                first_line = f.readline().strip()
                if first_line:
                    json.loads(first_line)
                    return True
        except:
            pass
        
        return False
    
    def parse(self, file_path: str) -> Generator[ParsedEvent, None, None]:
        """Parse JSON/NDJSON file"""
        if not self.can_parse(file_path):
            self.errors.append(f"Cannot parse file: {file_path}")
            return
        
        source_file = os.path.basename(file_path)
        hostname = self.extract_hostname(file_path)
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                content = f.read().strip()
            
            # Determine if it's a JSON array or NDJSON
            events = []
            if content.startswith('['):
                # JSON array
                try:
                    events = json.loads(content)
                except json.JSONDecodeError:
                    pass
            
            if not events:
                # Try NDJSON
                for line in content.split('\n'):
                    line = line.strip()
                    if line:
                        try:
                            events.append(json.loads(line))
                        except json.JSONDecodeError:
                            pass
            
            for event in events:
                if not isinstance(event, dict):
                    continue
                
                # Get timestamp
                timestamp = None
                for ts_field in ['timestamp', '@timestamp', 'time', 'datetime', 'date', 'created_at', 'event_time']:
                    if ts_field in event:
                        timestamp = self.parse_timestamp(event[ts_field])
                        if timestamp:
                            break
                
                if not timestamp:
                    timestamp = datetime.now()
                
                # Extract host
                host = hostname
                for host_field in ['hostname', 'host', 'computer', 'machine', 'server']:
                    if host_field in event:
                        host = str(event[host_field])
                        break
                
                yield ParsedEvent(
                    case_id=self.case_id,
                    artifact_type=self.artifact_type,
                    timestamp=timestamp,
                    source_file=source_file,
                    source_path=file_path,
                    source_host=host,
                    case_file_id=self.case_file_id,
                    raw_json=json.dumps(event, default=str),
                    search_blob=self.build_search_blob(event),
                    parser_version=self.parser_version,
                )
                
        except Exception as e:
            self.errors.append(f"Failed to parse {file_path}: {e}")
            logger.exception(f"Generic JSON parse error: {e}")


class CSVLogParser(BaseParser):
    """Generic parser for CSV-formatted log files"""
    
    VERSION = '1.0.0'
    ARTIFACT_TYPE = 'csv_log'
    
    def __init__(self, case_id: int, source_host: str = '', case_file_id: Optional[int] = None,
                 artifact_type_override: str = None):
        super().__init__(case_id, source_host, case_file_id)
        self._artifact_type = artifact_type_override or self.ARTIFACT_TYPE
    
    @property
    def artifact_type(self) -> str:
        return self._artifact_type
    
    def can_parse(self, file_path: str) -> bool:
        """Check if file is a CSV file"""
        if not os.path.isfile(file_path):
            return False
        
        return file_path.lower().endswith('.csv')
    
    def parse(self, file_path: str) -> Generator[ParsedEvent, None, None]:
        """Parse CSV file"""
        if not self.can_parse(file_path):
            self.errors.append(f"Cannot parse file: {file_path}")
            return
        
        source_file = os.path.basename(file_path)
        hostname = self.extract_hostname(file_path)
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='replace', newline='') as f:
                # Detect dialect
                sample = f.read(8192)
                f.seek(0)
                
                try:
                    dialect = csv.Sniffer().sniff(sample)
                except csv.Error:
                    dialect = csv.excel
                
                reader = csv.DictReader(f, dialect=dialect)
                
                for row_num, row in enumerate(reader, 1):
                    try:
                        # Get timestamp
                        timestamp = None
                        for ts_field in ['timestamp', 'time', 'datetime', 'date', 'created', 'logged']:
                            for key in row.keys():
                                if ts_field in key.lower():
                                    timestamp = self.parse_timestamp(row[key])
                                    if timestamp:
                                        break
                            if timestamp:
                                break
                        
                        if not timestamp:
                            timestamp = datetime.now()
                        
                        # Clean empty values
                        clean_row = {k: v for k, v in row.items() if v and v.strip()}
                        
                        yield ParsedEvent(
                            case_id=self.case_id,
                            artifact_type=self.artifact_type,
                            timestamp=timestamp,
                            source_file=source_file,
                            source_path=file_path,
                            source_host=hostname,
                            case_file_id=self.case_file_id,
                            raw_json=json.dumps(clean_row, default=str),
                            search_blob=self.build_search_blob(clean_row),
                            parser_version=self.parser_version,
                        )
                        
                    except Exception as e:
                        self.warnings.append(f"Error processing row {row_num}: {e}")
                        
        except Exception as e:
            self.errors.append(f"Failed to parse {file_path}: {e}")
            logger.exception(f"CSV parse error: {e}")
