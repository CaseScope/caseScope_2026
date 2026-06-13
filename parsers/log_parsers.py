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
from typing import Generator, Dict, List, Any, Optional, Tuple
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
    
    def __init__(self, case_id: int, source_host: str = '', case_file_id: Optional[int] = None,
                 case_tz: str = 'UTC', **kwargs):
        super().__init__(case_id, source_host, case_file_id, case_tz=case_tz)
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
                            timestamp = self.fallback_timestamp(
                                file_path=file_path,
                                reason='iis log entry missing timestamp',
                            )
                        
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
                        src_ip, src_ip_raw = self.normalize_ip_for_storage(client_ip)
                        dst_ip, dst_ip_raw = self.normalize_ip_for_storage(server_ip)
                        extra = {
                            'method': record.get('cs-method'),
                            'status_code': record.get('sc-status'),
                            'user_agent': record.get('cs(User-Agent)'),
                        }
                        if src_ip_raw:
                            extra['src_ip_raw'] = src_ip_raw
                        if dst_ip_raw:
                            extra['dst_ip_raw'] = dst_ip_raw
                        
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
                            timestamp_source_tz=self.get_source_tz(),  # IIS uses case TZ (ambiguous source)
                            source_file=source_file,
                            source_path=file_path,
                            source_host=hostname,
                            case_file_id=self.case_file_id,
                            username=self.safe_str(username),
                            src_ip=src_ip,
                            dst_ip=dst_ip,
                            dst_port=self.safe_int(record.get('s-port')),
                            target_path=uri,
                            raw_json=json.dumps(raw_data, default=str),
                            search_blob=' '.join(str(p) for p in search_parts if p),
                            extra_fields=json.dumps(extra, default=str),
                            parser_version=self.parser_version,
                        )
                        
                    except Exception as e:
                        self.warnings.append(f"Error parsing line {line_num}: {e}")
                        
        except Exception as e:
            self.errors.append(f"Failed to parse {file_path}: {e}")
            logger.exception(f"IIS parse error: {e}")


class GenericWeblogParser(BaseParser):
    """Parser for Apache/nginx access logs in Common or Combined Log Format.

    Covers the NCSA formats emitted by default Apache httpd and nginx
    configurations:
        host ident authuser [timestamp] "request" status bytes
    plus the Combined extension:
        ... "referer" "user-agent"
    """

    VERSION = '1.0.0'
    ARTIFACT_TYPE = 'generic_weblog'

    WEBLOG_PATTERN = re.compile(
        r'^(?P<client_ip>\S+)\s+'
        r'(?P<ident>\S+)\s+'
        r'(?P<username>\S+)\s+'
        r'\[(?P<timestamp>[^\]]+)\]\s+'
        r'"(?P<request>[^"]*)"\s+'
        r'(?P<status>\d{3}|-)\s+'
        r'(?P<bytes>\d+|-)'
        r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<user_agent>[^"]*)")?'
    )

    # 10/Oct/2000:13:55:36 -0700
    CLF_TIMESTAMP_TZ = '%d/%b/%Y:%H:%M:%S %z'
    CLF_TIMESTAMP_NAIVE = '%d/%b/%Y:%H:%M:%S'

    def __init__(self, case_id: int, source_host: str = '', case_file_id: Optional[int] = None,
                 case_tz: str = 'UTC', **kwargs):
        super().__init__(case_id, source_host, case_file_id, case_tz=case_tz)

    @property
    def artifact_type(self) -> str:
        return self.ARTIFACT_TYPE

    def _parse_clf_timestamp(self, value: str) -> Tuple[Optional[datetime], Optional[datetime]]:
        """Return (naive local timestamp, naive UTC timestamp or None)."""
        value = (value or '').strip()
        try:
            aware = datetime.strptime(value, self.CLF_TIMESTAMP_TZ)
            from datetime import timezone as _tz
            return aware.replace(tzinfo=None), aware.astimezone(_tz.utc).replace(tzinfo=None)
        except ValueError:
            pass
        try:
            return datetime.strptime(value, self.CLF_TIMESTAMP_NAIVE), None
        except ValueError:
            return None, None

    def can_parse(self, file_path: str) -> bool:
        """Check whether the first data lines look like CLF/Combined entries."""
        if not os.path.isfile(file_path):
            return False

        matched = 0
        checked = 0
        try:
            with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    checked += 1
                    if checked > 10:
                        break
                    match = self.WEBLOG_PATTERN.match(line)
                    if match:
                        local_ts, _ = self._parse_clf_timestamp(match.group('timestamp'))
                        if local_ts is not None:
                            matched += 1
        except Exception:
            return False

        if checked == 0:
            return False
        # Require a clear majority of sampled lines to match so mixed text
        # logs do not get claimed by this parser.
        return matched >= max(1, (min(checked, 10) + 1) // 2)

    def parse(self, file_path: str) -> Generator[ParsedEvent, None, None]:
        """Parse an Apache/nginx access log."""
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

                    match = self.WEBLOG_PATTERN.match(line)
                    if not match:
                        self.warnings.append(f"Unrecognized weblog line {line_num}")
                        continue

                    try:
                        record = match.groupdict()

                        timestamp, timestamp_utc = self._parse_clf_timestamp(record.get('timestamp'))
                        if timestamp is None:
                            timestamp = self.fallback_timestamp(
                                file_path=file_path,
                                reason='weblog entry missing timestamp',
                            )

                        request = record.get('request') or ''
                        request_parts = request.split()
                        method = request_parts[0] if len(request_parts) >= 1 else ''
                        uri = request_parts[1] if len(request_parts) >= 2 else ''
                        protocol = request_parts[2] if len(request_parts) >= 3 else ''

                        username = self.safe_str(record.get('username'))
                        client_ip = record.get('client_ip')
                        src_ip, src_ip_raw = self.normalize_ip_for_storage(client_ip)

                        status = self.safe_str(record.get('status'))
                        raw_data = {k: v for k, v in record.items() if v and v != '-'}
                        extra = {
                            'method': method,
                            'protocol': protocol,
                            'status_code': status,
                            'bytes_sent': self.safe_int(record.get('bytes')),
                            'referer': self.safe_str(record.get('referer')),
                            'user_agent': self.safe_str(record.get('user_agent')),
                        }
                        if src_ip_raw:
                            extra['src_ip_raw'] = src_ip_raw

                        search_parts = [
                            method,
                            uri,
                            client_ip or '',
                            username,
                            status,
                            self.safe_str(record.get('referer')),
                            self.safe_str(record.get('user_agent')),
                        ]

                        yield ParsedEvent(
                            case_id=self.case_id,
                            artifact_type=self.artifact_type,
                            timestamp=timestamp,
                            timestamp_utc=timestamp_utc,
                            # Offset-bearing lines carry their own UTC offset;
                            # offset-less lines fall back to the case timezone.
                            timestamp_source_tz='UTC' if timestamp_utc else self.get_source_tz(),
                            source_file=source_file,
                            source_path=file_path,
                            source_host=hostname,
                            case_file_id=self.case_file_id,
                            event_id=status,
                            username=username,
                            src_ip=src_ip,
                            target_path=uri,
                            raw_json=json.dumps(raw_data, default=str),
                            search_blob=' '.join(str(p) for p in search_parts if p),
                            extra_fields=json.dumps(extra, default=str),
                            parser_version=self.parser_version,
                        )

                    except Exception as e:
                        self.warnings.append(f"Error parsing line {line_num}: {e}")

        except Exception as e:
            self.errors.append(f"Failed to parse {file_path}: {e}")
            logger.exception(f"Generic weblog parse error: {e}")


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
    
    def __init__(self, case_id: int, source_host: str = '', case_file_id: Optional[int] = None,
                 case_tz: str = 'UTC', artifact_type_override: str = None, **kwargs):
        super().__init__(case_id, source_host, case_file_id, case_tz=case_tz)
        self._artifact_type = artifact_type_override or self.ARTIFACT_TYPE
    
    @property
    def artifact_type(self) -> str:
        return self._artifact_type
    
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
        
        w3c_fields = []
        try:
            with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue
                    if line.lower().startswith('#fields:'):
                        w3c_fields = line.split(':', 1)[1].strip().split()
                        continue
                    if line.startswith('#'):
                        continue
                    
                    try:
                        event = self._parse_w3c_line(line, w3c_fields) if w3c_fields else self._parse_line(line)
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
                            timestamp = self.fallback_timestamp(
                                file_path=file_path,
                                reason='firewall log entry missing timestamp',
                            )
                        
                        # Extract network fields
                        raw_src_ip = (
                            event.get('src') or event.get('srcip') or
                            event.get('src_ip') or event.get('source_ip')
                        )
                        raw_dst_ip = (
                            event.get('dst') or event.get('dstip') or
                            event.get('dst_ip') or event.get('dest_ip')
                        )
                        src_ip, src_ip_raw = self.normalize_ip_for_storage(raw_src_ip)
                        dst_ip, dst_ip_raw = self.normalize_ip_for_storage(raw_dst_ip)
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
                        extra = {
                            'action': action,
                            'protocol': event.get('proto') or event.get('protocol'),
                        }
                        if src_ip_raw:
                            extra['src_ip_raw'] = src_ip_raw
                        if dst_ip_raw:
                            extra['dst_ip_raw'] = dst_ip_raw
                        
                        yield ParsedEvent(
                            case_id=self.case_id,
                            artifact_type=self.artifact_type,
                            timestamp=timestamp,
                            timestamp_source_tz=self.get_source_tz(),  # Firewall uses case TZ (ambiguous source)
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
                            extra_fields=json.dumps(extra, default=str),
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

    def _parse_w3c_line(self, line: str, fields: List[str]) -> Optional[Dict[str, Any]]:
        """Parse W3C-style firewall rows such as Windows pfirewall.log."""
        if not fields:
            return None
        values = line.split()
        if len(values) < len(fields):
            return None
        row = {field.lower(): values[idx] for idx, field in enumerate(fields)}
        if row.get('date') and row.get('time'):
            row['timestamp'] = f"{row['date']} {row['time']}"
        aliases = {
            'src-ip': 'src_ip',
            'dst-ip': 'dst_ip',
            'src-port': 'src_port',
            'dst-port': 'dst_port',
            'protocol': 'protocol',
            'action': 'action',
        }
        for source, target in aliases.items():
            if source in row and target not in row:
                row[target] = row[source]
        return row


class HuntressParser(BaseParser):
    """Parser for Huntress EDR NDJSON exports
    
    Handles ECS (Elastic Common Schema) formatted JSON/NDJSON from Huntress.
    Supports process telemetry, detections, and other event types.
    
    Field mapping follows Huntress ECS schema:
    - host.hostname -> source_host
    - process.* -> process fields
    - process.user.* -> user fields
    - event.* -> event metadata
    - account/organization -> extra_fields
    """
    
    VERSION = '2.1.0'
    ARTIFACT_TYPE = 'huntress'
    
    def __init__(self, case_id: int, source_host: str = '', case_file_id: Optional[int] = None,
                 case_tz: str = 'UTC', **kwargs):
        super().__init__(case_id, source_host, case_file_id, case_tz=case_tz)
    
    @property
    def artifact_type(self) -> str:
        return self.ARTIFACT_TYPE
    
    def _get_nested(self, data: Dict, *keys, default=None):
        """Safely retrieve nested dictionary value"""
        current = data
        for key in keys:
            if isinstance(current, dict):
                current = current.get(key)
            else:
                return default
            if current is None:
                return default
        return current
    
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
        
        # Check content for Huntress/ECS markers
        try:
            with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                for i, line in enumerate(f):
                    if i > 5:
                        break
                    line = line.strip()
                    if not line:
                        continue
                    
                    # Quick check for huntress.io in raw content (agent URL, etc.)
                    if 'huntress.io' in line.lower():
                        return True
                    
                    try:
                        obj = json.loads(line)
                        # Look for Huntress-specific ECS fields
                        if 'agent' in obj and 'host' in obj and 'process' in obj:
                            # ECS format with agent/host/process
                            return True
                        if 'organization' in obj or 'account' in obj:
                            # Huntress org structure
                            return True
                        # Legacy flat field check
                        if any(k in obj for k in ['huntress_', 'agent_id', 'organization_id', 'incident_report']):
                            return True
                    except json.JSONDecodeError:
                        pass
        except:
            pass
        
        return False
    
    def parse(self, file_path: str) -> Generator[ParsedEvent, None, None]:
        """Parse Huntress NDJSON file with ECS field mapping"""
        if not self.can_parse(file_path):
            self.errors.append(f"Cannot parse file: {file_path}")
            return
        
        source_file = os.path.basename(file_path)
        default_hostname = self.extract_hostname(file_path)
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue
                    
                    try:
                        event = json.loads(line)
                        parsed = self._parse_ecs_event(event, source_file, file_path, default_hostname, line)
                        if parsed:
                            yield parsed
                        
                    except json.JSONDecodeError as e:
                        self.warnings.append(f"JSON parse error on line {line_num}: {e}")
                    except Exception as e:
                        self.warnings.append(f"Error processing line {line_num}: {e}")
                        
        except Exception as e:
            self.errors.append(f"Failed to parse {file_path}: {e}")
            logger.exception(f"Huntress parse error: {e}")
    
    def _parse_ecs_event(self, event: Dict, source_file: str, file_path: str, 
                         default_hostname: str, raw_line: str) -> Optional[ParsedEvent]:
        """Parse a single Huntress ECS-formatted event"""
        
        # === TIMESTAMP ===
        timestamp = None
        # ECS @timestamp first
        if '@timestamp' in event:
            timestamp = self.parse_timestamp(event['@timestamp'])
        # Fallback to other common fields
        if not timestamp:
            for ts_field in ['event_recorded_at', 'timestamp', 'created_at', 'detected_at', 'event_time']:
                if ts_field in event:
                    val = event[ts_field]
                    # Handle epoch milliseconds
                    if isinstance(val, (int, float)) and val > 1000000000000:
                        try:
                            timestamp = datetime.utcfromtimestamp(val / 1000)
                            break
                        except:
                            pass
                    else:
                        timestamp = self.parse_timestamp(val)
                        if timestamp:
                            break
        if not timestamp:
            timestamp = self.fallback_timestamp(
                file_path=file_path,
                reason='huntress event missing timestamp',
            )
        
        # === HOST ===
        host = self._get_nested(event, 'host', 'hostname') or \
               self._get_nested(event, 'host', 'name') or \
               event.get('hostname') or \
               event.get('computer_name') or \
               default_hostname
        
        host_ip = self._get_nested(event, 'host', 'ip')
        host_domain = self._get_nested(event, 'host', 'domain', default='')
        host_os_full = self._get_nested(event, 'host', 'os', 'full', default='')
        host_os_version = self._get_nested(event, 'host', 'os', 'version', default='')
        host_arch = self._get_nested(event, 'host', 'architecture', default='')
        host_mac = self._get_nested(event, 'host', 'mac', default=[])
        
        # === PROCESS ===
        proc = event.get('process', {})
        process_name = proc.get('name', '')
        process_path = proc.get('executable', '')
        process_id = self.safe_int(proc.get('pid'))
        command_line = proc.get('command_line', '')
        working_dir = proc.get('working_directory', '')
        entity_id = proc.get('entity_id', '')
        
        # Process hashes
        proc_hash = proc.get('hash', {})
        file_hash_md5 = proc_hash.get('md5', '')
        file_hash_sha1 = proc_hash.get('sha1', '')
        file_hash_sha256 = proc_hash.get('sha256', '')
        
        # Process PE info
        pe = proc.get('pe', {})
        pe_size = self.safe_int(pe.get('size'))
        pe_original_name = pe.get('original_file_name', '')
        pe_imphash = pe.get('imphash', '')
        pe_compile_time = pe.get('compile_time', '')
        
        # Code signature
        code_sig = proc.get('code_signature', {})
        sig_exists = code_sig.get('exists', False)
        sig_valid = code_sig.get('valid', False)
        sig_subject = code_sig.get('subject_name', '')
        sig_issuer = code_sig.get('issuer_name', '')
        
        # Process elevation/privileges
        elevated = proc.get('elevated', False)
        elevation_type = proc.get('elevation_type')
        mandatory_label = proc.get('mandatory_label', '')
        logon_id = proc.get('logon_id')
        
        # === PARENT PROCESS ===
        parent = proc.get('parent') or {}
        parent_name = parent.get('name', '') or parent.get('executable', '')
        parent_pid = self.safe_int(parent.get('pid'))
        parent_cmdline = parent.get('command_line', '')
        parent_entity_id = parent.get('entity_id', '')
        
        # Parent hashes
        parent_hash = parent.get('hash') or {}
        parent_md5 = parent_hash.get('md5', '')
        parent_sha256 = parent_hash.get('sha256', '')
        
        # Parent code signature
        parent_sig = parent.get('code_signature') or {}
        parent_sig_valid = parent_sig.get('valid', False)
        parent_sig_subject = parent_sig.get('subject_name', '')
        
        # === GRANDPARENT PROCESS ===
        grandparent = parent.get('parent') or {}
        grandparent_name = grandparent.get('name', '')
        grandparent_cmdline = grandparent.get('command_line', '')
        
        # === USER ===
        user = proc.get('user', {})
        username = user.get('name', '')
        domain = user.get('domain', '')
        sid = user.get('id', '')
        user_type = user.get('type', '')
        
        # === EVENT METADATA ===
        evt = event.get('event', {})
        event_kind = evt.get('kind', '')
        event_category = evt.get('category', '')
        event_type = evt.get('type', [])
        if isinstance(event_type, list):
            event_type = ','.join(event_type)
        
        # === ACCOUNT/ORGANIZATION ===
        account = event.get('account', {})
        account_id = account.get('id')
        account_name = account.get('name', '')
        
        org = event.get('organization', {})
        org_id = org.get('id')
        org_name = org.get('name', '')
        
        # === AGENT ===
        agent = event.get('agent', {})
        agent_id = agent.get('id')
        agent_version = agent.get('version', '')
        agent_url = agent.get('url', '')
        
        # === DETECTION INFO ===
        # Check for detection/alert fields
        labels = event.get('labels', {}) or {}
        rule_title = labels.get('detection_name') or labels.get('rule_name') or ''
        rule_level = labels.get('severity') or labels.get('risk_level') or ''
        
        # MITRE from labels or direct
        mitre_tactics = []
        mitre_tags = []
        if 'mitre' in event:
            mitre = event['mitre']
            if isinstance(mitre, dict):
                mitre_tactics = mitre.get('tactics', [])
                mitre_tags = mitre.get('techniques', [])
        
        # === NETWORK (if present) ===
        raw_src_ip = event.get('source', {}).get('ip') or event.get('src_ip')
        raw_dst_ip = event.get('destination', {}).get('ip') or event.get('dst_ip')
        src_ip, src_ip_raw = self.normalize_ip_for_storage(raw_src_ip)
        dst_ip, dst_ip_raw = self.normalize_ip_for_storage(raw_dst_ip)
        src_port = self.safe_int(event.get('source', {}).get('port'))
        dst_port = self.safe_int(event.get('destination', {}).get('port'))
        
        # === BUILD SEARCH BLOB ===
        search_parts = [
            # Process info
            process_name, process_path, command_line, working_dir,
            str(process_id) if process_id else '',
            # Hashes
            file_hash_md5, file_hash_sha1, file_hash_sha256,
            # Signature
            sig_subject, sig_issuer,
            # Parent
            parent_name, parent_cmdline, parent_md5, parent_sha256, parent_sig_subject,
            # Grandparent
            grandparent_name, grandparent_cmdline,
            # User
            username, domain, sid,
            # Host
            host, host_domain, host_ip or '', host_os_full,
            # Organization
            account_name, org_name,
            # Event
            event_kind, event_category, event_type,
            # PE
            pe_original_name, pe_imphash,
            # Entity IDs (for correlation)
            entity_id, parent_entity_id,
        ]
        search_blob = ' '.join(str(p) for p in search_parts if p)
        
        # === EXTRA FIELDS (comprehensive) ===
        extra = {
            # Event metadata
            'event_kind': event_kind,
            'event_category': event_category,
            'event_type': event_type,
            'ecs_version': self._get_nested(event, 'ecs', 'version', default=''),
            # Host extended
            'host_domain': host_domain,
            'host_ip': host_ip,
            'host_os': host_os_full,
            'host_os_version': host_os_version,
            'host_arch': host_arch,
            'host_mac': host_mac if isinstance(host_mac, list) else [host_mac] if host_mac else [],
            # Process extended
            'entity_id': entity_id,
            'working_directory': working_dir,
            'args': proc.get('args', []),
            'args_count': proc.get('args_count'),
            'command_length': proc.get('command_length'),
            'elevated': elevated,
            'elevation_type': elevation_type,
            'mandatory_label': mandatory_label,
            'logon_id': logon_id,
            'total_parents': proc.get('total_parents'),
            'exit_code': proc.get('exit_code'),
            'pid_spoofed': proc.get('pid_spoofed', False),
            # PE info
            'pe_original_name': pe_original_name,
            'pe_imphash': pe_imphash,
            'pe_exphash': pe.get('exphash', ''),
            'pe_compile_time': pe_compile_time,
            'pe_size': pe_size,
            'pe_arch': pe.get('arch', ''),
            'pe_temp_dir': pe.get('temp_dir', False),
            # Code signature
            'sig_exists': sig_exists,
            'sig_valid': sig_valid,
            'sig_subject': sig_subject,
            'sig_issuer': sig_issuer,
            'sig_serial': code_sig.get('serial', ''),
            # Parent extended
            'parent_entity_id': parent_entity_id,
            'parent_cmdline': parent_cmdline,
            'parent_md5': parent_md5,
            'parent_sha256': parent_sha256,
            'parent_sig_valid': parent_sig_valid,
            'parent_sig_subject': parent_sig_subject,
            # Grandparent
            'grandparent_name': grandparent_name,
            'grandparent_cmdline': grandparent_cmdline,
            # User extended
            'user_type': user_type,
            'user_roles': user.get('roles', ''),
            # Account/Org
            'account_id': account_id,
            'account_name': account_name,
            'account_subdomain': account.get('subdomain', ''),
            'org_id': org_id,
            'org_name': org_name,
            # Agent
            'agent_id': agent_id,
            'agent_version': agent_version,
            'agent_url': agent_url,
            # Timing
            'host_started_at': proc.get('host_started_at'),
            'host_terminated_at': proc.get('host_terminated_at'),
            'event_recorded_at': event.get('event_recorded_at'),
            # Reputation
            'rep_count': proc.get('rep_count'),
            'run_count': proc.get('run_count'),
            'cmd_hash': proc.get('cmd_hash', ''),
        }
        if src_ip_raw:
            extra['src_ip_raw'] = src_ip_raw
        if dst_ip_raw:
            extra['dst_ip_raw'] = dst_ip_raw
        # Remove None/empty values to save space
        extra = {k: v for k, v in extra.items() if v is not None and v != '' and v != []}
        
        return ParsedEvent(
            case_id=self.case_id,
            artifact_type=self.artifact_type,
            timestamp=timestamp,
            source_file=source_file,
            source_path=file_path,
            source_host=host,
            case_file_id=self.case_file_id,
            # Event metadata
            event_id=entity_id,
            channel=event_category,
            provider='huntress',
            level=event_kind,
            # User
            username=self.safe_str(username),
            domain=self.safe_str(domain),
            sid=self.safe_str(sid),
            elevated_token=self.safe_str(elevation_type),
            # Process
            process_name=self.safe_str(process_name),
            process_path=self.safe_str(process_path),
            process_id=process_id,
            parent_process=self.safe_str(parent_name),
            parent_pid=parent_pid,
            command_line=self.safe_str(command_line),
            # File/PE hashes
            file_hash_md5=self.safe_str(file_hash_md5),
            file_hash_sha1=self.safe_str(file_hash_sha1),
            file_hash_sha256=self.safe_str(file_hash_sha256),
            file_size=pe_size,
            # Network
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            # Detection
            rule_title=rule_title,
            rule_level=rule_level,
            mitre_tactics=mitre_tactics,
            mitre_tags=mitre_tags,
            # Full data
            raw_json=raw_line,
            search_blob=search_blob,
            extra_fields=json.dumps(extra, default=str),
            parser_version=self.parser_version,
        )


class PowerShellHistoryParser(BaseParser):
    """Parser for PowerShell PSReadLine command history."""

    VERSION = '1.0.0'
    ARTIFACT_TYPE = 'powershell_history'

    @property
    def artifact_type(self) -> str:
        return self.ARTIFACT_TYPE

    def can_parse(self, file_path: str) -> bool:
        if not os.path.isfile(file_path):
            return False

        filename = os.path.basename(file_path).lower()
        path_lower = file_path.lower().replace('\\', '/')
        return filename == 'consolehost_history.txt' and '/psreadline/' in path_lower

    def parse(self, file_path: str) -> Generator[ParsedEvent, None, None]:
        if not self.can_parse(file_path):
            self.errors.append(f"Cannot parse file: {file_path}")
            return

        source_file = os.path.basename(file_path)
        hostname = self.extract_hostname(file_path)
        fallback_ts = self.fallback_timestamp(
            file_path=file_path,
            reason='powershell history entries use file mtime timestamp',
        )

        try:
            with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                for line_number, line in enumerate(f, 1):
                    command = line.strip()
                    if not command:
                        continue

                    raw_data = {
                        'line_number': line_number,
                        'command': command,
                    }

                    yield ParsedEvent(
                        case_id=self.case_id,
                        artifact_type=self.artifact_type,
                        timestamp=fallback_ts,
                        source_file=source_file,
                        source_path=file_path,
                        source_host=hostname,
                        case_file_id=self.case_file_id,
                        process_name='powershell.exe',
                        command_line=command,
                        raw_json=json.dumps(raw_data, default=str),
                        search_blob=f"{command} powershell psreadline history",
                        extra_fields=json.dumps({'line_number': line_number}, default=str),
                        parser_version=self.parser_version,
                    )
        except Exception as e:
            self.errors.append(f"Failed to parse {file_path}: {e}")
            logger.exception(f"PowerShell history parse error: {e}")


class HostsFileParser(BaseParser):
    """Parser for Windows hosts file mappings."""

    VERSION = '1.0.0'
    ARTIFACT_TYPE = 'hosts'

    @property
    def artifact_type(self) -> str:
        return self.ARTIFACT_TYPE

    def can_parse(self, file_path: str) -> bool:
        if not os.path.isfile(file_path):
            return False

        filename = os.path.basename(file_path).lower()
        path_lower = file_path.lower().replace('\\', '/')
        return filename == 'hosts' and '/drivers/etc/' in path_lower

    def parse(self, file_path: str) -> Generator[ParsedEvent, None, None]:
        if not self.can_parse(file_path):
            self.errors.append(f"Cannot parse file: {file_path}")
            return

        source_file = os.path.basename(file_path)
        hostname = self.extract_hostname(file_path)
        fallback_ts = self.fallback_timestamp(
            file_path=file_path,
            reason='hosts entries use file mtime timestamp',
        )

        try:
            with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                for line_number, line in enumerate(f, 1):
                    stripped = line.strip()
                    if not stripped or stripped.startswith('#'):
                        continue

                    content, _, comment = stripped.partition('#')
                    parts = content.split()
                    if len(parts) < 2:
                        continue

                    ip_address = parts[0]
                    hostnames = parts[1:]
                    if not self.validate_ip(ip_address):
                        self.warnings.append(f"Invalid hosts IP at line {line_number}: {ip_address}")
                        continue

                    raw_data = {
                        'ip_address': ip_address,
                        'hostnames': hostnames,
                        'comment': comment.strip(),
                        'line_number': line_number,
                    }

                    yield ParsedEvent(
                        case_id=self.case_id,
                        artifact_type=self.artifact_type,
                        timestamp=fallback_ts,
                        source_file=source_file,
                        source_path=file_path,
                        source_host=hostname,
                        case_file_id=self.case_file_id,
                        remote_host=ip_address,
                        target_path=' '.join(hostnames),
                        raw_json=json.dumps(raw_data, default=str),
                        search_blob=f"{ip_address} {' '.join(hostnames)} hosts mapping",
                        extra_fields=json.dumps({'line_number': line_number}, default=str),
                        parser_version=self.parser_version,
                    )
        except Exception as e:
            self.errors.append(f"Failed to parse {file_path}: {e}")
            logger.exception(f"Hosts file parse error: {e}")


class SetupApiLogParser(BaseParser):
    """Parser for setupapi.dev.log device installation events."""

    VERSION = '1.0.0'
    ARTIFACT_TYPE = 'setupapi'
    FULL_TIMESTAMP_RE = re.compile(r'(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}\.\d{3})')
    TIME_ONLY_RE = re.compile(r'(\d{2}:\d{2}:\d{2}\.\d{3})$')
    ACTION_RE = re.compile(r'\{([^{}]+)\}')

    @property
    def artifact_type(self) -> str:
        return self.ARTIFACT_TYPE

    def can_parse(self, file_path: str) -> bool:
        return os.path.isfile(file_path) and os.path.basename(file_path).lower() == 'setupapi.dev.log'

    def _parse_line_timestamp(self, line: str, active_date: Optional[str]) -> Optional[datetime]:
        match = self.FULL_TIMESTAMP_RE.search(line)
        if match:
            return self.parse_timestamp(match.group(1), formats=['%Y/%m/%d %H:%M:%S.%f'])

        match = self.TIME_ONLY_RE.search(line.strip())
        if match and active_date:
            return self.parse_timestamp(
                f'{active_date} {match.group(1)}',
                formats=['%Y/%m/%d %H:%M:%S.%f'],
            )

        return None

    def parse(self, file_path: str) -> Generator[ParsedEvent, None, None]:
        if not self.can_parse(file_path):
            self.errors.append(f"Cannot parse file: {file_path}")
            return

        source_file = os.path.basename(file_path)
        hostname = self.extract_hostname(file_path)
        active_date = None
        current_section = ''

        try:
            with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                for line_number, line in enumerate(f, 1):
                    stripped = line.strip()
                    if not stripped:
                        continue

                    full_ts_match = self.FULL_TIMESTAMP_RE.search(stripped)
                    if full_ts_match:
                        active_date = full_ts_match.group(1).split()[0]

                    if (stripped.startswith('>>>') or stripped.startswith('<<<')) and '[' in stripped:
                        current_section = stripped

                    timestamp = self._parse_line_timestamp(stripped, active_date)
                    if not timestamp:
                        continue

                    action_match = self.ACTION_RE.search(stripped)
                    action_text = action_match.group(1).strip() if action_match else stripped
                    target_path = ''
                    if action_match and ': ' in action_text:
                        target_path = action_text.split(': ', 1)[1].strip()

                    prefix = stripped.split(':', 1)[0].strip() if ':' in stripped else ''
                    raw_data = {
                        'line_number': line_number,
                        'line': stripped,
                        'prefix': prefix,
                        'section': current_section,
                        'action': action_text,
                    }

                    yield ParsedEvent(
                        case_id=self.case_id,
                        artifact_type=self.artifact_type,
                        timestamp=timestamp,
                        timestamp_source_tz=self.case_tz,
                        source_file=source_file,
                        source_path=file_path,
                        source_host=hostname,
                        case_file_id=self.case_file_id,
                        level=prefix,
                        target_path=target_path,
                        raw_json=json.dumps(raw_data, default=str),
                        search_blob=' '.join(
                            part for part in [
                                prefix,
                                current_section,
                                action_text,
                                target_path,
                                'setupapi device install',
                            ] if part
                        ),
                        extra_fields=json.dumps({
                            'line_number': line_number,
                            'section': current_section,
                        }, default=str),
                        parser_version=self.parser_version,
                    )
        except Exception as e:
            self.errors.append(f"Failed to parse {file_path}: {e}")
            logger.exception(f"SetupAPI parse error: {e}")


class GenericJSONParser(BaseParser):
    """Generic parser for JSON/NDJSON log files
    
    Fallback parser for JSON-formatted logs that don't match specific parsers.
    Extracts common user/system/process fields for known users/systems discovery.
    """
    
    VERSION = '1.1.0'
    ARTIFACT_TYPE = 'json_log'
    
    def __init__(self, case_id: int, source_host: str = '', case_file_id: Optional[int] = None,
                 case_tz: str = 'UTC', artifact_type_override: str = None, **kwargs):
        super().__init__(case_id, source_host, case_file_id, case_tz=case_tz)
        self._artifact_type = artifact_type_override or self.ARTIFACT_TYPE
    
    @property
    def artifact_type(self) -> str:
        return self._artifact_type
    
    def _get_nested(self, data: Dict, *keys, default=None):
        """Safely retrieve nested dictionary value"""
        current = data
        for key in keys:
            if isinstance(current, dict):
                current = current.get(key)
            else:
                return default
            if current is None:
                return default
        return current
    
    def can_parse(self, file_path: str) -> bool:
        """Check if file is a JSON/NDJSON file"""
        if not os.path.isfile(file_path):
            return False
        
        filename = os.path.basename(file_path).lower()
        
        if not filename.endswith(('.json', '.ndjson', '.jsonl')):
            return False
        
        # Verify it's valid JSON (NDJSON or pretty-printed)
        try:
            with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                first_line = f.readline().strip()
                if first_line:
                    try:
                        json.loads(first_line)
                        return True
                    except json.JSONDecodeError:
                        pass
                    # First line alone didn't parse; try a larger chunk
                    # to handle pretty-printed JSON files
                    f.seek(0)
                    head = f.read(8192)
                    if head:
                        json.loads(head)
                        return True
        except Exception:
            pass
        
        return False
    
    def _extract_user_fields(self, event: Dict) -> Tuple[str, str, str]:
        """Extract username, domain, and SID from various JSON structures
        
        Supports common formats:
        - ECS: process.user.name, process.user.domain, process.user.id
        - Flat: username, user, user_name, domain, sid
        - Nested: user.name, user.domain, user.sid
        - Windows: SubjectUserName, TargetUserName, SubjectDomainName
        
        Returns: (username, domain, sid)
        """
        username = ''
        domain = ''
        sid = ''
        
        # Try ECS nested structure first (Huntress, Elastic, etc.)
        if 'process' in event and isinstance(event.get('process'), dict):
            proc = event['process']
            user = proc.get('user', {})
            if isinstance(user, dict):
                username = user.get('name', '') or ''
                domain = user.get('domain', '') or ''
                sid = user.get('id', '') or ''
        
        # Try user object
        if not username and 'user' in event and isinstance(event.get('user'), dict):
            user = event['user']
            username = user.get('name', '') or user.get('username', '') or ''
            domain = user.get('domain', '') or ''
            sid = user.get('id', '') or user.get('sid', '') or ''
        
        # Try flat fields (common in many log formats)
        if not username:
            for field in ['username', 'user', 'user_name', 'UserName', 'userName',
                         'SubjectUserName', 'TargetUserName', 'AccountName', 'account_name']:
                val = event.get(field)
                if val and isinstance(val, str):
                    username = val
                    break
        
        if not domain:
            for field in ['domain', 'Domain', 'SubjectDomainName', 'TargetDomainName', 
                         'user_domain', 'UserDomain', 'AccountDomain']:
                val = event.get(field)
                if val and isinstance(val, str):
                    domain = val
                    break
        
        if not sid:
            for field in ['sid', 'SID', 'Sid', 'user_sid', 'SubjectUserSid', 
                         'TargetUserSid', 'SecurityId', 'security_id']:
                val = event.get(field)
                if val and isinstance(val, str):
                    sid = val
                    break
        
        return (
            self.safe_str(username),
            self.safe_str(domain),
            self.safe_str(sid)
        )
    
    def _extract_host(self, event: Dict, default_host: str) -> str:
        """Extract hostname from various JSON structures
        
        Supports:
        - ECS: host.hostname, host.name
        - Flat: hostname, host, computer, machine, server, Computer
        - Nested: host.hostname for dict values
        """
        # Try ECS nested structure
        if 'host' in event:
            host_val = event.get('host')
            if isinstance(host_val, dict):
                hostname = host_val.get('hostname') or host_val.get('name') or ''
                if hostname:
                    return str(hostname)
            elif isinstance(host_val, str):
                return host_val
        
        # Try flat fields
        for field in ['hostname', 'host', 'computer', 'machine', 'server', 
                     'Computer', 'ComputerName', 'computer_name', 'MachineName']:
            val = event.get(field)
            if val and isinstance(val, str):
                return val
        
        return default_host
    
    def _extract_process_fields(self, event: Dict) -> Dict[str, Any]:
        """Extract process-related fields from various JSON structures"""
        result = {
            'process_name': '',
            'process_path': '',
            'process_id': None,
            'parent_process': '',
            'parent_pid': None,
            'command_line': '',
        }
        
        # Try ECS structure
        if 'process' in event and isinstance(event.get('process'), dict):
            proc = event['process']
            result['process_name'] = self.safe_str(proc.get('name', ''))
            result['process_path'] = self.safe_str(proc.get('executable', ''))
            result['process_id'] = self.safe_int(proc.get('pid'))
            result['command_line'] = self.safe_str(proc.get('command_line', ''))
            
            parent = proc.get('parent', {})
            if isinstance(parent, dict):
                result['parent_process'] = self.safe_str(parent.get('name', '') or parent.get('executable', ''))
                result['parent_pid'] = self.safe_int(parent.get('pid'))
        
        # Try flat fields as fallback
        if not result['process_name']:
            for field in ['process_name', 'ProcessName', 'Image', 'image', 'exe', 'executable']:
                val = event.get(field)
                if val and isinstance(val, str):
                    result['process_name'] = self.safe_str(val)
                    break
        
        if not result['process_id']:
            for field in ['process_id', 'pid', 'ProcessId', 'PID']:
                val = event.get(field)
                if val is not None:
                    result['process_id'] = self.safe_int(val)
                    if result['process_id']:
                        break
        
        if not result['command_line']:
            for field in ['command_line', 'CommandLine', 'cmdline', 'cmd']:
                val = event.get(field)
                if val and isinstance(val, str):
                    result['command_line'] = self.safe_str(val)
                    break
        
        return result
    
    def _extract_network_fields(self, event: Dict) -> Dict[str, Any]:
        """Extract network-related fields from various JSON structures"""
        result = {
            'src_ip': None,
            'dst_ip': None,
            'src_port': None,
            'dst_port': None,
            'src_ip_raw': None,
            'dst_ip_raw': None,
        }
        
        # Try ECS structure
        if 'source' in event and isinstance(event.get('source'), dict):
            result['src_ip'], result['src_ip_raw'] = self.normalize_ip_for_storage(
                event['source'].get('ip')
            )
            result['src_port'] = self.safe_int(event['source'].get('port'))
        
        if 'destination' in event and isinstance(event.get('destination'), dict):
            result['dst_ip'], result['dst_ip_raw'] = self.normalize_ip_for_storage(
                event['destination'].get('ip')
            )
            result['dst_port'] = self.safe_int(event['destination'].get('port'))
        
        # Try flat fields as fallback
        if not result['src_ip']:
            for field in ['src_ip', 'source_ip', 'SourceIp', 'SourceIP', 'srcip', 'SrcIP']:
                val = event.get(field)
                if val:
                    result['src_ip'], result['src_ip_raw'] = self.normalize_ip_for_storage(val)
                    if result['src_ip'] or result['src_ip_raw']:
                        break
        
        if not result['dst_ip']:
            for field in ['dst_ip', 'dest_ip', 'destination_ip', 'DestinationIp', 'DestIP', 'dstip']:
                val = event.get(field)
                if val:
                    result['dst_ip'], result['dst_ip_raw'] = self.normalize_ip_for_storage(val)
                    if result['dst_ip'] or result['dst_ip_raw']:
                        break
        
        if not result['src_port']:
            for field in ['src_port', 'source_port', 'SourcePort', 'srcport']:
                val = event.get(field)
                if val is not None:
                    result['src_port'] = self.safe_int(val)
                    if result['src_port']:
                        break
        
        if not result['dst_port']:
            for field in ['dst_port', 'dest_port', 'destination_port', 'DestinationPort', 'dstport']:
                val = event.get(field)
                if val is not None:
                    result['dst_port'] = self.safe_int(val)
                    if result['dst_port']:
                        break
        
        return result
    
    def parse(self, file_path: str) -> Generator[ParsedEvent, None, None]:
        """Parse JSON/NDJSON file with comprehensive field extraction"""
        if not self.can_parse(file_path):
            self.errors.append(f"Cannot parse file: {file_path}")
            return
        
        source_file = os.path.basename(file_path)
        default_hostname = self.extract_hostname(file_path)
        
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
                for ts_field in ['timestamp', '@timestamp', 'time', 'datetime', 'date', 
                                'created_at', 'event_time', 'EventTime', 'Time']:
                    if ts_field in event:
                        timestamp = self.parse_timestamp(event[ts_field])
                        if timestamp:
                            break
                
                if not timestamp:
                    timestamp = self.fallback_timestamp(
                        file_path=file_path,
                        reason='generic json event missing timestamp',
                    )
                
                # Extract all fields for known users/systems discovery
                host = self._extract_host(event, default_hostname)
                username, domain, sid = self._extract_user_fields(event)
                process_fields = self._extract_process_fields(event)
                network_fields = self._extract_network_fields(event)
                
                extra = {}
                if network_fields['src_ip_raw']:
                    extra['src_ip_raw'] = network_fields['src_ip_raw']
                if network_fields['dst_ip_raw']:
                    extra['dst_ip_raw'] = network_fields['dst_ip_raw']

                yield ParsedEvent(
                    case_id=self.case_id,
                    artifact_type=self.artifact_type,
                    timestamp=timestamp,
                    source_file=source_file,
                    source_path=file_path,
                    source_host=host,
                    case_file_id=self.case_file_id,
                    # User fields for known users discovery
                    username=username,
                    domain=domain,
                    sid=sid,
                    # Process fields
                    process_name=process_fields['process_name'],
                    process_path=process_fields['process_path'],
                    process_id=process_fields['process_id'],
                    parent_process=process_fields['parent_process'],
                    parent_pid=process_fields['parent_pid'],
                    command_line=process_fields['command_line'],
                    # Network fields
                    src_ip=network_fields['src_ip'],
                    dst_ip=network_fields['dst_ip'],
                    src_port=network_fields['src_port'],
                    dst_port=network_fields['dst_port'],
                    # Full data
                    raw_json=json.dumps(event, default=str),
                    search_blob=self.build_search_blob(event),
                    extra_fields=json.dumps(extra, default=str),
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
                 case_tz: str = 'UTC', artifact_type_override: str = None, **kwargs):
        super().__init__(case_id, source_host, case_file_id, case_tz=case_tz)
        self._artifact_type = artifact_type_override or self.ARTIFACT_TYPE
    
    @property
    def artifact_type(self) -> str:
        return self._artifact_type

    def _get_row_value(self, row: Dict[str, str], *candidates: str) -> str:
        """Return the first non-empty value for a set of candidate column names."""
        for key, value in row.items():
            key_lower = (key or '').strip().lower()
            if any(candidate in key_lower for candidate in candidates):
                if value and str(value).strip():
                    return str(value).strip()
        return ''

    def _extract_common_fields(self, row: Dict[str, str]) -> Dict[str, Any]:
        """Extract common huntable fields from generic CSV rows."""
        raw_src_ip = self._get_row_value(row, 'src ip', 'src_ip', 'source ip', 'source_ip', 'srcip')
        raw_dst_ip = self._get_row_value(row, 'dst ip', 'dst_ip', 'dest ip', 'dest_ip', 'destination ip', 'destination_ip', 'dstip')
        src_ip, src_ip_raw = self.normalize_ip_for_storage(raw_src_ip)
        dst_ip, dst_ip_raw = self.normalize_ip_for_storage(raw_dst_ip)
        src_port = self.safe_int(self._get_row_value(row, 'src port', 'src_port', 'source port', 'source_port', 'srcport'))
        dst_port = self.safe_int(self._get_row_value(row, 'dst port', 'dst_port', 'dest port', 'dest_port', 'destination port', 'destination_port', 'dstport'))
        return {
            'source_host': self.safe_str(self._get_row_value(row, 'hostname', 'device', 'computer', 'machine', 'host')),
            'username': self.safe_str(self._get_row_value(row, 'username', 'user', 'account name', 'account_name')),
            'domain': self.safe_str(self._get_row_value(row, 'domain')),
            'process_name': self.safe_str(self._get_row_value(row, 'processname', 'process name', 'image', 'filename', 'file name')),
            'command_line': self.safe_str(self._get_row_value(row, 'commandline', 'command line', 'cmdline', 'cmd')),
            'target_path': self.safe_str(self._get_row_value(row, 'path', 'url', 'uri', 'folderpath', 'folder path')),
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_ip_raw': src_ip_raw,
            'dst_ip_raw': dst_ip_raw,
            'src_port': src_port,
            'dst_port': dst_port,
        }
    
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
                            timestamp = self.fallback_timestamp(
                                file_path=file_path,
                                reason='csv log entry missing timestamp',
                            )
                        
                        # Clean empty values
                        clean_row = {k: v for k, v in row.items() if v and v.strip()}
                        common = self._extract_common_fields(clean_row)
                        
                        extra = {
                            'column_count': len(clean_row),
                        }
                        if common['src_ip_raw']:
                            extra['src_ip_raw'] = common['src_ip_raw']
                        if common['dst_ip_raw']:
                            extra['dst_ip_raw'] = common['dst_ip_raw']

                        yield ParsedEvent(
                            case_id=self.case_id,
                            artifact_type=self.artifact_type,
                            timestamp=timestamp,
                            timestamp_source_tz=self.get_source_tz(),  # CSV uses case TZ (ambiguous source)
                            source_file=source_file,
                            source_path=file_path,
                            source_host=common['source_host'] or hostname,
                            case_file_id=self.case_file_id,
                            username=common['username'],
                            domain=common['domain'],
                            process_name=common['process_name'],
                            command_line=common['command_line'],
                            target_path=common['target_path'],
                            src_ip=common['src_ip'],
                            dst_ip=common['dst_ip'],
                            src_port=common['src_port'],
                            dst_port=common['dst_port'],
                            raw_json=json.dumps(clean_row, default=str),
                            search_blob=self.build_search_blob(clean_row),
                            extra_fields=json.dumps(extra, default=str),
                            parser_version=self.parser_version,
                        )
                        
                    except Exception as e:
                        self.warnings.append(f"Error processing row {row_num}: {e}")
                        
        except Exception as e:
            self.errors.append(f"Failed to parse {file_path}: {e}")
            logger.exception(f"CSV parse error: {e}")


class SonicWallCSVParser(BaseParser):
    """Parser for SonicWall firewall CSV export logs
    
    Handles the 51-column CSV format exported from SonicWall appliances.
    Maps all fields to normalized DFIR schema for effective hunting.
    """
    
    VERSION = '1.0.0'
    ARTIFACT_TYPE = 'sonicwall'
    
    # SonicWall CSV column names (must match exactly)
    EXPECTED_COLUMNS = [
        'Time', 'ID', 'Category', 'Group', 'Event', 'Msg. Type', 'Priority',
        'Ether Type', 'Src. MAC', 'Src. Vendor', 'Src. Int.', 'Src. Zone',
        'Dst. MAC', 'Dst. Vendor', 'Dst. Int.', 'Dst. Zone', 'Src. IP',
        'Src. Port', 'Src. Name', 'Src.NAT IP', 'Src.NAT Port', 'In SPI',
        'Dst. IP', 'Dst. Port', 'Dst. Name', 'Dst.NAT IP', 'Dst.NAT Port',
        'Out SPI', 'IP Protocol', 'ICMP Type', 'ICMP Code', 'RX Bytes',
        'TX Bytes', 'Access Rule', 'NAT Policy', 'User Name', 'Session Time',
        'Session Type', 'IDP Rule', 'IDP Priority', 'HTTP OP', 'URL',
        'VPN Policy', 'HTTP Result', 'Block Cat', 'Application', 'FW Action',
        'DPI', 'Notes', 'Message', 'HTTP Referer'
    ]
    
    # Timestamp formats used by SonicWall
    TIMESTAMP_FORMATS = [
        '%m/%d/%Y %H:%M:%S',  # 09/05/2025 06:01:28
        '%Y-%m-%d %H:%M:%S',
        '%m/%d/%y %H:%M:%S',
    ]
    
    def __init__(self, case_id: int, source_host: str = '', case_file_id: Optional[int] = None,
                 case_tz: str = 'UTC', **kwargs):
        super().__init__(case_id, source_host, case_file_id, case_tz=case_tz)
    
    @property
    def artifact_type(self) -> str:
        return self.ARTIFACT_TYPE
    
    def can_parse(self, file_path: str) -> bool:
        """Check if file is a SonicWall CSV export"""
        if not os.path.isfile(file_path):
            return False
        
        if not file_path.lower().endswith('.csv'):
            return False
        
        # Check for SonicWall CSV header signature
        try:
            with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                header = f.readline().strip()
                # Check for key SonicWall columns
                if '"Time"' in header and '"Src. IP"' in header and '"FW Action"' in header:
                    return True
                # Also check unquoted
                if 'Time' in header and 'Src. IP' in header and 'FW Action' in header:
                    return True
        except:
            pass
        
        return False
    
    def parse(self, file_path: str) -> Generator[ParsedEvent, None, None]:
        """Parse SonicWall CSV export"""
        if not self.can_parse(file_path):
            self.errors.append(f"Cannot parse file: {file_path}")
            return
        
        source_file = os.path.basename(file_path)
        hostname = self.extract_hostname(file_path)
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='replace', newline='') as f:
                reader = csv.DictReader(f)
                
                for row_num, row in enumerate(reader, 1):
                    try:
                        event = self._parse_row(row, source_file, file_path, hostname)
                        if event:
                            yield event
                    except Exception as e:
                        self.warnings.append(f"Error processing row {row_num}: {e}")
                        
        except Exception as e:
            self.errors.append(f"Failed to parse {file_path}: {e}")
            logger.exception(f"SonicWall CSV parse error: {e}")
    
    def _parse_row(self, row: Dict[str, str], source_file: str, 
                   file_path: str, hostname: str) -> Optional[ParsedEvent]:
        """Parse a single SonicWall CSV row"""
        
        # Parse timestamp
        time_str = row.get('Time', '').strip()
        timestamp = self.parse_timestamp(time_str, self.TIMESTAMP_FORMATS)
        if not timestamp:
            timestamp = self.fallback_timestamp(
                file_path=file_path,
                reason='sonicwall csv entry missing timestamp',
            )
        
        # ClickHouse stores src/dst IP columns as IPv4 today, so preserve
        # SonicWall IPv6 values in searchable metadata instead of breaking
        # ingestion for otherwise valid firewall exports.
        raw_src_ip = self.safe_str(row.get('Src. IP', '').strip())
        raw_dst_ip = self.safe_str(row.get('Dst. IP', '').strip())
        src_ip = self.validate_ipv4(raw_src_ip)
        dst_ip = self.validate_ipv4(raw_dst_ip)
        
        # Extract ports
        src_port = self.safe_int(row.get('Src. Port', '').strip())
        dst_port = self.safe_int(row.get('Dst. Port', '').strip())
        
        # Extract NAT IPs (store in extra fields and search tokens)
        src_nat_ip = self.safe_str(row.get('Src.NAT IP', '').strip())
        dst_nat_ip = self.safe_str(row.get('Dst.NAT IP', '').strip())
        
        # Username
        username = self.safe_str(row.get('User Name', '').strip())
        
        # Event identification
        event_id = self.safe_str(row.get('ID', '').strip())
        category = self.safe_str(row.get('Category', '').strip())
        event_name = self.safe_str(row.get('Event', '').strip())
        priority = self.safe_str(row.get('Priority', '').strip())
        
        # Firewall action as rule title
        fw_action = self.safe_str(row.get('FW Action', '').strip())
        access_rule = self.safe_str(row.get('Access Rule', '').strip())
        
        # Map priority to rule level
        rule_level = ''
        priority_lower = priority.lower() if priority else ''
        if priority_lower in ('alert', 'critical', 'emergency'):
            rule_level = 'high'
        elif priority_lower in ('warning', 'notice'):
            rule_level = 'med'
        elif priority_lower in ('informational', 'debug'):
            rule_level = 'info'
        
        # Network/Application info
        protocol = self.safe_str(row.get('IP Protocol', '').strip())
        application = self.safe_str(row.get('Application', '').strip())
        url = self.safe_str(row.get('URL', '').strip())
        
        # VPN/IDP
        vpn_policy = self.safe_str(row.get('VPN Policy', '').strip())
        idp_rule = self.safe_str(row.get('IDP Rule', '').strip())
        
        # Message
        message = self.safe_str(row.get('Message', '').strip())
        notes = self.safe_str(row.get('Notes', '').strip())
        
        # Bytes transferred
        rx_bytes = self.safe_int(row.get('RX Bytes', '').strip())
        tx_bytes = self.safe_int(row.get('TX Bytes', '').strip())
        
        # Zone information
        src_zone = self.safe_str(row.get('Src. Zone', '').strip())
        dst_zone = self.safe_str(row.get('Dst. Zone', '').strip())
        
        # Build comprehensive rule title
        rule_title = ''
        if fw_action:
            rule_title = fw_action
        if event_name and event_name != fw_action:
            rule_title = f"{event_name}" if not rule_title else f"{rule_title}: {event_name}"
        
        searchable_src_ip = src_ip or raw_src_ip
        searchable_dst_ip = dst_ip or raw_dst_ip

        # Build search blob with all important fields
        search_parts = [
            time_str,
            event_id,
            category,
            event_name,
            priority,
            searchable_src_ip or '',
            str(src_port) if src_port else '',
            searchable_dst_ip or '',
            str(dst_port) if dst_port else '',
            username,
            protocol,
            application,
            fw_action,
            access_rule,
            url,
            vpn_policy,
            idp_rule,
            message,
            notes,
            src_zone,
            dst_zone,
        ]
        search_blob = ' '.join(str(p) for p in search_parts if p)

        kv_parts = []
        for key, value in (
            ('src_ip', raw_src_ip),
            ('dst_ip', raw_dst_ip),
            ('src_nat_ip', src_nat_ip),
            ('dst_nat_ip', dst_nat_ip),
            ('src_zone', src_zone),
            ('dst_zone', dst_zone),
            ('fw_action', fw_action),
            ('protocol', protocol),
            ('application', application),
            ('user_name', username),
        ):
            if value:
                kv_parts.append(f'{key}:{value}')
        if kv_parts:
            search_blob += ' ' + ' '.join(kv_parts)
        
        # Store all fields in raw_json (clean empty values)
        raw_data = {k: v.strip() for k, v in row.items() if v and v.strip()}
        
        # Extra fields for SonicWall-specific data
        extra = {
            'category': category,
            'group': self.safe_str(row.get('Group', '').strip()),
            'event': event_name,
            'msg_type': self.safe_str(row.get('Msg. Type', '').strip()),
            'priority': priority,
            'protocol': protocol,
            'application': application,
            'fw_action': fw_action,
            'access_rule': access_rule,
            'nat_policy': self.safe_str(row.get('NAT Policy', '').strip()),
            'vpn_policy': vpn_policy,
            'idp_rule': idp_rule,
            'idp_priority': self.safe_str(row.get('IDP Priority', '').strip()),
            'src_zone': src_zone,
            'dst_zone': dst_zone,
            'src_nat_ip': src_nat_ip,
            'dst_nat_ip': dst_nat_ip,
            'src_name': self.safe_str(row.get('Src. Name', '').strip()),
            'dst_name': self.safe_str(row.get('Dst. Name', '').strip()),
            'src_mac': self.safe_str(row.get('Src. MAC', '').strip()),
            'dst_mac': self.safe_str(row.get('Dst. MAC', '').strip()),
            'rx_bytes': rx_bytes,
            'tx_bytes': tx_bytes,
            'session_time': self.safe_str(row.get('Session Time', '').strip()),
            'session_type': self.safe_str(row.get('Session Type', '').strip()),
            'url': url,
            'http_op': self.safe_str(row.get('HTTP OP', '').strip()),
            'http_result': self.safe_str(row.get('HTTP Result', '').strip()),
            'http_referer': self.safe_str(row.get('HTTP Referer', '').strip()),
            'block_cat': self.safe_str(row.get('Block Cat', '').strip()),
            'dpi': self.safe_str(row.get('DPI', '').strip()),
            'notes': notes,
        }
        if raw_src_ip and raw_src_ip != (src_ip or '') and self.validate_ip(raw_src_ip):
            extra['src_ip_raw'] = raw_src_ip
        if raw_dst_ip and raw_dst_ip != (dst_ip or '') and self.validate_ip(raw_dst_ip):
            extra['dst_ip_raw'] = raw_dst_ip
        # Remove empty values
        extra = {k: v for k, v in extra.items() if v}
        
        return ParsedEvent(
            case_id=self.case_id,
            artifact_type=self.artifact_type,
            timestamp=timestamp,
            timestamp_source_tz=self.get_source_tz(),  # Sonicwall uses case TZ (ambiguous source)
            source_file=source_file,
            source_path=file_path,
            source_host=hostname,
            case_file_id=self.case_file_id,
            event_id=event_id,
            channel=category,
            level=rule_level,
            username=username,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            target_path=url,
            rule_title=rule_title,
            rule_level=rule_level,
            raw_json=json.dumps(raw_data, default=str),
            search_blob=search_blob,
            extra_fields=json.dumps(extra, default=str),
            parser_version=self.parser_version,
        )
