"""Sigma Rule Converter for CaseScope

Converts Sigma detection rules from various sources into CaseScope
AttackPattern format with executable ClickHouse queries.

Supports:
- SigmaHQ GitHub rules
- Hayabusa rules
- mdecrevoisier rules
- MITRE CAR analytics
- OpenCTI Sigma indicators
"""

import re
import yaml
import logging
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)


class SigmaToPatternConverter:
    """Convert Sigma rules to CaseScope executable patterns with ClickHouse queries"""
    
    # Map Sigma field names to ClickHouse column names
    FIELD_MAP = {
        # Standard fields
        'EventID': 'event_id',
        'event_id': 'event_id',
        'Channel': 'channel',
        'channel': 'channel',
        'Provider_Name': 'provider',
        'provider_name': 'provider',
        
        # User/Account fields
        'TargetUserName': 'username',
        'SubjectUserName': 'username',
        'UserName': 'username',
        'User': 'username',
        'AccountName': 'username',
        
        # Host fields
        'ComputerName': 'source_host',
        'Computer': 'source_host',
        'Hostname': 'source_host',
        'WorkstationName': 'source_host',
        
        # Network fields
        'IpAddress': 'src_ip',
        'SourceAddress': 'src_ip',
        'SourceIp': 'src_ip',
        'DestinationIp': 'dst_ip',
        'DestinationAddress': 'dst_ip',
        'SourcePort': 'src_port',
        'DestinationPort': 'dst_port',
        
        # Process fields
        'Image': 'process_name',
        'ProcessName': 'process_name',
        'NewProcessName': 'process_name',
        'ParentImage': 'parent_process',
        'ParentProcessName': 'parent_process',
        'CommandLine': 'command_line',
        'ParentCommandLine': 'parent_command_line',
        'ProcessId': 'process_id',
        'ParentProcessId': 'parent_process_id',
        
        # Logon fields
        'LogonType': 'logon_type',
        'LogonProcessName': 'logon_process',
        'AuthenticationPackageName': 'auth_package',
        'Status': 'status',
        'SubStatus': 'sub_status',
        'FailureReason': 'failure_reason',
        
        # Service fields
        'ServiceName': 'service_name',
        'ServiceFileName': 'service_path',
        'ServiceType': 'service_type',
        'StartType': 'start_type',
        
        # Task Scheduler
        'TaskName': 'task_name',
        'TaskContent': 'task_content',
        
        # Registry
        'TargetObject': 'registry_key',
        'ObjectName': 'object_name',
        'Details': 'registry_value',
        
        # File
        'TargetFilename': 'file_path',
        'FileName': 'file_name',
        
        # Hash
        'Hashes': 'hashes',
        'md5': 'md5',
        'sha1': 'sha1',
        'sha256': 'sha256',
    }
    
    # Severity mapping
    LEVEL_MAP = {
        'critical': 'critical',
        'high': 'high',
        'medium': 'medium',
        'low': 'low',
        'informational': 'low',
        'info': 'low',
    }
    
    # Confidence weight by severity
    CONFIDENCE_MAP = {
        'critical': 0.95,
        'high': 0.85,
        'medium': 0.70,
        'low': 0.50,
    }
    
    def convert_sigma_rule(self, sigma_yaml: str, source: str = 'sigma') -> Optional[Dict[str, Any]]:
        """
        Convert a single Sigma rule to CaseScope pattern format.
        
        Args:
            sigma_yaml: Raw YAML content of the Sigma rule
            source: Source identifier (sigma, hayabusa, mdecrevoisier, etc.)
            
        Returns:
            Dict with pattern data or None if conversion failed
        """
        try:
            rule = yaml.safe_load(sigma_yaml)
            if not rule:
                return None
            
            # Skip non-Windows or non-applicable rules
            logsource = rule.get('logsource', {})
            product = logsource.get('product', '').lower()
            if product and product not in ['windows', '']:
                return None
            
            # Extract detection logic
            detection = rule.get('detection', {})
            if not detection:
                logger.debug(f"Rule {rule.get('title', 'unknown')} has no detection block")
                return None
            
            # Get event IDs and channels
            event_ids = self._extract_event_ids(detection)
            channels = self._extract_channels(detection, logsource)
            
            # Build the ClickHouse query
            clickhouse_query = self._build_clickhouse_query(detection, event_ids, channels)
            
            # Extract MITRE info from tags
            tags = rule.get('tags', [])
            mitre_tactic = self._extract_tactic(tags)
            mitre_technique = self._extract_technique(tags)
            
            # Determine severity
            level = rule.get('level', 'medium').lower()
            severity = self.LEVEL_MAP.get(level, 'medium')
            confidence = self.CONFIDENCE_MAP.get(severity, 0.70)
            
            # Parse timeframe
            timeframe = rule.get('timeframe')
            time_window = self._parse_timeframe(timeframe) if timeframe else 60
            
            # Determine pattern type
            condition = detection.get('condition', '')
            if 'count' in condition.lower() or timeframe:
                pattern_type = 'aggregation'
            elif len(self._get_selection_keys(detection)) > 1:
                pattern_type = 'sequence'
            else:
                pattern_type = 'single'
            
            pattern = {
                'name': rule.get('title', 'Unnamed Rule'),
                'description': rule.get('description', ''),
                'mitre_tactic': mitre_tactic,
                'mitre_technique': mitre_technique,
                'source': source,
                'source_id': rule.get('id'),
                'source_url': rule.get('references', [None])[0] if rule.get('references') else None,
                'pattern_type': pattern_type,
                'severity': severity,
                'confidence_weight': confidence,
                'time_window_minutes': time_window,
                'required_event_ids': event_ids if event_ids else None,
                'required_channels': channels if channels else None,
                'pattern_definition': {
                    'type': pattern_type,
                    'condition': condition,
                    'detection': self._sanitize_detection(detection),
                    'sigma_level': level,
                    'sigma_status': rule.get('status', 'experimental'),
                    'false_positives': rule.get('falsepositives', []),
                },
                'clickhouse_query': clickhouse_query,
                'enabled': True,
                'created_by': f'{source}_import',
            }
            
            return pattern
            
        except yaml.YAMLError as e:
            logger.warning(f"YAML parse error: {e}")
            return None
        except Exception as e:
            logger.warning(f"Sigma conversion error: {e}")
            return None
    
    def _extract_event_ids(self, detection: Dict) -> List[str]:
        """Extract all event IDs from detection block"""
        event_ids = set()
        
        def find_event_ids(obj):
            if isinstance(obj, dict):
                for key, value in obj.items():
                    if key.lower() in ('eventid', 'event_id'):
                        if isinstance(value, list):
                            event_ids.update(str(v) for v in value)
                        else:
                            event_ids.add(str(value))
                    else:
                        find_event_ids(value)
            elif isinstance(obj, list):
                for item in obj:
                    find_event_ids(item)
        
        find_event_ids(detection)
        return sorted(list(event_ids))
    
    def _extract_channels(self, detection: Dict, logsource: Dict) -> List[str]:
        """Extract channels from detection or logsource"""
        channels = set()
        
        # Check logsource service mapping
        service = logsource.get('service', '').lower()
        service_map = {
            'security': 'Security',
            'system': 'System',
            'application': 'Application',
            'sysmon': 'Microsoft-Windows-Sysmon/Operational',
            'powershell': 'Microsoft-Windows-PowerShell/Operational',
            'powershell-classic': 'Windows PowerShell',
            'taskscheduler': 'Microsoft-Windows-TaskScheduler/Operational',
            'dns-server': 'DNS Server',
            'firewall-as': 'Microsoft-Windows-Windows Firewall With Advanced Security/Firewall',
        }
        if service in service_map:
            channels.add(service_map[service])
        
        # Check detection block for Channel field
        def find_channels(obj):
            if isinstance(obj, dict):
                for key, value in obj.items():
                    if key.lower() == 'channel':
                        if isinstance(value, list):
                            channels.update(value)
                        else:
                            channels.add(value)
                    else:
                        find_channels(value)
            elif isinstance(obj, list):
                for item in obj:
                    find_channels(item)
        
        find_channels(detection)
        return sorted(list(channels))
    
    def _build_clickhouse_query(self, detection: Dict, event_ids: List[str], channels: List[str]) -> Optional[str]:
        """Build a ClickHouse query from detection logic"""
        
        # Get all selection blocks
        selections = {}
        filters = {}
        condition = detection.get('condition', 'selection')
        
        for key, value in detection.items():
            if key == 'condition':
                continue
            if key.startswith('filter') or key.startswith('exclude'):
                filters[key] = value
            elif isinstance(value, dict):
                selections[key] = value
        
        if not selections:
            return None
        
        # Build WHERE clauses
        where_clauses = []
        
        # Add case_id parameter
        where_clauses.append("case_id = {case_id:UInt32}")
        
        # Add event ID filter if available
        if event_ids:
            if len(event_ids) == 1:
                where_clauses.append(f"event_id = '{event_ids[0]}'")
            else:
                ids_str = "', '".join(event_ids)
                where_clauses.append(f"event_id IN ('{ids_str}')")
        
        # Add channel filter if available
        if channels:
            if len(channels) == 1:
                where_clauses.append(f"channel = '{channels[0]}'")
            else:
                ch_str = "', '".join(channels)
                where_clauses.append(f"channel IN ('{ch_str}')")
        
        # Build field conditions from first selection
        first_selection = list(selections.values())[0] if selections else {}
        field_conditions = self._build_field_conditions(first_selection)
        where_clauses.extend(field_conditions)
        
        # Add filter exclusions
        for filter_block in filters.values():
            exclusions = self._build_exclusion_conditions(filter_block)
            where_clauses.extend(exclusions)
        
        # Handle aggregation in condition
        if 'count' in condition.lower():
            return self._build_aggregation_query(where_clauses, condition, first_selection)
        
        # Standard query
        where_str = "\n              AND ".join(where_clauses)
        
        query = f"""
            SELECT source_host, timestamp, event_id, channel, username,
                   process_name, command_line, search_blob
            FROM events
            WHERE {where_str}
            ORDER BY timestamp
            LIMIT 100
        """
        
        return query.strip()
    
    def _build_field_conditions(self, selection: Dict) -> List[str]:
        """Build WHERE conditions from selection fields"""
        conditions = []
        
        for sigma_field, value in selection.items():
            # Skip event_id and channel (handled separately)
            if sigma_field.lower() in ('eventid', 'event_id', 'channel'):
                continue
            
            ch_field = self.FIELD_MAP.get(sigma_field, sigma_field.lower())
            
            if isinstance(value, list):
                # Multiple values - use IN or LIKE
                if any('*' in str(v) or '?' in str(v) for v in value):
                    # Contains wildcards - use search_blob
                    patterns = []
                    for v in value:
                        clean = str(v).replace('*', '').replace('?', '')
                        if clean:
                            patterns.append(f"search_blob ILIKE '%{clean}%'")
                    if patterns:
                        conditions.append(f"({' OR '.join(patterns)})")
                else:
                    vals = "', '".join(str(v) for v in value)
                    conditions.append(f"{ch_field} IN ('{vals}')")
            elif isinstance(value, str):
                if '*' in value or '?' in value:
                    # Wildcard - search in search_blob
                    clean = value.replace('*', '').replace('?', '')
                    if clean:
                        conditions.append(f"search_blob ILIKE '%{clean}%'")
                elif '|' in value:
                    # Sigma modifier like 'contains|all'
                    conditions.append(f"search_blob ILIKE '%{value.split('|')[0]}%'")
                else:
                    conditions.append(f"{ch_field} = '{value}'")
            elif isinstance(value, (int, float)):
                conditions.append(f"{ch_field} = {value}")
        
        return conditions
    
    def _build_exclusion_conditions(self, filter_block: Dict) -> List[str]:
        """Build NOT conditions from filter block"""
        conditions = []
        
        for sigma_field, value in filter_block.items():
            ch_field = self.FIELD_MAP.get(sigma_field, sigma_field.lower())
            
            if isinstance(value, list):
                vals = "', '".join(str(v) for v in value)
                conditions.append(f"{ch_field} NOT IN ('{vals}')")
            elif value == '-' or value == '':
                conditions.append(f"({ch_field} IS NOT NULL AND {ch_field} != '')")
            else:
                conditions.append(f"{ch_field} != '{value}'")
        
        return conditions
    
    def _build_aggregation_query(self, base_conditions: List[str], condition: str, selection: Dict) -> str:
        """Build aggregation query for count-based rules"""
        
        # Parse condition like "selection | count() by IpAddress > 5"
        match = re.search(r'count\(\s*\)\s*(?:by\s+(\w+))?\s*([><=]+)\s*(\d+)', condition, re.I)
        
        group_by = 'source_host'
        operator = '>='
        threshold = 5
        
        if match:
            group_by_field = match.group(1)
            if group_by_field:
                group_by = self.FIELD_MAP.get(group_by_field, group_by_field.lower())
            operator = match.group(2)
            threshold = int(match.group(3))
        
        where_str = "\n              AND ".join(base_conditions)
        
        query = f"""
            SELECT {group_by}, count() as event_count,
                   min(timestamp) as first_seen, max(timestamp) as last_seen,
                   groupArray(10)(event_id) as sample_event_ids
            FROM events
            WHERE {where_str}
            GROUP BY {group_by}
            HAVING count() {operator} {threshold}
            ORDER BY event_count DESC
            LIMIT 100
        """
        
        return query.strip()
    
    def _get_selection_keys(self, detection: Dict) -> List[str]:
        """Get selection block keys (excluding condition and filters)"""
        return [k for k in detection.keys() 
                if k != 'condition' and not k.startswith('filter') and isinstance(detection[k], dict)]
    
    def _sanitize_detection(self, detection: Dict) -> Dict:
        """Sanitize detection block for JSON storage"""
        sanitized = {}
        for key, value in detection.items():
            if isinstance(value, dict):
                sanitized[key] = self._sanitize_detection(value)
            elif isinstance(value, list):
                sanitized[key] = [str(v) if not isinstance(v, (dict, list, str, int, float, bool, type(None))) else v for v in value]
            else:
                sanitized[key] = value
        return sanitized
    
    def _parse_timeframe(self, timeframe: str) -> int:
        """Parse Sigma timeframe to minutes"""
        if not timeframe:
            return 60
        
        tf = str(timeframe).lower().strip()
        
        match = re.match(r'(\d+)\s*(s|m|h|d)', tf)
        if match:
            value = int(match.group(1))
            unit = match.group(2)
            
            if unit == 's':
                return max(1, value // 60)
            elif unit == 'm':
                return value
            elif unit == 'h':
                return value * 60
            elif unit == 'd':
                return value * 1440
        
        return 60
    
    def _extract_tactic(self, tags: List[str]) -> Optional[str]:
        """Extract MITRE tactic from Sigma tags"""
        tactic_map = {
            'reconnaissance': 'Reconnaissance',
            'resource_development': 'Resource Development',
            'initial_access': 'Initial Access',
            'execution': 'Execution',
            'persistence': 'Persistence',
            'privilege_escalation': 'Privilege Escalation',
            'defense_evasion': 'Defense Evasion',
            'credential_access': 'Credential Access',
            'discovery': 'Discovery',
            'lateral_movement': 'Lateral Movement',
            'collection': 'Collection',
            'command_and_control': 'Command and Control',
            'exfiltration': 'Exfiltration',
            'impact': 'Impact',
        }
        
        for tag in tags:
            tag_lower = tag.lower().replace('attack.', '')
            if tag_lower in tactic_map:
                return tactic_map[tag_lower]
        
        return None
    
    def _extract_technique(self, tags: List[str]) -> Optional[str]:
        """Extract MITRE technique ID from Sigma tags"""
        for tag in tags:
            if tag.lower().startswith('attack.t'):
                return tag.replace('attack.', '').upper()
        return None


def convert_sigma_file(filepath: str, source: str = 'sigma') -> Optional[Dict[str, Any]]:
    """Convenience function to convert a Sigma rule file"""
    converter = SigmaToPatternConverter()
    
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
        return converter.convert_sigma_rule(content, source)
    except Exception as e:
        logger.warning(f"Failed to convert {filepath}: {e}")
        return None


def convert_sigma_directory(directory: str, source: str = 'sigma') -> List[Dict[str, Any]]:
    """Convert all Sigma rules in a directory"""
    import os
    
    converter = SigmaToPatternConverter()
    patterns = []
    
    for root, dirs, files in os.walk(directory):
        for filename in files:
            if filename.endswith(('.yml', '.yaml')):
                filepath = os.path.join(root, filename)
                try:
                    with open(filepath, 'r', encoding='utf-8') as f:
                        content = f.read()
                    
                    pattern = converter.convert_sigma_rule(content, source)
                    if pattern and pattern.get('required_event_ids'):
                        patterns.append(pattern)
                        
                except Exception as e:
                    logger.debug(f"Skipped {filename}: {e}")
    
    return patterns
