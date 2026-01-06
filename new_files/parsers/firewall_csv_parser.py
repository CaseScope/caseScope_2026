"""
Firewall CSV Parser
Parses firewall logs in CSV format (SonicWall, etc.) and creates search blobs for comprehensive searching
"""

import logging
import csv
import re
from datetime import datetime
from typing import Iterator, Dict, Any, Optional, List
from pathlib import Path

# Import normalization - handle both Flask and Celery contexts
try:
    from app.utils.event_normalization import normalize_event
except ImportError:
    from utils.event_normalization import normalize_event

logger = logging.getLogger(__name__)


def detect_csv_source_type(headers: List[str]) -> Optional[str]:
    """
    Detect the source type of CSV file based on headers
    
    Args:
        headers: List of CSV column headers
        
    Returns:
        str: Source type identifier ('sonicwall_csv', 'firewall_csv', etc.) or None
    """
    headers_str = '|'.join(headers).lower()
    
    # SonicWall signature: specific field combination
    if ('src. ip' in headers_str and 'dst. ip' in headers_str and 
        'fw action' in headers_str and 'src. mac' in headers_str):
        return 'sonicwall_csv'
    
    # Generic firewall: has source/dest IPs and action
    if (('source' in headers_str or 'src' in headers_str) and
        ('destination' in headers_str or 'dst' in headers_str) and
        ('action' in headers_str or 'policy' in headers_str)):
        return 'firewall_csv'
    
    return None


def normalize_field_name(field_name: str) -> str:
    """
    Normalize CSV field name to snake_case
    
    Examples:
        "Src. IP" -> "src_ip"
        "Src.NAT IP" -> "src_nat_ip"
        "HTTP Referer" -> "http_referer"
        
    Args:
        field_name: Original field name from CSV header
        
    Returns:
        Normalized field name in snake_case
    """
    # Remove quotes and extra spaces
    field_name = field_name.strip(' "')
    
    # Replace dots with spaces (e.g., "Src. IP" -> "Src IP")
    field_name = field_name.replace('.', ' ')
    
    # Convert to lowercase
    field_name = field_name.lower()
    
    # Replace spaces and special chars with underscores
    field_name = re.sub(r'[^\w]+', '_', field_name)
    
    # Remove duplicate underscores
    field_name = re.sub(r'_+', '_', field_name)
    
    # Remove leading/trailing underscores
    field_name = field_name.strip('_')
    
    # CRITICAL: Avoid OpenSearch mapping conflicts with EVTX fields
    # Rename fields that conflict with existing object-type mappings
    if field_name == 'event':
        field_name = 'fw_event'  # "Event" column becomes "fw_event"
    
    return field_name


def normalize_field_value(field_name: str, value: str) -> Any:
    """
    Normalize field value based on field type
    
    Args:
        field_name: Normalized field name
        value: Raw field value from CSV
        
    Returns:
        Normalized value (str, int, None)
    """
    # Strip whitespace
    value = value.strip()
    
    # Convert empty string to None
    if not value or value == '':
        return None
    
    # Convert "0.0.0.0" to None (special empty value for IPs)
    if value == '0.0.0.0' or value == '0':
        # Keep 0.0.0.0 for NAT IPs (context matters), but convert "0" ports to None
        if 'port' in field_name and value == '0':
            return None
        elif value == '0.0.0.0':
            return None
    
    # Convert numeric fields to integers
    numeric_fields = {
        'id', 'ether_type', 'src_port', 'dst_port', 'src_nat_port', 'dst_nat_port',
        'in_spi', 'out_spi', 'icmp_type', 'icmp_code', 'rx_bytes', 'tx_bytes',
        'idp_priority', 'session_time'
    }
    
    if field_name in numeric_fields:
        try:
            return int(value)
        except (ValueError, TypeError):
            return value  # Keep as string if conversion fails
    
    return value


def parse_timestamp(timestamp_str: str) -> str:
    """
    Parse timestamp string to ISO 8601 format
    
    Args:
        timestamp_str: Timestamp string (e.g., "11/21/2025 02:33:05")
        
    Returns:
        ISO 8601 formatted timestamp string
    """
    try:
        # MM/DD/YYYY HH:MM:SS format (SonicWall)
        dt = datetime.strptime(timestamp_str, '%m/%d/%Y %H:%M:%S')
        return dt.isoformat() + 'Z'
    except ValueError:
        try:
            # Try other common formats
            formats = [
                '%Y-%m-%d %H:%M:%S',    # YYYY-MM-DD HH:MM:SS
                '%d/%m/%Y %H:%M:%S',    # DD/MM/YYYY HH:MM:SS
                '%m/%d/%Y %H:%M',       # MM/DD/YYYY HH:MM
            ]
            for fmt in formats:
                try:
                    dt = datetime.strptime(timestamp_str, fmt)
                    return dt.isoformat() + 'Z'
                except ValueError:
                    continue
        except Exception:
            pass
    
    # Fallback: return as-is if unable to parse
    logger.warning(f"Could not parse timestamp: {timestamp_str}")
    return timestamp_str


def extract_ips_from_event(event: Dict[str, Any]) -> List[str]:
    """
    Extract all IP addresses from event for IOC hunting
    
    Args:
        event: Parsed event dictionary
        
    Returns:
        List of unique IP addresses (excluding 0.0.0.0, None)
    """
    ips = []
    
    # Direct IP fields
    ip_fields = ['src_ip', 'dst_ip', 'src_nat_ip', 'dst_nat_ip']
    for field in ip_fields:
        ip = event.get(field)
        if ip and ip not in ('0.0.0.0', None):
            ips.append(ip)
    
    # Extract IPs from message field using regex
    message = event.get('message', '')
    if message:
        # Match IPv4 addresses (basic pattern)
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        found_ips = re.findall(ip_pattern, str(message))
        for ip in found_ips:
            # Validate it's not 0.0.0.0 and looks reasonable
            if ip != '0.0.0.0' and not ip.startswith('0.'):
                ips.append(ip)
    
    # Return unique IPs
    return list(set(ips))


def extract_country_from_message(message: str) -> Optional[Dict[str, str]]:
    """
    Extract blocked country information from message field
    
    Example message:
        "Initiator from country blocked: Initiator IP:91.218.122.249 Country Name:Ukraine"
        
    Args:
        message: Message text from event
        
    Returns:
        Dict with country, ip, and direction or None
    """
    if not message:
        return None
    
    # Pattern: "Country Name:COUNTRY_NAME"
    country_match = re.search(r'Country Name:([^,\n]+)', message)
    if not country_match:
        return None
    
    country = country_match.group(1).strip()
    
    # Extract associated IP
    ip_match = re.search(r'IP:(\d+\.\d+\.\d+\.\d+)', message)
    ip = ip_match.group(1) if ip_match else None
    
    # Determine direction
    direction = None
    if 'Initiator' in message:
        direction = 'initiator'
    elif 'Responder' in message:
        direction = 'responder'
    
    return {
        'country': country,
        'ip': ip,
        'direction': direction
    }


def create_search_blob(event: Dict[str, Any]) -> str:
    """
    Create flattened search blob from ALL event data
    
    Recursively extracts all text from nested structures for IOC/keyword searching.
    Follows same pattern as EVTX and NDJSON parsers.
    
    Args:
        event: Original event dictionary
        
    Returns:
        Flattened, normalized text string for searching
    """
    # Fields to EXCLUDE from search_blob (metadata that shouldn't be searched)
    EXCLUDE_FIELDS = {
        'has_sigma', 'has_ioc', 'ioc_count', 'ioc_details', 'matched_iocs',
        'file_id', 'source_file', 'opensearch_key', 'case_id',
        'search_blob',  # Don't include ourselves
        'indexed_at',
        'extracted_ips',  # Don't duplicate IPs
        'geo_data',  # Don't duplicate geo data
    }
    
    def extract_text(obj: Any, depth: int = 0) -> str:
        """Recursively extract text from nested structures"""
        # Prevent infinite recursion
        if depth > 20:
            return ""
        
        if isinstance(obj, dict):
            # Extract from all dict values (except excluded fields)
            texts = []
            for key, value in obj.items():
                # Skip excluded fields
                if key in EXCLUDE_FIELDS:
                    continue
                
                # Recursively extract from value
                text = extract_text(value, depth=depth + 1)
                if text:
                    texts.append(text)
            return ' '.join(texts)
        
        elif isinstance(obj, (list, tuple)):
            # Extract from all list items
            texts = []
            for item in obj:
                text = extract_text(item, depth=depth + 1)
                if text:
                    texts.append(text)
            return ' '.join(texts)
        
        elif isinstance(obj, bool):
            return ""  # Skip boolean values
        
        elif obj is not None:
            # Convert to string and normalize line breaks
            text = str(obj)
            # Replace line breaks with spaces
            text = text.replace('\\r\\n', ' ').replace('\\n', ' ').replace('\\r', ' ')
            text = text.replace('\r\n', ' ').replace('\n', ' ').replace('\r', ' ')
            return text
        
        else:
            return ""
    
    # Extract from entire event
    search_blob = extract_text(event, depth=0)
    
    # Collapse multiple spaces to single space
    search_blob = ' '.join(search_blob.split())
    
    # Limit size to prevent huge blobs (100KB max)
    if len(search_blob) > 100000:
        search_blob = search_blob[:100000]
    
    return search_blob


def normalize_firewall_event(event: Dict[str, Any], log_source_type: str) -> Dict[str, Any]:
    """
    Normalize firewall event with standardized fields
    
    Adds:
    - normalized_timestamp: Standardized timestamp field
    - normalized_source_ip: Source IP
    - normalized_dest_ip: Destination IP
    - normalized_event_id: Event ID (from 'id' or 'event' field)
    - search_blob: Flattened searchable text
    - extracted_ips: Array of all IPs for IOC hunting
    - geo_data: Country/geo information if present
    - log_source_type: Detected source type
    
    Args:
        event: Original parsed event
        log_source_type: Detected log source type
        
    Returns:
        Normalized event with search blob
    """
    # Add log source type
    event['log_source_type'] = log_source_type
    event['file_type'] = log_source_type
    
    # Use comprehensive normalization (handles timestamp, computer, event_id)
    event = normalize_event(event)
    
    # Firewall-specific normalizations
    # Normalize source/dest IPs
    src_ip = event.get('src_ip')
    if src_ip:
        event['normalized_source_ip'] = src_ip
    
    dst_ip = event.get('dst_ip')
    if dst_ip:
        event['normalized_dest_ip'] = dst_ip
    
    # Extract all IPs for IOC hunting
    extracted_ips = extract_ips_from_event(event)
    if extracted_ips:
        event['extracted_ips'] = extracted_ips
    
    # Extract geo/country data from message
    message = event.get('message')
    if message:
        geo_data = extract_country_from_message(message)
        if geo_data:
            event['geo_data'] = geo_data
            event['geo_blocked_country'] = geo_data.get('country')
            event['geo_blocked_ip'] = geo_data.get('ip')
            event['geo_block_direction'] = geo_data.get('direction')
    
    # Create search blob for comprehensive searching
    search_blob = create_search_blob(event)
    if search_blob:
        event['search_blob'] = search_blob
    
    return event


def parse_firewall_csv(file_path: str) -> Iterator[Dict[str, Any]]:
    """
    Parse firewall CSV file and yield normalized events
    
    Args:
        file_path: Path to CSV file
        
    Yields:
        dict: Normalized event data with search blob
    """
    event_count = 0
    error_count = 0
    log_source_type = None
    
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            # Use csv.DictReader for reliable CSV parsing
            reader = csv.DictReader(f)
            
            # Detect source type from headers
            if reader.fieldnames:
                log_source_type = detect_csv_source_type(reader.fieldnames)
                if not log_source_type:
                    log_source_type = 'firewall_csv'  # Generic fallback
                
                logger.info(f"Detected log source type: {log_source_type}")
                logger.info(f"Found {len(reader.fieldnames)} columns")
            
            for row_num, row in enumerate(reader, start=1):
                try:
                    # Normalize field names and values
                    event = {}
                    for field_name, value in row.items():
                        # Normalize field name
                        normalized_name = normalize_field_name(field_name)
                        
                        # Normalize field value
                        normalized_value = normalize_field_value(normalized_name, value)
                        
                        # Only include non-None values
                        if normalized_value is not None:
                            event[normalized_name] = normalized_value
                    
                    # Add row number for tracking
                    event['row_number'] = row_num
                    
                    # Normalize event (adds search_blob, normalized fields, extracts IPs)
                    event = normalize_firewall_event(event, log_source_type)
                    
                    event_count += 1
                    yield event
                    
                except Exception as e:
                    error_count += 1
                    logger.error(f"Error processing row {row_num}: {e}")
                    continue
        
        logger.info(f"Parsed {event_count} events from {Path(file_path).name} ({error_count} errors)")
        
    except Exception as e:
        logger.error(f"Error reading CSV file {file_path}: {e}")
        raise


def get_firewall_csv_metadata(file_path: str) -> Dict[str, Any]:
    """
    Get metadata about firewall CSV file
    
    Args:
        file_path: Path to CSV file
        
    Returns:
        dict: Metadata including event count, file size, etc.
    """
    import os
    
    metadata = {
        'file_path': file_path,
        'file_name': Path(file_path).name,
        'file_size': os.path.getsize(file_path),
        'event_count': 0,
        'log_source_type': None,
        'source_ips': set(),
        'dest_ips': set(),
        'countries': set(),
        'actions': set(),
    }
    
    try:
        for event in parse_firewall_csv(file_path):
            metadata['event_count'] += 1
            
            # Capture log source type
            if not metadata['log_source_type']:
                metadata['log_source_type'] = event.get('log_source_type')
            
            # Sample source IPs
            if event.get('src_ip'):
                metadata['source_ips'].add(event['src_ip'])
            
            # Sample dest IPs
            if event.get('dst_ip'):
                metadata['dest_ips'].add(event['dst_ip'])
            
            # Sample countries
            if event.get('geo_blocked_country'):
                metadata['countries'].add(event['geo_blocked_country'])
            
            # Sample actions
            if event.get('fw_action'):
                metadata['actions'].add(event['fw_action'])
        
        # Convert sets to lists for JSON serialization
        metadata['source_ips'] = list(metadata['source_ips'])[:10]  # Limit to 10 samples
        metadata['dest_ips'] = list(metadata['dest_ips'])[:10]
        metadata['countries'] = list(metadata['countries'])
        metadata['actions'] = list(metadata['actions'])
        
    except Exception as e:
        logger.error(f"Error getting metadata: {e}")
        metadata['error'] = str(e)
    
    return metadata

