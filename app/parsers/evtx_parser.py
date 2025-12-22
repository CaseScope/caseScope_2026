"""
EVTX File Parser
Fast EVTX parsing using Rust-based evtx library
"""

import logging
import json
from datetime import datetime
from typing import Iterator, Dict, Any
from pathlib import Path

logger = logging.getLogger(__name__)

try:
    from evtx import PyEvtxParser
    EVTX_AVAILABLE = True
except ImportError:
    EVTX_AVAILABLE = False
    logger.warning("evtx library not available - EVTX parsing will not work")


class EVTXParser:
    """
    Fast EVTX parser using Rust-based library
    """
    
    def __init__(self, file_path: str):
        """
        Initialize parser
        
        Args:
            file_path: Path to EVTX file
        """
        if not EVTX_AVAILABLE:
            raise ImportError("evtx library not installed. Install with: pip install evtx")
        
        self.file_path = file_path
        self.parser = None
        
    def __enter__(self):
        """Context manager entry"""
        self.parser = PyEvtxParser(self.file_path)
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        # Parser automatically cleans up
        pass
    
    def parse(self) -> Iterator[Dict[str, Any]]:
        """
        Parse EVTX file and yield events
        
        Yields:
            dict: Parsed event data
        """
        if not self.parser:
            raise RuntimeError("Parser not initialized. Use context manager (with statement)")
        
        import xml.etree.ElementTree as ET
        
        event_count = 0
        
        for record in self.parser.records():
            try:
                # Get the record data (XML string)
                xml_data = record.get('data', '')
                
                if not xml_data:
                    continue
                
                # Parse XML
                root = ET.fromstring(xml_data)
                
                # Get timestamp and convert to ISO format
                timestamp_str = str(record.get('timestamp', ''))
                # Parse format: "2025-11-22 22:01:06.327821 UTC" -> ISO format
                try:
                    from datetime import datetime
                    # Remove ' UTC' and parse
                    ts_clean = timestamp_str.replace(' UTC', '')
                    dt = datetime.fromisoformat(ts_clean)
                    timestamp_iso = dt.isoformat() + 'Z'  # Add Z for UTC
                except Exception as e:
                    timestamp_iso = timestamp_str
                
                # Build event dictionary
                event = {
                    'event_record_id': record.get('event_record_id'),
                    'timestamp': timestamp_iso,
                    'is_from_hidden_file': False  # Files with events are NOT hidden
                }
                
                # Define namespace
                ns = {'': 'http://schemas.microsoft.com/win/2004/08/events/event'}
                
                # Extract System section
                system = root.find('System', ns)
                if system is not None:
                    # Event ID
                    event_id_elem = system.find('EventID', ns)
                    if event_id_elem is not None:
                        event['event_id'] = event_id_elem.text
                    
                    # Computer
                    computer_elem = system.find('Computer', ns)
                    if computer_elem is not None:
                        event['computer'] = computer_elem.text
                    
                    # Channel
                    channel_elem = system.find('Channel', ns)
                    if channel_elem is not None:
                        event['channel'] = channel_elem.text
                    
                    # Provider
                    provider_elem = system.find('Provider', ns)
                    if provider_elem is not None:
                        event['provider_name'] = provider_elem.get('Name')
                    
                    # Level
                    level_elem = system.find('Level', ns)
                    if level_elem is not None:
                        event['level'] = level_elem.text
                    
                    # TimeCreated
                    time_elem = system.find('TimeCreated', ns)
                    if time_elem is not None:
                        event['system_time'] = time_elem.get('SystemTime')
                
                # Extract EventData section
                event_data = root.find('EventData', ns)
                if event_data is not None:
                    event_data_fields = {}
                    for data_elem in event_data.findall('Data', ns):
                        name = data_elem.get('Name')
                        value = data_elem.text or ''
                        if name:
                            event_data_fields[name] = value
                    
                    if event_data_fields:
                        event['event_data_fields'] = event_data_fields
                
                # Store raw XML for reference
                event['raw_xml'] = xml_data
                
                event_count += 1
                yield event
                
            except ET.ParseError as e:
                logger.error(f"Failed to parse event XML: {e}")
                continue
            except Exception as e:
                logger.error(f"Error processing event: {e}")
                continue
        
        logger.info(f"Parsed {event_count} events from {Path(self.file_path).name}")


def parse_evtx_file(file_path: str) -> Iterator[Dict[str, Any]]:
    """
    Parse EVTX file and yield events
    
    Args:
        file_path: Path to EVTX file
    
    Yields:
        dict: Parsed event data
    """
    with EVTXParser(file_path) as parser:
        yield from parser.parse()


def get_evtx_metadata(file_path: str) -> Dict[str, Any]:
    """
    Get metadata about EVTX file
    
    Args:
        file_path: Path to EVTX file
    
    Returns:
        dict: Metadata including event count, file size, etc.
    """
    import os
    
    metadata = {
        'file_path': file_path,
        'file_name': Path(file_path).name,
        'file_size': os.path.getsize(file_path),
        'event_count': 0,
        'channels': set(),
        'event_ids': set(),
        'computers': set(),
    }
    
    try:
        with EVTXParser(file_path) as parser:
            for event in parser.parse():
                metadata['event_count'] += 1
                
                if event.get('channel'):
                    metadata['channels'].add(event['channel'])
                if event.get('event_id'):
                    metadata['event_ids'].add(str(event['event_id']))
                if event.get('computer'):
                    metadata['computers'].add(event['computer'])
        
        # Convert sets to lists for JSON serialization
        metadata['channels'] = list(metadata['channels'])
        metadata['event_ids'] = list(metadata['event_ids'])
        metadata['computers'] = list(metadata['computers'])
        
    except Exception as e:
        logger.error(f"Error getting metadata: {e}")
        metadata['error'] = str(e)
    
    return metadata
