"""
NDJSON File Parser
Parses newline-delimited JSON files and creates search blobs for comprehensive searching
"""

import logging
import json
from datetime import datetime
from typing import Iterator, Dict, Any
from pathlib import Path

logger = logging.getLogger(__name__)


def create_search_blob(event: Dict[str, Any]) -> str:
    """
    Create flattened search blob from ALL event data
    
    This ensures all nested data is searchable as plain text.
    Recursively extracts ALL text from nested structures for IOC/keyword searching.
    
    Behavior:
    - Recursively extracts text from dicts and lists
    - Normalizes line breaks (\\r\\n → space)
    - Collapses multiple spaces
    - Excludes internal metadata fields
    
    Args:
        event: Original event dictionary
    
    Returns:
        Flattened, normalized text string for searching
    """
    # Fields to EXCLUDE from search_blob (metadata that shouldn't be searched)
    EXCLUDE_FIELDS = {
        'has_sigma', 'has_ioc', 'ioc_count', 'ioc_details', 'matched_iocs',
        'is_hidden', 'hidden_by', 'hidden_at',
        'file_id', 'source_file', 'opensearch_key', 'source_file_type',
        'search_blob',  # Don't include ourselves
        'indexed_at', 'case_id',  # Indexing metadata
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


def normalize_ndjson_event(event: Dict[str, Any]) -> Dict[str, Any]:
    """
    Normalize NDJSON event with standardized fields
    
    Adds:
    - normalized_timestamp: Standardized timestamp field
    - normalized_computer: Computer/hostname
    - normalized_event_id: Event identifier (if available)
    - search_blob: Flattened searchable text
    
    Args:
        event: Original NDJSON event
    
    Returns:
        Normalized event with search blob
    """
    # Extract timestamp (try multiple common fields)
    timestamp = None
    timestamp_fields = [
        '@timestamp', 'timestamp', 'event.ingested', 
        'event.created', 'time', 'datetime'
    ]
    for field in timestamp_fields:
        if '.' in field:
            # Nested field (e.g., event.ingested)
            parts = field.split('.')
            value = event
            for part in parts:
                if isinstance(value, dict):
                    value = value.get(part)
                else:
                    value = None
                    break
            if value:
                timestamp = value
                break
        else:
            # Top-level field
            timestamp = event.get(field)
            if timestamp:
                break
    
    if timestamp:
        event['normalized_timestamp'] = timestamp
    
    # Extract computer/hostname (try multiple common fields)
    computer = None
    computer_fields = [
        'host.hostname', 'host.name', 'computer', 'hostname',
        'Computer', 'ComputerName', 'agent.name'
    ]
    for field in computer_fields:
        if '.' in field:
            # Nested field
            parts = field.split('.')
            value = event
            for part in parts:
                if isinstance(value, dict):
                    value = value.get(part)
                else:
                    value = None
                    break
            if value:
                computer = value
                break
        else:
            # Top-level field
            computer = event.get(field)
            if computer:
                break
    
    if computer:
        event['normalized_computer'] = computer
    
    # Extract event ID (try multiple common fields)
    event_id = None
    event_id_fields = [
        'event.code', 'event_id', 'EventID', 'event.id',
        'event.type', 'event_type'
    ]
    for field in event_id_fields:
        if '.' in field:
            # Nested field
            parts = field.split('.')
            value = event
            for part in parts:
                if isinstance(value, dict):
                    value = value.get(part)
                else:
                    value = None
                    break
            if value:
                event_id = str(value)
                break
        else:
            # Top-level field
            value = event.get(field)
            if value:
                event_id = str(value)
                break
    
    if event_id:
        event['normalized_event_id'] = event_id
    
    # Create search blob for comprehensive searching
    search_blob = create_search_blob(event)
    if search_blob:
        event['search_blob'] = search_blob
    
    return event


def parse_ndjson_file(file_path: str) -> Iterator[Dict[str, Any]]:
    """
    Parse NDJSON file and yield normalized events
    
    Args:
        file_path: Path to NDJSON file
    
    Yields:
        dict: Normalized event data with search blob
    """
    event_count = 0
    error_count = 0
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                # Skip empty lines
                line = line.strip()
                if not line:
                    continue
                
                try:
                    # Parse JSON line
                    event = json.loads(line)
                    
                    # Normalize event (adds search_blob, normalized fields)
                    event = normalize_ndjson_event(event)
                    
                    event_count += 1
                    yield event
                    
                except json.JSONDecodeError as e:
                    error_count += 1
                    logger.error(f"JSON parse error on line {line_num}: {e}")
                    continue
                
                except Exception as e:
                    error_count += 1
                    logger.error(f"Error processing line {line_num}: {e}")
                    continue
        
        logger.info(f"Parsed {event_count} events from {Path(file_path).name} ({error_count} errors)")
        
    except Exception as e:
        logger.error(f"Error reading NDJSON file {file_path}: {e}")
        raise


def get_ndjson_metadata(file_path: str) -> Dict[str, Any]:
    """
    Get metadata about NDJSON file
    
    Args:
        file_path: Path to NDJSON file
    
    Returns:
        dict: Metadata including event count, file size, etc.
    """
    import os
    
    metadata = {
        'file_path': file_path,
        'file_name': Path(file_path).name,
        'file_size': os.path.getsize(file_path),
        'event_count': 0,
        'computers': set(),
        'event_types': set(),
    }
    
    try:
        for event in parse_ndjson_file(file_path):
            metadata['event_count'] += 1
            
            # Sample computers
            if event.get('normalized_computer'):
                metadata['computers'].add(event['normalized_computer'])
            
            # Sample event types
            if event.get('normalized_event_id'):
                metadata['event_types'].add(str(event['normalized_event_id']))
        
        # Convert sets to lists for JSON serialization
        metadata['computers'] = list(metadata['computers'])
        metadata['event_types'] = list(metadata['event_types'])
        
    except Exception as e:
        logger.error(f"Error getting metadata: {e}")
        metadata['error'] = str(e)
    
    return metadata

