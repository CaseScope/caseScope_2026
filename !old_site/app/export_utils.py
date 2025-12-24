"""
CSV Export Utilities
Handles CSV generation for event exports
"""

import csv
import io
import json
from datetime import datetime
from typing import List, Dict, Any


def generate_events_csv(events: List[Dict[str, Any]]) -> str:
    """
    Generate CSV from event list with FULL event data
    
    Columns: Event ID, Date/Time, Computer Name, Source File, Raw Data (FULL JSON)
    
    The Raw Data column contains the COMPLETE OpenSearch _source including:
    - Event.EventData.TargetUserName
    - Event.EventData.IpAddress
    - Event.EventData.ShareName
    - Event.EventData.ObjectName
    - All other EventData fields for forensic analysis
    """
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Write header
    writer.writerow(['Event ID', 'Date/Time', 'Computer Name', 'Source File', 'Raw Data'])
    
    # Write data rows
    for event in events:
        # Extract normalized fields (added during ingestion)
        event_id = event.get('normalized_event_id', 'N/A')
        timestamp = event.get('normalized_timestamp', '')
        computer_name = event.get('normalized_computer', 'N/A')
        
        # Get source file
        source_file = ''
        if 'source_file' in event:
            source_file = event['source_file']
        elif 'file_metadata' in event and 'file_name' in event['file_metadata']:
            source_file = event['file_metadata']['file_name']
        
        # Convert ENTIRE event to JSON for raw data column
        # This includes Event.EventData with all fields (TargetUserName, ShareName, etc.)
        raw_data = json.dumps(event, default=str)
        
        writer.writerow([
            event_id,
            timestamp,
            computer_name,
            source_file,
            raw_data
        ])
    
    return output.getvalue()

