"""
EZ Tools EvtxECmd EVTX Parser  
==============================
Parses Windows Event Logs using Eric Zimmerman's EvtxECmd
Routes to: case_X index

Uses 453 normalization maps for event-specific field extraction
Better normalization than raw XML parsing

Extracts:
- Normalized event fields
- Event-specific data (varies by Event ID)
- Standardized schema for analytics
"""

import os
import subprocess
import json
import logging
import tempfile

logger = logging.getLogger(__name__)

# Path to EvtxECmd
EVTXECMD_PATH = '/opt/EvtxECmd/EvtxeCmd/EvtxECmd.dll'
DOTNET_PATH = '/opt/dotnet/dotnet'  # System-wide installation

# Check availability
EVTXECMD_AVAILABLE = os.path.exists(EVTXECMD_PATH) and os.path.exists(DOTNET_PATH)

if not EVTXECMD_AVAILABLE:
    logger.warning("EvtxECmd not available - will use Python EVTX parser")


def parse_evtx_file(file_path):
    """
    Parse EVTX file using EvtxECmd
    
    Yields normalized events with 453 event-specific maps
    """
    if not EVTXECMD_AVAILABLE:
        logger.error("EvtxECmd not available")
        return
    
    if not os.path.exists(file_path):
        logger.error(f"EVTX file not found: {file_path}")
        return
    
    filename = os.path.basename(file_path)
    
    try:
        # Create temp directory for JSON output
        with tempfile.TemporaryDirectory() as temp_dir:
            # Run EvtxECmd
            cmd = [
                DOTNET_PATH,
                EVTXECMD_PATH,
                '-f', file_path,
                '--json', temp_dir
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,  # 5 minutes for large EVTX files
                env={**os.environ, 'PATH': f"{os.path.dirname(DOTNET_PATH)}:{os.environ.get('PATH', '')}"} 
            )
            
            if result.returncode != 0:
                logger.error(f"EvtxECmd failed for {filename}: {result.stderr}")
                return
            
            # Read JSON output
            json_files = [f for f in os.listdir(temp_dir) if f.endswith('.json')]
            if not json_files:
                logger.warning(f"No JSON output from EvtxECmd for {filename}")
                return
            
            json_path = os.path.join(temp_dir, json_files[0])
            with open(json_path, 'r') as f:
                events_data = json.load(f)
            
            # EvtxECmd returns array of events
            if not isinstance(events_data, list):
                logger.warning(f"Unexpected JSON format for {filename}")
                return
            
            logger.info(f"Parsing {len(events_data)} events from {filename} with EvtxECmd")
            
            # Yield each event
            for event in events_data:
                # Add source file tracking
                event['source_file'] = filename
                event['file_type'] = 'EVTX'
                
                # Normalize timestamp field
                if 'TimeCreated' in event and '@timestamp' not in event:
                    event['@timestamp'] = event['TimeCreated']
                
                yield event
    
    except subprocess.TimeoutExpired:
        logger.error(f"EvtxECmd timeout for {filename} (>5min)")
    except Exception as e:
        logger.error(f"Error parsing EVTX {file_path} with EvtxECmd: {e}")
        import traceback
        traceback.print_exc()

