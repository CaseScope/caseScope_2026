"""
EZ Tools JLECmd JumpList Parser
================================
Parses Windows JumpList files using Eric Zimmerman's JLECmd
Routes to: case_X_execution index

Parses both:
- AutomaticDestinations-ms (automatic jump lists)
- CustomDestinations-ms (custom jump lists)

Extracts:
- Application usage timeline
- Recently accessed files
- File paths and timestamps
- Access patterns
"""

import os
import subprocess
import json
import logging
import tempfile
from datetime import datetime

logger = logging.getLogger(__name__)

# Path to JLECmd
JLECMD_PATH = '/opt/JLECmd/JLECmd.dll'
DOTNET_PATH = '/opt/dotnet/dotnet'  # System-wide installation

# Check availability
JLECMD_AVAILABLE = os.path.exists(JLECMD_PATH) and os.path.exists(DOTNET_PATH)

if not JLECMD_AVAILABLE:
    logger.warning("JLECmd not available - JumpList parsing will be skipped")


def parse_jumplist_file(file_path):
    """
    Parse Windows JumpList file using JLECmd
    
    Yields events for each entry in the JumpList
    """
    if not JLECMD_AVAILABLE:
        logger.error("JLECmd not available")
        return
    
    if not os.path.exists(file_path):
        logger.error(f"JumpList file not found: {file_path}")
        return
    
    filename = os.path.basename(file_path)
    
    try:
        # Create temp directory for JSON output
        with tempfile.TemporaryDirectory() as temp_dir:
            # Run JLECmd
            cmd = [
                DOTNET_PATH,
                JLECMD_PATH,
                '-f', file_path,
                '--json', temp_dir,
                '-q'  # Quiet mode
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60,
                env={**os.environ, 'PATH': f"{os.path.dirname(DOTNET_PATH)}:{os.environ.get('PATH', '')}"} 
            )
            
            if result.returncode != 0:
                logger.error(f"JLECmd failed for {filename}: {result.stderr}")
                return
            
            # Read JSON output - JLECmd creates filename based on input file
            json_files = [f for f in os.listdir(temp_dir) if f.endswith('.json')]
            if not json_files:
                logger.warning(f"No JSON output from JLECmd for {filename}")
                return
            
            json_path = os.path.join(temp_dir, json_files[0])
            with open(json_path, 'r', encoding='utf-8-sig') as f:  # Handle BOM
                jumplist_data = json.load(f)
            
            # JLECmd can return dict or array depending on file
            if isinstance(jumplist_data, dict):
                # Single entry - convert to list
                jumplist_data = [jumplist_data]
            elif not isinstance(jumplist_data, list):
                logger.warning(f"Unexpected JSON format for {filename}")
                return
            
            if len(jumplist_data) == 0:
                logger.info(f"Empty JumpList: {filename}")
                return
            
            # Process each entry in the jumplist
            for idx, entry in enumerate(jumplist_data):
                event = {
                    'event_type': 'jumplist_entry',
                    'artifact_type': 'jumplist',
                    'source_file': filename,
                    '@timestamp': entry.get('TargetCreated') or entry.get('SourceCreated') or datetime.utcnow().isoformat()
                }
                
                # Map JLECmd fields
                field_mapping = {
                    'SourceFile': 'jumplist_source',
                    'AppId': 'app_id',
                    'AppIdDescription': 'application',
                    'TargetCreated': 'target_created',
                    'TargetModified': 'target_modified',
                    'TargetAccessed': 'target_accessed',
                    'FilePath': 'file_path',
                    'FileName': 'file_name',
                    'FileSize': 'file_size',
                    'MachineID': 'machine_id',
                    'MacAddress': 'mac_address',
                    'TrackerCreatedOn': 'tracker_created',
                    'VolumeSerialNumber': 'volume_serial',
                    'VolumeLabel': 'volume_label',
                    'LocalPath': 'local_path',
                    'CommonPath': 'common_path',
                    'TargetIDAbsolutePath': 'absolute_path'
                }
                
                for jle_field, our_field in field_mapping.items():
                    if jle_field in entry and entry[jle_field]:
                        event[our_field] = entry[jle_field]
                
                logger.info(f"Parsed JumpList entry {idx+1} from {filename}")
                yield event
    
    except subprocess.TimeoutExpired:
        logger.error(f"JLECmd timeout for {filename}")
    except Exception as e:
        logger.error(f"Error parsing JumpList {file_path} with JLECmd: {e}")
        import traceback
        traceback.print_exc()

