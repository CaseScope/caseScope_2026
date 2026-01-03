"""
EZ Tools LECmd LNK Parser
==========================
Parses Windows LNK shortcuts using Eric Zimmerman's LECmd
Routes to: case_X_execution index

Extracts significantly more data than Python parsers:
- Machine ID (computer name)
- MAC Address
- MFT Entry Numbers
- Full directory traversal with timestamps
- Tracker database GUIDs
- Drive serial numbers
- Multiple timestamp sets (source + target files)
"""

import os
import subprocess
import json
import logging
import tempfile
from datetime import datetime

logger = logging.getLogger(__name__)

# Path to LECmd
LECMD_PATH = '/opt/LECmd/LECmd.dll'
DOTNET_PATH = '/opt/dotnet/dotnet'  # System-wide installation

# Check availability
LECMD_AVAILABLE = os.path.exists(LECMD_PATH) and os.path.exists(DOTNET_PATH)

if not LECMD_AVAILABLE:
    logger.warning(f"LECmd not available - LNK parsing will use fallback parser")


def parse_lnk_file(file_path):
    """
    Parse Windows LNK file using LECmd
    
    Yields enriched LNK events with full metadata
    """
    if not LECMD_AVAILABLE:
        logger.error("LECmd not available")
        return
    
    if not os.path.exists(file_path):
        logger.error(f"LNK file not found: {file_path}")
        return
    
    filename = os.path.basename(file_path)
    
    try:
        # Create temp directory for JSON output
        with tempfile.TemporaryDirectory() as temp_dir:
            # Run LECmd
            cmd = [
                DOTNET_PATH,
                LECMD_PATH,
                '-f', file_path,
                '--json', temp_dir,
                '-q'  # Quiet mode
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30,
                env={**os.environ, 'PATH': f"{os.path.dirname(DOTNET_PATH)}:{os.environ.get('PATH', '')}"} 
            )
            
            if result.returncode != 0:
                logger.error(f"LECmd failed for {filename}: {result.stderr}")
                return
            
            # Read JSON output
            json_files = [f for f in os.listdir(temp_dir) if f.endswith('.json')]
            if not json_files:
                logger.warning(f"No JSON output from LECmd for {filename}")
                return
            
            json_path = os.path.join(temp_dir, json_files[0])
            with open(json_path, 'r') as f:
                lnk_data = json.load(f)
            
            # LECmd returns a single dict object (not array)
            if not lnk_data or not isinstance(lnk_data, dict):
                logger.warning(f"Invalid LNK data format for {filename}")
                return
            
            lnk = lnk_data
            
            # Create event for OpenSearch
            event = {
                'event_type': 'lnk_shortcut',
                'artifact_type': 'lnk',
                'source_file': filename,
                '@timestamp': lnk.get('TargetCreated') or lnk.get('SourceCreated') or datetime.utcnow().isoformat()
            }
            
            # Add all LECmd fields (comprehensive extraction)
            field_mapping = {
                'SourceFile': 'source_path',
                'SourceCreated': 'source_created',
                'SourceModified': 'source_modified',
                'SourceAccessed': 'source_accessed',
                'TargetCreated': 'target_created',
                'TargetModified': 'target_modified',
                'TargetAccessed': 'target_accessed',
                'FileSize': 'target_file_size',
                'RelativePath': 'relative_path',
                'WorkingDirectory': 'working_directory',
                'Arguments': 'arguments',
                'IconLocation': 'icon_location',
                'LocalPath': 'local_path',
                'DriveType': 'drive_type',
                'VolumeSerialNumber': 'volume_serial',
                'VolumeLabel': 'volume_label',
                'MachineID': 'machine_id',  # Computer name!
                'MachineMACAddress': 'mac_address',  # Network adapter!
                'MACVendor': 'mac_vendor',
                'TrackerCreatedOn': 'tracker_created',
                'TargetIDAbsolutePath': 'absolute_path',
                'TargetMFTEntryNumber': 'mft_entry',
                'TargetMFTSequenceNumber': 'mft_sequence',
                'HeaderFlags': 'header_flags',
                'FileAttributes': 'file_attributes',
                'ExtraBlocksPresent': 'extra_blocks'
            }
            
            for lecmd_field, our_field in field_mapping.items():
                if lecmd_field in lnk and lnk[lecmd_field]:
                    event[our_field] = lnk[lecmd_field]
            
            logger.info(f"Parsed LNK with LECmd: {filename} (machine: {event.get('machine_id', 'unknown')})")
            
            yield event
    
    except subprocess.TimeoutExpired:
        logger.error(f"LECmd timeout for {filename}")
    except Exception as e:
        logger.error(f"Error parsing LNK {file_path} with LECmd: {e}")
        import traceback
        traceback.print_exc()

