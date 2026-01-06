"""
EZ Tools MFTECmd MFT Parser
============================
Parses NTFS Master File Table using Eric Zimmerman's MFTECmd
Routes to: case_X_filesystem index (new)

Extracts:
- Complete file system timeline
- Every file creation/modification/access
- Deleted file records
- MFT entry numbers
- File attributes and permissions
"""

import os
import subprocess
import json
import logging
import tempfile

logger = logging.getLogger(__name__)

# Path to MFTECmd
MFTECMD_PATH = '/opt/MFTEcmd/MFTECmd.dll'
DOTNET_PATH = '/opt/dotnet/dotnet'  # System-wide installation

# Check availability  
MFTECMD_AVAILABLE = os.path.exists(MFTECMD_PATH) and os.path.exists(DOTNET_PATH)

if not MFTECMD_AVAILABLE:
    logger.warning("MFTECmd not available - MFT parsing will be skipped")


def extract_hostname_from_mft_path(file_path):
    """
    Extract hostname from MFT file path/name
    
    Common patterns:
    - HOSTNAME_$MFT
    - HOSTNAME-$MFT  
    - /path/HOSTNAME/C/$MFT
    - /path/to/HOSTNAME/$MFT
    """
    filename = os.path.basename(file_path)
    full_path = os.path.abspath(file_path)
    
    # Pattern 1: HOSTNAME_$MFT or HOSTNAME-$MFT
    if '_' in filename and '$MFT' in filename:
        parts = filename.split('_')
        if len(parts) >= 2 and parts[0]:
            return parts[0]
    
    if '-' in filename and '$MFT' in filename:
        parts = filename.split('-')
        if len(parts) >= 2 and parts[0] and not parts[0].startswith('$'):
            return parts[0]
    
    # Pattern 2: Look in parent directories for hostname
    # Common structure: .../HOSTNAME/C/$MFT or .../HOSTNAME/$MFT
    path_parts = full_path.split(os.sep)
    for i, part in enumerate(path_parts):
        if part in ['$MFT', '$MFT.gz']:
            # Check 2-3 levels up for potential hostname
            if i >= 2 and path_parts[i-2] and not path_parts[i-2].startswith('case_'):
                potential_host = path_parts[i-2]
                # Skip common directory names
                if potential_host not in ['staging', 'storage', 'C', 'D', 'E', 'data', 'triage']:
                    return potential_host
            if i >= 1 and path_parts[i-1] and path_parts[i-1] not in ['C', 'D', 'E', 'data']:
                return path_parts[i-1]
    
    return None


def parse_mft_file(file_path):
    """
    Parse $MFT file using MFTECmd
    
    Yields file system timeline events
    WARNING: Can generate millions of events per $MFT!
    """
    if not MFTECMD_AVAILABLE:
        logger.error("MFTECmd not available")
        return
    
    if not os.path.exists(file_path):
        logger.error(f"MFT file not found: {file_path}")
        return
    
    filename = os.path.basename(file_path)
    hostname = extract_hostname_from_mft_path(file_path)
    
    if hostname:
        logger.info(f"Extracted hostname from MFT path: {hostname}")
    
    try:
        # Create temp directory for JSON output
        with tempfile.TemporaryDirectory() as temp_dir:
            # Run MFTECmd
            cmd = [
                DOTNET_PATH,
                MFTECMD_PATH,
                '-f', file_path,
                '--json', temp_dir
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600,  # 10 minutes for large MFT files
                env={**os.environ, 'PATH': f"{os.path.dirname(DOTNET_PATH)}:{os.environ.get('PATH', '')}"} 
            )
            
            if result.returncode != 0:
                logger.error(f"MFTECmd failed for {filename}: {result.stderr}")
                return
            
            # Read JSON output
            json_files = [f for f in os.listdir(temp_dir) if f.endswith('.json')]
            if not json_files:
                logger.warning(f"No JSON output from MFTECmd for {filename}")
                return
            
            json_path = os.path.join(temp_dir, json_files[0])
            
            # MFTECmd outputs NDJSON (one JSON object per line), not JSON array
            mft_data = []
            with open(json_path, 'r', encoding='utf-8-sig') as f:  # Handle BOM
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            entry = json.loads(line)
                            mft_data.append(entry)
                        except json.JSONDecodeError as e:
                            logger.debug(f"Skipping invalid MFT JSON line: {e}")
            
            if not mft_data:
                logger.info(f"No MFT entries in {filename}")
                return
            
            logger.info(f"Parsing {len(mft_data)} MFT entries from {filename} with MFTECmd")
            
            # Yield each MFT entry
            for idx, entry in enumerate(mft_data):
                event = {
                    'event_type': 'mft_entry',
                    'artifact_type': 'mft',
                    'source_file': filename,
                    '@timestamp': entry.get('Created0x10') or entry.get('Created0x30') or entry.get('Modified0x10')
                }
                
                # Add hostname if extracted
                if hostname:
                    event['computer'] = hostname
                    event['host'] = {'name': hostname}
                
                # Map important MFT fields
                field_mapping = {
                    'EntryNumber': 'mft_entry_number',
                    'SequenceNumber': 'sequence_number',
                    'InUse': 'in_use',
                    'ParentEntryNumber': 'parent_entry',
                    'ParentSequenceNumber': 'parent_sequence',
                    'FileName': 'file_name',
                    'Extension': 'extension',
                    'FileSize': 'file_size',
                    'ReferenceCount': 'reference_count',
                    'IsDirectory': 'is_directory',
                    'HasAds': 'has_ads',
                    'IsAds': 'is_ads',
                    'Created0x10': 'created_si',  # SI = Standard Information
                    'Created0x30': 'created_fn',  # FN = File Name
                    'Modified0x10': 'modified_si',
                    'Modified0x30': 'modified_fn',
                    'Accessed0x10': 'accessed_si',
                    'RecordNumber': 'record_number',
                    'LogfileSequenceNumber': 'logfile_sequence',
                    'SecurityId': 'security_id',
                    'ObjectIdFileDroid': 'object_id'
                }
                
                for mft_field, our_field in field_mapping.items():
                    if mft_field in entry and entry[mft_field] is not None:
                        event[our_field] = entry[mft_field]
                
                # Only log every 10000th entry to avoid spam
                if idx % 10000 == 0:
                    logger.info(f"Processing MFT entry {idx}/{len(mft_data)}")
                
                yield event
    
    except subprocess.TimeoutExpired:
        logger.error(f"MFTECmd timeout for {filename} (>10min)")
    except Exception as e:
        logger.error(f"Error parsing MFT {file_path} with MFTECmd: {e}")
        import traceback
        traceback.print_exc()

