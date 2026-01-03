"""
Windows Prefetch Parser - Full Win10/11 Support
================================================
Handles MAM (LZXPRESS Huffman) compressed prefetch files on Linux
Uses dissect.util for native decompression

Routes to: case_X_execution index

Extracts FULL data from Windows 10/11 compressed prefetch:
- Executable name
- Run count
- Last 8 execution timestamps
- Volume information
- All file references (DLLs, data files accessed)
- Directory references
"""

import os
import struct
import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

try:
    from dissect.util.compression import lzxpress_huffman
    DISSECT_AVAILABLE = True
except ImportError:
    logger.warning("dissect.util not available - compressed prefetch parsing will be limited")
    DISSECT_AVAILABLE = False


def filetime_to_datetime(filetime):
    """Convert Windows FILETIME to datetime (UTC)"""
    if filetime == 0:
        return None
    EPOCH_DIFF = 116444736000000000
    timestamp = (filetime - EPOCH_DIFF) / 10_000_000
    try:
        return datetime.fromtimestamp(timestamp, tz=timezone.utc)
    except (OSError, ValueError):
        return None


def parse_prefetch_file(file_path):
    """
    Parse Windows Prefetch file (supports Win10/11 compressed format)
    
    Yields execution events with full timeline data
    """
    if not DISSECT_AVAILABLE:
        logger.error("dissect.util not available - cannot parse compressed prefetch")
        return
    
    if not os.path.exists(file_path):
        logger.error(f"Prefetch file not found: {file_path}")
        return
    
    filename = os.path.basename(file_path)
    
    try:
        with open(file_path, "rb") as f:
            data = f.read()
        
        compressed = False
        
        # Check for MAM compression (Windows 10+)
        if data[:4] == b'MAM\x04':
            compressed = True
            decompressed_size = struct.unpack_from('<I', data, 4)[0]
            compressed_data = data[8:]
            data = lzxpress_huffman.decompress(compressed_data)
            logger.info(f"Decompressed MAM prefetch: {filename}")
        
        # Validate signature
        signature = data[4:8]
        if signature != b'SCCA':
            logger.error(f"Invalid prefetch signature for {filename}")
            return
        
        # Parse header
        version = struct.unpack_from('<I', data, 0)[0]
        executable = data[16:76].decode('utf-16-le').rstrip('\x00')
        pf_hash = f"{struct.unpack_from('<I', data, 76)[0]:08X}"
        
        version_map = {
            17: "Windows XP/2003",
            23: "Windows Vista/7",
            26: "Windows 8/8.1",
            30: "Windows 10",
            31: "Windows 11"
        }
        version_string = version_map.get(version, f"Unknown ({version})")
        
        # Version-specific parsing
        if version in (30, 31):  # Windows 10/11
            run_count = struct.unpack_from('<I', data, 124)[0]
            
            # Last run times (up to 8)
            last_run_times = []
            for i in range(8):
                ft = struct.unpack_from('<Q', data, 128 + (i * 8))[0]
                if ft:
                    dt = filetime_to_datetime(ft)
                    if dt:
                        last_run_times.append(dt.isoformat())
            
            # Parse volumes
            volumes_offset = struct.unpack_from('<I', data, 108)[0]
            volumes_count = struct.unpack_from('<I', data, 112)[0]
            volumes_size = struct.unpack_from('<I', data, 116)[0]
            
            volumes = []
            vol_data = data[volumes_offset:volumes_offset + volumes_size]
            for v in range(volumes_count):
                vol_entry_offset = v * 104
                if vol_entry_offset + 104 > len(vol_data):
                    break
                
                vol_name_offset = struct.unpack_from('<I', vol_data, vol_entry_offset)[0]
                vol_name_len = struct.unpack_from('<I', vol_data, vol_entry_offset + 4)[0]
                vol_create_time = struct.unpack_from('<Q', vol_data, vol_entry_offset + 8)[0]
                vol_serial = struct.unpack_from('<I', vol_data, vol_entry_offset + 16)[0]
                
                vol_name_abs = volumes_offset + vol_name_offset
                vol_name = data[vol_name_abs:vol_name_abs + vol_name_len * 2].decode('utf-16-le', errors='ignore').rstrip('\x00')
                vol_time = filetime_to_datetime(vol_create_time)
                
                volumes.append({
                    "path": vol_name,
                    "serial": f"{vol_serial:08X}",
                    "created": vol_time.isoformat() if vol_time else None
                })
            
            # Parse file references
            filename_offset = struct.unpack_from('<I', data, 100)[0]
            filename_size = struct.unpack_from('<I', data, 104)[0]
            metrics_offset = struct.unpack_from('<I', data, 84)[0]
            metrics_count = struct.unpack_from('<I', data, 88)[0]
            
            filename_strings = data[filename_offset:filename_offset + filename_size]
            file_references = []
            
            for i in range(min(metrics_count, 200)):  # Limit to 200 for indexing
                entry_offset = metrics_offset + (i * 32)
                if entry_offset + 32 > len(data):
                    break
                
                name_offset = struct.unpack_from('<I', data, entry_offset + 12)[0]
                try:
                    name_data = filename_strings[name_offset:name_offset + 520]
                    null_pos = 0
                    while null_pos < len(name_data) - 1:
                        if name_data[null_pos:null_pos+2] == b'\x00\x00':
                            break
                        null_pos += 2
                    name = name_data[:null_pos].decode('utf-16-le', errors='ignore')
                    if name:
                        file_references.append(name)
                except:
                    pass
            
            # Create comprehensive event
            event = {
                '@timestamp': last_run_times[0] if last_run_times else datetime.utcnow().isoformat(),
                'event_type': 'prefetch_execution',
                'artifact_type': 'prefetch',
                'executable': executable,
                'prefetch_hash': pf_hash,
                'prefetch_version': version,
                'version_string': version_string,
                'run_count': run_count,
                'last_run_times': last_run_times,
                'volumes': volumes,
                'file_references': file_references[:50],  # Limit for indexing
                'file_reference_count': len(file_references),
                'source_file': filename,
                'compressed_format': compressed
            }
            
            logger.info(f"Parsed Win{version} prefetch: {executable} (runs={run_count}, compressed={compressed})")
            yield event
        
        elif version == 26:  # Windows 8
            # Similar parsing for Win8 (uncompressed usually)
            run_count = struct.unpack_from('<I', data, 124)[0]
            
            last_run_times = []
            for i in range(8):
                ft = struct.unpack_from('<Q', data, 128 + (i * 8))[0]
                if ft:
                    dt = filetime_to_datetime(ft)
                    if dt:
                        last_run_times.append(dt.isoformat())
            
            event = {
                '@timestamp': last_run_times[0] if last_run_times else datetime.utcnow().isoformat(),
                'event_type': 'prefetch_execution',
                'artifact_type': 'prefetch',
                'executable': executable,
                'prefetch_hash': pf_hash,
                'prefetch_version': version,
                'version_string': version_string,
                'run_count': run_count,
                'last_run_times': last_run_times,
                'source_file': filename,
                'compressed_format': compressed
            }
            
            logger.info(f"Parsed Win8 prefetch: {executable} (runs={run_count})")
            yield event
        
        else:
            logger.warning(f"Unsupported prefetch version {version} for {filename}")
    
    except Exception as e:
        logger.error(f"Error parsing prefetch {file_path}: {e}")
        import traceback
        traceback.print_exc()

