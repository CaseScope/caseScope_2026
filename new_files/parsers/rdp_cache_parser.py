"""
RDP Bitmap Cache Parser
=======================
Parses Windows RDP Bitmap Cache files
Location: Users\*\AppData\Local\Microsoft\Terminal Server Client\Cache\*.bin
          (Cache0000.bin, Cache0001.bin, etc.)
          Also: bcache24.bmc (older format)
Routes to: case_X_filesystem index

Extracts:
- Cached bitmap tiles from RDP sessions
- Reconstructed screenshots (when possible)
- Cache entry metadata

Evidence Value:
- Visual evidence of RDP session content
- What attacker saw during lateral movement
- Data accessed over RDP
- Evidence of specific applications/documents viewed
"""

import os
import struct
import logging
import hashlib
from datetime import datetime

logger = logging.getLogger(__name__)

# RDP Cache file signatures
RDP_CACHE_V7_SIGNATURE = b'RDP8bmp\x00'  # Windows 7+
BMC_SIGNATURE = b'BMC\x00'  # Older BMC format


def parse_rdp_cache_bin(file_path, extract_tiles=False, output_dir=None):
    """
    Parse RDP Bitmap Cache .bin files (Windows 7+)
    
    Yields cache entry events
    """
    if not os.path.exists(file_path):
        logger.error(f"RDP cache file not found: {file_path}")
        return
    
    filename = os.path.basename(file_path)
    
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
        
        file_size = len(data)
        logger.info(f"Parsing RDP cache: {filename} ({file_size} bytes)")
        
        if file_size < 12:
            logger.warning(f"RDP cache file too small: {filename}")
            return
        
        # Check signature
        signature = data[0:8]
        
        if signature == RDP_CACHE_V7_SIGNATURE:
            # Windows 7+ format
            version = struct.unpack_from('<I', data, 8)[0]
            logger.info(f"RDP Cache version: {version}")
            
            # Parse cache entries
            offset = 12
            entry_count = 0
            tile_hashes = set()
            
            while offset < file_size - 12:
                try:
                    # Each entry has: hash (8 bytes), width (2), height (2), data
                    entry_hash = struct.unpack_from('<Q', data, offset)[0]
                    
                    if entry_hash == 0:
                        offset += 8
                        continue
                    
                    # Try to find tile dimensions and data
                    # Format varies - simplified extraction
                    width = struct.unpack_from('<H', data, offset + 8)[0]
                    height = struct.unpack_from('<H', data, offset + 10)[0]
                    
                    # Sanity check dimensions
                    if width > 0 and width <= 64 and height > 0 and height <= 64:
                        hash_str = f'{entry_hash:016X}'
                        
                        if hash_str not in tile_hashes:
                            tile_hashes.add(hash_str)
                            
                            event = {
                                '@timestamp': datetime.utcnow().isoformat(),
                                'event_type': 'rdp_cache_tile',
                                'tile_hash': hash_str,
                                'tile_width': width,
                                'tile_height': height,
                                'offset': offset,
                                'source_file': filename,
                                'artifact_type': 'rdp_cache'
                            }
                            
                            # Calculate data size (width * height * bytes_per_pixel)
                            # Typically 32-bit BGRA
                            data_size = width * height * 4
                            event['data_size'] = data_size
                            
                            entry_count += 1
                            yield event
                    
                    offset += 12  # Move to next potential entry
                
                except Exception as e:
                    offset += 4
                    continue
            
            logger.info(f"Found {entry_count} unique cache tiles in {filename}")
        
        else:
            # Try to parse as generic bitmap cache
            # Look for BMP-like structures
            logger.info(f"Unknown RDP cache format, attempting generic parse: {filename}")
            
            # Search for bitmap signatures within file
            offset = 0
            entry_count = 0
            
            while offset < file_size - 54:
                # Look for BMP signature
                if data[offset:offset+2] == b'BM':
                    try:
                        bmp_size = struct.unpack_from('<I', data, offset + 2)[0]
                        
                        if bmp_size > 0 and bmp_size < 1000000:  # Reasonable size
                            event = {
                                '@timestamp': datetime.utcnow().isoformat(),
                                'event_type': 'rdp_cache_bitmap',
                                'bitmap_size': bmp_size,
                                'offset': offset,
                                'source_file': filename,
                                'artifact_type': 'rdp_cache'
                            }
                            
                            entry_count += 1
                            yield event
                            
                            offset += bmp_size
                            continue
                    except:
                        pass
                
                offset += 1
            
            if entry_count == 0:
                # Just log file metadata
                event = {
                    '@timestamp': datetime.utcnow().isoformat(),
                    'event_type': 'rdp_cache_file',
                    'file_size': file_size,
                    'source_file': filename,
                    'artifact_type': 'rdp_cache',
                    'parser_note': 'unknown_format'
                }
                yield event
    
    except Exception as e:
        logger.error(f"Error parsing RDP cache {file_path}: {e}")
        import traceback
        traceback.print_exc()


def parse_rdp_cache_bmc(file_path):
    """
    Parse older BMC format RDP cache files
    """
    if not os.path.exists(file_path):
        logger.error(f"BMC file not found: {file_path}")
        return
    
    filename = os.path.basename(file_path)
    
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
        
        file_size = len(data)
        logger.info(f"Parsing BMC cache: {filename} ({file_size} bytes)")
        
        # BMC format: 12-byte header + entries
        if file_size < 12:
            return
        
        # Parse header
        version = struct.unpack_from('<I', data, 0)[0]
        num_entries = struct.unpack_from('<I', data, 4)[0]
        
        logger.info(f"BMC version: {version}, entries: {num_entries}")
        
        offset = 12
        entry_count = 0
        
        for i in range(min(num_entries, 10000)):
            if offset + 8 > file_size:
                break
            
            try:
                # BMC entry structure varies
                entry_size = struct.unpack_from('<I', data, offset)[0]
                
                if entry_size > 0 and entry_size < 100000:
                    # Calculate hash of tile data
                    tile_data = data[offset:offset + min(entry_size, 1000)]
                    tile_hash = hashlib.md5(tile_data).hexdigest()
                    
                    event = {
                        '@timestamp': datetime.utcnow().isoformat(),
                        'event_type': 'rdp_cache_tile_bmc',
                        'tile_hash': tile_hash,
                        'entry_size': entry_size,
                        'entry_index': i,
                        'offset': offset,
                        'source_file': filename,
                        'artifact_type': 'rdp_cache'
                    }
                    
                    entry_count += 1
                    yield event
                    
                    offset += entry_size
                else:
                    offset += 4
            
            except:
                offset += 4
        
        logger.info(f"Parsed {entry_count} BMC cache entries from {filename}")
    
    except Exception as e:
        logger.error(f"Error parsing BMC {file_path}: {e}")
        import traceback
        traceback.print_exc()


def parse_rdp_cache_file(file_path):
    """Parse RDP Bitmap Cache file (auto-detect format)"""
    filename = os.path.basename(file_path).lower()
    
    # Check for cache files
    if filename.startswith('cache') and filename.endswith('.bin'):
        logger.info(f"Detected RDP cache .bin file: {filename}")
        return parse_rdp_cache_bin(file_path)
    elif filename.endswith('.bmc'):
        logger.info(f"Detected RDP cache .bmc file: {filename}")
        return parse_rdp_cache_bmc(file_path)
    elif 'bcache' in filename:
        logger.info(f"Detected RDP bcache file: {filename}")
        return parse_rdp_cache_bmc(file_path)
    else:
        logger.warning(f"Not an RDP cache file: {filename}")
        return iter([])
