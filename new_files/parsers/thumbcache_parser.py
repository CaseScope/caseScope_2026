"""
Thumbcache Parser
=================
Parses Windows Thumbcache database files (thumbcache_*.db)
Location: Users\*\AppData\Local\Microsoft\Windows\Explorer\thumbcache_*.db
Routes to: case_X_filesystem index

Extracts:
- Thumbnail entries with cache IDs
- File size and dimensions
- Cache entry timestamps
- Actual thumbnail images (optional extraction)

File Format:
- Header: CMMM signature
- Entries: Cache ID, hash, size, data offset
"""

import os
import struct
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

# Thumbcache signatures
THUMBCACHE_SIGNATURE = b'CMMM'
THUMBCACHE_VISTA_SIGNATURE = b'IMMM'

# Thumbcache sizes (from filename)
THUMBCACHE_SIZES = {
    '32': '32x32',
    '96': '96x96', 
    '256': '256x256',
    '1024': '1024x1024',
    'sr': 'stretch',
    'wide': 'wide',
    'exif': 'exif',
    'wide_alternate': 'wide_alternate',
    'custom_stream': 'custom_stream',
    'idx': 'index'
}


def parse_thumbcache_header(data):
    """Parse thumbcache file header"""
    try:
        if len(data) < 24:
            return None
        
        signature = data[0:4]
        
        if signature == THUMBCACHE_SIGNATURE:
            # Windows 7+ format
            version = struct.unpack_from('<I', data, 4)[0]
            cache_type = struct.unpack_from('<I', data, 8)[0]
            first_entry_offset = struct.unpack_from('<I', data, 12)[0]
            first_available_offset = struct.unpack_from('<I', data, 16)[0]
            num_entries = struct.unpack_from('<I', data, 20)[0]
            
            return {
                'signature': 'CMMM',
                'version': version,
                'cache_type': cache_type,
                'first_entry_offset': first_entry_offset,
                'first_available_offset': first_available_offset,
                'num_entries': num_entries
            }
        
        elif signature == THUMBCACHE_VISTA_SIGNATURE:
            # Windows Vista format
            version = struct.unpack_from('<I', data, 4)[0]
            
            return {
                'signature': 'IMMM',
                'version': version,
                'cache_type': 0,
                'first_entry_offset': 24,
                'first_available_offset': 0,
                'num_entries': 0
            }
        
        return None
    
    except Exception as e:
        logger.debug(f"Error parsing thumbcache header: {e}")
        return None


def parse_thumbcache_entry(data, offset, version):
    """Parse a single thumbcache entry"""
    try:
        if offset + 32 > len(data):
            return None, 0
        
        # Entry structure varies by version
        if version >= 21:  # Windows 8+
            signature = data[offset:offset+4]
            if signature != THUMBCACHE_SIGNATURE:
                return None, 0
            
            entry_size = struct.unpack_from('<I', data, offset + 4)[0]
            entry_hash = struct.unpack_from('<Q', data, offset + 8)[0]
            filename_size = struct.unpack_from('<I', data, offset + 16)[0]
            padding_size = struct.unpack_from('<I', data, offset + 20)[0]
            data_size = struct.unpack_from('<I', data, offset + 24)[0]
            data_checksum = struct.unpack_from('<I', data, offset + 28)[0]
            header_checksum = struct.unpack_from('<Q', data, offset + 32)[0]
            
            # Extract filename if present
            filename = None
            if filename_size > 0:
                filename_offset = offset + 48
                try:
                    filename_bytes = data[filename_offset:filename_offset + filename_size]
                    filename = filename_bytes.decode('utf-16-le', errors='ignore').rstrip('\x00')
                except:
                    pass
            
            return {
                'cache_hash': f'{entry_hash:016X}',
                'entry_size': entry_size,
                'filename': filename,
                'data_size': data_size,
                'data_checksum': f'{data_checksum:08X}',
                'header_checksum': f'{header_checksum:016X}'
            }, entry_size
        
        else:  # Windows 7/Vista
            entry_size = struct.unpack_from('<I', data, offset)[0]
            entry_hash = struct.unpack_from('<Q', data, offset + 4)[0]
            data_size = struct.unpack_from('<I', data, offset + 20)[0]
            
            return {
                'cache_hash': f'{entry_hash:016X}',
                'entry_size': entry_size,
                'filename': None,
                'data_size': data_size,
                'data_checksum': None,
                'header_checksum': None
            }, entry_size
    
    except Exception as e:
        logger.debug(f"Error parsing thumbcache entry at offset {offset}: {e}")
        return None, 0


def parse_thumbcache(file_path):
    """
    Parse Windows Thumbcache database
    
    Yields thumbnail cache entries
    """
    if not os.path.exists(file_path):
        logger.error(f"Thumbcache file not found: {file_path}")
        return
    
    filename = os.path.basename(file_path)
    
    # Determine cache size from filename
    cache_size = 'unknown'
    for size_key, size_name in THUMBCACHE_SIZES.items():
        if size_key in filename.lower():
            cache_size = size_name
            break
    
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
        
        if len(data) < 24:
            logger.warning(f"Thumbcache file too small: {filename}")
            return
        
        # Parse header
        header = parse_thumbcache_header(data)
        
        if not header:
            logger.warning(f"Invalid thumbcache signature: {filename}")
            return
        
        logger.info(f"Parsing thumbcache: {filename} (version {header['version']}, ~{header.get('num_entries', 'unknown')} entries)")
        
        # Parse entries
        offset = header['first_entry_offset']
        entry_count = 0
        max_entries = 10000  # Safety limit
        
        while offset < len(data) and entry_count < max_entries:
            entry, entry_size = parse_thumbcache_entry(data, offset, header['version'])
            
            if entry is None or entry_size == 0:
                break
            
            # Skip empty entries
            if entry['data_size'] > 0:
                event = {
                    '@timestamp': datetime.utcnow().isoformat(),
                    'event_type': 'thumbcache_entry',
                    'cache_hash': entry['cache_hash'],
                    'cache_size': cache_size,
                    'data_size': entry['data_size'],
                    'source_file': filename,
                    'artifact_type': 'thumbcache'
                }
                
                if entry.get('filename'):
                    event['cached_filename'] = entry['filename']
                
                if entry.get('data_checksum'):
                    event['data_checksum'] = entry['data_checksum']
                
                yield event
                entry_count += 1
            
            offset += entry_size
            
            # Align to 8 bytes
            if offset % 8 != 0:
                offset += 8 - (offset % 8)
        
        logger.info(f"Parsed {entry_count} thumbcache entries from {filename}")
    
    except Exception as e:
        logger.error(f"Error parsing thumbcache {file_path}: {e}")
        import traceback
        traceback.print_exc()


def parse_thumbcache_file(file_path):
    """Parse thumbcache database file"""
    filename = os.path.basename(file_path).lower()
    
    if 'thumbcache' in filename and filename.endswith('.db'):
        logger.info(f"Detected thumbcache database: {filename}")
        return parse_thumbcache(file_path)
    else:
        logger.warning(f"Not a thumbcache file: {filename}")
        return iter([])
