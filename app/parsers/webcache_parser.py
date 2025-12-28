"""
WebCache ESE Parser (Phase 2)
==============================
Parses Windows WebCache (ESE database format)
Files: WebCacheV01.dat, WebCacheV24.dat
Routes to: case_X_browser index

Extracts:
- Browsing history (URLs, visits)
- Cookies
- Download history
- Cache entries
"""

import os
import sys
import logging
from datetime import datetime, timedelta

# Add system dist-packages for pyesedb
sys.path.append('/usr/lib/python3/dist-packages')

logger = logging.getLogger(__name__)

try:
    import pyesedb
    ESE_AVAILABLE = True
except ImportError:
    logger.warning("pyesedb not available - WebCache parsing will be skipped")
    ESE_AVAILABLE = False

# Windows FILETIME epoch: January 1, 1601
FILETIME_EPOCH = datetime(1601, 1, 1)

def filetime_to_datetime(filetime):
    """
    Convert Windows FILETIME (100-nanosecond intervals since 1601-01-01) to Python datetime
    """
    try:
        if not filetime or filetime == 0:
            return None
        # FILETIME is in 100-nanosecond intervals
        return FILETIME_EPOCH + timedelta(microseconds=filetime / 10)
    except Exception:
        return None


def parse_webcache_ese(file_path):
    """
    Parse WebCache ESE database
    
    Yields events from WebCache tables:
    - Container_X tables (URL history, cookies, downloads)
    """
    if not ESE_AVAILABLE:
        logger.error("pyesedb not available - cannot parse WebCache")
        return
    
    if not os.path.exists(file_path):
        logger.error(f"WebCache file not found: {file_path}")
        return
    
    filename = os.path.basename(file_path)
    
    try:
        # Copy file to avoid locking
        import shutil
        import tempfile
        
        with tempfile.NamedTemporaryFile(delete=False, suffix='.dat') as tmp_file:
            temp_path = tmp_file.name
        
        shutil.copy2(file_path, temp_path)
        
        # Open ESE database
        esedb = pyesedb.file()
        esedb.open(temp_path)
        
        logger.info(f"Opened WebCache ESE: {filename} ({esedb.number_of_tables} tables)")
        
        # Iterate through all tables
        for table_index in range(esedb.number_of_tables):
            try:
                table = esedb.get_table(table_index)
                table_name = table.name
                
                # Focus on Container tables (contain cached data)
                if not table_name.startswith('Container_'):
                    continue
                
                logger.info(f"Parsing table: {table_name} ({table.number_of_records} records)")
                
                # Get column names
                columns = []
                for col_index in range(table.number_of_columns):
                    col = table.get_column(col_index)
                    columns.append({'name': col.name, 'type': col.type})
                
                # Parse records
                for record_index in range(table.number_of_records):
                    try:
                        record = table.get_record(record_index)
                        
                        # Extract data from record
                        event = {
                            '@timestamp': datetime.utcnow().isoformat(),
                            'event_type': 'webcache_entry',
                            'browser': 'edge_ie',
                            'table_name': table_name,
                            'source_file': filename,
                            'artifact_type': 'browser_cache'
                        }
                        
                        # Extract column values
                        for col_index, col_info in enumerate(columns):
                            try:
                                col_name = col_info['name']
                                value = record.get_value_data_as_string(col_index)
                                
                                # Handle specific fields
                                if col_name in ['Url', 'SecureUrl', 'ResponseHeaders']:
                                    event[col_name.lower()] = value
                                elif col_name in ['AccessedTime', 'ModifiedTime', 'ExpiryTime', 'LastModifiedTime', 'LastAccessedTime']:
                                    # Try to parse as FILETIME
                                    try:
                                        if value:
                                            filetime = int(value) if value.isdigit() else 0
                                            dt = filetime_to_datetime(filetime)
                                            if dt:
                                                event[col_name.lower()] = dt.isoformat()
                                                # Use AccessedTime as main timestamp
                                                if col_name == 'AccessedTime':
                                                    event['@timestamp'] = dt.isoformat()
                                    except:
                                        pass
                                elif col_name in ['RequestHeaders', 'Filename', 'FileExtension']:
                                    event[col_name.lower()] = value
                                else:
                                    # Store other fields generically
                                    if value:
                                        event[f'webcache_{col_name.lower()}'] = value
                            
                            except Exception as e:
                                # Column read error - skip
                                pass
                        
                        # Only yield if we have meaningful data
                        if len(event) > 6:  # More than just the base fields
                            yield event
                    
                    except Exception as e:
                        # Record parse error - skip
                        logger.debug(f"Error parsing record {record_index} in {table_name}: {e}")
                        continue
            
            except Exception as e:
                logger.error(f"Error parsing table {table_index}: {e}")
                continue
        
        esedb.close()
        
        # Cleanup
        try:
            os.unlink(temp_path)
        except:
            pass
    
    except Exception as e:
        logger.error(f"Error parsing WebCache {file_path}: {e}")
        import traceback
        traceback.print_exc()


def parse_webcache_file(file_path):
    """
    Parse WebCache ESE database file
    Auto-detects WebCacheV01.dat or WebCacheV24.dat
    """
    filename = os.path.basename(file_path).lower()
    
    if 'webcache' in filename and filename.endswith('.dat'):
        logger.info(f"Detected WebCache ESE database: {filename}")
        return parse_webcache_ese(file_path)
    else:
        logger.warning(f"Not a WebCache file: {filename}")
        return iter([])  # Empty iterator

