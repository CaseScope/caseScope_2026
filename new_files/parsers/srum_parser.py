"""
SRUM Parser (Phase 3)
=====================
Parses Windows SRUM (System Resource Usage Monitor) database
File: SRUDB.dat (ESE database)
Routes to: case_X_network index

Extracts:
- Network data usage (per application)
- Application resource usage
- Network connectivity history
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
    logger.warning("pyesedb not available - SRUM parsing will be skipped")
    ESE_AVAILABLE = False

# Windows FILETIME epoch
FILETIME_EPOCH = datetime(1601, 1, 1)

def filetime_to_datetime(filetime):
    """Convert Windows FILETIME to Python datetime"""
    try:
        if not filetime or filetime == 0:
            return None
        return FILETIME_EPOCH + timedelta(microseconds=filetime / 10)
    except:
        return None


def parse_srum_ese(file_path):
    """
    Parse SRUM ESE database (SRUDB.dat)
    
    Yields network and resource usage events
    """
    if not ESE_AVAILABLE:
        logger.error("pyesedb not available - cannot parse SRUM")
        return
    
    if not os.path.exists(file_path):
        logger.error(f"SRUM file not found: {file_path}")
        return
    
    filename = os.path.basename(file_path)
    
    try:
        # Copy to avoid locking
        import shutil
        import tempfile
        
        with tempfile.NamedTemporaryFile(delete=False, suffix='.dat') as tmp_file:
            temp_path = tmp_file.name
        
        shutil.copy2(file_path, temp_path)
        
        # Open ESE database
        esedb = pyesedb.file()
        esedb.open(temp_path)
        
        logger.info(f"Opened SRUM ESE: {filename} ({esedb.number_of_tables} tables)")
        
        # Look for network data usage table (typically {DD6636C4-8929-4683-974E-22C046A43763})
        for table_index in range(esedb.number_of_tables):
            try:
                table = esedb.get_table(table_index)
                table_name = table.name
                
                # Focus on tables with data (skip system tables)
                if table.number_of_records == 0:
                    continue
                
                logger.info(f"Parsing SRUM table: {table_name} ({table.number_of_records} records)")
                
                # Get column names
                columns = []
                for col_index in range(table.number_of_columns):
                    col = table.get_column(col_index)
                    columns.append({'name': col.name, 'type': col.type})
                
                # Parse records (limit to 1000 per table for performance)
                for record_index in range(min(table.number_of_records, 1000)):
                    try:
                        record = table.get_record(record_index)
                        
                        event = {
                            '@timestamp': datetime.utcnow().isoformat(),
                            'event_type': 'srum_data',
                            'table_name': table_name,
                            'source_file': filename,
                            'artifact_type': 'srum'
                        }
                        
                        # Extract column values
                        for col_index, col_info in enumerate(columns):
                            try:
                                col_name = col_info['name']
                                value = record.get_value_data_as_string(col_index)
                                
                                # Map important SRUM columns
                                if col_name == 'AppId':
                                    event['application_id'] = value
                                elif col_name == 'UserId':
                                    event['user_id'] = value
                                elif col_name in ['BytesSent', 'BytesRecvd']:
                                    try:
                                        event[col_name.lower()] = int(value) if value else 0
                                    except:
                                        pass
                                elif col_name == 'TimeStamp':
                                    # Try to parse as FILETIME
                                    try:
                                        if value and value.isdigit():
                                            dt = filetime_to_datetime(int(value))
                                            if dt:
                                                event['@timestamp'] = dt.isoformat()
                                    except:
                                        pass
                                elif col_name == 'App':
                                    event['application'] = value
                                else:
                                    if value:
                                        event[f'srum_{col_name.lower()}'] = value
                            
                            except:
                                pass
                        
                        # Only yield if meaningful
                        if len(event) > 5:
                            yield event
                    
                    except Exception as e:
                        logger.debug(f"Error parsing SRUM record {record_index}: {e}")
                        continue
            
            except Exception as e:
                logger.error(f"Error parsing SRUM table {table_index}: {e}")
                continue
        
        esedb.close()
        
        # Cleanup
        try:
            os.unlink(temp_path)
        except:
            pass
    
    except Exception as e:
        logger.error(f"Error parsing SRUM {file_path}: {e}")
        import traceback
        traceback.print_exc()


def parse_srum_file(file_path):
    """Parse SRUM database file"""
    filename = os.path.basename(file_path).lower()
    
    if 'srudb.dat' in filename:
        logger.info(f"Detected SRUM database: {filename}")
        return parse_srum_ese(file_path)
    else:
        logger.warning(f"Not a SRUM file: {filename}")
        return iter([])

