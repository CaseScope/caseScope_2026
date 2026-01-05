r"""
BITS Database Parser
====================
Parses Windows BITS (Background Intelligent Transfer Service) database
Location: ProgramData\Microsoft\Network\Downloader\qmgr.db (Win10+) or qmgr0.dat/qmgr1.dat (older)
Routes to: case_X_network index

Extracts:
- Background transfer jobs
- Download URLs
- Local file destinations  
- Job states and priorities
- Creation/modification times

Evidence Value:
- Malware C2 downloads
- Data exfiltration
- Legitimate but suspicious downloads
- Persistence mechanisms (some malware uses BITS)
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
    logger.warning("pyesedb not available - BITS parsing will be skipped")
    ESE_AVAILABLE = False

# Windows FILETIME epoch
FILETIME_EPOCH = datetime(1601, 1, 1)

# BITS Job states
BITS_JOB_STATES = {
    0: 'QUEUED',
    1: 'CONNECTING',
    2: 'TRANSFERRING',
    3: 'SUSPENDED',
    4: 'ERROR',
    5: 'TRANSIENT_ERROR',
    6: 'TRANSFERRED',
    7: 'ACKNOWLEDGED',
    8: 'CANCELLED'
}

# BITS Job priorities
BITS_JOB_PRIORITIES = {
    0: 'FOREGROUND',
    1: 'HIGH',
    2: 'NORMAL',
    3: 'LOW'
}


def filetime_to_datetime(filetime):
    """Convert Windows FILETIME to Python datetime"""
    try:
        if not filetime or filetime == 0:
            return None
        return FILETIME_EPOCH + timedelta(microseconds=filetime / 10)
    except:
        return None


def parse_bits_ese(file_path):
    """
    Parse BITS ESE database (qmgr.db - Windows 10+)
    
    Yields BITS job events
    """
    if not ESE_AVAILABLE:
        logger.error("pyesedb not available - cannot parse BITS")
        return
    
    if not os.path.exists(file_path):
        logger.error(f"BITS file not found: {file_path}")
        return
    
    filename = os.path.basename(file_path)
    
    try:
        import shutil
        import tempfile
        
        with tempfile.NamedTemporaryFile(delete=False, suffix='.db') as tmp_file:
            temp_path = tmp_file.name
        
        shutil.copy2(file_path, temp_path)
        
        esedb = pyesedb.file()
        esedb.open(temp_path)
        
        logger.info(f"Opened BITS ESE: {filename} ({esedb.number_of_tables} tables)")
        
        # BITS database has tables like: Jobs, Files, etc.
        for table_index in range(esedb.number_of_tables):
            try:
                table = esedb.get_table(table_index)
                table_name = table.name
                
                if table.number_of_records == 0:
                    continue
                
                logger.info(f"Parsing BITS table: {table_name} ({table.number_of_records} records)")
                
                # Get column names
                columns = []
                for col_index in range(table.number_of_columns):
                    col = table.get_column(col_index)
                    columns.append({'name': col.name, 'type': col.type})
                
                # Parse records
                for record_index in range(table.number_of_records):
                    try:
                        record = table.get_record(record_index)
                        
                        event = {
                            '@timestamp': datetime.utcnow().isoformat(),
                            'event_type': 'bits_job',
                            'table_name': table_name,
                            'source_file': filename,
                            'artifact_type': 'bits'
                        }
                        
                        for col_index, col_info in enumerate(columns):
                            try:
                                col_name = col_info['name']
                                value = record.get_value_data_as_string(col_index)
                                
                                # Map important BITS columns
                                if col_name in ['Id', 'JobId', 'GUID']:
                                    event['job_id'] = value
                                elif col_name in ['Name', 'DisplayName', 'JobName']:
                                    event['job_name'] = value
                                elif col_name in ['RemoteUrl', 'Url', 'RemoteName']:
                                    event['remote_url'] = value
                                elif col_name in ['LocalPath', 'LocalName', 'LocalFile']:
                                    event['local_path'] = value
                                elif col_name in ['State', 'JobState']:
                                    try:
                                        state_num = int(value) if value else 0
                                        event['state'] = BITS_JOB_STATES.get(state_num, f'UNKNOWN_{state_num}')
                                        event['state_code'] = state_num
                                    except:
                                        event['state'] = value
                                elif col_name in ['Priority', 'JobPriority']:
                                    try:
                                        priority_num = int(value) if value else 2
                                        event['priority'] = BITS_JOB_PRIORITIES.get(priority_num, f'UNKNOWN_{priority_num}')
                                    except:
                                        event['priority'] = value
                                elif col_name in ['BytesTransferred', 'BytesDone']:
                                    try:
                                        event['bytes_transferred'] = int(value) if value else 0
                                    except:
                                        pass
                                elif col_name in ['BytesTotal', 'TotalBytes']:
                                    try:
                                        event['bytes_total'] = int(value) if value else 0
                                    except:
                                        pass
                                elif col_name in ['CreationTime', 'CreateTime']:
                                    try:
                                        if value and value.isdigit():
                                            dt = filetime_to_datetime(int(value))
                                            if dt:
                                                event['creation_time'] = dt.isoformat()
                                                event['@timestamp'] = dt.isoformat()
                                    except:
                                        pass
                                elif col_name in ['ModificationTime', 'ModTime']:
                                    try:
                                        if value and value.isdigit():
                                            dt = filetime_to_datetime(int(value))
                                            if dt:
                                                event['modification_time'] = dt.isoformat()
                                    except:
                                        pass
                                elif col_name in ['Owner', 'OwnerSid']:
                                    event['owner'] = value
                                elif col_name in ['Command', 'NotifyCommand']:
                                    event['notify_command'] = value
                                else:
                                    if value:
                                        event[f'bits_{col_name.lower()}'] = value
                            
                            except:
                                pass
                        
                        # Only yield if meaningful
                        if len(event) > 5:
                            yield event
                    
                    except Exception as e:
                        logger.debug(f"Error parsing BITS record {record_index}: {e}")
                        continue
            
            except Exception as e:
                logger.error(f"Error parsing BITS table {table_index}: {e}")
                continue
        
        esedb.close()
        
        try:
            os.unlink(temp_path)
        except:
            pass
    
    except Exception as e:
        logger.error(f"Error parsing BITS {file_path}: {e}")
        import traceback
        traceback.print_exc()


def parse_bits_legacy(file_path):
    """
    Parse legacy BITS database (qmgr0.dat/qmgr1.dat - Pre-Win10)
    
    These are custom binary format, not ESE
    """
    if not os.path.exists(file_path):
        logger.error(f"BITS file not found: {file_path}")
        return
    
    filename = os.path.basename(file_path)
    
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
        
        logger.info(f"Parsing legacy BITS file: {filename} ({len(data)} bytes)")
        
        # Legacy format is more complex - look for URL patterns
        # This is a simplified parser that extracts visible strings
        
        import re
        
        # Find HTTP/HTTPS URLs
        url_pattern = rb'https?://[^\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10-\x1f]+'
        urls = re.findall(url_pattern, data)
        
        # Find file paths (C:\, D:\, etc.)
        path_pattern = rb'[A-Za-z]:\\[^\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10-\x1f]+'
        paths = re.findall(path_pattern, data)
        
        seen_urls = set()
        
        for url in urls:
            try:
                url_str = url.decode('utf-8', errors='ignore').strip()
                if url_str and url_str not in seen_urls and len(url_str) > 10:
                    seen_urls.add(url_str)
                    
                    event = {
                        '@timestamp': datetime.utcnow().isoformat(),
                        'event_type': 'bits_job',
                        'remote_url': url_str,
                        'source_file': filename,
                        'artifact_type': 'bits',
                        'parser_note': 'legacy_string_extraction'
                    }
                    
                    yield event
            except:
                pass
        
        seen_paths = set()
        
        for path in paths:
            try:
                path_str = path.decode('utf-8', errors='ignore').strip()
                if path_str and path_str not in seen_paths and len(path_str) > 5:
                    seen_paths.add(path_str)
                    
                    event = {
                        '@timestamp': datetime.utcnow().isoformat(),
                        'event_type': 'bits_file',
                        'local_path': path_str,
                        'source_file': filename,
                        'artifact_type': 'bits',
                        'parser_note': 'legacy_string_extraction'
                    }
                    
                    yield event
            except:
                pass
        
        logger.info(f"Extracted {len(seen_urls)} URLs and {len(seen_paths)} paths from {filename}")
    
    except Exception as e:
        logger.error(f"Error parsing legacy BITS {file_path}: {e}")
        import traceback
        traceback.print_exc()


def parse_bits_file(file_path):
    """Parse BITS database file (auto-detect format)"""
    filename = os.path.basename(file_path).lower()
    
    if filename == 'qmgr.db':
        logger.info(f"Detected BITS ESE database: {filename}")
        return parse_bits_ese(file_path)
    elif filename in ['qmgr0.dat', 'qmgr1.dat']:
        logger.info(f"Detected legacy BITS database: {filename}")
        return parse_bits_legacy(file_path)
    else:
        logger.warning(f"Not a BITS file: {filename}")
        return iter([])
