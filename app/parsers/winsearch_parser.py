r"""
Windows Search Database Parser
==============================
Parses Windows Search ESE database (Windows.edb)
Location: ProgramData\Microsoft\Search\Data\Applications\Windows\Windows.edb
Routes to: case_X_filesystem index

Extracts:
- Indexed file metadata
- File paths and names
- Last modified times
- File sizes
- Content snippets (if available)
- Email metadata (if Outlook indexed)

Evidence Value:
- Evidence of file existence (even if deleted)
- Email content discovery
- User activity patterns
- Document content without original file
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
    logger.warning("pyesedb not available - Windows Search parsing will be skipped")
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


def parse_windows_search_ese(file_path):
    """
    Parse Windows Search ESE database (Windows.edb)
    
    Yields indexed content entries
    """
    if not ESE_AVAILABLE:
        logger.error("pyesedb not available - cannot parse Windows Search")
        return
    
    if not os.path.exists(file_path):
        logger.error(f"Windows Search file not found: {file_path}")
        return
    
    filename = os.path.basename(file_path)
    
    try:
        import shutil
        import tempfile
        
        with tempfile.NamedTemporaryFile(delete=False, suffix='.edb') as tmp_file:
            temp_path = tmp_file.name
        
        shutil.copy2(file_path, temp_path)
        
        esedb = pyesedb.file()
        esedb.open(temp_path)
        
        logger.info(f"Opened Windows Search ESE: {filename} ({esedb.number_of_tables} tables)")
        
        # Key tables in Windows.edb:
        # - SystemIndex_Gthr: Gathered content
        # - SystemIndex_GthrPth: File paths
        # - SystemIndex_PropertyStore: Property values
        
        target_tables = ['SystemIndex_Gthr', 'SystemIndex_GthrPth', 'SystemIndex_PropertyStore']
        
        for table_index in range(esedb.number_of_tables):
            try:
                table = esedb.get_table(table_index)
                table_name = table.name
                
                if table.number_of_records == 0:
                    continue
                
                # Process specific tables or any with records
                is_target = any(target in table_name for target in target_tables)
                
                if not is_target and table.number_of_records < 100:
                    continue
                
                logger.info(f"Parsing Windows Search table: {table_name} ({table.number_of_records} records)")
                
                # Get column names
                columns = []
                for col_index in range(table.number_of_columns):
                    col = table.get_column(col_index)
                    columns.append({'name': col.name, 'type': col.type})
                
                # Limit records for large tables
                max_records = min(table.number_of_records, 5000)
                
                for record_index in range(max_records):
                    try:
                        record = table.get_record(record_index)
                        
                        event = {
                            '@timestamp': datetime.utcnow().isoformat(),
                            'event_type': 'search_index_entry',
                            'table_name': table_name,
                            'source_file': filename,
                            'artifact_type': 'windows_search'
                        }
                        
                        for col_index, col_info in enumerate(columns):
                            try:
                                col_name = col_info['name']
                                value = record.get_value_data_as_string(col_index)
                                
                                if not value:
                                    continue
                                
                                # Map important columns
                                col_lower = col_name.lower()
                                
                                if col_lower in ['url', 'path', 'filename', 'itemurl']:
                                    event['file_path'] = value
                                elif col_lower in ['name', 'displayname', 'itemname', 'system_itemname']:
                                    event['file_name'] = value
                                elif col_lower in ['size', 'filesize', 'system_size']:
                                    try:
                                        event['file_size'] = int(value)
                                    except:
                                        pass
                                elif col_lower in ['datemodified', 'lastmodified', 'system_datemodified']:
                                    try:
                                        if value.isdigit():
                                            dt = filetime_to_datetime(int(value))
                                            if dt:
                                                event['date_modified'] = dt.isoformat()
                                                event['@timestamp'] = dt.isoformat()
                                    except:
                                        pass
                                elif col_lower in ['datecreated', 'system_datecreated']:
                                    try:
                                        if value.isdigit():
                                            dt = filetime_to_datetime(int(value))
                                            if dt:
                                                event['date_created'] = dt.isoformat()
                                    except:
                                        pass
                                elif col_lower in ['dateaccessed', 'system_dateaccessed']:
                                    try:
                                        if value.isdigit():
                                            dt = filetime_to_datetime(int(value))
                                            if dt:
                                                event['date_accessed'] = dt.isoformat()
                                    except:
                                        pass
                                elif col_lower in ['itemtype', 'type', 'system_itemtype']:
                                    event['item_type'] = value
                                elif col_lower in ['author', 'system_author']:
                                    event['author'] = value
                                elif col_lower in ['title', 'system_title']:
                                    event['title'] = value
                                elif col_lower in ['subject', 'system_subject']:
                                    event['subject'] = value
                                elif col_lower in ['keywords', 'system_keywords']:
                                    event['keywords'] = value
                                elif col_lower in ['contenttye', 'mimetype', 'system_contenttype']:
                                    event['content_type'] = value
                                elif col_lower in ['folderpath', 'directory']:
                                    event['folder_path'] = value
                                elif col_lower in ['extension', 'fileextension']:
                                    event['extension'] = value
                                # Email-specific fields
                                elif col_lower in ['from', 'system_message_fromnme']:
                                    event['email_from'] = value
                                elif col_lower in ['to', 'system_message_toname']:
                                    event['email_to'] = value
                                elif col_lower in ['cc', 'system_message_ccname']:
                                    event['email_cc'] = value
                                elif col_lower in ['datesent', 'system_message_datesent']:
                                    try:
                                        if value.isdigit():
                                            dt = filetime_to_datetime(int(value))
                                            if dt:
                                                event['email_date_sent'] = dt.isoformat()
                                    except:
                                        pass
                                # Store other potentially useful fields
                                elif len(value) < 500 and len(value) > 0:
                                    # Avoid very long values
                                    safe_name = col_name.replace(' ', '_').replace('.', '_').lower()
                                    event[f'search_{safe_name}'] = value
                            
                            except:
                                pass
                        
                        # Only yield if we have meaningful data
                        if len(event) > 5:
                            yield event
                    
                    except Exception as e:
                        logger.debug(f"Error parsing Search record {record_index}: {e}")
                        continue
            
            except Exception as e:
                logger.error(f"Error parsing Search table {table_index}: {e}")
                continue
        
        esedb.close()
        
        try:
            os.unlink(temp_path)
        except:
            pass
    
    except Exception as e:
        logger.error(f"Error parsing Windows Search {file_path}: {e}")
        import traceback
        traceback.print_exc()


def parse_windows_search_file(file_path):
    """Parse Windows Search database file"""
    filename = os.path.basename(file_path).lower()
    
    if filename == 'windows.edb' or 'search' in filename.lower():
        logger.info(f"Detected Windows Search database: {filename}")
        return parse_windows_search_ese(file_path)
    else:
        logger.warning(f"Not a Windows Search file: {filename}")
        return iter([])
