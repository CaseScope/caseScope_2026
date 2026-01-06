"""
OneDrive/Cloud Storage Parser
=============================
Parses OneDrive sync logs and databases
Location: 
  Users\*\AppData\Local\Microsoft\OneDrive\logs\
  Users\*\AppData\Local\Microsoft\OneDrive\settings\
  Users\*\OneDrive\ (sync folder)
Routes to: case_X_filesystem index

Extracts:
- Synced files list
- Sync timestamps
- File deletions
- Shared files
- Account information
- Sync errors

Evidence Value:
- Data exfiltration to cloud
- File access history
- Deleted/synced files
- Business vs personal OneDrive
- Timeline of cloud activity
"""

import os
import sqlite3
import json
import re
import logging
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

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


def unix_to_datetime(timestamp):
    """Convert Unix timestamp to datetime"""
    try:
        if not timestamp or timestamp == 0:
            return None
        return datetime.utcfromtimestamp(timestamp)
    except:
        return None


def parse_onedrive_sync_log(file_path):
    """
    Parse OneDrive sync log files (.odl, .odlgz, .odlsent)
    
    These contain sync operations and file changes
    """
    if not os.path.exists(file_path):
        logger.error(f"OneDrive log not found: {file_path}")
        return
    
    filename = os.path.basename(file_path)
    
    try:
        # Handle compressed logs
        if filename.endswith('.odlgz'):
            import gzip
            with gzip.open(file_path, 'rt', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        else:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        
        logger.info(f"Parsing OneDrive log: {filename} ({len(content)} chars)")
        
        # OneDrive logs are structured, look for key patterns
        
        # File operation patterns
        file_op_pattern = re.compile(
            r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[^\s]*)\s+.*?(Upload|Download|Delete|Create|Rename|Move).*?"([^"]+)"',
            re.IGNORECASE
        )
        
        for match in file_op_pattern.finditer(content):
            timestamp_str = match.group(1)
            operation = match.group(2)
            file_path_found = match.group(3)
            
            try:
                timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
            except:
                timestamp = datetime.utcnow()
            
            event = {
                '@timestamp': timestamp.isoformat(),
                'event_type': 'onedrive_file_operation',
                'operation': operation.lower(),
                'file_path': file_path_found,
                'source_file': filename,
                'artifact_type': 'onedrive'
            }
            
            yield event
        
        # Sync status patterns
        sync_pattern = re.compile(
            r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[^\s]*)\s+.*?(SyncComplete|SyncStart|Error|Warning).*?(\{[^}]+\})?',
            re.IGNORECASE
        )
        
        for match in sync_pattern.finditer(content):
            timestamp_str = match.group(1)
            status = match.group(2)
            
            try:
                timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
            except:
                timestamp = datetime.utcnow()
            
            event = {
                '@timestamp': timestamp.isoformat(),
                'event_type': 'onedrive_sync_status',
                'status': status.lower(),
                'source_file': filename,
                'artifact_type': 'onedrive'
            }
            
            # Try to extract JSON details
            if match.group(3):
                try:
                    details = json.loads(match.group(3))
                    event['details'] = details
                except:
                    pass
            
            yield event
        
        # Account patterns
        account_pattern = re.compile(
            r'(cid|userId|email|account)["\s:=]+([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+|[0-9a-f]{16})',
            re.IGNORECASE
        )
        
        seen_accounts = set()
        for match in account_pattern.finditer(content):
            account_type = match.group(1).lower()
            account_value = match.group(2)
            
            if account_value not in seen_accounts:
                seen_accounts.add(account_value)
                
                event = {
                    '@timestamp': datetime.utcnow().isoformat(),
                    'event_type': 'onedrive_account',
                    'account_type': account_type,
                    'account_value': account_value,
                    'source_file': filename,
                    'artifact_type': 'onedrive'
                }
                
                yield event
    
    except Exception as e:
        logger.error(f"Error parsing OneDrive log {file_path}: {e}")
        import traceback
        traceback.print_exc()


def parse_onedrive_settings_dat(file_path):
    """
    Parse OneDrive settings .dat files
    
    Contains account configuration and sync settings
    """
    if not os.path.exists(file_path):
        logger.error(f"OneDrive settings not found: {file_path}")
        return
    
    filename = os.path.basename(file_path)
    
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
        
        logger.info(f"Parsing OneDrive settings: {filename} ({len(data)} bytes)")
        
        # Extract strings from binary data
        strings = []
        
        # ASCII strings
        ascii_pattern = rb'[\x20-\x7e]{8,}'
        for match in re.finditer(ascii_pattern, data):
            try:
                s = match.group().decode('ascii')
                strings.append(s)
            except:
                pass
        
        # Unicode strings
        unicode_pattern = rb'(?:[\x20-\x7e]\x00){8,}'
        for match in re.finditer(unicode_pattern, data):
            try:
                s = match.group().decode('utf-16-le')
                strings.append(s)
            except:
                pass
        
        # Look for interesting data
        emails = []
        paths = []
        urls = []
        
        for s in strings:
            # Emails
            if '@' in s and '.' in s.split('@')[-1]:
                email_match = re.search(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+', s)
                if email_match:
                    emails.append(email_match.group())
            
            # File paths
            if ':\\' in s or s.startswith('/'):
                paths.append(s)
            
            # URLs
            if 'onedrive' in s.lower() or 'sharepoint' in s.lower():
                urls.append(s)
        
        if emails or paths or urls:
            event = {
                '@timestamp': datetime.utcnow().isoformat(),
                'event_type': 'onedrive_settings',
                'source_file': filename,
                'artifact_type': 'onedrive'
            }
            
            if emails:
                event['emails'] = list(set(emails))
            if paths:
                event['sync_paths'] = list(set(paths))[:20]
            if urls:
                event['urls'] = list(set(urls))[:20]
            
            yield event
    
    except Exception as e:
        logger.error(f"Error parsing OneDrive settings {file_path}: {e}")


def parse_onedrive_sqlite(file_path):
    """
    Parse OneDrive SQLite databases
    
    Some OneDrive data is stored in SQLite format
    """
    if not os.path.exists(file_path):
        logger.error(f"OneDrive DB not found: {file_path}")
        return
    
    filename = os.path.basename(file_path)
    
    try:
        import shutil
        import tempfile
        
        with tempfile.NamedTemporaryFile(delete=False, suffix='.db') as tmp_file:
            temp_db_path = tmp_file.name
        
        shutil.copy2(file_path, temp_db_path)
        
        conn = sqlite3.connect(f'file:{temp_db_path}?mode=ro', uri=True)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Get table list
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [row['name'] for row in cursor.fetchall()]
        
        logger.info(f"OneDrive SQLite tables: {tables}")
        
        # Common OneDrive tables
        file_tables = ['files', 'items', 'SyncItems', 'FileInfo']
        
        for table in tables:
            if any(ft.lower() in table.lower() for ft in file_tables):
                try:
                    cursor.execute(f"SELECT * FROM {table} LIMIT 1000")
                    columns = [description[0] for description in cursor.description]
                    
                    for row in cursor.fetchall():
                        event = {
                            '@timestamp': datetime.utcnow().isoformat(),
                            'event_type': 'onedrive_file_entry',
                            'table_name': table,
                            'source_file': filename,
                            'artifact_type': 'onedrive'
                        }
                        
                        row_dict = dict(zip(columns, row))
                        
                        # Map common fields
                        for key, value in row_dict.items():
                            if value is None:
                                continue
                            
                            key_lower = key.lower()
                            
                            if 'name' in key_lower or 'filename' in key_lower:
                                event['file_name'] = str(value)
                            elif 'path' in key_lower:
                                event['file_path'] = str(value)
                            elif 'size' in key_lower:
                                try:
                                    event['file_size'] = int(value)
                                except:
                                    pass
                            elif 'time' in key_lower or 'date' in key_lower:
                                try:
                                    if isinstance(value, int):
                                        dt = unix_to_datetime(value)
                                        if dt:
                                            event[key_lower] = dt.isoformat()
                                    else:
                                        event[key_lower] = str(value)
                                except:
                                    pass
                            elif 'hash' in key_lower or 'etag' in key_lower:
                                event[key_lower] = str(value)
                        
                        if len(event) > 4:  # Has meaningful data
                            yield event
                
                except sqlite3.OperationalError as e:
                    logger.debug(f"Error querying table {table}: {e}")
        
        conn.close()
        
        try:
            os.unlink(temp_db_path)
        except:
            pass
    
    except Exception as e:
        logger.error(f"Error parsing OneDrive SQLite {file_path}: {e}")
        import traceback
        traceback.print_exc()


def parse_onedrive_file(file_path):
    """Parse OneDrive file (auto-detect type)"""
    filename = os.path.basename(file_path).lower()
    
    # Log files
    if filename.endswith(('.odl', '.odlgz', '.odlsent', '.aodl')):
        logger.info(f"Detected OneDrive log: {filename}")
        return parse_onedrive_sync_log(file_path)
    
    # Settings files
    elif filename.endswith('.dat') or filename.endswith('.ini'):
        logger.info(f"Detected OneDrive settings: {filename}")
        return parse_onedrive_settings_dat(file_path)
    
    # SQLite databases
    elif filename.endswith('.db') or filename.endswith('.sqlite'):
        logger.info(f"Detected OneDrive SQLite: {filename}")
        return parse_onedrive_sqlite(file_path)
    
    else:
        # Try to detect file type
        try:
            with open(file_path, 'rb') as f:
                header = f.read(20)
            
            if header.startswith(b'SQLite format 3'):
                return parse_onedrive_sqlite(file_path)
        except:
            pass
        
        logger.warning(f"Unknown OneDrive file format: {filename}")
        return iter([])
