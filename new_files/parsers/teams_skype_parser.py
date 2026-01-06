"""
Teams/Skype Parser
==================
Parses Microsoft Teams and Skype communication databases
Location: 
  Teams: Users\*\AppData\Roaming\Microsoft\Teams\
  Skype: Users\*\AppData\Roaming\Microsoft\Skype for Desktop\
         Users\*\AppData\Roaming\Skype\<username>\main.db
Routes to: case_X_events index

Extracts:
- Chat messages
- Conversations/threads
- File transfers
- Call history
- Contact lists
- Meeting information

Evidence Value:
- Communication evidence
- Collaboration on malicious activity
- File sharing evidence
- Timeline of user activity
- Business correspondence
"""

import os
import sqlite3
import json
import logging
from datetime import datetime

logger = logging.getLogger(__name__)


def unix_ms_to_datetime(timestamp_ms):
    """Convert Unix millisecond timestamp to datetime"""
    try:
        if not timestamp_ms or timestamp_ms == 0:
            return None
        return datetime.utcfromtimestamp(timestamp_ms / 1000.0)
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


def parse_skype_main_db(file_path):
    """
    Parse Skype main.db SQLite database
    
    Yields message and call events
    """
    if not os.path.exists(file_path):
        logger.error(f"Skype DB not found: {file_path}")
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
        
        # Parse Messages table
        try:
            cursor.execute("""
                SELECT 
                    id,
                    convo_id,
                    chatname,
                    author,
                    from_dispname,
                    body_xml,
                    timestamp,
                    type,
                    sending_status,
                    consumption_status,
                    edited_by,
                    edited_timestamp,
                    remote_id
                FROM Messages
                ORDER BY timestamp DESC
                LIMIT 10000
            """)
            
            for row in cursor.fetchall():
                msg_time = unix_to_datetime(row['timestamp'])
                
                event = {
                    '@timestamp': msg_time.isoformat() if msg_time else datetime.utcnow().isoformat(),
                    'event_type': 'skype_message',
                    'message_id': row['id'],
                    'conversation_id': row['convo_id'],
                    'chat_name': row['chatname'],
                    'author': row['author'],
                    'author_display_name': row['from_dispname'],
                    'message_type': row['type'],
                    'source_file': filename,
                    'artifact_type': 'skype'
                }
                
                # Parse message body (may contain XML)
                if row['body_xml']:
                    body = row['body_xml']
                    # Strip XML tags for plain text
                    import re
                    plain_text = re.sub(r'<[^>]+>', '', body)
                    event['message_body'] = plain_text[:2000]
                    event['message_body_raw'] = body[:2000] if body != plain_text else None
                
                if row['edited_by']:
                    event['edited_by'] = row['edited_by']
                    edit_time = unix_to_datetime(row['edited_timestamp'])
                    if edit_time:
                        event['edited_time'] = edit_time.isoformat()
                
                yield event
        
        except sqlite3.OperationalError as e:
            logger.debug(f"Messages table not found or error: {e}")
        
        # Parse Calls table
        try:
            cursor.execute("""
                SELECT 
                    id,
                    begin_timestamp,
                    host_identity,
                    duration,
                    is_incoming,
                    current_video_audience,
                    name
                FROM Calls
                ORDER BY begin_timestamp DESC
                LIMIT 1000
            """)
            
            for row in cursor.fetchall():
                call_time = unix_to_datetime(row['begin_timestamp'])
                
                event = {
                    '@timestamp': call_time.isoformat() if call_time else datetime.utcnow().isoformat(),
                    'event_type': 'skype_call',
                    'call_id': row['id'],
                    'host': row['host_identity'],
                    'duration_seconds': row['duration'],
                    'is_incoming': bool(row['is_incoming']),
                    'call_name': row['name'],
                    'source_file': filename,
                    'artifact_type': 'skype'
                }
                
                if row['current_video_audience']:
                    event['video_enabled'] = True
                
                yield event
        
        except sqlite3.OperationalError as e:
            logger.debug(f"Calls table not found or error: {e}")
        
        # Parse Contacts table
        try:
            cursor.execute("""
                SELECT 
                    skypename,
                    displayname,
                    fullname,
                    phone_home,
                    phone_mobile,
                    phone_office,
                    emails,
                    city,
                    country,
                    about,
                    is_blocked
                FROM Contacts
                LIMIT 1000
            """)
            
            for row in cursor.fetchall():
                event = {
                    '@timestamp': datetime.utcnow().isoformat(),
                    'event_type': 'skype_contact',
                    'skype_name': row['skypename'],
                    'display_name': row['displayname'],
                    'full_name': row['fullname'],
                    'source_file': filename,
                    'artifact_type': 'skype'
                }
                
                if row['emails']:
                    event['emails'] = row['emails']
                if row['phone_mobile']:
                    event['phone_mobile'] = row['phone_mobile']
                if row['city']:
                    event['city'] = row['city']
                if row['country']:
                    event['country'] = row['country']
                if row['is_blocked']:
                    event['is_blocked'] = True
                
                yield event
        
        except sqlite3.OperationalError as e:
            logger.debug(f"Contacts table not found or error: {e}")
        
        # Parse Transfers (file transfers)
        try:
            cursor.execute("""
                SELECT 
                    id,
                    partner_handle,
                    partner_dispname,
                    filepath,
                    filename,
                    filesize,
                    starttime,
                    finishtime,
                    status,
                    type
                FROM Transfers
                ORDER BY starttime DESC
                LIMIT 1000
            """)
            
            for row in cursor.fetchall():
                start_time = unix_to_datetime(row['starttime'])
                
                event = {
                    '@timestamp': start_time.isoformat() if start_time else datetime.utcnow().isoformat(),
                    'event_type': 'skype_transfer',
                    'transfer_id': row['id'],
                    'partner': row['partner_handle'],
                    'partner_name': row['partner_dispname'],
                    'file_path': row['filepath'],
                    'file_name': row['filename'],
                    'file_size': row['filesize'],
                    'status': row['status'],
                    'transfer_type': row['type'],
                    'source_file': filename,
                    'artifact_type': 'skype'
                }
                
                finish_time = unix_to_datetime(row['finishtime'])
                if finish_time:
                    event['finish_time'] = finish_time.isoformat()
                
                yield event
        
        except sqlite3.OperationalError as e:
            logger.debug(f"Transfers table not found or error: {e}")
        
        conn.close()
        
        try:
            os.unlink(temp_db_path)
        except:
            pass
    
    except Exception as e:
        logger.error(f"Error parsing Skype DB {file_path}: {e}")
        import traceback
        traceback.print_exc()


def parse_teams_leveldb(file_path):
    """
    Parse Teams LevelDB storage
    
    Teams stores data in LevelDB format which is more complex.
    This extracts what it can from the raw files.
    """
    if not os.path.exists(file_path):
        logger.error(f"Teams file not found: {file_path}")
        return
    
    filename = os.path.basename(file_path)
    
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
        
        logger.info(f"Scanning Teams file: {filename} ({len(data)} bytes)")
        
        # Look for JSON objects in the data
        import re
        
        # Find potential JSON objects
        json_pattern = rb'\{[^{}]{10,5000}\}'
        
        seen_ids = set()
        
        for match in re.finditer(json_pattern, data):
            try:
                json_str = match.group().decode('utf-8', errors='ignore')
                obj = json.loads(json_str)
                
                # Look for message-like objects
                if isinstance(obj, dict):
                    # Check for message indicators
                    is_message = any(key in obj for key in ['messageId', 'content', 'from', 'conversationId', 'clientmessageid'])
                    
                    if is_message:
                        msg_id = obj.get('messageId') or obj.get('clientmessageid') or obj.get('id')
                        
                        if msg_id and msg_id not in seen_ids:
                            seen_ids.add(msg_id)
                            
                            event = {
                                '@timestamp': datetime.utcnow().isoformat(),
                                'event_type': 'teams_message',
                                'message_id': msg_id,
                                'source_file': filename,
                                'artifact_type': 'teams'
                            }
                            
                            # Extract available fields
                            if obj.get('content'):
                                event['message_content'] = obj['content'][:2000]
                            if obj.get('from'):
                                event['from'] = obj['from']
                            if obj.get('conversationId'):
                                event['conversation_id'] = obj['conversationId']
                            if obj.get('composeTime'):
                                event['compose_time'] = obj['composeTime']
                                try:
                                    event['@timestamp'] = obj['composeTime']
                                except:
                                    pass
                            
                            yield event
                    
                    # Check for user/contact objects
                    is_contact = any(key in obj for key in ['displayName', 'email', 'userPrincipalName'])
                    
                    if is_contact and not is_message:
                        user_id = obj.get('id') or obj.get('userPrincipalName')
                        
                        if user_id and user_id not in seen_ids:
                            seen_ids.add(user_id)
                            
                            event = {
                                '@timestamp': datetime.utcnow().isoformat(),
                                'event_type': 'teams_contact',
                                'user_id': user_id,
                                'display_name': obj.get('displayName'),
                                'email': obj.get('email') or obj.get('userPrincipalName'),
                                'source_file': filename,
                                'artifact_type': 'teams'
                            }
                            
                            yield event
            
            except json.JSONDecodeError:
                pass
            except:
                pass
        
        logger.info(f"Extracted {len(seen_ids)} unique items from {filename}")
    
    except Exception as e:
        logger.error(f"Error parsing Teams file {file_path}: {e}")


def parse_teams_sqlite(file_path):
    """
    Parse Teams IndexedDB SQLite wrapper
    Some Teams data is stored in SQLite databases
    """
    if not os.path.exists(file_path):
        logger.error(f"Teams SQLite not found: {file_path}")
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
        
        logger.info(f"Teams SQLite tables: {tables}")
        
        # Try to extract data from each table
        for table in tables:
            try:
                cursor.execute(f"SELECT * FROM {table} LIMIT 100")
                
                for row in cursor.fetchall():
                    row_dict = dict(row)
                    
                    # Look for JSON blobs in values
                    for key, value in row_dict.items():
                        if isinstance(value, str) and value.startswith('{'):
                            try:
                                obj = json.loads(value)
                                
                                event = {
                                    '@timestamp': datetime.utcnow().isoformat(),
                                    'event_type': 'teams_data',
                                    'table_name': table,
                                    'data': obj,
                                    'source_file': filename,
                                    'artifact_type': 'teams'
                                }
                                
                                yield event
                            except:
                                pass
            
            except sqlite3.OperationalError:
                continue
        
        conn.close()
        
        try:
            os.unlink(temp_db_path)
        except:
            pass
    
    except Exception as e:
        logger.error(f"Error parsing Teams SQLite {file_path}: {e}")


def parse_teams_skype_file(file_path):
    """Parse Teams or Skype file (auto-detect)"""
    filename = os.path.basename(file_path).lower()
    parent_dir = os.path.basename(os.path.dirname(file_path)).lower()
    
    # Skype main.db
    if filename == 'main.db' and 'skype' in parent_dir:
        logger.info(f"Detected Skype main.db: {filename}")
        return parse_skype_main_db(file_path)
    
    # Teams SQLite
    if filename.endswith('.db') and 'teams' in parent_dir:
        logger.info(f"Detected Teams SQLite: {filename}")
        return parse_teams_sqlite(file_path)
    
    # Teams LevelDB files
    if filename.endswith('.ldb') or filename.endswith('.log'):
        logger.info(f"Detected Teams LevelDB: {filename}")
        return parse_teams_leveldb(file_path)
    
    # Try generic parsing based on content
    try:
        # Check if SQLite
        with open(file_path, 'rb') as f:
            header = f.read(16)
        
        if header.startswith(b'SQLite format 3'):
            logger.info(f"Detected SQLite file: {filename}")
            return parse_skype_main_db(file_path)  # Try Skype parser
    except:
        pass
    
    logger.warning(f"Unknown Teams/Skype file format: {filename}")
    return iter([])
