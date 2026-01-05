r"""
Windows Notifications Parser
============================
Parses Windows Push Notifications database (wpndatabase.db)
Location: Users\*\AppData\Local\Microsoft\Windows\Notifications\wpndatabase.db
Routes to: case_X_events index

Extracts:
- Push notification history
- Application notifications
- Notification content/payloads
- Timestamps
- Notification badges
- Toast notifications

Evidence Value:
- Communication evidence (messaging apps)
- Email arrival notifications
- Application activity
- Deleted message artifacts
"""

import os
import sqlite3
import logging
import json
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

# Windows timestamp epoch
WINDOWS_EPOCH = datetime(1601, 1, 1)


def windows_timestamp_to_datetime(timestamp):
    """Convert Windows timestamp (100-ns intervals since 1601) to datetime"""
    try:
        if not timestamp or timestamp == 0:
            return None
        return WINDOWS_EPOCH + timedelta(microseconds=timestamp / 10)
    except:
        return None


def parse_notification_handler(handler_id, handlers_map):
    """Resolve handler ID to application name"""
    return handlers_map.get(handler_id, f'Handler_{handler_id}')


def parse_notifications_db(file_path):
    """
    Parse Windows Notifications database (wpndatabase.db)
    
    Yields notification events
    """
    if not os.path.exists(file_path):
        logger.error(f"Notifications DB file not found: {file_path}")
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
        
        # Build handler ID to name mapping
        handlers_map = {}
        try:
            cursor.execute("SELECT RecordId, PrimaryId, CreatedTime, ModifiedTime FROM NotificationHandler")
            for row in cursor.fetchall():
                handlers_map[row['RecordId']] = row['PrimaryId']
        except sqlite3.OperationalError:
            logger.debug("NotificationHandler table not found")
        
        # Parse Notification table
        try:
            cursor.execute("""
                SELECT 
                    Id,
                    HandlerId,
                    Type,
                    Payload,
                    PayloadType,
                    Tag,
                    Group,
                    ExpiresOnReboot,
                    ArrivalTime,
                    ExpirationTime,
                    BootId
                FROM Notification
                ORDER BY ArrivalTime DESC
            """)
            
            for row in cursor.fetchall():
                arrival_time = windows_timestamp_to_datetime(row['ArrivalTime'])
                expiration_time = windows_timestamp_to_datetime(row['ExpirationTime'])
                
                handler_name = parse_notification_handler(row['HandlerId'], handlers_map)
                
                event = {
                    '@timestamp': arrival_time.isoformat() if arrival_time else datetime.utcnow().isoformat(),
                    'event_type': 'notification',
                    'notification_id': row['Id'],
                    'handler_id': row['HandlerId'],
                    'application': handler_name,
                    'notification_type': row['Type'],
                    'payload_type': row['PayloadType'],
                    'source_file': filename,
                    'artifact_type': 'notifications'
                }
                
                if row['Tag']:
                    event['tag'] = row['Tag']
                
                if row['Group']:
                    event['group'] = row['Group']
                
                if arrival_time:
                    event['arrival_time'] = arrival_time.isoformat()
                
                if expiration_time:
                    event['expiration_time'] = expiration_time.isoformat()
                
                event['expires_on_reboot'] = bool(row['ExpiresOnReboot'])
                
                # Parse payload (usually XML or JSON)
                if row['Payload']:
                    try:
                        payload = row['Payload']
                        
                        # Try to decode as bytes if needed
                        if isinstance(payload, bytes):
                            payload = payload.decode('utf-8', errors='ignore')
                        
                        # Check if it's XML (toast notification)
                        if payload.strip().startswith('<'):
                            event['payload_format'] = 'xml'
                            # Extract text from XML (simplified)
                            import re
                            texts = re.findall(r'<text[^>]*>([^<]+)</text>', payload)
                            if texts:
                                event['notification_text'] = ' | '.join(texts)
                            
                            # Extract image sources
                            images = re.findall(r'<image[^>]*src="([^"]+)"', payload)
                            if images:
                                event['notification_images'] = images
                            
                            # Store truncated raw payload
                            if len(payload) < 2000:
                                event['payload_xml'] = payload
                        
                        # Check if it's JSON
                        elif payload.strip().startswith('{'):
                            event['payload_format'] = 'json'
                            try:
                                payload_json = json.loads(payload)
                                
                                # Extract common fields
                                if payload_json.get('title'):
                                    event['notification_title'] = payload_json['title']
                                if payload_json.get('body'):
                                    event['notification_body'] = payload_json['body']
                                if payload_json.get('text'):
                                    event['notification_text'] = payload_json['text']
                                
                                # Store full payload if small
                                if len(payload) < 2000:
                                    event['payload_json'] = payload_json
                            except:
                                event['payload_raw'] = payload[:1000]
                        
                        else:
                            event['payload_format'] = 'other'
                            if len(payload) < 1000:
                                event['payload_raw'] = payload
                    
                    except Exception as e:
                        logger.debug(f"Error parsing notification payload: {e}")
                
                yield event
        
        except sqlite3.OperationalError as e:
            logger.error(f"Error querying Notification table: {e}")
        
        # Parse WNSPushChannel table (push notification channels)
        try:
            cursor.execute("""
                SELECT 
                    ChannelId,
                    HandlerId,
                    Uri,
                    CreatedTime,
                    ExpirationTime,
                    PrimaryId
                FROM WNSPushChannel
                ORDER BY CreatedTime DESC
            """)
            
            for row in cursor.fetchall():
                created_time = windows_timestamp_to_datetime(row['CreatedTime'])
                expiration_time = windows_timestamp_to_datetime(row['ExpirationTime'])
                
                handler_name = parse_notification_handler(row['HandlerId'], handlers_map)
                
                event = {
                    '@timestamp': created_time.isoformat() if created_time else datetime.utcnow().isoformat(),
                    'event_type': 'notification_channel',
                    'channel_id': row['ChannelId'],
                    'handler_id': row['HandlerId'],
                    'application': handler_name,
                    'channel_uri': row['Uri'],
                    'primary_id': row['PrimaryId'],
                    'source_file': filename,
                    'artifact_type': 'notifications'
                }
                
                if created_time:
                    event['created_time'] = created_time.isoformat()
                
                if expiration_time:
                    event['expiration_time'] = expiration_time.isoformat()
                
                yield event
        
        except sqlite3.OperationalError as e:
            logger.debug(f"WNSPushChannel table not found: {e}")
        
        # Parse HandlerAssets table (app icons/badges)
        try:
            cursor.execute("""
                SELECT 
                    HandlerId,
                    AssetType,
                    AssetValue,
                    AssetFileSize
                FROM HandlerAssets
            """)
            
            for row in cursor.fetchall():
                handler_name = parse_notification_handler(row['HandlerId'], handlers_map)
                
                event = {
                    '@timestamp': datetime.utcnow().isoformat(),
                    'event_type': 'notification_asset',
                    'handler_id': row['HandlerId'],
                    'application': handler_name,
                    'asset_type': row['AssetType'],
                    'asset_value': row['AssetValue'],
                    'asset_size': row['AssetFileSize'],
                    'source_file': filename,
                    'artifact_type': 'notifications'
                }
                
                yield event
        
        except sqlite3.OperationalError as e:
            logger.debug(f"HandlerAssets table not found: {e}")
        
        conn.close()
        
        try:
            os.unlink(temp_db_path)
        except:
            pass
    
    except Exception as e:
        logger.error(f"Error parsing Notifications DB {file_path}: {e}")
        import traceback
        traceback.print_exc()


def parse_notifications_file(file_path):
    """Parse Windows Notifications database file"""
    filename = os.path.basename(file_path).lower()
    
    if 'wpndatabase' in filename and filename.endswith('.db'):
        logger.info(f"Detected Windows Notifications database: {filename}")
        return parse_notifications_db(file_path)
    elif 'notification' in filename and filename.endswith('.db'):
        logger.info(f"Detected possible Notifications database: {filename}")
        return parse_notifications_db(file_path)
    else:
        logger.warning(f"Not a Notifications file: {filename}")
        return iter([])
