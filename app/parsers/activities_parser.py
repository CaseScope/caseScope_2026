r"""
ActivitiesCache Parser (Windows Timeline)
=========================================
Parses Windows Timeline database (ActivitiesCache.db)
Location: Users\*\AppData\Local\ConnectedDevicesPlatform\*\ActivitiesCache.db
Routes to: case_X_execution index

Extracts:
- Application usage history
- File open activities
- Focus time per application
- Clipboard history (if enabled)
- Activity timestamps
- Device sync information

Evidence Value:
- User activity patterns
- Application usage timeline
- Files accessed with timestamps
- Cross-device activity (if synced)
"""

import os
import sqlite3
import logging
import json
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

# Windows timestamp epoch adjustment
WINDOWS_EPOCH = datetime(1601, 1, 1)

# Activity types
ACTIVITY_TYPES = {
    5: 'App_InFocus',
    6: 'App_Launch', 
    10: 'Clipboard',
    16: 'Copy',
    17: 'Cut',
    18: 'Paste'
}


def windows_timestamp_to_datetime(timestamp):
    """Convert Windows timestamp (100-ns intervals since 1601) to datetime"""
    try:
        if not timestamp or timestamp == 0:
            return None
        # Convert 100-nanosecond intervals to microseconds
        return WINDOWS_EPOCH + timedelta(microseconds=timestamp / 10)
    except:
        return None


def unix_timestamp_to_datetime(timestamp):
    """Convert Unix timestamp to datetime"""
    try:
        if not timestamp or timestamp == 0:
            return None
        return datetime.utcfromtimestamp(timestamp)
    except:
        return None


def parse_activities_cache(file_path):
    """
    Parse ActivitiesCache.db (Windows Timeline)
    
    Yields activity events
    """
    if not os.path.exists(file_path):
        logger.error(f"ActivitiesCache file not found: {file_path}")
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
        
        # Parse Activity table
        try:
            cursor.execute("""
                SELECT 
                    Id,
                    AppId,
                    PackageIdHash,
                    AppActivityId,
                    ActivityType,
                    ActivityStatus,
                    Priority,
                    IsLocalOnly,
                    Tag,
                    Group,
                    MatchId,
                    LastModifiedTime,
                    ExpirationTime,
                    Payload,
                    OriginalPayload,
                    ClipboardPayload,
                    StartTime,
                    EndTime,
                    LastModifiedOnClient,
                    OriginalLastModifiedOnClient,
                    ETag,
                    PlatformDeviceId
                FROM Activity
                ORDER BY LastModifiedTime DESC
            """)
            
            for row in cursor.fetchall():
                # Parse timestamps
                last_modified = windows_timestamp_to_datetime(row['LastModifiedTime'])
                start_time = windows_timestamp_to_datetime(row['StartTime'])
                end_time = windows_timestamp_to_datetime(row['EndTime'])
                
                # Use best available timestamp
                best_time = start_time or last_modified or datetime.utcnow()
                
                activity_type = ACTIVITY_TYPES.get(row['ActivityType'], f"Type_{row['ActivityType']}")
                
                event = {
                    '@timestamp': best_time.isoformat() if best_time else datetime.utcnow().isoformat(),
                    'event_type': 'timeline_activity',
                    'activity_id': row['Id'],
                    'activity_type': activity_type,
                    'activity_type_code': row['ActivityType'],
                    'activity_status': row['ActivityStatus'],
                    'app_id': row['AppId'],
                    'source_file': filename,
                    'artifact_type': 'activities_cache'
                }
                
                if start_time:
                    event['start_time'] = start_time.isoformat()
                if end_time:
                    event['end_time'] = end_time.isoformat()
                    # Calculate duration
                    if start_time and end_time > start_time:
                        duration = (end_time - start_time).total_seconds()
                        event['duration_seconds'] = duration
                        event['duration_minutes'] = round(duration / 60, 2)
                
                if last_modified:
                    event['last_modified'] = last_modified.isoformat()
                
                if row['Tag']:
                    event['tag'] = row['Tag']
                
                if row['PlatformDeviceId']:
                    event['device_id'] = row['PlatformDeviceId']
                
                # Parse JSON payload
                if row['Payload']:
                    try:
                        payload = json.loads(row['Payload'])
                        
                        if payload.get('displayText'):
                            event['display_text'] = payload['displayText']
                        if payload.get('description'):
                            event['description'] = payload['description']
                        if payload.get('appDisplayName'):
                            event['app_display_name'] = payload['appDisplayName']
                        if payload.get('activationUri'):
                            event['activation_uri'] = payload['activationUri']
                        if payload.get('contentUri'):
                            event['content_uri'] = payload['contentUri']
                        if payload.get('backgroundColor'):
                            event['background_color'] = payload['backgroundColor']
                    except:
                        # Store raw payload if not valid JSON
                        if len(row['Payload']) < 1000:
                            event['payload_raw'] = row['Payload']
                
                # Parse clipboard payload
                if row['ClipboardPayload']:
                    try:
                        clipboard = json.loads(row['ClipboardPayload'])
                        event['clipboard_content'] = clipboard
                    except:
                        pass
                
                yield event
        
        except sqlite3.OperationalError as e:
            logger.error(f"Error querying Activity table: {e}")
        
        # Parse ActivityOperation table (sync operations)
        try:
            cursor.execute("""
                SELECT 
                    OperationOrder,
                    AppId,
                    ActivityType,
                    LastModifiedTime,
                    OperationType,
                    Id
                FROM ActivityOperation
                ORDER BY LastModifiedTime DESC
                LIMIT 1000
            """)
            
            for row in cursor.fetchall():
                last_modified = windows_timestamp_to_datetime(row['LastModifiedTime'])
                activity_type = ACTIVITY_TYPES.get(row['ActivityType'], f"Type_{row['ActivityType']}")
                
                event = {
                    '@timestamp': last_modified.isoformat() if last_modified else datetime.utcnow().isoformat(),
                    'event_type': 'timeline_operation',
                    'operation_id': row['Id'],
                    'operation_order': row['OperationOrder'],
                    'operation_type': row['OperationType'],
                    'activity_type': activity_type,
                    'app_id': row['AppId'],
                    'source_file': filename,
                    'artifact_type': 'activities_cache'
                }
                
                yield event
        
        except sqlite3.OperationalError as e:
            logger.debug(f"ActivityOperation table not found or error: {e}")
        
        conn.close()
        
        try:
            os.unlink(temp_db_path)
        except:
            pass
    
    except Exception as e:
        logger.error(f"Error parsing ActivitiesCache {file_path}: {e}")
        import traceback
        traceback.print_exc()


def parse_activities_cache_file(file_path):
    """Parse ActivitiesCache database file"""
    filename = os.path.basename(file_path).lower()
    
    if 'activitiescache' in filename and filename.endswith('.db'):
        logger.info(f"Detected ActivitiesCache database: {filename}")
        return parse_activities_cache(file_path)
    else:
        logger.warning(f"Not an ActivitiesCache file: {filename}")
        return iter([])
