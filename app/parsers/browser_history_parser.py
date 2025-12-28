"""
Chrome History Parser (Phase 2)
================================
Parses Chrome/Chromium-based browser history SQLite databases
Routes to: case_X_browser index

Supports:
- Chrome History (places.sqlite)
- Chromium-based browsers (Edge, Brave, Opera)
- URLs, visits, downloads
"""

import os
import sqlite3
import logging
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

# Chrome epoch: January 1, 1601 (Windows FILETIME format)
CHROME_EPOCH = datetime(1601, 1, 1)

def chrome_timestamp_to_datetime(chrome_time):
    """
    Convert Chrome timestamp (microseconds since 1601-01-01) to Python datetime
    """
    try:
        if not chrome_time or chrome_time == 0:
            return None
        # Chrome time is in microseconds
        return CHROME_EPOCH + timedelta(microseconds=chrome_time)
    except Exception:
        return None


def parse_chrome_history(file_path):
    """
    Parse Chrome History SQLite database
    
    Yields events in standard format:
    {
        '@timestamp': ISO datetime,
        'event_type': 'browser_history',
        'browser': 'chrome',
        'url': URL visited,
        'title': Page title,
        'visit_count': Number of visits,
        'last_visit_time': Last visit timestamp,
        'source_file': filename
    }
    """
    if not os.path.exists(file_path):
        logger.error(f"Chrome history file not found: {file_path}")
        return
    
    filename = os.path.basename(file_path)
    
    try:
        # Copy database to avoid locking issues
        import shutil
        import tempfile
        
        with tempfile.NamedTemporaryFile(delete=False, suffix='.db') as tmp_file:
            temp_db_path = tmp_file.name
        
        shutil.copy2(file_path, temp_db_path)
        
        conn = sqlite3.connect(f'file:{temp_db_path}?mode=ro', uri=True)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Parse URLs table
        try:
            cursor.execute("""
                SELECT 
                    id,
                    url,
                    title,
                    visit_count,
                    typed_count,
                    last_visit_time,
                    hidden
                FROM urls
                WHERE url IS NOT NULL
                ORDER BY last_visit_time DESC
            """)
            
            for row in cursor.fetchall():
                last_visit = chrome_timestamp_to_datetime(row['last_visit_time'])
                
                event = {
                    '@timestamp': last_visit.isoformat() if last_visit else datetime.utcnow().isoformat(),
                    'event_type': 'browser_url',
                    'browser': 'chrome',
                    'url': row['url'],
                    'title': row['title'] or '',
                    'visit_count': row['visit_count'] or 0,
                    'typed_count': row['typed_count'] or 0,
                    'hidden': bool(row['hidden']),
                    'source_file': filename,
                    'artifact_type': 'browser_history'
                }
                
                yield event
        
        except sqlite3.OperationalError as e:
            logger.error(f"Error querying Chrome URLs table: {e}")
        
        # Parse visits table (detailed visit times)
        try:
            cursor.execute("""
                SELECT 
                    v.id,
                    v.url as url_id,
                    v.visit_time,
                    v.from_visit,
                    v.transition,
                    u.url,
                    u.title
                FROM visits v
                LEFT JOIN urls u ON v.url = u.id
                WHERE v.visit_time IS NOT NULL
                ORDER BY v.visit_time DESC
            """)
            
            for row in cursor.fetchall():
                visit_time = chrome_timestamp_to_datetime(row['visit_time'])
                
                event = {
                    '@timestamp': visit_time.isoformat() if visit_time else datetime.utcnow().isoformat(),
                    'event_type': 'browser_visit',
                    'browser': 'chrome',
                    'url': row['url'] or f"url_id:{row['url_id']}",
                    'title': row['title'] or '',
                    'transition': row['transition'],
                    'from_visit_id': row['from_visit'],
                    'source_file': filename,
                    'artifact_type': 'browser_history'
                }
                
                yield event
        
        except sqlite3.OperationalError as e:
            logger.error(f"Error querying Chrome visits table: {e}")
        
        # Parse downloads table
        try:
            cursor.execute("""
                SELECT 
                    id,
                    current_path,
                    target_path,
                    start_time,
                    end_time,
                    received_bytes,
                    total_bytes,
                    state,
                    danger_type,
                    interrupt_reason,
                    mime_type,
                    original_mime_type
                FROM downloads
                WHERE start_time IS NOT NULL
                ORDER BY start_time DESC
            """)
            
            for row in cursor.fetchall():
                start_time = chrome_timestamp_to_datetime(row['start_time'])
                end_time = chrome_timestamp_to_datetime(row['end_time'])
                
                event = {
                    '@timestamp': start_time.isoformat() if start_time else datetime.utcnow().isoformat(),
                    'event_type': 'browser_download',
                    'browser': 'chrome',
                    'file_path': row['target_path'] or row['current_path'],
                    'start_time': start_time.isoformat() if start_time else None,
                    'end_time': end_time.isoformat() if end_time else None,
                    'received_bytes': row['received_bytes'],
                    'total_bytes': row['total_bytes'],
                    'state': row['state'],
                    'danger_type': row['danger_type'],
                    'interrupt_reason': row['interrupt_reason'],
                    'mime_type': row['mime_type'] or row['original_mime_type'],
                    'source_file': filename,
                    'artifact_type': 'browser_download'
                }
                
                yield event
        
        except sqlite3.OperationalError as e:
            logger.error(f"Error querying Chrome downloads table: {e}")
        
        conn.close()
        
        # Cleanup temp file
        try:
            os.unlink(temp_db_path)
        except:
            pass
    
    except Exception as e:
        logger.error(f"Error parsing Chrome history {file_path}: {e}")
        import traceback
        traceback.print_exc()


def parse_firefox_history(file_path):
    """
    Parse Firefox History (places.sqlite)
    
    Very similar structure to Chrome, with minor differences
    """
    if not os.path.exists(file_path):
        logger.error(f"Firefox history file not found: {file_path}")
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
        
        # Firefox uses microseconds since Unix epoch
        try:
            cursor.execute("""
                SELECT 
                    p.id,
                    p.url,
                    p.title,
                    p.visit_count,
                    p.hidden,
                    p.last_visit_date
                FROM moz_places p
                WHERE p.url IS NOT NULL
                ORDER BY p.last_visit_date DESC
            """)
            
            for row in cursor.fetchall():
                # Firefox timestamps are in microseconds since Unix epoch
                if row['last_visit_date']:
                    last_visit = datetime.utcfromtimestamp(row['last_visit_date'] / 1000000.0)
                else:
                    last_visit = None
                
                event = {
                    '@timestamp': last_visit.isoformat() if last_visit else datetime.utcnow().isoformat(),
                    'event_type': 'browser_url',
                    'browser': 'firefox',
                    'url': row['url'],
                    'title': row['title'] or '',
                    'visit_count': row['visit_count'] or 0,
                    'hidden': bool(row['hidden']),
                    'source_file': filename,
                    'artifact_type': 'browser_history'
                }
                
                yield event
        
        except sqlite3.OperationalError as e:
            logger.error(f"Error querying Firefox places table: {e}")
        
        conn.close()
        
        # Cleanup
        try:
            os.unlink(temp_db_path)
        except:
            pass
    
    except Exception as e:
        logger.error(f"Error parsing Firefox history {file_path}: {e}")
        import traceback
        traceback.print_exc()


def parse_browser_history_file(file_path):
    """
    Auto-detect and parse browser history file
    Supports: Chrome, Firefox, Edge (Chromium-based)
    """
    filename = os.path.basename(file_path).lower()
    
    # Detect browser type
    if 'history' in filename and 'places.sqlite' not in filename:
        # Chrome/Edge/Chromium
        logger.info(f"Detected Chrome-based history: {filename}")
        return parse_chrome_history(file_path)
    elif 'places.sqlite' in filename:
        # Firefox
        logger.info(f"Detected Firefox history: {filename}")
        return parse_firefox_history(file_path)
    else:
        # Default to Chrome parser
        logger.info(f"Defaulting to Chrome parser for: {filename}")
        return parse_chrome_history(file_path)

