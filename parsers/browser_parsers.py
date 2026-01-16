"""Browser Artifact Parsers for CaseScope

Parsers for browser forensic artifacts:
- SQLite databases (Firefox, Chrome, Edge)
  - History (places.sqlite, History)
  - Cookies
  - Downloads
  - Form data
  - Logins
- Firefox JSONLZ4 compressed files
  - Session data
  - Search engines
  - Extensions
"""
import os
import re
import json
import sqlite3
import logging
import tempfile
import shutil
from datetime import datetime, timedelta
from typing import Generator, Dict, List, Any, Optional
from pathlib import Path

from parsers.base import BaseParser, ParsedEvent

logger = logging.getLogger(__name__)


# ============================================
# Firefox/Chrome timestamp conversion
# ============================================

def webkit_to_datetime(webkit_timestamp: int) -> Optional[datetime]:
    """Convert WebKit/Chrome timestamp to datetime
    
    WebKit timestamps are microseconds since 1601-01-01
    """
    if not webkit_timestamp or webkit_timestamp <= 0:
        return None
    try:
        # Microseconds from 1601 to 1970
        epoch_diff = 11644473600000000
        unix_timestamp = (webkit_timestamp - epoch_diff) / 1000000
        return datetime.utcfromtimestamp(unix_timestamp)
    except (ValueError, OSError, OverflowError):
        return None


def mozilla_to_datetime(mozilla_timestamp: int) -> Optional[datetime]:
    """Convert Mozilla/Firefox timestamp to datetime
    
    Mozilla timestamps are microseconds since Unix epoch
    """
    if not mozilla_timestamp or mozilla_timestamp <= 0:
        return None
    try:
        return datetime.utcfromtimestamp(mozilla_timestamp / 1000000)
    except (ValueError, OSError, OverflowError):
        return None


def prtime_to_datetime(prtime: int) -> Optional[datetime]:
    """Convert PRTime (Firefox) to datetime
    
    PRTime is microseconds since Unix epoch
    """
    return mozilla_to_datetime(prtime)


# ============================================
# SQLite Browser Parser
# ============================================

class BrowserSQLiteParser(BaseParser):
    """Parser for browser SQLite databases
    
    Supports:
    - Firefox: places.sqlite, cookies.sqlite, formhistory.sqlite, logins.json
    - Chrome/Edge: History, Cookies, Login Data, Web Data
    """
    
    VERSION = '1.0.1'
    ARTIFACT_TYPE = 'browser'
    
    # Database identification patterns
    FIREFOX_DBS = {
        'places.sqlite': 'firefox_history',
        'cookies.sqlite': 'firefox_cookies',
        'formhistory.sqlite': 'firefox_forms',
        'downloads.sqlite': 'firefox_downloads',
        'permissions.sqlite': 'firefox_permissions',
        'content-prefs.sqlite': 'firefox_prefs',
        'webappsstore.sqlite': 'firefox_storage',
        'favicons.sqlite': 'firefox_favicons',
    }
    
    CHROME_DBS = {
        'history': 'chrome_history',
        'cookies': 'chrome_cookies',
        'login data': 'chrome_logins',
        'web data': 'chrome_webdata',
        'top sites': 'chrome_topsites',
        'shortcuts': 'chrome_shortcuts',
        'network action predictor': 'chrome_predictor',
        'favicons': 'chrome_favicons',
    }
    
    # Windows cache files that are NOT browser databases (SQLite but not parseable)
    EXCLUDED_FILES = {
        # Windows Explorer cache files
        'iconcache_16.db', 'iconcache_32.db', 'iconcache_48.db', 'iconcache_96.db',
        'iconcache_256.db', 'iconcache_768.db', 'iconcache_1280.db', 'iconcache_1920.db',
        'iconcache_2560.db', 'iconcache_exif.db', 'iconcache_idx.db', 'iconcache_sr.db',
        'iconcache_wide.db', 'iconcache_wide_alternate.db', 'iconcache_custom_stream.db',
        'thumbcache_16.db', 'thumbcache_32.db', 'thumbcache_48.db', 'thumbcache_96.db',
        'thumbcache_256.db', 'thumbcache_768.db', 'thumbcache_1280.db', 'thumbcache_1920.db',
        'thumbcache_2560.db', 'thumbcache_exif.db', 'thumbcache_idx.db', 'thumbcache_sr.db',
        'thumbcache_wide.db', 'thumbcache_wide_alternate.db', 'thumbcache_custom_stream.db',
        # Other Windows cache/state files
        'cachedata.db', 'staterepository-deployment.srd',
        'staterepository-machine.srd', 'staterepository-deployment.srd',
    }
    
    # Filename patterns to exclude (partial matches)
    EXCLUDED_PATTERNS = [
        'iconcache_', 'thumbcache_', 'staterepository-',
    ]
    
    def __init__(self, case_id: int, source_host: str = '', case_file_id: Optional[int] = None):
        super().__init__(case_id, source_host, case_file_id)
        self._db_type = None
        self._browser = None
    
    @property
    def artifact_type(self) -> str:
        return self.ARTIFACT_TYPE
    
    def can_parse(self, file_path: str) -> bool:
        """Check if file is a browser SQLite database"""
        if not os.path.isfile(file_path):
            return False
        
        filename = os.path.basename(file_path).lower()
        
        # Explicitly exclude Windows cache files and other non-browser databases
        if filename in self.EXCLUDED_FILES:
            return False
        
        # Check exclusion patterns (partial matches)
        for pattern in self.EXCLUDED_PATTERNS:
            if pattern in filename:
                return False
        
        # Exclude text files and other non-database extensions
        if filename.endswith(('.txt', '.log', '.xml', '.json', '.csv', '.html', '.htm')):
            return False
        
        # Check known filenames
        if filename in self.FIREFOX_DBS or filename in self.CHROME_DBS:
            return True
        
        # Check SQLite magic bytes for known browser extensions
        if filename.endswith(('.sqlite', '.sqlite3')):
            try:
                with open(file_path, 'rb') as f:
                    magic = f.read(16)
                    return magic.startswith(b'SQLite format 3')
            except:
                pass
        
        # For generic .db files, verify it's actually a browser database
        if filename.endswith('.db'):
            try:
                with open(file_path, 'rb') as f:
                    magic = f.read(16)
                    if magic.startswith(b'SQLite format 3'):
                        # Must verify it's a browser DB, not just any SQLite
                        return self._identify_browser_db(file_path) is not None
            except:
                pass
        
        # Chrome databases often have no extension
        try:
            with open(file_path, 'rb') as f:
                magic = f.read(16)
                if magic.startswith(b'SQLite format 3'):
                    # Try to identify by tables
                    return self._identify_browser_db(file_path) is not None
        except:
            pass
        
        return False
    
    def _identify_browser_db(self, file_path: str) -> Optional[str]:
        """Identify browser database type by examining tables"""
        filename = os.path.basename(file_path).lower()
        
        # Check known names first
        if filename in self.FIREFOX_DBS:
            return self.FIREFOX_DBS[filename]
        if filename in self.CHROME_DBS:
            return self.CHROME_DBS[filename]
        
        # Examine tables
        try:
            conn = sqlite3.connect(f'file:{file_path}?mode=ro', uri=True)
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = set(row[0].lower() for row in cursor.fetchall())
            conn.close()
            
            # Firefox places.sqlite
            if 'moz_places' in tables and 'moz_historyvisits' in tables:
                return 'firefox_history'
            
            # Firefox cookies
            if 'moz_cookies' in tables:
                return 'firefox_cookies'
            
            # Firefox forms
            if 'moz_formhistory' in tables:
                return 'firefox_forms'
            
            # Chrome History
            if 'urls' in tables and 'visits' in tables:
                return 'chrome_history'
            
            # Chrome Cookies
            if 'cookies' in tables and 'host_key' in str(tables):
                return 'chrome_cookies'
            
            # Chrome Login Data
            if 'logins' in tables:
                return 'chrome_logins'
            
            # Chrome Web Data
            if 'autofill' in tables:
                return 'chrome_webdata'
                
        except Exception as e:
            logger.debug(f"Error identifying database {file_path}: {e}")
        
        return None
    
    def parse(self, file_path: str) -> Generator[ParsedEvent, None, None]:
        """Parse browser SQLite database"""
        if not self.can_parse(file_path):
            self.errors.append(f"Cannot parse file: {file_path}")
            return
        
        db_type = self._identify_browser_db(file_path)
        if not db_type:
            self.errors.append(f"Could not identify database type: {file_path}")
            return
        
        source_file = os.path.basename(file_path)
        hostname = self.extract_hostname(file_path)
        
        # Copy to temp file (SQLite needs write access for WAL)
        temp_dir = tempfile.mkdtemp()
        temp_path = os.path.join(temp_dir, source_file)
        
        try:
            shutil.copy2(file_path, temp_path)
            
            # Copy WAL and SHM if they exist
            for ext in ['-wal', '-shm', '-journal']:
                wal_path = file_path + ext
                if os.path.exists(wal_path):
                    shutil.copy2(wal_path, temp_path + ext)
            
            # Parse based on type
            if db_type == 'firefox_history':
                yield from self._parse_firefox_history(temp_path, source_file, hostname)
            elif db_type == 'firefox_cookies':
                yield from self._parse_firefox_cookies(temp_path, source_file, hostname)
            elif db_type == 'firefox_forms':
                yield from self._parse_firefox_forms(temp_path, source_file, hostname)
            elif db_type == 'chrome_history':
                yield from self._parse_chrome_history(temp_path, source_file, hostname)
                # Also parse downloads table from Chrome History database
                yield from self._parse_chrome_downloads(temp_path, source_file, hostname)
            elif db_type == 'chrome_cookies':
                yield from self._parse_chrome_cookies(temp_path, source_file, hostname)
            elif db_type == 'chrome_logins':
                yield from self._parse_chrome_logins(temp_path, source_file, hostname)
            elif db_type == 'chrome_webdata':
                yield from self._parse_chrome_webdata(temp_path, source_file, hostname)
            else:
                # Generic SQLite dump
                yield from self._parse_generic_sqlite(temp_path, source_file, hostname, db_type)
                
        except Exception as e:
            self.errors.append(f"Error parsing {file_path}: {e}")
            logger.exception(f"SQLite parse error: {e}")
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)
    
    def _parse_firefox_history(self, db_path: str, source_file: str, hostname: str) -> Generator[ParsedEvent, None, None]:
        """Parse Firefox places.sqlite history"""
        try:
            conn = sqlite3.connect(db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            # History visits with URLs
            query = """
                SELECT 
                    p.url,
                    p.title,
                    p.visit_count,
                    p.typed,
                    p.hidden,
                    p.frecency,
                    v.visit_date,
                    v.visit_type,
                    v.from_visit
                FROM moz_places p
                JOIN moz_historyvisits v ON p.id = v.place_id
                ORDER BY v.visit_date DESC
            """
            
            cursor.execute(query)
            
            visit_types = {
                1: 'link',
                2: 'typed',
                3: 'bookmark',
                4: 'embed',
                5: 'redirect_permanent',
                6: 'redirect_temporary',
                7: 'download',
                8: 'framed_link',
            }
            
            for row in cursor:
                timestamp = mozilla_to_datetime(row['visit_date'])
                if not timestamp:
                    timestamp = datetime.now()
                
                raw_data = {
                    'url': row['url'],
                    'title': row['title'],
                    'visit_count': row['visit_count'],
                    'typed': bool(row['typed']),
                    'hidden': bool(row['hidden']),
                    'frecency': row['frecency'],
                    'visit_type': visit_types.get(row['visit_type'], str(row['visit_type'])),
                    'from_visit': row['from_visit'],
                }
                
                yield ParsedEvent(
                    case_id=self.case_id,
                    artifact_type='browser_history',
                    timestamp=timestamp,
                    source_file=source_file,
                    source_path=db_path,
                    source_host=hostname,
                    case_file_id=self.case_file_id,
                    target_path=row['url'],
                    raw_json=json.dumps(raw_data, default=str),
                    search_blob=f"{row['url']} {row['title'] or ''} firefox history",
                    extra_fields=json.dumps({'browser': 'firefox', 'artifact': 'history'}),
                    parser_version=self.parser_version,
                )
            
            conn.close()
            
        except Exception as e:
            self.errors.append(f"Firefox history parse error: {e}")
    
    def _parse_firefox_cookies(self, db_path: str, source_file: str, hostname: str) -> Generator[ParsedEvent, None, None]:
        """Parse Firefox cookies.sqlite"""
        try:
            conn = sqlite3.connect(db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            query = """
                SELECT 
                    name, value, host, path, expiry,
                    lastAccessed, creationTime, isSecure, isHttpOnly,
                    sameSite
                FROM moz_cookies
            """
            
            cursor.execute(query)
            
            for row in cursor:
                timestamp = mozilla_to_datetime(row['creationTime'])
                if not timestamp:
                    timestamp = datetime.now()
                
                raw_data = {
                    'name': row['name'],
                    'value': row['value'][:100] if row['value'] else None,  # Truncate value
                    'host': row['host'],
                    'path': row['path'],
                    'expiry': row['expiry'],
                    'last_accessed': str(mozilla_to_datetime(row['lastAccessed'])),
                    'secure': bool(row['isSecure']),
                    'http_only': bool(row['isHttpOnly']),
                    'same_site': row['sameSite'],
                }
                
                yield ParsedEvent(
                    case_id=self.case_id,
                    artifact_type='browser_cookies',
                    timestamp=timestamp,
                    source_file=source_file,
                    source_path=db_path,
                    source_host=hostname,
                    case_file_id=self.case_file_id,
                    raw_json=json.dumps(raw_data, default=str),
                    search_blob=f"{row['host']} {row['name']} {row['path']} firefox cookie",
                    extra_fields=json.dumps({'browser': 'firefox', 'artifact': 'cookies'}),
                    parser_version=self.parser_version,
                )
            
            conn.close()
            
        except Exception as e:
            self.errors.append(f"Firefox cookies parse error: {e}")
    
    def _parse_firefox_forms(self, db_path: str, source_file: str, hostname: str) -> Generator[ParsedEvent, None, None]:
        """Parse Firefox formhistory.sqlite"""
        try:
            conn = sqlite3.connect(db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            query = """
                SELECT fieldname, value, timesUsed, firstUsed, lastUsed
                FROM moz_formhistory
            """
            
            cursor.execute(query)
            
            for row in cursor:
                timestamp = mozilla_to_datetime(row['lastUsed'])
                if not timestamp:
                    timestamp = datetime.now()
                
                raw_data = {
                    'field_name': row['fieldname'],
                    'value': row['value'][:200] if row['value'] else None,
                    'times_used': row['timesUsed'],
                    'first_used': str(mozilla_to_datetime(row['firstUsed'])),
                    'last_used': str(timestamp),
                }
                
                yield ParsedEvent(
                    case_id=self.case_id,
                    artifact_type='browser_forms',
                    timestamp=timestamp,
                    source_file=source_file,
                    source_path=db_path,
                    source_host=hostname,
                    case_file_id=self.case_file_id,
                    raw_json=json.dumps(raw_data, default=str),
                    search_blob=f"{row['fieldname']} {row['value'] or ''} firefox form",
                    extra_fields=json.dumps({'browser': 'firefox', 'artifact': 'forms'}),
                    parser_version=self.parser_version,
                )
            
            conn.close()
            
        except Exception as e:
            self.errors.append(f"Firefox forms parse error: {e}")
    
    def _parse_chrome_history(self, db_path: str, source_file: str, hostname: str) -> Generator[ParsedEvent, None, None]:
        """Parse Chrome/Edge History database"""
        try:
            conn = sqlite3.connect(db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            query = """
                SELECT 
                    u.url, u.title, u.visit_count, u.typed_count,
                    u.last_visit_time, u.hidden,
                    v.visit_time, v.transition
                FROM urls u
                LEFT JOIN visits v ON u.id = v.url
                ORDER BY v.visit_time DESC
            """
            
            cursor.execute(query)
            
            for row in cursor:
                timestamp = webkit_to_datetime(row['visit_time'] or row['last_visit_time'])
                if not timestamp:
                    timestamp = datetime.now()
                
                # Decode transition type
                transition = row['transition'] & 0xFF if row['transition'] else 0
                transition_types = {
                    0: 'link', 1: 'typed', 2: 'auto_bookmark',
                    3: 'auto_subframe', 4: 'manual_subframe',
                    5: 'generated', 6: 'auto_toplevel', 7: 'form_submit',
                    8: 'reload', 9: 'keyword', 10: 'keyword_generated'
                }
                
                raw_data = {
                    'url': row['url'],
                    'title': row['title'],
                    'visit_count': row['visit_count'],
                    'typed_count': row['typed_count'],
                    'hidden': bool(row['hidden']),
                    'transition': transition_types.get(transition, str(transition)),
                }
                
                yield ParsedEvent(
                    case_id=self.case_id,
                    artifact_type='browser_history',
                    timestamp=timestamp,
                    source_file=source_file,
                    source_path=db_path,
                    source_host=hostname,
                    case_file_id=self.case_file_id,
                    target_path=row['url'],
                    raw_json=json.dumps(raw_data, default=str),
                    search_blob=f"{row['url']} {row['title'] or ''} chrome history",
                    extra_fields=json.dumps({'browser': 'chrome', 'artifact': 'history'}),
                    parser_version=self.parser_version,
                )
            
            conn.close()
            
        except Exception as e:
            self.errors.append(f"Chrome history parse error: {e}")
    
    def _parse_chrome_downloads(self, db_path: str, source_file: str, hostname: str) -> Generator[ParsedEvent, None, None]:
        """Parse Chrome/Edge downloads table"""
        try:
            conn = sqlite3.connect(db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            # Check if downloads table exists
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='downloads'")
            if not cursor.fetchone():
                conn.close()
                return
            
            query = """
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
            """
            
            cursor.execute(query)
            
            # Also get download URLs from download_url_chains if available
            url_chains = {}
            try:
                cursor2 = conn.cursor()
                cursor2.execute("SELECT id, url FROM download_url_chains ORDER BY id, chain_index")
                for row in cursor2:
                    if row['id'] not in url_chains:
                        url_chains[row['id']] = []
                    url_chains[row['id']].append(row['url'])
            except:
                pass  # Table may not exist in older Chrome versions
            
            for row in cursor:
                start_time = webkit_to_datetime(row['start_time'])
                end_time = webkit_to_datetime(row['end_time'])
                
                if not start_time:
                    start_time = datetime.now()
                
                file_path = row['target_path'] or row['current_path'] or ''
                filename = file_path.split('\\')[-1].split('/')[-1] if file_path else ''
                
                # Get source URL from chain or try to extract from other fields
                source_url = ''
                if row['id'] in url_chains and url_chains[row['id']]:
                    source_url = url_chains[row['id']][0]  # First URL in chain is the source
                
                raw_data = {
                    'file_path': file_path,
                    'filename': filename,
                    'url': source_url,
                    'start_time': str(start_time),
                    'end_time': str(end_time) if end_time else None,
                    'received_bytes': row['received_bytes'],
                    'total_bytes': row['total_bytes'],
                    'state': row['state'],
                    'danger_type': row['danger_type'],
                    'interrupt_reason': row['interrupt_reason'],
                    'mime_type': row['mime_type'] or row['original_mime_type'],
                }
                
                yield ParsedEvent(
                    case_id=self.case_id,
                    artifact_type='browser_download',
                    timestamp=start_time,
                    source_file=source_file,
                    source_path=db_path,
                    source_host=hostname,
                    case_file_id=self.case_file_id,
                    target_path=file_path,
                    raw_json=json.dumps(raw_data, default=str),
                    search_blob=f"{filename} {source_url} {file_path} chrome download",
                    extra_fields=json.dumps({'browser': 'chrome', 'artifact': 'download'}),
                    parser_version=self.parser_version,
                )
            
            conn.close()
            
        except Exception as e:
            self.errors.append(f"Chrome downloads parse error: {e}")
    
    def _parse_chrome_cookies(self, db_path: str, source_file: str, hostname: str) -> Generator[ParsedEvent, None, None]:
        """Parse Chrome/Edge Cookies database"""
        try:
            conn = sqlite3.connect(db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            # Try different schema versions
            try:
                query = """
                    SELECT host_key, name, path, creation_utc, expires_utc,
                           last_access_utc, is_secure, is_httponly, samesite
                    FROM cookies
                """
                cursor.execute(query)
            except:
                query = """
                    SELECT host_key, name, path, creation_utc, expires_utc,
                           last_access_utc, secure, httponly
                    FROM cookies
                """
                cursor.execute(query)
            
            for row in cursor:
                timestamp = webkit_to_datetime(row['creation_utc'])
                if not timestamp:
                    timestamp = datetime.now()
                
                raw_data = {
                    'host': row['host_key'],
                    'name': row['name'],
                    'path': row['path'],
                    'created': str(timestamp),
                    'expires': str(webkit_to_datetime(row['expires_utc'])),
                    'last_access': str(webkit_to_datetime(row['last_access_utc'])),
                    'secure': bool(row.get('is_secure') or row.get('secure', 0)),
                    'http_only': bool(row.get('is_httponly') or row.get('httponly', 0)),
                }
                
                yield ParsedEvent(
                    case_id=self.case_id,
                    artifact_type='browser_cookies',
                    timestamp=timestamp,
                    source_file=source_file,
                    source_path=db_path,
                    source_host=hostname,
                    case_file_id=self.case_file_id,
                    raw_json=json.dumps(raw_data, default=str),
                    search_blob=f"{row['host_key']} {row['name']} chrome cookie",
                    extra_fields=json.dumps({'browser': 'chrome', 'artifact': 'cookies'}),
                    parser_version=self.parser_version,
                )
            
            conn.close()
            
        except Exception as e:
            self.errors.append(f"Chrome cookies parse error: {e}")
    
    def _parse_chrome_logins(self, db_path: str, source_file: str, hostname: str) -> Generator[ParsedEvent, None, None]:
        """Parse Chrome/Edge Login Data database"""
        try:
            conn = sqlite3.connect(db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            query = """
                SELECT origin_url, action_url, username_element, username_value,
                       password_element, signon_realm, date_created, date_last_used,
                       times_used, blacklisted_by_user
                FROM logins
            """
            
            cursor.execute(query)
            
            for row in cursor:
                timestamp = webkit_to_datetime(row['date_created'])
                if not timestamp:
                    timestamp = datetime.now()
                
                raw_data = {
                    'origin_url': row['origin_url'],
                    'action_url': row['action_url'],
                    'username_element': row['username_element'],
                    'username_value': row['username_value'],
                    'password_element': row['password_element'],
                    'signon_realm': row['signon_realm'],
                    'date_created': str(timestamp),
                    'date_last_used': str(webkit_to_datetime(row['date_last_used'])),
                    'times_used': row['times_used'],
                    'blacklisted': bool(row['blacklisted_by_user']),
                }
                
                yield ParsedEvent(
                    case_id=self.case_id,
                    artifact_type='browser_logins',
                    timestamp=timestamp,
                    source_file=source_file,
                    source_path=db_path,
                    source_host=hostname,
                    case_file_id=self.case_file_id,
                    username=row['username_value'],
                    target_path=row['origin_url'],
                    raw_json=json.dumps(raw_data, default=str),
                    search_blob=f"{row['origin_url']} {row['username_value']} chrome login",
                    extra_fields=json.dumps({'browser': 'chrome', 'artifact': 'logins'}),
                    parser_version=self.parser_version,
                )
            
            conn.close()
            
        except Exception as e:
            self.errors.append(f"Chrome logins parse error: {e}")
    
    def _parse_chrome_webdata(self, db_path: str, source_file: str, hostname: str) -> Generator[ParsedEvent, None, None]:
        """Parse Chrome/Edge Web Data (autofill)"""
        try:
            conn = sqlite3.connect(db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            # Autofill data
            try:
                query = """
                    SELECT name, value, count, date_created, date_last_used
                    FROM autofill
                """
                cursor.execute(query)
                
                for row in cursor:
                    timestamp = webkit_to_datetime(row['date_created'])
                    if not timestamp:
                        timestamp = datetime.now()
                    
                    raw_data = {
                        'field_name': row['name'],
                        'value': row['value'][:200] if row['value'] else None,
                        'count': row['count'],
                        'date_created': str(timestamp),
                        'date_last_used': str(webkit_to_datetime(row['date_last_used'])),
                    }
                    
                    yield ParsedEvent(
                        case_id=self.case_id,
                        artifact_type='browser_autofill',
                        timestamp=timestamp,
                        source_file=source_file,
                        source_path=db_path,
                        source_host=hostname,
                        case_file_id=self.case_file_id,
                        raw_json=json.dumps(raw_data, default=str),
                        search_blob=f"{row['name']} {row['value'] or ''} chrome autofill",
                        extra_fields=json.dumps({'browser': 'chrome', 'artifact': 'autofill'}),
                        parser_version=self.parser_version,
                    )
            except Exception as e:
                self.warnings.append(f"Autofill parse error: {e}")
            
            conn.close()
            
        except Exception as e:
            self.errors.append(f"Chrome webdata parse error: {e}")
    
    def _parse_generic_sqlite(self, db_path: str, source_file: str, hostname: str, db_type: str) -> Generator[ParsedEvent, None, None]:
        """Generic SQLite database dump"""
        try:
            conn = sqlite3.connect(db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            # Get all tables
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [row[0] for row in cursor.fetchall()]
            
            for table in tables:
                if table.startswith('sqlite_'):
                    continue
                
                try:
                    cursor.execute(f"SELECT * FROM [{table}] LIMIT 10000")
                    columns = [desc[0] for desc in cursor.description]
                    
                    for row in cursor:
                        row_dict = dict(zip(columns, row))
                        
                        # Try to find timestamp
                        timestamp = datetime.now()
                        for col in ['timestamp', 'time', 'date', 'created', 'modified', 'last_access']:
                            for key in row_dict:
                                if col in key.lower() and row_dict[key]:
                                    ts = self.parse_timestamp(str(row_dict[key]))
                                    if ts:
                                        timestamp = ts
                                        break
                        
                        yield ParsedEvent(
                            case_id=self.case_id,
                            artifact_type=f'sqlite_{db_type}',
                            timestamp=timestamp,
                            source_file=source_file,
                            source_path=db_path,
                            source_host=hostname,
                            case_file_id=self.case_file_id,
                            raw_json=json.dumps(row_dict, default=str),
                            search_blob=self.build_search_blob(row_dict),
                            extra_fields=json.dumps({'table': table}),
                            parser_version=self.parser_version,
                        )
                        
                except Exception as e:
                    self.warnings.append(f"Error reading table {table}: {e}")
            
            conn.close()
            
        except Exception as e:
            self.errors.append(f"Generic SQLite parse error: {e}")


# ============================================
# Firefox JSONLZ4 Parser
# ============================================

class FirefoxJSONLZ4Parser(BaseParser):
    """Parser for Firefox JSONLZ4 compressed files
    
    Firefox uses LZ4 compression with a custom header ("mozLz40\0")
    for various JSON files including:
    - sessionstore.jsonlz4 (session data, tabs)
    - search.json.mozlz4 (search engines)
    - addonStartup.json.lz4 (extensions)
    - handlers.json (protocol handlers)
    """
    
    VERSION = '1.0.0'
    ARTIFACT_TYPE = 'firefox_session'
    
    # Mozilla LZ4 magic header
    MOZLZ4_MAGIC = b'mozLz40\0'
    
    def __init__(self, case_id: int, source_host: str = '', case_file_id: Optional[int] = None):
        super().__init__(case_id, source_host, case_file_id)
        
        # Try to import lz4
        try:
            import lz4.block
            self._lz4 = lz4.block
        except ImportError:
            self._lz4 = None
    
    @property
    def artifact_type(self) -> str:
        return self.ARTIFACT_TYPE
    
    def can_parse(self, file_path: str) -> bool:
        """Check if file is a Firefox JSONLZ4 file"""
        if not os.path.isfile(file_path):
            return False
        
        filename = os.path.basename(file_path).lower()
        
        # Check extensions
        if filename.endswith(('.jsonlz4', '.mozlz4', '.json.lz4', '.baklz4')):
            return True
        
        # Check magic bytes
        try:
            with open(file_path, 'rb') as f:
                magic = f.read(8)
                return magic == self.MOZLZ4_MAGIC
        except:
            pass
        
        return False
    
    def _decompress_mozlz4(self, file_path: str) -> Optional[bytes]:
        """Decompress Mozilla LZ4 file"""
        if not self._lz4:
            # Fallback: try using system lz4
            try:
                import subprocess
                result = subprocess.run(
                    ['lz4', '-d', '-c', file_path],
                    capture_output=True
                )
                if result.returncode == 0:
                    # Skip the mozilla header manually
                    with open(file_path, 'rb') as f:
                        data = f.read()
                    if data.startswith(self.MOZLZ4_MAGIC):
                        # The subprocess approach won't work for mozlz4
                        pass
                return None
            except:
                return None
        
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
            
            # Check for Mozilla LZ4 header
            if not data.startswith(self.MOZLZ4_MAGIC):
                self.warnings.append(f"Not a valid mozlz4 file: {file_path}")
                return None
            
            # Skip header (8 bytes magic + 4 bytes uncompressed size)
            compressed_data = data[8:]
            
            # Decompress using lz4 block API
            # Mozilla stores uncompressed size in first 4 bytes after magic (little-endian)
            # But lz4.block.decompress can auto-detect
            try:
                decompressed = self._lz4.decompress(compressed_data)
                return decompressed
            except:
                # Try with explicit size
                import struct
                size = struct.unpack('<I', data[8:12])[0]
                decompressed = self._lz4.decompress(data[12:], uncompressed_size=size)
                return decompressed
                
        except Exception as e:
            self.errors.append(f"Decompression error: {e}")
            return None
    
    def parse(self, file_path: str) -> Generator[ParsedEvent, None, None]:
        """Parse Firefox JSONLZ4 file"""
        if not self.can_parse(file_path):
            self.errors.append(f"Cannot parse file: {file_path}")
            return
        
        source_file = os.path.basename(file_path)
        hostname = self.extract_hostname(file_path)
        
        # Decompress
        decompressed = self._decompress_mozlz4(file_path)
        if not decompressed:
            # Try reading as plain JSON (some files might not be compressed)
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
            except:
                self.errors.append(f"Could not decompress or read: {file_path}")
                return
        else:
            try:
                data = json.loads(decompressed.decode('utf-8'))
            except json.JSONDecodeError as e:
                self.errors.append(f"JSON decode error: {e}")
                return
        
        # Route to appropriate handler based on filename
        filename_lower = source_file.lower()
        
        if 'sessionstore' in filename_lower or 'session' in filename_lower:
            yield from self._parse_session_data(data, source_file, file_path, hostname)
        elif 'search' in filename_lower:
            yield from self._parse_search_engines(data, source_file, file_path, hostname)
        elif 'addon' in filename_lower or 'extension' in filename_lower:
            yield from self._parse_addons(data, source_file, file_path, hostname)
        elif 'handler' in filename_lower:
            yield from self._parse_handlers(data, source_file, file_path, hostname)
        else:
            # Generic JSON dump
            yield from self._parse_generic_json(data, source_file, file_path, hostname)
    
    def _parse_session_data(self, data: Dict, source_file: str, file_path: str, hostname: str) -> Generator[ParsedEvent, None, None]:
        """Parse Firefox session data (tabs, windows)"""
        
        # Get session timestamp
        session_time = data.get('session', {}).get('lastUpdate')
        base_timestamp = mozilla_to_datetime(session_time) if session_time else datetime.now()
        
        # Parse windows and tabs
        windows = data.get('windows', [])
        
        for win_idx, window in enumerate(windows):
            tabs = window.get('tabs', [])
            
            for tab_idx, tab in enumerate(tabs):
                entries = tab.get('entries', [])
                
                for entry_idx, entry in enumerate(entries):
                    url = entry.get('url', '')
                    title = entry.get('title', '')
                    
                    # Skip about: pages
                    if url.startswith('about:'):
                        continue
                    
                    # Get last accessed time if available
                    last_accessed = tab.get('lastAccessed')
                    timestamp = mozilla_to_datetime(last_accessed) if last_accessed else base_timestamp
                    
                    raw_data = {
                        'url': url,
                        'title': title,
                        'window_index': win_idx,
                        'tab_index': tab_idx,
                        'entry_index': entry_idx,
                        'referrer': entry.get('referrer'),
                        'scroll': entry.get('scroll'),
                        'persist': entry.get('persist'),
                    }
                    
                    yield ParsedEvent(
                        case_id=self.case_id,
                        artifact_type='firefox_session',
                        timestamp=timestamp,
                        source_file=source_file,
                        source_path=file_path,
                        source_host=hostname,
                        case_file_id=self.case_file_id,
                        target_path=url,
                        raw_json=json.dumps(raw_data, default=str),
                        search_blob=f"{url} {title} firefox session tab",
                        extra_fields=json.dumps({
                            'artifact_subtype': 'session_tab',
                            'window': win_idx,
                            'tab': tab_idx,
                        }),
                        parser_version=self.parser_version,
                    )
        
        # Parse closed tabs
        closed_windows = data.get('_closedWindows', [])
        for win in closed_windows:
            for tab in win.get('tabs', []):
                for entry in tab.get('entries', []):
                    url = entry.get('url', '')
                    if url.startswith('about:'):
                        continue
                    
                    yield ParsedEvent(
                        case_id=self.case_id,
                        artifact_type='firefox_session',
                        timestamp=base_timestamp,
                        source_file=source_file,
                        source_path=file_path,
                        source_host=hostname,
                        case_file_id=self.case_file_id,
                        target_path=url,
                        raw_json=json.dumps({'url': url, 'title': entry.get('title'), 'closed': True}, default=str),
                        search_blob=f"{url} {entry.get('title', '')} firefox closed tab",
                        extra_fields=json.dumps({'artifact_subtype': 'closed_tab'}),
                        parser_version=self.parser_version,
                    )
    
    def _parse_search_engines(self, data: Dict, source_file: str, file_path: str, hostname: str) -> Generator[ParsedEvent, None, None]:
        """Parse Firefox search engines configuration"""
        engines = data.get('engines', [])
        
        for engine in engines:
            name = engine.get('_name', engine.get('name', 'Unknown'))
            
            raw_data = {
                'name': name,
                'load_path': engine.get('_loadPath'),
                'description': engine.get('description'),
                'hidden': engine.get('_hidden', False),
                'alias': engine.get('_alias'),
            }
            
            # Get URLs
            urls = engine.get('_urls', [])
            for url_data in urls:
                if url_data.get('type') == 'text/html':
                    raw_data['search_url'] = url_data.get('template')
                    break
            
            yield ParsedEvent(
                case_id=self.case_id,
                artifact_type='firefox_search_engine',
                timestamp=datetime.now(),
                source_file=source_file,
                source_path=file_path,
                source_host=hostname,
                case_file_id=self.case_file_id,
                raw_json=json.dumps(raw_data, default=str),
                search_blob=f"{name} {raw_data.get('search_url', '')} firefox search engine",
                parser_version=self.parser_version,
            )
    
    def _parse_addons(self, data: Dict, source_file: str, file_path: str, hostname: str) -> Generator[ParsedEvent, None, None]:
        """Parse Firefox addons/extensions"""
        addons = data.get('addons', [])
        if not addons and isinstance(data, dict):
            # Try different structure
            addons = []
            for key, value in data.items():
                if isinstance(value, dict) and 'addons' in value:
                    addons.extend(value.get('addons', []))
        
        for addon in addons:
            if not isinstance(addon, dict):
                continue
            
            addon_id = addon.get('id', addon.get('addonId', 'Unknown'))
            name = addon.get('name', addon.get('defaultLocale', {}).get('name', addon_id))
            
            # Get install/update time
            install_date = addon.get('installDate')
            update_date = addon.get('updateDate')
            timestamp = datetime.now()
            if update_date:
                timestamp = datetime.utcfromtimestamp(update_date / 1000) if update_date > 1e10 else datetime.utcfromtimestamp(update_date)
            elif install_date:
                timestamp = datetime.utcfromtimestamp(install_date / 1000) if install_date > 1e10 else datetime.utcfromtimestamp(install_date)
            
            raw_data = {
                'id': addon_id,
                'name': name,
                'version': addon.get('version'),
                'type': addon.get('type'),
                'active': addon.get('active'),
                'visible': addon.get('visible'),
                'user_disabled': addon.get('userDisabled'),
                'homepage': addon.get('homepageURL'),
                'source_uri': addon.get('sourceURI'),
                'install_date': str(install_date),
                'update_date': str(update_date),
            }
            
            yield ParsedEvent(
                case_id=self.case_id,
                artifact_type='firefox_addon',
                timestamp=timestamp,
                source_file=source_file,
                source_path=file_path,
                source_host=hostname,
                case_file_id=self.case_file_id,
                raw_json=json.dumps(raw_data, default=str),
                search_blob=f"{addon_id} {name} firefox extension addon",
                parser_version=self.parser_version,
            )
    
    def _parse_handlers(self, data: Dict, source_file: str, file_path: str, hostname: str) -> Generator[ParsedEvent, None, None]:
        """Parse Firefox protocol handlers"""
        schemes = data.get('schemes', {})
        mime_types = data.get('mimeTypes', {})
        
        for scheme, handlers in schemes.items():
            if isinstance(handlers, dict):
                raw_data = {
                    'type': 'scheme',
                    'scheme': scheme,
                    'handlers': handlers,
                }
                
                yield ParsedEvent(
                    case_id=self.case_id,
                    artifact_type='firefox_handler',
                    timestamp=datetime.now(),
                    source_file=source_file,
                    source_path=file_path,
                    source_host=hostname,
                    case_file_id=self.case_file_id,
                    raw_json=json.dumps(raw_data, default=str),
                    search_blob=f"{scheme} firefox protocol handler",
                    parser_version=self.parser_version,
                )
        
        for mime, handlers in mime_types.items():
            if isinstance(handlers, dict):
                raw_data = {
                    'type': 'mime',
                    'mime_type': mime,
                    'handlers': handlers,
                }
                
                yield ParsedEvent(
                    case_id=self.case_id,
                    artifact_type='firefox_handler',
                    timestamp=datetime.now(),
                    source_file=source_file,
                    source_path=file_path,
                    source_host=hostname,
                    case_file_id=self.case_file_id,
                    raw_json=json.dumps(raw_data, default=str),
                    search_blob=f"{mime} firefox mime handler",
                    parser_version=self.parser_version,
                )
    
    def _parse_generic_json(self, data: Any, source_file: str, file_path: str, hostname: str) -> Generator[ParsedEvent, None, None]:
        """Generic JSON dump for unknown JSONLZ4 files"""
        if isinstance(data, dict):
            yield ParsedEvent(
                case_id=self.case_id,
                artifact_type='firefox_json',
                timestamp=datetime.now(),
                source_file=source_file,
                source_path=file_path,
                source_host=hostname,
                case_file_id=self.case_file_id,
                raw_json=json.dumps(data, default=str),
                search_blob=self.build_search_blob(data),
                parser_version=self.parser_version,
            )
        elif isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    yield ParsedEvent(
                        case_id=self.case_id,
                        artifact_type='firefox_json',
                        timestamp=datetime.now(),
                        source_file=source_file,
                        source_path=file_path,
                        source_host=hostname,
                        case_file_id=self.case_file_id,
                        raw_json=json.dumps(item, default=str),
                        search_blob=self.build_search_blob(item),
                        parser_version=self.parser_version,
                    )
