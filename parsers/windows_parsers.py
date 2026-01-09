"""Windows Artifact Parsers for CaseScope

Parsers for additional Windows forensic artifacts:
- Scheduled Tasks (XML files)
- Windows Timeline / ActivitiesCache.db (SQLite)
- WebCache (ESE database)
"""
import os
import re
import json
import sqlite3
import logging
import tempfile
import shutil
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta
from typing import Generator, Dict, List, Any, Optional
from pathlib import Path

from parsers.base import BaseParser, ParsedEvent

logger = logging.getLogger(__name__)


# ============================================
# Scheduled Task Parser
# ============================================

class ScheduledTaskParser(BaseParser):
    """Parser for Windows Scheduled Task XML files
    
    Windows Task Scheduler stores task definitions as XML files in:
    - C:/Windows/System32/Tasks/
    - C:/Windows/Tasks/ (legacy .job format not supported)
    
    These files are UTF-16LE encoded XML containing:
    - Task metadata (author, description, URI)
    - Registration info
    - Triggers (schedule, logon, boot, etc.)
    - Actions (execute, COM handler, email, message)
    - Principal (user context, privileges)
    """
    
    VERSION = '1.0.0'
    ARTIFACT_TYPE = 'scheduled_task'
    
    # XML namespace for Task Scheduler schema
    TASK_NS = {'task': 'http://schemas.microsoft.com/windows/2004/02/mit/task'}
    
    def __init__(self, case_id: int, source_host: str = '', case_file_id: Optional[int] = None):
        super().__init__(case_id, source_host, case_file_id)
    
    @property
    def artifact_type(self) -> str:
        return self.ARTIFACT_TYPE
    
    def can_parse(self, file_path: str) -> bool:
        """Check if file is a Scheduled Task XML file"""
        if not os.path.isfile(file_path):
            return False
        
        # Check if in Tasks folder
        path_lower = file_path.lower().replace('\\', '/')
        if '/tasks/' not in path_lower:
            return False
        
        # Skip .job files (legacy binary format)
        if file_path.lower().endswith('.job'):
            return False
        
        # Check for XML content (UTF-16LE BOM or UTF-8)
        try:
            with open(file_path, 'rb') as f:
                header = f.read(100)
                # UTF-16LE BOM followed by XML declaration
                if header.startswith(b'\xff\xfe') and b'<\x00?\x00x\x00m\x00l\x00' in header:
                    return True
                # UTF-8 XML
                if header.startswith(b'<?xml'):
                    return True
                # Check for Task element
                if b'<Task' in header or b'<\x00T\x00a\x00s\x00k\x00' in header:
                    return True
        except Exception:
            pass
        
        return False
    
    def _parse_xml_content(self, file_path: str) -> Optional[ET.Element]:
        """Parse XML content handling UTF-16LE encoding"""
        try:
            # Try reading as UTF-16LE first (most common for Task Scheduler)
            with open(file_path, 'rb') as f:
                content = f.read()
            
            # Handle BOM
            if content.startswith(b'\xff\xfe'):
                xml_str = content.decode('utf-16-le')
            elif content.startswith(b'\xfe\xff'):
                xml_str = content.decode('utf-16-be')
            else:
                xml_str = content.decode('utf-8', errors='replace')
            
            # Remove BOM if present in string
            xml_str = xml_str.lstrip('\ufeff')
            
            return ET.fromstring(xml_str)
            
        except ET.ParseError as e:
            self.warnings.append(f"XML parse error: {e}")
            return None
        except Exception as e:
            self.errors.append(f"Error reading file: {e}")
            return None
    
    def _get_text(self, element: ET.Element, xpath: str, default: str = '') -> str:
        """Get text content from element with namespace handling"""
        # Try with namespace
        el = element.find(xpath, self.TASK_NS)
        if el is not None and el.text:
            return el.text.strip()
        
        # Try without namespace (some tasks don't use it)
        xpath_no_ns = xpath.replace('task:', '')
        el = element.find(xpath_no_ns)
        if el is not None and el.text:
            return el.text.strip()
        
        return default
    
    def _extract_triggers(self, root: ET.Element) -> List[Dict]:
        """Extract trigger information"""
        triggers = []
        
        # Try with namespace
        triggers_el = root.find('.//task:Triggers', self.TASK_NS)
        if triggers_el is None:
            triggers_el = root.find('.//Triggers')
        
        if triggers_el is None:
            return triggers
        
        for trigger in triggers_el:
            tag = trigger.tag.split('}')[-1] if '}' in trigger.tag else trigger.tag
            
            trigger_info = {
                'type': tag,
            }
            
            # Extract common trigger properties
            for child in trigger:
                child_tag = child.tag.split('}')[-1] if '}' in child.tag else child.tag
                if child.text:
                    trigger_info[child_tag] = child.text.strip()
            
            triggers.append(trigger_info)
        
        return triggers
    
    def _extract_actions(self, root: ET.Element) -> List[Dict]:
        """Extract action information (commands to execute)"""
        actions = []
        
        # Try with namespace
        actions_el = root.find('.//task:Actions', self.TASK_NS)
        if actions_el is None:
            actions_el = root.find('.//Actions')
        
        if actions_el is None:
            return actions
        
        for action in actions_el:
            tag = action.tag.split('}')[-1] if '}' in action.tag else action.tag
            
            if tag == 'Exec':
                exec_info = {
                    'type': 'Exec',
                    'command': '',
                    'arguments': '',
                    'working_directory': '',
                }
                
                for child in action:
                    child_tag = child.tag.split('}')[-1] if '}' in child.tag else child.tag
                    if child.text:
                        if child_tag == 'Command':
                            exec_info['command'] = child.text.strip()
                        elif child_tag == 'Arguments':
                            exec_info['arguments'] = child.text.strip()
                        elif child_tag == 'WorkingDirectory':
                            exec_info['working_directory'] = child.text.strip()
                
                actions.append(exec_info)
            
            elif tag == 'ComHandler':
                com_info = {
                    'type': 'ComHandler',
                    'class_id': '',
                    'data': '',
                }
                
                for child in action:
                    child_tag = child.tag.split('}')[-1] if '}' in child.tag else child.tag
                    if child.text:
                        if child_tag == 'ClassId':
                            com_info['class_id'] = child.text.strip()
                        elif child_tag == 'Data':
                            com_info['data'] = child.text.strip()
                
                actions.append(com_info)
        
        return actions
    
    def _extract_principal(self, root: ET.Element) -> Dict:
        """Extract principal (security context) information"""
        principal = {
            'user_id': '',
            'run_level': '',
            'logon_type': '',
        }
        
        # Try with namespace
        principal_el = root.find('.//task:Principals/task:Principal', self.TASK_NS)
        if principal_el is None:
            principal_el = root.find('.//Principals/Principal')
        
        if principal_el is None:
            return principal
        
        for child in principal_el:
            child_tag = child.tag.split('}')[-1] if '}' in child.tag else child.tag
            if child.text:
                if child_tag == 'UserId':
                    principal['user_id'] = child.text.strip()
                elif child_tag == 'RunLevel':
                    principal['run_level'] = child.text.strip()
                elif child_tag == 'LogonType':
                    principal['logon_type'] = child.text.strip()
                elif child_tag == 'GroupId':
                    principal['group_id'] = child.text.strip()
        
        return principal
    
    def parse(self, file_path: str) -> Generator[ParsedEvent, None, None]:
        """Parse Scheduled Task XML file"""
        if not self.can_parse(file_path):
            self.errors.append(f"Cannot parse file: {file_path}")
            return
        
        source_file = os.path.basename(file_path)
        hostname = self.extract_hostname(file_path)
        
        root = self._parse_xml_content(file_path)
        if root is None:
            return
        
        try:
            # Extract registration info
            author = self._get_text(root, './/task:RegistrationInfo/task:Author')
            uri = self._get_text(root, './/task:RegistrationInfo/task:URI')
            description = self._get_text(root, './/task:RegistrationInfo/task:Description')
            date_str = self._get_text(root, './/task:RegistrationInfo/task:Date')
            source = self._get_text(root, './/task:RegistrationInfo/task:Source')
            
            # Parse registration date
            timestamp = datetime.now()
            if date_str:
                ts = self.parse_timestamp(date_str)
                if ts:
                    timestamp = ts
            
            # Extract triggers
            triggers = self._extract_triggers(root)
            
            # Extract actions
            actions = self._extract_actions(root)
            
            # Extract principal
            principal = self._extract_principal(root)
            
            # Extract settings
            enabled = self._get_text(root, './/task:Settings/task:Enabled', 'true')
            hidden = self._get_text(root, './/task:Settings/task:Hidden', 'false')
            
            # Build command line from first Exec action
            command_line = ''
            process_name = ''
            if actions:
                for action in actions:
                    if action.get('type') == 'Exec':
                        cmd = action.get('command', '')
                        args = action.get('arguments', '')
                        command_line = f"{cmd} {args}".strip()
                        process_name = os.path.basename(cmd.replace('\\', '/')) if cmd else ''
                        break
            
            # Build raw data
            raw_data = {
                'task_name': source_file,
                'uri': uri,
                'author': author,
                'description': description,
                'registration_date': date_str,
                'source': source,
                'enabled': enabled.lower() == 'true',
                'hidden': hidden.lower() == 'true',
                'principal': principal,
                'triggers': triggers,
                'actions': actions,
            }
            
            # Build search blob
            search_parts = [source_file, uri, author, description, command_line]
            search_parts.extend(principal.get('user_id', ''))
            for action in actions:
                if action.get('command'):
                    search_parts.append(action['command'])
                if action.get('arguments'):
                    search_parts.append(action['arguments'])
            
            yield ParsedEvent(
                case_id=self.case_id,
                artifact_type=self.artifact_type,
                timestamp=timestamp,
                source_file=source_file,
                source_path=file_path,
                source_host=hostname,
                case_file_id=self.case_file_id,
                process_name=self.safe_str(process_name),
                command_line=self.safe_str(command_line),
                username=self.safe_str(principal.get('user_id', '')),
                raw_json=json.dumps(raw_data, default=str),
                search_blob=' '.join(str(p) for p in search_parts if p),
                extra_fields=json.dumps({
                    'uri': uri,
                    'author': author,
                    'enabled': enabled.lower() == 'true',
                    'hidden': hidden.lower() == 'true',
                    'run_level': principal.get('run_level', ''),
                    'trigger_count': len(triggers),
                    'action_count': len(actions),
                }, default=str),
                parser_version=self.parser_version,
            )
            
        except Exception as e:
            self.errors.append(f"Error parsing {file_path}: {e}")
            logger.exception(f"Scheduled task parse error: {e}")


# ============================================
# Windows Timeline / ActivitiesCache Parser
# ============================================

class ActivitiesCacheParser(BaseParser):
    """Parser for Windows Timeline ActivitiesCache.db
    
    Windows Timeline stores user activity data in SQLite database at:
    Users/<user>/AppData/Local/ConnectedDevicesPlatform/<device_id>/ActivitiesCache.db
    
    Contains:
    - Application usage history
    - File access history
    - Clipboard history
    - Focus time data
    - Cross-device sync data
    """
    
    VERSION = '1.0.0'
    ARTIFACT_TYPE = 'activities_cache'
    
    def __init__(self, case_id: int, source_host: str = '', case_file_id: Optional[int] = None):
        super().__init__(case_id, source_host, case_file_id)
    
    @property
    def artifact_type(self) -> str:
        return self.ARTIFACT_TYPE
    
    def can_parse(self, file_path: str) -> bool:
        """Check if file is an ActivitiesCache database"""
        if not os.path.isfile(file_path):
            return False
        
        filename = os.path.basename(file_path).lower()
        if filename != 'activitiescache.db':
            return False
        
        # Verify SQLite
        try:
            with open(file_path, 'rb') as f:
                magic = f.read(16)
                return magic.startswith(b'SQLite format 3')
        except:
            return False
    
    def _parse_activity_payload(self, payload_json: str) -> Dict:
        """Parse activity payload JSON"""
        try:
            if payload_json:
                return json.loads(payload_json)
        except:
            pass
        return {}
    
    def _filetime_to_datetime(self, filetime: int) -> Optional[datetime]:
        """Convert Windows FILETIME to datetime"""
        if not filetime or filetime <= 0:
            return None
        try:
            # FILETIME is 100-nanosecond intervals since 1601-01-01
            EPOCH_DIFF = 116444736000000000
            if filetime < EPOCH_DIFF:
                return None
            unix_ts = (filetime - EPOCH_DIFF) / 10000000.0
            return datetime.utcfromtimestamp(unix_ts)
        except (ValueError, OSError, OverflowError):
            return None
    
    def parse(self, file_path: str) -> Generator[ParsedEvent, None, None]:
        """Parse ActivitiesCache.db"""
        if not self.can_parse(file_path):
            self.errors.append(f"Cannot parse file: {file_path}")
            return
        
        source_file = os.path.basename(file_path)
        hostname = self.extract_hostname(file_path)
        
        # Copy to temp (SQLite needs write access for WAL)
        temp_dir = tempfile.mkdtemp()
        temp_path = os.path.join(temp_dir, source_file)
        
        try:
            shutil.copy2(file_path, temp_path)
            
            # Copy WAL and SHM if they exist
            for ext in ['-wal', '-shm', '-journal']:
                wal_path = file_path + ext
                if os.path.exists(wal_path):
                    shutil.copy2(wal_path, temp_path + ext)
            
            conn = sqlite3.connect(temp_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            # Query Activity table
            try:
                query = """
                    SELECT 
                        Id, AppId, PackageIdHash, AppActivityId,
                        ActivityType, ActivityStatus, Priority,
                        IsLocalOnly, ETag, CreatedInCloud,
                        StartTime, EndTime, LastModifiedTime,
                        ExpirationTime, Payload, OriginalPayload,
                        ClipboardPayload, PlatformDeviceId
                    FROM Activity
                    ORDER BY StartTime DESC
                """
                cursor.execute(query)
                
                activity_types = {
                    5: 'App in use/Focus',
                    6: 'App in use',
                    10: 'Clipboard',
                    16: 'Copy/Paste',
                }
                
                for row in cursor:
                    # Parse timestamps
                    start_time = self._filetime_to_datetime(row['StartTime'])
                    end_time = self._filetime_to_datetime(row['EndTime'])
                    last_modified = self._filetime_to_datetime(row['LastModifiedTime'])
                    
                    timestamp = start_time or last_modified or datetime.now()
                    
                    # Parse payload
                    payload = self._parse_activity_payload(row['Payload'])
                    
                    # Extract app info from payload
                    app_id = row['AppId'] or ''
                    display_text = payload.get('displayText', '')
                    description = payload.get('description', '')
                    content_uri = payload.get('contentUri', '')
                    app_display_name = payload.get('appDisplayName', '')
                    
                    # Activity type
                    activity_type = activity_types.get(row['ActivityType'], str(row['ActivityType']))
                    
                    # Calculate duration
                    duration_seconds = None
                    if start_time and end_time:
                        duration_seconds = int((end_time - start_time).total_seconds())
                    
                    raw_data = {
                        'id': row['Id'],
                        'app_id': app_id,
                        'app_activity_id': row['AppActivityId'],
                        'activity_type': activity_type,
                        'activity_type_id': row['ActivityType'],
                        'status': row['ActivityStatus'],
                        'priority': row['Priority'],
                        'is_local_only': bool(row['IsLocalOnly']),
                        'start_time': str(start_time) if start_time else None,
                        'end_time': str(end_time) if end_time else None,
                        'duration_seconds': duration_seconds,
                        'display_text': display_text,
                        'description': description,
                        'content_uri': content_uri,
                        'app_display_name': app_display_name,
                        'platform_device_id': row['PlatformDeviceId'],
                        'payload': payload,
                    }
                    
                    # Build search blob
                    search_parts = [app_id, display_text, description, content_uri, app_display_name, activity_type]
                    
                    yield ParsedEvent(
                        case_id=self.case_id,
                        artifact_type=self.artifact_type,
                        timestamp=timestamp,
                        source_file=source_file,
                        source_path=file_path,
                        source_host=hostname,
                        case_file_id=self.case_file_id,
                        process_name=self.safe_str(app_display_name or app_id),
                        target_path=self.safe_str(content_uri),
                        raw_json=json.dumps(raw_data, default=str),
                        search_blob=' '.join(str(p) for p in search_parts if p),
                        extra_fields=json.dumps({
                            'activity_type': activity_type,
                            'duration_seconds': duration_seconds,
                            'is_local_only': bool(row['IsLocalOnly']),
                        }, default=str),
                        parser_version=self.parser_version,
                    )
                    
            except sqlite3.OperationalError as e:
                self.warnings.append(f"Error querying Activity table: {e}")
            
            # Query ActivityOperation table (clipboard, etc.)
            try:
                query = """
                    SELECT 
                        OperationOrder, AppId, ActivityType,
                        CreatedTime, EndTime, LastModifiedTime,
                        OperationType, Payload, ClipboardPayload
                    FROM ActivityOperation
                    ORDER BY CreatedTime DESC
                """
                cursor.execute(query)
                
                for row in cursor:
                    created_time = self._filetime_to_datetime(row['CreatedTime'])
                    timestamp = created_time or datetime.now()
                    
                    payload = self._parse_activity_payload(row['Payload'])
                    clipboard_payload = self._parse_activity_payload(row['ClipboardPayload'])
                    
                    app_id = row['AppId'] or ''
                    activity_type = activity_types.get(row['ActivityType'], str(row['ActivityType']))
                    
                    raw_data = {
                        'operation_order': row['OperationOrder'],
                        'app_id': app_id,
                        'activity_type': activity_type,
                        'activity_type_id': row['ActivityType'],
                        'operation_type': row['OperationType'],
                        'created_time': str(created_time) if created_time else None,
                        'payload': payload,
                        'clipboard_payload': clipboard_payload,
                    }
                    
                    yield ParsedEvent(
                        case_id=self.case_id,
                        artifact_type='activity_operation',
                        timestamp=timestamp,
                        source_file=source_file,
                        source_path=file_path,
                        source_host=hostname,
                        case_file_id=self.case_file_id,
                        process_name=self.safe_str(app_id),
                        raw_json=json.dumps(raw_data, default=str),
                        search_blob=f"{app_id} {activity_type}",
                        parser_version=self.parser_version,
                    )
                    
            except sqlite3.OperationalError as e:
                self.warnings.append(f"Error querying ActivityOperation table: {e}")
            
            conn.close()
            
        except Exception as e:
            self.errors.append(f"Error parsing {file_path}: {e}")
            logger.exception(f"ActivitiesCache parse error: {e}")
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)


# ============================================
# WebCache Parser (IE/Edge)
# ============================================

class WebCacheParser(BaseParser):
    """Parser for Windows WebCache (WebCacheV01.dat)
    
    Windows stores Internet Explorer and legacy Edge browsing data at:
    Users/<user>/AppData/Local/Microsoft/Windows/WebCache/WebCacheV01.dat
    
    This is an ESE (Extensible Storage Engine) database containing:
    - Browsing history (containers)
    - Cookies
    - Download history
    - Cache entries
    """
    
    VERSION = '1.0.0'
    ARTIFACT_TYPE = 'webcache'
    
    # Known container types
    CONTAINER_TYPES = {
        'Content': 'cache',
        'Cookies': 'cookies',
        'History': 'history',
        'DOMStore': 'dom_storage',
        'iedownload': 'downloads',
        'iecompat': 'compatibility',
    }
    
    def __init__(self, case_id: int, source_host: str = '', case_file_id: Optional[int] = None):
        super().__init__(case_id, source_host, case_file_id)
        
        try:
            from dissect.esedb import EseDB
            self._esedb_class = EseDB
        except ImportError:
            self._esedb_class = None
    
    @property
    def artifact_type(self) -> str:
        return self.ARTIFACT_TYPE
    
    def can_parse(self, file_path: str) -> bool:
        """Check if file is a WebCache database"""
        if not os.path.isfile(file_path):
            return False
        
        filename = os.path.basename(file_path).lower()
        if filename not in ('webcachev01.dat', 'webcachev24.dat'):
            return False
        
        return True
    
    def _filetime_to_datetime(self, filetime: int) -> Optional[datetime]:
        """Convert Windows FILETIME to datetime"""
        if not filetime or filetime <= 0:
            return None
        try:
            EPOCH_DIFF = 116444736000000000
            if filetime < EPOCH_DIFF:
                return None
            unix_ts = (filetime - EPOCH_DIFF) / 10000000.0
            return datetime.utcfromtimestamp(unix_ts)
        except (ValueError, OSError, OverflowError):
            return None
    
    def parse(self, file_path: str) -> Generator[ParsedEvent, None, None]:
        """Parse WebCache ESE database"""
        if not self.can_parse(file_path):
            self.errors.append(f"Cannot parse file: {file_path}")
            return
        
        if self._esedb_class is None:
            self.errors.append("dissect.esedb not installed")
            return
        
        source_file = os.path.basename(file_path)
        hostname = self.extract_hostname(file_path)
        
        try:
            from dissect.esedb import EseDB
            
            db = EseDB(open(file_path, 'rb'))
            
            # First, get container mapping from Containers table
            containers = {}
            for table in db.tables():
                if table.name == 'Containers':
                    for record in table.records():
                        try:
                            container_id = record.get('ContainerId')
                            name = record.get('Name')
                            directory = record.get('Directory')
                            
                            if container_id is not None and name:
                                if isinstance(name, bytes):
                                    name = name.decode('utf-16-le', errors='replace').rstrip('\x00')
                                containers[container_id] = {
                                    'name': str(name),
                                    'directory': str(directory) if directory else '',
                                }
                        except:
                            pass
                    break
            
            logger.info(f"Found {len(containers)} containers in WebCache")
            
            # Process container tables (named Container_N)
            for table in db.tables():
                table_name = table.name
                
                # Match Container_N pattern
                if not table_name.startswith('Container_'):
                    continue
                
                try:
                    container_id = int(table_name.split('_')[1])
                except (IndexError, ValueError):
                    continue
                
                container_info = containers.get(container_id, {'name': 'Unknown', 'directory': ''})
                container_name = container_info['name']
                
                # Determine container type
                container_type = 'unknown'
                for key, ctype in self.CONTAINER_TYPES.items():
                    if key.lower() in container_name.lower():
                        container_type = ctype
                        break
                
                try:
                    columns = table.columns
                    column_names = [c.name for c in columns]
                    
                    for record in table.records():
                        try:
                            record_dict = {}
                            for col in columns:
                                try:
                                    value = record.get(col.name)
                                    if value is not None:
                                        if isinstance(value, bytes):
                                            try:
                                                value = value.decode('utf-16-le').rstrip('\x00')
                                            except:
                                                try:
                                                    value = value.decode('utf-8', errors='replace')
                                                except:
                                                    value = value.hex()[:100]
                                        record_dict[col.name] = str(value)
                                except:
                                    pass
                            
                            # Extract URL
                            url = record_dict.get('Url', record_dict.get('url', ''))
                            
                            # Skip empty entries
                            if not url and not record_dict:
                                continue
                            
                            # Parse timestamps
                            timestamp = datetime.now()
                            for ts_field in ['AccessedTime', 'ModifiedTime', 'CreationTime', 'SyncTime']:
                                if ts_field in record_dict:
                                    try:
                                        ts_val = int(record_dict[ts_field])
                                        ts = self._filetime_to_datetime(ts_val)
                                        if ts:
                                            timestamp = ts
                                            break
                                    except:
                                        pass
                            
                            raw_data = {
                                'container_id': container_id,
                                'container_name': container_name,
                                'container_type': container_type,
                                'url': url,
                                'record': record_dict,
                            }
                            
                            # Build search blob
                            search_parts = [url, container_name, container_type]
                            
                            yield ParsedEvent(
                                case_id=self.case_id,
                                artifact_type=f'webcache_{container_type}',
                                timestamp=timestamp,
                                source_file=source_file,
                                source_path=file_path,
                                source_host=hostname,
                                case_file_id=self.case_file_id,
                                target_path=self.safe_str(url),
                                raw_json=json.dumps(raw_data, default=str),
                                search_blob=' '.join(str(p) for p in search_parts if p),
                                extra_fields=json.dumps({
                                    'container_id': container_id,
                                    'container_name': container_name,
                                    'container_type': container_type,
                                }, default=str),
                                parser_version=self.parser_version,
                            )
                            
                        except Exception as e:
                            self.warnings.append(f"Error processing record: {e}")
                            
                except Exception as e:
                    self.warnings.append(f"Error processing table {table_name}: {e}")
                    
        except Exception as e:
            self.errors.append(f"Failed to parse {file_path}: {e}")
            logger.exception(f"WebCache parse error: {e}")
