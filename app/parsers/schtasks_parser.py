r"""
Scheduled Tasks Parser
======================
Parses Windows Scheduled Task XML files
Location: Windows\System32\Tasks\ (and subdirectories)
          Windows\SysWOW64\Tasks\
Routes to: case_X_events index

Extracts:
- Task name and path
- Actions (commands, scripts to execute)
- Triggers (when task runs)
- Principal (user context)
- Registration info (author, date)
- Settings (hidden, run elevated, etc.)

Evidence Value:
- Persistence mechanisms
- Lateral movement (remote scheduled tasks)
- Backdoors
- Malware execution schedules
- Legitimate vs suspicious task differentiation
"""

import os
import xml.etree.ElementTree as ET
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

# Suspicious patterns in scheduled tasks
SUSPICIOUS_PATTERNS = [
    'powershell',
    'cmd.exe',
    'wscript',
    'cscript',
    'mshta',
    'regsvr32',
    'rundll32',
    'certutil',
    'bitsadmin',
    'base64',
    '-enc',
    '-encoded',
    'downloadstring',
    'invoke-expression',
    'iex',
    'webclient',
    'hidden',
    'bypass',
    'noprofile',
    'temp\\',
    'tmp\\',
    'appdata\\',
    'programdata\\',
]

# Known legitimate Windows tasks (not exhaustive, for context)
KNOWN_WINDOWS_TASKS = [
    'Microsoft\\Windows\\',
    'Microsoft\\Office\\',
    'Microsoft\\EdgeUpdate\\',
    'GoogleUpdate',
    'Adobe Acrobat Update',
]


def parse_scheduled_task_xml(file_path):
    """
    Parse a Windows Scheduled Task XML file
    
    Yields task configuration events
    """
    if not os.path.exists(file_path):
        logger.error(f"Task file not found: {file_path}")
        return
    
    filename = os.path.basename(file_path)
    
    try:
        tree = ET.parse(file_path)
        root = tree.getroot()
        
        # Handle namespace
        ns = {'task': 'http://schemas.microsoft.com/windows/2004/02/mit/task'}
        
        # Also try without namespace for older formats
        def find_element(parent, tag):
            """Find element with or without namespace"""
            # Try with namespace
            elem = parent.find(f'task:{tag}', ns)
            if elem is not None:
                return elem
            # Try without namespace
            elem = parent.find(tag)
            if elem is not None:
                return elem
            # Try finding by local name
            for child in parent:
                if child.tag.endswith(tag) or child.tag == tag:
                    return child
            return None
        
        def find_text(parent, tag, default=''):
            """Find element text with or without namespace"""
            elem = find_element(parent, tag)
            return elem.text if elem is not None and elem.text else default
        
        def find_all_elements(parent, tag):
            """Find all elements with or without namespace"""
            elements = parent.findall(f'task:{tag}', ns)
            if not elements:
                elements = parent.findall(tag)
            if not elements:
                elements = [child for child in parent if child.tag.endswith(tag)]
            return elements
        
        event = {
            '@timestamp': datetime.utcnow().isoformat(),
            'event_type': 'scheduled_task',
            'task_name': filename,
            'source_file': filename,
            'artifact_type': 'scheduled_task'
        }
        
        # Parse RegistrationInfo
        reg_info = find_element(root, 'RegistrationInfo')
        if reg_info is not None:
            event['author'] = find_text(reg_info, 'Author')
            event['description'] = find_text(reg_info, 'Description')
            event['source'] = find_text(reg_info, 'Source')
            event['uri'] = find_text(reg_info, 'URI')
            
            date_str = find_text(reg_info, 'Date')
            if date_str:
                try:
                    # Parse ISO format date
                    event['registration_date'] = date_str
                    event['@timestamp'] = date_str
                except:
                    pass
        
        # Parse Principals (who runs the task)
        principals = find_element(root, 'Principals')
        if principals is not None:
            principal = find_element(principals, 'Principal')
            if principal is not None:
                event['user_id'] = find_text(principal, 'UserId')
                event['logon_type'] = find_text(principal, 'LogonType')
                event['run_level'] = find_text(principal, 'RunLevel')
                
                if event.get('run_level', '').lower() == 'highestavailable':
                    event['runs_elevated'] = True
        
        # Parse Actions (what the task does)
        actions = find_element(root, 'Actions')
        if actions is not None:
            action_list = []
            
            # Exec actions
            for exec_elem in find_all_elements(actions, 'Exec'):
                action = {
                    'type': 'exec',
                    'command': find_text(exec_elem, 'Command'),
                    'arguments': find_text(exec_elem, 'Arguments'),
                    'working_directory': find_text(exec_elem, 'WorkingDirectory')
                }
                action_list.append(action)
            
            # COM handler actions
            for com_elem in find_all_elements(actions, 'ComHandler'):
                action = {
                    'type': 'com_handler',
                    'class_id': find_text(com_elem, 'ClassId'),
                    'data': find_text(com_elem, 'Data')
                }
                action_list.append(action)
            
            # Email actions (deprecated but still used)
            for email_elem in find_all_elements(actions, 'SendEmail'):
                action = {
                    'type': 'send_email',
                    'to': find_text(email_elem, 'To'),
                    'subject': find_text(email_elem, 'Subject')
                }
                action_list.append(action)
            
            if action_list:
                event['actions'] = action_list
                
                # Build full command line for analysis
                commands = []
                for action in action_list:
                    if action['type'] == 'exec':
                        cmd = action.get('command', '')
                        args = action.get('arguments', '')
                        full_cmd = f"{cmd} {args}".strip()
                        if full_cmd:
                            commands.append(full_cmd)
                
                if commands:
                    event['command_lines'] = commands
        
        # Parse Triggers (when the task runs)
        triggers = find_element(root, 'Triggers')
        if triggers is not None:
            trigger_list = []
            
            trigger_types = [
                'CalendarTrigger', 'TimeTrigger', 'BootTrigger', 
                'LogonTrigger', 'IdleTrigger', 'RegistrationTrigger',
                'SessionStateChangeTrigger', 'EventTrigger', 'WnfStateChangeTrigger'
            ]
            
            for trigger_type in trigger_types:
                for trigger_elem in find_all_elements(triggers, trigger_type):
                    trigger = {
                        'type': trigger_type.replace('Trigger', ''),
                        'enabled': find_text(trigger_elem, 'Enabled', 'true')
                    }
                    
                    start_boundary = find_text(trigger_elem, 'StartBoundary')
                    if start_boundary:
                        trigger['start_boundary'] = start_boundary
                    
                    # Event trigger specific
                    if trigger_type == 'EventTrigger':
                        subscription = find_element(trigger_elem, 'Subscription')
                        if subscription is not None and subscription.text:
                            trigger['subscription'] = subscription.text
                    
                    trigger_list.append(trigger)
            
            if trigger_list:
                event['triggers'] = trigger_list
                event['trigger_types'] = list(set(t['type'] for t in trigger_list))
        
        # Parse Settings
        settings = find_element(root, 'Settings')
        if settings is not None:
            event['hidden'] = find_text(settings, 'Hidden', 'false').lower() == 'true'
            event['allow_start_on_demand'] = find_text(settings, 'AllowStartOnDemand', 'true').lower() == 'true'
            event['stop_if_going_on_batteries'] = find_text(settings, 'StopIfGoingOnBatteries', 'true').lower() == 'true'
            event['run_only_if_network_available'] = find_text(settings, 'RunOnlyIfNetworkAvailable', 'false').lower() == 'true'
            event['enabled'] = find_text(settings, 'Enabled', 'true').lower() == 'true'
        
        # Analyze for suspicion
        suspicious_indicators = []
        
        # Check command lines for suspicious patterns
        for cmd in event.get('command_lines', []):
            cmd_lower = cmd.lower()
            for pattern in SUSPICIOUS_PATTERNS:
                if pattern in cmd_lower:
                    suspicious_indicators.append(f'command_contains_{pattern}')
        
        # Check if task is hidden
        if event.get('hidden'):
            suspicious_indicators.append('task_hidden')
        
        # Check for non-standard locations
        is_known = False
        task_path = event.get('uri', '') or filename
        for known in KNOWN_WINDOWS_TASKS:
            if known.lower() in task_path.lower():
                is_known = True
                break
        
        if not is_known and '\\' not in task_path:
            suspicious_indicators.append('non_standard_location')
        
        # Check for boot/logon triggers with exec actions
        trigger_types = event.get('trigger_types', [])
        if ('Boot' in trigger_types or 'Logon' in trigger_types) and event.get('actions'):
            suspicious_indicators.append('persistence_trigger')
        
        if suspicious_indicators:
            event['suspicious_indicators'] = list(set(suspicious_indicators))
            event['risk_level'] = 'high' if len(suspicious_indicators) > 2 else 'medium'
        else:
            event['risk_level'] = 'low'
        
        yield event
    
    except ET.ParseError as e:
        logger.error(f"XML parse error for {file_path}: {e}")
        
        # Try to extract what we can from invalid XML
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            event = {
                '@timestamp': datetime.utcnow().isoformat(),
                'event_type': 'scheduled_task_parse_error',
                'task_name': filename,
                'parse_error': str(e),
                'source_file': filename,
                'artifact_type': 'scheduled_task'
            }
            
            # Extract any commands visible in raw content
            import re
            commands = re.findall(r'<Command>([^<]+)</Command>', content)
            if commands:
                event['extracted_commands'] = commands
            
            yield event
        
        except:
            pass
    
    except Exception as e:
        logger.error(f"Error parsing task {file_path}: {e}")
        import traceback
        traceback.print_exc()


def parse_scheduled_task_file(file_path):
    """Parse scheduled task file"""
    filename = os.path.basename(file_path).lower()
    
    # Task files are XML but often don't have .xml extension
    if filename.endswith('.xml') or not '.' in filename:
        logger.info(f"Parsing scheduled task: {filename}")
        return parse_scheduled_task_xml(file_path)
    else:
        # Try to parse anyway - might be a task file
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read(100)
            
            if '<?xml' in content or '<Task' in content:
                logger.info(f"Detected scheduled task XML: {filename}")
                return parse_scheduled_task_xml(file_path)
        except:
            pass
        
        logger.warning(f"Not a scheduled task file: {filename}")
        return iter([])
