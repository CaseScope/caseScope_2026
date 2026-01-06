"""
WMI Persistence Parser
======================
Parses WMI Repository files for persistence mechanisms
Location: Windows\System32\wbem\Repository\OBJECTS.DATA
          Windows\System32\wbem\Repository\INDEX.BTR
          Windows\System32\wbem\Repository\MAPPING*.MAP
Routes to: case_X_events index

Extracts:
- EventFilter definitions (trigger conditions)
- EventConsumer definitions (actions to execute)
- FilterToConsumerBinding (links filters to consumers)
- Suspicious command lines and scripts

Evidence Value:
- Malware persistence mechanisms
- Fileless malware detection
- Backdoor triggers
- Lateral movement evidence
"""

import os
import re
import struct
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

# Known malicious WMI patterns
SUSPICIOUS_PATTERNS = [
    r'powershell',
    r'cmd\.exe',
    r'wscript',
    r'cscript',
    r'mshta',
    r'regsvr32',
    r'rundll32',
    r'certutil',
    r'bitsadmin',
    r'base64',
    r'downloadstring',
    r'invoke-expression',
    r'iex\s*\(',
    r'webclient',
    r'downloadfile',
    r'frombase64',
    r'hidden',
    r'bypass',
    r'encodedcommand',
    r'-enc\s',
    r'-e\s',
    r'vbscript:',
    r'javascript:',
]

# WMI class names of interest
WMI_PERSISTENCE_CLASSES = [
    '__EventFilter',
    '__EventConsumer', 
    'CommandLineEventConsumer',
    'ActiveScriptEventConsumer',
    '__FilterToConsumerBinding',
    '__TimerInstruction',
    '__AbsoluteTimerInstruction',
    '__IntervalTimerInstruction',
]


def extract_strings(data, min_length=6):
    """Extract ASCII and Unicode strings from binary data"""
    strings = []
    
    # ASCII strings
    ascii_pattern = rb'[\x20-\x7e]{' + str(min_length).encode() + rb',}'
    for match in re.finditer(ascii_pattern, data):
        try:
            s = match.group().decode('ascii', errors='ignore')
            strings.append(s)
        except:
            pass
    
    # Unicode strings (UTF-16LE)
    unicode_pattern = rb'(?:[\x20-\x7e]\x00){' + str(min_length).encode() + rb',}'
    for match in re.finditer(unicode_pattern, data):
        try:
            s = match.group().decode('utf-16-le', errors='ignore')
            if len(s) >= min_length:
                strings.append(s)
        except:
            pass
    
    return strings


def find_wmi_classes(data):
    """Find WMI class definitions in binary data"""
    findings = []
    
    for class_name in WMI_PERSISTENCE_CLASSES:
        # Search for class name in both ASCII and Unicode
        ascii_pattern = class_name.encode('ascii')
        unicode_pattern = class_name.encode('utf-16-le')
        
        for match in re.finditer(re.escape(ascii_pattern), data):
            findings.append({
                'class': class_name,
                'offset': match.start(),
                'encoding': 'ascii'
            })
        
        for match in re.finditer(re.escape(unicode_pattern), data):
            findings.append({
                'class': class_name,
                'offset': match.start(),
                'encoding': 'unicode'
            })
    
    return findings


def extract_wmi_context(data, offset, context_size=2000):
    """Extract context around a WMI finding"""
    start = max(0, offset - 500)
    end = min(len(data), offset + context_size)
    
    context_data = data[start:end]
    strings = extract_strings(context_data, min_length=4)
    
    return strings


def check_suspicious(strings):
    """Check for suspicious patterns in extracted strings"""
    suspicious = []
    
    combined = ' '.join(strings).lower()
    
    for pattern in SUSPICIOUS_PATTERNS:
        if re.search(pattern, combined, re.IGNORECASE):
            suspicious.append(pattern)
    
    return suspicious


def parse_wmi_objects_data(file_path):
    """
    Parse WMI OBJECTS.DATA file
    
    Yields WMI persistence events
    """
    if not os.path.exists(file_path):
        logger.error(f"WMI file not found: {file_path}")
        return
    
    filename = os.path.basename(file_path)
    
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
        
        file_size = len(data)
        logger.info(f"Parsing WMI OBJECTS.DATA: {filename} ({file_size} bytes)")
        
        # Find WMI class instances
        findings = find_wmi_classes(data)
        
        logger.info(f"Found {len(findings)} WMI class references")
        
        # Process each finding
        seen_contexts = set()
        
        for finding in findings:
            # Extract context around finding
            context_strings = extract_wmi_context(data, finding['offset'])
            
            # Create unique key to avoid duplicates
            context_key = hash(tuple(sorted(context_strings[:10])))
            
            if context_key in seen_contexts:
                continue
            seen_contexts.add(context_key)
            
            # Check for suspicious patterns
            suspicious = check_suspicious(context_strings)
            
            event = {
                '@timestamp': datetime.utcnow().isoformat(),
                'event_type': 'wmi_persistence',
                'wmi_class': finding['class'],
                'offset': finding['offset'],
                'encoding': finding['encoding'],
                'source_file': filename,
                'artifact_type': 'wmi_repository'
            }
            
            # Extract relevant strings
            commands = []
            scripts = []
            names = []
            queries = []
            
            for s in context_strings:
                s_lower = s.lower()
                
                # Command lines
                if any(cmd in s_lower for cmd in ['cmd', 'powershell', 'wscript', 'cscript', 'mshta']):
                    if len(s) > 10:
                        commands.append(s)
                
                # Scripts (VBS, JS, PS)
                if any(ext in s_lower for ext in ['.vbs', '.js', '.ps1', 'vbscript', 'javascript']):
                    scripts.append(s)
                
                # WMI queries
                if 'select' in s_lower and 'from' in s_lower:
                    queries.append(s)
                
                # Names (for filters/consumers)
                if 'name' in s_lower or finding['class'].lower() in s_lower:
                    if len(s) < 200:
                        names.append(s)
            
            if commands:
                event['commands'] = list(set(commands))[:5]
            
            if scripts:
                event['scripts'] = list(set(scripts))[:5]
            
            if queries:
                event['wmi_queries'] = list(set(queries))[:5]
            
            if names:
                event['names'] = list(set(names))[:10]
            
            if suspicious:
                event['suspicious_patterns'] = suspicious
                event['risk_level'] = 'high' if len(suspicious) > 2 else 'medium'
            else:
                event['risk_level'] = 'low'
            
            yield event
        
        # Also scan for any suspicious commands regardless of WMI class context
        all_strings = extract_strings(data, min_length=20)
        suspicious_commands = []
        
        for s in all_strings:
            s_lower = s.lower()
            
            # Look for command execution patterns
            if any(pattern in s_lower for pattern in ['powershell', 'cmd /c', 'cmd.exe', 'wscript', 'cscript']):
                suspicious = check_suspicious([s])
                if suspicious:
                    suspicious_commands.append({
                        'command': s[:500],
                        'patterns': suspicious
                    })
        
        # Deduplicate and yield
        seen_cmds = set()
        for cmd_info in suspicious_commands:
            cmd_key = cmd_info['command'][:100]
            if cmd_key not in seen_cmds:
                seen_cmds.add(cmd_key)
                
                event = {
                    '@timestamp': datetime.utcnow().isoformat(),
                    'event_type': 'wmi_suspicious_command',
                    'command': cmd_info['command'],
                    'suspicious_patterns': cmd_info['patterns'],
                    'risk_level': 'high',
                    'source_file': filename,
                    'artifact_type': 'wmi_repository'
                }
                
                yield event
    
    except Exception as e:
        logger.error(f"Error parsing WMI OBJECTS.DATA {file_path}: {e}")
        import traceback
        traceback.print_exc()


def parse_wmi_index(file_path):
    """
    Parse WMI INDEX.BTR file
    
    Yields index metadata events
    """
    if not os.path.exists(file_path):
        logger.error(f"WMI index file not found: {file_path}")
        return
    
    filename = os.path.basename(file_path)
    
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
        
        file_size = len(data)
        logger.info(f"Parsing WMI INDEX.BTR: {filename} ({file_size} bytes)")
        
        # Extract strings for class names and namespaces
        strings = extract_strings(data, min_length=8)
        
        # Filter for WMI-related strings
        wmi_strings = []
        for s in strings:
            if any(cls in s for cls in WMI_PERSISTENCE_CLASSES):
                wmi_strings.append(s)
            elif 'root\\' in s.lower() or 'cimv2' in s.lower():
                wmi_strings.append(s)
        
        if wmi_strings:
            event = {
                '@timestamp': datetime.utcnow().isoformat(),
                'event_type': 'wmi_index',
                'wmi_references': list(set(wmi_strings))[:50],
                'reference_count': len(set(wmi_strings)),
                'source_file': filename,
                'artifact_type': 'wmi_repository'
            }
            
            yield event
    
    except Exception as e:
        logger.error(f"Error parsing WMI INDEX.BTR {file_path}: {e}")


def parse_wmi_file(file_path):
    """Parse WMI repository file (auto-detect type)"""
    filename = os.path.basename(file_path).lower()
    
    if filename == 'objects.data':
        logger.info(f"Detected WMI OBJECTS.DATA: {filename}")
        return parse_wmi_objects_data(file_path)
    elif filename == 'index.btr':
        logger.info(f"Detected WMI INDEX.BTR: {filename}")
        return parse_wmi_index(file_path)
    elif filename.startswith('mapping') and filename.endswith('.map'):
        logger.info(f"Detected WMI MAPPING file: {filename}")
        # Mapping files are less useful for forensics, skip
        return iter([])
    else:
        logger.warning(f"Not a WMI repository file: {filename}")
        return iter([])
