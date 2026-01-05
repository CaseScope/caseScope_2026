r"""
USB Device History Parser
=========================
Comprehensive USB device history extraction from multiple sources
Sources:
- setupapi.dev.log (device installations)
- SYSTEM registry hive (via exported .reg files)
- USBSTOR entries
- MountedDevices
Routes to: case_X_devices index

Extracts:
- USB device connections with timestamps
- Device serial numbers
- Vendor/Product IDs
- First/Last connection times
- Volume GUIDs and mount points
- Device friendly names

Evidence Value:
- Data exfiltration via USB
- Unauthorized device usage
- Timeline of device connections
- Malware delivery via USB
"""

import os
import re
import logging
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

# USB VID/PID patterns
USB_VIDPID_PATTERN = re.compile(r'VID_([0-9A-Fa-f]{4})&PID_([0-9A-Fa-f]{4})')
USB_SERIAL_PATTERN = re.compile(r'USB\\VID_([0-9A-Fa-f]{4})&PID_([0-9A-Fa-f]{4})\\([^\\&\s]+)')
USBSTOR_PATTERN = re.compile(r'USBSTOR\\(Disk|CdRom)&Ven_([^&]+)&Prod_([^&]+)&Rev_([^\\]+)\\([^\\&\s]+)')

# Windows FILETIME epoch
FILETIME_EPOCH = datetime(1601, 1, 1)

# Known USB vendors (subset for enrichment)
KNOWN_VENDORS = {
    '0781': 'SanDisk',
    '090C': 'Silicon Motion',
    '0951': 'Kingston',
    '13FE': 'Phison/Kingston',
    '058F': 'Alcor Micro',
    '0930': 'Toshiba',
    '1908': 'ADATA',
    '0BC2': 'Seagate',
    '0BDA': 'Realtek',
    '8564': 'Transcend',
    '1B1C': 'Corsair',
    '0CF3': 'Atheros',
    '1058': 'Western Digital',
    '05AC': 'Apple',
    '045E': 'Microsoft',
    '046D': 'Logitech',
    '04E8': 'Samsung',
    '18D1': 'Google',
    '2717': 'Xiaomi',
    '22D9': 'OPPO',
    '12D1': 'Huawei',
}


def filetime_to_datetime(filetime):
    """Convert Windows FILETIME to Python datetime"""
    try:
        if not filetime or filetime == 0:
            return None
        return FILETIME_EPOCH + timedelta(microseconds=filetime / 10)
    except:
        return None


def get_vendor_name(vid):
    """Look up vendor name from VID"""
    return KNOWN_VENDORS.get(vid.upper(), f'VID_{vid}')


def parse_setupapi_dev_log(file_path):
    """
    Parse setupapi.dev.log for USB device history
    
    Yields device connection events
    """
    if not os.path.exists(file_path):
        logger.error(f"setupapi.dev.log not found: {file_path}")
        return
    
    filename = os.path.basename(file_path)
    
    try:
        current_timestamp = None
        section_lines = []
        
        # Try different encodings
        encodings = ['utf-16-le', 'utf-16', 'utf-8', 'latin-1']
        content = None
        
        for encoding in encodings:
            try:
                with open(file_path, 'r', encoding=encoding, errors='ignore') as f:
                    content = f.read()
                if content and len(content) > 100:
                    break
            except:
                continue
        
        if not content:
            logger.error(f"Could not read setupapi.dev.log: {filename}")
            return
        
        lines = content.split('\n')
        
        # Date patterns in setupapi.dev.log
        date_pattern1 = re.compile(r'>>>  \[(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?)\]')
        date_pattern2 = re.compile(r'\[(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})\.\d+\]')
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
            
            # Parse timestamp
            match = date_pattern1.search(line) or date_pattern2.search(line)
            if match:
                date_str = match.group(1)
                try:
                    if '.' in date_str:
                        current_timestamp = datetime.strptime(date_str.split('.')[0], '%Y/%m/%d %H:%M:%S')
                    else:
                        current_timestamp = datetime.strptime(date_str, '%Y/%m/%d %H:%M:%S')
                except:
                    pass
            
            # Look for USB device entries
            usb_match = USB_SERIAL_PATTERN.search(line)
            if usb_match and current_timestamp:
                vid = usb_match.group(1).upper()
                pid = usb_match.group(2).upper()
                serial = usb_match.group(3)
                
                # Clean serial number
                serial = serial.split('\\')[0].split('&')[0]
                
                event = {
                    '@timestamp': current_timestamp.isoformat(),
                    'event_type': 'usb_device_install',
                    'vendor_id': vid,
                    'product_id': pid,
                    'serial_number': serial,
                    'vendor_name': get_vendor_name(vid),
                    'device_class': 'USB',
                    'source_file': filename,
                    'artifact_type': 'usb_history'
                }
                
                yield event
            
            # Look for USBSTOR entries
            usbstor_match = USBSTOR_PATTERN.search(line)
            if usbstor_match and current_timestamp:
                device_type = usbstor_match.group(1)
                vendor = usbstor_match.group(2).replace('_', ' ').strip()
                product = usbstor_match.group(3).replace('_', ' ').strip()
                revision = usbstor_match.group(4)
                serial = usbstor_match.group(5).split('&')[0]
                
                event = {
                    '@timestamp': current_timestamp.isoformat(),
                    'event_type': 'usb_storage_install',
                    'device_type': device_type,
                    'vendor': vendor,
                    'product': product,
                    'revision': revision,
                    'serial_number': serial,
                    'device_class': 'USBSTOR',
                    'source_file': filename,
                    'artifact_type': 'usb_history'
                }
                
                yield event
        
        logger.info(f"Parsed setupapi.dev.log: {filename}")
    
    except Exception as e:
        logger.error(f"Error parsing setupapi.dev.log {file_path}: {e}")
        import traceback
        traceback.print_exc()


def parse_registry_export(file_path):
    """
    Parse exported .reg file for USB device history
    
    Look for USBSTOR, USB, and MountedDevices keys
    """
    if not os.path.exists(file_path):
        logger.error(f"Registry export not found: {file_path}")
        return
    
    filename = os.path.basename(file_path)
    
    try:
        # Read registry export
        encodings = ['utf-16-le', 'utf-16', 'utf-8', 'latin-1']
        content = None
        
        for encoding in encodings:
            try:
                with open(file_path, 'r', encoding=encoding, errors='ignore') as f:
                    content = f.read()
                if content and 'REGEDIT' in content.upper():
                    break
            except:
                continue
        
        if not content:
            logger.warning(f"Not a valid registry export: {filename}")
            return
        
        # Parse USBSTOR entries
        usbstor_pattern = re.compile(
            r'\[HKEY_LOCAL_MACHINE\\SYSTEM\\.*?ControlSet.*?\\Enum\\USBSTOR\\([^\]]+)\\\]([^\[]*)',
            re.IGNORECASE | re.DOTALL
        )
        
        for match in usbstor_pattern.finditer(content):
            device_path = match.group(1)
            properties = match.group(2)
            
            # Parse device path
            parts = device_path.split('\\')
            if len(parts) >= 2:
                device_desc = parts[0]  # e.g., "Disk&Ven_SanDisk&Prod_Cruzer&Rev_1.00"
                serial = parts[1].split('&')[0]
                
                # Parse device description
                desc_match = re.match(r'(Disk|CdRom)&Ven_([^&]+)&Prod_([^&]+)(?:&Rev_([^\\]+))?', device_desc)
                
                if desc_match:
                    event = {
                        '@timestamp': datetime.utcnow().isoformat(),
                        'event_type': 'usb_registry_entry',
                        'device_type': desc_match.group(1),
                        'vendor': desc_match.group(2).replace('_', ' ').strip(),
                        'product': desc_match.group(3).replace('_', ' ').strip(),
                        'revision': desc_match.group(4) if desc_match.group(4) else None,
                        'serial_number': serial,
                        'device_class': 'USBSTOR',
                        'source_file': filename,
                        'artifact_type': 'usb_history'
                    }
                    
                    # Extract friendly name if present
                    friendly_match = re.search(r'"FriendlyName"="([^"]+)"', properties)
                    if friendly_match:
                        event['friendly_name'] = friendly_match.group(1)
                    
                    yield event
        
        # Parse USB entries (VID/PID)
        usb_pattern = re.compile(
            r'\[HKEY_LOCAL_MACHINE\\SYSTEM\\.*?ControlSet.*?\\Enum\\USB\\VID_([0-9A-Fa-f]+)&PID_([0-9A-Fa-f]+)\\([^\]]+)\]([^\[]*)',
            re.IGNORECASE | re.DOTALL
        )
        
        for match in usb_pattern.finditer(content):
            vid = match.group(1).upper()
            pid = match.group(2).upper()
            serial = match.group(3).split('&')[0]
            properties = match.group(4)
            
            event = {
                '@timestamp': datetime.utcnow().isoformat(),
                'event_type': 'usb_registry_entry',
                'vendor_id': vid,
                'product_id': pid,
                'serial_number': serial,
                'vendor_name': get_vendor_name(vid),
                'device_class': 'USB',
                'source_file': filename,
                'artifact_type': 'usb_history'
            }
            
            # Extract friendly name
            friendly_match = re.search(r'"FriendlyName"="([^"]+)"', properties)
            if friendly_match:
                event['friendly_name'] = friendly_match.group(1)
            
            # Extract device description
            desc_match = re.search(r'"DeviceDesc"="([^"]+)"', properties)
            if desc_match:
                event['device_description'] = desc_match.group(1)
            
            yield event
        
        # Parse MountedDevices
        mounted_pattern = re.compile(
            r'\[HKEY_LOCAL_MACHINE\\SYSTEM\\MountedDevices\]([^\[]*)',
            re.IGNORECASE | re.DOTALL
        )
        
        mounted_match = mounted_pattern.search(content)
        if mounted_match:
            mounted_content = mounted_match.group(1)
            
            # Parse individual mount points
            mount_entries = re.findall(r'"([^"]+)"=hex:([^\r\n]+)', mounted_content)
            
            for mount_point, hex_data in mount_entries:
                event = {
                    '@timestamp': datetime.utcnow().isoformat(),
                    'event_type': 'mounted_device',
                    'mount_point': mount_point,
                    'source_file': filename,
                    'artifact_type': 'usb_history'
                }
                
                # Try to decode hex data for device info
                try:
                    hex_bytes = bytes([int(b, 16) for b in hex_data.replace(',', ' ').split()])
                    decoded = hex_bytes.decode('utf-16-le', errors='ignore')
                    
                    # Look for device identifiers
                    if 'USBSTOR' in decoded or 'USB#VID' in decoded:
                        event['device_path'] = decoded.strip('\x00')
                except:
                    pass
                
                if 'device_path' in event:
                    yield event
        
        logger.info(f"Parsed registry export: {filename}")
    
    except Exception as e:
        logger.error(f"Error parsing registry export {file_path}: {e}")
        import traceback
        traceback.print_exc()


def parse_usb_file(file_path):
    """Parse USB device history file (auto-detect type)"""
    filename = os.path.basename(file_path).lower()
    
    if 'setupapi.dev' in filename or 'setupapi' in filename:
        logger.info(f"Detected setupapi log: {filename}")
        return parse_setupapi_dev_log(file_path)
    elif filename.endswith('.reg'):
        logger.info(f"Detected registry export: {filename}")
        return parse_registry_export(file_path)
    else:
        # Try to detect file type
        try:
            with open(file_path, 'rb') as f:
                header = f.read(100)
            
            if b'REGEDIT' in header or b'Windows Registry' in header:
                return parse_registry_export(file_path)
            elif b'>>> ' in header or b'Device Install' in header:
                return parse_setupapi_dev_log(file_path)
        except:
            pass
        
        logger.warning(f"Unknown USB history file format: {filename}")
        return iter([])
