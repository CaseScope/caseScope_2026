"""
setupapi.dev.log Parser (Phase 3)
==================================
Parses Windows device installation log
File: setupapi.dev.log
Routes to: case_X_devices index

Extracts:
- USB device connections
- Device installations
- Timestamps of device activity
"""

import os
import re
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

# Regex patterns for setupapi.dev.log
DATE_PATTERN = re.compile(r'>>>  \[(.+?)\]')
DEVICE_PATTERN = re.compile(r'Device Install \(Hardware initiated\) - (.+)')
USB_SERIAL_PATTERN = re.compile(r'USB\\VID_([0-9A-F]{4})&PID_([0-9A-F]{4})\\(.+)')


def parse_setupapi_log(file_path):
    """
    Parse setupapi.dev.log
    
    Yields device installation/connection events
    """
    if not os.path.exists(file_path):
        logger.error(f"setupapi.dev.log not found: {file_path}")
        return
    
    filename = os.path.basename(file_path)
    
    try:
        current_timestamp = None
        current_device = None
        event_buffer = []
        
        with open(file_path, 'r', encoding='utf-16-le', errors='ignore') as f:
            for line_num, line in enumerate(f):
                line = line.strip()
                
                if not line:
                    continue
                
                # Parse timestamp
                date_match = DATE_PATTERN.match(line)
                if date_match:
                    date_str = date_match.group(1)
                    try:
                        # Example: "Device Install (Hardware initiated) - SWD\WPDBUSENUM\..."
                        current_timestamp = datetime.strptime(date_str, '%Y/%m/%d %H:%M:%S.%f')
                    except:
                        # Try alternate format
                        try:
                            current_timestamp = datetime.strptime(date_str.split('.')[0], '%Y/%m/%d %H:%M:%S')
                        except:
                            pass
                    continue
                
                # Parse device info
                device_match = DEVICE_PATTERN.search(line)
                if device_match:
                    current_device = device_match.group(1)
                    continue
                
                # Check for USB serial
                usb_match = USB_SERIAL_PATTERN.search(line)
                if usb_match and current_timestamp:
                    vid = usb_match.group(1)
                    pid = usb_match.group(2)
                    serial = usb_match.group(3)
                    
                    event = {
                        '@timestamp': current_timestamp.isoformat(),
                        'event_type': 'usb_device_connection',
                        'vendor_id': vid,
                        'product_id': pid,
                        'serial_number': serial,
                        'device_string': current_device or line,
                        'source_file': filename,
                        'artifact_type': 'device_log'
                    }
                    
                    yield event
                    current_device = None  # Reset
        
        logger.info(f"Parsed setupapi.dev.log: {filename}")
    
    except Exception as e:
        logger.error(f"Error parsing setupapi.dev.log {file_path}: {e}")
        import traceback
        traceback.print_exc()


def parse_setupapi_file(file_path):
    """Parse setupapi.dev.log file"""
    filename = os.path.basename(file_path).lower()
    
    if 'setupapi.dev.log' in filename:
        logger.info(f"Detected setupapi.dev.log: {filename}")
        return parse_setupapi_log(file_path)
    else:
        logger.warning(f"Not a setupapi.dev.log file: {filename}")
        return iter([])

