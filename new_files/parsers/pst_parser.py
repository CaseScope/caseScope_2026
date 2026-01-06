"""
PST/OST Email Parser
====================
Parses Outlook PST and OST files
Location: Various user profile locations
Routes to: case_X_events index

Extracts:
- Email metadata (from, to, cc, subject, date)
- Attachments list
- Folder structure
- Calendar items
- Contacts
- Tasks

Evidence Value:
- Communication evidence
- Phishing emails
- Data exfiltration planning
- Business correspondence
- Deleted emails (if recoverable)

Dependencies:
- readpst (apt install pst-utils)
- Or libpff-python for direct parsing
"""

import os
import subprocess
import shutil
import tempfile
import logging
import json
import email
from datetime import datetime
from email.utils import parsedate_to_datetime

logger = logging.getLogger(__name__)

# Check for readpst availability
try:
    result = subprocess.run(['which', 'readpst'], capture_output=True, text=True)
    READPST_AVAILABLE = result.returncode == 0
except:
    READPST_AVAILABLE = False

if not READPST_AVAILABLE:
    logger.warning("readpst not available - install with: apt install pst-utils")


def parse_email_file(eml_path):
    """Parse an extracted .eml file"""
    try:
        with open(eml_path, 'rb') as f:
            msg = email.message_from_binary_file(f)
        
        # Extract basic headers
        result = {
            'from': msg.get('From', ''),
            'to': msg.get('To', ''),
            'cc': msg.get('Cc', ''),
            'bcc': msg.get('Bcc', ''),
            'subject': msg.get('Subject', ''),
            'message_id': msg.get('Message-ID', ''),
            'in_reply_to': msg.get('In-Reply-To', ''),
            'references': msg.get('References', ''),
        }
        
        # Parse date
        date_str = msg.get('Date', '')
        if date_str:
            try:
                result['date'] = parsedate_to_datetime(date_str).isoformat()
            except:
                result['date_raw'] = date_str
        
        # Extract body preview
        body = ''
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                if content_type == 'text/plain':
                    try:
                        body = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                        break
                    except:
                        pass
        else:
            try:
                body = msg.get_payload(decode=True).decode('utf-8', errors='ignore')
            except:
                pass
        
        # Truncate body for storage
        if body:
            result['body_preview'] = body[:1000]
            result['body_length'] = len(body)
        
        # Extract attachments
        attachments = []
        if msg.is_multipart():
            for part in msg.walk():
                filename = part.get_filename()
                if filename:
                    attachments.append({
                        'filename': filename,
                        'content_type': part.get_content_type(),
                        'size': len(part.get_payload(decode=True) or b'')
                    })
        
        if attachments:
            result['attachments'] = attachments
            result['attachment_count'] = len(attachments)
        
        return result
    
    except Exception as e:
        logger.debug(f"Error parsing email file {eml_path}: {e}")
        return None


def parse_pst_with_readpst(file_path):
    """
    Parse PST/OST using readpst command-line tool
    
    Yields email events
    """
    if not READPST_AVAILABLE:
        logger.error("readpst not available - cannot parse PST")
        return
    
    if not os.path.exists(file_path):
        logger.error(f"PST file not found: {file_path}")
        return
    
    filename = os.path.basename(file_path)
    
    try:
        # Create temp directory for extraction
        temp_dir = tempfile.mkdtemp(prefix='pst_extract_')
        
        logger.info(f"Extracting PST with readpst: {filename}")
        
        # Run readpst
        # -e: extract emails as separate files
        # -D: include deleted items
        # -o: output directory
        # -q: quiet mode
        cmd = [
            'readpst',
            '-e',  # Extract to .eml files
            '-D',  # Include deleted items
            '-q',  # Quiet
            '-o', temp_dir,
            file_path
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        
        if result.returncode != 0:
            logger.error(f"readpst failed: {result.stderr}")
            # Try without -D flag
            cmd = ['readpst', '-e', '-q', '-o', temp_dir, file_path]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        
        # Walk extracted directory
        email_count = 0
        
        for root, dirs, files in os.walk(temp_dir):
            # Get folder path relative to temp_dir
            rel_folder = os.path.relpath(root, temp_dir)
            
            for fname in files:
                if fname.endswith('.eml'):
                    eml_path = os.path.join(root, fname)
                    
                    email_data = parse_email_file(eml_path)
                    
                    if email_data:
                        event = {
                            '@timestamp': email_data.get('date', datetime.utcnow().isoformat()),
                            'event_type': 'email',
                            'email_from': email_data.get('from', ''),
                            'email_to': email_data.get('to', ''),
                            'email_cc': email_data.get('cc', ''),
                            'email_subject': email_data.get('subject', ''),
                            'email_message_id': email_data.get('message_id', ''),
                            'folder': rel_folder,
                            'source_file': filename,
                            'artifact_type': 'email_pst'
                        }
                        
                        if email_data.get('body_preview'):
                            event['body_preview'] = email_data['body_preview']
                        
                        if email_data.get('attachments'):
                            event['attachments'] = email_data['attachments']
                            event['attachment_count'] = email_data['attachment_count']
                            
                            # Flag potentially suspicious attachments
                            suspicious_exts = ['.exe', '.dll', '.scr', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.hta']
                            for att in email_data['attachments']:
                                if any(att['filename'].lower().endswith(ext) for ext in suspicious_exts):
                                    event['suspicious_attachment'] = True
                                    break
                        
                        email_count += 1
                        yield event
        
        logger.info(f"Extracted {email_count} emails from {filename}")
        
        # Cleanup
        shutil.rmtree(temp_dir, ignore_errors=True)
    
    except subprocess.TimeoutExpired:
        logger.error(f"readpst timeout for {filename}")
        shutil.rmtree(temp_dir, ignore_errors=True)
    
    except Exception as e:
        logger.error(f"Error parsing PST {file_path}: {e}")
        import traceback
        traceback.print_exc()
        
        try:
            shutil.rmtree(temp_dir, ignore_errors=True)
        except:
            pass


def parse_pst_basic(file_path):
    """
    Basic PST parsing without readpst
    Extracts metadata and strings from PST file
    """
    if not os.path.exists(file_path):
        logger.error(f"PST file not found: {file_path}")
        return
    
    filename = os.path.basename(file_path)
    
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
        
        file_size = len(data)
        logger.info(f"Basic PST scan: {filename} ({file_size} bytes)")
        
        # Check PST signature
        if data[0:4] != b'!BDN':
            logger.warning(f"Invalid PST signature: {filename}")
            return
        
        # Extract email addresses
        import re
        email_pattern = rb'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        emails = list(set(re.findall(email_pattern, data)))
        
        # Extract subjects (look for common patterns)
        subjects = []
        subject_pattern = rb'Subject:\s*([^\r\n]+)'
        for match in re.finditer(subject_pattern, data):
            try:
                subject = match.group(1).decode('utf-8', errors='ignore').strip()
                if subject and len(subject) < 200:
                    subjects.append(subject)
            except:
                pass
        
        # Log basic stats
        event = {
            '@timestamp': datetime.utcnow().isoformat(),
            'event_type': 'pst_scan',
            'file_size': file_size,
            'email_addresses_found': len(emails),
            'subjects_found': len(subjects),
            'source_file': filename,
            'artifact_type': 'email_pst',
            'parser_note': 'basic_scan_readpst_unavailable'
        }
        
        # Include sample of found data
        if emails:
            event['sample_emails'] = [e.decode('utf-8', errors='ignore') for e in emails[:20]]
        
        if subjects:
            event['sample_subjects'] = list(set(subjects))[:20]
        
        yield event
    
    except Exception as e:
        logger.error(f"Error in basic PST scan {file_path}: {e}")


def parse_pst_file(file_path):
    """Parse PST/OST file (auto-select method)"""
    filename = os.path.basename(file_path).lower()
    
    if not (filename.endswith('.pst') or filename.endswith('.ost')):
        logger.warning(f"Not a PST/OST file: {filename}")
        return iter([])
    
    if READPST_AVAILABLE:
        logger.info(f"Parsing PST with readpst: {filename}")
        return parse_pst_with_readpst(file_path)
    else:
        logger.warning(f"readpst unavailable, using basic scan: {filename}")
        return parse_pst_basic(file_path)
