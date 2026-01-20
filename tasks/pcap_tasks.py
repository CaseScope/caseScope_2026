"""PCAP Processing Tasks - Zeek analysis for network captures"""
import os
import subprocess
import shutil
import logging
from datetime import datetime
from celery import shared_task

from models.database import db
from models.pcap_file import PcapFile, PcapFileStatus
from config import Config

logger = logging.getLogger(__name__)

# Zeek binary path
ZEEK_BIN = '/opt/zeek/bin/zeek'
ZEEK_CUT_BIN = '/opt/zeek/bin/zeek-cut'


def get_zeek_output_dir(case_uuid: str, pcap_id: int) -> str:
    """Get the Zeek output directory for a PCAP file
    
    Output path: /opt/casescope/storage/{case_uuid}/pcap/zeek_{pcap_id}/
    """
    base_path = os.path.join(Config.STORAGE_FOLDER, case_uuid, 'pcap', f'zeek_{pcap_id}')
    os.makedirs(base_path, exist_ok=True)
    
    try:
        shutil.chown(base_path, user='casescope', group='casescope')
    except (PermissionError, LookupError):
        pass
    
    return base_path


@shared_task(bind=True, name='tasks.process_pcap_with_zeek')
def process_pcap_with_zeek(self, pcap_id: int):
    """Process a PCAP file with Zeek to generate network logs
    
    Zeek generates various log files:
    - conn.log: Connection records
    - dns.log: DNS queries/responses
    - http.log: HTTP requests
    - ssl.log: SSL/TLS handshakes
    - files.log: File transfers
    - and more...
    
    Args:
        pcap_id: ID of the PcapFile record
        
    Returns:
        dict with processing results
    """
    from app import create_app
    app = create_app()
    
    with app.app_context():
        pcap_file = db.session.get(PcapFile, pcap_id)
        if not pcap_file:
            logger.error(f"PCAP file {pcap_id} not found")
            return {'success': False, 'error': 'PCAP file not found'}
        
        if not pcap_file.file_path or not os.path.exists(pcap_file.file_path):
            pcap_file.status = PcapFileStatus.ERROR
            pcap_file.error_message = 'PCAP file not found on disk'
            db.session.commit()
            return {'success': False, 'error': 'PCAP file not found on disk'}
        
        # Update status to processing
        pcap_file.status = PcapFileStatus.PROCESSING
        db.session.commit()
        
        try:
            # Create output directory
            output_dir = get_zeek_output_dir(pcap_file.case_uuid, pcap_id)
            
            # Clear any existing output
            for item in os.listdir(output_dir):
                item_path = os.path.join(output_dir, item)
                if os.path.isfile(item_path):
                    os.remove(item_path)
            
            # Run Zeek on the PCAP file
            # Using -r to read from file, -C to ignore checksums
            cmd = [
                ZEEK_BIN,
                '-r', pcap_file.file_path,
                '-C',  # Ignore checksum errors (common in captures)
                'local'  # Load local policy scripts
            ]
            
            logger.info(f"Running Zeek on {pcap_file.filename}: {' '.join(cmd)}")
            
            result = subprocess.run(
                cmd,
                cwd=output_dir,
                capture_output=True,
                text=True,
                timeout=3600  # 1 hour timeout for large files
            )
            
            if result.returncode != 0:
                error_msg = result.stderr[:500] if result.stderr else 'Unknown Zeek error'
                logger.error(f"Zeek failed for {pcap_file.filename}: {error_msg}")
                pcap_file.status = PcapFileStatus.ERROR
                pcap_file.error_message = f"Zeek error: {error_msg}"
                db.session.commit()
                return {'success': False, 'error': error_msg}
            
            # Count generated log files
            log_files = []
            for item in os.listdir(output_dir):
                if item.endswith('.log'):
                    log_path = os.path.join(output_dir, item)
                    log_size = os.path.getsize(log_path)
                    log_files.append({
                        'name': item,
                        'path': log_path,
                        'size': log_size
                    })
            
            # Update PCAP record with results
            pcap_file.status = PcapFileStatus.DONE
            pcap_file.zeek_output_path = output_dir
            pcap_file.logs_generated = len(log_files)
            pcap_file.processed_at = datetime.utcnow()
            pcap_file.error_message = None
            db.session.commit()
            
            logger.info(f"Zeek completed for {pcap_file.filename}: {len(log_files)} logs generated")
            
            return {
                'success': True,
                'pcap_id': pcap_id,
                'filename': pcap_file.filename,
                'output_dir': output_dir,
                'logs_generated': len(log_files),
                'log_files': log_files
            }
            
        except subprocess.TimeoutExpired:
            pcap_file.status = PcapFileStatus.ERROR
            pcap_file.error_message = 'Zeek processing timed out (>1 hour)'
            db.session.commit()
            return {'success': False, 'error': 'Processing timeout'}
            
        except Exception as e:
            logger.exception(f"Error processing PCAP {pcap_id}")
            pcap_file.status = PcapFileStatus.ERROR
            pcap_file.error_message = str(e)[:500]
            db.session.commit()
            return {'success': False, 'error': str(e)}


@shared_task(bind=True, name='tasks.process_case_pcaps')
def process_case_pcaps(self, case_uuid: str):
    """Process all pending PCAP files for a case
    
    Args:
        case_uuid: Case UUID
        
    Returns:
        dict with queued task info
    """
    from app import create_app
    app = create_app()
    
    with app.app_context():
        # Get all pending PCAP files
        pending = PcapFile.query.filter(
            PcapFile.case_uuid == case_uuid,
            PcapFile.is_archive == False,
            PcapFile.status == PcapFileStatus.NEW
        ).all()
        
        queued = []
        for pcap in pending:
            pcap.status = PcapFileStatus.QUEUED
            db.session.commit()
            
            # Queue individual processing task
            task = process_pcap_with_zeek.delay(pcap.id)
            queued.append({
                'pcap_id': pcap.id,
                'filename': pcap.filename,
                'task_id': task.id
            })
        
        return {
            'success': True,
            'case_uuid': case_uuid,
            'queued_count': len(queued),
            'queued': queued
        }


def get_zeek_log_content(pcap_id: int, log_name: str, limit: int = 1000) -> dict:
    """Get content of a Zeek log file
    
    Args:
        pcap_id: PCAP file ID
        log_name: Log file name (e.g., 'conn.log', 'dns.log')
        limit: Maximum number of lines to return
        
    Returns:
        dict with log content and metadata
    """
    pcap_file = db.session.get(PcapFile, pcap_id)
    if not pcap_file or not pcap_file.zeek_output_path:
        return {'success': False, 'error': 'PCAP or Zeek output not found'}
    
    log_path = os.path.join(pcap_file.zeek_output_path, log_name)
    if not os.path.exists(log_path):
        return {'success': False, 'error': f'Log file {log_name} not found'}
    
    try:
        lines = []
        headers = []
        
        with open(log_path, 'r') as f:
            for i, line in enumerate(f):
                if i >= limit + 10:  # Account for header lines
                    break
                
                line = line.strip()
                if line.startswith('#'):
                    # Parse header lines
                    if line.startswith('#fields'):
                        headers = line.replace('#fields\t', '').split('\t')
                    continue
                
                if len(lines) < limit:
                    lines.append(line.split('\t'))
        
        return {
            'success': True,
            'log_name': log_name,
            'headers': headers,
            'lines': lines,
            'total_lines': len(lines),
            'truncated': len(lines) >= limit
        }
        
    except Exception as e:
        return {'success': False, 'error': str(e)}


def get_zeek_log_with_cut(pcap_id: int, log_name: str, columns: list = None, limit: int = 1000) -> dict:
    """Get Zeek log content using zeek-cut for specific columns
    
    Args:
        pcap_id: PCAP file ID
        log_name: Log file name
        columns: List of column names to extract (None = all)
        limit: Maximum lines
        
    Returns:
        dict with log content
    """
    pcap_file = db.session.get(PcapFile, pcap_id)
    if not pcap_file or not pcap_file.zeek_output_path:
        return {'success': False, 'error': 'PCAP or Zeek output not found'}
    
    log_path = os.path.join(pcap_file.zeek_output_path, log_name)
    if not os.path.exists(log_path):
        return {'success': False, 'error': f'Log file {log_name} not found'}
    
    try:
        cmd = ['cat', log_path, '|', ZEEK_CUT_BIN]
        if columns:
            cmd.extend(columns)
        
        # Use shell to handle pipe
        shell_cmd = f"cat '{log_path}' | {ZEEK_CUT_BIN}"
        if columns:
            shell_cmd += ' ' + ' '.join(columns)
        shell_cmd += f" | head -n {limit}"
        
        result = subprocess.run(
            shell_cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=30
        )
        
        lines = []
        for line in result.stdout.strip().split('\n'):
            if line:
                lines.append(line.split('\t'))
        
        return {
            'success': True,
            'log_name': log_name,
            'columns': columns or ['all'],
            'lines': lines,
            'total_lines': len(lines)
        }
        
    except Exception as e:
        return {'success': False, 'error': str(e)}
