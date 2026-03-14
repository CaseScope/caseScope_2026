"""Memory Forensics Parser for CaseScope

Parses Volatility 3 JSON output files and inserts into memory_* tables.
Supports all standard Vol3 Windows plugins.
"""
import os
import json
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
from dateutil.parser import parse as dateutil_parse

from models.database import db
from models.memory_data import (
    MemoryProcess, MemoryNetwork, MemoryService, MemoryMalfind,
    MemoryModule, MemoryCredential, MemorySID, MemoryInfo
)

logger = logging.getLogger(__name__)


def extract_system_time_from_info_rows(data: List[Dict[str, Any]]) -> Optional[datetime]:
    """Extract SystemTime from Volatility windows.info rows."""
    for item in data:
        if not isinstance(item, dict):
            continue

        variable_name = item.get('Variable')
        if variable_name == 'SystemTime':
            try:
                return dateutil_parse(str(item.get('Value')))
            except Exception:
                continue

        system_time = item.get('SystemTime') or item.get('system_time')
        if system_time:
            try:
                return dateutil_parse(str(system_time))
            except Exception:
                continue

    return None


class MemoryParser:
    """Parser for Volatility 3 JSON output files"""
    
    VERSION = '1.0.1'
    
    # Maximum valid PID value (PostgreSQL INTEGER max is 2,147,483,647)
    # Windows PIDs are typically < 65536, but can go higher. We use a safe limit.
    MAX_VALID_PID = 2147483647
    
    # Plugin to parser method mapping
    # Note: psscan skipped as pslist provides same data (psscan finds hidden processes but creates duplicates)
    PLUGIN_HANDLERS = {
        'windows_pslist': 'parse_pslist',
        # 'windows_psscan': 'parse_pslist',  # Skipped - would create duplicates with pslist
        'windows_pstree': 'parse_pstree',
        'windows_cmdline': 'parse_cmdline',
        'windows_netscan': 'parse_network',
        'windows_netstat': 'parse_network',
        'windows_svcscan': 'parse_services',
        'windows_malfind': 'parse_malfind',
        'windows_ldrmodules': 'parse_ldrmodules',
        'windows_getsids': 'parse_getsids',
        'windows_hashdump': 'parse_hashdump',
        'windows_cachedump': 'parse_cachedump',
        'windows_lsadump': 'parse_lsadump',
        'windows_info': 'parse_info',
    }
    UNSUPPORTED_PLUGIN_REASONS = {
        'windows_psscan': 'Retained as raw output only to avoid duplicating windows.pslist process rows',
        'windows_dlllist': 'Retained as raw output only because its schema does not map cleanly to memory_modules',
    }
    
    def __init__(self, job_id: int, case_id: int, hostname: str):
        """Initialize parser with job context
        
        Args:
            job_id: memory_jobs.id
            case_id: cases.id
            hostname: System hostname
        """
        self.job_id = job_id
        self.case_id = case_id
        self.hostname = hostname
        self.stats = {
            'processes': 0,
            'network': 0,
            'services': 0,
            'malfind': 0,
            'modules': 0,
            'credentials': 0,
            'sids': 0,
        }
        self.errors: List[str] = []
    
    def parse_output_folder(self, vol3_output_path: str) -> Dict[str, Any]:
        """Parse all JSON files in a Vol3 output folder
        
        Args:
            vol3_output_path: Path to vol3_output directory
            
        Returns:
            Dict with parsing results and statistics
        """
        if not os.path.exists(vol3_output_path):
            return {'success': False, 'error': f'Path not found: {vol3_output_path}'}
        
        parsed_files = []
        failed_files = []
        unsupported_files = []
        plugin_statuses = {}
        netscan_output_path = os.path.join(vol3_output_path, 'windows_netscan.json')
        netscan_row_count = self._count_json_rows(netscan_output_path) if os.path.exists(netscan_output_path) else 0
        
        for filename in sorted(os.listdir(vol3_output_path)):
            if not filename.endswith('.json'):
                continue
            
            filepath = os.path.join(vol3_output_path, filename)
            plugin_name = filename.replace('.json', '')
            output_rows = self._count_json_rows(filepath)

            if plugin_name == 'windows_netstat' and netscan_row_count > 0:
                reason = 'Skipped because windows.netscan already produced network results'
                unsupported_files.append({
                    'file': filename,
                    'plugin': plugin_name,
                    'count': output_rows,
                    'reason': reason,
                    'state': 'completed_unsupported',
                })
                plugin_statuses[plugin_name] = {
                    'state': 'completed_unsupported',
                    'count': output_rows,
                    'file': filename,
                    'reason': reason,
                }
                logger.info("Skipping netstat ingest because netscan already produced results")
                continue
            
            if plugin_name in self.PLUGIN_HANDLERS:
                try:
                    handler = getattr(self, self.PLUGIN_HANDLERS[plugin_name])
                    count = handler(filepath)
                    state = 'completed_ingested' if count > 0 else 'completed_zero_rows'
                    parsed_files.append({
                        'file': filename,
                        'plugin': plugin_name,
                        'count': count,
                        'state': state,
                    })
                    plugin_statuses[plugin_name] = {
                        'state': state,
                        'count': count,
                        'file': filename,
                    }
                    logger.info(f"Parsed {plugin_name}: {count} records")
                except Exception as e:
                    logger.error(f"Error parsing {filename}: {e}")
                    failed_files.append({
                        'file': filename,
                        'plugin': plugin_name,
                        'error': str(e),
                        'count': output_rows,
                    })
                    plugin_statuses[plugin_name] = {
                        'state': 'failed',
                        'count': output_rows,
                        'file': filename,
                        'error': str(e),
                    }
                    self.errors.append(f"{filename}: {str(e)}")
            else:
                reason = self.UNSUPPORTED_PLUGIN_REASONS.get(
                    plugin_name,
                    'No ingestion handler configured for this plugin',
                )
                unsupported_files.append({
                    'file': filename,
                    'plugin': plugin_name,
                    'count': output_rows,
                    'reason': reason,
                    'state': 'completed_unsupported',
                })
                plugin_statuses[plugin_name] = {
                    'state': 'completed_unsupported',
                    'count': output_rows,
                    'file': filename,
                    'reason': reason,
                }
                logger.info(f"Skipping unsupported plugin output: {plugin_name}")
        
        # Commit all changes
        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            return {'success': False, 'error': f'Database commit failed: {e}'}
        
        return {
            'success': True,
            'parsed_files': parsed_files,
            'failed_files': failed_files,
            'unsupported_files': unsupported_files,
            'plugin_statuses': plugin_statuses,
            'stats': self.stats,
            'errors': self.errors
        }
    
    def _load_json(self, filepath: str) -> List[Dict]:
        """Load and parse JSON file"""
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)
        return data if isinstance(data, list) else [data]

    def _count_json_rows(self, filepath: str) -> int:
        """Count JSON rows without interpreting plugin schema."""
        data = self._load_json(filepath)
        return len(data)
    
    def _parse_timestamp(self, value: Any) -> Optional[datetime]:
        """Parse timestamp from Vol3 format"""
        if not value:
            return None
        try:
            return dateutil_parse(str(value))
        except Exception:
            return None
    
    def _parse_bool(self, value: Any) -> bool:
        """Parse boolean from Vol3 format"""
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            return value.lower() in ('true', '1', 'yes')
        return bool(value)
    
    def _is_valid_pid(self, pid: Any) -> bool:
        """Validate PID is within acceptable range for database storage.
        
        Returns False for garbage/corrupt PIDs that exceed PostgreSQL INTEGER max.
        """
        if pid is None:
            return False
        try:
            pid_int = int(pid)
            return 0 <= pid_int <= self.MAX_VALID_PID
        except (ValueError, TypeError):
            return False
    
    def _is_valid_process_name(self, name: Any) -> bool:
        """Validate process name is not garbage data.
        
        Returns False for names with control characters or excessive non-ASCII.
        """
        if not name or not isinstance(name, str):
            return False
        # Skip entries with null bytes or mostly non-printable characters
        printable_count = sum(1 for c in name if c.isprintable())
        return printable_count >= len(name) * 0.5  # At least 50% printable
    
    def parse_pslist(self, filepath: str) -> int:
        """Parse windows.pslist or windows.psscan output"""
        data = self._load_json(filepath)
        count = 0
        skipped = 0
        
        for item in data:
            try:
                pid = item.get('PID', 0)
                name = item.get('ImageFileName', '')
                
                # Validate PID and process name to filter out corrupt/garbage entries
                if not self._is_valid_pid(pid):
                    logger.debug(f"Skipping process with invalid PID: {pid}")
                    skipped += 1
                    continue
                if not self._is_valid_process_name(name):
                    logger.debug(f"Skipping process with invalid name: {repr(name)}")
                    skipped += 1
                    continue
                
                proc = MemoryProcess(
                    job_id=self.job_id,
                    case_id=self.case_id,
                    hostname=self.hostname,
                    pid=pid,
                    ppid=item.get('PPID') if self._is_valid_pid(item.get('PPID')) else None,
                    name=name,
                    name_lower=name.lower(),
                    offset_v=item.get('Offset(V)'),
                    session_id=item.get('SessionId'),
                    threads=item.get('Threads'),
                    handles=item.get('Handles'),
                    wow64=self._parse_bool(item.get('Wow64', False)),
                    create_time=self._parse_timestamp(item.get('CreateTime')),
                    exit_time=self._parse_timestamp(item.get('ExitTime')),
                )
                db.session.add(proc)
                count += 1
            except Exception as e:
                logger.warning(f"Error parsing process: {e}")
        
        if skipped > 0:
            logger.info(f"Skipped {skipped} corrupt/garbage process entries")
        self.stats['processes'] += count
        return count
    
    def parse_pstree(self, filepath: str) -> int:
        """Parse windows.pstree output (recursive with __children)"""
        data = self._load_json(filepath)
        count = 0
        skipped = 0
        
        def process_tree(items: List[Dict], depth: int = 0):
            nonlocal count, skipped
            for item in items:
                try:
                    pid = item.get('PID', 0)
                    name = item.get('ImageFileName', '')
                    
                    # Validate PID and process name to filter out corrupt/garbage entries
                    if not self._is_valid_pid(pid):
                        logger.debug(f"Skipping pstree entry with invalid PID: {pid}")
                        skipped += 1
                        # Still process children - they might be valid
                        children = item.get('__children', [])
                        if children:
                            process_tree(children, depth + 1)
                        continue
                    if not self._is_valid_process_name(name):
                        logger.debug(f"Skipping pstree entry with invalid name: {repr(name)}")
                        skipped += 1
                        children = item.get('__children', [])
                        if children:
                            process_tree(children, depth + 1)
                        continue
                    
                    # Check if process already exists (from pslist)
                    existing = MemoryProcess.query.filter_by(
                        job_id=self.job_id,
                        pid=pid
                    ).first()
                    
                    if existing:
                        # Update with pstree-specific fields
                        existing.path = item.get('Path') or existing.path
                        existing.cmdline = item.get('Cmd') or existing.cmdline
                        existing.audit_path = item.get('Audit')
                    else:
                        proc = MemoryProcess(
                            job_id=self.job_id,
                            case_id=self.case_id,
                            hostname=self.hostname,
                            pid=pid,
                            ppid=item.get('PPID') if self._is_valid_pid(item.get('PPID')) else None,
                            name=name,
                            name_lower=name.lower(),
                            path=item.get('Path'),
                            cmdline=item.get('Cmd'),
                            audit_path=item.get('Audit'),
                            offset_v=item.get('Offset(V)'),
                            session_id=item.get('SessionId'),
                            threads=item.get('Threads'),
                            handles=item.get('Handles'),
                            wow64=self._parse_bool(item.get('Wow64', False)),
                            create_time=self._parse_timestamp(item.get('CreateTime')),
                            exit_time=self._parse_timestamp(item.get('ExitTime')),
                        )
                        db.session.add(proc)
                        count += 1
                    
                    # Process children recursively
                    children = item.get('__children', [])
                    if children:
                        process_tree(children, depth + 1)
                        
                except Exception as e:
                    logger.warning(f"Error parsing pstree item: {e}")
        
        process_tree(data)
        if skipped > 0:
            logger.info(f"Skipped {skipped} corrupt/garbage pstree entries")
        self.stats['processes'] += count
        return count
    
    def parse_cmdline(self, filepath: str) -> int:
        """Parse windows.cmdline output - updates existing processes"""
        data = self._load_json(filepath)
        count = 0
        
        for item in data:
            try:
                pid = item.get('PID', 0)
                cmdline = item.get('Args', '')
                
                # Update existing process
                proc = MemoryProcess.query.filter_by(
                    job_id=self.job_id,
                    pid=pid
                ).first()
                
                if proc and cmdline:
                    proc.cmdline = cmdline
                    count += 1
            except Exception as e:
                logger.warning(f"Error updating cmdline: {e}")
        
        return count
    
    def parse_network(self, filepath: str) -> int:
        """Parse windows.netscan or windows.netstat output"""
        data = self._load_json(filepath)
        count = 0
        
        for item in data:
            try:
                pid = item.get('PID')
                # Validate PID if present
                if pid is not None and not self._is_valid_pid(pid):
                    pid = None
                
                net = MemoryNetwork(
                    job_id=self.job_id,
                    case_id=self.case_id,
                    hostname=self.hostname,
                    protocol=item.get('Proto'),
                    local_addr=item.get('LocalAddr'),
                    local_port=item.get('LocalPort'),
                    foreign_addr=item.get('ForeignAddr'),
                    foreign_port=item.get('ForeignPort'),
                    state=item.get('State'),
                    pid=pid,
                    owner=item.get('Owner'),
                    offset=item.get('Offset'),
                    created_time=self._parse_timestamp(item.get('Created')),
                )
                db.session.add(net)
                count += 1
            except Exception as e:
                logger.warning(f"Error parsing network: {e}")
        
        self.stats['network'] += count
        return count
    
    def parse_services(self, filepath: str) -> int:
        """Parse windows.svcscan output"""
        data = self._load_json(filepath)
        count = 0
        
        for item in data:
            try:
                pid = item.get('PID')
                # Validate PID if present
                if pid is not None and not self._is_valid_pid(pid):
                    pid = None
                
                svc = MemoryService(
                    job_id=self.job_id,
                    case_id=self.case_id,
                    hostname=self.hostname,
                    name=item.get('Name', ''),
                    name_lower=item.get('Name', '').lower(),
                    display_name=item.get('Display'),
                    binary_path=item.get('Binary'),
                    binary_path_registry=item.get('Binary (Registry)'),
                    dll=item.get('Dll'),
                    state=item.get('State'),
                    start_type=item.get('Start'),
                    service_type=item.get('Type'),
                    pid=pid,
                    offset=item.get('Offset'),
                    order=item.get('Order'),
                )
                db.session.add(svc)
                count += 1
            except Exception as e:
                logger.warning(f"Error parsing service: {e}")
        
        self.stats['services'] += count
        return count
    
    def parse_malfind(self, filepath: str) -> int:
        """Parse windows.malfind output"""
        data = self._load_json(filepath)
        count = 0
        skipped = 0
        
        for item in data:
            try:
                pid = item.get('PID', 0)
                # Skip entries with invalid PIDs
                if not self._is_valid_pid(pid):
                    skipped += 1
                    continue
                
                malf = MemoryMalfind(
                    job_id=self.job_id,
                    case_id=self.case_id,
                    hostname=self.hostname,
                    pid=pid,
                    process_name=item.get('Process'),
                    protection=item.get('Protection'),
                    start_vpn=item.get('Start VPN'),
                    end_vpn=item.get('End VPN'),
                    tag=item.get('Tag'),
                    commit_charge=item.get('CommitCharge'),
                    private_memory=self._parse_bool(item.get('PrivateMemory', False)),
                    hexdump=item.get('Hexdump'),
                    disasm=item.get('Disasm'),
                    notes=item.get('Notes'),
                )
                db.session.add(malf)
                count += 1
            except Exception as e:
                logger.warning(f"Error parsing malfind: {e}")
        
        if skipped > 0:
            logger.info(f"Skipped {skipped} malfind entries with invalid PIDs")
        self.stats['malfind'] += count
        return count
    
    def parse_ldrmodules(self, filepath: str) -> int:
        """Parse windows.ldrmodules output"""
        data = self._load_json(filepath)
        count = 0
        skipped = 0
        
        for item in data:
            try:
                pid = item.get('Pid', 0)
                # Skip entries with invalid PIDs
                if not self._is_valid_pid(pid):
                    skipped += 1
                    continue
                
                mod = MemoryModule(
                    job_id=self.job_id,
                    case_id=self.case_id,
                    hostname=self.hostname,
                    pid=pid,
                    process_name=item.get('Process'),
                    base_address=item.get('Base'),
                    mapped_path=item.get('MappedPath'),
                    in_init=self._parse_bool(item.get('InInit', False)),
                    in_load=self._parse_bool(item.get('InLoad', False)),
                    in_mem=self._parse_bool(item.get('InMem', False)),
                )
                db.session.add(mod)
                count += 1
            except Exception as e:
                logger.warning(f"Error parsing ldrmodules: {e}")
        
        if skipped > 0:
            logger.info(f"Skipped {skipped} ldrmodules entries with invalid PIDs")
        self.stats['modules'] += count
        return count
    
    def parse_getsids(self, filepath: str) -> int:
        """Parse windows.getsids output"""
        data = self._load_json(filepath)
        count = 0
        skipped = 0
        
        for item in data:
            try:
                pid = item.get('PID', 0)
                # Skip entries with invalid PIDs
                if not self._is_valid_pid(pid):
                    skipped += 1
                    continue
                
                sid = MemorySID(
                    job_id=self.job_id,
                    case_id=self.case_id,
                    hostname=self.hostname,
                    pid=pid,
                    process_name=item.get('Process'),
                    sid=item.get('SID'),
                    sid_name=item.get('Name'),
                )
                db.session.add(sid)
                count += 1
            except Exception as e:
                logger.warning(f"Error parsing getsids: {e}")
        
        if skipped > 0:
            logger.info(f"Skipped {skipped} getsids entries with invalid PIDs")
        self.stats['sids'] += count
        return count
    
    def parse_hashdump(self, filepath: str) -> int:
        """Parse windows.hashdump output"""
        data = self._load_json(filepath)
        count = 0
        
        for item in data:
            try:
                cred = MemoryCredential(
                    job_id=self.job_id,
                    case_id=self.case_id,
                    hostname=self.hostname,
                    source_plugin='hashdump',
                    username=item.get('User'),
                    rid=item.get('rid'),
                    lm_hash=item.get('lmhash'),
                    nt_hash=item.get('nthash'),
                )
                db.session.add(cred)
                count += 1
            except Exception as e:
                logger.warning(f"Error parsing hashdump: {e}")
        
        self.stats['credentials'] += count
        return count
    
    def parse_cachedump(self, filepath: str) -> int:
        """Parse windows.cachedump output"""
        data = self._load_json(filepath)
        count = 0
        
        for item in data:
            try:
                # Normalize hash format (spaces to no spaces)
                hash_val = item.get('Hash', '')
                if hash_val:
                    hash_val = hash_val.replace(' ', '')
                
                cred = MemoryCredential(
                    job_id=self.job_id,
                    case_id=self.case_id,
                    hostname=self.hostname,
                    source_plugin='cachedump',
                    username=item.get('Username'),
                    domain=item.get('Domain name') or item.get('Domain'),
                    cached_hash=hash_val,
                )
                db.session.add(cred)
                count += 1
            except Exception as e:
                logger.warning(f"Error parsing cachedump: {e}")
        
        self.stats['credentials'] += count
        return count
    
    def parse_lsadump(self, filepath: str) -> int:
        """Parse windows.lsadump output"""
        data = self._load_json(filepath)
        count = 0
        
        for item in data:
            try:
                cred = MemoryCredential(
                    job_id=self.job_id,
                    case_id=self.case_id,
                    hostname=self.hostname,
                    source_plugin='lsadump',
                    lsa_key=item.get('Key'),
                    lsa_secret_hex=item.get('Hex'),
                )
                db.session.add(cred)
                count += 1
            except Exception as e:
                logger.warning(f"Error parsing lsadump: {e}")
        
        self.stats['credentials'] += count
        return count
    
    def parse_info(self, filepath: str) -> int:
        """Parse windows.info output"""
        data = self._load_json(filepath)
        
        # Convert list of variable/value pairs to dict
        info_dict = {}
        for item in data:
            var = item.get('Variable', '')
            val = item.get('Value')
            info_dict[var] = val
        
        try:
            system_time = extract_system_time_from_info_rows(data)
            
            info = MemoryInfo(
                job_id=self.job_id,
                case_id=self.case_id,
                hostname=self.hostname,
                kernel_base=info_dict.get('Kernel Base'),
                dtb=info_dict.get('DTB'),
                symbols=info_dict.get('Symbols'),
                is_64bit=info_dict.get('Is64Bit') == 'True',
                is_pae=info_dict.get('IsPAE') == 'True',
                major_minor=info_dict.get('Major/Minor'),
                nt_major=int(info_dict.get('NtMajorVersion', 0) or 0),
                nt_minor=int(info_dict.get('NtMinorVersion', 0) or 0),
                machine_type=int(info_dict.get('MachineType', 0) or 0),
                num_processors=int(info_dict.get('KeNumberProcessors', 0) or 0),
                nt_product_type=info_dict.get('NtProductType'),
                nt_system_root=info_dict.get('NtSystemRoot'),
                system_time=system_time,
            )
            db.session.add(info)
            return 1
        except Exception as e:
            logger.warning(f"Error parsing info: {e}")
            return 0


def ingest_memory_job(job_id: int) -> Dict[str, Any]:
    """Ingest all Vol3 output for a memory job
    
    Args:
        job_id: memory_jobs.id
        
    Returns:
        Dict with ingestion results
    """
    from models.memory_job import MemoryJob
    
    job = MemoryJob.query.get(job_id)
    if not job:
        return {'success': False, 'error': f'Job {job_id} not found'}
    
    if not job.output_folder:
        return {'success': False, 'error': 'Job has no output folder'}
    
    vol3_output = os.path.join(job.output_folder, 'vol3_output')
    if not os.path.exists(vol3_output):
        return {'success': False, 'error': f'Vol3 output folder not found: {vol3_output}'}
    
    # Clear existing data for this job (re-ingestion)
    clear_job_data(job_id)
    
    # Parse all output files
    parser = MemoryParser(job_id, job.case_id, job.hostname)
    result = parser.parse_output_folder(vol3_output)
    
    if result['success']:
        info = MemoryInfo.query.filter_by(job_id=job_id).first()
        if info and info.system_time:
            job.memory_timestamp = info.system_time
            db.session.commit()

        # Update cross-memory counts
        update_cross_memory_counts(job.case_id)
    
    return result


def clear_job_data(job_id: int):
    """Clear all parsed data for a job (for re-ingestion)"""
    MemoryProcess.query.filter_by(job_id=job_id).delete()
    MemoryNetwork.query.filter_by(job_id=job_id).delete()
    MemoryService.query.filter_by(job_id=job_id).delete()
    MemoryMalfind.query.filter_by(job_id=job_id).delete()
    MemoryModule.query.filter_by(job_id=job_id).delete()
    MemoryCredential.query.filter_by(job_id=job_id).delete()
    MemorySID.query.filter_by(job_id=job_id).delete()
    MemoryInfo.query.filter_by(job_id=job_id).delete()
    db.session.commit()


def update_cross_memory_counts(case_id: int):
    """Update cross-memory reference counts for all processes in a case
    
    For each unique process name, count how many different memory jobs
    it appears in and update the cross_memory_count field.
    """
    # Get process name counts across jobs
    from sqlalchemy import func
    
    # Subquery: count distinct jobs per process name
    counts = db.session.query(
        MemoryProcess.name_lower,
        func.count(func.distinct(MemoryProcess.job_id)).label('job_count')
    ).filter(
        MemoryProcess.case_id == case_id
    ).group_by(
        MemoryProcess.name_lower
    ).all()
    
    # Update each process with its count
    for name_lower, job_count in counts:
        if job_count > 1:  # Only update if found in multiple dumps
            MemoryProcess.query.filter_by(
                case_id=case_id,
                name_lower=name_lower
            ).update({'cross_memory_count': job_count})
    
    # Similar for network (by foreign_addr)
    net_counts = db.session.query(
        MemoryNetwork.foreign_addr,
        func.count(func.distinct(MemoryNetwork.job_id)).label('job_count')
    ).filter(
        MemoryNetwork.case_id == case_id,
        MemoryNetwork.foreign_addr.isnot(None),
        MemoryNetwork.foreign_addr != '0.0.0.0',
        MemoryNetwork.foreign_addr != '::',
    ).group_by(
        MemoryNetwork.foreign_addr
    ).all()
    
    for addr, job_count in net_counts:
        if job_count > 1:
            MemoryNetwork.query.filter_by(
                case_id=case_id,
                foreign_addr=addr
            ).update({'cross_memory_count': job_count})
    
    # Similar for services
    svc_counts = db.session.query(
        MemoryService.name_lower,
        func.count(func.distinct(MemoryService.job_id)).label('job_count')
    ).filter(
        MemoryService.case_id == case_id
    ).group_by(
        MemoryService.name_lower
    ).all()
    
    for name_lower, job_count in svc_counts:
        if job_count > 1:
            MemoryService.query.filter_by(
                case_id=case_id,
                name_lower=name_lower
            ).update({'cross_memory_count': job_count})
    
    db.session.commit()
    logger.info(f"Updated cross-memory counts for case {case_id}")
