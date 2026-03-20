"""Memory Forensics Celery Tasks for CaseScope

Thread-safe with cached Flask app instance for connection pool efficiency.
"""
import os
import json
import shutil
import subprocess
import re
import zipfile
import threading
from datetime import datetime
from celery import shared_task
import redis

from config import Config
from utils.artifact_paths import copy_to_directory, ensure_case_artifact_paths

# Cached Flask app instance to avoid creating new connection pools for each task
_flask_app = None
_flask_app_lock = threading.Lock()

def get_flask_app():
    """Get or create a shared Flask app instance for Celery tasks (thread-safe)"""
    global _flask_app
    if _flask_app is None:
        with _flask_app_lock:
            if _flask_app is None:
                from app import create_app
                _flask_app = create_app()
    return _flask_app


# Cached Redis client with thread-safe initialization
_redis_client = None
_redis_lock = threading.Lock()

def get_redis_client():
    """Get Redis client for progress tracking (thread-safe)"""
    global _redis_client
    if _redis_client is None:
        with _redis_lock:
            if _redis_client is None:
                _redis_client = redis.Redis(
                    host=Config.REDIS_HOST, 
                    port=Config.REDIS_PORT, 
                    db=Config.REDIS_DB
                )
    return _redis_client


def update_job_progress(job_id: int, progress: int, current_plugin: str = None, status: str = None):
    """Update job progress in Redis for real-time tracking"""
    r = get_redis_client()
    key = f"memory_job:{job_id}"
    data = {
        'progress': progress,
        'updated_at': datetime.utcnow().isoformat()
    }
    if current_plugin:
        data['current_plugin'] = current_plugin
    if status:
        data['status'] = status
    r.hset(key, mapping=data)
    r.expire(key, 3600)  # 1 hour TTL


def get_job_progress(job_id: int) -> dict:
    """Get job progress from Redis"""
    r = get_redis_client()
    key = f"memory_job:{job_id}"
    data = r.hgetall(key)
    if data:
        return {k.decode(): v.decode() for k, v in data.items()}
    return {}


def get_output_row_count(output_file: str) -> int:
    """Count rows in a Volatility JSON output file."""
    if not output_file or not os.path.exists(output_file):
        return 0

    try:
        with open(output_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        if isinstance(data, list):
            return len(data)
        return 1
    except Exception:
        return 0


def build_completed_plugin_entry(plugin_name: str, output_file: str, selected: bool = True,
                                 auto_added: bool = False) -> dict:
    """Create a normalized plugin result entry for successful execution."""
    return {
        'name': plugin_name,
        'output_file': output_file,
        'timestamp': datetime.utcnow().isoformat(),
        'selected': selected,
        'auto_added': auto_added,
        'execution_status': 'completed',
        'row_count': get_output_row_count(output_file),
    }


def build_failed_plugin_entry(plugin_name: str, error: str, selected: bool = True,
                              auto_added: bool = False) -> dict:
    """Create a normalized plugin result entry for failed execution."""
    return {
        'name': plugin_name,
        'error': error,
        'timestamp': datetime.utcnow().isoformat(),
        'selected': selected,
        'auto_added': auto_added,
    }


def merge_plugin_ingestion_results(completed_plugins: list, failed_plugins: list,
                                   ingest_result: dict) -> tuple[list, list]:
    """Merge parser ingest status back into stored plugin execution results."""
    plugin_statuses = ingest_result.get('plugin_statuses') or {}
    merged_completed = []

    for item in completed_plugins:
        entry = dict(item)
        plugin_key = entry.get('name', '').replace('.', '_').replace(' ', '_')
        ingest_status = plugin_statuses.get(plugin_key)
        if ingest_status:
            entry['ingest_status'] = ingest_status.get('state')
            entry['state'] = ingest_status.get('state')
            entry['row_count'] = ingest_status.get('count', entry.get('row_count'))
            if ingest_status.get('reason'):
                entry['reason'] = ingest_status.get('reason')
            if ingest_status.get('error'):
                entry['error'] = ingest_status.get('error')
        else:
            entry.setdefault('state', 'completed')
        merged_completed.append(entry)

    merged_failed = []
    for item in failed_plugins:
        entry = dict(item)
        entry['state'] = 'failed'
        merged_failed.append(entry)

    return merged_completed, merged_failed


@shared_task(bind=True, max_retries=0)
def process_memory_dump(self, job_id: int):
    """
    Process a memory dump with Volatility3
    
    Args:
        job_id: ID of the MemoryJob record
    """
    from models.database import db
    from models.memory_job import MemoryJob
    
    app = get_flask_app()
    
    with app.app_context():
        job = MemoryJob.query.get(job_id)
        if not job:
            return {'success': False, 'error': 'Job not found'}
        
        try:
            # Update status to running
            job.status = 'running'
            job.started_at = datetime.utcnow()
            job.celery_task_id = self.request.id
            db.session.commit()
            update_job_progress(job_id, 0, status='running')
            
            # Create output folder - use case UUID, not integer ID
            # Include UUID suffix to prevent collision if two jobs start in same second
            import uuid as uuid_lib
            timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
            unique_suffix = str(uuid_lib.uuid4())[:8]
            case_paths = ensure_case_artifact_paths(job.case.uuid)
            working_base = os.path.join(
                case_paths['memory_staging'],
                f"job_{job.id}_{timestamp}_{unique_suffix}"
            )
            output_base = os.path.join(
                Config.STORAGE_FOLDER,
                job.case.uuid,
                job.hostname,
                f"memory_{timestamp}_{unique_suffix}"
            )
            vol3_output = os.path.join(output_base, 'vol3_output')
            extracted_folder = os.path.join(working_base, 'extracted')
            
            os.makedirs(vol3_output, exist_ok=True)
            os.makedirs(extracted_folder, exist_ok=True)
            
            job.output_folder = output_base
            db.session.commit()
            
            # Work from a transient staging copy so raw memory artifacts do not remain in storage.
            working_source = copy_to_directory(
                job.source_file,
                working_base,
                os.path.basename(job.source_file),
            )
            if not working_source:
                raise Exception('Failed to create staged working copy from retained original')

            # Handle ZIP files - extract first
            memory_file = working_source
            
            if job.source_file.lower().endswith('.zip'):
                update_job_progress(job_id, 0, current_plugin='Extracting ZIP...', status='running')
                job.current_plugin = 'Extracting ZIP...'
                db.session.commit()
                
                extracted_file = extract_memory_from_zip(working_source, extracted_folder)
                if not extracted_file:
                    raise Exception("No valid memory dump found in ZIP file. Expected: .raw, .dmp, .vmem, .mem, .lime, .bin")
                
                memory_file = extracted_file
                job.extracted_file_path = None
            
            # Process each selected plugin
            selected_plugins = list(job.selected_plugins or [])
            plugins = list(selected_plugins)
            completed_plugins = []
            failed_plugins = []
            idx = 0

            while idx < len(plugins):
                plugin_name = plugins[idx]
                total_plugins = max(len(plugins), 1)
                progress = int((idx / total_plugins) * 100)
                job.progress = progress
                job.current_plugin = plugin_name
                db.session.commit()
                update_job_progress(job_id, progress, current_plugin=plugin_name)
                
                # Run volatility3 for this plugin
                success, output_file, error = run_volatility_plugin(
                    memory_file,
                    plugin_name,
                    vol3_output,
                    job.os_type
                )
                
                if success:
                    plugin_entry = build_completed_plugin_entry(
                        plugin_name,
                        output_file,
                        selected=plugin_name in selected_plugins,
                        auto_added=plugin_name not in selected_plugins,
                    )
                    completed_plugins.append(plugin_entry)
                    
                    # Try to extract timestamp from windows.info
                    if plugin_name == 'windows.info' and output_file:
                        memory_ts = extract_timestamp_from_info(output_file)
                        if memory_ts:
                            job.memory_timestamp = memory_ts

                    if (
                        job.os_type == 'windows'
                        and plugin_name == 'windows.netscan'
                        and plugin_entry.get('row_count', 0) == 0
                        and 'windows.netstat' not in plugins
                    ):
                        plugins.append('windows.netstat')
                else:
                    failed_plugins.append(
                        build_failed_plugin_entry(
                            plugin_name,
                            error,
                            selected=plugin_name in selected_plugins,
                            auto_added=plugin_name not in selected_plugins,
                        )
                    )
                
                job.plugins_completed = completed_plugins
                job.plugins_failed = failed_plugins
                db.session.commit()
                idx += 1
            
            # Ingest parsed data into database tables for hunting
            job.current_plugin = 'Ingesting data...'
            db.session.commit()
            update_job_progress(job_id, 95, current_plugin='Ingesting data...')
            
            ingest_result = ingest_memory_data(job_id)
            if not ingest_result.get('success'):
                job.status = 'failed'
                job.error_message = ingest_result.get('error') or 'Memory ingestion failed'
                job.extracted_file_path = None
                job.completed_at = datetime.utcnow()
                db.session.commit()
                update_job_progress(job_id, job.progress, status='failed')
                if os.path.isdir(working_base):
                    shutil.rmtree(working_base, ignore_errors=True)
                return {
                    'success': False,
                    'job_id': job_id,
                    'completed': len(completed_plugins),
                    'failed': len(failed_plugins),
                    'output_folder': output_base,
                    'ingestion': ingest_result,
                }

            completed_plugins, failed_plugins = merge_plugin_ingestion_results(
                completed_plugins,
                failed_plugins,
                ingest_result,
            )
            job.plugins_completed = completed_plugins
            job.plugins_failed = failed_plugins
            db.session.commit()
            
            # Mark as completed
            job.status = 'completed'
            job.progress = 100
            job.current_plugin = None
            job.completed_at = datetime.utcnow()
            job.extracted_file_path = None
            db.session.commit()
            update_job_progress(job_id, 100, status='completed')

            if os.path.isdir(working_base):
                shutil.rmtree(working_base, ignore_errors=True)
            
            return {
                'success': True,
                'job_id': job_id,
                'completed': len(completed_plugins),
                'failed': len(failed_plugins),
                'output_folder': output_base,
                'ingestion': ingest_result
            }
            
        except Exception as e:
            try:
                if 'working_base' in locals() and os.path.isdir(working_base):
                    shutil.rmtree(working_base, ignore_errors=True)
            except Exception:
                pass
            job.status = 'failed'
            job.error_message = str(e)
            job.extracted_file_path = None
            job.completed_at = datetime.utcnow()
            db.session.commit()
            update_job_progress(job_id, job.progress, status='failed')
            
            return {'success': False, 'error': str(e)}


def run_volatility_plugin(memory_file: str, plugin_name: str, output_dir: str, os_type: str) -> tuple:
    """
    Run a single Volatility3 plugin
    
    Returns:
        (success: bool, output_file: str or None, error: str or None)
    """
    # Sanitize plugin name for filename
    safe_name = plugin_name.replace('.', '_').replace(' ', '_')
    output_file = os.path.join(output_dir, f"{safe_name}.json")
    
    try:
        # Build volatility3 command
        cmd = [
            'vol',  # or 'python', '-m', 'volatility3' depending on installation
            '-f', memory_file,
            '-r', 'json',  # JSON output
            plugin_name
        ]
        
        # Run the command
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=3600  # 1 hour timeout per plugin
        )
        
        if result.returncode == 0:
            # Write output to file
            with open(output_file, 'w') as f:
                f.write(result.stdout)
            return (True, output_file, None)
        else:
            error_msg = result.stderr or f"Exit code: {result.returncode}"
            return (False, None, error_msg)
            
    except subprocess.TimeoutExpired:
        return (False, None, "Plugin execution timed out (1 hour)")
    except FileNotFoundError:
        return (False, None, "Volatility3 not found. Please install with: pip install volatility3")
    except Exception as e:
        return (False, None, str(e))


def extract_timestamp_from_info(info_file: str) -> datetime:
    """
    Extract system timestamp from windows.info output
    """
    try:
        with open(info_file, 'r') as f:
            data = json.load(f)
        
        # Look for SystemTime in the output
        for item in data:
            if isinstance(item, dict):
                if item.get('Variable') == 'SystemTime':
                    system_time = item.get('Value')
                    if system_time:
                        try:
                            return datetime.fromisoformat(str(system_time).replace('Z', '+00:00')).replace(tzinfo=None)
                        except Exception:
                            pass

                # Different vol3 versions format this differently
                system_time = item.get('SystemTime') or item.get('system_time')
                if system_time:
                    # Parse the timestamp
                    if isinstance(system_time, str):
                        # Try common formats
                        for fmt in ['%Y-%m-%d %H:%M:%S', '%Y-%m-%dT%H:%M:%S', '%Y-%m-%d %H:%M:%S.%f']:
                            try:
                                return datetime.strptime(system_time[:19], fmt[:len(system_time)])
                            except:
                                continue
        return None
    except:
        return None


def extract_memory_from_zip(zip_path: str, extract_to: str) -> str:
    """
    Extract memory dump from a ZIP file
    
    Args:
        zip_path: Path to the ZIP file
        extract_to: Directory to extract to
        
    Returns:
        Path to extracted memory file, or None if no valid memory found
    """
    memory_extensions = ['.raw', '.dmp', '.vmem', '.mem', '.lime', '.bin']
    
    try:
        with zipfile.ZipFile(zip_path, 'r') as zf:
            members = zf.infolist()
            if len(members) > 2000:
                return None
            if sum(member.file_size for member in members) > 20 * 1024 * 1024 * 1024:
                return None
            # Find memory files in the archive
            memory_files = []
            for member in members:
                name = member.filename
                lower_name = name.lower()
                if any(lower_name.endswith(ext) for ext in memory_extensions):
                    memory_files.append(name)
            
            if not memory_files:
                return None
            
            # Extract the largest memory file (most likely the main dump)
            largest_file = max(memory_files, key=lambda x: zf.getinfo(x).file_size)
            real_extract_to = os.path.realpath(extract_to)
            target_path = os.path.realpath(os.path.join(extract_to, largest_file))
            if not target_path.startswith(real_extract_to + os.sep):
                return None
            
            # Extract just this file
            zf.extract(largest_file, extract_to)
            extracted_path = os.path.join(extract_to, largest_file)
            
            # Flatten the path if it was in subdirectories
            base_name = os.path.basename(largest_file)
            final_path = os.path.join(extract_to, base_name)
            
            if extracted_path != final_path:
                shutil.move(extracted_path, final_path)
                # Clean up empty directories
                try:
                    subdir = os.path.dirname(extracted_path)
                    while subdir != extract_to:
                        os.rmdir(subdir)
                        subdir = os.path.dirname(subdir)
                except:
                    pass
                    
            return final_path
            
    except zipfile.BadZipFile:
        return None
    except Exception as e:
        return None


def ingest_memory_data(job_id: int) -> dict:
    """
    Ingest Vol3 JSON output into database tables for hunting
    
    Args:
        job_id: ID of the MemoryJob record
        
    Returns:
        Dict with ingestion results
    """
    from parsers.memory_parser import ingest_memory_job
    
    try:
        result = ingest_memory_job(job_id)
        return result
    except Exception as e:
        return {'success': False, 'error': str(e)}


def extract_timestamp_from_filename(filename: str) -> datetime:
    """
    Try to extract timestamp from filename patterns like:
    - HOST_20260119_153045.raw
    - memory_2026-01-19_15-30-45.dmp
    """
    patterns = [
        r'(\d{8})_(\d{6})',  # YYYYMMDD_HHMMSS
        r'(\d{4}-\d{2}-\d{2})_(\d{2}-\d{2}-\d{2})',  # YYYY-MM-DD_HH-MM-SS
        r'(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2})',  # ISO format
    ]
    
    for pattern in patterns:
        match = re.search(pattern, filename)
        if match:
            try:
                date_part = match.group(1)
                time_part = match.group(2)
                
                # Normalize separators
                date_part = date_part.replace('-', '')
                time_part = time_part.replace('-', '').replace(':', '')
                
                if len(date_part) == 8 and len(time_part) == 6:
                    return datetime.strptime(f"{date_part}{time_part}", '%Y%m%d%H%M%S')
            except:
                continue
    
    return None
