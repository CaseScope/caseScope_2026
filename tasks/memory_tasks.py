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
from utils.artifact_paths import ensure_case_subdir, move_to_directory

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
            output_base = os.path.join(
                Config.STORAGE_FOLDER,
                job.case.uuid,
                job.hostname,
                f"memory_{timestamp}_{unique_suffix}"
            )
            vol3_output = os.path.join(output_base, 'vol3_output')
            extracted_folder = os.path.join(output_base, 'extracted')
            
            os.makedirs(vol3_output, exist_ok=True)
            os.makedirs(extracted_folder, exist_ok=True)
            
            job.output_folder = output_base
            db.session.commit()
            
            # Handle ZIP files - extract first
            memory_file = job.source_file
            cleanup_extracted = False
            
            if job.source_file.lower().endswith('.zip'):
                update_job_progress(job_id, 0, current_plugin='Extracting ZIP...', status='running')
                job.current_plugin = 'Extracting ZIP...'
                db.session.commit()
                
                extracted_file = extract_memory_from_zip(job.source_file, extracted_folder)
                if not extracted_file:
                    raise Exception("No valid memory dump found in ZIP file. Expected: .raw, .dmp, .vmem, .mem, .lime, .bin")
                
                memory_file = extracted_file
                job.extracted_file_path = extracted_file
                cleanup_extracted = True
            
            # Process each selected plugin
            plugins = job.selected_plugins or []
            total_plugins = len(plugins)
            completed_plugins = []
            failed_plugins = []
            
            for idx, plugin_name in enumerate(plugins):
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
                    completed_plugins.append({
                        'name': plugin_name,
                        'output_file': output_file,
                        'timestamp': datetime.utcnow().isoformat()
                    })
                    
                    # Try to extract timestamp from windows.info
                    if plugin_name == 'windows.info' and output_file:
                        memory_ts = extract_timestamp_from_info(output_file)
                        if memory_ts:
                            job.memory_timestamp = memory_ts
                else:
                    failed_plugins.append({
                        'name': plugin_name,
                        'error': error,
                        'timestamp': datetime.utcnow().isoformat()
                    })
                
                job.plugins_completed = completed_plugins
                job.plugins_failed = failed_plugins
                db.session.commit()
            
            # Retain extracted memory files under case storage instead of deleting them.
            if cleanup_extracted and memory_file and os.path.exists(memory_file):
                retained_extract_dir = ensure_case_subdir(job.case.uuid, 'memory', 'extracted')
                retained_extract = move_to_directory(
                    memory_file,
                    retained_extract_dir,
                    os.path.basename(memory_file)
                )
                if retained_extract:
                    memory_file = retained_extract
                    job.extracted_file_path = retained_extract
                    db.session.commit()
            
            # Ingest parsed data into database tables for hunting
            job.current_plugin = 'Ingesting data...'
            db.session.commit()
            update_job_progress(job_id, 95, current_plugin='Ingesting data...')
            
            ingest_result = ingest_memory_data(job_id)
            if not ingest_result.get('success'):
                job.status = 'failed'
                job.error_message = ingest_result.get('error') or 'Memory ingestion failed'
                job.completed_at = datetime.utcnow()
                db.session.commit()
                update_job_progress(job_id, job.progress, status='failed')
                return {
                    'success': False,
                    'job_id': job_id,
                    'completed': len(completed_plugins),
                    'failed': len(failed_plugins),
                    'output_folder': output_base,
                    'ingestion': ingest_result,
                }
            
            # Mark as completed
            job.status = 'completed'
            job.progress = 100
            job.current_plugin = None
            job.completed_at = datetime.utcnow()
            db.session.commit()
            update_job_progress(job_id, 100, status='completed')
            
            return {
                'success': True,
                'job_id': job_id,
                'completed': len(completed_plugins),
                'failed': len(failed_plugins),
                'output_folder': output_base,
                'ingestion': ingest_result
            }
            
        except Exception as e:
            job.status = 'failed'
            job.error_message = str(e)
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
