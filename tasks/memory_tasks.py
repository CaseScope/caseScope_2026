"""Memory Forensics Celery Tasks for CaseScope"""
import os
import json
import shutil
import subprocess
import re
from datetime import datetime
from celery import shared_task
import redis

from config import Config


def get_redis_client():
    """Get Redis client for progress tracking"""
    return redis.Redis(host=Config.REDIS_HOST, port=Config.REDIS_PORT, db=Config.REDIS_DB)


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
    from app import create_app
    from models.database import db
    from models.memory_job import MemoryJob
    
    app = create_app()
    
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
            
            # Create output folder
            timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
            output_base = os.path.join(
                Config.STORAGE_FOLDER,
                str(job.case_id),
                job.hostname,
                f"memory_{timestamp}"
            )
            vol3_output = os.path.join(output_base, 'vol3_output')
            extracted_folder = os.path.join(output_base, 'extracted')
            
            os.makedirs(vol3_output, exist_ok=True)
            os.makedirs(extracted_folder, exist_ok=True)
            
            job.output_folder = output_base
            db.session.commit()
            
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
                    job.source_file,
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
            
            # Clean up source file (purge after processing)
            if os.path.exists(job.source_file):
                try:
                    os.remove(job.source_file)
                except Exception as e:
                    pass  # Don't fail job if cleanup fails
            
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
                'output_folder': output_base
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
