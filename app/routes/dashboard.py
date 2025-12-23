"""
Dashboard API Routes
Provides system statistics and metrics for the main dashboard
"""

from flask import Blueprint, jsonify
from flask_login import login_required
import psutil
import os
import platform
import subprocess
from datetime import datetime
from pathlib import Path

dashboard_bp = Blueprint('dashboard', __name__, url_prefix='/api/dashboard')


@dashboard_bp.route('/stats')
@login_required
def dashboard_stats():
    """
    Get comprehensive dashboard statistics
    Returns system info, case stats, and software versions
    """
    try:
        stats = {
            'system': get_system_info(),
            'cases': get_case_statistics(),
            'software': get_software_versions(),
            'timestamp': datetime.utcnow().isoformat()
        }
        return jsonify(stats)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


def get_system_info():
    """Get system hardware and storage information"""
    
    # System name and OS
    hostname = platform.node()
    os_info = f"{platform.system()} {platform.release()}"
    
    # CPU usage (current percentage)
    cpu_percent = psutil.cpu_percent(interval=1)
    cpu_count = psutil.cpu_count()
    
    # RAM usage
    ram = psutil.virtual_memory()
    ram_total_gb = ram.total / (1024**3)
    ram_used_gb = ram.used / (1024**3)
    ram_percent = ram.percent
    
    # Disk usage for all partitions
    disks = []
    for partition in psutil.disk_partitions():
        try:
            usage = psutil.disk_usage(partition.mountpoint)
            disks.append({
                'device': partition.device,
                'mountpoint': partition.mountpoint,
                'fstype': partition.fstype,
                'total_gb': usage.total / (1024**3),
                'used_gb': usage.used / (1024**3),
                'free_gb': usage.free / (1024**3),
                'percent': usage.percent
            })
        except PermissionError:
            continue
    
    # Case files storage
    case_files_live = get_directory_size('/opt/casescope/storage') if os.path.exists('/opt/casescope/storage') else 0
    case_files_archive = 0  # Archive location TBD
    
    return {
        'hostname': hostname,
        'os': os_info,
        'cpu': {
            'cores': cpu_count,
            'usage_percent': cpu_percent
        },
        'ram': {
            'total_gb': round(ram_total_gb, 2),
            'used_gb': round(ram_used_gb, 2),
            'free_gb': round(ram_total_gb - ram_used_gb, 2),
            'percent': ram_percent
        },
        'disks': disks,
        'case_storage': {
            'live_gb': round(case_files_live / (1024**3), 2),
            'archive_gb': round(case_files_archive / (1024**3), 2),
            'total_gb': round((case_files_live + case_files_archive) / (1024**3), 2)
        }
    }


def get_case_statistics():
    """Get case and event statistics from database"""
    from main import db
    from models import Case, User
    
    # Total cases
    total_cases = Case.query.count()
    
    # Total events (will need to query OpenSearch or sum from case files table in future)
    # Placeholder for now
    total_events = 0
    
    # Total users
    total_users = User.query.count()
    
    return {
        'total_cases': total_cases,
        'total_events': total_events,
        'total_users': total_users
    }


def get_software_versions():
    """
    Get versions of all software dependencies
    Dynamically detected, not hardcoded
    """
    versions = {}
    
    # Python version
    versions['python'] = platform.python_version()
    
    # PostgreSQL version
    try:
        result = subprocess.run(['psql', '--version'], capture_output=True, text=True, timeout=2)
        if result.returncode == 0:
            versions['postgresql'] = result.stdout.strip().split()[-1]
        else:
            versions['postgresql'] = 'Not detected'
    except Exception:
        versions['postgresql'] = 'Not detected'
    
    # OpenSearch version (check via HTTP API)
    try:
        import requests
        from app.config import Config
        opensearch_url = f"http://{Config.OPENSEARCH_HOST}:{Config.OPENSEARCH_PORT}"
        response = requests.get(opensearch_url, timeout=2)
        if response.status_code == 200:
            data = response.json()
            versions['opensearch'] = data.get('version', {}).get('number', 'Unknown')
        else:
            versions['opensearch'] = 'Not detected'
    except Exception:
        versions['opensearch'] = 'Not detected'
    
    # Flask version
    try:
        import flask
        versions['flask'] = flask.__version__
    except Exception:
        versions['flask'] = 'Unknown'
    
    # SQLAlchemy version
    try:
        import sqlalchemy
        versions['sqlalchemy'] = sqlalchemy.__version__
    except Exception:
        versions['sqlalchemy'] = 'Unknown'
    
    # Gunicorn version
    try:
        import gunicorn
        versions['gunicorn'] = gunicorn.__version__
    except Exception:
        versions['gunicorn'] = 'Not detected'
    
    # Celery version (if installed)
    try:
        import celery
        versions['celery'] = celery.__version__
    except Exception:
        versions['celery'] = 'Not installed'
    
    # Werkzeug version
    try:
        # Werkzeug 3.x removed __version__ attribute, get version from package metadata
        import importlib.metadata
        versions['werkzeug'] = importlib.metadata.version('werkzeug')
    except Exception:
        versions['werkzeug'] = 'Unknown'
    
    return versions


def get_directory_size(path):
    """Calculate total size of a directory in bytes"""
    total = 0
    try:
        for entry in os.scandir(path):
            if entry.is_file(follow_symlinks=False):
                total += entry.stat().st_size
            elif entry.is_dir(follow_symlinks=False):
                total += get_directory_size(entry.path)
    except (PermissionError, OSError):
        pass
    return total
