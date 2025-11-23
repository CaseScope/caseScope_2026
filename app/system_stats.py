"""
CaseScope 2026 - System Statistics Module
Provides system health monitoring and software version detection
"""

import os
import platform
import subprocess
import psutil
from pathlib import Path


def get_gpu_info():
    """Detect GPU information using nvidia-smi, lspci, or other methods"""
    try:
        # Try nvidia-smi first (NVIDIA GPUs)
        env = os.environ.copy()
        env['PATH'] = '/usr/bin:/usr/local/bin:/bin:' + env.get('PATH', '')
        result = subprocess.run(['nvidia-smi', '--query-gpu=gpu_name,driver_version,memory.total', 
                                '--format=csv,noheader,nounits'],
                              capture_output=True, text=True, timeout=5,
                              env=env)
        if result.returncode == 0 and result.stdout.strip():
            # Parse nvidia-smi output
            lines = result.stdout.strip().split('\n')
            gpus = []
            for line in lines:
                parts = [p.strip() for p in line.split(',')]
                if len(parts) >= 3:
                    gpu_name = parts[0]
                    driver = parts[1]
                    vram_mb = parts[2]
                    vram_gb = round(float(vram_mb) / 1024, 1)
                    gpus.append(f"{gpu_name} ({vram_gb}GB VRAM, Driver: {driver})")
            
            if gpus:
                return gpus
    except Exception as e:
        pass  # nvidia-smi not available or failed
    
    try:
        # Fallback: Try lspci for any GPU
        env = os.environ.copy()
        env['PATH'] = '/usr/bin:/usr/local/bin:/bin:/sbin:/usr/sbin:' + env.get('PATH', '')
        result = subprocess.run(['lspci'], capture_output=True, text=True, timeout=5,
                              env=env)
        if result.returncode == 0:
            gpus = []
            for line in result.stdout.split('\n'):
                # Look for VGA, 3D, or Display controller
                if 'VGA' in line or '3D controller' in line or 'Display controller' in line:
                    # Extract GPU name (everything after the : )
                    if ':' in line:
                        gpu_line = line.split(':', 2)[-1].strip()
                        # Clean up common prefixes
                        gpu_line = gpu_line.replace('VGA compatible controller:', '').strip()
                        gpu_line = gpu_line.replace('3D controller:', '').strip()
                        gpu_line = gpu_line.replace('Display controller:', '').strip()
                        if gpu_line and 'vendor' not in gpu_line.lower():
                            gpus.append(gpu_line)
            
            if gpus:
                return gpus
    except Exception as e:
        pass  # lspci not available or failed
    
    return None  # No GPU detected


def get_system_status():
    """Get system status information"""
    try:
        # CPU info
        cpu_count = psutil.cpu_count(logical=True)
        cpu_percent = psutil.cpu_percent(interval=1)
        
        # Memory info
        mem = psutil.virtual_memory()
        mem_total_gb = round(mem.total / (1024**3), 2)
        mem_used_gb = round(mem.used / (1024**3), 2)
        mem_percent = mem.percent
        
        # Disk info
        disk = psutil.disk_usage('/')
        disk_total_gb = round(disk.total / (1024**3), 2)
        disk_used_gb = round(disk.used / (1024**3), 2)
        disk_percent = disk.percent
        
        # OS info
        os_name = f"{platform.system()} {platform.release()}"
        
        # GPU detection
        gpu_info = get_gpu_info()
        
        result = {
            'os_name': os_name,
            'cpu_cores': cpu_count,
            'cpu_usage': cpu_percent,
            'memory_total_gb': mem_total_gb,
            'memory_used_gb': mem_used_gb,
            'memory_percent': mem_percent,
            'disk_total_gb': disk_total_gb,
            'disk_used_gb': disk_used_gb,
            'disk_percent': disk_percent
        }
        
        # Add GPU info if found
        if gpu_info:
            result['gpu_info'] = gpu_info
        
        return result
    except Exception as e:
        print(f"Error getting system status: {e}")
        return None


def get_case_files_space():
    """Calculate space consumed by case files"""
    try:
        uploads_path = '/opt/casescope/uploads'
        staging_path = '/opt/casescope/staging'
        
        total_size = 0
        
        # Calculate uploads directory size
        if os.path.exists(uploads_path):
            for dirpath, dirnames, filenames in os.walk(uploads_path):
                for filename in filenames:
                    filepath = os.path.join(dirpath, filename)
                    if os.path.exists(filepath):
                        total_size += os.path.getsize(filepath)
        
        # Calculate staging directory size
        if os.path.exists(staging_path):
            for dirpath, dirnames, filenames in os.walk(staging_path):
                for filename in filenames:
                    filepath = os.path.join(dirpath, filename)
                    if os.path.exists(filepath):
                        total_size += os.path.getsize(filepath)
        
        # Convert to GB
        total_gb = round(total_size / (1024**3), 2)
        return total_gb
    except Exception as e:
        print(f"Error calculating case files space: {e}")
        return 0


def get_software_versions():
    """Detect installed software versions"""
    versions = {}
    
    # Python version
    versions['Python'] = platform.python_version()
    
    # PostgreSQL version
    try:
        import os as os_module
        env = os_module.environ.copy()
        env['PATH'] = '/usr/bin:/usr/local/bin:/bin:' + env.get('PATH', '')
        result = subprocess.run(['psql', '--version'], 
                              capture_output=True, text=True, timeout=5,
                              env=env)
        if result.returncode == 0 and result.stdout:
            # Parse version from output like "psql (PostgreSQL) 16.10"
            version_line = result.stdout.strip()
            # Extract version number (e.g., "16.10" from "psql (PostgreSQL) 16.10")
            if 'PostgreSQL' in version_line or 'psql' in version_line:
                parts = version_line.split()
                # Look for version number pattern (contains dot)
                for part in parts:
                    if '.' in part and part[0].isdigit():
                        versions['PostgreSQL'] = part.strip()
                        break
                else:
                    versions['PostgreSQL'] = 'Installed'
            else:
                versions['PostgreSQL'] = 'Installed'
        else:
            versions['PostgreSQL'] = 'Unknown'
    except Exception as e:
        print(f"PostgreSQL version detection error: {e}")
        versions['PostgreSQL'] = 'Unknown'
    
    # Flask version
    try:
        import flask
        versions['Flask'] = flask.__version__
    except:
        versions['Flask'] = 'Unknown'
    
    # Celery version
    try:
        import celery
        versions['Celery'] = celery.__version__
    except:
        versions['Celery'] = 'Unknown'
    
    # Redis version
    try:
        import os as os_module
        env = os_module.environ.copy()
        env['PATH'] = '/usr/bin:/usr/local/bin:/bin:' + env.get('PATH', '')
        result = subprocess.run(['redis-cli', '--version'], 
                              capture_output=True, text=True, timeout=5,
                              env=env)
        if result.returncode == 0:
            # Parse version from output like "redis-cli 7.0.15"
            version_line = result.stdout.strip()
            parts = version_line.split()
            if len(parts) >= 2 and '.' in parts[1]:
                # Extract just the version number (second part)
                versions['Redis'] = parts[1].strip()
            else:
                # Fallback: try to find any part with dots (version pattern)
                for part in parts:
                    if '.' in part and part[0].isdigit():
                        versions['Redis'] = part.strip()
                        break
                else:
                    versions['Redis'] = 'Installed'
        else:
            versions['Redis'] = 'Unknown'
    except Exception as e:
        print(f"Redis version detection error: {e}")
        versions['Redis'] = 'Unknown'
    
    # OpenSearch version
    try:
        import requests
        response = requests.get('http://localhost:9200', timeout=2)
        if response.status_code == 200:
            data = response.json()
            versions['OpenSearch'] = data.get('version', {}).get('number', 'Unknown')
        else:
            versions['OpenSearch'] = 'Running'
    except:
        versions['OpenSearch'] = 'Unknown'
    
    # evtx_dump version
    try:
        result = subprocess.run(['/opt/casescope/bin/evtx_dump', '--version'], 
                              capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            # Extract version from output
            version_line = result.stderr.strip() or result.stdout.strip()
            if version_line:
                versions['evtx_dump'] = version_line.split()[-1] if ' ' in version_line else version_line
            else:
                versions['evtx_dump'] = 'Installed'
        else:
            versions['evtx_dump'] = 'Installed'
    except:
        versions['evtx_dump'] = 'Not Found'
    
    # Chainsaw version
    try:
        result = subprocess.run(['/opt/casescope/bin/chainsaw', '--version'], 
                              capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            # Parse version like "chainsaw 2.9.1"
            version_line = result.stdout.strip()
            if ' ' in version_line:
                versions['Chainsaw'] = version_line.split()[-1]
            else:
                versions['Chainsaw'] = version_line
        else:
            versions['Chainsaw'] = 'Installed'
    except:
        versions['Chainsaw'] = 'Not Found'
    
    # Gunicorn version
    try:
        import gunicorn
        versions['Gunicorn'] = gunicorn.__version__
    except:
        versions['Gunicorn'] = 'Unknown'
    
    return versions


def get_service_status():
    """Check if critical services are running"""
    services = {}
    
    # Check systemd services
    service_names = ['casescope', 'casescope-worker', 'opensearch', 'redis']
    
    for service in service_names:
        try:
            result = subprocess.run(['systemctl', 'is-active', service], 
                                  capture_output=True, text=True, timeout=2)
            services[service] = result.stdout.strip() == 'active'
        except:
            services[service] = False
    
    return services


def get_sigma_rules_info():
    """Get SIGMA rules information (v1.26.0: includes last_checked and last_updated)"""
    import json
    from pathlib import Path
    try:
        sigma_path = '/opt/casescope/sigma_rules'
        tracking_file = Path('/opt/casescope/app/sigma_update_tracking.json')
        
        if not os.path.exists(sigma_path):
            return {'total': 0, 'enabled': 0, 'last_checked': None, 'last_updated': None}
        
        # Count .yml files
        total_rules = 0
        for root, dirs, files in os.walk(sigma_path):
            total_rules += len([f for f in files if f.endswith('.yml')])
        
        # Get tracked timestamps from tracking file (v1.26.0)
        last_checked = None
        last_updated = None
        
        if tracking_file.exists():
            try:
                from datetime import datetime
                tracking_data = json.loads(tracking_file.read_text())
                if 'last_checked' in tracking_data:
                    last_checked = datetime.fromisoformat(tracking_data['last_checked'])
                if 'last_updated' in tracking_data:
                    last_updated = datetime.fromisoformat(tracking_data['last_updated'])
            except Exception as e:
                print(f"Warning: Could not read SIGMA tracking file: {e}")
        
        # Fallback: Get last modification time if no tracking file
        if last_updated is None:
            try:
                stat = os.stat(sigma_path)
                from datetime import datetime
                last_updated = datetime.fromtimestamp(stat.st_mtime)
            except:
                last_updated = None
        
        return {
            'total': total_rules,
            'enabled': total_rules,  # All rules are enabled by default
            'last_checked': last_checked,  # v1.26.0: When we last ran update check
            'last_updated': last_updated   # v1.26.0: When rules were actually updated
        }
    except Exception as e:
        print(f"Error getting SIGMA rules info: {e}")
        return {'total': 0, 'enabled': 0, 'last_checked': None, 'last_updated': None}

