"""
Hardware Setup and Requirements Installation
Handles NVIDIA driver installation and CUDA configuration
"""
import subprocess
import logging
import os
import re
import time

logger = logging.getLogger(__name__)


def check_nvidia_driver():
    """Check if NVIDIA driver is installed and get version"""
    try:
        result = subprocess.run(
            ['nvidia-smi', '--query-gpu=driver_version', '--format=csv,noheader'],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            version = result.stdout.strip()
            return {'installed': True, 'version': version}
    except:
        pass
    return {'installed': False, 'version': None}


def check_cuda_libraries():
    """Check if CUDA libraries exist for Ollama"""
    cuda_path = '/usr/local/lib/ollama'
    cuda_dirs = []
    
    if os.path.exists(cuda_path):
        for item in os.listdir(cuda_path):
            if 'cuda' in item.lower():
                cuda_dirs.append(item)
    
    return {'found': len(cuda_dirs) > 0, 'versions': cuda_dirs}


def check_ollama_service_config():
    """Check if Ollama service is configured for CUDA"""
    service_file = '/etc/systemd/system/ollama.service'
    
    if not os.path.exists(service_file):
        return {'exists': False, 'cuda_configured': False}
    
    try:
        with open(service_file, 'r') as f:
            content = f.read()
            cuda_configured = 'LD_LIBRARY_PATH' in content and 'cuda' in content.lower()
            return {'exists': True, 'cuda_configured': cuda_configured}
    except:
        return {'exists': True, 'cuda_configured': False}


def get_gpu_requirements_status():
    """Get complete status of GPU requirements"""
    driver = check_nvidia_driver()
    cuda_libs = check_cuda_libraries()
    ollama_config = check_ollama_service_config()
    
    all_ready = (
        driver['installed'] and
        cuda_libs['found'] and
        ollama_config.get('cuda_configured', False)
    )
    
    return {
        'ready': all_ready,
        'driver': driver,
        'cuda_libs': cuda_libs,
        'ollama_config': ollama_config
    }


def install_nvidia_driver(progress_callback=None):
    """Install NVIDIA driver (version 550+)"""
    steps = []
    
    try:
        if progress_callback:
            progress_callback("Checking current driver version...")
        
        # Check if driver already installed
        driver_check = check_nvidia_driver()
        if driver_check['installed']:
            if progress_callback:
                progress_callback(f"✓ Driver already installed: {driver_check['version']}")
            return {'success': True, 'already_installed': True}
        
        if progress_callback:
            progress_callback("Installing NVIDIA driver 550...")
        
        # Add NVIDIA PPA
        steps.append(("Adding NVIDIA PPA...", [
            '/usr/bin/sudo', 'add-apt-repository', 'ppa:graphics-drivers/ppa', '-y'
        ]))
        
        # Update package list
        steps.append(("Updating package lists...", [
            '/usr/bin/sudo', 'apt-get', 'update'
        ]))
        
        # Install driver
        steps.append(("Installing NVIDIA driver (this may take 5-10 minutes)...", [
            '/usr/bin/sudo', 'apt-get', 'install', '-y', 'nvidia-driver-550'
        ]))
        
        for step_msg, cmd in steps:
            if progress_callback:
                progress_callback(step_msg)
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            if result.returncode != 0:
                error_msg = f"Failed: {step_msg}\n{result.stderr}"
                if progress_callback:
                    progress_callback(f"❌ {error_msg}")
                return {'success': False, 'error': error_msg}
        
        if progress_callback:
            progress_callback("✓ Driver installed successfully. Reboot required!")
        
        return {'success': True, 'reboot_required': True}
        
    except Exception as e:
        error_msg = f"Installation error: {str(e)}"
        if progress_callback:
            progress_callback(f"❌ {error_msg}")
        return {'success': False, 'error': error_msg}


def configure_ollama_cuda(progress_callback=None):
    """Configure Ollama service to use CUDA libraries"""
    try:
        if progress_callback:
            progress_callback("Configuring Ollama for CUDA...")
        
        service_file = '/etc/systemd/system/ollama.service'
        
        if not os.path.exists(service_file):
            return {'success': False, 'error': 'Ollama service file not found'}
        
        # Read current service file
        with open(service_file, 'r') as f:
            lines = f.readlines()
        
        # Check if already configured
        has_ld_library = any('LD_LIBRARY_PATH' in line for line in lines)
        
        if has_ld_library:
            if progress_callback:
                progress_callback("✓ Ollama already configured for CUDA")
            return {'success': True, 'already_configured': True}
        
        # Add CUDA environment variables
        new_lines = []
        for line in lines:
            new_lines.append(line)
            if '[Service]' in line:
                new_lines.append('Environment="LD_LIBRARY_PATH=/usr/local/lib/ollama:/usr/local/lib/ollama/cuda_v12"\n')
                new_lines.append('Environment="OLLAMA_LLM_LIBRARY=cuda_v12"\n')
        
        # Write updated service file using sudo tee
        if progress_callback:
            progress_callback("Writing updated service configuration...")
        
        # Use tee to write with sudo privileges
        tee_process = subprocess.Popen(
            ['/usr/bin/sudo', 'tee', service_file],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        stdout, stderr = tee_process.communicate(input=''.join(new_lines))
        if tee_process.returncode != 0:
            raise Exception(f"Failed to write service file: {stderr}")
        
        # Reload systemd and restart Ollama
        if progress_callback:
            progress_callback("Reloading systemd...")
        subprocess.run(['/usr/bin/sudo', 'systemctl', 'daemon-reload'], check=True, timeout=30)
        
        if progress_callback:
            progress_callback("Restarting Ollama service...")
        subprocess.run(['/usr/bin/sudo', 'systemctl', 'restart', 'ollama.service'], check=True, timeout=30)
        
        if progress_callback:
            progress_callback("✓ Ollama configured for CUDA successfully")
        
        return {'success': True}
        
    except Exception as e:
        error_msg = f"Configuration error: {str(e)}"
        if progress_callback:
            progress_callback(f"❌ {error_msg}")
        return {'success': False, 'error': error_msg}


def setup_gpu_requirements(progress_callback=None):
    """
    Complete GPU setup process
    Returns dict with success status and messages
    """
    if progress_callback:
        progress_callback("🔍 Checking GPU requirements...")
    
    status = get_gpu_requirements_status()
    
    if status['ready']:
        if progress_callback:
            progress_callback("✓ All GPU requirements already met!")
        return {'success': True, 'already_ready': True}
    
    steps_completed = []
    
    # Step 1: Install NVIDIA driver if needed
    if not status['driver']['installed']:
        if progress_callback:
            progress_callback("📦 Installing NVIDIA driver...")
        result = install_nvidia_driver(progress_callback)
        if not result['success']:
            return result
        steps_completed.append('driver')
    else:
        if progress_callback:
            progress_callback(f"✓ NVIDIA driver OK: {status['driver']['version']}")
    
    # Step 2: Configure Ollama for CUDA
    if not status['ollama_config'].get('cuda_configured', False):
        if progress_callback:
            progress_callback("⚙️ Configuring Ollama for CUDA...")
        result = configure_ollama_cuda(progress_callback)
        if not result['success']:
            return result
        steps_completed.append('ollama_config')
    else:
        if progress_callback:
            progress_callback("✓ Ollama CUDA config OK")
    
    if progress_callback:
        progress_callback(f"✅ Setup complete! Steps: {', '.join(steps_completed)}")
    
    return {
        'success': True,
        'steps_completed': steps_completed,
        'reboot_required': 'driver' in steps_completed
    }

