#!/usr/bin/env python3
"""
Auto-tune Celery worker count based on system resources
Called at startup to optimize for available CPU/RAM
"""

import psutil
import sys
import os
import re

def calculate_optimal_workers():
    """
    Calculate optimal worker count based on:
    - CPU cores
    - Available RAM
    - Workload type (I/O vs CPU intensive)
    
    Target: <5 minutes for 3GB ZIP with ~1000 files
    """
    # Get system resources
    cpu_count = psutil.cpu_count(logical=True)
    memory_gb = psutil.virtual_memory().total / (1024**3)
    
    # Base calculation: Start with CPU cores
    # For forensic file processing (mixed I/O + CPU):
    # - Use 75% of CPU cores (leave headroom for Flask, OpenSearch)
    # - Cap at 16 workers (diminishing returns beyond this)
    # - Minimum 4 workers
    
    optimal_workers = max(4, min(16, int(cpu_count * 0.75)))
    
    # Adjust for available RAM
    # Each worker needs ~512MB-1GB for large files
    # Leave 4GB for system + Flask + OpenSearch
    reserved_ram = 4.0
    available_ram = memory_gb - reserved_ram
    ram_based_max = int(available_ram / 0.75)  # Assume 750MB per worker
    
    if ram_based_max < optimal_workers:
        print(f"⚠️  RAM constraint: Reducing workers from {optimal_workers} to {ram_based_max}", file=sys.stderr)
        optimal_workers = max(4, ram_based_max)
    
    return optimal_workers


def update_config_workers(worker_count):
    """Update config.py with new worker count"""
    config_path = '/opt/casescope/app/config.py'
    
    try:
        with open(config_path, 'r') as f:
            content = f.read()
        
        # Replace CELERY_WORKERS value
        pattern = r'CELERY_WORKERS\s*=\s*\d+'
        replacement = f'CELERY_WORKERS = {worker_count}'
        
        new_content = re.sub(pattern, replacement, content)
        
        with open(config_path, 'w') as f:
            f.write(new_content)
        
        return True
    except Exception as e:
        print(f"❌ Failed to update config: {e}", file=sys.stderr)
        return False


if __name__ == '__main__':
    # Get system info
    cpu_count = psutil.cpu_count(logical=True)
    memory_gb = psutil.virtual_memory().total / (1024**3)
    
    print("=" * 60)
    print("CaseScope Performance Auto-Tune")
    print("=" * 60)
    print(f"System Resources:")
    print(f"  CPU Cores: {cpu_count}")
    print(f"  Total RAM: {memory_gb:.1f} GB")
    print()
    
    # Calculate optimal workers
    optimal = calculate_optimal_workers()
    
    print(f"Recommended Workers: {optimal}")
    print(f"  Target: <5min for 3GB ZIP (~1000 files)")
    print(f"  Estimated throughput: ~{optimal * 6} files/minute")
    print()
    
    # Check if we should update (only if different from current)
    try:
        sys.path.insert(0, '/opt/casescope/app')
        from config import CELERY_WORKERS as current_workers
        
        if current_workers == optimal:
            print(f"✓ Already optimized ({current_workers} workers)")
            sys.exit(0)
        
        print(f"Current: {current_workers} workers")
        print(f"Updating to: {optimal} workers")
        print()
        
        if update_config_workers(optimal):
            print("✅ Configuration updated successfully!")
            print(f"   Workers: {current_workers} → {optimal}")
            print()
            print("⚠️  Restart casescope-workers to apply changes:")
            print("   sudo systemctl restart casescope-workers")
        else:
            print("❌ Failed to update configuration")
            sys.exit(1)
    
    except Exception as e:
        print(f"❌ Error: {e}", file=sys.stderr)
        sys.exit(1)

