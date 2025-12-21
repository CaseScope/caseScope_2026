#!/usr/bin/env python3
"""
Cleanup Stale Case Locks (v1.25.0)
Run this script periodically (e.g., hourly cron job) to clean up stale locks

Crontab example:
0 * * * * /opt/casescope/venv/bin/python3 /opt/casescope/app/cleanup_stale_locks.py >> /opt/casescope/logs/lock_cleanup.log 2>&1
"""

import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from main import app
from case_lock_manager import cleanup_stale_locks
from datetime import datetime

def main():
    with app.app_context():
        print(f"[{datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}] Starting stale lock cleanup...")
        count, message = cleanup_stale_locks()
        print(f"[{datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}] {message}")
        
        if count > 0:
            print(f"[{datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}] ✅ Cleaned up {count} stale lock(s)")
        else:
            print(f"[{datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}] ✅ No stale locks found")

if __name__ == '__main__':
    main()

