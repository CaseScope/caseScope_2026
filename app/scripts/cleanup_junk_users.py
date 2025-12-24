#!/usr/bin/env python3
"""
Cleanup script to remove junk/system users from Known Users
Run this after updating the exclusion list to clean up previously discovered entries
"""

import os
import sys
import re

# Add app directory to Python path
app_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if app_dir not in sys.path:
    sys.path.insert(0, app_dir)

from main import app, db
from models import KnownUser

# Same exclusion logic as the discovery task
EXCLUDED_USERNAMES = {
    # System accounts
    'system', 'local service', 'network service', 'local_service', 'network_service',
    'dwa\\system', 'nt authority\\system', 'nt authority\\local service', 
    'nt authority\\network service', 'authority\\system',
    
    # Built-in Windows accounts
    'guest', 'administrator', 'defaultaccount', 'default', 'wdagutilityaccount',
    'krbtgt', 'wsiaccount', 'wsiuser', 'defaultuser', 'defaultuser0',
    
    # Windows group names
    'users', 'administrators', 'guests', 'power users', 'backup operators',
    'replicator', 'network configuration operators', 'performance monitor users',
    'performance log users', 'distributed com users', 'iis_iusrs',
    'cryptographic operators', 'event log readers', 'certificate service dcom access',
    'rds remote access servers', 'rds endpoint servers', 'rds management servers',
    'hyper-v administrators', 'access control assistance operators',
    'remote management users', 'storage replica administrators',
    'domain admins', 'domain users', 'domain guests', 'domain computers',
    'domain controllers', 'schema admins', 'enterprise admins', 'group policy creator owners',
    'read-only domain controllers', 'cloneable domain controllers', 'protected users',
    'key admins', 'enterprise key admins', 'dnsadmins', 'dnsupdateproxy',
    
    # Health monitoring
    'healthmailbox', 'healthmailboxc3d7722', 'healthmailbox0659e34', 
    'healthmailbox83d6781', 'healthmailbox6ded678', 'healthmailbox7108a4e',
    'healthmailbox4a58f8e', 'healthmailboxdb3a90f', 'healthmailboxfdcd4b9',
    'healthmailboxbe58608', 'healthmailboxf6f5e91', 'healthmailboxfd78d85',
    'healthmailbox968e74d', 'healthmailbox2ab6a02', 'healthmailbox57e9d8a',
    
    # Service accounts
    'udw', 'umfd-0', 'umfd-1', 'umfd-2', 'umfd-3', 'umfd-4', 'umfd-5',
    'dwm-1', 'dwm-2', 'dwm-3', 'dwm-4', 'dwm-5',
    'anonymous logon', 'anonymous', 'nobody',
    
    # Invalid
    '-', '', 'null', 'n/a', 'unknown',
    
    # Microsoft services
    'microsoft.activedirectory', 'azure ad connect', 'aad connect',
    'msol_', 'exchange online', 'o365', 'office365',
}

EXCLUDED_PREFIXES = [
    'msol_',
    'healthmailbox',
    'umfd-',
    'dwm-',
    'system\\',
    'nt authority\\',
    'font driver host\\',
    'window manager\\',
]

EXCLUDED_PATTERNS = [
    r'^.*\$$',
    r'^S-\d+-\d+',
    r'.*_\d+[a-z]{5,}$',  # Pattern like "name_5wofrIv"
    r'^[a-z0-9]{20,}$',
    r'^[A-Z0-9]{8,}-[A-Z0-9]{4,}-',
]

def should_exclude_username(username):
    """Check if username should be excluded"""
    if not username or not isinstance(username, str):
        return True
    
    username_lower = username.lower().strip()
    
    if not username_lower or len(username_lower) < 2:
        return True
    
    # Check exact matches
    if username_lower in EXCLUDED_USERNAMES:
        return True
    
    # Check prefixes
    for prefix in EXCLUDED_PREFIXES:
        if username_lower.startswith(prefix.lower()):
            return True
    
    # Check patterns
    for pattern in EXCLUDED_PATTERNS:
        if re.match(pattern, username, re.IGNORECASE):
            return True
    
    return False


def cleanup_junk_users(dry_run=True):
    """
    Clean up junk users from database
    
    Args:
        dry_run: If True, only show what would be deleted without actually deleting
    """
    with app.app_context():
        # Get all users
        all_users = KnownUser.query.all()
        
        to_delete = []
        
        for user in all_users:
            if should_exclude_username(user.username):
                to_delete.append(user)
        
        print(f"\n{'=' * 80}")
        print(f"Found {len(to_delete)} junk users to delete out of {len(all_users)} total users")
        print(f"{'=' * 80}\n")
        
        if to_delete:
            print("Users to be deleted:\n")
            for user in to_delete:
                display_name = f"{user.domain_name}\\{user.username}" if user.domain_name and user.domain_name != '-' else user.username
                print(f"  - {display_name} (ID: {user.id}, Source: {user.source})")
            
            if dry_run:
                print(f"\n{'=' * 80}")
                print("DRY RUN - No users were deleted")
                print("Run with --execute flag to actually delete these users")
                print(f"{'=' * 80}\n")
            else:
                print(f"\n{'=' * 80}")
                response = input("Are you sure you want to delete these users? (yes/no): ")
                if response.lower() == 'yes':
                    for user in to_delete:
                        db.session.delete(user)
                    db.session.commit()
                    print(f"✓ Deleted {len(to_delete)} junk users")
                    print(f"{'=' * 80}\n")
                else:
                    print("Cancelled - no users were deleted")
        else:
            print("✓ No junk users found - database is clean!\n")


if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='Clean up junk users from Known Users')
    parser.add_argument('--execute', action='store_true', help='Actually delete users (default is dry-run)')
    args = parser.parse_args()
    
    cleanup_junk_users(dry_run=not args.execute)

