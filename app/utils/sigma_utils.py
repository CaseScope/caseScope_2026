"""
Utility functions for SIGMA rule management
Handles parsing SIGMA rule files and syncing to database
"""

import os
import yaml
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any

logger = logging.getLogger(__name__)

SIGMA_BASE_DIR = '/opt/casescope/rules/sigma'
SIGMA_RULES_FOLDERS = [
    'rules',
    'rules-emerging-threats',
    'rules-threat-hunting',
    'rules-compliance',
    'rules-dfir'
]


def parse_sigma_rule_file(file_path: str) -> Dict[str, Any]:
    """
    Parse a SIGMA rule YAML file and extract metadata
    
    Args:
        file_path: Full path to the SIGMA rule file
    
    Returns:
        dict: Rule metadata or None if parsing fails
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            rule_data = yaml.safe_load(f)
        
        if not isinstance(rule_data, dict):
            logger.warning(f"Invalid SIGMA rule format: {file_path}")
            return None
        
        # Extract MITRE tags
        tags = rule_data.get('tags', [])
        if isinstance(tags, list):
            mitre_tags = ','.join([t for t in tags if isinstance(t, str) and t.startswith('attack.')])
        else:
            mitre_tags = ''
        
        # Extract logsource
        logsource = rule_data.get('logsource', {})
        
        return {
            'rule_id': rule_data.get('id', ''),
            'rule_title': rule_data.get('title', ''),
            'rule_level': (rule_data.get('level', 'medium') or 'medium').lower(),
            'rule_status': rule_data.get('status', ''),
            'logsource': logsource,
            'mitre_tags': mitre_tags
        }
    
    except yaml.YAMLError as e:
        logger.error(f"YAML parsing error in {file_path}: {e}")
        return None
    except Exception as e:
        logger.error(f"Error parsing SIGMA rule {file_path}: {e}")
        return None


def scan_sigma_rules_directory(folder_name: str) -> List[Dict[str, Any]]:
    """
    Scan a SIGMA rules folder and extract all rule metadata
    
    Args:
        folder_name: Name of the folder (e.g., 'rules', 'rules-emerging-threats')
    
    Returns:
        list: List of rule metadata dicts
    """
    rules_list = []
    folder_path = os.path.join(SIGMA_BASE_DIR, folder_name)
    
    if not os.path.exists(folder_path):
        logger.warning(f"SIGMA folder not found: {folder_path}")
        return rules_list
    
    logger.info(f"Scanning SIGMA folder: {folder_path}")
    
    # Walk through directory
    for root, dirs, files in os.walk(folder_path):
        # Skip certain directories
        skip_dirs = ['tests', 'deprecated', 'images', 'documentation', 'other', 'regression_data']
        dirs[:] = [d for d in dirs if d not in skip_dirs]
        
        for file in files:
            if not file.endswith('.yml') and not file.endswith('.yaml'):
                continue
            
            full_path = os.path.join(root, file)
            relative_path = os.path.relpath(full_path, folder_path)
            
            # Parse rule
            rule_metadata = parse_sigma_rule_file(full_path)
            
            if rule_metadata:
                # Determine category from path
                category = os.path.dirname(relative_path).replace(os.sep, '/')
                
                rules_list.append({
                    'file_path': full_path,
                    'rule_path': relative_path,
                    'source_folder': folder_name,
                    'rule_category': category,
                    **rule_metadata
                })
    
    logger.info(f"Found {len(rules_list)} rules in {folder_name}")
    return rules_list


def sync_sigma_rules_to_database(db) -> Dict[str, int]:
    """
    Scan all SIGMA rule folders and sync to database
    Preserves existing enabled/disabled states
    
    Args:
        db: SQLAlchemy database session
    
    Returns:
        dict: Statistics (added, updated, skipped)
    """
    from models import SigmaRule
    
    added = 0
    updated = 0
    skipped = 0
    
    for folder_name in SIGMA_RULES_FOLDERS:
        logger.info(f"Processing folder: {folder_name}")
        
        rules_list = scan_sigma_rules_directory(folder_name)
        
        for rule_data in rules_list:
            try:
                # Check if rule already exists
                existing_rule = SigmaRule.query.filter_by(rule_path=rule_data['rule_path']).first()
                
                if existing_rule:
                    # Update existing rule (preserve is_enabled status)
                    existing_rule.rule_id = rule_data['rule_id']
                    existing_rule.rule_title = rule_data['rule_title']
                    existing_rule.rule_level = rule_data['rule_level']
                    existing_rule.rule_status = rule_data['rule_status']
                    existing_rule.rule_category = rule_data['rule_category']
                    existing_rule.logsource = rule_data['logsource']
                    existing_rule.mitre_tags = rule_data['mitre_tags']
                    existing_rule.source_folder = rule_data['source_folder']
                    existing_rule.last_synced = datetime.utcnow()
                    # Do NOT update is_enabled - preserve user's choice
                    
                    updated += 1
                else:
                    # Create new rule (enabled by default)
                    new_rule = SigmaRule(
                        rule_path=rule_data['rule_path'],
                        rule_id=rule_data['rule_id'],
                        rule_title=rule_data['rule_title'],
                        rule_level=rule_data['rule_level'],
                        rule_status=rule_data['rule_status'],
                        rule_category=rule_data['rule_category'],
                        logsource=rule_data['logsource'],
                        mitre_tags=rule_data['mitre_tags'],
                        source_folder=rule_data['source_folder'],
                        is_enabled=True,
                        last_synced=datetime.utcnow()
                    )
                    db.session.add(new_rule)
                    added += 1
                
                # Commit in batches
                if (added + updated) % 100 == 0:
                    db.session.commit()
            
            except Exception as e:
                logger.error(f"Error syncing rule {rule_data['rule_path']}: {e}")
                skipped += 1
                continue
    
    # Final commit
    db.session.commit()
    
    logger.info(f"Sync complete: {added} added, {updated} updated, {skipped} skipped")
    
    return {
        'added': added,
        'updated': updated,
        'skipped': skipped
    }


def update_sigma_rules_from_github() -> Dict[str, Any]:
    """
    Clone or update SIGMA rules from GitHub
    
    Returns:
        dict: Result with success status and message
    """
    import subprocess
    
    try:
        # Check if rules directory exists and is a git repo
        sigma_rules_dir = os.path.join(SIGMA_BASE_DIR)
        git_dir = os.path.join(sigma_rules_dir, '.git')
        
        if os.path.exists(git_dir):
            # Pull latest changes
            logger.info("Pulling latest SIGMA rules from GitHub")
            
            result = subprocess.run(
                ['git', 'pull'],
                cwd=sigma_rules_dir,
                capture_output=True,
                text=True,
                timeout=300
            )
            
            if result.returncode != 0:
                logger.error(f"Git pull failed: {result.stderr}")
                return {
                    'success': False,
                    'message': f'Git pull failed: {result.stderr}'
                }
            
            logger.info("Git pull completed successfully")
            return {
                'success': True,
                'message': 'Rules updated from GitHub successfully'
            }
        else:
            # Clone repository
            logger.info("Cloning SIGMA rules repository from GitHub")
            
            # Remove existing directory if it exists but is not a git repo
            if os.path.exists(sigma_rules_dir):
                logger.warning(f"Removing non-git directory: {sigma_rules_dir}")
                import shutil
                shutil.rmtree(sigma_rules_dir)
            
            # Clone
            result = subprocess.run(
                ['git', 'clone', 'https://github.com/SigmaHQ/sigma.git', sigma_rules_dir],
                capture_output=True,
                text=True,
                timeout=600
            )
            
            if result.returncode != 0:
                logger.error(f"Git clone failed: {result.stderr}")
                return {
                    'success': False,
                    'message': f'Git clone failed: {result.stderr}'
                }
            
            logger.info("Git clone completed successfully")
            return {
                'success': True,
                'message': 'Rules cloned from GitHub successfully'
            }
    
    except subprocess.TimeoutExpired:
        logger.error("Git operation timed out")
        return {
            'success': False,
            'message': 'Git operation timed out'
        }
    except Exception as e:
        logger.error(f"Error updating SIGMA rules: {e}")
        return {
            'success': False,
            'message': str(e)
        }


def get_enabled_sigma_rules() -> List[str]:
    """
    Get list of enabled SIGMA rule file paths for Chainsaw
    
    Returns:
        list: Full paths to enabled SIGMA rule files
    """
    from models import SigmaRule
    
    enabled_rules = SigmaRule.query.filter_by(is_enabled=True).all()
    
    rule_paths = []
    for rule in enabled_rules:
        full_path = os.path.join(SIGMA_BASE_DIR, rule.source_folder, rule.rule_path)
        if os.path.exists(full_path):
            rule_paths.append(full_path)
    
    return rule_paths

