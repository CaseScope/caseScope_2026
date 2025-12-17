"""
IOC Extraction Routes
Handles extraction of IOCs from EDR reports using Mistral AI or regex fallback.
Supports iterative processing of multiple reports.
"""

from flask import Blueprint, request, jsonify
from flask_login import login_required, current_user
from models import db, Case, IOC
from logger_config import get_logger
import os
import re

logger = get_logger('app')

ioc_extraction_bp = Blueprint('ioc_extraction', __name__)


# ============================================================================
# IOC Extraction Helpers
# ============================================================================

def extract_username(value):
    """Extract username from domain\\username or domain/username format."""
    if '\\' in value:
        parts = value.split('\\')
        username = parts[-1]
        domain = parts[0] if len(parts) > 1 else None
        return username, domain
    elif '/' in value and not value.startswith('/'):
        parts = value.split('/')
        username = parts[-1]
        domain = parts[0] if len(parts) > 1 else None
        return username, domain
    return value, None


def extract_filename(value):
    """Extract filename without extension from full path."""
    # Get basename
    basename = os.path.basename(value.replace('\\', '/'))
    # Remove extension
    filename_no_ext = os.path.splitext(basename)[0]
    return filename_no_ext if filename_no_ext else basename


def is_command_line(value):
    """Determine if value is a command line (has arguments) vs just a path/filename."""
    # Check for command-line indicators: spaces with args, pipes, redirects, &&, ||
    if any(indicator in value for indicator in [' -', ' /', ' --', '|', '>', '<', '&&', '||']):
        return True
    # Check if it has spaces (but not just a path with spaces)
    if ' ' in value.strip():
        # If it looks like a path (starts with drive letter or /, \), might just be a path with spaces
        if re.match(r'^[A-Za-z]:\\', value) or value.startswith('/') or value.startswith('\\'):
            # Check if there's content after potential path
            parts = value.split()
            if len(parts) > 1 and not all(part.endswith('\\') or part.endswith('/') for part in parts[:-1]):
                return True
        else:
            return True
    return False


def find_existing_ioc_across_types(case_id, value, primary_type, alt_types=None):
    """Find existing IOC by value, checking primary type and alternative types."""
    # Check primary type first
    existing = IOC.query.filter_by(case_id=case_id, ioc_type=primary_type).filter(
        db.func.lower(IOC.ioc_value) == db.func.lower(value)
    ).first()
    if existing:
        return existing
    
    # Check alternative types (for username cross-type matching)
    if alt_types:
        for alt_type in alt_types:
            existing = IOC.query.filter_by(case_id=case_id, ioc_type=alt_type).filter(
                db.func.lower(IOC.ioc_value) == db.func.lower(value)
            ).first()
            if existing:
                return existing
    return None


def update_or_create_ioc(case_id, ioc_type, ioc_value, description, extraction_source, is_active=True, alt_types=None):
    """Update existing IOC or create new one. Returns (action, ioc) where action is 'added', 'updated', or 'skipped'."""
    existing = find_existing_ioc_across_types(case_id, ioc_value, ioc_type, alt_types)
    
    if existing:
        # Check if this description info is new
        if description not in (existing.description or ''):
            existing.description = (existing.description or '') + f"\n{description}"
            # Preserve is_active status (don't re-enable disabled IOCs)
            return ('updated', existing)
        else:
            return ('skipped', existing)
    else:
        new_ioc = IOC(
            case_id=case_id,
            ioc_type=ioc_type,
            ioc_value=ioc_value,
            description=description,
            is_active=is_active,
            created_by=current_user.id
        )
        db.session.add(new_ioc)
        return ('added', new_ioc)


# ============================================================================
# Routes
# ============================================================================

@ioc_extraction_bp.route('/case/<int:case_id>/triage/extract-iocs', methods=['POST'])
@login_required
def extract_iocs(case_id):
    """
    Extract IOCs from a specific EDR report using Mistral AI.
    Supports iterative processing of multiple reports.
    """
    from ai_mistral_extract_iocs import extract_iocs_from_single_report, get_ioc_summary, split_reports
    
    case = db.session.get(Case, case_id)
    if not case:
        return jsonify({'success': False, 'error': 'Case not found'}), 404
    
    if not case.edr_report or not case.edr_report.strip():
        return jsonify({'success': False, 'error': 'No EDR report configured for this case'}), 400
    
    data = request.get_json() or {}
    report_index = data.get('report_index', 0)  # Which report to process (0-based)
    
    try:
        # Split reports
        reports = split_reports(case.edr_report)
        total_reports = len(reports)
        
        # Validate report index
        if report_index < 0 or report_index >= total_reports:
            return jsonify({
                'success': False,
                'error': f'Invalid report index: {report_index} (total reports: {total_reports})'
            }), 400
        
        # Extract from this specific report
        logger.info(f"[MISTRAL_IOC] Extracting from report {report_index + 1}/{total_reports} for case {case_id}")
        result = extract_iocs_from_single_report(reports[report_index])
        
        if not result['success']:
            return jsonify({
                'success': False,
                'error': result.get('error', 'Extraction failed'),
                'report_index': report_index,
                'total_reports': total_reports,
                'extraction_method': 'mistral_ai'
            }), 500
        
        summary = get_ioc_summary(result['iocs'])
        
        logger.info(f"[MISTRAL_IOC] Extracted {summary['total_count']} IOCs from report {report_index + 1}/{total_reports} (case {case_id})")
        
        return jsonify({
            'success': True,
            'iocs': result['iocs'],
            'summary': summary,
            'report_index': report_index,
            'total_reports': total_reports,
            'has_more': (report_index + 1) < total_reports,
            'extraction_method': 'mistral_ai'
        })
    except Exception as e:
        logger.error(f"[MISTRAL_IOC] IOC extraction failed for case {case_id}, report {report_index}: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@ioc_extraction_bp.route('/case/<int:case_id>/triage/add-extracted-iocs', methods=['POST'])
@login_required
def add_extracted_iocs(case_id):
    """
    Add extracted IOCs to the case's IOC database.
    Handles duplicates by appending descriptions.
    Maps IOC types correctly, uses 'other' for unknown types.
    Smart handling of usernames, filenames, and commands.
    """
    case = db.session.get(Case, case_id)
    if not case:
        return jsonify({'success': False, 'error': 'Case not found'}), 404
    
    data = request.get_json()
    if not data or 'iocs' not in data:
        return jsonify({'success': False, 'error': 'No IOCs provided'}), 400
    
    iocs = data['iocs']
    extraction_method = data.get('extraction_method', 'unknown')
    
    added_count = 0
    updated_count = 0
    skipped_count = 0
    
    try:
        # Map Mistral/Regex IOC types to database IOC types
        # Database types: ip, username, user_sid, hostname, fqdn, command, command_complex, 
        #                 filename, malware_name, hash, port, url, registry_key, email, pid, other
        type_mapping = {
            'ip_addresses': 'ip',
            'hostnames': 'hostname',
            'usernames': 'username',
            'file_paths': 'other',  # Mix of paths - categorize as other
            'domains': 'fqdn',
            'urls': 'url',
            'network_shares': 'other',
            'ports': 'port',
            'registry_keys': 'registry_key',
            'email_addresses': 'email',
            'protocols': 'other',
            'timestamps_utc': 'other',
            'ssh_keys': 'other'
        }
        
        extraction_source = f"Extracted from EDR Report ({'Mistral AI' if extraction_method == 'mistral_ai' else 'Regex'})"
        
        # Process simple arrays
        for ioc_type, ioc_type_db in type_mapping.items():
            values = iocs.get(ioc_type, [])
            if isinstance(values, list):
                for value in values:
                    if not value or (isinstance(value, str) and not value.strip()):
                        skipped_count += 1
                        continue
                    
                    value_str = str(value).strip()
                    
                    # Special handling for usernames
                    if ioc_type == 'usernames':
                        clean_username, domain = extract_username(value_str)
                        desc_parts = [extraction_source]
                        if domain:
                            desc_parts.append(f"Domain: {domain}")
                        if value_str != clean_username:
                            desc_parts.append(f"Full: {value_str}")
                        description = '\n'.join(desc_parts)
                        
                        action, ioc = update_or_create_ioc(
                            case_id, 'username', clean_username[:500], description,
                            extraction_source, alt_types=['user_sid']
                        )
                    else:
                        # Standard processing for other types
                        action, ioc = update_or_create_ioc(
                            case_id, ioc_type_db, value_str[:500], extraction_source,
                            extraction_source
                        )
                    
                    if action == 'added':
                        added_count += 1
                    elif action == 'updated':
                        updated_count += 1
                    else:
                        skipped_count += 1
        
        # Process nested structures: file_hashes
        file_hashes = iocs.get('file_hashes', {})
        if isinstance(file_hashes, dict):
            for hash_type, hash_values in file_hashes.items():
                if isinstance(hash_values, list):
                    for hash_value in hash_values:
                        if not hash_value or not hash_value.strip():
                            skipped_count += 1
                            continue
                        
                        hash_str = hash_value.strip()[:500].lower()  # Normalize to lowercase
                        hash_desc = f"{extraction_source} ({hash_type.upper()} hash)"
                        
                        action, ioc = update_or_create_ioc(
                            case_id, 'hash', hash_str, hash_desc, extraction_source
                        )
                        
                        if action == 'added':
                            added_count += 1
                        elif action == 'updated':
                            updated_count += 1
                        else:
                            skipped_count += 1
        
        # Process nested structures: credentials (usernames and passwords)
        credentials = iocs.get('credentials', {})
        if isinstance(credentials, dict):
            cred_usernames = credentials.get('usernames', [])
            if isinstance(cred_usernames, list):
                for username in cred_usernames:
                    if not username or not username.strip():
                        skipped_count += 1
                        continue
                    
                    # Extract username from domain\username format
                    clean_username, domain = extract_username(username.strip())
                    
                    # Build description with domain info if present
                    desc_parts = [f"{extraction_source} (Credential - Username)"]
                    if domain:
                        desc_parts.append(f"Domain: {domain}")
                    if username != clean_username:
                        desc_parts.append(f"Full: {username}")
                    cred_desc = '\n'.join(desc_parts)
                    
                    # Check for duplicates across username and user_sid types
                    action, ioc = update_or_create_ioc(
                        case_id, 'username', clean_username[:500], cred_desc, 
                        extraction_source, alt_types=['user_sid']
                    )
                    
                    if action == 'added':
                        added_count += 1
                    elif action == 'updated':
                        updated_count += 1
                    else:
                        skipped_count += 1
            
            # Handle passwords as 'other' type (sensitive data)
            cred_passwords = credentials.get('passwords', [])
            if isinstance(cred_passwords, list):
                for password in cred_passwords:
                    if not password or not password.strip():
                        skipped_count += 1
                        continue
                    
                    pwd_desc = f"{extraction_source} (Credential - Password)"
                    
                    action, ioc = update_or_create_ioc(
                        case_id, 'other', password.strip()[:500], pwd_desc, extraction_source
                    )
                    
                    if action == 'added':
                        added_count += 1
                    elif action == 'updated':
                        updated_count += 1
                    else:
                        skipped_count += 1
        
        # Process nested structures: processes (executables and commands)
        processes = iocs.get('processes', {})
        if isinstance(processes, dict):
            executables = processes.get('executables', [])
            if isinstance(executables, list):
                for executable in executables:
                    if not executable or not executable.strip():
                        skipped_count += 1
                        continue
                    
                    exe_str = executable.strip()
                    
                    # Determine if it's a command line or just a filename/path
                    if is_command_line(exe_str):
                        # It's a full command line
                        ioc_type = 'command_complex' if len(exe_str) > 100 else 'command'
                        ioc_value = exe_str[:500]
                        description = f"{extraction_source} (Command Line)"
                    else:
                        # It's just a filename or path
                        filename_clean = extract_filename(exe_str)
                        ioc_type = 'filename'
                        ioc_value = filename_clean[:500]
                        desc_parts = [f"{extraction_source} (Executable/File)"]
                        if exe_str != filename_clean:
                            desc_parts.append(f"Full path: {exe_str}")
                        description = '\n'.join(desc_parts)
                    
                    action, ioc = update_or_create_ioc(
                        case_id, ioc_type, ioc_value, description, extraction_source
                    )
                    
                    if action == 'added':
                        added_count += 1
                    elif action == 'updated':
                        updated_count += 1
                    else:
                        skipped_count += 1
            
            commands = processes.get('commands', [])
            if isinstance(commands, list):
                for command in commands:
                    if not command or not command.strip():
                        skipped_count += 1
                        continue
                    
                    cmd_str = command.strip()
                    
                    # Determine if it's a command line or just a filename/path
                    if is_command_line(cmd_str):
                        # It's a full command line
                        ioc_type = 'command_complex' if len(cmd_str) > 100 else 'command'
                        ioc_value = cmd_str[:500]
                        description = f"{extraction_source} (Command Line)"
                    else:
                        # It's just a filename or path
                        filename_clean = extract_filename(cmd_str)
                        ioc_type = 'filename'
                        ioc_value = filename_clean[:500]
                        desc_parts = [f"{extraction_source} (Filename from command)"]
                        if cmd_str != filename_clean:
                            desc_parts.append(f"Original: {cmd_str}")
                        description = '\n'.join(desc_parts)
                    
                    action, ioc = update_or_create_ioc(
                        case_id, ioc_type, ioc_value, description, extraction_source
                    )
                    
                    if action == 'added':
                        added_count += 1
                    elif action == 'updated':
                        updated_count += 1
                    else:
                        skipped_count += 1
        
        db.session.commit()
        logger.info(f"[TRIAGE_IOC] Case {case_id}: Added {added_count}, Updated {updated_count}, Skipped {skipped_count} IOCs ({extraction_method})")
        
        return jsonify({
            'success': True,
            'added_count': added_count,
            'updated_count': updated_count,
            'skipped_count': skipped_count,
            'extraction_method': extraction_method,
            'message': f'Added {added_count} new IOCs, updated {updated_count} existing IOCs, skipped {skipped_count} duplicates'
        })
    except Exception as e:
        db.session.rollback()
        logger.error(f"[TRIAGE_IOC] Failed to add IOCs to case {case_id}: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

