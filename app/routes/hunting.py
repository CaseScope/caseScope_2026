"""
Hunting Routes
Automated threat hunting functionality
"""

from flask import Blueprint, render_template, session, jsonify, request
from flask_login import login_required, current_user
from models import Case, IOC
from main import db
from audit_logger import log_action
import logging
import json
import ollama
from utils.ioc_extractor import extract_iocs as regex_extract_iocs

logger = logging.getLogger(__name__)

hunting_bp = Blueprint('hunting', __name__, url_prefix='/hunting')


@hunting_bp.route('/')
@hunting_bp.route('/dashboard')
@login_required
def dashboard():
    """
    Hunting dashboard - automated threat hunting tools
    """
    # Get selected case from session
    case_id = session.get('selected_case_id')
    case = None
    
    if case_id:
        case = Case.query.get(case_id)
        
        # Check permissions for read-only users
        if current_user.role == 'read-only':
            if not case or case.id != current_user.case_assigned:
                case = None
    
    return render_template('hunting/dashboard.html', case=case)


@hunting_bp.route('/api/check_edr')
@login_required
def api_check_edr():
    """
    Check if current case has EDR reports
    """
    try:
        case_id = session.get('selected_case_id')
        if not case_id:
            return jsonify({'success': False, 'error': 'No case selected'}), 400
        
        case = Case.query.get(case_id)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404
        
        has_edr = bool(case.edr_reports and case.edr_reports.strip())
        
        if has_edr:
            # Count reports
            reports = case.edr_reports.split('*** NEW REPORT ***')
            report_count = len([r for r in reports if r.strip()])
        else:
            report_count = 0
        
        return jsonify({
            'success': True,
            'has_edr': has_edr,
            'report_count': report_count
        })
        
    except Exception as e:
        logger.error(f"Error checking EDR: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@hunting_bp.route('/api/extract_edr_iocs', methods=['POST'])
@login_required
def api_extract_edr_iocs():
    """
    Extract IOCs from a specific EDR report using AI
    """
    try:
        case_id = session.get('selected_case_id')
        if not case_id:
            return jsonify({'success': False, 'error': 'No case selected'}), 400
        
        case = Case.query.get(case_id)
        if not case or not case.edr_reports:
            return jsonify({'success': False, 'error': 'No EDR reports found'}), 404
        
        data = request.get_json()
        report_index = data.get('report_index', 0)
        
        # Split reports
        reports = [r.strip() for r in case.edr_reports.split('*** NEW REPORT ***') if r.strip()]
        
        if report_index >= len(reports):
            return jsonify({'success': False, 'error': 'Report index out of range'}), 400
        
        report_text = reports[report_index]
        
        # Load IOC extraction prompt
        import os
        prompt_path = os.path.join(os.path.dirname(__file__), '../ai/ai_prompts/ioc_extraction.md')
        with open(prompt_path, 'r') as f:
            example_output = f.read()
        
        # Create the extraction prompt
        prompt = f"""You are a DFIR analyst extracting IOCs from incident reports.

EXAMPLE OUTPUT FORMAT (use this exact JSON structure):
{example_output}

IMPORTANT RULES:
1. Return ONLY valid JSON matching the structure above
2. Extract ALL relevant IOCs from the report
3. Categorize IOCs correctly (network, file, host, identity, threat_intel)
4. Include MITRE ATT&CK techniques if identifiable
5. Create a timeline of key events if timestamps are present
6. Add extraction notes about the incident nature
7. For command_lines, capture full commands with parameters
8. For file_paths, include full paths
9. For usernames, include both with and without domain if present

NOW EXTRACT IOCS FROM THIS EDR REPORT:

{report_text}

Return ONLY the JSON object. No explanations, no markdown, just the JSON."""

        # Query AI model with fallback to regex extraction
        from config import LLM_MODEL_CHAT
        extraction = None
        used_fallback = False
        
        try:
            response = ollama.chat(
                model=LLM_MODEL_CHAT,
                messages=[{"role": "user", "content": prompt}],
                format="json",
                options={"temperature": 0}
            )
            
            extraction = json.loads(response['message']['content'])
            logger.info("Successfully extracted IOCs using AI")
            
        except Exception as ai_error:
            logger.warning(f"AI extraction failed: {ai_error}. Falling back to regex extraction.")
            used_fallback = True
            
            # Use regex fallback
            extraction = regex_extract_iocs(report_text)
            
            # Modify extraction summary to indicate fallback was used
            if 'extraction_summary' in extraction:
                extraction['extraction_summary']['extraction_method'] = 'regex_fallback'
                extraction['extraction_summary']['extraction_notes'] = f"AI unavailable - used regex extraction. Original error: {str(ai_error)}"
        
        if not extraction:
            return jsonify({'success': False, 'error': 'Failed to extract IOCs'}), 500
        
        # Process extracted IOCs and check for duplicates
        iocs_to_import = []
        processed_values = {}  # Track values in current batch: {value_lower: {'type': type, 'index': index}}
        
        # Process each category
        categories_map = {
            'network': [
                ('ip_v4', 'ipv4', 'network'),
                ('ip_v6', 'ipv6', 'network'),
                ('domains', 'domain', 'network'),
                ('urls', 'url', 'network'),
                ('emails', 'email_address', 'network')
            ],
            'file': [
                ('md5', 'md5', 'file'),
                ('sha1', 'sha1', 'file'),
                ('sha256', 'sha256', 'file'),
                ('file_names', 'filename', 'file'),
                ('file_paths', 'filepath', 'file')
            ],
            'host': [
                ('hostnames', 'hostname', 'host'),
                ('command_lines', 'command_line', 'host'),
                ('process_names', 'process_name', 'host'),
                ('registry_keys', 'registry_key', 'host'),
                ('service_names', 'service_name', 'host')
            ],
            'identity': [
                ('usernames', 'username', 'identity'),
                ('sids', 'sid', 'identity')
            ]
        }
        
        for category, mappings in categories_map.items():
            if category not in extraction:
                continue
            
            for field_name, ioc_type, ioc_category in mappings:
                values = extraction[category].get(field_name, [])
                if not isinstance(values, list):
                    continue
                
                for value in values:
                    if not value or not str(value).strip():
                        continue
                    
                    value = str(value).strip()
                    value_lower = value.lower()
                    
                    # Check for duplicates in current batch first
                    batch_duplicate = False
                    
                    # For usernames, check if domain version or base version already in batch
                    if ioc_type == 'username':
                        if '\\' in value:
                            # This is domain\user, check if base user is in batch
                            base_user = value.split('\\')[1].lower()
                            if base_user in processed_values and processed_values[base_user]['type'] == 'username':
                                # Base user already in batch, add domain version to its notes
                                idx = processed_values[base_user]['index']
                                if 'analyst_notes' in iocs_to_import[idx]:
                                    iocs_to_import[idx]['analyst_notes'] += f"\nAlso seen as: {value}"
                                else:
                                    iocs_to_import[idx]['analyst_notes'] = f"Also seen as: {value}"
                                batch_duplicate = True
                        else:
                            # This is base user, check if domain version already in batch
                            for key, info in processed_values.items():
                                if info['type'] == 'username' and '\\' in key and key.split('\\')[1].lower() == value_lower:
                                    # Domain version already in batch, add base to its notes
                                    idx = info['index']
                                    if 'analyst_notes' in iocs_to_import[idx]:
                                        iocs_to_import[idx]['analyst_notes'] += f"\nAlso seen as: {value}"
                                    else:
                                        iocs_to_import[idx]['analyst_notes'] = f"Also seen as: {value}"
                                    batch_duplicate = True
                                    break
                    
                    # Check for same value with different type in batch
                    if value_lower in processed_values and not batch_duplicate:
                        existing_type = processed_values[value_lower]['type']
                        type_preference = {
                            'filepath': 5, 'command_line': 4, 'process_name': 3, 'filename': 2, 'username': 1
                        }
                        current_priority = type_preference.get(ioc_type, 0)
                        existing_priority = type_preference.get(existing_type, 0)
                        
                        if existing_priority > current_priority:
                            # Skip this one, existing is more specific
                            batch_duplicate = True
                        elif current_priority > existing_priority:
                            # Upgrade existing to this more specific type
                            idx = processed_values[value_lower]['index']
                            iocs_to_import[idx]['type'] = ioc_type
                            iocs_to_import[idx]['category'] = ioc_category
                            if 'analyst_notes' in iocs_to_import[idx]:
                                iocs_to_import[idx]['analyst_notes'] += f"\nUpgraded from {existing_type} to {ioc_type}"
                            else:
                                iocs_to_import[idx]['analyst_notes'] = f"Upgraded from {existing_type} to {ioc_type}"
                            processed_values[value_lower]['type'] = ioc_type
                            batch_duplicate = True
                        else:
                            # Same priority, skip duplicate
                            batch_duplicate = True
                    
                    if batch_duplicate:
                        # Still add to list but mark as duplicate
                        iocs_to_import.append({
                            'type': ioc_type,
                            'value': value,
                            'category': ioc_category,
                            'threat_level': 'medium',
                            'confidence': 100,
                            'description': f'Extracted from EDR report',
                            'analyst_notes': f'Duplicate in current batch',
                            'source': 'ai_extraction',
                            'is_duplicate': True
                        })
                        continue
                    
                    # Check for duplicates and overlaps in database
                    merge_result = _check_and_merge_ioc(case_id, value, ioc_type)
                    
                    if merge_result['action'] == 'skip':
                        # Exact duplicate - show to user but mark as duplicate
                        iocs_to_import.append({
                            'type': ioc_type,
                            'value': value,
                            'category': ioc_category,
                            'threat_level': 'medium',
                            'confidence': 100,
                            'description': f'Extracted from EDR report',
                            'analyst_notes': f'Already exists in database',
                            'source': 'ai_extraction',
                            'merge_action': '📋 Duplicate - already exists',
                            'existing_ioc_id': merge_result.get('existing_ioc_id'),
                            'is_duplicate': True
                        })
                    elif merge_result['action'] == 'merge':
                        # Add to existing IOC's analyst notes
                        iocs_to_import.append({
                            'type': ioc_type,
                            'value': merge_result['value'],
                            'category': ioc_category,
                            'threat_level': 'medium',
                            'confidence': 100,
                            'description': f'Extracted from EDR report',
                            'analyst_notes': merge_result['merge_note'],
                            'source': 'ai_extraction',
                            'merge_action': merge_result['message'],
                            'existing_ioc_id': merge_result.get('existing_ioc_id'),
                            'upgrade': merge_result.get('upgrade', False)
                        })
                    else:
                        # New IOC
                        iocs_to_import.append({
                            'type': ioc_type,
                            'value': value,
                            'category': ioc_category,
                            'threat_level': 'medium',
                            'confidence': 100,
                            'description': f'Extracted from EDR report',
                            'source': 'ai_extraction'
                        })
                        # Track this value in the current batch
                        processed_values[value_lower] = {
                            'type': ioc_type,
                            'index': len(iocs_to_import) - 1
                        }
        
        return jsonify({
            'success': True,
            'extraction_summary': extraction.get('extraction_summary', {}),
            'iocs_to_import': iocs_to_import,
            'full_extraction': extraction
        })
        
    except Exception as e:
        logger.error(f"Error extracting EDR IOCs: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500


def _check_and_merge_ioc(case_id, value, ioc_type):
    """
    Check if IOC exists and determine merge action
    Returns: dict with action ('skip', 'merge', 'create'), value, and merge_note
    """
    value_lower = value.lower()
    
    # Check for exact match with same type
    existing = IOC.query.filter(
        IOC.case_id == case_id,
        db.func.lower(IOC.value) == value_lower,
        IOC.type == ioc_type
    ).first()
    
    if existing:
        return {'action': 'skip', 'value': value}
    
    # Check for same value with different types (e.g., filename vs process_name)
    # Prefer more specific types
    type_preference = {
        'filepath': 5,      # Most specific
        'command_line': 4,
        'process_name': 3,
        'filename': 2,      # Least specific
        'username': 1       # Special handling
    }
    
    similar_iocs = IOC.query.filter(
        IOC.case_id == case_id,
        db.func.lower(IOC.value) == value_lower
    ).all()
    
    if similar_iocs:
        # Found same value with different type
        for similar in similar_iocs:
            current_priority = type_preference.get(ioc_type, 0)
            existing_priority = type_preference.get(similar.type, 0)
            
            # If existing IOC is more specific, skip this one
            if existing_priority > current_priority:
                return {
                    'action': 'skip',
                    'value': value,
                    'reason': f'More specific IOC already exists as {similar.type}'
                }
            # If this one is more specific, note to add type info to existing
            elif current_priority > existing_priority:
                return {
                    'action': 'merge',
                    'value': value,
                    'merge_note': f'Also seen as {similar.type}: {similar.value}',
                    'message': f'Upgrading from {similar.type} to {ioc_type}',
                    'existing_ioc_id': similar.id,
                    'upgrade': True
                }
    
    # Check for overlaps (e.g., username vs domain\username)
    if ioc_type == 'username' and '\\' in value:
        # Check if base username exists
        base_username = value.split('\\')[1] if '\\' in value else value
        base_existing = IOC.query.filter(
            IOC.case_id == case_id,
            IOC.type == 'username',
            db.func.lower(IOC.value) == base_username.lower()
        ).first()
        
        if base_existing:
            # Base username exists, add domain version to its notes
            return {
                'action': 'merge',
                'value': base_existing.value,
                'merge_note': f'Also seen as: {value}',
                'message': f'Merging into existing IOC "{base_existing.value}"',
                'existing_ioc_id': base_existing.id
            }
    
    if ioc_type == 'username' and '\\' not in value:
        # Check if domain\username version exists
        domain_versions = IOC.query.filter(
            IOC.case_id == case_id,
            IOC.type == 'username',
            db.func.lower(IOC.value).like(f'%\\{value_lower}')
        ).first()
        
        if domain_versions:
            # Domain version exists, use this as primary and add domain to notes
            return {
                'action': 'merge',
                'value': value,
                'merge_note': f'Also seen as: {domain_versions.value}',
                'message': f'Using "{value}" as primary, noting domain variant',
                'existing_ioc_id': domain_versions.id
            }
    
    # No duplicates or overlaps
    return {'action': 'create', 'value': value}


@hunting_bp.route('/api/save_extracted_iocs', methods=['POST'])
@login_required
def api_save_extracted_iocs():
    """
    Save extracted IOCs to the database
    """
    try:
        if current_user.role == 'read-only':
            return jsonify({'success': False, 'error': 'Insufficient permissions'}), 403
        
        case_id = session.get('selected_case_id')
        if not case_id:
            return jsonify({'success': False, 'error': 'No case selected'}), 400
        
        case = Case.query.get(case_id)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404
        
        data = request.get_json()
        iocs_data = data.get('iocs', [])
        
        created_count = 0
        updated_count = 0
        
        for ioc_data in iocs_data:
            if 'existing_ioc_id' in ioc_data:
                # Update existing IOC
                existing_ioc = IOC.query.get(ioc_data['existing_ioc_id'])
                if existing_ioc:
                    # Check if this is an upgrade (more specific type)
                    if ioc_data.get('upgrade'):
                        # Upgrade the type to the more specific one
                        old_type = existing_ioc.type
                        existing_ioc.type = ioc_data['type']
                        if existing_ioc.analyst_notes:
                            existing_ioc.analyst_notes += f"\nUpgraded from {old_type} to {ioc_data['type']}"
                        else:
                            existing_ioc.analyst_notes = f"Upgraded from {old_type} to {ioc_data['type']}"
                    else:
                        # Just append to analyst notes
                        if existing_ioc.analyst_notes:
                            existing_ioc.analyst_notes += f"\n{ioc_data.get('analyst_notes', '')}"
                        else:
                            existing_ioc.analyst_notes = ioc_data.get('analyst_notes', '')
                    
                    existing_ioc.updated_by = current_user.id
                    updated_count += 1
            else:
                # Create new IOC
                ioc = IOC(
                    type=ioc_data['type'],
                    value=ioc_data['value'],
                    category=ioc_data['category'],
                    threat_level=ioc_data.get('threat_level', 'medium'),
                    confidence=ioc_data.get('confidence', 100),
                    description=ioc_data.get('description'),
                    analyst_notes=ioc_data.get('analyst_notes'),
                    source=ioc_data.get('source', 'ai_extraction'),
                    case_id=case_id,
                    created_by=current_user.id,
                    updated_by=current_user.id,
                    last_seen=None  # Don't set last_seen for extracted IOCs
                )
                db.session.add(ioc)
                created_count += 1
        
        db.session.commit()
        
        # Build detailed IOC list for audit log
        saved_ioc_details = []
        for ioc_data in iocs_data:
            saved_ioc_details.append({
                'type': ioc_data['type'],
                'value': ioc_data['value'],
                'category': ioc_data['category'],
                'threat_level': ioc_data['threat_level'],
                'action': 'updated' if ioc_data.get('existing_ioc_id') else 'created'
            })
        
        # Log action with detailed information
        log_action(
            action='iocs_extracted_from_edr',
            resource_type='case',
            resource_id=case.id,
            resource_name=case.name,
            details=f'Extracted and saved {created_count} new IOCs, updated {updated_count} existing IOCs from EDR reports. IOCs: {saved_ioc_details}'
        )
        
        return jsonify({
            'success': True,
            'created_count': created_count,
            'updated_count': updated_count
        })
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error saving extracted IOCs: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500
