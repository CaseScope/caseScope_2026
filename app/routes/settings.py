"""System Settings Routes"""
from flask import Blueprint, render_template, request, redirect, url_for, flash, Response, stream_with_context, jsonify
from flask_login import login_required, current_user
from functools import wraps
from main import db, opensearch_client
from models import SystemSettings

settings_bp = Blueprint('settings', __name__, url_prefix='/settings')


def admin_required(f):
    """Decorator to require administrator role"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'administrator':
            flash('⛔ Administrator access required', 'error')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function


def get_setting(key, default=None):
    """Get a system setting value"""
    setting = db.session.query(SystemSettings).filter_by(setting_key=key).first()
    return setting.setting_value if setting else default


def set_setting(key, value, description=None):
    """Set a system setting value"""
    setting = db.session.query(SystemSettings).filter_by(setting_key=key).first()
    if setting:
        setting.setting_value = value
        if description:
            setting.description = description
    else:
        setting = SystemSettings(
            setting_key=key,
            setting_value=value,
            description=description
        )
        db.session.add(setting)
    db.session.commit()


@settings_bp.route('/')
@login_required
@admin_required
def index():
    """System settings page"""
    # Get AI system status (GPU + Ollama + Models)
    ai_system_status = {}
    try:
        from ai_gpu_detection import get_gpu_info
        from ai_ollama_detection import get_ai_system_status
        
        gpu_info = get_gpu_info()
        ai_system_status = get_ai_system_status()
        ai_system_status['gpu'] = gpu_info
    except Exception as e:
        import logging
        import traceback
        logger = logging.getLogger(__name__)
        logger.error(f"[Settings] Error loading AI system status: {e}")
        logger.error(f"[Settings] Traceback: {traceback.format_exc()}")
        ai_system_status = {
            'gpu': {'gpu_detected': False, 'gpu_model': 'Error', 'gpu_vram_gb': 0},
            'ollama': {'installed': False, 'running': False, 'version': 'Error'},
            'models': {},
            'model_summary': 'Error loading status',
            'ready': False
        }
    
    # Get DFIR-IRIS settings
    dfir_iris_enabled = get_setting('dfir_iris_enabled', 'false') == 'true'
    dfir_iris_url = get_setting('dfir_iris_url', '')
    dfir_iris_api_key = get_setting('dfir_iris_api_key', '')
    
    # Get OpenCTI settings
    opencti_enabled = get_setting('opencti_enabled', 'false') == 'true'
    opencti_url = get_setting('opencti_url', '')
    opencti_api_key = get_setting('opencti_api_key', '')
    
    # Get Logging settings
    log_level = get_setting('log_level', 'INFO')
    
    # Get AI settings
    ai_enabled = get_setting('ai_enabled', 'false') == 'true'
    ai_model_name = get_setting('ai_model_name', 'dfir-llama:latest')
    ai_hardware_mode = get_setting('ai_hardware_mode', 'cpu')  # cpu or gpu
    ai_gpu_vram = get_setting('ai_gpu_vram', '8')  # VRAM in GB
    
    # Get Archive settings (v1.18.0)
    archive_root_path = get_setting('archive_root_path', '')
    
    # Check AI system status and load models from database
    ai_status = {'installed': False, 'running': False, 'model_available': False, 'models': []}
    all_models = []
    try:
        from ai_report import check_ollama_status, calculate_cpu_offload_percent, parse_model_size
        from models import AIModel
        
        ai_status = check_ollama_status()
        
        # Get list of installed model names from Ollama
        installed_model_names = [m['name'] for m in ai_status.get('models', [])]
        
        # Get user's VRAM for CPU offload calculation
        user_vram_gb = float(ai_gpu_vram)
        
        # Query all models from database
        db_models = AIModel.query.all()
        
        for model in db_models:
            is_installed = model.model_name in installed_model_names
            
            # Update installed status in database if changed
            if model.installed != is_installed:
                model.installed = is_installed
            
            # Calculate CPU offload percentage
            model_size_gb = parse_model_size(model.size)
            cpu_offload = calculate_cpu_offload_percent(model_size_gb, user_vram_gb)
            
            all_models.append({
                'name': model.model_name,
                'display_name': model.display_name,
                'speed': model.speed,
                'quality': model.quality,
                'size': model.size,
                'description': model.description,
                'speed_estimate': model.speed_estimate,
                'time_estimate': model.time_estimate,
                'recommended': model.recommended,
                'trainable': model.trainable,
                'trained': model.trained,
                'trained_date': model.trained_date,
                'training_examples': model.training_examples,
                'installed': is_installed,
                'cpu_offload': cpu_offload
            })
        
        # Commit any installed status updates
        db.session.commit()
        
        # Sort: by CPU offload (0% first), then installed status, then recommended
        all_models.sort(key=lambda x: (x['cpu_offload'], not x['installed'], not x['recommended']))
        
    except Exception as e:
        import logging
        logging.getLogger(__name__).error(f"Error loading AI models: {e}")
    
    # Detect hardware for AI settings
    hardware_info = {'gpu': {'gpu_detected': False}, 'cpu': {'cpu_count': 0}}
    try:
        import logging
        logger = logging.getLogger(__name__)
        logger.info("[Settings] Starting hardware detection...")
        from hardware_utils import get_hardware_status
        hardware_info = get_hardware_status()
        logger.info(f"[Settings] Hardware detection complete: {hardware_info}")
    except Exception as e:
        import traceback
        logger.error(f"[Settings] Hardware detection error: {e}")
        logger.error(f"[Settings] Traceback: {traceback.format_exc()}")
    
    return render_template('settings.html',
                         dfir_iris_enabled=dfir_iris_enabled,
                         dfir_iris_url=dfir_iris_url,
                         dfir_iris_api_key=dfir_iris_api_key,
                         opencti_enabled=opencti_enabled,
                         opencti_url=opencti_url,
                         opencti_api_key=opencti_api_key,
                         log_level=log_level,
                         archive_root_path=archive_root_path,
                         ai_enabled=ai_enabled,
                         ai_model_name=ai_model_name,
                         ai_hardware_mode=ai_hardware_mode,
                         ai_gpu_vram=ai_gpu_vram,
                         ai_status=ai_status,
                         all_models=all_models,
                         hardware_info=hardware_info,
                         ai_system_status=ai_system_status)


@settings_bp.route('/save', methods=['POST'])
@login_required
@admin_required
def save():
    """Save system settings"""
    # DFIR-IRIS settings
    dfir_iris_enabled = request.form.get('dfir_iris_enabled') == 'on'
    dfir_iris_url = request.form.get('dfir_iris_url', '').strip()
    dfir_iris_api_key = request.form.get('dfir_iris_api_key', '').strip()
    
    set_setting('dfir_iris_enabled', 'true' if dfir_iris_enabled else 'false', 
                'Enable DFIR-IRIS integration')
    set_setting('dfir_iris_url', dfir_iris_url, 
                'DFIR-IRIS instance URL')
    set_setting('dfir_iris_api_key', dfir_iris_api_key, 
                'DFIR-IRIS API key')
    
    # OpenCTI settings
    opencti_enabled = request.form.get('opencti_enabled') == 'on'
    opencti_url = request.form.get('opencti_url', '').strip()
    opencti_api_key = request.form.get('opencti_api_key', '').strip()
    
    set_setting('opencti_enabled', 'true' if opencti_enabled else 'false',
                'Enable OpenCTI integration')
    set_setting('opencti_url', opencti_url,
                'OpenCTI instance URL')
    set_setting('opencti_api_key', opencti_api_key,
                'OpenCTI API key')
    
    # Logging settings
    log_level = request.form.get('log_level', 'INFO').upper()
    if log_level not in ['DEBUG', 'INFO', 'WARNING', 'ERROR']:
        log_level = 'INFO'  # Default to INFO if invalid
    
    old_log_level = get_setting('log_level', 'INFO')
    set_setting('log_level', log_level, 'Application log level')
    
    # Update log level dynamically if changed
    if old_log_level != log_level:
        try:
            import sys
            sys.path.insert(0, '/opt/casescope/app')
            from logging_config import update_log_level
            update_log_level(log_level)
        except Exception as e:
            print(f"Warning: Could not update log level dynamically: {e}")
    
    # Archive settings (v1.18.0)
    archive_root_path = request.form.get('archive_root_path', '').strip()
    
    # Validate archive path if provided
    if archive_root_path:
        import os
        if not os.path.isabs(archive_root_path):
            flash('⚠️ Archive path must be absolute (e.g., /archive)', 'warning')
        elif not os.path.exists(archive_root_path):
            flash('⚠️ Archive path does not exist. Please create it first.', 'warning')
        elif not os.access(archive_root_path, os.W_OK):
            flash('⚠️ Archive path is not writable by casescope user. Check permissions.', 'warning')
    
    set_setting('archive_root_path', archive_root_path,
                'Root path for archived case files')
    
    # AI settings
    ai_enabled = request.form.get('ai_enabled') == 'on'
    ai_model_name = request.form.get('ai_model_name', 'dfir-llama:latest').strip()
    ai_hardware_mode = request.form.get('ai_hardware_mode', 'cpu').strip().lower()
    ai_gpu_vram = request.form.get('ai_gpu_vram', '8').strip()
    
    # Validate hardware mode
    if ai_hardware_mode not in ['cpu', 'gpu']:
        ai_hardware_mode = 'cpu'  # Default to CPU if invalid
    
    set_setting('ai_enabled', 'true' if ai_enabled else 'false',
                'Enable AI report generation features')
    set_setting('ai_model_name', ai_model_name,
                'AI model name for report generation')
    set_setting('ai_hardware_mode', ai_hardware_mode,
                'AI hardware mode: cpu or gpu (auto-optimizes settings)')
    set_setting('ai_gpu_vram', ai_gpu_vram,
                'GPU VRAM in GB (for model recommendations)')
    
    # Auto-setup GPU if needed
    if ai_hardware_mode == 'gpu':
        from hardware_setup import get_gpu_requirements_status
        status = get_gpu_requirements_status()
        if not status['ready']:
            flash('⚠️ GPU mode enabled but requirements not met. Please ensure NVIDIA drivers and CUDA are installed.', 'warning')
    
    # Audit log
    from audit_logger import log_action
    log_action('update_settings', resource_type='settings', resource_name='System Settings',
              details={
                  'dfir_iris_enabled': dfir_iris_enabled,
                  'opencti_enabled': opencti_enabled,
                  'log_level': log_level,
                  'archive_root_path': archive_root_path,
                  'ai_enabled': ai_enabled,
                  'ai_model_name': ai_model_name,
                  'ai_hardware_mode': ai_hardware_mode,
                  'ai_gpu_vram': ai_gpu_vram
              })
    
    flash('✓ Settings saved successfully', 'success')
    return redirect(url_for('settings.index'))


@settings_bp.route('/test_iris', methods=['POST'])
@login_required
@admin_required
def test_iris():
    """Test DFIR-IRIS connection"""
    from dfir_iris import DFIRIrisClient
    
    url = request.json.get('url', '').strip()
    api_key = request.json.get('api_key', '').strip()
    
    if not url or not api_key:
        return jsonify({'success': False, 'message': 'URL and API key are required'})
    
    try:
        client = DFIRIrisClient(url, api_key)
        # Try to list cases as connection test (requires cid parameter)
        result = client._request('GET', '/manage/cases/list?cid=1')
        
        if result is not None:
            # If we get any response (even empty data), connection works
            if isinstance(result, dict) and 'data' in result:
                case_count = len(result['data']) if isinstance(result['data'], list) else 0
                return jsonify({
                    'success': True,
                    'message': f'✓ Connection successful! Found {case_count} case(s)'
                })
            else:
                return jsonify({
                    'success': True,
                    'message': '✓ Connection successful! API authenticated'
                })
        else:
            return jsonify({
                'success': False,
                'message': '✗ Connection failed - No response from server'
            })
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'✗ Connection failed: {str(e)}'
        })


@settings_bp.route('/sync_now', methods=['POST'])
@login_required
@admin_required
def sync_now():
    """Force sync all cases, IOCs, timeline events, and systems to DFIR-IRIS"""
    from flask import jsonify
    from dfir_iris import DFIRIrisClient, sync_case_to_dfir_iris
    from models import Case, System
    import logging
    
    logger = logging.getLogger(__name__)
    
    # Check if DFIR-IRIS is enabled
    dfir_iris_enabled = get_setting('dfir_iris_enabled', 'false') == 'true'
    if not dfir_iris_enabled:
        return jsonify({
            'success': False,
            'message': '✗ DFIR-IRIS integration is not enabled'
        })
    
    dfir_iris_url = get_setting('dfir_iris_url', '')
    dfir_iris_api_key = get_setting('dfir_iris_api_key', '')
    
    if not dfir_iris_url or not dfir_iris_api_key:
        return jsonify({
            'success': False,
            'message': '✗ DFIR-IRIS URL and API key must be configured'
        })
    
    try:
        client = DFIRIrisClient(dfir_iris_url, dfir_iris_api_key)
        
        # Get all cases
        # v1.16.0+: Get all cases regardless of status
        active_cases = db.session.query(Case).all()
        
        if not active_cases:
            return jsonify({
                'success': True,
                'message': '✓ No active cases to sync'
            })
        
        cases_synced = 0
        cases_failed = 0
        systems_synced = 0
        systems_failed = 0
        
        # Sync cases (which includes IOCs and timeline events)
        for case in active_cases:
            try:
                result = sync_case_to_dfir_iris(db.session, opensearch_client, case.id, client)
                if result.get('success'):
                    cases_synced += 1
                    logger.info(f"Synced case: {case.name} (ID: {case.id})")
                else:
                    cases_failed += 1
                    logger.error(f"Failed to sync case: {case.name} (ID: {case.id})")
            except Exception as e:
                cases_failed += 1
                logger.error(f"Error syncing case {case.name} (ID: {case.id}): {e}")
        
        # Sync all systems as assets
        from routes.systems import sync_to_dfir_iris
        all_systems = db.session.query(System).all()
        
        for system in all_systems:
            try:
                result = sync_to_dfir_iris(system)
                if result:
                    systems_synced += 1
                else:
                    systems_failed += 1
            except Exception as e:
                systems_failed += 1
                logger.error(f"Error syncing system {system.system_name} (ID: {system.id}): {e}")
        
        # Sync all evidence files
        from models import EvidenceFile
        from datetime import datetime
        evidence_synced = 0
        evidence_failed = 0
        
        # Get all evidence files across all cases
        all_evidence = db.session.query(EvidenceFile).all()
        
        for evidence_file in all_evidence:
            try:
                # Get case for this evidence file
                case = db.session.get(Case, evidence_file.case_id)
                if not case:
                    continue
                
                # Get or create customer and case in DFIR-IRIS
                company_name = case.company or 'Unknown Company'
                customer_id = client.get_or_create_customer(company_name)
                if not customer_id:
                    evidence_failed += 1
                    continue
                
                iris_case_id = client.get_or_create_case(customer_id, case.name, case.description or '', company_name)
                if not iris_case_id:
                    evidence_failed += 1
                    continue
                
                # Check if file exists on disk
                import os
                if not os.path.exists(evidence_file.file_path):
                    evidence_failed += 1
                    logger.warning(f"Evidence file not found: {evidence_file.file_path}")
                    continue
                
                # Upload to DFIR-IRIS
                file_id = client.upload_evidence_file(
                    iris_case_id,
                    evidence_file.file_path,
                    evidence_file.original_filename,
                    evidence_file.description or ''
                )
                
                if file_id:
                    # Update evidence file record
                    evidence_file.dfir_iris_synced = True
                    evidence_file.dfir_iris_file_id = str(file_id)
                    evidence_file.dfir_iris_sync_date = datetime.utcnow()
                    db.session.commit()
                    evidence_synced += 1
                else:
                    evidence_failed += 1
            except Exception as e:
                evidence_failed += 1
                logger.error(f"Error syncing evidence file {evidence_file.id}: {e}")
                db.session.rollback()
        
        # Build response message
        messages = []
        if cases_synced > 0:
            messages.append(f'{cases_synced} case(s)')
        if systems_synced > 0:
            messages.append(f'{systems_synced} system(s)')
        if evidence_synced > 0:
            messages.append(f'{evidence_synced} evidence file(s)')
        
        if cases_failed == 0 and systems_failed == 0 and evidence_failed == 0:
            return jsonify({
                'success': True,
                'message': f'✓ Successfully synced {", ".join(messages)} to DFIR-IRIS'
            })
        else:
            fail_messages = []
            if cases_failed > 0:
                fail_messages.append(f'{cases_failed} case(s) failed')
            if systems_failed > 0:
                fail_messages.append(f'{systems_failed} system(s) failed')
            if evidence_failed > 0:
                fail_messages.append(f'{evidence_failed} evidence file(s) failed')
            
            return jsonify({
                'success': True if cases_synced > 0 or systems_synced > 0 or evidence_synced > 0 else False,
                'message': f'⚠️ Synced {", ".join(messages)}. Failed: {", ".join(fail_messages)}. Check logs for details.'
            })
    
    except Exception as e:
        logger.error(f"Sync failed: {e}")
        return jsonify({
            'success': False,
            'message': f'✗ Sync failed: {str(e)}'
        })


@settings_bp.route('/test_opencti', methods=['POST'])
@login_required
@admin_required
def test_opencti():
    """Test OpenCTI connection"""
    from flask import jsonify
    from opencti import OpenCTIClient
    
    url = request.json.get('url', '').strip()
    api_key = request.json.get('api_key', '').strip()
    
    if not url or not api_key:
        return jsonify({'success': False, 'message': 'URL and API key are required'})
    
    try:
        client = OpenCTIClient(url, api_key)
        
        # Check if client initialization failed with specific error
        if client.init_error:
            return jsonify({
                'success': False,
                'message': f'✗ {client.init_error}'
            })
        
        # Test connection with ping
        if client.ping():
            return jsonify({
                'success': True,
                'message': '✓ Connection successful! OpenCTI is accessible'
            })
        else:
            return jsonify({
                'success': False,
                'message': '✗ Connection failed - Could not reach OpenCTI or invalid credentials'
            })
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'✗ Connection failed: {str(e)}'
        })


@settings_bp.route('/sync_opencti', methods=['POST'])
@login_required
@admin_required
def sync_opencti():
    """Enrich all IOCs with OpenCTI threat intelligence"""
    from flask import jsonify
    from opencti import OpenCTIClient, enrich_case_iocs
    from models import Case
    import logging
    
    logger = logging.getLogger(__name__)
    
    # Check if OpenCTI is enabled
    opencti_enabled = get_setting('opencti_enabled', 'false') == 'true'
    if not opencti_enabled:
        return jsonify({
            'success': False,
            'message': '✗ OpenCTI integration is not enabled'
        })
    
    opencti_url = get_setting('opencti_url', '')
    opencti_api_key = get_setting('opencti_api_key', '')
    
    if not opencti_url or not opencti_api_key:
        return jsonify({
            'success': False,
            'message': '✗ OpenCTI URL and API key must be configured'
        })
    
    try:
        client = OpenCTIClient(opencti_url, opencti_api_key)
        
        # Get all cases
        # v1.16.0+: Get all cases regardless of status
        active_cases = db.session.query(Case).all()
        
        if not active_cases:
            return jsonify({
                'success': True,
                'message': '✓ No active cases to enrich'
            })
        
        total_enriched = 0
        total_found = 0
        total_not_found = 0
        failed_cases = 0
        
        for case in active_cases:
            try:
                result = enrich_case_iocs(db.session, case.id, client)
                if result.get('success'):
                    total_enriched += result.get('enriched_count', 0)
                    total_found += result.get('found_count', 0)
                    total_not_found += result.get('not_found_count', 0)
                    logger.info(f"Enriched IOCs for case: {case.name} (ID: {case.id})")
                else:
                    failed_cases += 1
                    logger.error(f"Failed to enrich case: {case.name} (ID: {case.id})")
            except Exception as e:
                failed_cases += 1
                logger.error(f"Error enriching case {case.name} (ID: {case.id}): {e}")
        
        if failed_cases == 0:
            return jsonify({
                'success': True,
                'message': f'✓ Enriched {total_enriched} IOC(s) across {len(active_cases)} case(s): {total_found} found in OpenCTI, {total_not_found} not found'
            })
        else:
            return jsonify({
                'success': False if total_enriched == 0 else True,
                'message': f'⚠️ Enriched {total_enriched} IOC(s), {failed_cases} case(s) failed. Check logs for details.'
            })
    
    except Exception as e:
        logger.error(f"OpenCTI enrichment failed: {e}")
        return jsonify({
            'success': False,
            'message': f'✗ Enrichment failed: {str(e)}'
        })


@settings_bp.route('/update_models', methods=['POST'])
@login_required
@admin_required
def update_models():
    """Update all installed AI models (streaming progress)"""
    from flask import Response, stream_with_context
    import subprocess
    import json
    import re
    
    def generate_progress():
        """Generator function to stream progress updates"""
        try:
            # Get list of installed models
            result = subprocess.run(['ollama', 'list'], capture_output=True, text=True)
            if result.returncode != 0:
                yield f"data: {json.dumps({'error': 'Failed to get model list'})}\n\n"
                return
            
            # Parse installed models (skip header line)
            lines = result.stdout.strip().split('\n')[1:]
            models = []
            for line in lines:
                parts = line.split()
                if parts:
                    model_name = parts[0]
                    models.append(model_name)
            
            if not models:
                yield f"data: {json.dumps({'error': 'No models installed'})}\n\n"
                return
            
            total_models = len(models)
            yield f"data: {json.dumps({'total': total_models, 'models': models})}\n\n"
            
            # Update each model
            for idx, model in enumerate(models, 1):
                yield f"data: {json.dumps({'stage': 'starting', 'model': model, 'index': idx, 'total': total_models})}\n\n"
                
                # Run ollama pull with streaming output
                process = subprocess.Popen(
                    ['ollama', 'pull', model],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    bufsize=1
                )
                
                last_status = None
                for line in iter(process.stdout.readline, ''):
                    if not line:
                        break
                    
                    line = line.strip()
                    if not line:
                        continue
                    
                    # Parse progress from ollama output
                    # Format: "pulling <layer>: <percent>% ▕████▏ <size>"
                    status_match = re.search(r'(pulling|verifying|writing)\s+(\w+):\s+(\d+)%', line)
                    if status_match:
                        action = status_match.group(1)
                        layer = status_match.group(2)
                        percent = int(status_match.group(3))
                        status = f"{action.capitalize()} {layer[:8]}... {percent}%"
                        
                        # Only send if status changed (reduce spam)
                        if status != last_status:
                            yield f"data: {json.dumps({'stage': 'downloading', 'model': model, 'index': idx, 'total': total_models, 'progress': percent, 'status': status})}\n\n"
                            last_status = status
                    
                    # Check for completion messages
                    if 'success' in line.lower():
                        yield f"data: {json.dumps({'stage': 'completed', 'model': model, 'index': idx, 'total': total_models})}\n\n"
                    elif 'error' in line.lower():
                        yield f"data: {json.dumps({'stage': 'error', 'model': model, 'index': idx, 'total': total_models, 'error': line})}\n\n"
                
                process.wait()
                
                # Ensure completion message is sent
                if process.returncode == 0:
                    yield f"data: {json.dumps({'stage': 'completed', 'model': model, 'index': idx, 'total': total_models})}\n\n"
                else:
                    yield f"data: {json.dumps({'stage': 'error', 'model': model, 'index': idx, 'total': total_models, 'error': f'Exit code {process.returncode}'})}\n\n"
            
            # All done
            yield f"data: {json.dumps({'stage': 'all_complete', 'total': total_models})}\n\n"
            
        except Exception as e:
            yield f"data: {json.dumps({'error': str(e)})}\n\n"
    
    return Response(
        stream_with_context(generate_progress()),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'X-Accel-Buffering': 'no'
        }
    )


@settings_bp.route('/check_gpu_requirements', methods=['POST'])
@login_required
@admin_required
def check_gpu_requirements():
    """Check if GPU requirements are met"""
    try:
        from hardware_setup import get_gpu_requirements_status
        status = get_gpu_requirements_status()
        return jsonify({'success': True, 'status': status})
    except Exception as e:
        logger.error(f"[Settings] GPU check error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@settings_bp.route('/setup_gpu', methods=['GET'])
@login_required
@admin_required
def setup_gpu_stream():
    """Setup GPU requirements with progress streaming"""
    def generate():
        try:
            from hardware_setup import setup_gpu_requirements
            import json
            
            def progress_callback(message):
                yield f"data: {json.dumps({'status': 'progress', 'message': message})}\n\n"
            
            # Run setup
            result = setup_gpu_requirements(progress_callback)
            
            if result['success']:
                yield f"data: {json.dumps({'status': 'complete', 'result': result})}\n\n"
            else:
                yield f"data: {json.dumps({'status': 'error', 'message': result.get('error', 'Setup failed')})}\n\n"
                
        except Exception as e:
            logger.error(f"[Settings] GPU setup error: {e}")
            yield f"data: {json.dumps({'status': 'error', 'message': str(e)})}\n\n"
    
    return Response(stream_with_context(generate()), mimetype='text/event-stream')


@settings_bp.route('/train_ai', methods=['POST'])
@login_required
@admin_required
def train_ai():
    """Start AI training using OpenCTI threat intel"""
    import logging
    logger = logging.getLogger(__name__)
    
    try:
        # Get request data
        data = request.get_json() or {}
        model_name = data.get('model_name')
        report_count = data.get('report_count', 100)
        
        # Validate model_name
        if not model_name:
            return jsonify({'success': False, 'error': 'Model name is required'}), 400
        
        # Check if model exists and is trainable
        from models import AIModel
        model = AIModel.query.filter_by(model_name=model_name).first()
        if not model:
            return jsonify({'success': False, 'error': f'Model "{model_name}" not found'}), 404
        
        if not model.trainable:
            return jsonify({
                'success': False, 
                'error': f'Model "{model_name}" is not trainable. Only dfir-mistral:latest and dfir-qwen:latest support training.'
            }), 400
        
        # Validate report_count
        try:
            report_count = int(report_count)
            if report_count < 50 or report_count > 500:
                return jsonify({'success': False, 'error': 'Report count must be between 50 and 500'}), 400
        except (ValueError, TypeError):
            return jsonify({'success': False, 'error': 'Invalid report count'}), 400
        
        # Check OpenCTI is enabled
        opencti_enabled = get_setting('opencti_enabled', 'false') == 'true'
        if not opencti_enabled:
            return jsonify({'success': False, 'error': 'OpenCTI integration must be enabled first'}), 400
        
        # Check Ollama is running
        from ai_report import check_ollama_status
        ai_status = check_ollama_status()
        if not ai_status.get('running'):
            return jsonify({'success': False, 'error': 'Ollama is not running'}), 400
        
        # CRITICAL: Check if AI resources are already locked
        from ai_resource_lock import acquire_ai_lock
        lock_acquired, lock_message = acquire_ai_lock(
            operation_type='AI Model Training',
            user_id=current_user.id,
            operation_details=f'Training {model_name} with {report_count} reports from OpenCTI'
        )
        
        if not lock_acquired:
            return jsonify({'success': False, 'error': lock_message}), 409  # 409 Conflict
        
        # Start async training task with model and report count
        from tasks import train_dfir_model_from_opencti
        task = train_dfir_model_from_opencti.delay(
            model_name=model_name,
            limit=report_count
        )
        
        logger.info(f"[Settings] Started AI training task: {task.id} by user {current_user.username} (model={model_name}, reports={report_count}, batched)")
        
        return jsonify({
            'success': True,
            'task_id': task.id,
            'message': f'Training started for {model_name} with {report_count} reports'
        })
        
    except Exception as e:
        logger.error(f"[Settings] Error starting AI training: {e}")
        # Release lock if we acquired it
        try:
            from ai_resource_lock import release_ai_lock
            release_ai_lock()
        except:
            pass
        return jsonify({'success': False, 'error': str(e)}), 500


@settings_bp.route('/train_ai_status/<task_id>', methods=['GET'])
@login_required
@admin_required
def train_ai_status(task_id):
    """Get AI training status from both Celery and database (persistent)"""
    from celery.result import AsyncResult
    from models import AITrainingSession
    
    # First check database for persistent session
    session = AITrainingSession.query.filter_by(task_id=task_id).first()
    
    if session:
        # Database session found - use it as primary source
        response = {
            'status': session.status,
            'progress': session.progress or 0,
            'current_step': session.current_step or 'Initializing...',
            'log': session.log or '',
            'started_at': session.started_at.isoformat() if session.started_at else None,
            'completed_at': session.completed_at.isoformat() if session.completed_at else None,
            'error': session.error_message
        }
    else:
        # Fallback to Celery task metadata (legacy)
        task = AsyncResult(task_id)
        
        response = {
            'status': task.state.lower(),
            'log': ''
        }
        
        # Get task metadata (log messages)
        if task.info:
            if isinstance(task.info, dict):
                response['log'] = task.info.get('log', '')
                response['progress'] = task.info.get('progress', 0)
            elif isinstance(task.info, str):
                response['log'] = task.info
        
        # If completed, include result
        if task.state == 'SUCCESS':
            response['status'] = 'completed'
            if task.result:
                response['result'] = task.result
        elif task.state == 'FAILURE':
            response['status'] = 'failed'
            response['error'] = str(task.info) if task.info else 'Unknown error'
    
    return jsonify(response)


@settings_bp.route('/get_active_training', methods=['GET'])
@login_required
@admin_required
def get_active_training():
    """Check if there's an active training session and return its task_id"""
    from models import AITrainingSession
    
    # Find any active training session (status in ['pending', 'running'])
    active_session = AITrainingSession.query.filter(
        AITrainingSession.status.in_(['pending', 'running'])
    ).order_by(AITrainingSession.started_at.desc()).first()
    
    if active_session:
        elapsed_seconds = (datetime.now() - active_session.started_at).total_seconds()
        
        return jsonify({
            'active': True,
            'task_id': active_session.task_id,
            'model_name': active_session.model_name,
            'progress': active_session.progress,
            'current_step': active_session.current_step,
            'started_at': active_session.started_at.isoformat(),
            'elapsed_seconds': int(elapsed_seconds)
        })
    else:
        return jsonify({'active': False})


@settings_bp.route('/clear_trained_models', methods=['POST'])
@login_required
@admin_required
def clear_trained_models():
    """Clear all trained models - reset to default state"""
    import logging
    import os
    import shutil
    logger = logging.getLogger(__name__)
    
    try:
        from models import AIModel
        
        # Get all trained models
        trained_models = AIModel.query.filter_by(trained=True).all()
        
        if not trained_models:
            return jsonify({
                'success': True,
                'message': 'No trained models to clear'
            })
        
        model_names = [m.display_name for m in trained_models]
        
        # Reset all models to untrained state
        for model in trained_models:
            model.trained = False
            model.trained_date = None
            model.training_examples = None
            
            # Delete LoRA adapter files if they exist
            if model.trained_model_path and os.path.exists(model.trained_model_path):
                try:
                    shutil.rmtree(model.trained_model_path)
                    logger.info(f"[Settings] Deleted training data for {model.model_name}: {model.trained_model_path}")
                except Exception as e:
                    logger.warning(f"[Settings] Could not delete training data for {model.model_name}: {e}")
            
            model.trained_model_path = None
        
        db.session.commit()
        
        # Clear old system settings for trained model references
        try:
            set_setting('ai_model_trained', 'false')
            set_setting('ai_model_trained_date', '')
            set_setting('ai_model_training_examples', '0')
            set_setting('ai_model_trained_path', '')
        except:
            pass
        
        logger.info(f"[Settings] Cleared {len(trained_models)} trained models by user {current_user.username}")
        
        return jsonify({
            'success': True,
            'message': f'Successfully cleared {len(trained_models)} trained model(s): {", ".join(model_names)}'
        })
        
    except Exception as e:
        logger.error(f"[Settings] Error clearing trained models: {e}")
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

