"""Activation Routes for CaseScope

Provides endpoints for license activation and management.
"""

import json
import logging
from flask import Blueprint, render_template, request, jsonify, flash, redirect, url_for
from flask_login import login_required, current_user

from utils.licensing.license_manager import LicenseManager, ActivationStatus
from utils.licensing.fingerprint import MachineFingerprint
from utils.licensing.validator import LicenseValidator

logger = logging.getLogger(__name__)

activation_bp = Blueprint('activation', __name__, url_prefix='/activation')


# ============================================================================
# Web UI Routes
# ============================================================================

@activation_bp.route('/')
@login_required
def activation_page():
    """Activation management page."""
    activation_info = LicenseManager.get_activation_info()
    warnings = LicenseManager.get_license_warnings()
    
    # Get activation request for display
    activation_request = LicenseManager.generate_activation_request()
    
    # Check if public key is configured
    public_key_configured = LicenseValidator.is_public_key_configured()
    
    return render_template(
        'activation.html',
        activation_info=activation_info,
        warnings=warnings,
        activation_request=json.dumps(activation_request, indent=2),
        public_key_configured=public_key_configured
    )


# ============================================================================
# API Routes
# ============================================================================

@activation_bp.route('/api/status')
@login_required
def api_status():
    """Get current activation status."""
    try:
        activation_info = LicenseManager.get_activation_info()
        warnings = LicenseManager.get_license_warnings()
        
        return jsonify({
            'success': True,
            'activation': activation_info,
            'warnings': warnings
        })
        
    except Exception as e:
        logger.error(f"[Activation] Failed to get status: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@activation_bp.route('/api/request')
@login_required
def api_activation_request():
    """Generate activation request data."""
    try:
        request_data = LicenseManager.generate_activation_request()
        
        return jsonify({
            'success': True,
            'request': request_data
        })
        
    except Exception as e:
        logger.error(f"[Activation] Failed to generate request: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@activation_bp.route('/api/fingerprint')
@login_required
def api_fingerprint():
    """Get current machine fingerprint (for debugging)."""
    try:
        # Only show to admins
        from config import PermissionLevel
        if current_user.permission_level < PermissionLevel.ADMINISTRATOR:
            return jsonify({
                'success': False,
                'error': 'Administrator access required'
            }), 403
        
        fingerprint_info = MachineFingerprint.get_fingerprint_for_activation()
        debug_info = MachineFingerprint.get_debug_info()
        
        return jsonify({
            'success': True,
            'fingerprint': fingerprint_info,
            'debug': debug_info
        })
        
    except Exception as e:
        logger.error(f"[Activation] Failed to get fingerprint: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@activation_bp.route('/api/activate', methods=['POST'])
@login_required
def api_activate():
    """
    Activate with a license file.
    
    Expects JSON body with 'license' field containing the license file contents.
    """
    try:
        # Check admin permission
        from config import PermissionLevel
        if current_user.permission_level < PermissionLevel.ADMINISTRATOR:
            return jsonify({
                'success': False,
                'error': 'Administrator access required for activation'
            }), 403
        
        data = request.get_json()
        if not data:
            return jsonify({
                'success': False,
                'error': 'No data provided'
            }), 400
        
        license_content = data.get('license')
        if not license_content:
            return jsonify({
                'success': False,
                'error': 'License content is required'
            }), 400
        
        # If license_content is a dict, serialize it
        if isinstance(license_content, dict):
            license_content = json.dumps(license_content)
        
        # Install the license
        success, message = LicenseManager.install_license(license_content)
        
        if success:
            # Record activation in database
            try:
                from models.license import LicenseActivation, ActivationAuditLog
                license_data = json.loads(license_content)
                fingerprint = MachineFingerprint.get_fingerprint_for_activation()
                
                LicenseActivation.record_activation(
                    license_data=license_data,
                    activated_by=current_user.username,
                    fingerprint_hash=fingerprint['fingerprint_hash'],
                    fingerprint_match_count=fingerprint['component_count']
                )
                
                ActivationAuditLog.log(
                    action='activate',
                    username=current_user.username,
                    license_id=license_data.get('license_id'),
                    details={'customer_name': license_data.get('customer_name')},
                    ip_address=request.remote_addr
                )
                
            except Exception as e:
                logger.warning(f"[Activation] Failed to record activation: {e}")
            
            # Get updated activation info
            activation_info = LicenseManager.get_activation_info()
            
            logger.info(f"[Activation] License activated by {current_user.username}")
            
            return jsonify({
                'success': True,
                'message': message,
                'activation': activation_info
            })
        else:
            # Log failed attempt
            try:
                from models.license import ActivationAuditLog
                ActivationAuditLog.log(
                    action='activate_failed',
                    username=current_user.username,
                    details={'error': message},
                    ip_address=request.remote_addr
                )
            except Exception:
                pass
            
            return jsonify({
                'success': False,
                'error': message
            }), 400
        
    except json.JSONDecodeError as e:
        return jsonify({
            'success': False,
            'error': f'Invalid JSON format: {e}'
        }), 400
        
    except Exception as e:
        logger.error(f"[Activation] Activation failed: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@activation_bp.route('/api/validate', methods=['POST'])
@login_required
def api_validate():
    """Validate current license with activation server."""
    try:
        # First refresh local validation
        LicenseManager.refresh_license_status()
        
        # Then verify with activation server
        server_result = LicenseManager.verify_with_server()
        
        # Get updated activation info
        activation_info = LicenseManager.get_activation_info()
        
        # Log validation
        try:
            from models.license import ActivationAuditLog
            ActivationAuditLog.log(
                action='server_verify',
                username=current_user.username,
                license_id=activation_info['license'].get('license_id'),
                details={
                    'server_reachable': server_result.get('server_reachable'),
                    'valid': server_result.get('valid'),
                    'in_grace_period': server_result.get('in_grace_period')
                },
                ip_address=request.remote_addr
            )
        except Exception:
            pass
        
        return jsonify({
            'success': True,
            'activation': activation_info,
            'server_verification': server_result
        })
        
    except Exception as e:
        logger.error(f"[Activation] Validation failed: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@activation_bp.route('/api/checkin', methods=['POST'])
@login_required
def api_checkin():
    """Perform daily check-in with activation server."""
    try:
        result = LicenseManager.perform_checkin()
        activation_info = LicenseManager.get_activation_info()
        
        # Log check-in
        try:
            from models.license import ActivationAuditLog
            ActivationAuditLog.log(
                action='server_checkin',
                username=current_user.username,
                license_id=activation_info['license'].get('license_id'),
                details={
                    'server_reachable': result.get('server_reachable'),
                    'valid': result.get('valid')
                },
                ip_address=request.remote_addr
            )
        except Exception:
            pass
        
        return jsonify({
            'success': result.get('success', False),
            'checkin_result': result,
            'activation': activation_info
        })
        
    except Exception as e:
        logger.error(f"[Activation] Check-in failed: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@activation_bp.route('/api/server-status')
@login_required
def api_server_status():
    """Get activation server connection status."""
    try:
        from utils.licensing.server_client import ActivationServerClient
        
        server_info = ActivationServerClient.get_last_check_info()
        needs_checkin = ActivationServerClient.needs_checkin()
        
        return jsonify({
            'success': True,
            'server': server_info,
            'needs_checkin': needs_checkin
        })
        
    except Exception as e:
        logger.error(f"[Activation] Failed to get server status: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@activation_bp.route('/api/features')
@login_required
def api_features():
    """Get licensed feature availability."""
    try:
        features = LicenseManager.get_feature_availability()
        is_activated = LicenseManager.is_activated()
        
        return jsonify({
            'success': True,
            'is_activated': is_activated,
            'features': features
        })
        
    except Exception as e:
        logger.error(f"[Activation] Failed to get features: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@activation_bp.route('/api/history')
@login_required
def api_history():
    """Get activation history."""
    try:
        from config import PermissionLevel
        if current_user.permission_level < PermissionLevel.ADMINISTRATOR:
            return jsonify({
                'success': False,
                'error': 'Administrator access required'
            }), 403
        
        from models.license import LicenseActivation, ActivationAuditLog
        
        activations = LicenseActivation.get_activation_history(limit=20)
        audit_log = ActivationAuditLog.get_recent(limit=50)
        
        return jsonify({
            'success': True,
            'activations': [a.to_dict() for a in activations],
            'audit_log': [a.to_dict() for a in audit_log]
        })
        
    except Exception as e:
        logger.error(f"[Activation] Failed to get history: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@activation_bp.route('/api/public-key', methods=['GET'])
@login_required
def api_get_public_key():
    """Get public key configuration status."""
    try:
        from config import PermissionLevel
        if current_user.permission_level < PermissionLevel.ADMINISTRATOR:
            return jsonify({
                'success': False,
                'error': 'Administrator access required'
            }), 403
        
        is_configured = LicenseValidator.is_public_key_configured()
        
        # Only show first/last few chars for security
        public_key = LicenseValidator.get_public_key_b64()
        masked_key = None
        if public_key:
            if len(public_key) > 12:
                masked_key = f"{public_key[:6]}...{public_key[-6:]}"
            else:
                masked_key = public_key
        
        return jsonify({
            'success': True,
            'is_configured': is_configured,
            'masked_key': masked_key
        })
        
    except Exception as e:
        logger.error(f"[Activation] Failed to get public key status: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@activation_bp.route('/api/public-key', methods=['POST'])
@login_required
def api_set_public_key():
    """Set the license verification public key."""
    try:
        from config import PermissionLevel
        if current_user.permission_level < PermissionLevel.ADMINISTRATOR:
            return jsonify({
                'success': False,
                'error': 'Administrator access required'
            }), 403
        
        data = request.get_json()
        if not data:
            return jsonify({
                'success': False,
                'error': 'No data provided'
            }), 400
        
        public_key = data.get('public_key', '').strip()
        if not public_key:
            return jsonify({
                'success': False,
                'error': 'Public key is required'
            }), 400
        
        success, message = LicenseValidator.set_public_key(public_key)
        
        if success:
            # Log the action
            try:
                from models.license import ActivationAuditLog
                ActivationAuditLog.log(
                    action='set_public_key',
                    username=current_user.username,
                    ip_address=request.remote_addr
                )
            except Exception:
                pass
            
            return jsonify({
                'success': True,
                'message': message
            })
        else:
            return jsonify({
                'success': False,
                'error': message
            }), 400
        
    except Exception as e:
        logger.error(f"[Activation] Failed to set public key: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500
