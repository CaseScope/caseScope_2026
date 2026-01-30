"""Activation Server Client

Handles communication with the CaseScope activation server for:
- License verification (/api/verify)
- Daily check-ins (/api/checkin)
- Grace period management when server is unreachable
"""

import json
import logging
import os
import requests
from datetime import datetime, timedelta
from typing import Dict, Optional, Tuple

logger = logging.getLogger(__name__)

# Activation server configuration
ACTIVATION_SERVER_URL = os.environ.get(
    'CASESCOPE_ACTIVATION_SERVER',
    'https://activation.casescope.net'
)

# Grace period when server is unreachable (days)
OFFLINE_GRACE_PERIOD_DAYS = 7

# Request timeout (seconds)
REQUEST_TIMEOUT = 10

# Database setting keys
LAST_SERVER_CHECK_KEY = 'license_last_server_check'
LAST_SERVER_STATUS_KEY = 'license_last_server_status'
SERVER_GRACE_START_KEY = 'license_grace_period_start'


class ServerVerificationResult:
    """Result of server verification."""
    
    def __init__(self):
        self.success = False
        self.valid = False
        self.error_message: Optional[str] = None
        self.server_reachable = False
        self.in_grace_period = False
        self.grace_days_remaining: Optional[int] = None
        self.license_status: Optional[str] = None
        self.features: Dict[str, bool] = {}
        self.message: Optional[str] = None
        self.expires_at: Optional[str] = None
        self.revoked = False
    
    def to_dict(self) -> Dict:
        return {
            'success': self.success,
            'valid': self.valid,
            'error_message': self.error_message,
            'server_reachable': self.server_reachable,
            'in_grace_period': self.in_grace_period,
            'grace_days_remaining': self.grace_days_remaining,
            'license_status': self.license_status,
            'features': self.features,
            'message': self.message,
            'expires_at': self.expires_at,
            'revoked': self.revoked
        }


class ActivationServerClient:
    """
    Client for communicating with the activation server.
    
    Endpoints:
    - POST /api/verify: Full verification with license details
    - POST /api/checkin: Daily heartbeat check-in
    """
    
    @classmethod
    def verify_license(cls, license_id: str, fingerprint_hash: str, 
                      license_data: Dict = None) -> ServerVerificationResult:
        """
        Verify license with the activation server.
        
        Called on startup and when user clicks "Verify" button.
        
        Args:
            license_id: The license ID from the local license file
            fingerprint_hash: Current machine fingerprint hash
            license_data: Optional full license data for verification
            
        Returns:
            ServerVerificationResult with verification status
        """
        result = ServerVerificationResult()
        
        try:
            payload = {
                'license_id': license_id,
                'fingerprint_hash': fingerprint_hash,
                'timestamp': datetime.utcnow().isoformat() + 'Z'
            }
            
            if license_data:
                payload['customer_id'] = license_data.get('customer_id')
                payload['features'] = license_data.get('features', {})
            
            # Add system info
            payload['system_info'] = cls._get_system_info()
            
            response = requests.post(
                f"{ACTIVATION_SERVER_URL}/api/verify",
                json=payload,
                timeout=REQUEST_TIMEOUT,
                headers={'Content-Type': 'application/json'}
            )
            
            result.server_reachable = True
            
            if response.status_code == 200:
                data = response.json()
                result.success = True
                result.valid = data.get('valid', False)
                result.license_status = data.get('status')
                result.features = data.get('features', {})
                result.message = data.get('message')
                result.expires_at = data.get('expires_at')
                result.revoked = data.get('revoked', False)
                
                if not result.valid:
                    result.error_message = data.get('message', 'License not valid')
                
                # Clear grace period on successful server contact
                cls._clear_grace_period()
                cls._save_last_check(result.valid, result.license_status)
                
            else:
                result.error_message = f"Server returned status {response.status_code}"
                try:
                    error_data = response.json()
                    result.error_message = error_data.get('message', result.error_message)
                except Exception:
                    pass
            
            logger.info(f"[ActivationServer] Verify result: valid={result.valid}, "
                       f"status={result.license_status}")
            
        except requests.exceptions.Timeout:
            logger.warning("[ActivationServer] Verify request timed out")
            result.error_message = "Activation server timeout"
            result = cls._handle_offline(result)
            
        except requests.exceptions.ConnectionError:
            logger.warning("[ActivationServer] Could not connect to activation server")
            result.error_message = "Could not connect to activation server"
            result = cls._handle_offline(result)
            
        except Exception as e:
            logger.error(f"[ActivationServer] Verify error: {e}")
            result.error_message = str(e)
            result = cls._handle_offline(result)
        
        return result
    
    @classmethod
    def checkin(cls, license_id: str, fingerprint_hash: str) -> ServerVerificationResult:
        """
        Daily check-in with the activation server.
        
        Lighter-weight than full verify, just confirms license is still valid.
        
        Args:
            license_id: The license ID
            fingerprint_hash: Current machine fingerprint hash
            
        Returns:
            ServerVerificationResult with check-in status
        """
        result = ServerVerificationResult()
        
        try:
            payload = {
                'license_id': license_id,
                'fingerprint_hash': fingerprint_hash,
                'timestamp': datetime.utcnow().isoformat() + 'Z'
            }
            
            response = requests.post(
                f"{ACTIVATION_SERVER_URL}/api/checkin",
                json=payload,
                timeout=REQUEST_TIMEOUT,
                headers={'Content-Type': 'application/json'}
            )
            
            result.server_reachable = True
            
            if response.status_code == 200:
                data = response.json()
                result.success = True
                result.valid = data.get('valid', False)
                result.license_status = data.get('status')
                result.message = data.get('message')
                result.revoked = data.get('revoked', False)
                
                if not result.valid:
                    result.error_message = data.get('message', 'License not valid')
                
                # Clear grace period on successful server contact
                cls._clear_grace_period()
                cls._save_last_check(result.valid, result.license_status)
                
            else:
                result.error_message = f"Server returned status {response.status_code}"
            
            logger.info(f"[ActivationServer] Check-in result: valid={result.valid}")
            
        except requests.exceptions.Timeout:
            logger.warning("[ActivationServer] Check-in request timed out")
            result.error_message = "Activation server timeout"
            result = cls._handle_offline(result)
            
        except requests.exceptions.ConnectionError:
            logger.warning("[ActivationServer] Could not connect for check-in")
            result.error_message = "Could not connect to activation server"
            result = cls._handle_offline(result)
            
        except Exception as e:
            logger.error(f"[ActivationServer] Check-in error: {e}")
            result.error_message = str(e)
            result = cls._handle_offline(result)
        
        return result
    
    @classmethod
    def _handle_offline(cls, result: ServerVerificationResult) -> ServerVerificationResult:
        """
        Handle case when server is unreachable.
        
        Implements grace period logic - allow offline operation for up to 7 days
        if the last successful check showed a valid license OR if the local
        license is valid and this is the first connection attempt.
        """
        result.server_reachable = False
        
        try:
            from models.system_settings import SystemSettings
            from utils.licensing.validator import LicenseValidator
            
            # Get last successful check info
            last_status = SystemSettings.get(LAST_SERVER_STATUS_KEY)
            last_check_str = SystemSettings.get(LAST_SERVER_CHECK_KEY)
            grace_start_str = SystemSettings.get(SERVER_GRACE_START_KEY)
            
            # Check if local license is valid
            local_validation = LicenseValidator.validate()
            local_valid = local_validation.is_valid
            
            # Allow grace period if:
            # 1. Last server status was valid, OR
            # 2. Local license is valid and server has never been contacted (first-time setup)
            should_grant_grace = last_status == 'valid' or (local_valid and last_status is None)
            
            if should_grant_grace:
                # Start grace period if not already started
                if not grace_start_str:
                    grace_start = datetime.utcnow()
                    SystemSettings.set(SERVER_GRACE_START_KEY, grace_start.isoformat())
                else:
                    grace_start = datetime.fromisoformat(grace_start_str)
                
                # Calculate days remaining in grace period
                days_offline = (datetime.utcnow() - grace_start).days
                grace_remaining = OFFLINE_GRACE_PERIOD_DAYS - days_offline
                
                if grace_remaining > 0:
                    result.in_grace_period = True
                    result.grace_days_remaining = grace_remaining
                    result.valid = True  # Allow operation during grace period
                    result.license_status = 'grace_period'
                    if last_status is None:
                        result.message = f"Activation server unreachable. Operating in offline mode: {grace_remaining} days remaining"
                    else:
                        result.message = f"Offline mode: {grace_remaining} days remaining"
                    logger.info(f"[ActivationServer] In grace period: {grace_remaining} days remaining")
                else:
                    result.valid = False
                    result.license_status = 'grace_expired'
                    result.error_message = "Offline grace period expired. Please connect to verify license."
                    logger.warning("[ActivationServer] Grace period expired")
            else:
                # No valid local license and no previous valid status
                result.valid = False
                result.license_status = 'unverified'
                if local_valid:
                    result.error_message = "Activation server previously marked license as invalid"
                else:
                    result.error_message = "No valid license installed"
                
        except Exception as e:
            logger.error(f"[ActivationServer] Error handling offline mode: {e}")
            result.valid = False
            result.error_message = "Could not verify license status"
        
        return result
    
    @classmethod
    def _save_last_check(cls, valid: bool, status: str):
        """Save last successful check info."""
        try:
            from models.system_settings import SystemSettings
            
            SystemSettings.set(LAST_SERVER_CHECK_KEY, datetime.utcnow().isoformat())
            SystemSettings.set(LAST_SERVER_STATUS_KEY, 'valid' if valid else 'invalid')
            
        except Exception as e:
            logger.error(f"[ActivationServer] Error saving last check: {e}")
    
    @classmethod
    def _clear_grace_period(cls):
        """Clear grace period start when server is reachable."""
        try:
            from models.system_settings import SystemSettings
            SystemSettings.delete(SERVER_GRACE_START_KEY)
        except Exception:
            pass
    
    @classmethod
    def get_last_check_info(cls) -> Dict:
        """Get information about the last server check."""
        try:
            from models.system_settings import SystemSettings
            
            last_check_str = SystemSettings.get(LAST_SERVER_CHECK_KEY)
            last_status = SystemSettings.get(LAST_SERVER_STATUS_KEY)
            grace_start_str = SystemSettings.get(SERVER_GRACE_START_KEY)
            
            last_check = None
            if last_check_str:
                last_check = datetime.fromisoformat(last_check_str)
            
            grace_start = None
            grace_days_remaining = None
            if grace_start_str:
                grace_start = datetime.fromisoformat(grace_start_str)
                days_offline = (datetime.utcnow() - grace_start).days
                grace_days_remaining = max(0, OFFLINE_GRACE_PERIOD_DAYS - days_offline)
            
            return {
                'last_check': last_check.isoformat() if last_check else None,
                'last_status': last_status,
                'in_grace_period': grace_start is not None,
                'grace_days_remaining': grace_days_remaining,
                'server_url': ACTIVATION_SERVER_URL
            }
            
        except Exception as e:
            logger.error(f"[ActivationServer] Error getting last check info: {e}")
            return {
                'last_check': None,
                'last_status': None,
                'in_grace_period': False,
                'grace_days_remaining': None,
                'server_url': ACTIVATION_SERVER_URL
            }
    
    @classmethod
    def needs_checkin(cls) -> bool:
        """Check if a daily check-in is needed."""
        try:
            from models.system_settings import SystemSettings
            
            last_check_str = SystemSettings.get(LAST_SERVER_CHECK_KEY)
            if not last_check_str:
                return True
            
            last_check = datetime.fromisoformat(last_check_str)
            hours_since_check = (datetime.utcnow() - last_check).total_seconds() / 3600
            
            # Check-in if more than 24 hours since last check
            return hours_since_check >= 24
            
        except Exception:
            return True
    
    @classmethod
    def _get_system_info(cls) -> Dict:
        """Get system information for verification requests."""
        import platform
        
        return {
            'hostname': platform.node(),
            'platform': platform.system(),
            'platform_version': platform.release(),
            'python_version': platform.python_version()
        }
