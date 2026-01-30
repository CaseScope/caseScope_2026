"""License Manager Module

High-level API for license management and activation status.

Integrates:
- Local license file validation
- Server-side verification (activation.casescope.net)
- Grace period for offline operation
"""

import logging
from datetime import datetime
from typing import Dict, Optional

from utils.licensing.fingerprint import MachineFingerprint
from utils.licensing.validator import LicenseValidator, LicenseValidationResult
from utils.licensing.server_client import ActivationServerClient, ServerVerificationResult

logger = logging.getLogger(__name__)


class ActivationStatus:
    """Activation status constants."""
    NOT_ACTIVATED = 'not_activated'
    ACTIVATED = 'activated'
    EXPIRED = 'expired'
    INVALID = 'invalid'
    REVOKED = 'revoked'
    GRACE_PERIOD = 'grace_period'
    GRACE_EXPIRED = 'grace_expired'


class LicenseManager:
    """
    High-level license management API.
    
    Provides activation checking, feature gating, and license management.
    """
    
    # Cached activation status
    _cached_status: Optional[str] = None
    _cached_features: Optional[Dict[str, bool]] = None
    _cache_time: Optional[datetime] = None
    CACHE_DURATION_SECONDS = 60  # 1 minute for status checks
    
    @classmethod
    def is_activated(cls) -> bool:
        """
        Check if the system is activated with a valid license.
        
        Returns:
            bool: True if system has a valid, non-expired license
        """
        result = LicenseValidator.validate()
        return result.is_valid
    
    @classmethod
    def get_activation_status(cls) -> str:
        """
        Get detailed activation status.
        
        Returns:
            str: One of ActivationStatus constants
        """
        result = LicenseValidator.validate()
        
        if result.is_valid:
            return ActivationStatus.ACTIVATED
        
        if result.error_message:
            if 'expired' in result.error_message.lower():
                return ActivationStatus.EXPIRED
            if 'No license file' in result.error_message:
                return ActivationStatus.NOT_ACTIVATED
        
        return ActivationStatus.INVALID
    
    @classmethod
    def is_feature_activated(cls, feature: str) -> bool:
        """
        Check if a specific feature is activated.
        
        This checks both:
        1. System is activated (valid license)
        2. Feature is enabled in the license
        
        Args:
            feature: Feature name ('ai', 'opencti')
            
        Returns:
            bool: True if feature is activated
        """
        return LicenseValidator.is_feature_licensed(feature)
    
    @classmethod
    def get_activation_info(cls) -> Dict:
        """
        Get comprehensive activation information.
        
        Returns:
            dict: Activation status, license details, features, expiry info, server status
        """
        validation = LicenseValidator.validate()
        status = cls.get_activation_status()
        server_info = ActivationServerClient.get_last_check_info()
        
        # Adjust status based on server verification
        if validation.is_valid and server_info.get('last_status') == 'invalid':
            status = ActivationStatus.REVOKED
        elif server_info.get('in_grace_period'):
            status = ActivationStatus.GRACE_PERIOD
        
        return {
            'status': status,
            'is_activated': validation.is_valid and status not in [ActivationStatus.REVOKED, ActivationStatus.GRACE_EXPIRED],
            'license': validation.to_dict(),
            'features': {
                'ai': validation.features.get('ai', False) if validation.is_valid else False,
                'opencti': validation.features.get('opencti', False) if validation.is_valid else False,
                'max_cases': validation.features.get('max_cases', -1) if validation.is_valid else 0
            },
            'expiry': {
                'expires_at': validation.expires_at.isoformat() if validation.expires_at else None,
                'days_remaining': validation.days_until_expiry,
                'is_expiring_soon': validation.days_until_expiry is not None and validation.days_until_expiry <= 30
            },
            'server': {
                'last_check': server_info.get('last_check'),
                'last_status': server_info.get('last_status'),
                'in_grace_period': server_info.get('in_grace_period', False),
                'grace_days_remaining': server_info.get('grace_days_remaining'),
                'needs_checkin': ActivationServerClient.needs_checkin()
            }
        }
    
    @classmethod
    def generate_activation_request(cls) -> Dict:
        """
        Generate an activation request to send to the license server.
        
        This includes machine fingerprint data that will be bound to the license.
        
        Returns:
            dict: Activation request data
        """
        fingerprint = MachineFingerprint.get_fingerprint_for_activation()
        
        return {
            'request_type': 'activation',
            'request_version': '1.0',
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'fingerprint': fingerprint,
            'system_info': cls._get_system_info()
        }
    
    @classmethod
    def _get_system_info(cls) -> Dict:
        """Get basic system information for activation request."""
        import platform
        import os
        
        return {
            'platform': platform.system(),
            'platform_release': platform.release(),
            'platform_version': platform.version(),
            'machine': platform.machine(),
            'python_version': platform.python_version(),
            'hostname': platform.node()
        }
    
    @classmethod
    def install_license(cls, license_content: str) -> tuple:
        """
        Install a new license.
        
        Args:
            license_content: JSON string of the license file
            
        Returns:
            tuple: (success, message)
        """
        success, message = LicenseValidator.install_license(license_content)
        
        if success:
            # Clear all caches
            cls._cached_status = None
            cls._cached_features = None
            cls._cache_time = None
            LicenseValidator.clear_cache()
        
        return success, message
    
    @classmethod
    def get_feature_availability(cls) -> Dict[str, bool]:
        """
        Get availability status for all licensable features.
        
        Returns:
            dict: Feature name -> is_available
        """
        validation = LicenseValidator.validate()
        
        if not validation.is_valid:
            return {
                'ai': False,
                'opencti': False
            }
        
        return {
            'ai': validation.features.get('ai', False),
            'opencti': validation.features.get('opencti', False)
        }
    
    @classmethod
    def refresh_license_status(cls):
        """Force refresh of license status (bypass cache)."""
        cls._cached_status = None
        cls._cached_features = None
        cls._cache_time = None
        LicenseValidator.clear_cache()
        LicenseValidator.validate(force_refresh=True)
    
    @classmethod
    def verify_with_server(cls) -> Dict:
        """
        Verify license with the activation server.
        
        Called on startup and when user clicks "Verify" button.
        
        Returns:
            dict: Server verification result
        """
        validation = LicenseValidator.validate()
        
        if not validation.is_valid:
            return {
                'success': False,
                'error': 'No valid local license to verify',
                'server_result': None
            }
        
        # Get fingerprint and verify with server
        fingerprint = MachineFingerprint.get_fingerprint_for_activation()
        
        license_data = {
            'customer_id': validation.customer_id,
            'features': validation.features
        }
        
        result = ActivationServerClient.verify_license(
            license_id=validation.license_id,
            fingerprint_hash=fingerprint['fingerprint_hash'],
            license_data=license_data
        )
        
        # Clear caches to reflect new status
        cls.refresh_license_status()
        
        return {
            'success': result.success,
            'valid': result.valid,
            'error': result.error_message,
            'server_reachable': result.server_reachable,
            'in_grace_period': result.in_grace_period,
            'grace_days_remaining': result.grace_days_remaining,
            'message': result.message,
            'revoked': result.revoked,
            'server_result': result.to_dict()
        }
    
    @classmethod
    def perform_checkin(cls) -> Dict:
        """
        Perform daily check-in with activation server.
        
        Returns:
            dict: Check-in result
        """
        validation = LicenseValidator.validate()
        
        if not validation.is_valid:
            return {
                'success': False,
                'error': 'No valid local license for check-in'
            }
        
        fingerprint = MachineFingerprint.get_fingerprint_for_activation()
        
        result = ActivationServerClient.checkin(
            license_id=validation.license_id,
            fingerprint_hash=fingerprint['fingerprint_hash']
        )
        
        return {
            'success': result.success,
            'valid': result.valid,
            'error': result.error_message,
            'server_reachable': result.server_reachable,
            'in_grace_period': result.in_grace_period,
            'grace_days_remaining': result.grace_days_remaining,
            'message': result.message,
            'revoked': result.revoked
        }
    
    @classmethod
    def check_and_handle_revocation(cls) -> bool:
        """
        Check if license has been revoked and handle accordingly.
        
        Returns:
            bool: True if license is still valid, False if revoked/expired
        """
        server_info = ActivationServerClient.get_last_check_info()
        
        # If last server check showed invalid, license may be revoked
        if server_info.get('last_status') == 'invalid':
            logger.warning("[LicenseManager] License appears to be revoked")
            return False
        
        # If in grace period but expired
        if server_info.get('in_grace_period') and server_info.get('grace_days_remaining', 0) <= 0:
            logger.warning("[LicenseManager] Grace period expired")
            return False
        
        return True
    
    @classmethod
    def should_perform_checkin(cls) -> bool:
        """Check if a check-in should be performed."""
        return ActivationServerClient.needs_checkin()
    
    @classmethod
    def get_license_warnings(cls) -> list:
        """
        Get any warnings about the current license.
        
        Returns:
            list: Warning messages (empty if no warnings)
        """
        warnings = []
        validation = LicenseValidator.validate()
        server_info = ActivationServerClient.get_last_check_info()
        
        if validation.is_valid:
            # Check for expiring soon
            if validation.days_until_expiry is not None:
                if validation.days_until_expiry <= 7:
                    warnings.append(f"License expires in {validation.days_until_expiry} days!")
                elif validation.days_until_expiry <= 30:
                    warnings.append(f"License expires in {validation.days_until_expiry} days")
            
            # Check for partial fingerprint match
            if validation.fingerprint_match_count < 5:
                warnings.append(
                    f"Hardware changes detected: {validation.fingerprint_match_count}/5 "
                    "fingerprint components match"
                )
        
        # Server-related warnings
        if server_info.get('in_grace_period'):
            grace_days = server_info.get('grace_days_remaining', 0)
            if grace_days <= 3:
                warnings.append(f"Offline mode: Only {grace_days} days remaining! Connect to verify license.")
            else:
                warnings.append(f"Offline mode: {grace_days} days remaining until verification required")
        
        if server_info.get('last_status') == 'invalid':
            warnings.append("License has been revoked or is invalid. Please contact support.")
        
        # Suggest check-in if needed
        if ActivationServerClient.needs_checkin() and not server_info.get('in_grace_period'):
            warnings.append("License verification is due. Click 'Verify' to check status.")
        
        return warnings
