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
    NOT_ACTIVATED = 'not_activated'       # No license file present
    ACTIVATED = 'activated'               # Valid and verified license
    EXPIRING_SOON = 'expiring_soon'       # Valid but within 30 days of expiry
    EXPIRED = 'expired'                   # License has expired (checked via NIST)
    VERIFICATION_FAILED = 'verification_failed'  # Server verification failed
    REVOKED = 'revoked'                   # Server explicitly revoked license
    GRACE_PERIOD = 'grace_period'         # Server unreachable, in grace period
    GRACE_EXPIRED = 'grace_expired'       # Grace period has ended
    INVALID = 'invalid'                   # License file invalid (signature, fingerprint, etc.)


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
        
        Uses NIST time servers to verify expiration and prevent date manipulation.
        
        Returns:
            str: One of ActivationStatus constants
        """
        from utils.licensing.nist_time import is_expired, is_expiring_soon
        
        result = LicenseValidator.validate()
        server_info = ActivationServerClient.get_last_check_info()
        
        # No license file present
        if result.error_message and 'No license file' in result.error_message:
            return ActivationStatus.NOT_ACTIVATED
        
        # Check for server-side revocation (explicit revoke action)
        if server_info.get('last_status') == 'revoked':
            return ActivationStatus.REVOKED
        
        # Check for server verification failure (not revoked, but failed checks)
        if server_info.get('last_status') == 'invalid':
            return ActivationStatus.VERIFICATION_FAILED
        
        # Check for grace period status
        if server_info.get('in_grace_period'):
            grace_days = server_info.get('grace_days_remaining', 0)
            if grace_days <= 0:
                return ActivationStatus.GRACE_EXPIRED
            return ActivationStatus.GRACE_PERIOD
        
        # Check expiration using NIST time
        if result.expires_at:
            expired, _ = is_expired(result.expires_at)
            if expired:
                return ActivationStatus.EXPIRED
            
            expiring, days_remaining = is_expiring_soon(result.expires_at, threshold_days=30)
            if expiring and result.is_valid:
                return ActivationStatus.EXPIRING_SOON
        
        # License is valid
        if result.is_valid:
            return ActivationStatus.ACTIVATED
        
        # Other validation errors (signature, fingerprint, etc.)
        if result.error_message and 'expired' in result.error_message.lower():
            return ActivationStatus.EXPIRED
        
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
        
        Uses NIST time servers to verify expiration dates.
        
        Returns:
            dict: Activation status, license details, features, expiry info, server status
        """
        from utils.licensing.nist_time import is_expired, is_expiring_soon, get_nist_time
        
        validation = LicenseValidator.validate()
        status = cls.get_activation_status()
        server_info = ActivationServerClient.get_last_check_info()
        
        # Calculate accurate days remaining using NIST time
        days_remaining = None
        is_expired_nist = False
        is_expiring_soon_nist = False
        
        if validation.expires_at:
            is_expired_nist, _ = is_expired(validation.expires_at)
            is_expiring_soon_nist, days_remaining = is_expiring_soon(validation.expires_at, threshold_days=30)
            if is_expired_nist:
                days_remaining = None
        
        # Determine if features should be enabled
        # Features are disabled if: not activated, expired, revoked, verification failed, or grace expired
        features_enabled = (
            validation.is_valid and 
            status in [
                ActivationStatus.ACTIVATED, 
                ActivationStatus.EXPIRING_SOON, 
                ActivationStatus.GRACE_PERIOD
            ]
        )
        
        # Get NIST time status for display
        nist_result = get_nist_time()
        
        return {
            'status': status,
            'status_label': cls._get_status_label(status),
            'status_class': cls._get_status_css_class(status),
            'is_activated': features_enabled,
            'license': validation.to_dict(),
            'features': {
                'ai': validation.features.get('ai', False) if features_enabled else False,
                'opencti': validation.features.get('opencti', False) if features_enabled else False,
                'max_cases': validation.features.get('max_cases', -1) if features_enabled else 0
            },
            'expiry': {
                'expires_at': validation.expires_at.isoformat() if validation.expires_at else None,
                'days_remaining': days_remaining,
                'is_expired': is_expired_nist,
                'is_expiring_soon': is_expiring_soon_nist
            },
            'server': {
                'last_check': server_info.get('last_check'),
                'last_status': server_info.get('last_status'),
                'in_grace_period': server_info.get('in_grace_period', False),
                'grace_days_remaining': server_info.get('grace_days_remaining'),
                'needs_checkin': ActivationServerClient.needs_checkin(),
                'server_url': server_info.get('server_url', 'activation.casescope.net')
            },
            'time_verification': {
                'nist_verified': nist_result.success,
                'servers_agreed': nist_result.servers_agreed,
                'local_time_trusted': nist_result.is_local_time_trusted,
                'time_offset_seconds': nist_result.offset_seconds if nist_result.success else None
            },
            'warnings': cls.get_license_warnings()
        }
    
    @classmethod
    def _get_status_label(cls, status: str) -> str:
        """Get human-readable label for status."""
        labels = {
            ActivationStatus.NOT_ACTIVATED: 'Not Activated',
            ActivationStatus.ACTIVATED: 'Activated',
            ActivationStatus.EXPIRING_SOON: 'Expiring Soon',
            ActivationStatus.EXPIRED: 'Expired',
            ActivationStatus.VERIFICATION_FAILED: 'Verification Failed',
            ActivationStatus.REVOKED: 'Revoked',
            ActivationStatus.GRACE_PERIOD: 'Offline Mode',
            ActivationStatus.GRACE_EXPIRED: 'Grace Period Expired',
            ActivationStatus.INVALID: 'Invalid License',
        }
        return labels.get(status, 'Unknown')
    
    @classmethod
    def _get_status_css_class(cls, status: str) -> str:
        """Get CSS class for status styling."""
        classes = {
            ActivationStatus.NOT_ACTIVATED: 'not-activated',
            ActivationStatus.ACTIVATED: 'activated',
            ActivationStatus.EXPIRING_SOON: 'expiring-soon',
            ActivationStatus.EXPIRED: 'expired',
            ActivationStatus.VERIFICATION_FAILED: 'verification-failed',
            ActivationStatus.REVOKED: 'revoked',
            ActivationStatus.GRACE_PERIOD: 'grace-period',
            ActivationStatus.GRACE_EXPIRED: 'grace-expired',
            ActivationStatus.INVALID: 'invalid',
        }
        return classes.get(status, 'unknown')
    
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
            'features': validation.features,
            'expires_at': validation.expires_at.isoformat() + 'Z' if validation.expires_at else None,
            'fingerprint_components': fingerprint.get('components', {})
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
