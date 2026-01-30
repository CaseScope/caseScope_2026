"""License Manager Module

High-level API for license management and activation status.
"""

import logging
from datetime import datetime
from typing import Dict, Optional

from utils.licensing.fingerprint import MachineFingerprint
from utils.licensing.validator import LicenseValidator, LicenseValidationResult

logger = logging.getLogger(__name__)


class ActivationStatus:
    """Activation status constants."""
    NOT_ACTIVATED = 'not_activated'
    ACTIVATED = 'activated'
    EXPIRED = 'expired'
    INVALID = 'invalid'


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
            dict: Activation status, license details, features, expiry info
        """
        validation = LicenseValidator.validate()
        status = cls.get_activation_status()
        
        return {
            'status': status,
            'is_activated': validation.is_valid,
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
    def get_license_warnings(cls) -> list:
        """
        Get any warnings about the current license.
        
        Returns:
            list: Warning messages (empty if no warnings)
        """
        warnings = []
        validation = LicenseValidator.validate()
        
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
        
        return warnings
