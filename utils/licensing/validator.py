"""License Validator Module

Validates signed license files using Ed25519 public key cryptography.
"""

import base64
import hashlib
import json
import logging
import os
from datetime import datetime
from typing import Dict, Optional, Tuple

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

from utils.licensing.fingerprint import MachineFingerprint

logger = logging.getLogger(__name__)

# License file location
LICENSE_FILE_PATH = '/opt/casescope/license.json'

# Setting key for public key storage
LICENSE_PUBLIC_KEY_SETTING = 'license_public_key'


class LicenseValidationResult:
    """Result of license validation."""
    
    def __init__(self):
        self.is_valid = False
        self.error_message: Optional[str] = None
        self.license_id: Optional[str] = None
        self.customer_id: Optional[str] = None
        self.customer_name: Optional[str] = None
        self.issued_at: Optional[datetime] = None
        self.expires_at: Optional[datetime] = None
        self.features: Dict[str, bool] = {}
        self.fingerprint_match_count: int = 0
        self.fingerprint_matched_components: list = []
        self.days_until_expiry: Optional[int] = None
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for API responses."""
        return {
            'is_valid': self.is_valid,
            'error_message': self.error_message,
            'license_id': self.license_id,
            'customer_id': self.customer_id,
            'customer_name': self.customer_name,
            'issued_at': self.issued_at.isoformat() if self.issued_at else None,
            'expires_at': self.expires_at.isoformat() if self.expires_at else None,
            'features': self.features,
            'fingerprint_match_count': self.fingerprint_match_count,
            'fingerprint_matched_components': self.fingerprint_matched_components,
            'days_until_expiry': self.days_until_expiry
        }


class LicenseValidator:
    """
    Validates license files with Ed25519 signatures.
    
    License file format:
    {
        "license_id": "CS-2026-0001",
        "customer_id": "acme-corp",
        "customer_name": "ACME Corporation",
        "issued_at": "2026-01-30T00:00:00Z",
        "expires_at": "2027-01-30T00:00:00Z",
        "features": {
            "ai": true,
            "opencti": true,
            "max_cases": -1
        },
        "fingerprint_components": {
            "machine_uuid": "hash...",
            "disk_serial": "hash...",
            "mac_address": "hash...",
            "cpu_model": "hash...",
            "installation_id": "hash..."
        },
        "signature": "base64-encoded-ed25519-signature"
    }
    """
    
    _cached_result: Optional[LicenseValidationResult] = None
    _cache_time: Optional[datetime] = None
    CACHE_DURATION_SECONDS = 300  # 5 minutes
    
    @classmethod
    def get_public_key_b64(cls) -> Optional[str]:
        """Get the public key from database or environment."""
        # First check environment variable (for backwards compatibility)
        env_key = os.environ.get('CASESCOPE_LICENSE_PUBLIC_KEY')
        if env_key:
            return env_key
        
        # Then check database
        try:
            from models.system_settings import SystemSettings
            db_key = SystemSettings.get(LICENSE_PUBLIC_KEY_SETTING)
            if db_key:
                return db_key
        except Exception as e:
            logger.debug(f"[License] Could not read public key from database: {e}")
        
        return None
    
    @classmethod
    def set_public_key(cls, public_key_b64: str) -> Tuple[bool, str]:
        """
        Set the public key in the database.
        
        Args:
            public_key_b64: Base64-encoded Ed25519 public key
            
        Returns:
            tuple: (success, message)
        """
        # Validate the key format
        try:
            key_bytes = base64.b64decode(public_key_b64)
            if len(key_bytes) != 32:
                return False, "Invalid key length (Ed25519 public keys are 32 bytes)"
            # Try to load it to verify format
            Ed25519PublicKey.from_public_bytes(key_bytes)
        except Exception as e:
            return False, f"Invalid public key format: {e}"
        
        # Save to database
        try:
            from models.system_settings import SystemSettings
            SystemSettings.set(LICENSE_PUBLIC_KEY_SETTING, public_key_b64, value_type='string')
            cls.clear_cache()
            logger.info("[License] Public key updated successfully")
            return True, "Public key saved successfully"
        except Exception as e:
            logger.error(f"[License] Failed to save public key: {e}")
            return False, f"Failed to save public key: {e}"
    
    @classmethod
    def is_public_key_configured(cls) -> bool:
        """Check if a public key is configured."""
        return cls.get_public_key_b64() is not None
    
    @classmethod
    def get_public_key(cls) -> Optional[Ed25519PublicKey]:
        """Load the public key from database or environment."""
        try:
            public_key_b64 = cls.get_public_key_b64()
            
            if not public_key_b64:
                logger.warning("[License] Public key not configured")
                return None
            
            key_bytes = base64.b64decode(public_key_b64)
            return Ed25519PublicKey.from_public_bytes(key_bytes)
            
        except Exception as e:
            logger.error(f"[License] Failed to load public key: {e}")
            return None
    
    @classmethod
    def validate(cls, force_refresh: bool = False) -> LicenseValidationResult:
        """
        Validate the installed license file.
        
        Args:
            force_refresh: Bypass cache and re-validate
            
        Returns:
            LicenseValidationResult with validation status
        """
        # Check cache
        if not force_refresh and cls._cached_result and cls._cache_time:
            elapsed = (datetime.utcnow() - cls._cache_time).total_seconds()
            if elapsed < cls.CACHE_DURATION_SECONDS:
                return cls._cached_result
        
        result = LicenseValidationResult()
        
        # Check if license file exists
        if not os.path.exists(LICENSE_FILE_PATH):
            result.error_message = "No license file found"
            cls._update_cache(result)
            return result
        
        # Load license file
        try:
            with open(LICENSE_FILE_PATH, 'r') as f:
                license_data = json.load(f)
        except json.JSONDecodeError as e:
            result.error_message = f"Invalid license file format: {e}"
            cls._update_cache(result)
            return result
        except Exception as e:
            result.error_message = f"Failed to read license file: {e}"
            cls._update_cache(result)
            return result
        
        # Validate license structure
        validation_error = cls._validate_license_structure(license_data)
        if validation_error:
            result.error_message = validation_error
            cls._update_cache(result)
            return result
        
        # Verify signature
        signature_valid, sig_error = cls._verify_signature(license_data)
        if not signature_valid:
            result.error_message = sig_error or "Invalid license signature"
            cls._update_cache(result)
            return result
        
        # Parse dates
        try:
            result.issued_at = datetime.fromisoformat(license_data['issued_at'].replace('Z', '+00:00'))
            result.expires_at = datetime.fromisoformat(license_data['expires_at'].replace('Z', '+00:00'))
        except (ValueError, KeyError) as e:
            result.error_message = f"Invalid date format in license: {e}"
            cls._update_cache(result)
            return result
        
        # Check expiry
        now = datetime.utcnow().replace(tzinfo=result.expires_at.tzinfo)
        if now > result.expires_at:
            result.error_message = f"License expired on {result.expires_at.strftime('%Y-%m-%d')}"
            result.days_until_expiry = 0
            cls._update_cache(result)
            return result
        
        result.days_until_expiry = (result.expires_at - now).days
        
        # Verify fingerprint
        fingerprint_components = license_data.get('fingerprint_components', {})
        fp_valid, match_count, matched = MachineFingerprint.match_fingerprint(fingerprint_components)
        
        result.fingerprint_match_count = match_count
        result.fingerprint_matched_components = matched
        
        if not fp_valid:
            result.error_message = (
                f"Machine fingerprint mismatch: {match_count}/{MachineFingerprint.TOTAL_COMPONENTS} "
                f"components matched (need {MachineFingerprint.REQUIRED_MATCHES})"
            )
            cls._update_cache(result)
            return result
        
        # License is valid - populate result
        result.is_valid = True
        result.license_id = license_data.get('license_id')
        result.customer_id = license_data.get('customer_id')
        result.customer_name = license_data.get('customer_name')
        result.features = license_data.get('features', {})
        
        logger.info(f"[License] Valid license for {result.customer_name} "
                   f"(expires in {result.days_until_expiry} days)")
        
        cls._update_cache(result)
        return result
    
    @classmethod
    def _update_cache(cls, result: LicenseValidationResult):
        """Update the validation cache."""
        cls._cached_result = result
        cls._cache_time = datetime.utcnow()
    
    @classmethod
    def clear_cache(cls):
        """Clear the validation cache."""
        cls._cached_result = None
        cls._cache_time = None
    
    @classmethod
    def _validate_license_structure(cls, data: Dict) -> Optional[str]:
        """Validate required fields are present."""
        required_fields = ['license_id', 'customer_id', 'issued_at', 'expires_at', 
                          'features', 'fingerprint_components', 'signature']
        
        for field in required_fields:
            if field not in data:
                return f"Missing required field: {field}"
        
        if not isinstance(data['features'], dict):
            return "Features must be a dictionary"
        
        if not isinstance(data['fingerprint_components'], dict):
            return "Fingerprint components must be a dictionary"
        
        return None
    
    @classmethod
    def _verify_signature(cls, license_data: Dict) -> Tuple[bool, Optional[str]]:
        """
        Verify the Ed25519 signature.
        
        The signature is computed over the JSON-serialized license data
        (excluding the signature field itself).
        """
        try:
            public_key = cls.get_public_key()
            if not public_key:
                return False, "License verification not configured (missing public key)"
            
            # Extract signature
            signature_b64 = license_data.get('signature', '')
            try:
                signature = base64.b64decode(signature_b64)
            except Exception:
                return False, "Invalid signature encoding"
            
            # Reconstruct signed data (everything except signature)
            signed_data = {k: v for k, v in license_data.items() if k != 'signature'}
            # Sort keys for deterministic serialization
            message = json.dumps(signed_data, sort_keys=True, separators=(',', ':')).encode()
            
            # Verify signature
            try:
                public_key.verify(signature, message)
                return True, None
            except InvalidSignature:
                return False, "Signature verification failed"
            
        except Exception as e:
            logger.error(f"[License] Signature verification error: {e}")
            return False, f"Signature verification error: {e}"
    
    @classmethod
    def install_license(cls, license_content: str) -> Tuple[bool, str]:
        """
        Install a new license file.
        
        Args:
            license_content: JSON string of the license file
            
        Returns:
            tuple: (success, message)
        """
        try:
            # Parse and validate
            license_data = json.loads(license_content)
        except json.JSONDecodeError as e:
            return False, f"Invalid JSON format: {e}"
        
        # Validate structure
        error = cls._validate_license_structure(license_data)
        if error:
            return False, error
        
        # Verify signature before saving
        sig_valid, sig_error = cls._verify_signature(license_data)
        if not sig_valid:
            return False, sig_error or "Invalid signature"
        
        # Check fingerprint before saving
        fingerprint_components = license_data.get('fingerprint_components', {})
        fp_valid, match_count, matched = MachineFingerprint.match_fingerprint(fingerprint_components)
        
        if not fp_valid:
            return False, (
                f"License is for a different machine: {match_count}/{MachineFingerprint.TOTAL_COMPONENTS} "
                f"fingerprint components matched (need {MachineFingerprint.REQUIRED_MATCHES})"
            )
        
        # Check expiry
        try:
            expires_at = datetime.fromisoformat(license_data['expires_at'].replace('Z', '+00:00'))
            now = datetime.utcnow().replace(tzinfo=expires_at.tzinfo)
            if now > expires_at:
                return False, f"License has already expired on {expires_at.strftime('%Y-%m-%d')}"
        except ValueError as e:
            return False, f"Invalid expiry date format: {e}"
        
        # Save license file
        try:
            with open(LICENSE_FILE_PATH, 'w') as f:
                json.dump(license_data, f, indent=2)
            
            os.chmod(LICENSE_FILE_PATH, 0o644)
            
            # Clear cache to force re-validation
            cls.clear_cache()
            
            customer_name = license_data.get('customer_name', 'Unknown')
            logger.info(f"[License] Successfully installed license for {customer_name}")
            
            return True, f"License installed successfully for {customer_name}"
            
        except Exception as e:
            logger.error(f"[License] Failed to save license file: {e}")
            return False, f"Failed to save license file: {e}"
    
    @classmethod
    def is_feature_licensed(cls, feature: str) -> bool:
        """
        Check if a specific feature is licensed.
        
        Args:
            feature: Feature name (e.g., 'ai', 'opencti')
            
        Returns:
            bool: True if feature is licensed
        """
        result = cls.validate()
        if not result.is_valid:
            return False
        
        return result.features.get(feature, False)
    
    @classmethod
    def get_license_info(cls) -> Dict:
        """Get current license information."""
        result = cls.validate()
        return result.to_dict()
