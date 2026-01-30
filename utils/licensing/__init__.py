"""CaseScope Licensing System

Provides machine-bound license validation for feature activation.
"""

from utils.licensing.license_manager import LicenseManager
from utils.licensing.fingerprint import MachineFingerprint
from utils.licensing.validator import LicenseValidator

__all__ = ['LicenseManager', 'MachineFingerprint', 'LicenseValidator']
