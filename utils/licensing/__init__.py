"""CaseScope Licensing System

Provides machine-bound license validation for feature activation.
Includes server-side verification with activation.casescope.net.
"""

from utils.licensing.license_manager import LicenseManager
from utils.licensing.fingerprint import MachineFingerprint
from utils.licensing.validator import LicenseValidator
from utils.licensing.server_client import ActivationServerClient

__all__ = ['LicenseManager', 'MachineFingerprint', 'LicenseValidator', 'ActivationServerClient']
