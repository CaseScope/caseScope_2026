"""Shared helpers for route modules."""

from flask import jsonify

DEFAULT_ARCHIVE_PATH = "/archive"
DEFAULT_ORIGINALS_PATH = "/originals"


def _viewer_write_error(message: str = "Viewers cannot modify case data"):
    return jsonify({"success": False, "error": message}), 403


def _is_license_feature_active(feature: str) -> bool:
    """Check whether a licensed feature is currently active."""
    from utils.licensing.license_manager import LicenseManager

    return LicenseManager.is_feature_activated(feature)


def _is_threat_intel_license_active() -> bool:
    """Shared entitlement gate for OpenCTI and MISP integrations."""
    return _is_license_feature_active("opencti")
