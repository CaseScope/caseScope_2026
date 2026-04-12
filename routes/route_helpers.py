"""Shared helpers for route modules."""

from flask import jsonify, session

DEFAULT_ARCHIVE_PATH = "/archive"
DEFAULT_ORIGINALS_PATH = "/originals"
API_TASK_SESSION_KEY = "api_task_access"


def _viewer_write_error(message: str = "Viewers cannot modify case data"):
    return jsonify({"success": False, "error": message}), 403


def _is_license_feature_active(feature: str) -> bool:
    """Check whether a licensed feature is currently active."""
    from utils.licensing.license_manager import LicenseManager

    return LicenseManager.is_feature_activated(feature)


def _is_threat_intel_license_active() -> bool:
    """Shared entitlement gate for OpenCTI and MISP integrations."""
    return _is_license_feature_active("opencti")


def _remember_task_access(task_id: str, case_id=None):
    tracked = session.get(API_TASK_SESSION_KEY, {})
    tracked[task_id] = {"case_id": case_id}
    if len(tracked) > 100:
        tracked = dict(list(tracked.items())[-100:])
    session[API_TASK_SESSION_KEY] = tracked
    session.modified = True


def _task_access_allowed(task_id: str, case_id=None) -> bool:
    tracked = session.get(API_TASK_SESSION_KEY, {})
    task_meta = tracked.get(task_id)
    if not task_meta:
        return False
    if case_id is not None and task_meta.get("case_id") not in (None, case_id):
        return False
    return True


def _get_parser_hints_for_case_file(case_file) -> list:
    """Resolve parser hints for a persisted CaseFile selection label."""
    from parsers.catalog import get_parser_hints_for_upload_type

    return get_parser_hints_for_upload_type((case_file.file_type or "").strip())


def _default_upload_type_label() -> str:
    """Return the canonical fallback upload label."""
    from parsers.catalog import AUTO_DETECT_UPLOAD_LABEL

    return AUTO_DETECT_UPLOAD_LABEL
