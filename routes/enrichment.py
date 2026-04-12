"""Threat-intelligence settings and status API routes."""

import logging

from flask import Blueprint, jsonify, request
from flask_login import current_user, login_required

from routes.route_helpers import _is_license_feature_active, _is_threat_intel_license_active

logger = logging.getLogger(__name__)

enrichment_bp = Blueprint("enrichment", __name__, url_prefix="/api")


@enrichment_bp.route("/settings/opencti", methods=["GET"])
@login_required
def get_opencti_settings():
    """Get OpenCTI integration settings."""
    if not current_user.is_administrator:
        return jsonify({"success": False, "error": "Administrator access required"}), 403

    try:
        from models.system_settings import get_opencti_settings as load_opencti_settings

        feature_active = _is_license_feature_active("opencti")

        return jsonify(
            {
                "success": True,
                "settings": load_opencti_settings(feature_active=feature_active),
                "feature_active": feature_active,
            }
        )
    except Exception as e:
        logger.error("[OpenCTI] Error getting settings: %s", e)
        return jsonify({"success": False, "error": str(e)}), 500


@enrichment_bp.route("/settings/opencti", methods=["POST"])
@login_required
def set_opencti_settings():
    """Set OpenCTI integration settings."""
    if not current_user.is_administrator:
        return jsonify({"success": False, "error": "Administrator access required"}), 403
    if not _is_license_feature_active("opencti"):
        return jsonify(
            {
                "success": False,
                "error": "OpenCTI settings are locked until a valid active OpenCTI license is available",
            }
        ), 403

    try:
        from models.system_settings import save_opencti_settings

        data = request.get_json() or {}
        replace_api_key = bool(data.get("replace_api_key")) or bool((data.get("api_key") or "").strip())

        save_opencti_settings(
            enabled=data["enabled"] if "enabled" in data else None,
            url=data["url"] if "url" in data else None,
            api_key=data.get("api_key", ""),
            replace_api_key=replace_api_key,
            ssl_verify=data["ssl_verify"] if "ssl_verify" in data else None,
            auto_enrich=data["auto_enrich"] if "auto_enrich" in data else None,
            rag_sync=data["rag_sync"] if "rag_sync" in data else None,
            updated_by=current_user.username,
        )

        logger.info("[OpenCTI] Settings updated by %s", current_user.username)

        return jsonify({"success": True, "message": "OpenCTI settings saved"})

    except Exception as e:
        logger.error("[OpenCTI] Error saving settings: %s", e)
        return jsonify({"success": False, "error": str(e)}), 500


@enrichment_bp.route("/settings/opencti/test", methods=["POST"])
@login_required
def test_opencti_connection():
    """Test OpenCTI connection with provided or saved credentials."""
    if not current_user.is_administrator:
        return jsonify({"success": False, "error": "Administrator access required"}), 403
    if not _is_license_feature_active("opencti"):
        return jsonify(
            {
                "success": False,
                "message": "OpenCTI settings are locked until a valid active OpenCTI license is available",
            }
        ), 403

    try:
        from models.system_settings import SettingKeys, SystemSettings, get_opencti_api_key
        from utils.opencti import OpenCTIClient

        data = request.get_json() or {}

        url = data.get("url", "").strip() or SystemSettings.get(SettingKeys.OPENCTI_URL, "")
        api_key = data.get("api_key", "").strip() or get_opencti_api_key(log_errors=True)
        ssl_verify = data.get("ssl_verify", SystemSettings.get(SettingKeys.OPENCTI_SSL_VERIFY, False))

        if not url or not api_key:
            return jsonify({"success": False, "message": "URL and API key are required"})

        client = OpenCTIClient(url, api_key, ssl_verify)

        if client.init_error:
            return jsonify({"success": False, "message": f"Connection failed: {client.init_error}"})

        if client.ping():
            return jsonify(
                {
                    "success": True,
                    "message": "Connection successful! OpenCTI is accessible",
                }
            )

        return jsonify(
            {
                "success": False,
                "message": "Connection failed - Could not reach OpenCTI or invalid credentials",
            }
        )

    except Exception as e:
        logger.error("[OpenCTI] Connection test failed: %s", e)
        return jsonify({"success": False, "message": f"Connection failed: {str(e)}"})


@enrichment_bp.route("/opencti/status", methods=["GET"])
@login_required
def get_opencti_status():
    """Get current OpenCTI feature availability for UI gating."""
    try:
        from utils.feature_availability import FeatureAvailability

        summary = FeatureAvailability.get_status_summary()
        opencti_status = summary.get("opencti_status", {})
        return jsonify(
            {
                "success": True,
                "enabled": opencti_status.get("enabled", False),
                "licensed": opencti_status.get("licensed", False),
                "config_enabled": opencti_status.get("config_enabled", False),
                "setting_enabled": opencti_status.get("setting_enabled", False),
                "configured": opencti_status.get("configured", False),
                "reachable": opencti_status.get("reachable", False),
                "last_checked": opencti_status.get("last_checked"),
            }
        )
    except Exception as e:
        logger.error("[OpenCTI] Error getting status: %s", e)
        return jsonify({"success": False, "error": str(e)}), 500


@enrichment_bp.route("/opencti/connectors", methods=["GET"])
@login_required
def get_opencti_connectors():
    """Return OpenCTI connector metadata for admin visibility."""
    if not current_user.is_administrator:
        return jsonify({"success": False, "error": "Administrator access required"}), 403

    try:
        from utils.feature_availability import FeatureAvailability
        from utils.opencti import get_opencti_client

        summary = FeatureAvailability.get_status_summary()
        opencti_status = summary.get("opencti_status", {})

        if not opencti_status.get("licensed", False):
            return jsonify(
                {
                    "success": True,
                    "licensed": False,
                    "configured": opencti_status.get("configured", False),
                    "reachable": False,
                    "connectors": [],
                    "connector_summary": {
                        "total_connectors": 0,
                        "active_connectors": 0,
                        "by_type": {},
                    },
                }
            )

        client = get_opencti_client()
        if not client or client.init_error:
            return jsonify(
                {
                    "success": True,
                    "licensed": True,
                    "configured": opencti_status.get("configured", False),
                    "reachable": False,
                    "error": client.get_error() if client else "OpenCTI client unavailable",
                    "connectors": [],
                    "connector_summary": {
                        "total_connectors": 0,
                        "active_connectors": 0,
                        "by_type": {},
                    },
                }
            )

        connector_summary = client.get_connector_status_summary()
        return jsonify(
            {
                "success": True,
                "licensed": True,
                "configured": opencti_status.get("configured", False),
                "reachable": True,
                "connectors": connector_summary.get("connectors", []),
                "connector_summary": {
                    "total_connectors": connector_summary.get("total_connectors", 0),
                    "active_connectors": connector_summary.get("active_connectors", 0),
                    "by_type": connector_summary.get("by_type", {}),
                },
            }
        )
    except Exception as e:
        logger.error("[OpenCTI] Error getting connectors: %s", e)
        return jsonify({"success": False, "error": str(e)}), 500


@enrichment_bp.route("/settings/misp", methods=["GET"])
@login_required
def get_misp_settings():
    """Get MISP integration settings."""
    if not current_user.is_administrator:
        return jsonify({"success": False, "error": "Administrator access required"}), 403

    try:
        from models.system_settings import get_misp_settings as load_misp_settings

        feature_active = _is_threat_intel_license_active()
        return jsonify(
            {
                "success": True,
                "settings": load_misp_settings(feature_active=feature_active),
                "feature_active": feature_active,
            }
        )
    except Exception as e:
        logger.error("[MISP] Error getting settings: %s", e)
        return jsonify({"success": False, "error": str(e)}), 500


@enrichment_bp.route("/settings/misp", methods=["POST"])
@login_required
def set_misp_settings():
    """Set MISP integration settings."""
    if not current_user.is_administrator:
        return jsonify({"success": False, "error": "Administrator access required"}), 403
    if not _is_threat_intel_license_active():
        return jsonify(
            {
                "success": False,
                "error": "MISP settings are locked until a valid active threat intelligence license is available",
            }
        ), 403

    try:
        from models.system_settings import save_misp_settings

        data = request.get_json() or {}
        replace_api_key = bool(data.get("replace_api_key")) or bool((data.get("api_key") or "").strip())

        save_misp_settings(
            enabled=data["enabled"] if "enabled" in data else None,
            url=data["url"] if "url" in data else None,
            api_key=data.get("api_key", ""),
            replace_api_key=replace_api_key,
            ssl_verify=data["ssl_verify"] if "ssl_verify" in data else None,
            auto_enrich=data["auto_enrich"] if "auto_enrich" in data else None,
            updated_by=current_user.username,
        )

        logger.info("[MISP] Settings updated by %s", current_user.username)
        return jsonify({"success": True, "message": "MISP settings saved"})
    except Exception as e:
        logger.error("[MISP] Error saving settings: %s", e)
        return jsonify({"success": False, "error": str(e)}), 500


@enrichment_bp.route("/settings/misp/test", methods=["POST"])
@login_required
def test_misp_connection():
    """Test MISP connection with provided or saved credentials."""
    if not current_user.is_administrator:
        return jsonify({"success": False, "error": "Administrator access required"}), 403
    if not _is_threat_intel_license_active():
        return jsonify(
            {
                "success": False,
                "message": "MISP settings are locked until a valid active threat intelligence license is available",
            }
        ), 403

    try:
        from models.system_settings import SettingKeys, SystemSettings, get_misp_api_key
        from utils.misp import MISPClient

        data = request.get_json() or {}
        url = data.get("url", "").strip() or SystemSettings.get(SettingKeys.MISP_URL, "")
        api_key = data.get("api_key", "").strip() or get_misp_api_key(log_errors=True)
        ssl_verify = data.get("ssl_verify", SystemSettings.get(SettingKeys.MISP_SSL_VERIFY, False))

        if not url or not api_key:
            return jsonify({"success": False, "message": "URL and API key are required"})

        client = MISPClient(url, api_key, ssl_verify)
        if client.init_error:
            return jsonify({"success": False, "message": client.init_error})

        if client.ping():
            return jsonify(
                {
                    "success": True,
                    "message": "Connection successful! MISP is accessible",
                }
            )

        return jsonify({"success": False, "message": f"Connection failed: {client.get_error()}"})
    except Exception as e:
        logger.error("[MISP] Connection test failed: %s", e)
        return jsonify({"success": False, "message": f"Connection failed: {str(e)}"})


@enrichment_bp.route("/misp/status", methods=["GET"])
@login_required
def get_misp_status():
    """Get current MISP status for admin UI gating."""
    try:
        from utils.misp import get_misp_status_summary

        misp_status = get_misp_status_summary()
        return jsonify(
            {
                "success": True,
                "enabled": misp_status.get("enabled", False),
                "licensed": misp_status.get("licensed", False),
                "config_enabled": misp_status.get("config_enabled", False),
                "setting_enabled": misp_status.get("setting_enabled", False),
                "configured": misp_status.get("configured", False),
                "reachable": misp_status.get("reachable", False),
                "error": misp_status.get("error"),
            }
        )
    except Exception as e:
        logger.error("[MISP] Error getting status: %s", e)
        return jsonify({"success": False, "error": str(e)}), 500
