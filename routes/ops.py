"""Operational settings, logs, and audit API routes."""

import logging
import os

from flask import Blueprint, jsonify, request
from flask_login import current_user, login_required

from models.database import db
from models.file_audit_log import FileAuditLog
from routes.route_helpers import DEFAULT_ARCHIVE_PATH, DEFAULT_ORIGINALS_PATH

logger = logging.getLogger(__name__)

ops_bp = Blueprint("ops", __name__, url_prefix="/api")


@ops_bp.route("/logs/audit/<category>")
@login_required
def get_audit_logs(category):
    """Get paginated audit logs by category."""
    try:
        if not current_user.is_administrator:
            return jsonify({"success": False, "error": "Administrator access required"}), 403

        page = request.args.get("page", 1, type=int)
        per_page = min(request.args.get("per_page", 25, type=int), 100)
        search = request.args.get("search", "").strip()

        if category == "file_audit_log":
            query = FileAuditLog.query

            if search:
                search_pattern = f"%{search}%"
                query = query.filter(
                    db.or_(
                        FileAuditLog.filename.ilike(search_pattern),
                        FileAuditLog.sha256_hash.ilike(search_pattern),
                        FileAuditLog.performed_by.ilike(search_pattern),
                        FileAuditLog.notes.ilike(search_pattern),
                        FileAuditLog.case_uuid.ilike(search_pattern),
                    )
                )

            query = query.order_by(FileAuditLog.performed_at.desc())
            pagination = query.paginate(page=page, per_page=per_page, error_out=False)
            logs = [log.to_dict() for log in pagination.items]

            return jsonify(
                {
                    "success": True,
                    "logs": logs,
                    "total": pagination.total,
                    "pages": pagination.pages,
                    "page": page,
                    "per_page": per_page,
                }
            )

        return jsonify(
            {
                "success": False,
                "error": f"Unknown audit log category: {category}",
            }
        ), 400

    except Exception as e:
        logger.error("Error fetching audit logs: %s", e)
        return jsonify({"success": False, "error": str(e)}), 500


@ops_bp.route("/settings/logging", methods=["GET"])
@login_required
def get_logging_settings():
    """Get logging configuration settings."""
    if not current_user.is_administrator:
        return jsonify({"success": False, "error": "Administrator access required"}), 403

    try:
        from models.system_settings import SettingKeys, SystemSettings
        from utils.logger import DEFAULT_LOG_PATH, get_log_files_info

        settings = {
            "log_level": SystemSettings.get(SettingKeys.LOG_LEVEL, "INFO"),
            "log_path": SystemSettings.get(SettingKeys.LOG_PATH, DEFAULT_LOG_PATH),
            "log_retention_days": SystemSettings.get(SettingKeys.LOG_RETENTION_DAYS, 90),
            "log_max_size_mb": SystemSettings.get(SettingKeys.LOG_MAX_SIZE_MB, 100),
            "audit_view_permission": SystemSettings.get(SettingKeys.AUDIT_VIEW_PERMISSION, "administrator"),
        }

        log_info = get_log_files_info()

        return jsonify({"success": True, "settings": settings, "log_info": log_info})
    except Exception as e:
        logger.error("Error getting logging settings: %s", e)
        return jsonify({"success": False, "error": str(e)}), 500


@ops_bp.route("/settings/logging", methods=["POST"])
@login_required
def set_logging_settings():
    """Set logging configuration settings."""
    if not current_user.is_administrator:
        return jsonify({"success": False, "error": "Administrator access required"}), 403

    try:
        from models.audit_log import audit_setting_change
        from models.system_settings import SettingKeys, SystemSettings
        from utils.logger import ensure_log_directories, invalidate_settings_cache

        data = request.get_json()
        valid_levels = ["DEBUG", "INFO", "WARNING", "ERROR"]

        if "log_level" in data:
            level = data["log_level"].upper()
            if level not in valid_levels:
                return jsonify(
                    {
                        "success": False,
                        "error": f"Invalid log level. Must be one of: {valid_levels}",
                    }
                ), 400

            old_value = SystemSettings.get(SettingKeys.LOG_LEVEL, "INFO")
            if old_value != level:
                SystemSettings.set(
                    SettingKeys.LOG_LEVEL,
                    level,
                    value_type="string",
                    updated_by=current_user.username,
                )
                audit_setting_change("log_level", old_value, level)

        if "log_path" in data:
            path = data["log_path"].strip()
            if not path.startswith("/"):
                return jsonify({"success": False, "error": "Log path must be an absolute path"}), 400

            try:
                os.makedirs(path, exist_ok=True)
                test_file = os.path.join(path, ".write_test")
                with open(test_file, "w") as f:
                    f.write("test")
                os.remove(test_file)
            except Exception as e:
                return jsonify({"success": False, "error": f"Log path is not writable: {e}"}), 400

            old_value = SystemSettings.get(SettingKeys.LOG_PATH, "/opt/casescope/logs")
            if old_value != path:
                SystemSettings.set(
                    SettingKeys.LOG_PATH,
                    path,
                    value_type="string",
                    updated_by=current_user.username,
                )
                audit_setting_change("log_path", old_value, path)

        if "log_retention_days" in data:
            try:
                days = int(data["log_retention_days"])
                if days < 1 or days > 365:
                    return jsonify(
                        {
                            "success": False,
                            "error": "Retention days must be between 1 and 365",
                        }
                    ), 400

                old_value = SystemSettings.get(SettingKeys.LOG_RETENTION_DAYS, 90)
                if old_value != days:
                    SystemSettings.set(
                        SettingKeys.LOG_RETENTION_DAYS,
                        days,
                        value_type="int",
                        updated_by=current_user.username,
                    )
                    audit_setting_change("log_retention_days", old_value, days)
            except (ValueError, TypeError):
                return jsonify({"success": False, "error": "Invalid retention days value"}), 400

        if "log_max_size_mb" in data:
            try:
                size = int(data["log_max_size_mb"])
                if size < 1 or size > 1000:
                    return jsonify(
                        {
                            "success": False,
                            "error": "Max size must be between 1 and 1000 MB",
                        }
                    ), 400

                old_value = SystemSettings.get(SettingKeys.LOG_MAX_SIZE_MB, 100)
                if old_value != size:
                    SystemSettings.set(
                        SettingKeys.LOG_MAX_SIZE_MB,
                        size,
                        value_type="int",
                        updated_by=current_user.username,
                    )
                    audit_setting_change("log_max_size_mb", old_value, size)
            except (ValueError, TypeError):
                return jsonify({"success": False, "error": "Invalid max size value"}), 400

        invalidate_settings_cache()
        ensure_log_directories()

        return jsonify({"success": True, "message": "Logging settings saved"})

    except Exception as e:
        logger.error("Error saving logging settings: %s", e)
        return jsonify({"success": False, "error": str(e)}), 500


@ops_bp.route("/settings/logging/test-path", methods=["POST"])
@login_required
def test_log_path():
    """Test if a log path is valid and writable."""
    if not current_user.is_administrator:
        return jsonify({"success": False, "error": "Administrator access required"}), 403

    try:
        data = request.get_json()
        path = data.get("path", "").strip()

        if not path:
            return jsonify({"success": False, "error": "Path is required"}), 400

        if not path.startswith("/"):
            return jsonify({"success": False, "error": "Path must be absolute"}), 400

        try:
            os.makedirs(path, exist_ok=True)
        except Exception as e:
            return jsonify({"success": False, "error": f"Cannot create directory: {e}"}), 400

        try:
            test_file = os.path.join(path, ".write_test")
            with open(test_file, "w") as f:
                f.write("test")
            os.remove(test_file)
        except Exception as e:
            return jsonify({"success": False, "error": f"Cannot write to directory: {e}"}), 400

        return jsonify({"success": True, "message": "Path is valid and writable"})

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@ops_bp.route("/settings/paths", methods=["GET"])
@login_required
def get_folder_path_settings():
    """Get folder path configuration settings."""
    if not current_user.is_administrator:
        return jsonify({"success": False, "error": "Administrator access required"}), 403

    try:
        from models.system_settings import SettingKeys, SystemSettings

        settings = {
            "archive_path": SystemSettings.get(SettingKeys.ARCHIVE_PATH, DEFAULT_ARCHIVE_PATH),
            "originals_path": SystemSettings.get(SettingKeys.ORIGINALS_PATH, DEFAULT_ORIGINALS_PATH),
        }

        return jsonify({"success": True, "settings": settings})
    except Exception as e:
        logger.error("Error getting folder path settings: %s", e)
        return jsonify({"success": False, "error": str(e)}), 500


@ops_bp.route("/settings/paths", methods=["POST"])
@login_required
def set_folder_path_settings():
    """Set folder path configuration settings."""
    if not current_user.is_administrator:
        return jsonify({"success": False, "error": "Administrator access required"}), 403

    try:
        from models.audit_log import audit_setting_change
        from models.system_settings import SettingKeys, SystemSettings

        data = request.get_json()

        if "archive_path" in data:
            path = data["archive_path"].strip()

            if not path:
                return jsonify({"success": False, "error": "Archive path is required"}), 400

            if not path.startswith("/"):
                return jsonify({"success": False, "error": "Archive path must be an absolute path"}), 400

            if not os.path.exists(path):
                return jsonify({"success": False, "error": f"Path does not exist: {path}"}), 400

            if not os.path.isdir(path):
                return jsonify({"success": False, "error": f"Path is not a directory: {path}"}), 400

            if not os.access(path, os.R_OK):
                return jsonify({"success": False, "error": f"Path is not readable: {path}"}), 400

            old_value = SystemSettings.get(SettingKeys.ARCHIVE_PATH, DEFAULT_ARCHIVE_PATH)
            if old_value != path:
                SystemSettings.set(
                    SettingKeys.ARCHIVE_PATH,
                    path,
                    value_type="string",
                    updated_by=current_user.username,
                )
                audit_setting_change("archive_path", old_value, path)

        if "originals_path" in data:
            path = data["originals_path"].strip()

            if not path:
                return jsonify({"success": False, "error": "Originals path is required"}), 400

            if not path.startswith("/"):
                return jsonify({"success": False, "error": "Originals path must be an absolute path"}), 400

            if not os.path.exists(path):
                return jsonify({"success": False, "error": f"Path does not exist: {path}"}), 400

            if not os.path.isdir(path):
                return jsonify({"success": False, "error": f"Path is not a directory: {path}"}), 400

            if not os.access(path, os.R_OK):
                return jsonify({"success": False, "error": f"Path is not readable: {path}"}), 400

            old_value = SystemSettings.get(SettingKeys.ORIGINALS_PATH, DEFAULT_ORIGINALS_PATH)
            if old_value != path:
                SystemSettings.set(
                    SettingKeys.ORIGINALS_PATH,
                    path,
                    value_type="string",
                    updated_by=current_user.username,
                )
                audit_setting_change("originals_path", old_value, path)

        return jsonify({"success": True, "message": "Folder path settings saved"})

    except Exception as e:
        logger.error("Error saving folder path settings: %s", e)
        return jsonify({"success": False, "error": str(e)}), 500


@ops_bp.route("/settings/paths/test", methods=["POST"])
@login_required
def test_folder_path():
    """Test if a folder path exists and is accessible."""
    if not current_user.is_administrator:
        return jsonify({"success": False, "error": "Administrator access required"}), 403

    try:
        data = request.get_json()
        path = data.get("path", "").strip()

        if not path:
            return jsonify({"success": False, "error": "Path is required"}), 400

        if not path.startswith("/"):
            return jsonify({"success": False, "error": "Path must be an absolute path"}), 400

        if not os.path.exists(path):
            return jsonify({"success": False, "error": f"Path does not exist: {path}"}), 400

        if not os.path.isdir(path):
            return jsonify({"success": False, "error": f"Path is not a directory: {path}"}), 400

        if not os.access(path, os.R_OK):
            return jsonify({"success": False, "error": f"Path is not readable: {path}"}), 400

        return jsonify({"success": True, "message": "Path exists and is accessible"})

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@ops_bp.route("/logs/view/<path:log_path>", methods=["GET"])
@login_required
def view_log_file(log_path):
    """View contents of a log file."""
    if not current_user.is_administrator:
        return jsonify({"success": False, "error": "Administrator access required"}), 403

    try:
        from utils.logger import get_log_path, read_log_tail

        lines = request.args.get("lines", 100, type=int)
        lines = min(lines, 1000)

        base_path = get_log_path()
        full_path = os.path.join(base_path, log_path)
        full_path = os.path.realpath(full_path)

        if not full_path.startswith(os.path.realpath(base_path)):
            return jsonify({"success": False, "error": "Invalid log path"}), 400

        if not os.path.exists(full_path):
            return jsonify({"success": False, "error": "Log file not found"}), 404

        log_lines = read_log_tail(full_path, lines)

        return jsonify(
            {
                "success": True,
                "path": log_path,
                "lines": log_lines,
                "total_lines": len(log_lines),
            }
        )

    except Exception as e:
        logger.error("Error viewing log file: %s", e)
        return jsonify({"success": False, "error": str(e)}), 500


@ops_bp.route("/logs/case/<case_uuid>", methods=["GET"])
@login_required
def get_case_logs(case_uuid):
    """Get log files for a specific case."""
    try:
        from utils.logger import get_log_files_info

        log_info = get_log_files_info(case_uuid)

        return jsonify({"success": True, "case_uuid": case_uuid, "log_info": log_info})

    except Exception as e:
        logger.error("Error getting case logs: %s", e)
        return jsonify({"success": False, "error": str(e)}), 500


@ops_bp.route("/audit-log", methods=["GET"])
@login_required
def get_audit_log():
    """Get audit log entries with filtering."""
    if not current_user.is_administrator:
        return jsonify({"success": False, "error": "Administrator access required"}), 403

    try:
        from datetime import datetime, timedelta

        from models.audit_log import AuditAction, AuditEntityType, AuditLog

        page = request.args.get("page", 1, type=int)
        per_page = min(request.args.get("per_page", 50, type=int), 200)
        entity_type = request.args.get("entity_type")
        action = request.args.get("action")
        username = request.args.get("username")
        case_uuid = request.args.get("case_uuid")
        search = request.args.get("search", "").strip()
        days = request.args.get("days", type=int)

        query = AuditLog.query

        if entity_type:
            query = query.filter(AuditLog.entity_type == entity_type)
        if action:
            query = query.filter(AuditLog.action == action)
        if username:
            query = query.filter(AuditLog.username == username)
        if case_uuid:
            query = query.filter(AuditLog.case_uuid == case_uuid)
        if days:
            cutoff = datetime.utcnow() - timedelta(days=days)
            query = query.filter(AuditLog.timestamp >= cutoff)
        if search:
            search_pattern = f"%{search}%"
            query = query.filter(
                db.or_(
                    AuditLog.entity_name.ilike(search_pattern),
                    AuditLog.old_value.ilike(search_pattern),
                    AuditLog.new_value.ilike(search_pattern),
                    AuditLog.username.ilike(search_pattern),
                )
            )

        query = query.order_by(AuditLog.timestamp.desc())
        pagination = query.paginate(page=page, per_page=per_page, error_out=False)

        return jsonify(
            {
                "success": True,
                "entries": [e.to_dict() for e in pagination.items],
                "total": pagination.total,
                "pages": pagination.pages,
                "page": page,
                "per_page": per_page,
                "filters": {
                    "entity_types": AuditEntityType.all(),
                    "actions": AuditAction.all(),
                },
            }
        )

    except Exception as e:
        logger.error("Error getting audit log: %s", e)
        return jsonify({"success": False, "error": str(e)}), 500


@ops_bp.route("/audit-log/entity/<entity_type>/<entity_id>", methods=["GET"])
@login_required
def get_entity_audit_log(entity_type, entity_id):
    """Get audit log entries for a specific entity."""
    try:
        from models.audit_log import AuditLog

        limit = request.args.get("limit", 50, type=int)
        limit = min(limit, 200)

        entries = AuditLog.get_by_entity(entity_type, entity_id, limit=limit)

        return jsonify(
            {
                "success": True,
                "entity_type": entity_type,
                "entity_id": entity_id,
                "entries": [e.to_dict() for e in entries],
            }
        )

    except Exception as e:
        logger.error("Error getting entity audit log: %s", e)
        return jsonify({"success": False, "error": str(e)}), 500
