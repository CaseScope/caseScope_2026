"""Hunting support API routes."""

import logging

from flask import Blueprint, jsonify
from flask_login import current_user, login_required

from models.case import Case
from routes.route_helpers import _remember_task_access, _task_access_allowed, _viewer_write_error
from utils.forensic_chat_sources import get_browser_download_rows

logger = logging.getLogger(__name__)

hunting_bp = Blueprint("hunting", __name__, url_prefix="/api")


@hunting_bp.route("/hunting/browser/downloads/<int:case_id>")
@login_required
def get_browser_downloads(case_id):
    """Get user-initiated browser download events for a case."""
    try:
        case = Case.get_by_id(case_id)
        if not case:
            return jsonify({"success": False, "error": "Case not found"}), 404

        return jsonify(
            {
                "success": True,
                "case_id": case_id,
                **get_browser_download_rows(case_id, limit=10000),
            }
        )

    except Exception as e:
        logger.exception("Error getting browser downloads: %s", e)
        return jsonify({"success": False, "error": str(e)}), 500


@hunting_bp.route("/hunting/noise/stats/<int:case_id>")
@login_required
def get_noise_stats(case_id):
    """Get noise statistics for a case."""
    try:
        from utils.clickhouse import get_client

        client = get_client()

        result = client.query(
            "SELECT count() FROM events WHERE case_id = {case_id:UInt32} AND noise_matched = true",
            parameters={"case_id": case_id},
        )
        noise_count = result.result_rows[0][0] if result.result_rows else 0

        total_result = client.query(
            "SELECT count() FROM events WHERE case_id = {case_id:UInt32}",
            parameters={"case_id": case_id},
        )
        total_count = total_result.result_rows[0][0] if total_result.result_rows else 0

        case = Case.get_by_id(case_id)
        last_scan = case.noise_last_scan.isoformat() if case and case.noise_last_scan else None

        return jsonify(
            {
                "success": True,
                "case_id": case_id,
                "noise_count": noise_count,
                "total_count": total_count,
                "noise_percentage": round((noise_count / total_count * 100), 2) if total_count > 0 else 0,
                "last_scan": last_scan,
            }
        )

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@hunting_bp.route("/hunting/noise/tag/<int:case_id>", methods=["POST"])
@login_required
def start_noise_tagging(case_id):
    """Start noise tagging task for a case."""
    try:
        from tasks.noise_tagger import tag_noise_events

        if current_user.permission_level == "viewer":
            return _viewer_write_error("Viewers cannot modify hunting state")

        case = Case.get_by_id(case_id)
        if not case:
            return jsonify({"success": False, "error": "Case not found"}), 404

        task = tag_noise_events.delay(case_id, current_user.username)
        _remember_task_access(task.id, case_id=case.id)

        return jsonify(
            {
                "success": True,
                "task_id": task.id,
                "message": "Noise tagging started",
            }
        )

    except Exception as e:
        import traceback

        traceback.print_exc()
        return jsonify({"success": False, "error": str(e)}), 500


@hunting_bp.route("/hunting/noise/status/<task_id>")
@login_required
def get_noise_task_status(task_id):
    """Get status of a noise tagging task."""
    try:
        from celery.result import AsyncResult
        from tasks.celery_tasks import celery_app

        if not _task_access_allowed(task_id):
            return jsonify({"success": False, "error": "Task not found"}), 404

        task = AsyncResult(task_id, app=celery_app)

        response = {
            "success": True,
            "task_id": task_id,
            "state": task.state,
            "progress": 0,
            "status": "Unknown",
        }

        if task.state == "PENDING":
            response["status"] = "Waiting to start..."
            response["progress"] = 0
        elif task.state == "PROGRESS":
            info = task.info or {}
            response["progress"] = info.get("progress", 0)
            response["status"] = info.get("status", "Processing...")
        elif task.state == "SUCCESS":
            response["state"] = "completed"
            response["progress"] = 100
            response["status"] = "Completed"
            response["result"] = task.result
        elif task.state == "FAILURE":
            response["state"] = "failed"
            response["error"] = str(task.result) if task.result else "Task failed"

        return jsonify(response)

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@hunting_bp.route("/hunting/field-enhancers")
@login_required
def get_field_enhancers():
    """Get all enabled field enhancers for client-side caching."""
    try:
        from models.field_enhancer import FieldEnhancer

        enhancers = FieldEnhancer.query.filter_by(is_enabled=True).all()

        lookup = {}
        for e in enhancers:
            key = f"{e.artifact_type}:{e.field_path}:{e.field_value}"
            lookup[key] = {
                "description": e.description,
                "source_pattern": e.source_pattern,
            }

        return jsonify(
            {
                "success": True,
                "enhancers": lookup,
                "count": len(lookup),
            }
        )

    except Exception as e:
        logger.error("Error fetching field enhancers: %s", e)
        return jsonify({"success": False, "error": str(e)}), 500
