"""Case archive and restore API routes."""

import json
import logging
import os

from flask import Blueprint, jsonify, request
from flask_login import current_user, login_required

from config import Config
from models.case import Case
from models.database import db
from routes.route_helpers import DEFAULT_ARCHIVE_PATH, _viewer_write_error
from utils.artifact_paths import ensure_case_artifact_paths

logger = logging.getLogger(__name__)

archive_bp = Blueprint("archive", __name__, url_prefix="/api")


@archive_bp.route("/case/<case_uuid>/archive", methods=["POST"])
@login_required
def start_case_archive(case_uuid):
    """Start archiving a case."""
    try:
        from models.archive_job import ARCHIVE_STAGES, ArchiveJob, ArchiveJobStatus, ArchiveJobType
        from models.audit_log import AuditLog
        from models.system_settings import SettingKeys, SystemSettings
        from tasks.archive_tasks import archive_case_task

        if current_user.permission_level == "viewer":
            return _viewer_write_error("Viewers cannot archive cases")

        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({"success": False, "error": "Case not found"}), 404

        if case.status == "archived":
            return jsonify({"success": False, "error": "Case is already archived"}), 400

        existing_job = ArchiveJob.query.filter_by(
            case_uuid=case_uuid,
            job_type=ArchiveJobType.ARCHIVE.value,
            status=ArchiveJobStatus.RUNNING.value,
        ).first()

        if existing_job:
            return jsonify(
                {
                    "success": False,
                    "error": "Archive already in progress",
                    "job_id": existing_job.id,
                }
            ), 400

        archive_path = SystemSettings.get(SettingKeys.ARCHIVE_PATH, DEFAULT_ARCHIVE_PATH)
        if not os.path.exists(archive_path):
            return jsonify(
                {
                    "success": False,
                    "error": f"Archive path does not exist: {archive_path}. Please configure in Settings.",
                }
            ), 400

        if not os.access(archive_path, os.W_OK):
            return jsonify(
                {
                    "success": False,
                    "error": f"Archive path is not writable: {archive_path}",
                }
            ), 400

        job = ArchiveJob(
            case_id=case.id,
            case_uuid=case_uuid,
            job_type=ArchiveJobType.ARCHIVE.value,
            status=ArchiveJobStatus.PENDING.value,
            total_stages=len(ARCHIVE_STAGES),
            archive_path=archive_path,
            created_by=current_user.username if current_user.is_authenticated else "system",
        )
        db.session.add(job)
        db.session.commit()

        task = archive_case_task.delay(job.id)
        job.celery_task_id = task.id
        db.session.commit()

        AuditLog.log(
            entity_type="case",
            entity_id=case.id,
            action="archived",
            entity_name=case.name,
            case_uuid=case_uuid,
            details={"job_id": job.id},
        )

        return jsonify({"success": True, "job_id": job.id, "message": "Archive started"})

    except Exception as e:
        logger.error("Error starting archive: %s", e)
        import traceback

        traceback.print_exc()
        return jsonify({"success": False, "error": str(e)}), 500


@archive_bp.route("/case/<case_uuid>/archive/status")
@login_required
def get_archive_status(case_uuid):
    """Get status of most recent archive job for a case."""
    try:
        from models.archive_job import ArchiveJob, ArchiveJobType
        from tasks.archive_tasks import get_archive_progress

        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({"success": False, "error": "Case not found"}), 404

        job = (
            ArchiveJob.query.filter_by(
                case_uuid=case_uuid,
                job_type=ArchiveJobType.ARCHIVE.value,
            )
            .order_by(ArchiveJob.created_at.desc())
            .first()
        )

        if not job:
            return jsonify({"success": False, "error": "No archive job found"}), 404

        redis_progress = {}
        if job.status == "running":
            redis_progress = get_archive_progress(job.id)

        response = job.to_dict()
        response["progress_percent"] = job.get_progress_percent()

        if redis_progress:
            if "stage" in redis_progress:
                response["current_stage"] = redis_progress["stage"]
            if "current_file" in redis_progress:
                response["current_file_count"] = int(redis_progress["current_file"])
            if "total_files" in redis_progress:
                response["total_file_count"] = int(redis_progress["total_files"])
            if "filename" in redis_progress:
                response["current_file_name"] = redis_progress["filename"]

        return jsonify({"success": True, "job": response})

    except Exception as e:
        logger.error("Error getting archive status: %s", e)
        return jsonify({"success": False, "error": str(e)}), 500


@archive_bp.route("/case/<case_uuid>/archive/info")
@login_required
def get_archive_info(case_uuid):
    """Get archive information for an archived case."""
    try:
        from models.system_settings import SettingKeys, SystemSettings

        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({"success": False, "error": "Case not found"}), 404

        if case.status != "archived":
            return jsonify({"success": False, "error": "Case is not archived"}), 400

        archive_path = SystemSettings.get(SettingKeys.ARCHIVE_PATH, DEFAULT_ARCHIVE_PATH)
        archive_folder = os.path.join(archive_path, case_uuid)
        manifest_path = os.path.join(archive_folder, "manifest.json")

        if not os.path.exists(manifest_path):
            return jsonify(
                {
                    "success": False,
                    "error": "Archive manifest not found. Archive may be corrupted.",
                }
            ), 404

        with open(manifest_path, "r") as f:
            manifest = json.load(f)

        storage_zip = os.path.join(archive_folder, "storage.zip")
        evidence_zip = os.path.join(archive_folder, "evidence.zip")
        originals_zip = os.path.join(archive_folder, "originals.zip")

        manifest["storage_zip_exists"] = os.path.exists(storage_zip)
        manifest["evidence_zip_exists"] = os.path.exists(evidence_zip)
        manifest["originals_zip_exists"] = os.path.exists(originals_zip)
        manifest["archive_folder"] = archive_folder

        if manifest["storage_zip_exists"]:
            manifest["storage_zip_size"] = os.path.getsize(storage_zip)
        if manifest["evidence_zip_exists"]:
            manifest["evidence_zip_size"] = os.path.getsize(evidence_zip)
        if manifest["originals_zip_exists"]:
            manifest["originals_zip_size"] = os.path.getsize(originals_zip)

        return jsonify({"success": True, "manifest": manifest})

    except Exception as e:
        logger.error("Error getting archive info: %s", e)
        return jsonify({"success": False, "error": str(e)}), 500


@archive_bp.route("/case/<case_uuid>/restore", methods=["POST"])
@login_required
def start_case_restore(case_uuid):
    """Start restoring an archived case."""
    try:
        from models.archive_job import ArchiveJob, ArchiveJobStatus, ArchiveJobType, RESTORE_STAGES
        from models.audit_log import AuditLog
        from models.system_settings import SettingKeys, SystemSettings
        from tasks.archive_tasks import restore_case_task

        if current_user.permission_level == "viewer":
            return _viewer_write_error("Viewers cannot restore cases")

        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({"success": False, "error": "Case not found"}), 404

        if case.status != "archived":
            return jsonify({"success": False, "error": "Case is not archived"}), 400

        existing_job = ArchiveJob.query.filter_by(
            case_uuid=case_uuid,
            job_type=ArchiveJobType.RESTORE.value,
            status=ArchiveJobStatus.RUNNING.value,
        ).first()

        if existing_job:
            return jsonify(
                {
                    "success": False,
                    "error": "Restore already in progress",
                    "job_id": existing_job.id,
                }
            ), 400

        archive_path = SystemSettings.get(SettingKeys.ARCHIVE_PATH, DEFAULT_ARCHIVE_PATH)
        archive_folder = os.path.join(archive_path, case_uuid)

        if not os.path.exists(archive_folder):
            return jsonify(
                {
                    "success": False,
                    "error": f"Archive folder not found: {archive_folder}",
                }
            ), 404

        data = request.get_json() or {}
        delete_archive = data.get("delete_archive", False)

        job = ArchiveJob(
            case_id=case.id,
            case_uuid=case_uuid,
            job_type=ArchiveJobType.RESTORE.value,
            status=ArchiveJobStatus.PENDING.value,
            total_stages=len(RESTORE_STAGES),
            archive_path=archive_path,
            archive_folder=archive_folder,
            delete_archive_after_restore=delete_archive,
            created_by=current_user.username if current_user.is_authenticated else "system",
        )
        db.session.add(job)
        db.session.commit()

        task = restore_case_task.delay(job.id)
        job.celery_task_id = task.id
        db.session.commit()

        AuditLog.log(
            entity_type="case",
            entity_id=case.id,
            action="restored",
            entity_name=case.name,
            case_uuid=case_uuid,
            details={"job_id": job.id, "delete_archive": delete_archive},
        )

        return jsonify({"success": True, "job_id": job.id, "message": "Restore started"})

    except Exception as e:
        logger.error("Error starting restore: %s", e)
        import traceback

        traceback.print_exc()
        return jsonify({"success": False, "error": str(e)}), 500


@archive_bp.route("/case/<case_uuid>/restore/status")
@login_required
def get_restore_status(case_uuid):
    """Get status of most recent restore job for a case."""
    try:
        from models.archive_job import ArchiveJob, ArchiveJobType
        from tasks.archive_tasks import get_archive_progress

        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({"success": False, "error": "Case not found"}), 404

        job = (
            ArchiveJob.query.filter_by(
                case_uuid=case_uuid,
                job_type=ArchiveJobType.RESTORE.value,
            )
            .order_by(ArchiveJob.created_at.desc())
            .first()
        )

        if not job:
            return jsonify({"success": False, "error": "No restore job found"}), 404

        redis_progress = {}
        if job.status == "running":
            redis_progress = get_archive_progress(job.id)

        response = job.to_dict()
        response["progress_percent"] = job.get_progress_percent()

        if redis_progress:
            if "stage" in redis_progress:
                response["current_stage"] = redis_progress["stage"]
            if "current_file" in redis_progress:
                response["current_file_count"] = int(redis_progress["current_file"])
            if "total_files" in redis_progress:
                response["total_file_count"] = int(redis_progress["total_files"])
            if "filename" in redis_progress:
                response["current_file_name"] = redis_progress["filename"]

        return jsonify({"success": True, "job": response})

    except Exception as e:
        logger.error("Error getting restore status: %s", e)
        return jsonify({"success": False, "error": str(e)}), 500


@archive_bp.route("/case/<case_uuid>/storage/size")
@login_required
def get_case_storage_size(case_uuid):
    """Get current storage size for a case."""
    try:
        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({"success": False, "error": "Case not found"}), 404

        storage_folder = os.path.join(Config.STORAGE_FOLDER, case_uuid)
        evidence_folder = os.path.join(Config.EVIDENCE_FOLDER, case_uuid)
        staging_folder = os.path.join(Config.STAGING_FOLDER, case_uuid)
        originals_folder = ensure_case_artifact_paths(case_uuid)["originals_root"]

        def get_folder_stats(folder_path):
            if not os.path.exists(folder_path):
                return {"exists": False, "size_bytes": 0, "file_count": 0}

            total_size = 0
            file_count = 0
            for root, _, filenames in os.walk(folder_path):
                for filename in filenames:
                    filepath = os.path.join(root, filename)
                    try:
                        total_size += os.path.getsize(filepath)
                        file_count += 1
                    except OSError:
                        pass

            return {
                "exists": True,
                "size_bytes": total_size,
                "size_gb": round(total_size / (1024**3), 2),
                "file_count": file_count,
            }

        return jsonify(
            {
                "success": True,
                "storage": get_folder_stats(storage_folder),
                "originals": get_folder_stats(originals_folder),
                "evidence": get_folder_stats(evidence_folder),
                "staging": get_folder_stats(staging_folder),
                "is_archived": case.status == "archived",
            }
        )

    except Exception as e:
        logger.error("Error getting storage size: %s", e)
        return jsonify({"success": False, "error": str(e)}), 500


@archive_bp.route("/archive/jobs/active")
@login_required
def get_active_archive_jobs():
    """Get all active archive and restore jobs."""
    try:
        from models.archive_job import ArchiveJob, ArchiveJobStatus
        from tasks.archive_tasks import get_archive_progress

        jobs = (
            ArchiveJob.query.filter(
                ArchiveJob.status.in_([ArchiveJobStatus.PENDING.value, ArchiveJobStatus.RUNNING.value])
            )
            .order_by(ArchiveJob.created_at.desc())
            .all()
        )

        result = []
        for job in jobs:
            if not current_user.can_access_case(job.case_id):
                continue
            job_data = job.to_dict()
            job_data["progress_percent"] = job.get_progress_percent()

            if job.status == "running":
                redis_progress = get_archive_progress(job.id)
                if redis_progress:
                    if "stage" in redis_progress:
                        job_data["current_stage"] = redis_progress["stage"]
                    if "current_file" in redis_progress:
                        job_data["current_file_count"] = int(redis_progress["current_file"])
                    if "total_files" in redis_progress:
                        job_data["total_file_count"] = int(redis_progress["total_files"])

            case = Case.get_by_id_unchecked(job.case_id)
            if case:
                job_data["case_name"] = case.name

            result.append(job_data)

        return jsonify({"success": True, "jobs": result})

    except Exception as e:
        logger.error("Error getting active archive jobs: %s", e)
        return jsonify({"success": False, "error": str(e)}), 500
