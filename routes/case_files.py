"""Case file management API routes."""

import logging
import os
from datetime import datetime

from flask import Blueprint, jsonify, request
from flask_login import current_user, login_required

from config import Config
from models.audit_log import AuditAction, AuditEntityType, AuditLog
from models.case import Case
from models.case_file import CaseFile
from models.database import db
from routes.route_helpers import (
    _default_upload_type_label,
    _get_parser_hints_for_case_file,
    _remember_task_access,
    _require_case_write_access,
    _task_access_allowed,
)
from utils.async_status import build_async_status_response

logger = logging.getLogger(__name__)

case_files_bp = Blueprint("case_files", __name__, url_prefix="/api")


@case_files_bp.route("/files/stats/<case_uuid>")
@login_required
def get_file_stats(case_uuid):
    """Get file statistics for a case."""
    try:
        from models.known_system import KnownSystem
        from models.known_user import KnownUser
        from utils.progress import get_progress

        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({"success": False, "error": "Case not found"}), 404

        stats = CaseFile.get_stats(case_uuid)
        stats["review"] = CaseFile.get_review_stats(case_uuid)

        latest_ingest = (
            AuditLog.query.filter_by(
                case_uuid=case_uuid,
                entity_type=AuditEntityType.CASE_FILE,
                action=AuditAction.INGESTED,
            )
            .order_by(AuditLog.timestamp.desc())
            .first()
        )
        stats["latest_ingest_summary"] = latest_ingest.to_dict()["details"] if latest_ingest else None
        stats["latest_ingest_at"] = latest_ingest.timestamp.isoformat() if latest_ingest else None

        progress = get_progress(case_uuid) or {}
        progress_status = progress.get("status", "idle")
        known_systems = KnownSystem.query.filter_by(case_id=case.id).count()
        known_users = KnownUser.query.filter_by(case_id=case.id).count()
        all_files_finished = stats.get("total", 0) > 0 and stats.get("pending", 0) == 0
        completion_stalled = (
            all_files_finished
            and latest_ingest is None
            and progress_status in ("complete", "waiting_for_completion")
        )
        stats["completion"] = {
            "progress_status": progress_status,
            "all_files_finished": all_files_finished,
            "has_ingest_summary": latest_ingest is not None,
            "stalled": completion_stalled,
            "repair_available": all_files_finished and latest_ingest is None,
            "known_systems": known_systems,
            "known_users": known_users,
        }

        latest_events = (((stats["latest_ingest_summary"] or {}).get("events") or {}).get("total"))
        if latest_events is not None:
            stats["events_total"] = latest_events
        else:
            try:
                from utils.clickhouse import count_events

                stats["events_total"] = count_events(case.id)
            except Exception as e:
                logger.warning("Could not load event count for file summary %s: %s", case_uuid, e)
                stats["events_total"] = 0
        stats["success"] = True
        stats["case_uuid"] = case_uuid

        return jsonify(stats)

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@case_files_bp.route("/case/statistics/<case_uuid>")
@login_required
def get_case_statistics(case_uuid):
    """Get comprehensive statistics for a case dashboard."""
    try:
        from models import network_log
        from models.evidence_file import EvidenceFile
        from models.ioc import IOC
        from models.known_system import KnownSystem
        from models.known_user import KnownUser
        from models.memory_job import MemoryJob
        from models.pcap_file import PcapFile
        from utils.clickhouse import get_client

        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({"success": False, "error": "Case not found"}), 404

        file_stats = CaseFile.get_stats(case_uuid)

        file_type_counts = (
            db.session.query(CaseFile.file_type, db.func.count(CaseFile.id))
            .filter(
                CaseFile.case_uuid == case_uuid,
                CaseFile.is_archive == False,
                CaseFile.status != "duplicate",
            )
            .group_by(CaseFile.file_type)
            .all()
        )
        file_types = {ft or "Unknown": count for ft, count in file_type_counts}

        artifact_stats = {
            "total": 0,
            "by_type": {},
            "analyst_tagged": 0,
            "ioc_tagged": 0,
            "sigma_tagged": 0,
            "noise_matched": 0,
        }

        try:
            client = get_client()
            from utils.event_analyst_state import build_analyst_projection, ensure_event_analyst_state_table
            from utils.event_ioc_state import build_ioc_projection, ensure_event_ioc_state_tables
            from utils.event_noise_state import build_noise_projection, ensure_event_noise_state_tables

            ensure_event_analyst_state_table(client)
            ensure_event_noise_state_tables(client)
            ensure_event_ioc_state_tables(client)
            analyst_projection = build_analyst_projection(alias="e")
            noise_projection = build_noise_projection(alias="e")
            ioc_projection = build_ioc_projection(alias="e")
            result = client.query(
                "SELECT count() FROM events WHERE case_id = {case_id:UInt32}",
                parameters={"case_id": case.id},
            )
            artifact_stats["total"] = result.result_rows[0][0] if result.result_rows else 0

            result = client.query(
                """SELECT artifact_type, count() as cnt
                   FROM events
                   WHERE case_id = {case_id:UInt32}
                   GROUP BY artifact_type
                   ORDER BY cnt DESC""",
                parameters={"case_id": case.id},
            )
            for row in result.result_rows:
                artifact_stats["by_type"][row[0] or "unknown"] = row[1]

            result = client.query(
                f"""
                SELECT count()
                FROM events AS e
                {analyst_projection["join_sql"]}
                WHERE e.case_id = {{case_id:UInt32}}
                  AND {analyst_projection["tagged_sql"]} = true
                """,
                parameters={"case_id": case.id},
            )
            artifact_stats["analyst_tagged"] = result.result_rows[0][0] if result.result_rows else 0

            result = client.query(
                f"""
                SELECT count()
                FROM events AS e
                {ioc_projection["join_sql"]}
                WHERE e.case_id = {{case_id:UInt32}}
                  AND {ioc_projection["has_ioc_sql"]}
                """,
                parameters={"case_id": case.id},
            )
            artifact_stats["ioc_tagged"] = result.result_rows[0][0] if result.result_rows else 0

            result = client.query(
                "SELECT count() FROM events WHERE case_id = {case_id:UInt32} AND rule_title IS NOT NULL AND rule_title != ''",
                parameters={"case_id": case.id},
            )
            artifact_stats["sigma_tagged"] = result.result_rows[0][0] if result.result_rows else 0

            result = client.query(
                f"""
                SELECT count()
                FROM events AS e
                {noise_projection["join_sql"]}
                WHERE e.case_id = {{case_id:UInt32}}
                  AND {noise_projection["matched_sql"]} = true
                """,
                parameters={"case_id": case.id},
            )
            artifact_stats["noise_matched"] = result.result_rows[0][0] if result.result_rows else 0
        except Exception:
            pass

        ioc_count = IOC.query.filter(IOC.case_id == case.id, IOC.false_positive == False).count()
        system_count = KnownSystem.query.filter_by(case_id=case.id).count()
        user_count = KnownUser.query.filter_by(case_id=case.id).count()

        pcap_stats = PcapFile.get_stats(case_uuid)

        network_stats = {
            "total": 0,
            "by_type": {},
            "unique_src_ips": 0,
            "unique_dst_ips": 0,
        }
        try:
            net_stats = network_log.get_network_stats(case.id)
            network_stats["total"] = net_stats.get("total", 0)
            network_stats["by_type"] = net_stats.get("by_type", {})
            network_stats["unique_src_ips"] = net_stats.get("unique_src_ips", 0)
            network_stats["unique_dst_ips"] = net_stats.get("unique_dst_ips", 0)
        except Exception:
            pass

        memory_stats = {
            "total": 0,
            "completed": 0,
            "running": 0,
            "pending": 0,
            "failed": 0,
            "total_plugins_run": 0,
        }
        try:
            memory_jobs = MemoryJob.query.filter_by(case_id=case.id).all()
            memory_stats["total"] = len(memory_jobs)

            for job in memory_jobs:
                if job.status == "completed":
                    memory_stats["completed"] += 1
                    plugin_summary = job.plugin_summary()
                    memory_stats["total_plugins_run"] += plugin_summary.get("execution_total", 0)
                elif job.status == "running":
                    memory_stats["running"] += 1
                elif job.status == "pending":
                    memory_stats["pending"] += 1
                elif job.status == "failed":
                    memory_stats["failed"] += 1
        except Exception:
            pass

        evidence_stats = {
            "total_files": 0,
            "total_size": 0,
            "total_size_display": "0 B",
            "by_type": {},
        }
        try:
            ev_stats = EvidenceFile.get_case_stats(case_uuid)
            evidence_stats["total_files"] = ev_stats.get("total_files", 0)
            evidence_stats["total_size"] = ev_stats.get("total_size", 0)
            evidence_stats["by_type"] = ev_stats.get("file_types", {})
            size = evidence_stats["total_size"]
            if size < 1024:
                evidence_stats["total_size_display"] = f"{size} B"
            elif size < 1024 * 1024:
                evidence_stats["total_size_display"] = f"{size / 1024:.1f} KB"
            elif size < 1024 * 1024 * 1024:
                evidence_stats["total_size_display"] = f"{size / (1024 * 1024):.1f} MB"
            else:
                evidence_stats["total_size_display"] = f"{size / (1024 * 1024 * 1024):.2f} GB"
        except Exception:
            pass

        return jsonify(
            {
                "success": True,
                "case_uuid": case_uuid,
                "file_stats": {
                    "total": file_stats["total"],
                    "fully_indexed": file_stats["fully_indexed"],
                    "partially_indexed": file_stats["partially_indexed"],
                    "no_parser": file_stats["no_parser"],
                    "parse_error": file_stats["parse_error"],
                    "error": file_stats["error"],
                    "pending": file_stats["pending"],
                    "by_type": file_types,
                },
                "artifact_stats": artifact_stats,
                "entity_counts": {
                    "iocs": ioc_count,
                    "systems": system_count,
                    "users": user_count,
                },
                "pcap_stats": pcap_stats,
                "network_stats": network_stats,
                "memory_stats": memory_stats,
                "evidence_stats": evidence_stats,
            }
        )

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@case_files_bp.route("/files/list/<case_uuid>")
@login_required
def get_file_list(case_uuid):
    """Get paginated file list for a case."""
    try:
        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({"success": False, "error": "Case not found"}), 404

        page = request.args.get("page", 1, type=int)
        per_page = request.args.get("per_page", 25, type=int)
        search = request.args.get("search", "", type=str).strip()
        include_duplicates = request.args.get("include_duplicates", "false", type=str).lower() == "true"

        per_page = min(max(per_page, 10), 200)

        query = CaseFile.query.filter_by(case_uuid=case_uuid)
        if not include_duplicates:
            query = query.filter(CaseFile.status != "duplicate")

        if search:
            search_filter = f"%{search}%"
            query = query.filter(
                db.or_(
                    CaseFile.filename.ilike(search_filter),
                    CaseFile.hostname.ilike(search_filter),
                    CaseFile.file_type.ilike(search_filter),
                    CaseFile.uploaded_by.ilike(search_filter),
                    CaseFile.parser_type.ilike(search_filter),
                )
            )

        query = query.order_by(CaseFile.uploaded_at.desc())
        total = query.count()
        files = query.offset((page - 1) * per_page).limit(per_page).all()

        file_list = []
        parent_cache = {}
        for cf in files:
            parent_filename = None
            if cf.parent_id:
                if cf.parent_id not in parent_cache:
                    parent = CaseFile.query.get(cf.parent_id)
                    parent_cache[cf.parent_id] = parent.filename if parent else None
                parent_filename = parent_cache[cf.parent_id]
            review_status = CaseFile.derive_review_status(
                filename=cf.filename or cf.original_filename,
                status=cf.status,
                ingestion_status=cf.ingestion_status,
                is_archive=cf.is_archive,
                retention_state=cf.retention_state,
                error_message=cf.error_message,
            )

            file_list.append(
                {
                    "id": cf.id,
                    "parent_filename": parent_filename,
                    "filename": cf.filename,
                    "file_size": cf.file_size,
                    "hostname": cf.hostname or "-",
                    "file_type": cf.file_type or "-",
                    "upload_source": cf.upload_source,
                    "uploaded_by": cf.uploaded_by,
                    "uploaded_at": cf.uploaded_at.strftime("%Y-%m-%d %H:%M") if cf.uploaded_at else "-",
                    "status": cf.status,
                    "ingestion_status": cf.ingestion_status,
                    "parser_type": cf.parser_type or "-",
                    "events_indexed": cf.events_indexed,
                    "error_message": cf.error_message,
                    "status_detail": review_status.get("detail") or cf.error_message or "",
                    "review_status": review_status,
                }
            )

        return jsonify(
            {
                "success": True,
                "case_uuid": case_uuid,
                "files": file_list,
                "total": total,
                "page": page,
                "per_page": per_page,
                "total_pages": (total + per_page - 1) // per_page,
            }
        )

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@case_files_bp.route("/files/progress/<case_uuid>")
@login_required
def get_processing_progress(case_uuid):
    """Get processing progress for a case."""
    try:
        from tasks.celery_tasks import celery_app
        from utils.progress import get_progress

        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({"success": False, "error": "Case not found"}), 404

        progress = get_progress(case_uuid)

        if progress:
            phase = progress.get("phase", "files")
            status = progress.get("status", "idle")
            current_item = progress.get("current_item", "")

            files_data = progress.get("files", {})
            total_files = files_data.get("total", 0)
            processed_files = files_data.get("completed", 0)

            dedup_data = progress.get("deduplication", {})
            systems_data = progress.get("systems", {})
            users_data = progress.get("users", {})

            is_processing = status == "processing"
            is_completing = status in (
                "waiting_for_completion",
                "flushing_buffer",
                "deduplicating",
                "discovering_systems",
                "discovering_users",
            )

            completion_phase_map = {
                "waiting_for_completion": "waiting_for_completion",
                "flushing_buffer": "flushing_buffer",
                "deduplicating": "deduplicating",
                "discovering_systems": "discovering_systems",
                "discovering_users": "discovering_users",
            }
            completion_phase = completion_phase_map.get(status)
        else:
            phase = "idle"
            status = "idle"
            current_item = ""
            total_files = 0
            processed_files = 0
            dedup_data = {"total": 0, "completed": 0}
            systems_data = {"total": 0, "completed": 0}
            users_data = {"total": 0, "completed": 0}
            is_processing = False
            is_completing = False
            completion_phase = None

        workers = []
        try:
            inspect = celery_app.control.inspect()
            active = inspect.active() or {}

            for worker_name, tasks in active.items():
                for task in tasks:
                    if task.get("name") == "tasks.parse_file":
                        args = task.get("args", [])
                        kwargs = task.get("kwargs", {})

                        case_file_id = kwargs.get("case_file_id") or (args[3] if len(args) > 3 else None)
                        if case_file_id:
                            cf = CaseFile.query.get(case_file_id)
                            if cf and cf.case_uuid == case_uuid:
                                workers.append(
                                    {
                                        "worker": worker_name.split("@")[-1],
                                        "file": cf.filename,
                                        "task_id": task.get("id"),
                                    }
                                )
        except Exception:
            pass

        return jsonify(
            {
                "success": True,
                "case_uuid": case_uuid,
                "total_files": total_files,
                "processed_files": processed_files,
                "workers": workers,
                "is_processing": is_processing,
                "is_completing": is_completing,
                "completion_phase": completion_phase,
                "phase": phase,
                "status": status,
                "current_item": current_item,
                "files": {"total": total_files, "completed": processed_files},
                "deduplication": dedup_data,
                "systems": systems_data,
                "users": users_data,
            }
        )

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@case_files_bp.route("/files/reindex/<case_uuid>", methods=["POST"])
@login_required
def reindex_case_files(case_uuid):
    """Queue an originals-based clean rebuild for the case."""
    try:
        from tasks.celery_tasks import reindex_case_task
        from utils.clickhouse import get_active_destructive_event_rewrite

        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({"success": False, "error": "Case not found"}), 404

        write_error = _require_case_write_access(current_user)
        if write_error:
            return write_error

        active_rewrite = get_active_destructive_event_rewrite()
        if active_rewrite:
            return jsonify(
                {
                    "success": False,
                    "error": "Another destructive event rewrite is already running",
                    "active_rewrite": active_rewrite,
                }
            ), 409

        task = reindex_case_task.delay(
            case_uuid=case_uuid,
            case_id=case.id,
            username=current_user.username,
        )

        return jsonify(
            {
                "success": True,
                "case_uuid": case_uuid,
                "task_id": task.id,
                "message": "Originals-based case rebuild queued",
            }
        )

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@case_files_bp.route("/files/repair-completion/<case_uuid>", methods=["POST"])
@login_required
def repair_case_completion(case_uuid):
    """Re-run post-ingest completion tasks for a finished case."""
    try:
        from tasks.celery_tasks import case_indexing_complete_task
        from utils.progress import clear_completion_trigger, get_progress, set_phase

        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({"success": False, "error": "Case not found"}), 404

        write_error = _require_case_write_access(current_user)
        if write_error:
            return write_error

        pending_count = CaseFile.query.filter(
            CaseFile.case_uuid == case_uuid,
            CaseFile.is_archive == False,
            CaseFile.status.in_(["new", "queued", "ingesting"]),
        ).count()
        if pending_count > 0:
            return jsonify(
                {
                    "success": False,
                    "error": f"{pending_count} files are still processing",
                }
            ), 409

        progress = get_progress(case_uuid) or {}
        clear_completion_trigger(case_uuid)
        set_phase(case_uuid, "waiting_for_completion")
        task = case_indexing_complete_task.delay(case_id=case.id, case_uuid=case_uuid)

        return jsonify(
            {
                "success": True,
                "task_id": task.id,
                "case_uuid": case_uuid,
                "previous_progress_status": progress.get("status", "idle"),
                "message": "Post-ingest completion queued",
            }
        )

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@case_files_bp.route("/events/duplicates/preview/<case_uuid>")
@login_required
def preview_duplicate_events(case_uuid):
    """Preview duplicate events for a case without deleting them."""
    try:
        from utils.event_deduplication import get_duplicate_summary

        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({"success": False, "error": "Case not found"}), 404

        summary = get_duplicate_summary(case.id)

        return jsonify(
            {
                "success": True,
                "case_uuid": case_uuid,
                "case_id": case.id,
                "total_duplicates": summary.get("total_duplicates", 0),
                "by_artifact_type": summary.get("by_artifact_type", {}),
            }
        )

    except Exception as e:
        logger.error("Error previewing duplicates for case %s: %s", case_uuid, e)
        return jsonify({"success": False, "error": str(e)}), 500


@case_files_bp.route("/events/duplicates/remove/<case_uuid>", methods=["POST"])
@login_required
def remove_duplicate_events(case_uuid):
    """Queue duplicate-event removal for a case."""
    try:
        from tasks.celery_tasks import deduplicate_case_events_task
        from utils.clickhouse import get_active_destructive_event_rewrite

        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({"success": False, "error": "Case not found"}), 404

        write_error = _require_case_write_access(current_user)
        if write_error:
            return write_error

        active_rewrite = get_active_destructive_event_rewrite()
        if active_rewrite:
            return jsonify(
                {
                    "success": False,
                    "error": "Another destructive event rewrite is already running",
                    "active_rewrite": active_rewrite,
                }
            ), 409

        data = request.get_json(silent=True) or {}
        force_large_dedup = bool(data.get("force_large_dedup"))

        task = deduplicate_case_events_task.delay(
            case_id=case.id,
            case_uuid=case_uuid,
            force_large_dedup=force_large_dedup,
        )
        _remember_task_access(task.id, case_id=case.id)

        return jsonify(
            {
                "success": True,
                "case_uuid": case_uuid,
                "case_id": case.id,
                "task_id": task.id,
                "status": "queued",
                "force_large_dedup": force_large_dedup,
                "message": "Duplicate removal queued",
            }
        )

    except Exception as e:
        logger.error("Error removing duplicates for case %s: %s", case_uuid, e)
        return jsonify({"success": False, "error": str(e)}), 500


@case_files_bp.route("/events/duplicates/status/<case_uuid>/<task_id>")
@login_required
def get_duplicate_event_removal_status(case_uuid, task_id):
    """Get status for an async duplicate-removal task."""
    try:
        from celery.result import AsyncResult
        from tasks.celery_tasks import celery_app

        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({"success": False, "error": "Case not found"}), 404

        if not _task_access_allowed(task_id, case_id=case.id):
            return jsonify({"success": False, "error": "Task not found"}), 404

        task = AsyncResult(task_id, app=celery_app)
        payload, status_code = build_async_status_response(
            task,
            task_id=task_id,
            pending_builder=lambda _task: {
                "status": "queued",
                "message": "Waiting to start duplicate removal...",
            },
            progress_builder=lambda task: {
                "status": "processing",
                "meta": task.info or {},
            },
            success_builder=lambda task: {
                "status": "completed",
                "result": task.result,
            },
            failure_builder=lambda task: {
                "status": "failed",
                "error": str(task.result) if task.result else "Duplicate removal failed",
            },
            other_builder=lambda task: {"status": (getattr(task, "state", "") or "").lower()},
        )
        payload["case_uuid"] = case_uuid
        payload["case_id"] = case.id
        return jsonify(payload), status_code

    except Exception as e:
        logger.error("Error loading duplicate-removal status for case %s task %s: %s", case_uuid, task_id, e)
        return jsonify({"success": False, "error": str(e)}), 500


@case_files_bp.route("/files/staging/check/<case_uuid>")
@login_required
def check_staging_orphans(case_uuid):
    """Check for orphan files in staging directory for a case."""
    try:
        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({"success": False, "error": "Case not found"}), 404

        staging_path = os.path.join(Config.STAGING_FOLDER, case_uuid)

        if not os.path.isdir(staging_path):
            return jsonify(
                {
                    "success": True,
                    "has_orphans": False,
                    "orphan_count": 0,
                    "orphans": [],
                }
            )

        staging_files = []
        for root, _, files in os.walk(staging_path):
            for filename in files:
                file_path = os.path.join(root, filename)
                rel_path = os.path.relpath(file_path, staging_path)
                staging_files.append(
                    {
                        "path": file_path,
                        "rel_path": rel_path,
                        "filename": filename,
                        "size": os.path.getsize(file_path),
                    }
                )

        if not staging_files:
            return jsonify(
                {
                    "success": True,
                    "has_orphans": False,
                    "orphan_count": 0,
                    "orphans": [],
                }
            )

        db_files = CaseFile.query.filter_by(case_uuid=case_uuid).with_entities(CaseFile.file_path).all()
        db_paths = {f.file_path for f in db_files if f.file_path}

        junk_extensions = {".sqlite-wal", ".sqlite-shm", ".sqlite-journal"}
        orphans = []
        junk_count = 0
        unknown_count = 0
        for sf in staging_files:
            if sf["path"] not in db_paths:
                ext = os.path.splitext(sf["filename"])[1].lower()
                is_junk = ext in junk_extensions
                if is_junk:
                    junk_count += 1
                else:
                    unknown_count += 1
                orphans.append(
                    {
                        "path": sf["path"],
                        "rel_path": sf["rel_path"],
                        "filename": sf["filename"],
                        "size": sf["size"],
                        "is_junk": is_junk,
                    }
                )

        return jsonify(
            {
                "success": True,
                "has_orphans": len(orphans) > 0,
                "orphan_count": len(orphans),
                "junk_count": junk_count,
                "unknown_count": unknown_count,
                "orphans": orphans[:100],
            }
        )

    except Exception as e:
        logger.exception("Error checking staging orphans for case %s", case_uuid)
        return jsonify({"success": False, "error": str(e)}), 500


@case_files_bp.route("/files/staging/import/<case_uuid>", methods=["POST"])
@login_required
def import_staging_orphans(case_uuid):
    """Import orphan files from staging into the case."""
    try:
        from tasks.celery_tasks import parse_file_task
        from utils.progress import init_progress

        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({"success": False, "error": "Case not found"}), 404

        write_error = _require_case_write_access(current_user)
        if write_error:
            return write_error

        staging_path = os.path.join(Config.STAGING_FOLDER, case_uuid)

        if not os.path.isdir(staging_path):
            return jsonify({"success": False, "error": "No staging directory found"}), 404

        staging_files = []
        for root, _, files in os.walk(staging_path):
            for filename in files:
                file_path = os.path.join(root, filename)
                rel_path = os.path.relpath(file_path, staging_path)
                staging_files.append({"path": file_path, "rel_path": rel_path, "filename": filename})

        db_files = CaseFile.query.filter_by(case_uuid=case_uuid).with_entities(CaseFile.file_path).all()
        db_paths = {f.file_path for f in db_files if f.file_path}

        imported = []
        files_to_queue = []

        for sf in staging_files:
            if sf["path"] not in db_paths:
                try:
                    file_path = sf["path"]
                    file_size = os.path.getsize(file_path)
                    sha256_hash = CaseFile.calculate_sha256(file_path)
                    is_archive = CaseFile.is_zip_file(file_path)

                    case_file = CaseFile(
                        case_uuid=case_uuid,
                        parent_id=None,
                        filename=sf["rel_path"],
                        original_filename=sf["filename"],
                        file_path=file_path,
                        file_size=file_size,
                        sha256_hash=sha256_hash,
                        hostname="",
                        file_type=_default_upload_type_label(),
                        upload_source="staging_import",
                        is_archive=is_archive,
                        is_extracted=False,
                        extraction_status="n/a",
                        status="new",
                        uploaded_by=current_user.username,
                    )

                    db.session.add(case_file)
                    db.session.flush()

                    if not is_archive:
                        files_to_queue.append(case_file)

                    imported.append(sf["rel_path"])

                except Exception as e:
                    logger.warning("Failed to import staging file %s: %s", sf["path"], e)
                    continue

        db.session.commit()

        if files_to_queue:
            init_progress(case_uuid, len(files_to_queue))

            for cf in files_to_queue:
                cf.status = "queued"
                db.session.flush()

                parse_file_task.delay(
                    file_path=cf.file_path,
                    case_id=case.id,
                    source_host=cf.hostname or "",
                    case_file_id=cf.id,
                    parser_hints=_get_parser_hints_for_case_file(cf),
                )

            db.session.commit()

        return jsonify(
            {
                "success": True,
                "imported_count": len(imported),
                "queued_for_parsing": len(files_to_queue),
                "imported": imported[:50],
            }
        )

    except Exception as e:
        db.session.rollback()
        logger.exception("Error importing staging orphans for case %s", case_uuid)
        return jsonify({"success": False, "error": str(e)}), 500


@case_files_bp.route("/files/staging/delete/<case_uuid>", methods=["POST"])
@login_required
def delete_staging_orphans(case_uuid):
    """Delete orphan files from staging directory."""
    try:
        if current_user.permission_level != "administrator":
            return jsonify({"success": False, "error": "Administrator access required"}), 403

        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({"success": False, "error": "Case not found"}), 404

        staging_path = os.path.join(Config.STAGING_FOLDER, case_uuid)

        if not os.path.isdir(staging_path):
            return jsonify({"success": False, "error": "No staging directory found"}), 404

        staging_files = []
        for root, _, files in os.walk(staging_path):
            for filename in files:
                file_path = os.path.join(root, filename)
                staging_files.append(file_path)

        db_files = CaseFile.query.filter_by(case_uuid=case_uuid).with_entities(CaseFile.file_path).all()
        db_paths = {f.file_path for f in db_files if f.file_path}

        deleted = []
        for file_path in staging_files:
            if file_path not in db_paths:
                try:
                    os.remove(file_path)
                    deleted.append(file_path)
                except Exception as e:
                    logger.warning("Failed to delete staging file %s: %s", file_path, e)

        for root, dirs, _ in os.walk(staging_path, topdown=False):
            for d in dirs:
                dir_path = os.path.join(root, d)
                try:
                    if not os.listdir(dir_path):
                        os.rmdir(dir_path)
                except Exception:
                    pass

        return jsonify({"success": True, "deleted_count": len(deleted)})

    except Exception as e:
        logger.exception("Error deleting staging orphans for case %s", case_uuid)
        return jsonify({"success": False, "error": str(e)}), 500


@case_files_bp.route("/files/recover-stuck/<case_uuid>", methods=["POST"])
@login_required
def recover_stuck_files(case_uuid):
    """Recover files stuck in ingesting or queued status."""
    try:
        from tasks.celery_tasks import parse_file_task
        from utils.artifact_paths import is_within_root
        from utils.progress import init_progress

        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({"success": False, "error": "Case not found"}), 404

        write_error = _require_case_write_access(current_user)
        if write_error:
            return write_error

        requeue = request.json.get("requeue", True) if request.is_json else True
        threshold_hours = request.json.get("threshold_hours", 2) if request.is_json else 2

        from datetime import timedelta

        cutoff = datetime.utcnow() - timedelta(hours=threshold_hours)

        stuck_files = CaseFile.query.filter(
            CaseFile.case_uuid == case_uuid,
            CaseFile.status.in_(["ingesting", "queued"]),
            CaseFile.uploaded_at < cutoff,
        ).all()

        if not stuck_files:
            return jsonify({"success": True, "message": "No stuck files found", "recovered": 0})

        recovered = []
        for cf in stuck_files:
            cf.status = "new"
            cf.ingestion_status = "not_done"
            cf.error_message = None
            cf.processed_at = None
            recovered.append(
                {
                    "id": cf.id,
                    "filename": cf.filename,
                    "previous_status": "ingesting/queued",
                    "file_exists": os.path.exists(cf.file_path) if cf.file_path else False,
                }
            )

        db.session.commit()

        queued_count = 0
        if requeue:
            files_to_queue = [
                cf
                for cf in stuck_files
                if cf.file_path
                and os.path.exists(cf.file_path)
                and not cf.is_archive
                and is_within_root(cf.file_path, os.path.join(Config.STAGING_FOLDER, case_uuid))
            ]

            if files_to_queue:
                init_progress(case_uuid, len(files_to_queue))

                for cf in files_to_queue:
                    cf.status = "queued"
                    db.session.flush()

                    parse_file_task.delay(
                        file_path=cf.file_path,
                        case_id=case.id,
                        source_host=cf.hostname or "",
                        case_file_id=cf.id,
                        parser_hints=_get_parser_hints_for_case_file(cf),
                    )
                    queued_count += 1

                db.session.commit()

        logger.info("Recovered %s stuck files for case %s, re-queued %s", len(recovered), case_uuid, queued_count)

        return jsonify(
            {
                "success": True,
                "recovered": len(recovered),
                "requeued": queued_count,
                "requeue_note": "Only files still present in transient staging were re-queued. Files already cleaned from staging require future reparse redesign.",
                "files": recovered,
            }
        )

    except Exception as e:
        db.session.rollback()
        logger.exception("Error recovering stuck files for case %s", case_uuid)
        return jsonify({"success": False, "error": str(e)}), 500


@case_files_bp.route("/files/delete/<int:file_id>", methods=["POST"])
@login_required
def delete_case_file(file_id):
    """Delete a case file and all associated data."""
    try:
        from models.file_audit_log import FileAuditLog
        from utils.clickhouse import count_file_events, delete_file_events

        if current_user.permission_level != "administrator":
            return jsonify({"success": False, "error": "Administrator access required"}), 403

        case_file = CaseFile.query.get(file_id)
        if not case_file:
            return jsonify({"success": False, "error": "File not found"}), 404

        case = Case.get_by_uuid(case_file.case_uuid)
        if not case:
            return jsonify({"success": False, "error": "Case not found"}), 404

        deleted_stats = {
            "file_id": file_id,
            "filename": case_file.filename,
            "events_deleted": 0,
            "child_files_deleted": 0,
            "disk_file_deleted": False,
        }

        try:
            deleted_stats["events_deleted"] = count_file_events(file_id)
        except Exception as e:
            logger.warning("Could not count events for file %s: %s", file_id, e)

        try:
            delete_file_events(file_id, wait=True)
            logger.info("Deleted ClickHouse events for file_id=%s", file_id)
        except Exception as e:
            logger.error("Failed to delete ClickHouse events for file_id=%s: %s", file_id, e)

        child_files = CaseFile.query.filter_by(parent_id=file_id).all()
        for child in child_files:
            try:
                delete_file_events(child.id, wait=True)
                logger.info("Deleted ClickHouse events for child file_id=%s", child.id)
            except Exception as e:
                logger.warning("Failed to delete ClickHouse events for child file %s: %s", child.id, e)

            if child.file_path and os.path.exists(child.file_path):
                try:
                    os.remove(child.file_path)
                    logger.info("Deleted child file from disk: %s", child.file_path)
                except Exception as e:
                    logger.warning("Failed to delete child file %s: %s", child.file_path, e)

            db.session.delete(child)
            deleted_stats["child_files_deleted"] += 1

        if case_file.file_path and os.path.exists(case_file.file_path):
            try:
                os.remove(case_file.file_path)
                deleted_stats["disk_file_deleted"] = True
                logger.info("Deleted file from disk: %s", case_file.file_path)
            except Exception as e:
                logger.error("Failed to delete file from disk %s: %s", case_file.file_path, e)

        audit_entry = FileAuditLog(
            case_uuid=case_file.case_uuid,
            filename=case_file.filename,
            sha256_hash=case_file.sha256_hash,
            file_path=case_file.file_path,
            file_size=case_file.file_size,
            action="deleted_manual",
            performed_by=current_user.username,
            notes=f"Deleted via Case Files page. Events deleted: {deleted_stats['events_deleted']}, Child files: {deleted_stats['child_files_deleted']}",
        )
        db.session.add(audit_entry)

        db.session.delete(case_file)
        db.session.commit()

        logger.info(
            "User %s deleted file %s (%s) from case %s",
            current_user.username,
            file_id,
            case_file.filename,
            case_file.case_uuid,
        )

        return jsonify(
            {
                "success": True,
                "message": f'File "{case_file.filename}" deleted successfully',
                **deleted_stats,
            }
        )

    except Exception as e:
        db.session.rollback()
        logger.exception("Error deleting file %s", file_id)
        return jsonify({"success": False, "error": str(e)}), 500
