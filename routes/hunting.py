"""Hunting API routes."""

import json
import logging

from flask import Blueprint, jsonify, request
from flask_login import current_user, login_required

from models.case import Case
from models.database import db
from routes.route_helpers import _remember_task_access, _task_access_allowed, _viewer_write_error
from routes.hunting_query_helpers import (
    _build_hunting_alert_type_filter,
    build_hunting_search_clause,
    build_event_description,
    build_hunting_time_filter,
    build_hunting_type_filter,
)
from utils.async_status import build_async_status_response
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

        case = Case.get_by_id(case_id)
        if not case:
            return jsonify({"success": False, "error": "Case not found"}), 404

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
        payload, status_code = build_async_status_response(
            task,
            task_id=task_id,
            pending_builder=lambda _task: {"progress": 0, "status": "pending", "message": "Waiting to start..."},
            progress_builder=lambda task: {
                "progress": (task.info or {}).get("progress", 0),
                "status": "processing",
                "message": (task.info or {}).get("status", "Processing..."),
            },
            success_builder=lambda task: {
                "progress": 100,
                "status": "completed",
                "result": task.result,
            },
            failure_builder=lambda task: {
                "progress": 100,
                "status": "failed",
                "error": str(task.result) if task.result else "Task failed",
            },
            other_builder=lambda task: {"status": getattr(task, "state", "Unknown")},
        )
        return jsonify(payload), status_code

    except ValueError as e:
        return jsonify({"success": False, "error": str(e)}), 400
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


@hunting_bp.route("/hunting/events/<int:case_id>")
@login_required
def get_hunting_events(case_id):
    """Get paginated events for hunting page."""
    try:
        from utils.clickhouse import get_client
        from utils.timezone import format_for_display

        case = Case.get_by_id(case_id)
        if not case:
            return jsonify({"success": False, "error": "Case not found"}), 404

        case_tz = case.timezone or "UTC"
        page = request.args.get("page", 1, type=int)
        per_page = request.args.get("per_page", 50, type=int)
        search = request.args.get("search", "", type=str).strip()
        artifact_types = request.args.get("types", "", type=str).strip()
        sigma_filter_param = request.args.get("sigma_filter", "", type=str).strip()
        ioc_filter_param = request.args.get("ioc_filter", "", type=str).strip()
        analyst_filter_param = request.args.get("analyst_filter", "", type=str).strip()
        other_filter_param = request.args.get("other_filter", "", type=str).strip()
        severity_levels_param = request.args.get("severity_levels", "", type=str).strip()
        show_noise = request.args.get("show_noise", "false", type=str).strip().lower() == "true"
        time_range = request.args.get("time_range", "none", type=str).strip()
        time_start = request.args.get("time_start", "", type=str).strip()
        time_end = request.args.get("time_end", "", type=str).strip()

        per_page = min(max(per_page, 10), 500)
        offset = (page - 1) * per_page
        client = get_client()
        params = {"case_id": case.id, "limit": per_page, "offset": offset}

        type_filter = build_hunting_type_filter(artifact_types, params)
        alert_type_filter = _build_hunting_alert_type_filter(
            sigma_filter_param,
            ioc_filter_param,
            analyst_filter_param,
            other_filter_param,
            severity_levels_param,
        )

        noise_filter = ""
        if not show_noise:
            noise_filter = " AND (noise_matched = false OR noise_matched IS NULL)"

        time_filter = build_hunting_time_filter(
            client,
            case.id,
            case_tz,
            time_range,
            time_start,
            time_end,
            params,
        )

        event_columns = """
            timestamp, timestamp_utc, artifact_type, source_file, source_path, source_host,
            event_id, channel, provider, record_id, level,
            username, domain, sid, logon_type,
            process_name, process_path, process_id, parent_process, parent_pid, command_line,
            target_path, file_hash_md5, file_hash_sha1, file_hash_sha256, file_size,
            src_ip, dst_ip, src_port, dst_port,
            reg_key, reg_value, reg_data,
            rule_title, rule_level, rule_file, mitre_tactics, mitre_tags,
            search_blob, extra_fields, raw_json, ioc_types, noise_matched,
            analyst_tagged, analyst_tags, analyst_notes
        """

        search_clause = build_hunting_search_clause(search, params)

        if search_clause:
            count_query = f"""
                SELECT count() FROM events
                WHERE case_id = {{case_id:UInt32}}{search_clause}{type_filter}{alert_type_filter}{noise_filter}{time_filter}
            """
            data_query = f"""
                SELECT {event_columns}
                FROM events
                WHERE case_id = {{case_id:UInt32}}{search_clause}{type_filter}{alert_type_filter}{noise_filter}{time_filter}
                ORDER BY timestamp DESC
                LIMIT {{limit:UInt32}} OFFSET {{offset:UInt32}}
            """
        else:
            count_query = f"SELECT count() FROM events WHERE case_id = {{case_id:UInt32}}{type_filter}{alert_type_filter}{noise_filter}{time_filter}"
            data_query = f"""
                SELECT {event_columns}
                FROM events
                WHERE case_id = {{case_id:UInt32}}{type_filter}{alert_type_filter}{noise_filter}{time_filter}
                ORDER BY timestamp DESC
                LIMIT {{limit:UInt32}} OFFSET {{offset:UInt32}}
            """

        count_result = client.query(count_query, parameters=params)
        total = count_result.result_rows[0][0] if count_result.result_rows else 0
        data_result = client.query(data_query, parameters=params)

        events = []
        for row in data_result.result_rows:
            (
                timestamp,
                timestamp_utc,
                artifact_type,
                source_file,
                source_path,
                source_host,
                event_id,
                channel,
                provider,
                record_id,
                level,
                username,
                domain,
                sid,
                logon_type,
                process_name,
                process_path,
                process_id,
                parent_process,
                parent_pid,
                command_line,
                target_path,
                file_hash_md5,
                file_hash_sha1,
                file_hash_sha256,
                file_size,
                src_ip,
                dst_ip,
                src_port,
                dst_port,
                reg_key,
                reg_value,
                reg_data,
                rule_title,
                rule_level,
                rule_file,
                mitre_tactics,
                mitre_tags,
                search_blob,
                extra_fields,
                raw_json,
                ioc_types,
                noise_matched,
                analyst_tagged,
                analyst_tags,
                analyst_notes,
            ) = row

            description = build_event_description(
                artifact_type,
                channel,
                provider,
                username,
                process_name,
                command_line,
                target_path,
                search_blob,
            )
            display_ts = timestamp_utc if timestamp_utc else timestamp

            events.append(
                {
                    "timestamp": format_for_display(display_ts, case_tz) if display_ts else "-",
                    "timestamp_utc_raw": display_ts.strftime("%Y-%m-%d %H:%M:%S") if display_ts else "",
                    "artifact_type": artifact_type or "-",
                    "source_host": source_host or "-",
                    "description": description,
                    "rule_level": rule_level or "",
                    "source_file": source_file or "",
                    "source_path": source_path or "",
                    "event_id": event_id or "",
                    "channel": channel or "",
                    "provider": provider or "",
                    "record_id": record_id,
                    "level": level or "",
                    "username": username or "",
                    "domain": domain or "",
                    "sid": sid or "",
                    "logon_type": logon_type,
                    "process_name": process_name or "",
                    "process_path": process_path or "",
                    "process_id": process_id,
                    "parent_process": parent_process or "",
                    "parent_pid": parent_pid,
                    "command_line": command_line or "",
                    "target_path": target_path or "",
                    "file_hash_md5": file_hash_md5 or "",
                    "file_hash_sha1": file_hash_sha1 or "",
                    "file_hash_sha256": file_hash_sha256 or "",
                    "file_size": file_size,
                    "src_ip": str(src_ip) if src_ip else "",
                    "dst_ip": str(dst_ip) if dst_ip else "",
                    "src_port": src_port,
                    "dst_port": dst_port,
                    "reg_key": reg_key or "",
                    "reg_value": reg_value or "",
                    "reg_data": reg_data or "",
                    "rule_title": rule_title or "",
                    "rule_file": rule_file or "",
                    "mitre_tactics": list(mitre_tactics) if mitre_tactics else [],
                    "mitre_tags": list(mitre_tags) if mitre_tags else [],
                    "search_blob": search_blob or "",
                    "extra_fields": extra_fields or "{}",
                    "raw_json": raw_json or "",
                    "ioc_types": list(ioc_types) if ioc_types else [],
                    "noise_matched": bool(noise_matched) if noise_matched else False,
                    "analyst_tagged": bool(analyst_tagged) if analyst_tagged else False,
                    "analyst_tags": list(analyst_tags) if analyst_tags else [],
                    "analyst_notes": analyst_notes or "",
                }
            )

        total_pages = (total + per_page - 1) // per_page if total > 0 else 1
        return jsonify(
            {
                "success": True,
                "case_id": case_id,
                "events": events,
                "total": total,
                "page": page,
                "per_page": per_page,
                "total_pages": total_pages,
            }
        )

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@hunting_bp.route("/hunting/event/raw/<int:case_id>")
@login_required
def get_raw_event_data(case_id):
    """Get full raw data for a specific event from ClickHouse."""
    try:
        from datetime import datetime, timedelta, timezone

        from utils.clickhouse import get_client

        case = Case.get_by_id(case_id)
        if not case:
            return jsonify({"success": False, "error": "Case not found"}), 404

        timestamp = request.args.get("timestamp", "", type=str).strip()
        source_host = request.args.get("source_host", "", type=str).strip()
        record_id = request.args.get("record_id", "", type=str).strip()
        artifact_type = request.args.get("artifact_type", "", type=str).strip()
        event_id = request.args.get("event_id", "", type=str).strip()

        if not timestamp:
            return jsonify({"success": False, "error": "Timestamp is required"}), 400

        client = get_client()
        conditions = ["case_id = {case_id:UInt32}"]
        params = {"case_id": case.id}

        try:
            ts = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")
            ts = ts.replace(tzinfo=timezone.utc)
            params["ts_start"] = ts
            params["ts_end"] = ts + timedelta(seconds=2)
            conditions.append(
                "COALESCE(timestamp_utc, timestamp) >= {ts_start:DateTime64} "
                "AND COALESCE(timestamp_utc, timestamp) < {ts_end:DateTime64}"
            )
        except ValueError:
            return jsonify({"success": False, "error": "Invalid timestamp format"}), 400

        if source_host and source_host != "-":
            params["source_host"] = source_host
            conditions.append("source_host = {source_host:String}")

        if record_id and record_id != "0":
            try:
                rid = int(record_id)
                if rid > 0:
                    params["record_id"] = rid
                    conditions.append("record_id = {record_id:UInt64}")
            except (ValueError, TypeError):
                pass

        if artifact_type and artifact_type != "-":
            params["artifact_type"] = artifact_type
            conditions.append("artifact_type = {artifact_type:String}")

        if event_id and event_id != "-":
            params["event_id"] = event_id
            conditions.append("event_id = {event_id:String}")

        query = f"SELECT * FROM events WHERE {' AND '.join(conditions)} LIMIT 1"
        result = client.query(query, parameters=params)
        if not result.result_rows:
            return jsonify({"success": False, "error": "Event not found"}), 404

        raw_data = {}
        for i, col_name in enumerate(result.column_names):
            value = result.result_rows[0][i]
            if value is None:
                raw_data[col_name] = None
            elif hasattr(value, "isoformat"):
                raw_data[col_name] = value.isoformat()
            elif isinstance(value, (list, tuple)):
                raw_data[col_name] = [str(v) if hasattr(v, "packed") else v for v in value]
            elif isinstance(value, bytes):
                raw_data[col_name] = value.decode("utf-8", errors="replace")
            elif hasattr(value, "packed"):
                raw_data[col_name] = str(value)
            elif col_name == "extra_fields" and value:
                try:
                    raw_data[col_name] = json.loads(value) if isinstance(value, str) else value
                except json.JSONDecodeError:
                    raw_data[col_name] = value
            else:
                raw_data[col_name] = value

        return jsonify({"success": True, "raw_data": raw_data})

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@hunting_bp.route("/hunting/event/tag/<int:case_id>", methods=["POST"])
@login_required
def update_analyst_tag(case_id):
    """Update analyst tagging for a specific event in ClickHouse."""
    try:
        from datetime import datetime, timedelta, timezone

        from utils.clickhouse import get_client

        if current_user.permission_level == "viewer":
            return _viewer_write_error("Viewers cannot modify hunting state")

        case = Case.get_by_id(case_id)
        if not case:
            return jsonify({"success": False, "error": "Case not found"}), 404

        data = request.get_json()
        if not data:
            return jsonify({"success": False, "error": "No data provided"}), 400

        event_id = data.get("event_id", "").strip() if data.get("event_id") else ""
        record_id = data.get("record_id", "")
        source_file = data.get("source_file", "").strip() if data.get("source_file") else ""
        timestamp = data.get("timestamp", "").strip()
        source_host = data.get("source_host", "").strip()
        artifact_type = data.get("artifact_type", "").strip()
        analyst_tagged = data.get("analyst_tagged", False)
        analyst_tags = data.get("analyst_tags", [])
        analyst_notes = data.get("analyst_notes", "")

        conditions = ["case_id = {case_id:UInt32}"]
        params = {"case_id": case_id}
        has_unique_id = False

        if event_id and event_id != "-":
            params["event_id"] = event_id
            conditions.append("event_id = {event_id:String}")
            has_unique_id = True

        if record_id and str(record_id) != "0":
            try:
                rid = int(record_id)
                if rid > 0:
                    params["record_id"] = rid
                    conditions.append("record_id = {record_id:UInt64}")
                    if source_file and source_host and source_host != "-":
                        params["source_file"] = source_file
                        params["source_host"] = source_host
                        conditions.append("source_file = {source_file:String}")
                        conditions.append("source_host = {source_host:String}")
                        has_unique_id = True
            except (ValueError, TypeError):
                pass

        if not has_unique_id:
            if not timestamp:
                return jsonify({"success": False, "error": "No unique identifier available"}), 400
            try:
                ts = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")
                ts = ts.replace(tzinfo=timezone.utc)
                params["ts_start"] = ts
                params["ts_end"] = ts + timedelta(seconds=2)
                conditions.append(
                    "COALESCE(timestamp_utc, timestamp) >= {ts_start:DateTime64} "
                    "AND COALESCE(timestamp_utc, timestamp) < {ts_end:DateTime64}"
                )
                if source_host and source_host != "-":
                    params["source_host"] = source_host
                    conditions.append("source_host = {source_host:String}")
                if artifact_type and artifact_type != "-":
                    params["artifact_type"] = artifact_type
                    conditions.append("artifact_type = {artifact_type:String}")
            except ValueError:
                return jsonify({"success": False, "error": "Invalid timestamp format"}), 400

        client = get_client()
        tags_array = [str(t).strip() for t in analyst_tags if t and str(t).strip()]
        notes_value = str(analyst_notes).strip() if analyst_notes else None

        set_parts = [f"analyst_tagged = {1 if analyst_tagged else 0}"]
        if tags_array:
            escaped_tags = [t.replace("'", "\\'") for t in tags_array]
            tags_str = ", ".join([f"'{t}'" for t in escaped_tags])
            set_parts.append(f"analyst_tags = [{tags_str}]")
        else:
            set_parts.append("analyst_tags = []")

        if notes_value:
            escaped_notes = notes_value.replace("'", "\\'").replace("\\", "\\\\")
            set_parts.append(f"analyst_notes = '{escaped_notes}'")
        else:
            set_parts.append("analyst_notes = NULL")

        query = f"ALTER TABLE events UPDATE {', '.join(set_parts)} WHERE {' AND '.join(conditions)}"
        client.query(query, parameters=params)

        return jsonify(
            {
                "success": True,
                "message": "Event tag updated successfully",
                "analyst_tagged": analyst_tagged,
                "analyst_tags": tags_array,
                "analyst_notes": notes_value,
            }
        )

    except Exception as e:
        logger.error("Error updating analyst tag: %s", e)
        return jsonify({"success": False, "error": str(e)}), 500


@hunting_bp.route("/hunting/events/bulk-tag/<int:case_id>", methods=["POST"])
@login_required
def bulk_analyst_tag(case_id):
    """Bulk update analyst tagging for multiple events."""
    try:
        from datetime import datetime, timedelta, timezone

        from utils.clickhouse import get_client

        if current_user.permission_level == "viewer":
            return _viewer_write_error("Viewers cannot modify hunting state")

        case = Case.get_by_id(case_id)
        if not case:
            return jsonify({"success": False, "error": "Case not found"}), 404

        data = request.get_json()
        if not data or "events" not in data:
            return jsonify({"success": False, "error": "No events provided"}), 400

        events = data.get("events", [])
        analyst_tagged = data.get("analyst_tagged", True)
        analyst_tags = data.get("analyst_tags", [])
        analyst_notes = data.get("analyst_notes", "")
        if not events:
            return jsonify({"success": False, "error": "Empty events list"}), 400

        client = get_client()
        updated_count = 0
        tags_array = [str(t).strip() for t in analyst_tags if t and str(t).strip()]
        notes_value = str(analyst_notes).strip() if analyst_notes else None

        set_parts = [f"analyst_tagged = {1 if analyst_tagged else 0}"]
        if tags_array:
            escaped_tags = [t.replace("'", "\\'") for t in tags_array]
            tags_str = ", ".join([f"'{t}'" for t in escaped_tags])
            set_parts.append(f"analyst_tags = [{tags_str}]")
        else:
            set_parts.append("analyst_tags = []")

        if notes_value:
            escaped_notes = notes_value.replace("'", "\\'").replace("\\", "\\\\")
            set_parts.append(f"analyst_notes = '{escaped_notes}'")
        else:
            set_parts.append("analyst_notes = NULL")

        for event in events:
            event_id = event.get("event_id", "").strip() if event.get("event_id") else ""
            record_id = event.get("record_id", "")
            source_file = event.get("source_file", "").strip() if event.get("source_file") else ""
            source_host = event.get("source_host", "").strip() if event.get("source_host") else ""
            timestamp = event.get("timestamp", "").strip() if event.get("timestamp") else ""
            artifact_type = event.get("artifact_type", "").strip() if event.get("artifact_type") else ""

            conditions = ["case_id = {case_id:UInt32}"]
            params = {"case_id": case_id}
            has_unique_id = False

            if event_id and event_id != "-":
                params["event_id"] = event_id
                conditions.append("event_id = {event_id:String}")
                has_unique_id = True

            if record_id and str(record_id) != "0":
                try:
                    rid = int(record_id)
                    if rid > 0:
                        params["record_id"] = rid
                        conditions.append("record_id = {record_id:UInt64}")
                        if source_file and source_host and source_host != "-":
                            params["source_file"] = source_file
                            params["source_host"] = source_host
                            conditions.append("source_file = {source_file:String}")
                            conditions.append("source_host = {source_host:String}")
                            has_unique_id = True
                except (ValueError, TypeError):
                    pass

            if not has_unique_id and timestamp:
                try:
                    ts = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")
                    ts = ts.replace(tzinfo=timezone.utc)
                    params["ts_start"] = ts
                    params["ts_end"] = ts + timedelta(seconds=2)
                    conditions.append(
                        "COALESCE(timestamp_utc, timestamp) >= {ts_start:DateTime64} "
                        "AND COALESCE(timestamp_utc, timestamp) < {ts_end:DateTime64}"
                    )
                    if source_host and source_host != "-":
                        params["source_host"] = source_host
                        conditions.append("source_host = {source_host:String}")
                    if artifact_type and artifact_type != "-":
                        params["artifact_type"] = artifact_type
                        conditions.append("artifact_type = {artifact_type:String}")
                except ValueError:
                    continue
            elif not has_unique_id:
                continue

            query = f"ALTER TABLE events UPDATE {', '.join(set_parts)} WHERE {' AND '.join(conditions)}"
            try:
                client.query(query, parameters=params)
                updated_count += 1
            except Exception as e:
                logger.warning("Failed to update event: %s", e)

        return jsonify(
            {
                "success": True,
                "updated": updated_count,
                "total": len(events),
                "message": f"Successfully tagged {updated_count} event(s)",
            }
        )

    except Exception as e:
        logger.error("Error in bulk analyst tag: %s", e)
        return jsonify({"success": False, "error": str(e)}), 500


@hunting_bp.route("/hunting/events/bulk-noise/<int:case_id>", methods=["POST"])
@login_required
def bulk_noise_tag(case_id):
    """Bulk mark events as noise."""
    try:
        from datetime import datetime, timedelta, timezone

        from utils.clickhouse import get_client

        if current_user.permission_level == "viewer":
            return _viewer_write_error("Viewers cannot modify hunting state")

        case = Case.get_by_id(case_id)
        if not case:
            return jsonify({"success": False, "error": "Case not found"}), 404

        data = request.get_json()
        if not data or "events" not in data:
            return jsonify({"success": False, "error": "No events provided"}), 400

        events = data.get("events", [])
        if not events:
            return jsonify({"success": False, "error": "Empty events list"}), 400

        client = get_client()
        updated_count = 0

        for event in events:
            event_id = event.get("event_id", "").strip() if event.get("event_id") else ""
            record_id = event.get("record_id", "")
            source_file = event.get("source_file", "").strip() if event.get("source_file") else ""
            source_host = event.get("source_host", "").strip() if event.get("source_host") else ""
            timestamp = event.get("timestamp", "").strip() if event.get("timestamp") else ""
            artifact_type = event.get("artifact_type", "").strip() if event.get("artifact_type") else ""

            conditions = ["case_id = {case_id:UInt32}"]
            params = {"case_id": case_id}
            has_unique_id = False

            if event_id and event_id != "-":
                params["event_id"] = event_id
                conditions.append("event_id = {event_id:String}")
                has_unique_id = True

            if record_id and str(record_id) != "0":
                try:
                    rid = int(record_id)
                    if rid > 0:
                        params["record_id"] = rid
                        conditions.append("record_id = {record_id:UInt64}")
                        if source_file and source_host and source_host != "-":
                            params["source_file"] = source_file
                            params["source_host"] = source_host
                            conditions.append("source_file = {source_file:String}")
                            conditions.append("source_host = {source_host:String}")
                            has_unique_id = True
                except (ValueError, TypeError):
                    pass

            if not has_unique_id and timestamp:
                try:
                    ts = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")
                    ts = ts.replace(tzinfo=timezone.utc)
                    params["ts_start"] = ts
                    params["ts_end"] = ts + timedelta(seconds=2)
                    conditions.append(
                        "COALESCE(timestamp_utc, timestamp) >= {ts_start:DateTime64} "
                        "AND COALESCE(timestamp_utc, timestamp) < {ts_end:DateTime64}"
                    )
                    if source_host and source_host != "-":
                        params["source_host"] = source_host
                        conditions.append("source_host = {source_host:String}")
                    if artifact_type and artifact_type != "-":
                        params["artifact_type"] = artifact_type
                        conditions.append("artifact_type = {artifact_type:String}")
                except ValueError:
                    continue
            elif not has_unique_id:
                continue

            query = f"ALTER TABLE events UPDATE noise_matched = true WHERE {' AND '.join(conditions)}"
            try:
                client.query(query, parameters=params)
                updated_count += 1
            except Exception as e:
                logger.warning("Failed to mark event as noise: %s", e)

        return jsonify(
            {
                "success": True,
                "updated": updated_count,
                "total": len(events),
                "message": f"Successfully marked {updated_count} event(s) as noise",
            }
        )

    except Exception as e:
        logger.error("Error in bulk noise tag: %s", e)
        return jsonify({"success": False, "error": str(e)}), 500


@hunting_bp.route("/hunting/events/export-tagged/<int:case_id>")
@login_required
def export_tagged_events(case_id):
    """Export all analyst-tagged events with full data."""
    try:
        from datetime import datetime

        from utils.clickhouse import get_client

        case = Case.get_by_id(case_id)
        if not case:
            return jsonify({"success": False, "error": "Case not found"}), 404

        client = get_client()
        query = """
            SELECT *
            FROM events
            WHERE case_id = {case_id:UInt32}
            AND analyst_tagged = true
            ORDER BY timestamp DESC
        """
        result = client.query(query, parameters={"case_id": case_id})

        events = []
        for row in result.result_rows:
            event_data = {}
            for i, col_name in enumerate(result.column_names):
                value = row[i]
                if value is None:
                    event_data[col_name] = None
                elif hasattr(value, "isoformat"):
                    event_data[col_name] = value.isoformat()
                elif isinstance(value, (list, tuple)):
                    event_data[col_name] = [str(v) if hasattr(v, "packed") else v for v in value]
                elif isinstance(value, bytes):
                    event_data[col_name] = value.decode("utf-8", errors="replace")
                elif hasattr(value, "packed"):
                    event_data[col_name] = str(value)
                elif col_name in ("raw_json", "extra_fields") and value:
                    try:
                        event_data[col_name] = json.loads(value) if isinstance(value, str) else value
                    except json.JSONDecodeError:
                        event_data[col_name] = value
                else:
                    event_data[col_name] = value
            events.append(event_data)

        return jsonify(
            {
                "success": True,
                "case_id": case_id,
                "case_name": case.name,
                "export_timestamp": datetime.utcnow().isoformat(),
                "total_count": len(events),
                "events": events,
            }
        )

    except Exception as e:
        logger.error("Error exporting tagged events: %s", e)
        return jsonify({"success": False, "error": str(e)}), 500


@hunting_bp.route("/hunting/events/export-view/<int:case_id>")
@login_required
def export_view_events(case_id):
    """Export all events matching current view filters with full data."""
    try:
        from datetime import datetime

        from utils.clickhouse import get_client

        case = Case.get_by_id(case_id)
        if not case:
            return jsonify({"success": False, "error": "Case not found"}), 404

        case_tz = case.timezone or "UTC"
        client = get_client()
        search = request.args.get("search", "", type=str).strip()
        artifact_types = request.args.get("types", "", type=str).strip()
        sigma_filter_param = request.args.get("sigma_filter", "", type=str).strip()
        ioc_filter_param = request.args.get("ioc_filter", "", type=str).strip()
        analyst_filter_param = request.args.get("analyst_filter", "", type=str).strip()
        other_filter_param = request.args.get("other_filter", "", type=str).strip()
        severity_levels_param = request.args.get("severity_levels", "", type=str).strip()
        show_noise = request.args.get("show_noise", "false", type=str).strip().lower() == "true"
        time_range = request.args.get("time_range", "none", type=str).strip()
        time_start = request.args.get("time_start", "", type=str).strip()
        time_end = request.args.get("time_end", "", type=str).strip()

        params = {"case_id": case_id}
        type_filter = build_hunting_type_filter(artifact_types, params)
        alert_type_filter = _build_hunting_alert_type_filter(
            sigma_filter_param,
            ioc_filter_param,
            analyst_filter_param,
            other_filter_param,
            severity_levels_param,
        )

        noise_filter = ""
        if not show_noise:
            noise_filter = " AND (noise_matched = false OR noise_matched IS NULL)"

        time_filter = build_hunting_time_filter(
            client,
            case.id,
            case_tz,
            time_range,
            time_start,
            time_end,
            params,
        )
        search_clause = build_hunting_search_clause(search, params)

        query = f"""
            SELECT *
            FROM events
            WHERE case_id = {{case_id:UInt32}}{search_clause}{type_filter}{alert_type_filter}{noise_filter}{time_filter}
            ORDER BY timestamp DESC
        """
        result = client.query(query, parameters=params)

        events = []
        for row in result.result_rows:
            event_data = {}
            for i, col_name in enumerate(result.column_names):
                value = row[i]
                if value is None:
                    event_data[col_name] = None
                elif hasattr(value, "isoformat"):
                    event_data[col_name] = value.isoformat()
                elif isinstance(value, (list, tuple)):
                    event_data[col_name] = [str(v) if hasattr(v, "packed") else v for v in value]
                elif isinstance(value, bytes):
                    event_data[col_name] = value.decode("utf-8", errors="replace")
                elif hasattr(value, "packed"):
                    event_data[col_name] = str(value)
                elif col_name in ("raw_json", "extra_fields") and value:
                    try:
                        event_data[col_name] = json.loads(value) if isinstance(value, str) else value
                    except json.JSONDecodeError:
                        event_data[col_name] = value
                else:
                    event_data[col_name] = value
            events.append(event_data)

        return jsonify(
            {
                "success": True,
                "case_id": case_id,
                "case_name": case.name,
                "export_timestamp": datetime.utcnow().isoformat(),
                "total_count": len(events),
                "events": events,
            }
        )

    except ValueError as e:
        logger.error("Error exporting view events: %s", e)
        return jsonify({"success": False, "error": str(e)}), 400
    except Exception as e:
        logger.error("Error exporting view events: %s", e)
        return jsonify({"success": False, "error": str(e)}), 500


@hunting_bp.route("/hunting/process/children/<int:case_id>")
@login_required
def get_process_children(case_id):
    """Get child processes of a given process."""
    try:
        from utils.clickhouse import get_client
        from utils.timezone import format_for_display

        case = Case.get_by_id(case_id)
        if not case:
            return jsonify({"success": False, "error": "Case not found"}), 404

        case_tz = case.timezone or "UTC"
        hostname = request.args.get("host", "", type=str).strip()
        parent_pid = request.args.get("parent_pid", 0, type=int)
        parent_process = request.args.get("parent_process", "", type=str).strip()

        if not hostname or not parent_pid:
            return jsonify({"success": False, "error": "host and parent_pid are required"}), 400

        client = get_client()
        query = """
            SELECT
                COALESCE(timestamp_utc, timestamp) as ts,
                process_name,
                process_path,
                process_id,
                parent_process,
                parent_pid,
                command_line,
                username
            FROM events
            WHERE case_id = {case_id:UInt32}
            AND source_host = {hostname:String}
            AND parent_pid = {parent_pid:UInt64}
            AND process_name != ''
        """
        params = {"case_id": case_id, "hostname": hostname, "parent_pid": parent_pid}
        if parent_process:
            query += " AND parent_process = {parent_process:String}"
            params["parent_process"] = parent_process
        query += " ORDER BY timestamp ASC LIMIT 100"

        result = client.query(query, parameters=params)
        children = []
        for row in result.result_rows:
            ts, proc_name, proc_path, pid, par_proc, par_pid, cmdline, username = row
            child_count_result = client.query(
                """SELECT count() FROM events
                   WHERE case_id = {case_id:UInt32}
                   AND source_host = {hostname:String}
                   AND parent_pid = {pid:UInt64}
                   AND process_name != ''
                   LIMIT 1""",
                parameters={"case_id": case_id, "hostname": hostname, "pid": pid or 0},
            )
            child_count = child_count_result.result_rows[0][0] if child_count_result.result_rows else 0

            children.append(
                {
                    "timestamp": format_for_display(ts, case_tz) if ts else "",
                    "process_name": proc_name or "",
                    "process_path": proc_path or "",
                    "pid": pid,
                    "parent_process": par_proc or "",
                    "parent_pid": par_pid,
                    "command_line": cmdline or "",
                    "username": username or "",
                    "child_count": child_count,
                }
            )

        return jsonify(
            {
                "success": True,
                "children": children,
                "parent_pid": parent_pid,
                "parent_process": parent_process,
                "hostname": hostname,
            }
        )

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@hunting_bp.route("/hunting/process/parent/<int:case_id>")
@login_required
def get_process_parent(case_id):
    """Get parent process and siblings."""
    try:
        from utils.clickhouse import get_client
        from utils.timezone import format_for_display

        case = Case.get_by_id(case_id)
        if not case:
            return jsonify({"success": False, "error": "Case not found"}), 404

        case_tz = case.timezone or "UTC"
        hostname = request.args.get("host", "", type=str).strip()
        pid = request.args.get("pid", 0, type=int)

        if not hostname:
            return jsonify({"success": False, "error": "host is required"}), 400

        client = get_client()
        parent = None
        if pid:
            parent_query = """
                SELECT
                    COALESCE(timestamp_utc, timestamp) as ts,
                    process_name,
                    process_path,
                    process_id,
                    parent_process,
                    parent_pid,
                    command_line,
                    username
                FROM events
                WHERE case_id = {case_id:UInt32}
                AND source_host = {hostname:String}
                AND process_id = {pid:UInt64}
                AND process_name != ''
                ORDER BY timestamp DESC
                LIMIT 1
            """
            result = client.query(parent_query, parameters={"case_id": case_id, "hostname": hostname, "pid": pid})
            if result.result_rows:
                row = result.result_rows[0]
                parent = {
                    "timestamp": format_for_display(row[0], case_tz) if row[0] else "",
                    "process_name": row[1] or "",
                    "process_path": row[2] or "",
                    "pid": row[3],
                    "parent_process": row[4] or "",
                    "parent_pid": row[5],
                    "command_line": row[6] or "",
                    "username": row[7] or "",
                }

        siblings = []
        if parent and parent["pid"]:
            siblings_query = """
                SELECT
                    COALESCE(timestamp_utc, timestamp) as ts,
                    process_name,
                    process_path,
                    process_id,
                    parent_process,
                    parent_pid,
                    command_line,
                    username
                FROM events
                WHERE case_id = {case_id:UInt32}
                AND source_host = {hostname:String}
                AND parent_pid = {parent_pid:UInt64}
                AND process_name != ''
                ORDER BY timestamp ASC
                LIMIT 50
            """
            result = client.query(
                siblings_query,
                parameters={"case_id": case_id, "hostname": hostname, "parent_pid": parent["pid"]},
            )
            for row in result.result_rows:
                child_count_result = client.query(
                    """SELECT count() FROM events
                       WHERE case_id = {case_id:UInt32}
                       AND source_host = {hostname:String}
                       AND parent_pid = {pid:UInt64}
                       AND process_name != ''
                       LIMIT 1""",
                    parameters={"case_id": case_id, "hostname": hostname, "pid": row[3] or 0},
                )
                child_count = child_count_result.result_rows[0][0] if child_count_result.result_rows else 0
                siblings.append(
                    {
                        "timestamp": format_for_display(row[0], case_tz) if row[0] else "",
                        "process_name": row[1] or "",
                        "process_path": row[2] or "",
                        "pid": row[3],
                        "parent_process": row[4] or "",
                        "parent_pid": row[5],
                        "command_line": row[6] or "",
                        "username": row[7] or "",
                        "child_count": child_count,
                    }
                )

        return jsonify({"success": True, "parent": parent, "siblings": siblings, "hostname": hostname})

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@hunting_bp.route("/hunting/processes/list/<int:case_id>")
@login_required
def get_unified_processes(case_id):
    """Get unified process list from all sources."""
    try:
        from models.memory_data import MemoryProcess
        from models.memory_job import MemoryJob
        from utils.clickhouse import get_client
        from utils.timezone import format_for_display

        case = Case.get_by_id(case_id)
        if not case:
            return jsonify({"success": False, "error": "Case not found"}), 404

        case_tz = case.timezone or "UTC"
        page = request.args.get("page", 1, type=int)
        per_page = min(request.args.get("per_page", 50, type=int), 200)
        offset = (page - 1) * per_page
        search = request.args.get("search", "", type=str).strip()
        hostname_filter = request.args.get("hostname", "", type=str).strip()
        source_filter = request.args.get("source", "", type=str).strip()

        processes = []
        total_events = 0
        total_memory = 0

        if source_filter in ("", "events"):
            client = get_client()
            executable_filter = """(
                process_name LIKE '%.exe' OR
                process_name LIKE '%.dll' OR
                process_name LIKE '%.bat' OR
                process_name LIKE '%.cmd' OR
                process_name LIKE '%.ps1' OR
                process_name LIKE '%.vbs' OR
                process_name LIKE '%.com' OR
                process_name LIKE '%.msi' OR
                process_name LIKE '%.js' OR
                process_name LIKE '%.wsf'
            )"""
            where_clauses = [
                "case_id = {case_id:UInt32}",
                "process_name != ''",
                "process_id > 0",
                executable_filter,
            ]
            params = {"case_id": case_id}
            if hostname_filter:
                where_clauses.append("source_host = {hostname:String}")
                params["hostname"] = hostname_filter
            if search:
                where_clauses.append("(process_name ILIKE {search:String} OR command_line ILIKE {search:String} OR parent_process ILIKE {search:String})")
                params["search"] = f"%{search}%"

            where_sql = " AND ".join(where_clauses)
            count_query = f"""
                SELECT count(DISTINCT (source_host, process_id, process_name))
                FROM events
                WHERE {where_sql}
            """
            count_result = client.query(count_query, parameters=params)
            total_events = count_result.result_rows[0][0] if count_result.result_rows else 0

            if source_filter != "memory":
                query = f"""
                    SELECT
                        source_host,
                        process_id,
                        process_name,
                        max(COALESCE(timestamp_utc, timestamp)) as latest_ts,
                        min(COALESCE(timestamp_utc, timestamp)) as first_ts,
                        argMax(parent_pid, COALESCE(timestamp_utc, timestamp)) as ppid_val,
                        argMax(parent_process, COALESCE(timestamp_utc, timestamp)) as parent_proc_val,
                        argMax(command_line, COALESCE(timestamp_utc, timestamp)) as cmdline_val,
                        argMax(username, COALESCE(timestamp_utc, timestamp)) as username_val,
                        argMax(process_path, COALESCE(timestamp_utc, timestamp)) as proc_path_val,
                        count() as event_count
                    FROM events
                    WHERE {where_sql}
                    GROUP BY source_host, process_id, process_name
                    ORDER BY latest_ts DESC
                    LIMIT {per_page} OFFSET {offset}
                """
                result = client.query(query, parameters=params)
                pid_list = [(row[0], row[1]) for row in result.result_rows]
                children_set = set()
                if pid_list:
                    pids_str = ",".join([str(p[1]) for p in pid_list if p[1]])
                    if pids_str:
                        child_check_query = f"""
                            SELECT DISTINCT parent_pid
                            FROM events
                            WHERE case_id = {{case_id:UInt32}}
                            AND parent_pid IN ({pids_str})
                            AND process_name != ''
                        """
                        child_result = client.query(child_check_query, parameters={"case_id": case_id})
                        children_set = {row[0] for row in child_result.result_rows if row[0]}

                for row in result.result_rows:
                    hostname, pid, proc_name, latest_ts, first_ts, ppid, parent_proc, cmdline, username, proc_path, evt_count = row
                    processes.append(
                        {
                            "id": f"evt_{hostname}_{pid}_{proc_name}",
                            "source": "events",
                            "hostname": hostname,
                            "pid": pid,
                            "ppid": ppid,
                            "process_name": proc_name or "",
                            "parent_process": parent_proc or "",
                            "command_line": cmdline or "",
                            "username": username or "",
                            "process_path": proc_path or "",
                            "timestamp": format_for_display(latest_ts, case_tz) if latest_ts else "",
                            "first_seen": format_for_display(first_ts, case_tz) if first_ts else "",
                            "event_count": evt_count,
                            "has_children": pid in children_set,
                            "has_parent": bool(ppid and ppid > 0),
                        }
                    )

        if source_filter in ("", "memory"):
            jobs = MemoryJob.query.filter_by(case_id=case_id, status="completed").all()
            job_ids = [j.id for j in jobs]
            if job_ids:
                query = MemoryProcess.query.filter(
                    MemoryProcess.job_id.in_(job_ids),
                    MemoryProcess.case_id == case_id,
                )
                if hostname_filter:
                    query = query.filter(MemoryProcess.hostname == hostname_filter)
                if search:
                    search_term = f"%{search}%"
                    query = query.filter(
                        db.or_(
                            MemoryProcess.name.ilike(search_term),
                            MemoryProcess.cmdline.ilike(search_term),
                            MemoryProcess.path.ilike(search_term),
                        )
                    )

                total_memory = query.count()
                if source_filter != "events":
                    if source_filter == "memory":
                        mem_procs = query.order_by(MemoryProcess.create_time.desc()).offset(offset).limit(per_page).all()
                    else:
                        mem_procs = query.order_by(MemoryProcess.create_time.desc()).limit(500).all()

                    all_pids_by_host = {}
                    all_ppids_by_host = {}
                    for mp in MemoryProcess.query.filter(MemoryProcess.job_id.in_(job_ids)).all():
                        host = mp.hostname
                        if host not in all_pids_by_host:
                            all_pids_by_host[host] = set()
                            all_ppids_by_host[host] = set()
                        all_pids_by_host[host].add(mp.pid)
                        if mp.ppid:
                            all_ppids_by_host[host].add(mp.ppid)

                    for mp in mem_procs:
                        processes.append(
                            {
                                "id": f"mem_{mp.id}",
                                "source": "memory",
                                "hostname": mp.hostname,
                                "pid": mp.pid,
                                "ppid": mp.ppid,
                                "process_name": mp.name or "",
                                "parent_process": "",
                                "command_line": mp.cmdline or "",
                                "username": "",
                                "process_path": mp.path or "",
                                "timestamp": format_for_display(mp.create_time, case_tz) if mp.create_time else "",
                                "first_seen": "",
                                "event_count": 1,
                                "has_children": mp.pid in all_ppids_by_host.get(mp.hostname, set()),
                                "has_parent": bool(mp.ppid and mp.ppid in all_pids_by_host.get(mp.hostname, set())),
                                "cross_memory_count": mp.cross_memory_count,
                                "cross_events_count": mp.cross_events_count,
                            }
                        )

        processes.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
        if source_filter == "":
            processes = processes[:per_page]

        total = total_events + total_memory
        return jsonify(
            {
                "success": True,
                "processes": processes,
                "total": total,
                "total_events": total_events,
                "total_memory": total_memory,
                "page": page,
                "per_page": per_page,
                "pages": (total + per_page - 1) // per_page if total > 0 else 0,
            }
        )

    except Exception as e:
        logger.error("Error fetching unified processes: %s", e)
        return jsonify({"success": False, "error": str(e)}), 500


@hunting_bp.route("/hunting/processes/tree/<int:case_id>")
@login_required
def get_unified_process_tree(case_id):
    """Get process tree for a specific process from all sources."""
    try:
        from models.memory_data import MemoryProcess
        from models.memory_job import MemoryJob
        from utils.clickhouse import get_client
        from utils.timezone import format_for_display

        case = Case.get_by_id(case_id)
        if not case:
            return jsonify({"success": False, "error": "Case not found"}), 404

        case_tz = case.timezone or "UTC"
        hostname = request.args.get("hostname", "", type=str).strip()
        pid = request.args.get("pid", 0, type=int)
        process_name = request.args.get("process_name", "", type=str).strip()
        include_parent = request.args.get("include_parent", "true", type=str).lower() == "true"
        max_depth = min(request.args.get("max_depth", 5, type=int), 10)

        if not hostname or not pid:
            return jsonify({"success": False, "error": "hostname and pid are required"}), 400

        client = get_client()

        def get_process_from_events(host, p_id, p_name=None):
            query = """
                SELECT
                    source_host,
                    process_id,
                    process_name,
                    max(COALESCE(timestamp_utc, timestamp)) as latest_ts,
                    argMax(parent_pid, COALESCE(timestamp_utc, timestamp)) as ppid_val,
                    argMax(parent_process, COALESCE(timestamp_utc, timestamp)) as parent_proc_val,
                    argMax(command_line, COALESCE(timestamp_utc, timestamp)) as cmdline_val,
                    argMax(username, COALESCE(timestamp_utc, timestamp)) as username_val,
                    argMax(process_path, COALESCE(timestamp_utc, timestamp)) as proc_path_val
                FROM events
                WHERE case_id = {case_id:UInt32}
                AND source_host = {hostname:String}
                AND process_id = {pid:UInt64}
                AND process_name != ''
            """
            params = {"case_id": case_id, "hostname": host, "pid": p_id}
            if p_name:
                query += " AND process_name = {process_name:String}"
                params["process_name"] = p_name
            query += " GROUP BY source_host, process_id, process_name LIMIT 1"

            result = client.query(query, parameters=params)
            if result.result_rows:
                row = result.result_rows[0]
                return {
                    "source": "events",
                    "hostname": row[0],
                    "pid": row[1],
                    "process_name": row[2] or "",
                    "timestamp": format_for_display(row[3], case_tz) if row[3] else "",
                    "ppid": row[4],
                    "parent_process": row[5] or "",
                    "command_line": row[6] or "",
                    "username": row[7] or "",
                    "process_path": row[8] or "",
                }
            return None

        def get_children_from_events(host, parent_pid_val, parent_name=None, depth=0):
            if depth >= max_depth:
                return []
            query = """
                SELECT
                    source_host,
                    process_id,
                    process_name,
                    max(COALESCE(timestamp_utc, timestamp)) as latest_ts,
                    argMax(parent_pid, COALESCE(timestamp_utc, timestamp)) as ppid_val,
                    argMax(parent_process, COALESCE(timestamp_utc, timestamp)) as parent_proc_val,
                    argMax(command_line, COALESCE(timestamp_utc, timestamp)) as cmdline_val,
                    argMax(username, COALESCE(timestamp_utc, timestamp)) as username_val
                FROM events
                WHERE case_id = {case_id:UInt32}
                AND source_host = {hostname:String}
                AND parent_pid = {parent_pid:UInt64}
                AND parent_process = {parent_process:String}
                AND process_name != ''
                GROUP BY source_host, process_id, process_name
                ORDER BY latest_ts ASC
                LIMIT 50
            """
            params = {
                "case_id": case_id,
                "hostname": host,
                "parent_pid": parent_pid_val,
                "parent_process": parent_name or "",
            }
            result = client.query(query, parameters=params)
            children = []
            for row in result.result_rows:
                children.append(
                    {
                        "source": "events",
                        "hostname": row[0],
                        "pid": row[1],
                        "process_name": row[2] or "",
                        "timestamp": format_for_display(row[3], case_tz) if row[3] else "",
                        "ppid": row[4],
                        "parent_process": row[5] or "",
                        "command_line": row[6] or "",
                        "username": row[7] or "",
                        "children": get_children_from_events(host, row[1], row[2], depth + 1),
                    }
                )
            return children

        def get_children_from_memory(host, parent_pid_val, depth=0):
            if depth >= max_depth:
                return []
            jobs = MemoryJob.query.filter_by(case_id=case_id, status="completed").all()
            job_ids = [j.id for j in jobs]
            if not job_ids:
                return []
            children_query = MemoryProcess.query.filter(
                MemoryProcess.job_id.in_(job_ids),
                MemoryProcess.hostname == host,
                MemoryProcess.ppid == parent_pid_val,
            ).all()
            children = []
            for mp in children_query:
                children.append(
                    {
                        "source": "memory",
                        "hostname": mp.hostname,
                        "pid": mp.pid,
                        "process_name": mp.name or "",
                        "timestamp": format_for_display(mp.create_time, case_tz) if mp.create_time else "",
                        "ppid": mp.ppid,
                        "parent_process": "",
                        "command_line": mp.cmdline or "",
                        "username": "",
                        "children": get_children_from_memory(host, mp.pid, depth + 1),
                    }
                )
            return children

        process = get_process_from_events(hostname, pid, process_name)
        if not process:
            jobs = MemoryJob.query.filter_by(case_id=case_id, status="completed").all()
            job_ids = [j.id for j in jobs]
            if job_ids:
                mp = MemoryProcess.query.filter(
                    MemoryProcess.job_id.in_(job_ids),
                    MemoryProcess.hostname == hostname,
                    MemoryProcess.pid == pid,
                ).first()
                if mp:
                    process = {
                        "source": "memory",
                        "hostname": mp.hostname,
                        "pid": mp.pid,
                        "process_name": mp.name or "",
                        "timestamp": format_for_display(mp.create_time, case_tz) if mp.create_time else "",
                        "ppid": mp.ppid,
                        "parent_process": "",
                        "command_line": mp.cmdline or "",
                        "username": "",
                        "process_path": mp.path or "",
                    }

        if not process:
            return jsonify({"success": False, "error": "Process not found"}), 404

        children_events = get_children_from_events(hostname, pid, process_name)
        children_memory = get_children_from_memory(hostname, pid)
        seen = set()
        all_children = []
        for child in children_events + children_memory:
            key = (child["pid"], child["process_name"])
            if key not in seen:
                seen.add(key)
                all_children.append(child)

        process["children"] = all_children

        parent_chain = None
        if include_parent and process.get("ppid"):
            parent_chain = []
            current_ppid = process.get("ppid")
            current_parent_name = process.get("parent_process", "")

            for _ in range(max_depth):
                if not current_ppid or current_ppid <= 0:
                    break

                parent = get_process_from_events(hostname, current_ppid, current_parent_name or None)
                if not parent:
                    jobs = MemoryJob.query.filter_by(case_id=case_id, status="completed").all()
                    job_ids = [j.id for j in jobs]
                    if job_ids:
                        mp = MemoryProcess.query.filter(
                            MemoryProcess.job_id.in_(job_ids),
                            MemoryProcess.hostname == hostname,
                            MemoryProcess.pid == current_ppid,
                        ).first()
                        if mp:
                            parent = {
                                "source": "memory",
                                "hostname": mp.hostname,
                                "pid": mp.pid,
                                "process_name": mp.name or "",
                                "timestamp": format_for_display(mp.create_time, case_tz) if mp.create_time else "",
                                "ppid": mp.ppid,
                                "parent_process": "",
                                "command_line": mp.cmdline or "",
                                "username": "",
                            }

                if parent:
                    parent_chain.append(parent)
                    current_ppid = parent.get("ppid")
                    current_parent_name = parent.get("parent_process", "")
                else:
                    parent_chain.append(
                        {
                            "source": "unknown",
                            "hostname": hostname,
                            "pid": current_ppid,
                            "process_name": current_parent_name or f"PID {current_ppid}",
                            "timestamp": "",
                            "ppid": None,
                            "parent_process": "",
                            "command_line": "",
                            "username": "",
                            "not_found": True,
                        }
                    )
                    break

        return jsonify({"success": True, "process": process, "parent_chain": parent_chain, "hostname": hostname})

    except Exception as e:
        logger.error("Error fetching process tree: %s", e)
        return jsonify({"success": False, "error": str(e)}), 500


@hunting_bp.route("/hunting/processes/hostnames/<int:case_id>")
@login_required
def get_process_hostnames(case_id):
    """Get unique hostnames that have process data."""
    try:
        from models.memory_data import MemoryProcess
        from models.memory_job import MemoryJob
        from utils.clickhouse import get_client

        case = Case.get_by_id(case_id)
        if not case:
            return jsonify({"success": False, "error": "Case not found"}), 404

        hostnames = set()
        client = get_client()
        query = """
            SELECT DISTINCT source_host
            FROM events
            WHERE case_id = {case_id:UInt32}
            AND process_name != ''
            AND process_id > 0
            AND (
                process_name LIKE '%.exe' OR
                process_name LIKE '%.dll' OR
                process_name LIKE '%.bat' OR
                process_name LIKE '%.cmd' OR
                process_name LIKE '%.ps1' OR
                process_name LIKE '%.vbs' OR
                process_name LIKE '%.com' OR
                process_name LIKE '%.msi'
            )
        """
        result = client.query(query, parameters={"case_id": case_id})
        for row in result.result_rows:
            if row[0]:
                hostnames.add(row[0])

        jobs = MemoryJob.query.filter_by(case_id=case_id, status="completed").all()
        job_ids = [j.id for j in jobs]
        if job_ids:
            mem_hosts = db.session.query(MemoryProcess.hostname).filter(MemoryProcess.job_id.in_(job_ids)).distinct().all()
            for row in mem_hosts:
                if row[0]:
                    hostnames.add(row[0])

        return jsonify({"success": True, "hostnames": sorted(list(hostnames))})

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500
