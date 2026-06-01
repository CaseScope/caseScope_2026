"""Hunting API routes."""

import csv
import io
import json
import logging
from datetime import datetime

from flask import Blueprint, Response, jsonify, request, stream_with_context
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
from utils.event_analyst_state import (
    build_analyst_projection,
    build_event_selector_key,
    ensure_event_analyst_state_table,
    normalize_analyst_tags,
    upsert_event_analyst_state_rows,
)
from utils.event_ioc_state import build_ioc_projection, ensure_event_ioc_state_tables
from utils.event_noise_state import (
    build_noise_projection,
    count_effective_noise_events,
    ensure_event_noise_state_tables,
    ensure_noise_overlay_case,
    upsert_manual_noise_state_rows,
)
from utils.forensic_chat_sources import get_browser_download_rows

logger = logging.getLogger(__name__)

hunting_bp = Blueprint("hunting", __name__, url_prefix="/api")


def _event_export_filename(prefix: str, case_id: int) -> str:
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    return f"{prefix}_case{case_id}_{timestamp}.csv"


def _coerce_event_export_value(col_name, value):
    if value is None:
        return None
    if hasattr(value, "isoformat"):
        return value.isoformat()
    if isinstance(value, (list, tuple)):
        return [str(v) if hasattr(v, "packed") else v for v in value]
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    if hasattr(value, "packed"):
        return str(value)
    if col_name in ("raw_json", "extra_fields") and value:
        try:
            return json.loads(value) if isinstance(value, str) else value
        except json.JSONDecodeError:
            return value
    return value


def _event_row_to_export_dict(row, column_names):
    event_data = {
        col_name: _coerce_event_export_value(col_name, row[i])
        for i, col_name in enumerate(column_names)
    }
    if "analyst_tagged_effective" in event_data:
        event_data["analyst_tagged"] = bool(event_data.pop("analyst_tagged_effective"))
    if "analyst_tags_effective" in event_data:
        event_data["analyst_tags"] = list(event_data.pop("analyst_tags_effective") or [])
    if "analyst_notes_effective" in event_data:
        event_data["analyst_notes"] = event_data.pop("analyst_notes_effective") or ""
    if "ioc_types_effective" in event_data:
        event_data["ioc_types"] = list(event_data.pop("ioc_types_effective") or [])
    if "noise_matched_effective" in event_data:
        event_data["noise_matched"] = bool(event_data.pop("noise_matched_effective"))
    if "noise_rules_effective" in event_data:
        event_data["noise_rules"] = list(event_data.pop("noise_rules_effective") or [])
    return event_data


def _event_export_header(column_names):
    header = []
    replacements = {
        "analyst_tagged_effective": "analyst_tagged",
        "analyst_tags_effective": "analyst_tags",
        "analyst_notes_effective": "analyst_notes",
        "ioc_types_effective": "ioc_types",
        "noise_matched_effective": "noise_matched",
        "noise_rules_effective": "noise_rules",
    }
    for column_name in column_names:
        export_name = replacements.get(column_name, column_name)
        if export_name not in header:
            header.append(export_name)
    return header


def _coerce_event_csv_value(value):
    if value is None:
        return ""
    if isinstance(value, (dict, list, tuple)):
        return json.dumps(value, ensure_ascii=False, default=str)
    if isinstance(value, bool):
        return "true" if value else "false"
    return value


def _write_csv_row(writer, output, values):
    output.seek(0)
    output.truncate(0)
    writer.writerow([_coerce_event_csv_value(value) for value in values])
    return output.getvalue()


def _stream_event_export(client, query, params, filename):
    def generate():
        output = io.StringIO()
        writer = csv.writer(output)
        with client.query_rows_stream(query, parameters=params) as rows:
            column_names = rows.source.column_names
            header = _event_export_header(column_names)
            yield _write_csv_row(writer, output, header)
            for row in rows:
                event_data = _event_row_to_export_dict(row, column_names)
                yield _write_csv_row(writer, output, [event_data.get(column_name) for column_name in header])

    return Response(
        stream_with_context(generate()),
        mimetype="text/csv",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


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

        ensure_event_noise_state_tables(client)
        noise_count = count_effective_noise_events(case_id, client=client)

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


@hunting_bp.route("/hunting/mitre/stats/<int:case_id>")
@login_required
def get_mitre_mapping_case_stats(case_id):
    """Get MITRE procedure mapping statistics for a case."""
    try:
        from utils.clickhouse import get_client
        from utils.event_mitre_state import get_mitre_mapping_stats

        case = Case.get_by_id(case_id)
        if not case:
            return jsonify({"success": False, "error": "Case not found"}), 404

        stats = get_mitre_mapping_stats(case_id, client=get_client())
        return jsonify({"success": True, **stats})

    except Exception as e:
        logger.exception("Error getting MITRE mapping stats")
        return jsonify({"success": False, "error": str(e)}), 500


@hunting_bp.route("/hunting/mitre/map/<int:case_id>", methods=["POST"])
@login_required
def start_mitre_mapping(case_id):
    """Start MITRE procedure mapping for a case."""
    try:
        from tasks.mitre_mapper import map_case_mitre_procedures

        if current_user.permission_level == "viewer":
            return _viewer_write_error("Viewers cannot modify hunting state")

        case = Case.get_by_id(case_id)
        if not case:
            return jsonify({"success": False, "error": "Case not found"}), 404

        task = map_case_mitre_procedures.delay(case_id, current_user.username)
        _remember_task_access(task.id, case_id=case.id)

        return jsonify(
            {
                "success": True,
                "task_id": task.id,
                "message": "MITRE procedure mapping started",
            }
        )

    except Exception as e:
        logger.exception("Error starting MITRE mapping")
        return jsonify({"success": False, "error": str(e)}), 500


@hunting_bp.route("/hunting/mitre/status/<task_id>")
@login_required
def get_mitre_mapping_status(task_id):
    """Get status of a MITRE procedure mapping task."""
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
        logger.exception("Error getting MITRE mapping status")
        return jsonify({"success": False, "error": str(e)}), 500


@hunting_bp.route("/hunting/mitre/matches/<int:case_id>")
@login_required
def list_mitre_mapping_matches(case_id):
    """List precomputed MITRE procedure mappings for search/drill-down."""
    try:
        from utils.clickhouse import get_client
        from utils.event_mitre_state import MITRE_MATCH_TABLE, ensure_event_mitre_state_tables

        case = Case.get_by_id(case_id)
        if not case:
            return jsonify({"success": False, "error": "Case not found"}), 404

        attack_id = (request.args.get("attack_id") or "").strip()
        selector_key = (request.args.get("selector_key") or "").strip()
        tactic = (request.args.get("tactic") or "").strip()
        evidence_strength = (request.args.get("evidence_strength") or "").strip()
        min_confidence = max(0, min(100, request.args.get("min_confidence", 0, type=int)))
        page = max(1, request.args.get("page", 1, type=int))
        per_page = max(1, min(500, request.args.get("per_page", request.args.get("limit", 100, type=int), type=int)))
        offset = (page - 1) * per_page
        hide_noise = (request.args.get("hide_noise") or "false").strip().lower() == "true"

        where_parts = [
            "case_id = {case_id:UInt32}",
            "source = 'mitre_procedure_rule'",
            "mapping_confidence >= {min_confidence:UInt8}",
        ]
        params = {
            "case_id": case_id,
            "min_confidence": min_confidence,
            "limit": per_page,
            "offset": offset,
        }
        if attack_id:
            where_parts.append("attack_id = {attack_id:String}")
            params["attack_id"] = attack_id
        if selector_key:
            where_parts.append("selector_key = {selector_key:String}")
            params["selector_key"] = selector_key
        if tactic:
            where_parts.append("positionCaseInsensitive(tactic, {tactic:String}) > 0")
            params["tactic"] = tactic
        if evidence_strength:
            where_parts.append("evidence_strength = {evidence_strength:String}")
            params["evidence_strength"] = evidence_strength
        if hide_noise:
            where_parts.append(
                """
                selector_key NOT IN (
                    SELECT selector_key
                    FROM events
                    WHERE case_id = {case_id:UInt32}
                      AND noise_matched = true
                )
                """
            )

        client = get_client()
        ensure_event_mitre_state_tables(client)
        where_sql = " AND ".join(where_parts)
        total_result = client.query(
            f"""
            SELECT count()
            FROM {MITRE_MATCH_TABLE}
            WHERE {where_sql}
            """,
            parameters=params,
        )
        total = int(total_result.result_rows[0][0]) if total_result.result_rows else 0
        total_pages = (total + per_page - 1) // per_page if total > 0 else 1
        result = client.query(
            f"""
            SELECT
                selector_key,
                artifact_type,
                source_host,
                timestamp,
                attack_id,
                attack_name,
                object_type,
                tactic,
                procedure_name,
                mapping_confidence,
                evidence_strength,
                reason,
                matched_fields_json,
                rule_id
            FROM {MITRE_MATCH_TABLE}
            WHERE {where_sql}
            ORDER BY timestamp DESC
            LIMIT {{limit:UInt32}} OFFSET {{offset:UInt32}}
            """,
            parameters=params,
        )

        matches = []
        for row in result.result_rows:
            matched_fields = {}
            try:
                matched_fields = json.loads(row[12] or "{}")
            except json.JSONDecodeError:
                matched_fields = {}
            matches.append(
                {
                    "selector_key": row[0],
                    "artifact_type": row[1],
                    "source_host": row[2],
                    "timestamp": row[3].isoformat() if hasattr(row[3], "isoformat") else str(row[3]),
                    "attack_id": row[4],
                    "attack_name": row[5],
                    "object_type": row[6],
                    "tactic": row[7],
                    "procedure_name": row[8],
                    "mapping_confidence": row[9],
                    "evidence_strength": row[10],
                    "reason": row[11],
                    "matched_fields": matched_fields,
                    "rule_id": row[13],
                }
            )

        return jsonify(
            {
                "success": True,
                "matches": matches,
                "count": len(matches),
                "total": total,
                "page": page,
                "per_page": per_page,
                "total_pages": total_pages,
                "has_more": page < total_pages,
                "hide_noise": hide_noise,
            }
        )

    except Exception as e:
        logger.exception("Error listing MITRE mapping matches")
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
        from utils.event_mitre_state import ensure_event_mitre_state_tables
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
        ensure_event_analyst_state_table(client)
        ensure_event_noise_state_tables(client)
        ensure_event_ioc_state_tables(client)
        ensure_event_mitre_state_tables(client)
        analyst_projection = build_analyst_projection(alias="e", case_id_filter_sql="{case_id:UInt32}")
        noise_projection = build_noise_projection(alias="e", case_id_filter_sql="{case_id:UInt32}")
        ioc_projection = build_ioc_projection(alias="e", case_id_filter_sql="{case_id:UInt32}")
        params = {"case_id": case.id, "limit": per_page, "offset": offset}

        type_filter = build_hunting_type_filter(artifact_types, params)
        alert_type_filter = _build_hunting_alert_type_filter(
            sigma_filter_param,
            ioc_filter_param,
            analyst_filter_param,
            other_filter_param,
            severity_levels_param,
            analyst_tagged_sql=analyst_projection["tagged_sql"],
            has_ioc_sql=ioc_projection["has_ioc_sql"],
        )

        noise_filter = ""
        if not show_noise:
            noise_filter = f" AND ({noise_projection['matched_sql']} = false)"

        time_filter = build_hunting_time_filter(
            client,
            case.id,
            case_tz,
            time_range,
            time_start,
            time_end,
            params,
        )

        event_columns = f"""
            e.timestamp, e.timestamp_utc, e.selector_key,
            e.artifact_type, e.source_file, e.source_path, e.source_host,
            e.event_id, e.channel, e.provider, e.record_id, e.level,
            e.username, e.domain, e.sid, e.logon_type,
            e.process_name, e.process_path, e.process_id, e.parent_process, e.parent_pid, e.command_line,
            e.target_path, e.file_hash_md5, e.file_hash_sha1, e.file_hash_sha256, e.file_size,
            e.src_ip, e.dst_ip, e.src_port, e.dst_port,
            e.reg_key, e.reg_value, e.reg_data,
            e.rule_title, e.rule_level, e.rule_file, e.mitre_tactics, e.mitre_tags,
            e.mitre_attack_ids, e.mitre_attack_tactics, e.mitre_attack_sources, e.mitre_mapping_max_confidence,
            e.search_blob, e.extra_fields, e.raw_json,
            {ioc_projection["ioc_types_sql"]} AS ioc_types,
            {noise_projection["matched_sql"]} AS noise_matched,
            {analyst_projection["tagged_sql"]} AS analyst_tagged,
            {analyst_projection["tags_sql"]} AS analyst_tags,
            {analyst_projection["notes_sql"]} AS analyst_notes
        """

        search_clause = build_hunting_search_clause(search, params)

        where_clause = (
            f"e.case_id = {{case_id:UInt32}}"
            f"{search_clause}{type_filter}{alert_type_filter}{noise_filter}{time_filter}"
        )
        from_clause = f"""
            FROM events AS e
            {analyst_projection["join_sql"]}
            {noise_projection["join_sql"]}
            {ioc_projection["join_sql"]}
            WHERE {where_clause}
        """
        count_query = f"""
            SELECT count()
            {from_clause}
        """
        data_query = f"""
            SELECT {event_columns}
            {from_clause}
            ORDER BY e.timestamp DESC
            LIMIT {{limit:UInt32}} OFFSET {{offset:UInt32}}
        """

        count_result = client.query(count_query, parameters=params)
        total = count_result.result_rows[0][0] if count_result.result_rows else 0
        total_pages = (total + per_page - 1) // per_page if total > 0 else 1
        data_result = client.query(data_query, parameters=params)
        result_rows = list(data_result.result_rows or [])
        has_more = page < total_pages

        events = []
        for row in result_rows:
            (
                timestamp,
                timestamp_utc,
                selector_key,
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
                mitre_attack_ids,
                mitre_attack_tactics,
                mitre_attack_sources,
                mitre_mapping_max_confidence,
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
                    "selector_key": selector_key or "",
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
                    "mitre_attack_ids": list(mitre_attack_ids) if mitre_attack_ids else [],
                    "mitre_attack_tactics": list(mitre_attack_tactics) if mitre_attack_tactics else [],
                    "mitre_attack_sources": list(mitre_attack_sources) if mitre_attack_sources else [],
                    "mitre_mapping_max_confidence": int(mitre_mapping_max_confidence or 0),
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

        return jsonify(
            {
                "success": True,
                "case_id": case_id,
                "events": events,
                "total": total,
                "page": page,
                "per_page": per_page,
                "total_pages": total_pages,
                "has_more": has_more,
                "page_event_count": len(events),
            }
        )

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@hunting_bp.route("/hunting/event/detail/<int:case_id>")
@login_required
def get_hunting_event_detail(case_id):
    """Get one hunting event by selector key for drill-down modals."""
    try:
        from utils.clickhouse import get_client
        from utils.event_mitre_state import ensure_event_mitre_state_tables
        from utils.timezone import format_for_display

        case = Case.get_by_id(case_id)
        if not case:
            return jsonify({"success": False, "error": "Case not found"}), 404

        selector_key = (request.args.get("selector_key") or "").strip()
        if not selector_key:
            return jsonify({"success": False, "error": "Selector key is required"}), 400

        case_tz = case.timezone or "UTC"
        client = get_client()
        ensure_event_analyst_state_table(client)
        ensure_event_noise_state_tables(client)
        ensure_event_ioc_state_tables(client)
        ensure_event_mitre_state_tables(client)
        analyst_projection = build_analyst_projection(alias="e", case_id_filter_sql="{case_id:UInt32}")
        noise_projection = build_noise_projection(alias="e", case_id_filter_sql="{case_id:UInt32}")
        ioc_projection = build_ioc_projection(alias="e", case_id_filter_sql="{case_id:UInt32}")

        query = f"""
            SELECT
                e.timestamp, e.timestamp_utc, e.selector_key,
                e.artifact_type, e.source_file, e.source_path, e.source_host,
                e.event_id, e.channel, e.provider, e.record_id, e.level,
                e.username, e.domain, e.sid, e.logon_type,
                e.process_name, e.process_path, e.process_id, e.parent_process, e.parent_pid, e.command_line,
                e.target_path, e.file_hash_md5, e.file_hash_sha1, e.file_hash_sha256, e.file_size,
                e.src_ip, e.dst_ip, e.src_port, e.dst_port,
                e.reg_key, e.reg_value, e.reg_data,
                e.rule_title, e.rule_level, e.rule_file, e.mitre_tactics, e.mitre_tags,
                e.mitre_attack_ids, e.mitre_attack_tactics, e.mitre_attack_sources, e.mitre_mapping_max_confidence,
                e.search_blob, e.extra_fields, e.raw_json,
                {ioc_projection["ioc_types_sql"]} AS ioc_types,
                {noise_projection["matched_sql"]} AS noise_matched,
                {analyst_projection["tagged_sql"]} AS analyst_tagged,
                {analyst_projection["tags_sql"]} AS analyst_tags,
                {analyst_projection["notes_sql"]} AS analyst_notes
            FROM events AS e
            {analyst_projection["join_sql"]}
            {noise_projection["join_sql"]}
            {ioc_projection["join_sql"]}
            WHERE e.case_id = {{case_id:UInt32}}
              AND e.selector_key = {{selector_key:String}}
            LIMIT 1
        """
        result = client.query(query, parameters={"case_id": case.id, "selector_key": selector_key})
        if not result.result_rows:
            return jsonify({"success": False, "error": "Event not found"}), 404

        (
            timestamp,
            timestamp_utc,
            selector_key_value,
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
            mitre_attack_ids,
            mitre_attack_tactics,
            mitre_attack_sources,
            mitre_mapping_max_confidence,
            search_blob,
            extra_fields,
            raw_json,
            ioc_types,
            noise_matched,
            analyst_tagged,
            analyst_tags,
            analyst_notes,
        ) = result.result_rows[0]

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
        event = {
            "timestamp": format_for_display(display_ts, case_tz) if display_ts else "-",
            "timestamp_utc_raw": display_ts.strftime("%Y-%m-%d %H:%M:%S") if display_ts else "",
            "selector_key": selector_key_value or "",
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
            "mitre_attack_ids": list(mitre_attack_ids) if mitre_attack_ids else [],
            "mitre_attack_tactics": list(mitre_attack_tactics) if mitre_attack_tactics else [],
            "mitre_attack_sources": list(mitre_attack_sources) if mitre_attack_sources else [],
            "mitre_mapping_max_confidence": int(mitre_mapping_max_confidence or 0),
            "search_blob": search_blob or "",
            "extra_fields": extra_fields or "{}",
            "raw_json": raw_json or "",
            "ioc_types": list(ioc_types) if ioc_types else [],
            "noise_matched": bool(noise_matched) if noise_matched else False,
            "analyst_tagged": bool(analyst_tagged) if analyst_tagged else False,
            "analyst_tags": list(analyst_tags) if analyst_tags else [],
            "analyst_notes": analyst_notes or "",
        }

        return jsonify({"success": True, "event": event})

    except Exception as e:
        logger.exception("Error getting hunting event detail")
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
        ensure_event_analyst_state_table(client)
        ensure_event_noise_state_tables(client)
        ensure_event_ioc_state_tables(client)
        analyst_projection = build_analyst_projection(alias="e", case_id_filter_sql="{case_id:UInt32}")
        noise_projection = build_noise_projection(alias="e", case_id_filter_sql="{case_id:UInt32}")
        ioc_projection = build_ioc_projection(alias="e", case_id_filter_sql="{case_id:UInt32}")
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

        query = f"""
            SELECT e.*,
                   {analyst_projection["tagged_sql"]} AS analyst_tagged_effective,
                   {analyst_projection["tags_sql"]} AS analyst_tags_effective,
                   {analyst_projection["notes_sql"]} AS analyst_notes_effective,
                   {ioc_projection["ioc_types_sql"]} AS ioc_types_effective,
                   {noise_projection["matched_sql"]} AS noise_matched_effective,
                   {noise_projection["rules_sql"]} AS noise_rules_effective
            FROM events AS e
            {analyst_projection["join_sql"]}
            {noise_projection["join_sql"]}
            {ioc_projection["join_sql"]}
            WHERE {' AND '.join(conditions)}
            LIMIT 1
        """
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

        if "analyst_tagged_effective" in raw_data:
            raw_data["analyst_tagged"] = bool(raw_data.pop("analyst_tagged_effective"))
        if "analyst_tags_effective" in raw_data:
            raw_data["analyst_tags"] = list(raw_data.pop("analyst_tags_effective") or [])
        if "analyst_notes_effective" in raw_data:
            raw_data["analyst_notes"] = raw_data.pop("analyst_notes_effective") or ""
        if "ioc_types_effective" in raw_data:
            raw_data["ioc_types"] = list(raw_data.pop("ioc_types_effective") or [])
        if "noise_matched_effective" in raw_data:
            raw_data["noise_matched"] = bool(raw_data.pop("noise_matched_effective"))
        if "noise_rules_effective" in raw_data:
            raw_data["noise_rules"] = list(raw_data.pop("noise_rules_effective") or [])

        return jsonify({"success": True, "raw_data": raw_data})

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@hunting_bp.route("/hunting/event/tag/<int:case_id>", methods=["POST"])
@login_required
def update_analyst_tag(case_id):
    """Update analyst tagging for a specific event in ClickHouse."""
    try:
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

        client = get_client()
        ensure_event_analyst_state_table(client)

        try:
            selector_key = build_event_selector_key(
                event_id=event_id,
                record_id=record_id,
                source_file=source_file,
                source_host=source_host,
                timestamp=timestamp,
                artifact_type=artifact_type,
            )
        except ValueError as exc:
            return jsonify({"success": False, "error": str(exc)}), 400

        tags_array = normalize_analyst_tags(analyst_tags)
        notes_value = str(analyst_notes).strip() if analyst_notes else None
        updated = upsert_event_analyst_state_rows(
            case_id,
            [
                {
                    "selector_key": selector_key,
                    "artifact_type": artifact_type,
                    "analyst_tagged": analyst_tagged,
                    "analyst_tags": tags_array,
                    "analyst_notes": notes_value,
                }
            ],
            updated_by=current_user.username,
            client=client,
        )
        if updated != 1:
            return jsonify({"success": False, "error": "No valid event identifier provided"}), 400

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
        ensure_event_analyst_state_table(client)
        updated_count = 0
        tags_array = normalize_analyst_tags(analyst_tags)
        notes_value = str(analyst_notes).strip() if analyst_notes else None
        updates = []

        for event in events:
            event_id = event.get("event_id", "").strip() if event.get("event_id") else ""
            record_id = event.get("record_id", "")
            source_file = event.get("source_file", "").strip() if event.get("source_file") else ""
            source_host = event.get("source_host", "").strip() if event.get("source_host") else ""
            timestamp = event.get("timestamp", "").strip() if event.get("timestamp") else ""
            artifact_type = event.get("artifact_type", "").strip() if event.get("artifact_type") else ""
            try:
                selector_key = build_event_selector_key(
                    event_id=event_id,
                    record_id=record_id,
                    source_file=source_file,
                    source_host=source_host,
                    timestamp=timestamp,
                    artifact_type=artifact_type,
                )
            except ValueError:
                continue
            updates.append(
                {
                    "selector_key": selector_key,
                    "artifact_type": artifact_type,
                    "analyst_tagged": analyst_tagged,
                    "analyst_tags": tags_array,
                    "analyst_notes": notes_value,
                }
            )

        try:
            updated_count = upsert_event_analyst_state_rows(
                case_id,
                updates,
                updated_by=current_user.username,
                client=client,
            )
        except Exception as e:
            logger.warning("Failed to update analyst state rows: %s", e)

        return jsonify(
            {
                "success": True,
                "updated": updated_count,
                "total": len(events),
                "message": f"Successfully {'tagged' if analyst_tagged else 'untagged'} {updated_count} event(s)",
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
        ensure_event_noise_state_tables(client)
        ensure_noise_overlay_case(case_id, updated_by=current_user.username, client=client)
        updates = []
        for event in events:
            try:
                selector_key = build_event_selector_key(
                    event_id=event.get("event_id", "").strip() if event.get("event_id") else "",
                    record_id=event.get("record_id", ""),
                    source_file=event.get("source_file", "").strip() if event.get("source_file") else "",
                    source_host=event.get("source_host", "").strip() if event.get("source_host") else "",
                    timestamp=event.get("timestamp", "").strip() if event.get("timestamp") else "",
                    artifact_type=event.get("artifact_type", "").strip() if event.get("artifact_type") else "",
                )
            except ValueError:
                continue
            artifact_type = event.get("artifact_type", "").strip() if event.get("artifact_type") else ""
            updates.append(
                {
                    "selector_key": selector_key,
                    "artifact_type": artifact_type,
                    "noise_matched": True,
                    "noise_rules": [],
                }
            )

        updated_count = upsert_manual_noise_state_rows(
            case_id,
            updates,
            updated_by=current_user.username,
            client=client,
        )

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
        from utils.clickhouse import get_client

        case = Case.get_by_id(case_id)
        if not case:
            return jsonify({"success": False, "error": "Case not found"}), 404

        client = get_client()
        ensure_event_analyst_state_table(client)
        ensure_event_noise_state_tables(client)
        ensure_event_ioc_state_tables(client)
        analyst_projection = build_analyst_projection(alias="e", case_id_filter_sql="{case_id:UInt32}")
        noise_projection = build_noise_projection(alias="e", case_id_filter_sql="{case_id:UInt32}")
        ioc_projection = build_ioc_projection(alias="e", case_id_filter_sql="{case_id:UInt32}")
        query = """
            SELECT e.*,
                   {analyst_tagged} AS analyst_tagged_effective,
                   {analyst_tags} AS analyst_tags_effective,
                   {analyst_notes} AS analyst_notes_effective,
                   {ioc_types} AS ioc_types_effective,
                   {noise_matched} AS noise_matched_effective,
                   {noise_rules} AS noise_rules_effective
            FROM events AS e
            {analyst_join}
            {noise_join}
            {ioc_join}
            WHERE e.case_id = {{case_id:UInt32}}
              AND {analyst_tagged} = true
        """.format(
            analyst_join=analyst_projection["join_sql"],
            analyst_tagged=analyst_projection["tagged_sql"],
            analyst_tags=analyst_projection["tags_sql"],
            analyst_notes=analyst_projection["notes_sql"],
            noise_join=noise_projection["join_sql"],
            noise_matched=noise_projection["matched_sql"],
            noise_rules=noise_projection["rules_sql"],
            ioc_join=ioc_projection["join_sql"],
            ioc_types=ioc_projection["ioc_types_sql"],
        )
        return _stream_event_export(
            client,
            query,
            {"case_id": case_id},
            _event_export_filename("tagged_events", case_id),
        )

    except Exception as e:
        logger.error("Error exporting tagged events: %s", e)
        return jsonify({"success": False, "error": str(e)}), 500


@hunting_bp.route("/hunting/events/export-view/<int:case_id>")
@login_required
def export_view_events(case_id):
    """Export all events matching current view filters with full data."""
    try:
        from utils.clickhouse import get_client

        case = Case.get_by_id(case_id)
        if not case:
            return jsonify({"success": False, "error": "Case not found"}), 404

        case_tz = case.timezone or "UTC"
        client = get_client()
        ensure_event_analyst_state_table(client)
        ensure_event_noise_state_tables(client)
        ensure_event_ioc_state_tables(client)
        analyst_projection = build_analyst_projection(alias="e", case_id_filter_sql="{case_id:UInt32}")
        noise_projection = build_noise_projection(alias="e", case_id_filter_sql="{case_id:UInt32}")
        ioc_projection = build_ioc_projection(alias="e", case_id_filter_sql="{case_id:UInt32}")
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
            analyst_tagged_sql=analyst_projection["tagged_sql"],
            has_ioc_sql=ioc_projection["has_ioc_sql"],
        )

        noise_filter = ""
        if not show_noise:
            noise_filter = f" AND ({noise_projection['matched_sql']} = false)"

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
            SELECT e.*,
                   {analyst_projection["tagged_sql"]} AS analyst_tagged_effective,
                   {analyst_projection["tags_sql"]} AS analyst_tags_effective,
                   {analyst_projection["notes_sql"]} AS analyst_notes_effective,
                   {ioc_projection["ioc_types_sql"]} AS ioc_types_effective,
                   {noise_projection["matched_sql"]} AS noise_matched_effective,
                   {noise_projection["rules_sql"]} AS noise_rules_effective
            FROM events AS e
            {analyst_projection["join_sql"]}
            {noise_projection["join_sql"]}
            {ioc_projection["join_sql"]}
            WHERE e.case_id = {{case_id:UInt32}}{search_clause}{type_filter}{alert_type_filter}{noise_filter}{time_filter}
        """
        return _stream_event_export(
            client,
            query,
            params,
            _event_export_filename("view_events", case_id),
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
