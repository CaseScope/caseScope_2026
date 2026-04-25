"""IOC management API routes."""

import json
import logging
from datetime import datetime

from flask import Blueprint, jsonify, request
from flask_login import current_user, login_required
from sqlalchemy import or_

from models.case import Case
from models.database import db
from routes.route_helpers import _remember_task_access, _require_case_write_access, _task_access_allowed
from utils.async_status import build_async_status_response

logger = logging.getLogger(__name__)

iocs_bp = Blueprint("iocs", __name__, url_prefix="/api")
IOC_TASK_QUEUE = "ioc"


def _queued_ioc_task_payload(task_id: str, message: str):
    return {
        "task_id": task_id,
        "status": "queued",
        "queue": IOC_TASK_QUEUE,
        "message": message,
    }


@iocs_bp.route("/iocs/types")
@login_required
def get_ioc_types():
    """Get all IOC types organized by category."""
    try:
        from models.ioc import IOCCategory, get_ioc_types_by_category

        types_by_category = get_ioc_types_by_category()
        icons = IOCCategory.icons()

        return jsonify(
            {
                "success": True,
                "types_by_category": types_by_category,
                "category_icons": icons,
                "categories": IOCCategory.all(),
            }
        )

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@iocs_bp.route("/iocs/values/<int:case_id>")
@login_required
def get_ioc_values_for_case(case_id):
    """Get just IOC values for a case."""
    try:
        from models.ioc import IOC
        from utils.ioc_artifact_tagger import extract_searchable_terms

        case = Case.get_by_id(case_id)
        if not case:
            return jsonify({"success": False, "error": "Case not found"}), 404

        iocs = IOC.query.filter(
            IOC.case_id == case_id,
            IOC.false_positive == False,
            IOC.active == True,
        ).all()

        values = set()
        for ioc in iocs:
            terms = extract_searchable_terms(ioc.value, ioc.ioc_type)
            for term, _ in terms:
                if term:
                    values.add(term)

        return jsonify({"success": True, "values": list(values)})

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@iocs_bp.route("/iocs/list/<case_uuid>")
@login_required
def get_iocs_for_case(case_uuid):
    """Get IOCs for a case with pagination and filtering."""
    try:
        from models.ioc import IOC, IOCCase, IOCCategory

        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({"success": False, "error": "Case not found"}), 404

        page = request.args.get("page", 1, type=int)
        per_page = request.args.get("per_page", 50, type=int)
        search = request.args.get("search", "", type=str).strip()
        category = request.args.get("category", "", type=str).strip()
        ioc_type = request.args.get("type", "", type=str).strip()
        malicious_only = request.args.get("malicious", "false", type=str).lower() == "true"

        per_page = min(max(per_page, 10), 200)

        query = IOC.query.filter(IOC.case_id == case.id)

        if search:
            search_filter = f"%{search}%"
            query = query.filter(
                or_(
                    IOC.value.ilike(search_filter),
                    db.cast(IOC.aliases, db.Text).ilike(search_filter),
                    IOC.notes.ilike(search_filter),
                )
            )

        if category:
            query = query.filter(IOC.category == category)

        if ioc_type:
            query = query.filter(IOC.ioc_type == ioc_type)

        if malicious_only:
            query = query.filter(IOC.malicious == True)

        query = query.filter(IOC.false_positive == False)
        query = query.order_by(IOC.last_seen_in_artifacts.desc().nullslast(), IOC.created_at.desc())

        total = query.count()
        iocs = query.offset((page - 1) * per_page).limit(per_page).all()

        stats = {"total": total, "by_category": {}}
        for cat in IOCCategory.all():
            cat_count = IOC.query.filter(
                IOC.case_id == case.id,
                IOC.category == cat,
                IOC.false_positive == False,
            ).count()
            stats["by_category"][cat] = cat_count

        return jsonify(
            {
                "success": True,
                "case_uuid": case_uuid,
                "iocs": [ioc.to_dict() for ioc in iocs],
                "total": total,
                "page": page,
                "per_page": per_page,
                "total_pages": (total + per_page - 1) // per_page if total > 0 else 1,
                "stats": stats,
            }
        )

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@iocs_bp.route("/iocs/analyze-match-type", methods=["POST"])
@login_required
def analyze_ioc_match_type():
    """Analyze an IOC value and recommend a match type."""
    try:
        from models.ioc import IOCMatchType, get_match_type_recommendation

        data = request.get_json()
        value = data.get("value", "").strip()
        ioc_type = data.get("ioc_type", "").strip()

        if not value:
            return jsonify({"success": False, "error": "Value required"}), 400

        if not ioc_type:
            return jsonify({"success": False, "error": "IOC type required"}), 400

        recommendation = get_match_type_recommendation(value, ioc_type)

        return jsonify(
            {
                "success": True,
                "recommendation": recommendation,
                "match_types": [
                    {
                        "value": IOCMatchType.TOKEN,
                        "label": "Token (Whole Word)",
                        "description": "Best for hashes, IPs, unique identifiers - avoids partial matches",
                    },
                    {
                        "value": IOCMatchType.SUBSTRING,
                        "label": "Substring (Contains)",
                        "description": "Best for paths, registry, URLs - matches anywhere in event",
                    },
                    {
                        "value": IOCMatchType.REGEX,
                        "label": "Regex (Pattern)",
                        "description": "For complex patterns with wildcards",
                    },
                ],
            }
        )

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@iocs_bp.route("/iocs/create/<case_uuid>", methods=["POST"])
@login_required
def create_ioc(case_uuid):
    """Create a new IOC and link to case."""
    try:
        from models.ioc import IOC, IOCAudit, IOCMatchType, get_category_for_type, get_match_type_recommendation
        from utils.opencti import maybe_auto_enrich_ioc

        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({"success": False, "error": "Case not found"}), 404

        write_error = _require_case_write_access(current_user)
        if write_error:
            return write_error

        data = request.get_json()
        ioc_type = (data.get("ioc_type") or "").strip()
        value = (data.get("value") or "").strip()
        notes = (data.get("notes") or "").strip()
        malicious = data.get("malicious", False)
        match_type = (data.get("match_type") or "").strip() or None

        if not value:
            return jsonify({"success": False, "error": "IOC value required"}), 400

        if not ioc_type:
            from models.ioc import detect_ioc_type_from_value

            suggested_type = detect_ioc_type_from_value(value)
            return jsonify(
                {
                    "success": False,
                    "needs_type": True,
                    "error": "Please select an IOC type",
                    "suggestion": suggested_type,
                    "message": f'Based on the value, this looks like a "{suggested_type}". Please confirm or select the correct type.',
                }
            ), 400

        category = get_category_for_type(ioc_type)
        if not category:
            return jsonify({"success": False, "error": f"Unknown IOC type: {ioc_type}"}), 400

        is_valid, error = IOC.validate_value(value, ioc_type)
        if not is_valid:
            return jsonify({"success": False, "error": error}), 400

        if match_type and match_type not in IOCMatchType.all():
            return jsonify({"success": False, "error": f"Invalid match type: {match_type}"}), 400

        ioc, created = IOC.get_or_create(
            value=value,
            ioc_type=ioc_type,
            category=category,
            created_by=current_user.username,
            case_id=case.id,
            match_type=match_type,
            source="manual",
        )

        if notes:
            ioc.notes = notes
        if malicious:
            ioc.malicious = malicious

        if created:
            IOCAudit.log_change(
                ioc_id=ioc.id,
                changed_by=current_user.username,
                field_name="ioc",
                action="create",
                new_value=f"{ioc_type}: {value} (match: {ioc.get_effective_match_type()})",
            )

        db.session.commit()
        auto_enrichment = None
        if created:
            auto_enrichment = maybe_auto_enrich_ioc(ioc)

        recommendation = get_match_type_recommendation(value, ioc_type)

        return jsonify(
            {
                "success": True,
                "created": created,
                "ioc": ioc.to_dict(),
                "match_type_info": recommendation,
                "auto_enrichment": auto_enrichment,
            }
        )

    except ValueError as e:
        return jsonify({"success": False, "error": str(e)}), 400
    except Exception as e:
        db.session.rollback()
        return jsonify({"success": False, "error": str(e)}), 500


@iocs_bp.route("/iocs/<int:ioc_id>")
@login_required
def get_ioc(ioc_id):
    """Get details for a specific IOC."""
    try:
        from models.ioc import IOC

        ioc = IOC.query.get(ioc_id)
        if not ioc:
            return jsonify({"success": False, "error": "IOC not found"}), 404

        return jsonify({"success": True, "ioc": ioc.to_dict()})

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@iocs_bp.route("/iocs/<int:ioc_id>/update", methods=["POST"])
@login_required
def update_ioc(ioc_id):
    """Update an IOC field."""
    try:
        from models.ioc import IOC, IOCAudit

        write_error = _require_case_write_access(current_user)
        if write_error:
            return write_error

        ioc = IOC.query.get(ioc_id)
        if not ioc:
            return jsonify({"success": False, "error": "IOC not found"}), 404

        data = request.get_json()
        field_name = data.get("field")
        new_value = data.get("value")

        if not field_name:
            return jsonify({"success": False, "error": "Field name required"}), 400

        allowed_fields = ["notes", "malicious", "false_positive", "active", "hidden", "aliases", "match_type"]
        if field_name not in allowed_fields:
            return jsonify({"success": False, "error": f"Cannot update field: {field_name}"}), 400

        old_value = getattr(ioc, field_name)

        if field_name in ["malicious", "false_positive", "active"]:
            new_value = bool(new_value)

        if field_name == "aliases":
            if not isinstance(new_value, list):
                return jsonify({"success": False, "error": "Aliases must be a list"}), 400
            new_value = list(set([str(a).lower().strip() for a in new_value if a]))

        if field_name == "match_type":
            from models.ioc import IOCMatchType

            if new_value and new_value not in IOCMatchType.all():
                return jsonify({"success": False, "error": f"Invalid match type: {new_value}"}), 400
            if new_value == "":
                new_value = None

        setattr(ioc, field_name, new_value)

        IOCAudit.log_change(
            ioc_id=ioc.id,
            changed_by=current_user.username,
            field_name=field_name,
            action="update",
            old_value=old_value,
            new_value=new_value,
        )

        db.session.commit()

        return jsonify({"success": True, "ioc": ioc.to_dict()})

    except Exception as e:
        db.session.rollback()
        return jsonify({"success": False, "error": str(e)}), 500


@iocs_bp.route("/iocs/<int:ioc_id>/systems")
@login_required
def get_ioc_systems(ioc_id):
    """Get all systems where this IOC was found."""
    try:
        from models.ioc import IOC, IOCSystemSighting

        ioc = IOC.query.get(ioc_id)
        if not ioc:
            return jsonify({"success": False, "error": "IOC not found"}), 404

        sightings = ioc.system_sightings.all()

        return jsonify({"success": True, "ioc_id": ioc_id, "systems": [s.to_dict() for s in sightings]})

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@iocs_bp.route("/iocs/<int:ioc_id>/audit")
@login_required
def get_ioc_audit(ioc_id):
    """Get audit history for an IOC."""
    try:
        from models.ioc import IOC, IOCAudit

        ioc = IOC.query.get(ioc_id)
        if not ioc:
            return jsonify({"success": False, "error": "IOC not found"}), 404

        audits = IOCAudit.query.filter_by(ioc_id=ioc_id).order_by(IOCAudit.changed_on.desc()).all()

        return jsonify(
            {
                "success": True,
                "ioc_id": ioc_id,
                "ioc_value": ioc.value,
                "audit_history": [a.to_dict() for a in audits],
            }
        )

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@iocs_bp.route("/iocs/<int:ioc_id>/delete", methods=["POST"])
@login_required
def delete_ioc_from_case(ioc_id):
    """Delete a case-owned IOC or remove a legacy IOC-case link."""
    try:
        from models.ioc import IOC, IOCAudit, IOCCase, IOCSystemSighting

        write_error = _require_case_write_access(current_user)
        if write_error:
            return write_error

        data = request.get_json()
        case_uuid = data.get("case_uuid")

        if not case_uuid:
            return jsonify({"success": False, "error": "Case UUID required"}), 400

        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({"success": False, "error": "Case not found"}), 404

        ioc = IOC.query.get(ioc_id)
        if not ioc:
            return jsonify({"success": False, "error": "IOC not found"}), 404

        if ioc.case_id == case.id:
            IOCAudit.query.filter_by(ioc_id=ioc.id).delete()
            IOCSystemSighting.query.filter_by(ioc_id=ioc.id).delete()
            IOCCase.query.filter_by(ioc_id=ioc.id).delete()
            db.session.delete(ioc)
            db.session.commit()

            return jsonify({"success": True, "deleted": True})

        link = IOCCase.query.filter_by(ioc_id=ioc_id, case_id=case.id).first()
        if link:
            IOCAudit.log_change(
                ioc_id=ioc_id,
                changed_by=current_user.username,
                field_name="case",
                action="delete",
                old_value=case.name,
            )
            db.session.delete(link)
            db.session.commit()
            return jsonify({"success": True, "deleted": False, "removed_legacy_link": True})

        return jsonify({"success": False, "error": "IOC not associated with this case"}), 404

    except Exception as e:
        db.session.rollback()
        return jsonify({"success": False, "error": str(e)}), 500


@iocs_bp.route("/iocs/bulk-create/<case_uuid>", methods=["POST"])
@login_required
def bulk_create_iocs(case_uuid):
    """Bulk create IOCs from a list."""
    try:
        from models.ioc import IOC, IOCAudit, IOCMatchType, get_category_for_type
        from utils.opencti import maybe_auto_enrich_iocs

        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({"success": False, "error": "Case not found"}), 404

        write_error = _require_case_write_access(current_user)
        if write_error:
            return write_error

        data = request.get_json()
        iocs_data = data.get("iocs", [])

        if not iocs_data:
            return jsonify({"success": False, "error": "No IOCs provided"}), 400

        created_count = 0
        existing_count = 0
        errors = []
        created_iocs = []

        for item in iocs_data:
            ioc_type = item.get("ioc_type", "").strip()
            value = item.get("value", "").strip()
            match_type = item.get("match_type", "").strip() or None

            if not ioc_type or not value:
                errors.append(f"Missing type or value: {item}")
                continue

            category = get_category_for_type(ioc_type)
            if not category:
                errors.append(f"Unknown type: {ioc_type}")
                continue

            if match_type and match_type not in IOCMatchType.all():
                errors.append(f"Invalid match type for {value}: {match_type}")
                continue

            try:
                ioc, created = IOC.get_or_create(
                    value=value,
                    ioc_type=ioc_type,
                    category=category,
                    created_by=current_user.username,
                    case_id=case.id,
                    match_type=match_type,
                    source="bulk_import",
                )

                if created:
                    created_count += 1
                    created_iocs.append(ioc)
                    IOCAudit.log_change(
                        ioc_id=ioc.id,
                        changed_by=current_user.username,
                        field_name="ioc",
                        action="create",
                        new_value=f"{ioc_type}: {value} (match: {ioc.get_effective_match_type()})",
                    )
                else:
                    existing_count += 1

            except ValueError as e:
                errors.append(f"{ioc_type}: {value} - {str(e)}")

        db.session.commit()
        auto_enrichment = maybe_auto_enrich_iocs(created_iocs)

        return jsonify(
            {
                "success": True,
                "created": created_count,
                "existing": existing_count,
                "linked": 0,
                "errors": errors,
                "auto_enrichment": auto_enrichment,
            }
        )

    except Exception as e:
        db.session.rollback()
        return jsonify({"success": False, "error": str(e)}), 500


@iocs_bp.route("/iocs/extraction/check/<case_uuid>")
@login_required
def check_edr_reports(case_uuid):
    """Check if case has EDR reports available for extraction."""
    try:
        from utils.feature_availability import FeatureAvailability
        from utils.ioc_extractor import get_report_preview, split_edr_reports

        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({"success": False, "error": "Case not found"}), 404

        has_reports = bool(case.edr_report and case.edr_report.strip())
        report_count = 0
        report_previews = []

        if has_reports:
            reports = split_edr_reports(case.edr_report)
            report_count = len(reports)
            report_previews = [
                {"index": i, "preview": get_report_preview(r, 150), "length": len(r)}
                for i, r in enumerate(reports)
            ]

        return jsonify(
            {
                "success": True,
                "has_reports": has_reports,
                "report_count": report_count,
                "report_previews": report_previews,
                "ai_enabled": FeatureAvailability.is_ai_enabled(),
            }
        )

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@iocs_bp.route("/iocs/extraction/extract/<case_uuid>", methods=["POST"])
@login_required
def extract_iocs_from_report(case_uuid):
    """Start async IOC extraction for a specific EDR report."""
    try:
        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({"success": False, "error": "Case not found"}), 404

        write_error = _require_case_write_access(current_user)
        if write_error:
            return write_error

        from models.ioc_enhancement import CaseIOCEnhancementRun, IOCEnhancementStatus
        from tasks.celery_tasks import extract_iocs_from_report_task
        from utils.feature_availability import FeatureAvailability
        from utils.ioc_extractor import split_edr_reports

        if not case.edr_report or not case.edr_report.strip():
            return jsonify({"success": False, "error": "No EDR reports available"}), 400

        data = request.get_json() or {}
        report_index = data.get("report_index", 0)
        enhance_with_ai = bool(data.get("enhance_with_ai"))
        ai_enabled = FeatureAvailability.is_ai_enabled()
        if enhance_with_ai and not ai_enabled:
            return jsonify({"success": False, "error": "AI enhancement is not available"}), 400

        reports = split_edr_reports(case.edr_report)

        if report_index < 0 or report_index >= len(reports):
            return jsonify({"success": False, "error": "Invalid report index"}), 400

        enhancement_run = None
        if enhance_with_ai:
            enhancement_run = CaseIOCEnhancementRun(
                case_id=case.id,
                report_index=report_index,
                status=IOCEnhancementStatus.PENDING,
                progress_percent=0,
                current_phase="Waiting for deterministic extraction",
                requested_by=current_user.username,
            )
            db.session.add(enhancement_run)
            db.session.commit()

        task = extract_iocs_from_report_task.apply_async(
            args=(
                case.id,
                case.uuid,
                report_index,
                current_user.username,
                enhance_with_ai,
                enhancement_run.id if enhancement_run else None,
            ),
            queue=IOC_TASK_QUEUE,
        )
        _remember_task_access(task.id, case_id=case.id)
        return jsonify(
            {
                "success": True,
                "report_index": report_index,
                "total_reports": len(reports),
                "ai_enhancement_requested": enhance_with_ai,
                "ai_enhancement_run_id": enhancement_run.id if enhancement_run else None,
                **_queued_ioc_task_payload(
                    task.id,
                    "Queued on the IOC worker and waiting to start extraction...",
                ),
            }
        )

    except Exception as e:
        import traceback

        traceback.print_exc()
        return jsonify({"success": False, "error": str(e)}), 500


@iocs_bp.route("/iocs/extraction/progress/<case_uuid>/<task_id>")
@login_required
def get_extract_iocs_progress(case_uuid, task_id):
    """Get progress of an async IOC extraction task."""
    try:
        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({"success": False, "error": "Case not found"}), 404
        if not _task_access_allowed(task_id, case_id=case.id):
            return jsonify({"success": False, "error": "Task not accessible"}), 403

        import redis
        from celery.result import AsyncResult
        from config import Config
        from tasks.celery_tasks import celery_app

        r = redis.Redis(
            host=Config.REDIS_HOST,
            port=Config.REDIS_PORT,
            db=Config.REDIS_DB,
            decode_responses=True,
        )
        key = f"ioc_extract_progress:{case.id}:{task_id}"
        data = r.get(key)
        if data:
            progress = json.loads(data)
            return jsonify({"success": True, **progress})

        result = AsyncResult(task_id, app=celery_app)
        payload, status_code = build_async_status_response(
            result,
            task_id=task_id,
            pending_builder=lambda _task: {
                "status": "queued",
                "progress": 0,
                "queue": IOC_TASK_QUEUE,
                "message": "Queued on the IOC worker and waiting to start extraction...",
            },
            progress_builder=lambda _task: {
                "status": "processing",
                "progress": 0,
                "queue": IOC_TASK_QUEUE,
                "message": "Waiting for the first extraction progress update...",
            },
            success_builder=lambda _task: {"status": "complete", "progress": 100},
            failure_builder=lambda task: {
                "status": "failed",
                "progress": 100,
                "message": str(task.result),
            },
        )
        return jsonify(payload), status_code

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@iocs_bp.route("/iocs/extraction/results/<case_uuid>/<task_id>")
@login_required
def get_extract_iocs_results(case_uuid, task_id):
    """Get results of a completed async IOC extraction task."""
    try:
        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({"success": False, "error": "Case not found"}), 404
        if not _task_access_allowed(task_id, case_id=case.id):
            return jsonify({"success": False, "error": "Task not accessible"}), 403

        import redis
        from config import Config

        r = redis.Redis(
            host=Config.REDIS_HOST,
            port=Config.REDIS_PORT,
            db=Config.REDIS_DB,
            decode_responses=True,
        )
        key = f"ioc_extract_results:{case.id}:{task_id}"
        data = r.get(key)
        if not data:
            return jsonify({"success": False, "error": "Results not found or expired"}), 404

        return jsonify(json.loads(data))

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@iocs_bp.route("/iocs/extraction/save/<case_uuid>", methods=["POST"])
@login_required
def save_extracted_iocs_api(case_uuid):
    """Save selected extracted IOCs to the database."""
    try:
        from utils.ioc_extractor import save_extracted_iocs

        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({"success": False, "error": "Case not found"}), 404

        write_error = _require_case_write_access(current_user)
        if write_error:
            return write_error

        data = request.get_json()
        iocs_data = data.get("iocs", [])
        known_systems = data.get("known_systems", [])
        known_users = data.get("known_users", [])

        results = save_extracted_iocs(
            iocs_data=iocs_data,
            case_id=case.id,
            username=current_user.username,
            known_systems=known_systems,
            known_users=known_users,
        )

        return jsonify({"success": True, "results": results})

    except Exception as e:
        import traceback

        traceback.print_exc()
        return jsonify({"success": False, "error": str(e)}), 500


@iocs_bp.route("/iocs/ai-enhancement/status/<case_uuid>")
@login_required
def get_ioc_ai_enhancement_status(case_uuid):
    """Return the latest durable IOC AI enhancement status for a case."""
    try:
        from models.ioc_enhancement import CaseIOCEnhancementRun

        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({"success": False, "error": "Case not found"}), 404

        run = (
            CaseIOCEnhancementRun.query.filter_by(case_id=case.id)
            .order_by(CaseIOCEnhancementRun.created_at.desc())
            .first()
        )
        if not run:
            return jsonify({"success": True, "status": "idle", "run": None})

        return jsonify({"success": True, "status": run.status, "run": run.to_dict()})

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@iocs_bp.route("/iocs/ai-enhancement/review/<case_uuid>/<int:run_id>", methods=["POST"])
@login_required
def review_ioc_ai_enhancement_candidates(case_uuid, run_id):
    """Accept or reject staged IOC candidates from a completed AI enhancement run."""
    try:
        from models.ioc_enhancement import CaseIOCEnhancementRun
        from utils.ioc_extractor import save_extracted_iocs

        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({"success": False, "error": "Case not found"}), 404

        write_error = _require_case_write_access(current_user)
        if write_error:
            return write_error

        run = CaseIOCEnhancementRun.query.filter_by(id=run_id, case_id=case.id).first()
        if not run:
            return jsonify({"success": False, "error": "AI enhancement run not found"}), 404

        data = request.get_json() or {}
        action = str(data.get("action") or "").strip().lower()
        candidate_ids = {
            str(candidate_id)
            for candidate_id in data.get("candidate_ids", [])
            if str(candidate_id).strip()
        }
        if action not in {"accept", "reject"}:
            return jsonify({"success": False, "error": "Invalid review action"}), 400
        if not candidate_ids:
            return jsonify({"success": False, "error": "No candidates selected"}), 400

        candidates = []
        selected = []
        for candidate in run.staged_candidates or []:
            if not isinstance(candidate, dict):
                continue
            updated = dict(candidate)
            if (
                str(updated.get("candidate_id")) in candidate_ids
                and str(updated.get("review_status") or "pending") == "pending"
            ):
                selected.append(updated)
                updated["review_status"] = "accepted" if action == "accept" else "rejected"
                updated["reviewed_by"] = current_user.username
                updated["reviewed_at"] = datetime.utcnow().isoformat()
            candidates.append(updated)

        if not selected:
            return jsonify({"success": False, "error": "No pending candidates matched the request"}), 400

        save_results = None
        if action == "accept":
            save_results = save_extracted_iocs(
                iocs_data=selected,
                case_id=case.id,
                username=current_user.username,
                known_systems=[],
                known_users=[],
            )

        run.staged_candidates = candidates
        db.session.commit()
        return jsonify({"success": True, "run": run.to_dict(), "results": save_results})

    except Exception as e:
        db.session.rollback()
        return jsonify({"success": False, "error": str(e)}), 500


@iocs_bp.route("/iocs/find-in-events/stats/<case_uuid>")
@login_required
def get_find_iocs_stats(case_uuid):
    """Get stats for Find IOCs feature."""
    try:
        from models.ioc import IOC
        from utils.clickhouse import get_fresh_client
        from utils.event_ioc_state import build_ioc_projection, ensure_event_ioc_state_tables

        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({"success": False, "error": "Case not found"}), 404

        client = get_fresh_client()
        ensure_event_ioc_state_tables(client)
        ioc_projection = build_ioc_projection(alias="e")
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
        tagged_count = result.result_rows[0][0] if result.result_rows else 0

        ioc_count = IOC.query.filter(
            IOC.case_id == case.id,
            IOC.active == True,
            IOC.false_positive == False,
        ).count()

        return jsonify(
            {
                "success": True,
                "tagged_event_count": tagged_count,
                "ioc_count": ioc_count,
            }
        )

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@iocs_bp.route("/iocs/find-in-events/start/<case_uuid>", methods=["POST"])
@login_required
def start_find_iocs_in_events(case_uuid):
    """Start async task to find IOCs in tagged events."""
    try:
        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({"success": False, "error": "Case not found"}), 404

        write_error = _require_case_write_access(current_user)
        if write_error:
            return write_error

        from tasks.celery_tasks import find_iocs_in_events_task

        task = find_iocs_in_events_task.apply_async(
            args=(case.id, current_user.username),
            queue=IOC_TASK_QUEUE,
        )
        _remember_task_access(task.id, case_id=case.id)

        return jsonify(
            {
                "success": True,
                **_queued_ioc_task_payload(
                    task.id,
                    "Queued on the IOC worker and waiting to start event scanning...",
                ),
            }
        )

    except Exception as e:
        import traceback

        traceback.print_exc()
        return jsonify({"success": False, "error": str(e)}), 500


@iocs_bp.route("/iocs/find-in-events/progress/<case_uuid>/<task_id>")
@login_required
def get_find_iocs_progress(case_uuid, task_id):
    """Get progress of find IOCs task."""
    try:
        import redis
        from config import Config

        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({"success": False, "error": "Case not found"}), 404
        if not _task_access_allowed(task_id, case_id=case.id):
            return jsonify({"success": False, "error": "Task not accessible"}), 403

        r = redis.Redis(
            host=Config.REDIS_HOST,
            port=Config.REDIS_PORT,
            db=Config.REDIS_DB,
            decode_responses=True,
        )

        key = f"find_iocs_progress:{case.id}:{task_id}"
        data = r.get(key)

        if data:
            progress = json.loads(data)
            return jsonify(
                {
                    "success": True,
                    "status": progress.get("status", "processing"),
                    "current": progress.get("current", 0),
                    "total": progress.get("total", 0),
                    "found_count": progress.get("found_count", 0),
                    "current_value": progress.get("current_value", ""),
                    "message": progress.get("message") or progress.get("current_value", ""),
                    "error": progress.get("error"),
                }
            )

        from celery.result import AsyncResult
        from tasks.celery_tasks import celery_app

        result = AsyncResult(task_id, app=celery_app)
        payload, status_code = build_async_status_response(
            result,
            task_id=task_id,
            pending_builder=lambda _task: {
                "status": "queued",
                "current": 0,
                "total": 0,
                "found_count": 0,
                "queue": IOC_TASK_QUEUE,
                "message": "Queued on the IOC worker and waiting to start event scanning...",
            },
            progress_builder=lambda _task: {
                "status": "processing",
                "current": 0,
                "total": 0,
                "found_count": 0,
                "queue": IOC_TASK_QUEUE,
                "message": "Waiting for the first IOC scan progress update...",
            },
            success_builder=lambda _task: {
                "status": "complete",
                "current": 0,
                "total": 0,
                "found_count": 0,
                "message": "Event scanning complete",
            },
            failure_builder=lambda task: {
                "status": "failed",
                "error": str(task.result),
                "current": 0,
                "total": 0,
                "found_count": 0,
            },
        )
        return jsonify(payload), status_code

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@iocs_bp.route("/iocs/find-in-events/results/<case_uuid>/<task_id>")
@login_required
def get_find_iocs_results(case_uuid, task_id):
    """Get results of completed find IOCs task."""
    try:
        import redis
        from config import Config

        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({"success": False, "error": "Case not found"}), 404
        if not _task_access_allowed(task_id, case_id=case.id):
            return jsonify({"success": False, "error": "Task not accessible"}), 403

        r = redis.Redis(
            host=Config.REDIS_HOST,
            port=Config.REDIS_PORT,
            db=Config.REDIS_DB,
            decode_responses=True,
        )

        key = f"find_iocs_results:{case.id}:{task_id}"
        data = r.get(key)

        if data:
            results = json.loads(data)
            return jsonify({"success": True, **results})
        return jsonify({"success": False, "error": "Results not found or expired"}), 404

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@iocs_bp.route("/iocs/find-in-events/save/<case_uuid>", methods=["POST"])
@login_required
def save_find_iocs_results(case_uuid):
    """Save selected IOCs from find-in-events results."""
    try:
        from utils.ioc_extractor import save_extracted_iocs

        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({"success": False, "error": "Case not found"}), 404

        write_error = _require_case_write_access(current_user)
        if write_error:
            return write_error

        data = request.get_json()
        iocs_data = data.get("iocs", [])
        known_systems = data.get("known_systems", [])
        known_users = data.get("known_users", [])

        results = save_extracted_iocs(
            iocs_data=iocs_data,
            case_id=case.id,
            username=current_user.username,
            known_systems=known_systems,
            known_users=known_users,
        )

        return jsonify({"success": True, "results": results})

    except Exception as e:
        import traceback

        traceback.print_exc()
        return jsonify({"success": False, "error": str(e)}), 500


@iocs_bp.route("/iocs/tag-artifacts/<case_uuid>", methods=["POST"])
@login_required
def tag_artifacts_for_case(case_uuid):
    """Search all artifacts in case for IOC matches and update artifact counts."""
    try:
        from utils.ioc_artifact_tagger import tag_all_iocs_globally

        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({"success": False, "error": "Case not found"}), 404

        write_error = _require_case_write_access(current_user)
        if write_error:
            return write_error

        results = tag_all_iocs_globally(case.id)

        return jsonify(
            {
                "success": results.get("success", False),
                "total_iocs_searched": results.get("total_iocs", 0),
                "iocs_with_matches": results.get("iocs_with_matches", 0),
                "total_artifact_matches": results.get("total_artifact_matches", 0),
                "events_tagged": results.get("events_tagged", 0),
                "system_sightings_created": results.get("system_sightings_created", 0),
                "new_links_created": results.get("system_sightings_created", 0),
                "details": results.get("details", []),
                "error": results.get("error"),
            }
        )

    except Exception as e:
        import traceback

        traceback.print_exc()
        return jsonify({"success": False, "error": str(e)}), 500


@iocs_bp.route("/iocs/tag-artifacts/start/<case_uuid>", methods=["POST"])
@login_required
def start_tag_artifacts_for_case(case_uuid):
    """Start async IOC artifact tagging for a case."""
    try:
        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({"success": False, "error": "Case not found"}), 404

        write_error = _require_case_write_access(current_user)
        if write_error:
            return write_error

        from tasks.celery_tasks import tag_iocs_for_case

        task = tag_iocs_for_case.apply_async(args=(case.id,), queue=IOC_TASK_QUEUE)
        _remember_task_access(task.id, case_id=case.id)
        return jsonify(
            {
                "success": True,
                **_queued_ioc_task_payload(
                    task.id,
                    "Queued on the IOC worker and waiting to start artifact tagging...",
                ),
            }
        )

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@iocs_bp.route("/iocs/tag-artifacts/<case_uuid>/progress", methods=["GET"])
@login_required
def get_tag_artifacts_progress(case_uuid):
    """Get progress of IOC artifact tagging for a case."""
    try:
        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({"success": False, "error": "Case not found"}), 404

        task_id = (request.args.get("task_id") or "").strip()
        if task_id and not _task_access_allowed(task_id, case_id=case.id):
            return jsonify({"success": False, "error": "Task not accessible"}), 403

        from celery.result import AsyncResult
        from tasks.celery_tasks import celery_app
        from utils.ioc_artifact_tagger import get_tag_progress

        progress = get_tag_progress(case.id)
        if progress:
            return jsonify({"success": True, "progress": progress})
        if not task_id:
            return jsonify({"success": True, "progress": None})

        result = AsyncResult(task_id, app=celery_app)
        payload, _status_code = build_async_status_response(
            result,
            task_id=task_id,
            pending_builder=lambda _task: {
                "status": "queued",
                "queue": IOC_TASK_QUEUE,
                "message": "Queued on the IOC worker and waiting to start artifact tagging...",
            },
            progress_builder=lambda task: {
                "status": (getattr(task, "state", "") or "").lower(),
                "queue": IOC_TASK_QUEUE,
                "message": "Waiting for the first artifact-tagging progress update...",
            },
            success_builder=lambda _task: {"status": "complete"},
            failure_builder=lambda task: {"status": "failed", "error": str(task.result)},
            other_builder=lambda task: {"status": (getattr(task, "state", "") or "").lower()},
        )
        return jsonify({"success": True, "progress": payload})

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@iocs_bp.route("/iocs/tag-artifacts/results/<case_uuid>/<task_id>", methods=["GET"])
@login_required
def get_tag_artifacts_results(case_uuid, task_id):
    """Get async IOC artifact tagging results for a case."""
    try:
        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({"success": False, "error": "Case not found"}), 404
        if not _task_access_allowed(task_id, case_id=case.id):
            return jsonify({"success": False, "error": "Task not accessible"}), 403

        from celery.result import AsyncResult
        from tasks.celery_tasks import celery_app

        result = AsyncResult(task_id, app=celery_app)
        payload, status_code = build_async_status_response(
            result,
            task_id=task_id,
            pending_builder=lambda _task: {"status": "pending"},
            progress_builder=lambda task: {"status": (getattr(task, "state", "") or "").lower()},
            success_builder=lambda task: {
                **dict(task.result or {}),
                "total_iocs_searched": dict(task.result or {}).get(
                    "total_iocs_searched",
                    dict(task.result or {}).get("total_iocs", 0),
                ),
            },
            failure_builder=lambda task: {"status": "failed", "error": str(task.result)},
            other_builder=lambda task: {"status": (getattr(task, "state", "") or "").lower()},
        )
        return jsonify(payload), status_code

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@iocs_bp.route("/ioc/<int:ioc_id>/enrich", methods=["POST"])
@login_required
def enrich_ioc(ioc_id):
    """Enrich a single IOC with available threat intelligence providers."""
    try:
        from models.ioc import IOC
        from utils.feature_availability import FeatureAvailability
        from utils.opencti import enrich_ioc as do_enrich

        write_error = _require_case_write_access(current_user)
        if write_error:
            return write_error

        if not FeatureAvailability.is_threat_intel_enabled():
            return jsonify(
                {
                    "success": False,
                    "error": "Threat intelligence enrichment is not currently available",
                }
            ), 400

        ioc = IOC.query.get(ioc_id)
        if not ioc:
            return jsonify({"success": False, "error": "IOC not found"}), 404

        result = do_enrich(ioc)

        if result:
            return jsonify(
                {
                    "success": True,
                    "message": "IOC enriched successfully",
                    "enrichment": json.loads(ioc.opencti_enrichment) if ioc.opencti_enrichment else None,
                    "enriched_at": ioc.opencti_enriched_at.isoformat() if ioc.opencti_enriched_at else None,
                }
            )
        return jsonify(
            {
                "success": False,
                "error": "Enrichment failed - check logs for details",
            }
        ), 500

    except Exception as e:
        logger.error("[ThreatIntel] Error enriching IOC %s: %s", ioc_id, e)
        return jsonify({"success": False, "error": str(e)}), 500


@iocs_bp.route("/ioc/<int:ioc_id>/enrichment", methods=["GET"])
@login_required
def get_ioc_enrichment(ioc_id):
    """Get persisted threat-intel enrichment data for an IOC."""
    try:
        from models.ioc import IOC

        ioc = IOC.query.get(ioc_id)
        if not ioc:
            return jsonify({"success": False, "error": "IOC not found"}), 404

        if not ioc.opencti_enrichment:
            return jsonify({"success": False, "error": "No enrichment data available"}), 404

        enrichment = json.loads(ioc.opencti_enrichment)

        return jsonify(
            {
                "success": True,
                "ioc_id": ioc_id,
                "ioc_value": ioc.value,
                "ioc_type": ioc.ioc_type,
                "enrichment": enrichment,
                "enriched_at": ioc.opencti_enriched_at.isoformat() if ioc.opencti_enriched_at else None,
            }
        )

    except Exception as e:
        logger.error("[OpenCTI] Error getting enrichment for IOC %s: %s", ioc_id, e)
        return jsonify({"success": False, "error": str(e)}), 500


@iocs_bp.route("/iocs/bulk-enrich", methods=["POST"])
@login_required
def bulk_enrich_iocs():
    """Bulk enrich multiple IOCs with available threat intelligence providers."""
    try:
        from models.ioc import IOC
        from utils.feature_availability import FeatureAvailability
        from utils.opencti import enrich_iocs_batch

        write_error = _require_case_write_access(current_user)
        if write_error:
            return write_error

        if not FeatureAvailability.is_threat_intel_enabled():
            return jsonify(
                {
                    "success": False,
                    "error": "Threat intelligence enrichment is not currently available",
                }
            ), 400

        data = request.get_json()
        ioc_ids = data.get("ioc_ids", [])

        if not ioc_ids or not isinstance(ioc_ids, list):
            return jsonify({"success": False, "error": "IOC IDs array required"}), 400

        iocs = IOC.query.filter(IOC.id.in_(ioc_ids)).all()

        if not iocs:
            return jsonify({"success": False, "error": "No valid IOCs found"}), 404

        result = enrich_iocs_batch(iocs)

        return jsonify(result)

    except Exception as e:
        logger.error("[ThreatIntel] Error in bulk enrichment: %s", e)
        return jsonify({"success": False, "error": str(e)}), 500


@iocs_bp.route("/iocs/bulk-update", methods=["POST"])
@login_required
def bulk_update_iocs():
    """Bulk update multiple IOCs."""
    try:
        from models.ioc import IOC, IOCAudit

        write_error = _require_case_write_access(current_user)
        if write_error:
            return write_error

        data = request.get_json()
        ioc_ids = data.get("ioc_ids", [])
        updates = data.get("updates", {})

        if not ioc_ids or not isinstance(ioc_ids, list):
            return jsonify({"success": False, "error": "ioc_ids array required"}), 400

        if not updates or not isinstance(updates, dict):
            return jsonify({"success": False, "error": "updates object required"}), 400

        allowed_fields = {"active", "malicious", "false_positive"}
        update_fields = {k: v for k, v in updates.items() if k in allowed_fields}

        if not update_fields:
            return jsonify({"success": False, "error": "No valid update fields provided"}), 400

        iocs = IOC.query.filter(IOC.id.in_(ioc_ids)).all()

        if not iocs:
            return jsonify({"success": False, "error": "No valid IOCs found"}), 404

        updated_count = 0
        for ioc in iocs:
            for field, value in update_fields.items():
                old_value = getattr(ioc, field)
                if old_value != value:
                    setattr(ioc, field, value)
                    IOCAudit.log_change(
                        ioc_id=ioc.id,
                        changed_by=current_user.username,
                        field_name=field,
                        action="update",
                        old_value=str(old_value),
                        new_value=str(value),
                    )
            updated_count += 1

        db.session.commit()

        return jsonify({"success": True, "updated_count": updated_count})

    except Exception as e:
        db.session.rollback()
        logger.error("Error in IOC bulk update: %s", e)
        return jsonify({"success": False, "error": str(e)}), 500


@iocs_bp.route("/iocs/bulk-delete/<case_uuid>", methods=["POST"])
@login_required
def bulk_delete_iocs(case_uuid):
    """Bulk delete case-owned IOCs and remove any legacy links."""
    try:
        from models.ioc import IOC, IOCAudit, IOCCase, IOCSystemSighting

        write_error = _require_case_write_access(current_user)
        if write_error:
            return write_error

        case = Case.query.filter_by(uuid=case_uuid).first()
        if not case:
            return jsonify({"success": False, "error": "Case not found"}), 404

        data = request.get_json()
        ioc_ids = data.get("ioc_ids", [])

        if not ioc_ids or not isinstance(ioc_ids, list):
            return jsonify({"success": False, "error": "ioc_ids array required"}), 400

        deleted_count = 0
        removed_legacy_links = 0

        for ioc_id in ioc_ids:
            ioc = IOC.query.get(ioc_id)
            if ioc and ioc.case_id == case.id:
                IOCAudit.query.filter_by(ioc_id=ioc.id).delete()
                IOCSystemSighting.query.filter_by(ioc_id=ioc.id).delete()
                IOCCase.query.filter_by(ioc_id=ioc.id).delete()
                db.session.delete(ioc)
                deleted_count += 1
                continue

            ioc_case = IOCCase.query.filter_by(ioc_id=ioc_id, case_id=case.id).first()
            if ioc_case:
                IOCAudit.log_change(
                    ioc_id=ioc_id,
                    changed_by=current_user.username,
                    field_name="case",
                    action="delete",
                    old_value=case.uuid,
                    new_value=None,
                )
                db.session.delete(ioc_case)
                removed_legacy_links += 1

        db.session.commit()

        return jsonify(
            {
                "success": True,
                "deleted_count": deleted_count,
                "removed_legacy_links": removed_legacy_links,
            }
        )

    except Exception as e:
        db.session.rollback()
        logger.error("Error in IOC bulk delete: %s", e)
        return jsonify({"success": False, "error": str(e)}), 500
