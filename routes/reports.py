"""Report-related API routes extracted from the monolithic API module."""

import logging
import os

from flask import Blueprint, jsonify, request, send_file
from flask_login import current_user, login_required

from models.case import Case
from models.database import db
from routes.route_helpers import _viewer_write_error

logger = logging.getLogger(__name__)

reports_bp = Blueprint("reports", __name__, url_prefix="/api")


@reports_bp.route("/reports/templates")
@login_required
def list_report_templates():
    """List all report templates."""
    try:
        from models.report_template import ReportTemplate

        templates = ReportTemplate.query.order_by(
            ReportTemplate.is_default.desc(),
            ReportTemplate.display_name,
        ).all()

        return jsonify(
            {
                "success": True,
                "templates": [t.to_dict() for t in templates],
            }
        )

    except Exception as e:
        logger.error("Error listing report templates: %s", e)
        return jsonify({"success": False, "error": str(e)}), 500


@reports_bp.route("/reports/templates/active")
@login_required
def list_active_report_templates():
    """List only active templates that exist on disk."""
    try:
        from models.report_template import ReportTemplate

        templates = ReportTemplate.get_active_templates()

        return jsonify(
            {
                "success": True,
                "templates": [t.to_dict() for t in templates],
            }
        )

    except Exception as e:
        logger.error("Error listing active report templates: %s", e)
        return jsonify({"success": False, "error": str(e)}), 500


@reports_bp.route("/reports/templates/scan", methods=["POST"])
@login_required
def scan_report_templates():
    """Scan templates folder and sync with database."""
    if not current_user.is_administrator:
        return jsonify({"success": False, "error": "Administrator access required"}), 403

    try:
        from models.report_template import ReportTemplate

        result = ReportTemplate.scan_templates(updated_by=current_user.username)

        return jsonify(
            {
                "success": True,
                "added": result["added"],
                "removed": result["removed"],
                "existing": result["existing"],
                "total_on_disk": result["total_on_disk"],
            }
        )

    except Exception as e:
        logger.error("Error scanning report templates: %s", e)
        return jsonify({"success": False, "error": str(e)}), 500


@reports_bp.route("/reports/templates/types")
@login_required
def list_report_types():
    """List available report types for templates."""
    try:
        from models.report_template import ReportTemplate, ReportType

        types = []
        for rt in ReportType.all():
            types.append(
                {
                    "value": rt,
                    "label": ReportType.labels().get(rt, rt),
                    "description": ReportType.descriptions().get(rt, ""),
                }
            )

        type_counts = ReportTemplate.get_report_types_with_templates()
        for item in types:
            item["template_count"] = type_counts.get(item["value"], 0)

        return jsonify(
            {
                "success": True,
                "report_types": types,
            }
        )

    except Exception as e:
        logger.error("Error listing report types: %s", e)
        return jsonify({"success": False, "error": str(e)}), 500


@reports_bp.route("/reports/templates/by-type/<report_type>")
@login_required
def list_templates_by_type(report_type):
    """List active templates for a specific report type."""
    try:
        from models.report_template import ReportTemplate, ReportType

        if report_type not in ReportType.all():
            return jsonify(
                {
                    "success": False,
                    "error": f'Invalid report type. Valid types: {", ".join(ReportType.all())}',
                }
            ), 400

        templates = ReportTemplate.get_templates_by_type(report_type)

        return jsonify(
            {
                "success": True,
                "report_type": report_type,
                "report_type_label": ReportType.labels().get(report_type, report_type),
                "templates": [t.to_dict() for t in templates],
            }
        )

    except Exception as e:
        logger.error("Error listing templates by type: %s", e)
        return jsonify({"success": False, "error": str(e)}), 500


@reports_bp.route("/reports/templates/<int:template_id>", methods=["PUT"])
@login_required
def update_report_template(template_id):
    """Update report template metadata."""
    if not current_user.is_administrator:
        return jsonify({"success": False, "error": "Administrator access required"}), 403

    try:
        from models.report_template import ReportTemplate, ReportType

        template = ReportTemplate.query.get(template_id)
        if not template:
            return jsonify({"success": False, "error": "Template not found"}), 404

        data = request.get_json() or {}

        if "display_name" in data:
            display_name = data["display_name"].strip()
            if display_name:
                template.display_name = display_name

        if "description" in data:
            template.description = data["description"].strip() or None

        if "report_type" in data:
            report_type = data["report_type"]
            if report_type and report_type in ReportType.all():
                template.report_type = report_type
            elif report_type:
                return jsonify(
                    {
                        "success": False,
                        "error": f'Invalid report type. Valid types: {", ".join(ReportType.all())}',
                    }
                ), 400

        if "is_active" in data:
            template.is_active = bool(data["is_active"])

        if "is_default" in data and data["is_default"]:
            ReportTemplate.query.filter(ReportTemplate.id != template_id).update(
                {ReportTemplate.is_default: False}
            )
            template.is_default = True
        elif "is_default" in data and not data["is_default"]:
            template.is_default = False

        template.updated_by = current_user.username
        db.session.commit()

        return jsonify(
            {
                "success": True,
                "template": template.to_dict(),
            }
        )

    except Exception as e:
        logger.error("Error updating report template: %s", e)
        db.session.rollback()
        return jsonify({"success": False, "error": str(e)}), 500


@reports_bp.route("/reports/templates/<int:template_id>", methods=["DELETE"])
@login_required
def delete_report_template(template_id):
    """Delete a report template."""
    try:
        from models.report_template import ReportTemplate

        template = ReportTemplate.query.get(template_id)
        if not template:
            return jsonify({"success": False, "error": "Template not found"}), 404

        filename = template.filename
        db.session.delete(template)
        db.session.commit()

        return jsonify(
            {
                "success": True,
                "message": f'Template "{filename}" removed from database',
            }
        )

    except Exception as e:
        logger.error("Error deleting report template: %s", e)
        db.session.rollback()
        return jsonify({"success": False, "error": str(e)}), 500


@reports_bp.route("/reports/templates/<int:template_id>/placeholders")
@login_required
def get_template_placeholders(template_id):
    """Get available placeholders in a template."""
    try:
        from models.report_template import ReportTemplate
        from utils.report_generator import ReportGenerator

        template = ReportTemplate.query.get(template_id)
        if not template:
            return jsonify({"success": False, "error": "Template not found"}), 404

        if not template.file_exists:
            return jsonify({"success": False, "error": "Template file not found on disk"}), 404

        template_path = ReportTemplate.get_template_path(template.filename)
        generator = ReportGenerator(template_path)
        placeholders = generator.get_available_placeholders()

        return jsonify(
            {
                "success": True,
                "placeholders": placeholders,
            }
        )

    except Exception as e:
        logger.error("Error getting template placeholders: %s", e)
        return jsonify({"success": False, "error": str(e)}), 500


@reports_bp.route("/reports/generate/<case_uuid>", methods=["POST"])
@login_required
def generate_report(case_uuid):
    """Generate a report for a case."""
    try:
        from models.report_template import ReportTemplate
        from utils.report_generator import generate_case_report, get_base_case_context
        from utils.hunt_negative_report_adapter import build_negative_findings_report_context

        if current_user.permission_level == "viewer":
            return _viewer_write_error("Viewers cannot generate reports")

        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({"success": False, "error": "Case not found"}), 404

        data = request.get_json() or {}

        template_id = data.get("template_id")
        if template_id:
            template = ReportTemplate.query.get(template_id)
        else:
            template = ReportTemplate.get_default_template()

        if not template:
            return jsonify(
                {
                    "success": False,
                    "error": "No template specified and no default template set",
                }
            ), 400

        if not template.file_exists:
            return jsonify(
                {
                    "success": False,
                    "error": "Template file not found on disk",
                }
            ), 400

        context = get_base_case_context(case)
        selected_negative_finding_ids = data.get("negative_finding_ids", [])
        context.update(
            build_negative_findings_report_context(
                case.id,
                selected_finding_ids=selected_negative_finding_ids,
            )
        )
        if "context" in data:
            reserved_negative_finding_keys = {
                "negative_findings",
                "negative_findings_section",
                "negative_findings_section_title",
                "negative_findings_audit_appendix",
                "negative_findings_audit_appendix_title",
                "negative_findings_included",
            }
            context.update({
                key: value
                for key, value in data["context"].items()
                if key not in reserved_negative_finding_keys
            })

        report_path = generate_case_report(
            case_uuid=case_uuid,
            template_id=template.id,
            context=context,
        )

        if not report_path:
            return jsonify({"success": False, "error": "Failed to generate report"}), 500

        filename = os.path.basename(report_path)

        return jsonify(
            {
                "success": True,
                "report_path": report_path,
                "filename": filename,
                "negative_findings_included": context["negative_findings_included"],
            }
        )

    except Exception as e:
        logger.error("Error generating report: %s", e)
        return jsonify({"success": False, "error": str(e)}), 500


@reports_bp.route("/reports/negative-findings/preview/<case_uuid>", methods=["GET", "POST"])
@login_required
def preview_report_negative_findings(case_uuid):
    """Preview reportable negative findings before per-report inclusion."""
    try:
        from utils.hunt_negative_report_adapter import (
            build_negative_findings_report_context,
            get_reportable_negative_findings_for_case,
            serialize_reportable_negative_finding,
        )

        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({"success": False, "error": "Case not found"}), 404

        data = request.get_json(silent=True) or {}
        selected_negative_finding_ids = data.get("negative_finding_ids", [])
        candidates = [
            serialize_reportable_negative_finding(finding)
            for finding in get_reportable_negative_findings_for_case(case.id)
        ]
        selected_context = build_negative_findings_report_context(
            case.id,
            selected_finding_ids=selected_negative_finding_ids,
        )

        return jsonify(
            {
                "success": True,
                "section_title": selected_context["negative_findings_section_title"],
                "candidates": candidates,
                "selected_negative_finding_ids": selected_negative_finding_ids,
                "selected_negative_findings": selected_context["negative_findings"],
                "negative_findings_section": selected_context["negative_findings_section"],
                "negative_findings_included": selected_context["negative_findings_included"],
                "approval_rule": "Negative findings are included only when selected for this report.",
            }
        )

    except Exception as e:
        logger.error("Error previewing report negative findings: %s", e)
        return jsonify({"success": False, "error": str(e)}), 500


@reports_bp.route("/reports/list/<case_uuid>")
@login_required
def list_case_reports(case_uuid):
    """List all generated reports for a case."""
    try:
        from utils.report_generator import list_case_reports as get_reports

        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({"success": False, "error": "Case not found"}), 404

        reports = get_reports(case_uuid)

        return jsonify(
            {
                "success": True,
                "reports": reports,
            }
        )

    except Exception as e:
        logger.error("Error listing case reports: %s", e)
        return jsonify({"success": False, "error": str(e)}), 500


@reports_bp.route("/reports/download/<case_uuid>/<filename>")
@login_required
def download_report(case_uuid, filename):
    """Download a generated report."""
    try:
        from utils.report_generator import get_case_reports_folder

        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({"success": False, "error": "Case not found"}), 404

        safe_filename = os.path.basename(filename)
        if not safe_filename.lower().endswith(".docx"):
            return jsonify({"success": False, "error": "Invalid file type"}), 400

        reports_folder = get_case_reports_folder(case_uuid)
        file_path = os.path.join(reports_folder, safe_filename)

        if not os.path.isfile(file_path):
            return jsonify({"success": False, "error": "Report not found"}), 404

        return send_file(
            file_path,
            as_attachment=True,
            download_name=safe_filename,
            mimetype="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        )

    except Exception as e:
        logger.error("Error downloading report: %s", e)
        return jsonify({"success": False, "error": str(e)}), 500


@reports_bp.route("/reports/case/<case_uuid>")
@login_required
def list_case_reports_managed(case_uuid):
    """List all reports for a case with sync."""
    try:
        from models.case_report import CaseReport

        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({"success": False, "error": "Case not found"}), 404

        sync_result = CaseReport.sync_reports_for_case(
            case_uuid=case_uuid,
            case_id=case.id,
            username=current_user.username if current_user.is_authenticated else "system",
        )

        reports = CaseReport.get_reports_for_case(case.id)

        return jsonify(
            {
                "success": True,
                "reports": [r.to_dict() for r in reports],
                "sync": sync_result,
            }
        )

    except Exception as e:
        logger.error("Error listing case reports: %s", e)
        import traceback

        traceback.print_exc()
        return jsonify({"success": False, "error": str(e)}), 500


@reports_bp.route("/reports/<int:report_id>/notes", methods=["PUT"])
@login_required
def update_report_notes(report_id):
    """Update notes for a report."""
    try:
        from models.case_report import CaseReport

        if current_user.permission_level == "viewer":
            return _viewer_write_error("Viewers cannot modify reports")

        report = CaseReport.get_by_id(report_id)
        if not report:
            return jsonify({"success": False, "error": "Report not found"}), 404

        case = Case.get_by_id(report.case_id)
        if not case:
            return jsonify({"success": False, "error": "Associated case not found"}), 404

        data = request.get_json() or {}
        notes = data.get("notes", "")

        report.update_notes(
            notes=notes,
            username=current_user.username if current_user.is_authenticated else "system",
            case_uuid=case.uuid,
        )

        return jsonify(
            {
                "success": True,
                "report": report.to_dict(),
            }
        )

    except Exception as e:
        logger.error("Error updating report notes: %s", e)
        import traceback

        traceback.print_exc()
        return jsonify({"success": False, "error": str(e)}), 500


@reports_bp.route("/reports/<int:report_id>", methods=["DELETE"])
@login_required
def delete_case_report(report_id):
    """Delete a report."""
    try:
        from models.case_report import CaseReport

        if current_user.permission_level == "viewer":
            return _viewer_write_error("Viewers cannot delete reports")

        report = CaseReport.get_by_id(report_id)
        if not report:
            return jsonify({"success": False, "error": "Report not found"}), 404

        case = Case.get_by_id(report.case_id)
        if not case:
            return jsonify({"success": False, "error": "Associated case not found"}), 404

        filename = report.filename

        report.delete_report(
            username=current_user.username if current_user.is_authenticated else "system",
            case_uuid=case.uuid,
            delete_file=True,
        )

        return jsonify(
            {
                "success": True,
                "message": f"Report {filename} deleted successfully",
            }
        )

    except Exception as e:
        logger.error("Error deleting report: %s", e)
        import traceback

        traceback.print_exc()
        return jsonify({"success": False, "error": str(e)}), 500
