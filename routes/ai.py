"""AI-specific API routes extracted from the monolithic API module."""

import logging
import os
from datetime import datetime, timedelta

from flask import Blueprint, jsonify, request
from flask_login import current_user, login_required

from models.case import Case
from models.case_work import CaseWorkActivityType
from models.database import db
from routes.route_helpers import _is_license_feature_active, _viewer_write_error
from utils.case_work import safe_log_case_work_activity

logger = logging.getLogger(__name__)

ai_bp = Blueprint("ai", __name__, url_prefix="/api")


@ai_bp.route("/settings/ai", methods=["GET"])
@login_required
def get_ai_settings():
    """Get AI settings including per-provider configuration."""
    try:
        from models.system_settings import (
            AIProviderType,
            SettingKeys,
            SystemSettings,
            get_ai_provider_settings,
            mask_api_key,
        )
        from utils.ai_adapters import (
            get_builtin_local_adapter_catalog,
            split_saved_adapter_targets,
        )

        feature_active = _is_license_feature_active("ai")
        settings = get_ai_provider_settings(include_all_keys=True)
        adapter_selection = split_saved_adapter_targets(
            settings.get("compat_function_adapter_models", {}),
        )

        return jsonify(
            {
                "success": True,
                "ai_enabled": settings["ai_enabled"] if feature_active else False,
                "feature_active": feature_active,
                "provider_type": settings["provider_type"],
                "provider_types": AIProviderType.LABELS,
                "compat_url": settings["compat_url"],
                "compat_key_set": bool(settings["compat_key"]),
                "compat_key_masked": mask_api_key(settings["compat_key"]) if settings["compat_key"] else "",
                "compat_model": settings["compat_model"],
                "compat_function_adapter_models": settings.get("compat_function_adapter_models", {}),
                "compat_function_builtin_adapters": adapter_selection.get("builtin", {}),
                "compat_function_custom_adapters": adapter_selection.get("custom", {}),
                "compat_adapter_catalog": get_builtin_local_adapter_catalog(),
                "openai_key_set": bool(settings["openai_key"]),
                "openai_key_masked": mask_api_key(settings["openai_key"]) if settings["openai_key"] else "",
                "openai_model": settings["openai_model"],
                "claude_key_set": bool(settings["claude_key"]),
                "claude_key_masked": mask_api_key(settings["claude_key"]) if settings["claude_key"] else "",
                "claude_model": settings["claude_model"],
                "api_url": settings["api_url"],
                "api_key_set": bool(settings["api_key"]),
                "api_key_masked": mask_api_key(settings["api_key"]) if settings["api_key"] else "",
                "model_name": settings["model_name"],
                "gpu_tier": settings["gpu_tier"],
                "max_tokens": settings.get("max_tokens"),
                "compat_function_models": settings.get("compat_function_models", {}),
                "openai_function_models": settings.get("openai_function_models", {}),
                "claude_function_models": settings.get("claude_function_models", {}),
                "privacy_obfuscation_level": settings.get("privacy_obfuscation_level"),
                "privacy_off_ack": settings.get("privacy_off_ack", {}),
            }
        )

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@ai_bp.route("/settings/ai", methods=["POST"])
@login_required
def set_ai_settings():
    """Set AI settings including per-provider configuration."""
    try:
        if not current_user.is_administrator:
            return jsonify({"success": False, "error": "Administrator access required"}), 403
        if not _is_license_feature_active("ai"):
            return jsonify(
                {
                    "success": False,
                    "error": "AI settings are locked until a valid active AI license is available",
                }
            ), 403

        from models.system_settings import SettingKeys, SystemSettings, save_ai_provider_settings
        from utils.feature_availability import FeatureAvailability
        from utils.ai_providers import invalidate_provider_cache

        data = request.get_json()

        if "ai_enabled" in data:
            SystemSettings.set(
                SettingKeys.AI_ENABLED,
                data["ai_enabled"],
                value_type="bool",
                updated_by=current_user.username,
            )

        if "provider_type" in data:
            save_ai_provider_settings(
                provider_type=data.get("provider_type", "openai_compatible"),
                compat_url=data.get("compat_url", ""),
                compat_key=data.get("compat_key", ""),
                compat_model=data.get("compat_model", ""),
                openai_key=data.get("openai_key", ""),
                openai_model=data.get("openai_model", ""),
                claude_key=data.get("claude_key", ""),
                claude_model=data.get("claude_model", ""),
                compat_function_models=data.get("compat_function_models"),
                compat_function_adapter_models=data.get("compat_function_adapter_models"),
                openai_function_models=data.get("openai_function_models"),
                claude_function_models=data.get("claude_function_models"),
                max_tokens=data.get("max_tokens"),
                privacy_obfuscation_level=data.get("privacy_obfuscation_level", ""),
                privacy_off_ack=data.get("privacy_off_ack"),
                updated_by=current_user.username,
            )
            invalidate_provider_cache()
            FeatureAvailability.clear_cache()

        return jsonify({"success": True})

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@ai_bp.route("/settings/ai/test-connection", methods=["POST"])
@login_required
def test_ai_connection():
    """Test connectivity to the configured AI provider."""
    try:
        if not current_user.is_administrator:
            return jsonify({"success": False, "error": "Administrator access required"}), 403
        if not _is_license_feature_active("ai"):
            return jsonify(
                {
                    "success": False,
                    "error": "AI settings are locked until a valid active AI license is available",
                }
            ), 403

        from utils.ai_providers import get_llm_provider

        provider = get_llm_provider()
        health = provider.health_check()

        return jsonify(
            {
                "success": True,
                "provider_type": provider.provider_type(),
                "health": health,
            }
        )

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@ai_bp.route("/settings/ai/models", methods=["GET"])
@login_required
def list_ai_models():
    """Fetch available models from the configured AI provider with profile info."""
    try:
        if not _is_license_feature_active("ai"):
            return jsonify(
                {
                    "success": False,
                    "error": "AI settings are locked until a valid active AI license is available",
                }
            ), 403
        from utils.ai_adapters import get_builtin_local_adapter_targets
        from utils.ai_providers import get_llm_provider, get_model_profile

        provider = get_llm_provider()
        model_ids = provider.list_models()
        if provider.provider_type() == "openai_compatible":
            builtin_adapter_targets = get_builtin_local_adapter_targets()
            model_ids = [
                model_id
                for model_id in model_ids
                if (model_id or "").strip().lower() not in builtin_adapter_targets
            ]

        models = []
        for mid in model_ids:
            profile = get_model_profile(mid)
            models.append(
                {
                    "id": mid,
                    "context_window": profile["context_window"],
                    "tier": profile["tier"],
                    "batch_size": profile["batch_size"],
                    "timeout": profile["timeout"],
                }
            )

        return jsonify(
            {
                "success": True,
                "provider_type": provider.provider_type(),
                "models": models,
            }
        )

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@ai_bp.route("/settings/ai/fetch-models", methods=["POST"])
@login_required
def fetch_models_for_provider():
    """Fetch available models for a specific provider using ad-hoc credentials."""
    try:
        if not current_user.is_administrator:
            return jsonify({"success": False, "error": "Administrator access required"}), 403
        if not _is_license_feature_active("ai"):
            return jsonify(
                {
                    "success": False,
                    "error": "AI settings are locked until a valid active AI license is available",
                }
            ), 403
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return jsonify({"success": False, "error": "JSON request body required"}), 400
        provider_type = data.get("provider_type")
        api_url = data.get("api_url", "")
        api_key = data.get("api_key", "")

        if not api_key:
            from models.system_settings import SettingKeys, SystemSettings, decrypt_api_key

            if provider_type == "openai_compatible":
                api_key = decrypt_api_key(
                    SystemSettings.get(SettingKeys.AI_COMPAT_KEY, "")
                    or SystemSettings.get(SettingKeys.AI_API_KEY, "")
                )
            elif provider_type == "openai":
                api_key = decrypt_api_key(SystemSettings.get(SettingKeys.AI_OPENAI_KEY, ""))
            elif provider_type == "claude":
                api_key = decrypt_api_key(SystemSettings.get(SettingKeys.AI_CLAUDE_KEY, ""))

        from utils.ai_adapters import get_builtin_local_adapter_targets
        from utils.ai_providers import (
            ClaudeProvider,
            OpenAICompatibleProvider,
            OpenAIProvider,
            get_model_profile,
        )

        if provider_type == "openai_compatible":
            provider = OpenAICompatibleProvider(
                api_url=api_url or "http://127.0.0.1:11434",
                model="",
                api_key=api_key,
            )
        elif provider_type == "openai":
            if not api_key:
                return jsonify({"success": False, "error": "OpenAI API key is required"}), 400
            provider = OpenAIProvider(api_key=api_key, model="gpt-4o")
        elif provider_type == "claude":
            if not api_key:
                return jsonify({"success": False, "error": "Anthropic API key is required"}), 400
            provider = ClaudeProvider(api_key=api_key, model="claude-sonnet-4-6")
        else:
            return jsonify({"success": False, "error": "Invalid provider type"}), 400

        model_ids = provider.list_models()
        if provider_type == "openai_compatible":
            builtin_adapter_targets = get_builtin_local_adapter_targets()
            model_ids = [
                model_id
                for model_id in model_ids
                if (model_id or "").strip().lower() not in builtin_adapter_targets
            ]
        models = []
        for mid in model_ids:
            profile = get_model_profile(mid)
            models.append(
                {
                    "id": mid,
                    "context_window": profile["context_window"],
                    "tier": profile["tier"],
                    "batch_size": profile["batch_size"],
                    "timeout": profile["timeout"],
                }
            )

        return jsonify({"success": True, "models": models})

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@ai_bp.route("/settings/ai/status", methods=["GET"])
@login_required
def get_ai_provider_status():
    """Return current AI provider info and rate limit status for UI display."""
    try:
        if not _is_license_feature_active("ai"):
            return jsonify(
                {
                    "success": True,
                    "provider_type": None,
                    "model": None,
                    "display": "AI settings locked until activation is restored",
                    "rate_limit": {},
                    "profile": {},
                    "feature_active": False,
                }
            )
        from utils.ai_providers import get_llm_provider

        provider = get_llm_provider()
        rate = provider.get_rate_limit_info()
        batch = provider.get_batch_config()

        return jsonify(
            {
                "success": True,
                "provider_type": provider.provider_type(),
                "model": provider.model,
                "display": provider.get_provider_display(),
                "rate_limit": rate,
                "profile": batch,
                "feature_active": True,
            }
        )

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@ai_bp.route("/settings/ai/runtime-metrics", methods=["GET"])
@login_required
def get_ai_runtime_metrics():
    """Return aggregate AI runtime metrics for admin observability."""
    if not current_user.is_administrator:
        return jsonify({"success": False, "error": "Administrator access required"}), 403

    try:
        from utils.ai import get_ai_runtime_metrics as load_runtime_metrics
        from utils.ai_providers import get_llm_provider

        provider_payload = {}
        if _is_license_feature_active("ai"):
            provider = get_llm_provider()
            provider_payload = {
                "provider_type": provider.provider_type(),
                "model": provider.model,
                "display": provider.get_provider_display(),
                "rate_limit": provider.get_rate_limit_info(),
                "profile": provider.get_batch_config(),
            }

        return jsonify(
            {
                "success": True,
                "feature_active": _is_license_feature_active("ai"),
                "metrics": load_runtime_metrics(),
                "provider": provider_payload,
            }
        )

    except Exception as e:
        logger.error("Error getting AI runtime metrics: %s", e)
        return jsonify({"success": False, "error": str(e)}), 500


@ai_bp.route("/settings/ai-audit", methods=["GET"])
@login_required
def get_ai_audit_settings():
    """Return AI Audit policy settings and summary counts."""
    if not current_user.is_administrator:
        return jsonify({"success": False, "error": "Administrator access required"}), 403

    try:
        from models.ai_audit_log import AIAuditLog
        from models.system_settings import SettingKeys, SystemSettings

        return jsonify(
            {
                "success": True,
                "enabled": SystemSettings.get(SettingKeys.AI_AUDIT_ENABLED, True),
                "strict_mode": SystemSettings.get(SettingKeys.AI_AUDIT_STRICT_MODE, True),
                "total_records": AIAuditLog.query.count(),
                "last_record": (
                    AIAuditLog.query.order_by(AIAuditLog.timestamp.desc()).first().to_dict()
                    if AIAuditLog.query.count()
                    else None
                ),
            }
        )
    except Exception as e:
        logger.error("Error getting AI audit settings: %s", e)
        return jsonify({"success": False, "error": str(e)}), 500


@ai_bp.route("/settings/ai-audit", methods=["POST"])
@login_required
def set_ai_audit_settings():
    """Update AI Audit policy settings with required reason for degraded modes."""
    if not current_user.is_administrator:
        return jsonify({"success": False, "error": "Administrator access required"}), 403

    try:
        from models.audit_log import AuditAction, AuditEntityType, AuditLog
        from models.system_settings import SettingKeys, SystemSettings

        data = request.get_json(silent=True) or {}
        reason = (data.get("reason") or "").strip()
        old_enabled = SystemSettings.get(SettingKeys.AI_AUDIT_ENABLED, True)
        old_strict = SystemSettings.get(SettingKeys.AI_AUDIT_STRICT_MODE, True)
        new_enabled = bool(data.get("enabled", old_enabled))
        new_strict = bool(data.get("strict_mode", old_strict))

        if (old_enabled and not new_enabled or old_strict and not new_strict) and not reason:
            return jsonify({"success": False, "error": "A reason is required to disable or degrade AI Audit"}), 400

        if "enabled" in data:
            SystemSettings.set(
                SettingKeys.AI_AUDIT_ENABLED,
                new_enabled,
                value_type="bool",
                updated_by=current_user.username,
            )
            if old_enabled != new_enabled:
                AuditLog.log(
                    entity_type=AuditEntityType.SETTING,
                    entity_id=SettingKeys.AI_AUDIT_ENABLED,
                    action=AuditAction.SETTING_CHANGED,
                    entity_name="AI Audit Enabled",
                    field_name=SettingKeys.AI_AUDIT_ENABLED,
                    old_value=old_enabled,
                    new_value=new_enabled,
                    details={"reason": reason},
                )

        if "strict_mode" in data:
            SystemSettings.set(
                SettingKeys.AI_AUDIT_STRICT_MODE,
                new_strict,
                value_type="bool",
                updated_by=current_user.username,
            )
            if old_strict != new_strict:
                AuditLog.log(
                    entity_type=AuditEntityType.AI_AUDIT,
                    entity_id=SettingKeys.AI_AUDIT_STRICT_MODE,
                    action=AuditAction.AI_AUDIT_STRICT_MODE_CHANGED,
                    entity_name="AI Audit Strict Mode",
                    old_value=old_strict,
                    new_value=new_strict,
                    details={"reason": reason},
                )

        return jsonify({"success": True, "enabled": new_enabled, "strict_mode": new_strict})
    except Exception as e:
        logger.error("Error updating AI audit settings: %s", e)
        return jsonify({"success": False, "error": str(e)}), 500


@ai_bp.route("/settings/ai-audit/records", methods=["GET"])
@login_required
def get_ai_audit_records():
    """Return paginated AI Audit records with metadata filters."""
    if not current_user.is_administrator:
        return jsonify({"success": False, "error": "Administrator access required"}), 403

    try:
        from models.ai_audit_log import AIAuditLog, AIAuditStatus

        page = request.args.get("page", 1, type=int)
        per_page = min(request.args.get("per_page", 50, type=int), 200)
        case_uuid = request.args.get("case_uuid")
        function = request.args.get("function")
        model = request.args.get("model")
        status = request.args.get("status")
        username = request.args.get("username")
        days = request.args.get("days", type=int)
        search = request.args.get("search", "").strip()

        query = AIAuditLog.query
        if case_uuid:
            query = query.filter(AIAuditLog.case_uuid == case_uuid)
        if function:
            query = query.filter(AIAuditLog.function == function)
        if model:
            query = query.filter(AIAuditLog.model == model)
        if status:
            query = query.filter(AIAuditLog.status == status)
        if username:
            query = query.filter(AIAuditLog.username == username)
        if days:
            query = query.filter(AIAuditLog.timestamp >= datetime.utcnow() - timedelta(days=days))
        if search:
            pattern = f"%{search}%"
            query = query.filter(
                db.or_(
                    AIAuditLog.case_name.ilike(pattern),
                    AIAuditLog.client_name.ilike(pattern),
                    AIAuditLog.username.ilike(pattern),
                    AIAuditLog.model.ilike(pattern),
                    AIAuditLog.function.ilike(pattern),
                    AIAuditLog.record_hash.ilike(pattern),
                )
            )

        pagination = query.order_by(AIAuditLog.timestamp.desc()).paginate(
            page=page,
            per_page=per_page,
            error_out=False,
        )

        return jsonify(
            {
                "success": True,
                "entries": [entry.to_dict() for entry in pagination.items],
                "total": pagination.total,
                "pages": pagination.pages,
                "page": page,
                "per_page": per_page,
                "filters": {
                    "statuses": AIAuditStatus.all(),
                    "functions": [
                        row[0]
                        for row in db.session.query(AIAuditLog.function)
                        .distinct()
                        .order_by(AIAuditLog.function.asc())
                        .all()
                    ],
                },
            }
        )
    except Exception as e:
        logger.error("Error getting AI audit records: %s", e)
        return jsonify({"success": False, "error": str(e)}), 500


@ai_bp.route("/settings/ai-audit/records/<int:record_id>", methods=["GET"])
@login_required
def get_ai_audit_record(record_id):
    """Return one AI Audit record including prompt and response payloads."""
    if not current_user.is_administrator:
        return jsonify({"success": False, "error": "Administrator access required"}), 403

    try:
        from models.ai_audit_log import AIAuditLog

        entry = AIAuditLog.query.get_or_404(record_id)
        return jsonify({"success": True, "entry": entry.to_dict(include_payloads=True)})
    except Exception as e:
        logger.error("Error getting AI audit record: %s", e)
        return jsonify({"success": False, "error": str(e)}), 500


@ai_bp.route("/settings/ai-audit/verify", methods=["POST"])
@login_required
def verify_ai_audit_records():
    """Verify the global AI Audit hash chain and attest the result in AuditLog."""
    if not current_user.is_administrator:
        return jsonify({"success": False, "error": "Administrator access required"}), 403

    started_at = datetime.utcnow()
    try:
        from models.audit_log import AuditAction, AuditEntityType, AuditLog
        from utils.ai_audit import verify_ai_audit_chain

        result = verify_ai_audit_chain()
        ended_at = datetime.utcnow()
        details = {
            "scope": "global",
            "record_count_checked": result.get("record_count_checked", 0),
            "started_at": started_at.isoformat(),
            "ended_at": ended_at.isoformat(),
            "first_record_timestamp": result.get("first_record_timestamp"),
            "last_record_timestamp": result.get("last_record_timestamp"),
            "first_inconsistent_record_id": result.get("first_inconsistent_record_id"),
            "expected_hash": result.get("expected_hash"),
            "actual_hash": result.get("actual_hash"),
            "previous_record_hash": result.get("previous_record_hash"),
            "verified_by": current_user.username,
        }
        AuditLog.log(
            entity_type=AuditEntityType.AI_AUDIT,
            entity_id="global",
            entity_name="AI Audit chain verification",
            action=AuditAction.AI_AUDIT_VERIFIED if result.get("valid") else AuditAction.AI_AUDIT_VERIFICATION_FAILED,
            details=details,
        )
        return jsonify({"success": True, **result, "started_at": details["started_at"], "ended_at": details["ended_at"]})
    except Exception as e:
        logger.error("Error verifying AI audit chain: %s", e)
        return jsonify({"success": False, "error": str(e)}), 500


@ai_bp.route("/reports/generate-status/<case_uuid>", methods=["GET"])
@login_required
def get_ai_report_generation_status(case_uuid):
    """Case-keyed status of the AI report generation, resumable after reload."""
    try:
        from tasks.report_tasks import get_ai_report_status

        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({"success": False, "error": "Case not found"}), 404

        return jsonify({"success": True, "generation": get_ai_report_status(case_uuid)})
    except Exception as e:
        logger.error("Error reading AI report generation status: %s", e)
        return jsonify({"success": False, "error": str(e)}), 500


@ai_bp.route("/reports/generate-cancel/<case_uuid>", methods=["POST"])
@login_required
def cancel_ai_report_generation(case_uuid):
    """Cancel the in-flight AI report generation for a case.

    Sets a cooperative cancellation token (honored at the next generation
    step) and revokes the Celery task so queued work never starts.
    """
    try:
        from tasks.celery_tasks import celery_app
        from tasks.report_tasks import (
            AI_REPORT_CANCEL_SCOPE,
            get_ai_report_status,
            set_ai_report_status,
        )
        from utils.async_cancellation import request_cancellation

        if current_user.permission_level == "viewer":
            return _viewer_write_error("Viewers cannot cancel report generation")

        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({"success": False, "error": "Case not found"}), 404

        status = get_ai_report_status(case_uuid)
        if not status or status.get("status") != "running":
            return jsonify({"success": False, "error": "No report generation is running for this case"}), 400

        request_cancellation(AI_REPORT_CANCEL_SCOPE, case_uuid, {"by": current_user.username})
        task_id = status.get("task_id")
        if task_id:
            celery_app.control.revoke(task_id, terminate=True, signal="SIGTERM")
        set_ai_report_status(case_uuid, status="cancelled", message="Cancelled by analyst")

        return jsonify({"success": True, "message": "Report generation cancelled"})
    except Exception as e:
        logger.error("Error cancelling AI report: %s", e)
        return jsonify({"success": False, "error": str(e)}), 500


@ai_bp.route("/reports/generate-ai/<case_uuid>", methods=["POST"])
@login_required
def generate_ai_report(case_uuid):
    """Queue an AI-powered report generation for a case based on template type."""
    try:
        from models.report_template import ReportTemplate, ReportType
        from tasks.report_tasks import (
            generate_ai_report_task,
            is_ai_report_generation_running,
            set_ai_report_status,
        )
        from utils.feature_availability import FeatureAvailability

        if current_user.permission_level == "viewer":
            return _viewer_write_error("Viewers cannot generate reports")

        if not FeatureAvailability.is_ai_enabled():
            return jsonify(
                {
                    "success": False,
                    "error": "AI features are not currently available",
                }
            ), 400

        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({"success": False, "error": "Case not found"}), 404

        running = is_ai_report_generation_running(case_uuid)
        if running:
            return jsonify(
                {
                    "success": False,
                    "error": "A report generation is already running for this case",
                    "in_progress": True,
                    "task_id": running.get("task_id"),
                }
            ), 409

        data = request.get_json() or {}
        template_id = data.get("template_id")

        template = None
        if template_id:
            template = ReportTemplate.query.get(template_id)

        if not template:
            template = ReportTemplate.get_default_template_for_type(ReportType.DFIR)

        if not template:
            template = ReportTemplate.get_default_template()

        if not template:
            return jsonify({"success": False, "error": "No template found"}), 400

        report_type = template.report_type or ReportType.DFIR
        report_kind = "timeline" if report_type == ReportType.TIMELINE else "dfir"

        # Drop any stale cancel token from a previous run
        from tasks.report_tasks import AI_REPORT_CANCEL_SCOPE
        from utils.async_cancellation import clear_cancellation
        clear_cancellation(AI_REPORT_CANCEL_SCOPE, case_uuid)

        # Seed status before queueing so an immediate status poll sees the run
        set_ai_report_status(
            case_uuid,
            status="running",
            percent=0,
            message="Queued...",
            report_kind=report_kind,
            username=current_user.username,
            filename=None,
            download_url=None,
            error=None,
        )
        task = generate_ai_report_task.delay(
            case_id=case.id,
            case_uuid=case_uuid,
            template_id=template.id,
            negative_finding_ids=data.get("negative_finding_ids", []),
            username=current_user.username,
            report_kind=report_kind,
        )
        set_ai_report_status(case_uuid, task_id=task.id)

        return jsonify(
            {
                "success": True,
                "queued": True,
                "task_id": task.id,
                "report_type": report_kind,
                "status_url": f"/api/reports/generate-status/{case_uuid}",
            }
        )

    except Exception as e:
        logger.error("Error queueing AI report: %s", e)
        return jsonify({"success": False, "error": str(e)}), 500


@ai_bp.route("/reports/generate-timeline/<case_uuid>", methods=["POST"])
@login_required
def generate_timeline_report(case_uuid):
    """Queue an AI-powered timeline report generation for a case."""
    try:
        from tasks.report_tasks import (
            generate_ai_report_task,
            is_ai_report_generation_running,
            set_ai_report_status,
        )
        from utils.feature_availability import FeatureAvailability

        if current_user.permission_level == "viewer":
            return _viewer_write_error("Viewers cannot generate reports")

        if not FeatureAvailability.is_ai_enabled():
            return jsonify(
                {
                    "success": False,
                    "error": "AI features are not currently available",
                }
            ), 400

        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({"success": False, "error": "Case not found"}), 404

        running = is_ai_report_generation_running(case_uuid)
        if running:
            return jsonify(
                {
                    "success": False,
                    "error": "A report generation is already running for this case",
                    "in_progress": True,
                    "task_id": running.get("task_id"),
                }
            ), 409

        data = request.get_json() or {}
        template_id = data.get("template_id")

        # Drop any stale cancel token from a previous run
        from tasks.report_tasks import AI_REPORT_CANCEL_SCOPE
        from utils.async_cancellation import clear_cancellation
        clear_cancellation(AI_REPORT_CANCEL_SCOPE, case_uuid)

        set_ai_report_status(
            case_uuid,
            status="running",
            percent=0,
            message="Queued...",
            report_kind="timeline",
            username=current_user.username,
            filename=None,
            download_url=None,
            error=None,
        )
        task = generate_ai_report_task.delay(
            case_id=case.id,
            case_uuid=case_uuid,
            template_id=template_id,
            negative_finding_ids=[],
            username=current_user.username,
            report_kind="timeline",
        )
        set_ai_report_status(case_uuid, task_id=task.id)

        return jsonify(
            {
                "success": True,
                "queued": True,
                "task_id": task.id,
                "report_type": "timeline",
                "status_url": f"/api/reports/generate-status/{case_uuid}",
            }
        )

    except Exception as e:
        logger.error("Error queueing timeline report: %s", e)
        return jsonify({"success": False, "error": str(e)}), 500
