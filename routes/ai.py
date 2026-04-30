"""AI-specific API routes extracted from the monolithic API module."""

import logging
import os
from datetime import datetime

from flask import Blueprint, jsonify, request
from flask_login import current_user, login_required

from models.case import Case
from models.database import db
from routes.route_helpers import _is_license_feature_active, _viewer_write_error

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
                privacy_obfuscation_level=data.get("privacy_obfuscation_level", ""),
                privacy_off_ack=data.get("privacy_off_ack"),
                updated_by=current_user.username,
            )
            invalidate_provider_cache()

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


@ai_bp.route("/reports/generate-ai/<case_uuid>", methods=["POST"])
@login_required
def generate_ai_report(case_uuid):
    """Generate an AI-powered report for a case based on template type."""
    try:
        from models.report_template import ReportTemplate, ReportType
        from utils.ai_report_generator import AIReportGenerator
        from utils.ai_timeline_generator import AITimelineGenerator
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

        if report_type == ReportType.TIMELINE:
            generator = AITimelineGenerator(case.id, template.id)
        else:
            generator = AIReportGenerator(case.id, template.id)

        result = generator.generate_report()

        if result.get("success"):
            from models.case_report import CaseReport

            ai_model = result.get("ai_model", "")
            try:
                output_path = result["output_path"]
                stat = os.stat(output_path)
                report_record = CaseReport(
                    case_id=case.id,
                    filename=result["filename"],
                    file_path=output_path,
                    file_size=stat.st_size,
                    report_type=CaseReport.extract_report_type(result["filename"]),
                    ai_model=ai_model,
                    file_created_at=datetime.fromtimestamp(stat.st_mtime),
                    created_by=current_user.username,
                )
                db.session.add(report_record)
                db.session.commit()
            except Exception as e:
                logger.warning("Could not create report record: %s", e)
                db.session.rollback()

            response = {
                "success": True,
                "filename": result["filename"],
                "output_path": result["output_path"],
                "download_url": f"/api/reports/download/{case_uuid}/{result['filename']}",
                "sections": result.get("sections", []),
                "report_type": report_type,
                "ai_model": ai_model,
            }
            if "stats" in result:
                response["stats"] = result["stats"]
            return jsonify(response)

        return jsonify(
            {
                "success": False,
                "error": result.get("error", "Report generation failed"),
            }
        ), 500

    except Exception as e:
        logger.error("Error generating AI report: %s", e)
        import traceback

        traceback.print_exc()
        return jsonify({"success": False, "error": str(e)}), 500


@ai_bp.route("/reports/generate-timeline/<case_uuid>", methods=["POST"])
@login_required
def generate_timeline_report(case_uuid):
    """Generate an AI-powered timeline report for a case."""
    try:
        from utils.ai_timeline_generator import AITimelineGenerator
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

        data = request.get_json() or {}
        template_id = data.get("template_id")

        generator = AITimelineGenerator(case.id, template_id)
        result = generator.generate_report()

        if result.get("success"):
            from models.case_report import CaseReport

            ai_model = result.get("ai_model", "")
            try:
                output_path = result["output_path"]
                stat = os.stat(output_path)
                report_record = CaseReport(
                    case_id=case.id,
                    filename=result["filename"],
                    file_path=output_path,
                    file_size=stat.st_size,
                    report_type=CaseReport.extract_report_type(result["filename"]),
                    ai_model=ai_model,
                    file_created_at=datetime.fromtimestamp(stat.st_mtime),
                    created_by=current_user.username,
                )
                db.session.add(report_record)
                db.session.commit()
            except Exception as e:
                logger.warning("Could not create report record: %s", e)
                db.session.rollback()

            return jsonify(
                {
                    "success": True,
                    "filename": result["filename"],
                    "output_path": result["output_path"],
                    "download_url": f"/api/reports/download/{case_uuid}/{result['filename']}",
                    "sections": result["sections"],
                    "stats": result.get("stats", {}),
                    "ai_model": ai_model,
                }
            )

        return jsonify(
            {
                "success": False,
                "error": result.get("error", "Timeline report generation failed"),
            }
        ), 400

    except Exception as e:
        logger.error("Error generating timeline report: %s", e)
        import traceback

        traceback.print_exc()
        return jsonify({"success": False, "error": str(e)}), 500
