"""Administrative API routes extracted from the monolithic API module."""

import logging
import subprocess

from flask import Blueprint, jsonify, request
from flask_login import current_user, login_required

logger = logging.getLogger(__name__)

admin_bp = Blueprint("admin", __name__, url_prefix="/api")


@admin_bp.route("/settings/detect-gpu", methods=["GET"])
@login_required
def detect_gpu():
    """Detect GPU(s), drivers, and Ollama installation."""
    try:
        result = {
            "success": True,
            "gpus": [],
            "recommended_gpu": None,
            "drivers": [],
            "ollama": {
                "installed": False,
                "version": None,
                "models": [],
            },
        }

        cuda_version = None
        try:
            cuda_check = subprocess.run(["nvidia-smi"], capture_output=True, text=True, timeout=10)
            if cuda_check.returncode == 0:
                import re

                cuda_match = re.search(r"CUDA Version:\s*(\d+\.\d+)", cuda_check.stdout)
                if cuda_match:
                    cuda_version = cuda_match.group(1)

            nvidia_output = subprocess.run(
                [
                    "nvidia-smi",
                    "--query-gpu=index,name,memory.total,memory.free,driver_version",
                    "--format=csv,noheader,nounits",
                ],
                capture_output=True,
                text=True,
                timeout=10,
            )

            if nvidia_output.returncode == 0 and nvidia_output.stdout.strip():
                for line in nvidia_output.stdout.strip().split("\n"):
                    parts = [p.strip() for p in line.split(",")]
                    if len(parts) >= 5:
                        gpu = {
                            "index": int(parts[0]),
                            "name": parts[1],
                            "vram_total_mb": int(float(parts[2])),
                            "vram_free_mb": int(float(parts[3])),
                            "driver_version": parts[4],
                            "cuda_version": cuda_version,
                            "type": "NVIDIA",
                        }
                        result["gpus"].append(gpu)

                        driver_info = f"NVIDIA Driver {parts[4]}"
                        if driver_info not in [d["name"] for d in result["drivers"]]:
                            result["drivers"].append(
                                {
                                    "name": driver_info,
                                    "cuda": f"CUDA {cuda_version}" if cuda_version else None,
                                }
                            )
        except FileNotFoundError:
            pass
        except Exception:
            pass

        has_nvidia_from_smi = any(g["type"] == "NVIDIA" and g["vram_total_mb"] for g in result["gpus"])

        try:
            lspci_output = subprocess.run(
                ["lspci", "-v"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if lspci_output.returncode == 0:
                import re

                vga_pattern = re.compile(r"(VGA compatible controller|3D controller):\s*(.+)", re.IGNORECASE)
                for match in vga_pattern.finditer(lspci_output.stdout):
                    gpu_name = match.group(2).strip()

                    if "NVIDIA" in gpu_name.upper():
                        gpu_type = "NVIDIA"
                        if has_nvidia_from_smi:
                            continue
                    elif "AMD" in gpu_name.upper() or "RADEON" in gpu_name.upper():
                        gpu_type = "AMD"
                    elif "INTEL" in gpu_name.upper():
                        gpu_type = "Intel"
                    else:
                        gpu_type = "Other"

                    already_found = any(g["type"] == gpu_type for g in result["gpus"])

                    if not already_found:
                        result["gpus"].append(
                            {
                                "index": len(result["gpus"]),
                                "name": gpu_name,
                                "vram_total_mb": None,
                                "vram_free_mb": None,
                                "driver_version": None,
                                "cuda_version": None,
                                "type": gpu_type,
                            }
                        )
        except Exception:
            pass

        has_nvidia = any(g["type"] == "NVIDIA" for g in result["gpus"])
        if has_nvidia and not result["drivers"]:
            try:
                fallback_cuda = None
                cuda_check = subprocess.run(["nvidia-smi"], capture_output=True, text=True, timeout=10)
                if cuda_check.returncode == 0:
                    import re

                    cuda_match = re.search(r"CUDA Version:\s*(\d+\.\d+)", cuda_check.stdout)
                    if cuda_match:
                        fallback_cuda = cuda_match.group(1)

                driver_check = subprocess.run(
                    ["nvidia-smi", "--query-gpu=driver_version", "--format=csv,noheader,nounits"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                if driver_check.returncode == 0 and driver_check.stdout.strip():
                    driver_ver = driver_check.stdout.strip().split("\n")[0].strip()
                    result["drivers"].append(
                        {
                            "name": f"NVIDIA Driver {driver_ver}",
                            "cuda": f"CUDA {fallback_cuda}" if fallback_cuda else None,
                        }
                    )
                    for gpu in result["gpus"]:
                        if gpu["type"] == "NVIDIA":
                            gpu["driver_version"] = driver_ver
                            gpu["cuda_version"] = fallback_cuda
            except Exception:
                pass

        for gpu in result["gpus"]:
            if gpu["type"] == "NVIDIA" and gpu["vram_total_mb"] is None:
                try:
                    vram_check = subprocess.run(
                        ["nvidia-smi", "--query-gpu=memory.total,memory.free", "--format=csv,noheader,nounits"],
                        capture_output=True,
                        text=True,
                        timeout=10,
                    )
                    if vram_check.returncode == 0 and vram_check.stdout.strip():
                        parts = [p.strip() for p in vram_check.stdout.strip().split("\n")[0].split(",")]
                        if len(parts) >= 2:
                            try:
                                gpu["vram_total_mb"] = int(float(parts[0]))
                                gpu["vram_free_mb"] = int(float(parts[1]))
                            except ValueError:
                                pass
                except Exception:
                    pass

        if result["gpus"]:
            nvidia_gpus = [g for g in result["gpus"] if g["type"] == "NVIDIA"]
            if nvidia_gpus:
                nvidia_gpus.sort(key=lambda x: x["vram_total_mb"] or 0, reverse=True)
                result["recommended_gpu"] = nvidia_gpus[0]
            else:
                result["recommended_gpu"] = result["gpus"][0]

        try:
            ollama_version = subprocess.run(
                ["ollama", "--version"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if ollama_version.returncode == 0:
                result["ollama"]["installed"] = True
                version_text = ollama_version.stdout.strip() or ollama_version.stderr.strip()
                if "version" in version_text.lower():
                    import re

                    version_match = re.search(r"(\d+\.\d+\.\d+)", version_text)
                    if version_match:
                        result["ollama"]["version"] = version_match.group(1)
                    else:
                        result["ollama"]["version"] = version_text
                else:
                    result["ollama"]["version"] = version_text

                try:
                    ollama_list = subprocess.run(
                        ["ollama", "list"],
                        capture_output=True,
                        text=True,
                        timeout=10,
                    )
                    if ollama_list.returncode == 0 and ollama_list.stdout.strip():
                        lines = ollama_list.stdout.strip().split("\n")
                        for line in lines[1:]:
                            parts = line.split()
                            if len(parts) >= 2:
                                model_name = parts[0]
                                model_size = parts[2] if len(parts) >= 3 else "Unknown"
                                result["ollama"]["models"].append(
                                    {
                                        "name": model_name,
                                        "size": model_size,
                                    }
                                )
                except Exception:
                    pass
        except FileNotFoundError:
            result["ollama"]["installed"] = False
        except Exception:
            pass

        from models.system_settings import AI_FUNCTION_DESCRIPTIONS, SettingKeys, SystemSettings, get_ai_model_config

        recommended_vram = None
        if result["recommended_gpu"] and result["recommended_gpu"].get("vram_total_mb"):
            recommended_vram = result["recommended_gpu"]["vram_total_mb"]

        model_config = get_ai_model_config(recommended_vram)
        if model_config:
            tier = "16gb" if recommended_vram and recommended_vram >= 14000 else "8gb"
            result["model_config"] = {
                "tier": tier,
                "functions": {},
            }
            for func_key, model_name in model_config.items():
                result["model_config"]["functions"][func_key] = {
                    "model": model_name,
                    "description": AI_FUNCTION_DESCRIPTIONS.get(func_key, func_key),
                }

            SystemSettings.set(
                SettingKeys.AI_GPU_TIER,
                tier,
                value_type="string",
                updated_by="system",
            )
        else:
            result["model_config"] = None

        return jsonify(result)

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@admin_bp.route("/settings/workers", methods=["GET"])
@login_required
def get_worker_settings():
    """Get current worker settings and system limits."""
    try:
        from models.system_settings import WORKER_OPTIONS, get_worker_concurrency, get_worker_limits, get_worker_override

        limits = get_worker_limits()
        current_concurrency = get_worker_concurrency()
        override_enabled = get_worker_override()

        return jsonify(
            {
                "success": True,
                "settings": {
                    "concurrency": current_concurrency,
                    "override_recommended": override_enabled,
                },
                "limits": limits,
                "options": WORKER_OPTIONS,
            }
        )

    except Exception as e:
        logger.exception("Error getting worker settings")
        return jsonify({"success": False, "error": str(e)}), 500


@admin_bp.route("/settings/workers", methods=["POST"])
@login_required
def set_worker_settings():
    """Set worker concurrency settings."""
    try:
        if not current_user.is_administrator:
            return jsonify({"success": False, "error": "Administrator access required"}), 403

        from models.system_settings import SettingKeys, SystemSettings, WORKER_OPTIONS, get_worker_limits

        data = request.get_json()
        concurrency = data.get("concurrency")
        override_recommended = data.get("override_recommended", False)

        if concurrency is None:
            return jsonify({"success": False, "error": "Concurrency value required"}), 400

        try:
            concurrency = int(concurrency)
        except (ValueError, TypeError):
            return jsonify({"success": False, "error": "Invalid concurrency value"}), 400

        limits = get_worker_limits()

        if concurrency not in WORKER_OPTIONS:
            return jsonify(
                {
                    "success": False,
                    "error": f"Invalid concurrency value. Must be one of: {WORKER_OPTIONS}",
                }
            ), 400

        if override_recommended:
            max_allowed = limits["absolute_max"]
        else:
            max_allowed = limits["recommended_max"]

        original_concurrency = concurrency
        if concurrency > max_allowed:
            concurrency = max_allowed

        SystemSettings.set(
            SettingKeys.WORKER_OVERRIDE_RECOMMENDED,
            override_recommended,
            value_type="bool",
            updated_by=current_user.username,
        )

        SystemSettings.set(
            SettingKeys.WORKER_CONCURRENCY,
            concurrency,
            value_type="int",
            updated_by=current_user.username,
        )

        update_result = _update_worker_service_concurrency(concurrency)

        response = {
            "success": True,
            "concurrency": concurrency,
            "override_recommended": override_recommended,
            "service_updated": update_result["success"],
            "requires_restart": True,
        }

        if original_concurrency != concurrency:
            response["clamped"] = True
            response["original_value"] = original_concurrency
            response["message"] = (
                f"Concurrency clamped from {original_concurrency} to {concurrency} "
                f"(max allowed: {max_allowed})"
            )

        if not update_result["success"]:
            response["service_error"] = update_result.get("error", "Unknown error")

        return jsonify(response)

    except Exception as e:
        logger.exception("Error setting worker settings")
        return jsonify({"success": False, "error": str(e)}), 500


@admin_bp.route("/settings/workers/restart", methods=["POST"])
@login_required
def restart_worker_service():
    """Restart the Celery worker service to apply new settings."""
    try:
        if not current_user.is_administrator:
            return jsonify({"success": False, "error": "Administrator access required"}), 403

        result = subprocess.run(
            ["sudo", "/usr/bin/systemctl", "restart", "casescope-workers"],
            capture_output=True,
            text=True,
            timeout=30,
        )

        if result.returncode == 0:
            return jsonify(
                {
                    "success": True,
                    "message": "Worker service restarted successfully",
                }
            )

        return jsonify(
            {
                "success": False,
                "error": f"Failed to restart service: {result.stderr}",
            }
        ), 500

    except subprocess.TimeoutExpired:
        return jsonify(
            {
                "success": False,
                "error": "Service restart timed out",
            }
        ), 500
    except Exception as e:
        logger.exception("Error restarting worker service")
        return jsonify({"success": False, "error": str(e)}), 500


@admin_bp.route("/settings/timezone", methods=["GET"])
@login_required
def get_default_timezone():
    """Get the default timezone for new cases."""
    try:
        from models.system_settings import SettingKeys, SystemSettings

        timezone = SystemSettings.get(SettingKeys.DEFAULT_TIMEZONE, "America/New_York")

        return jsonify(
            {
                "success": True,
                "timezone": timezone,
            }
        )
    except Exception as e:
        logger.exception("Error getting default timezone")
        return jsonify({"success": False, "error": str(e)}), 500


@admin_bp.route("/settings/timezone", methods=["POST"])
@login_required
def set_default_timezone():
    """Set the default timezone for new cases."""
    try:
        if not current_user.is_administrator:
            return jsonify({"success": False, "error": "Administrator access required"}), 403

        from models.system_settings import SettingKeys, SystemSettings
        from utils.timezone import is_valid_timezone

        data = request.get_json()
        timezone = data.get("timezone", "UTC")

        if not is_valid_timezone(timezone):
            return jsonify({"success": False, "error": "Invalid timezone"}), 400

        SystemSettings.set(
            SettingKeys.DEFAULT_TIMEZONE,
            timezone,
            value_type="string",
            updated_by=current_user.username,
        )

        return jsonify(
            {
                "success": True,
                "timezone": timezone,
                "message": "Default timezone saved successfully",
            }
        )
    except Exception as e:
        logger.exception("Error setting default timezone")
        return jsonify({"success": False, "error": str(e)}), 500


def _update_worker_service_concurrency(concurrency: int) -> dict:
    """Update the systemd service file with a new concurrency value."""
    try:
        result = subprocess.run(
            ["sudo", "/opt/casescope/bin/update_worker_concurrency.sh", str(concurrency)],
            capture_output=True,
            text=True,
            timeout=10,
        )

        if result.returncode != 0:
            return {"success": False, "error": f"Failed to update service: {result.stderr or result.stdout}"}

        logger.info("Updated worker concurrency to %s", concurrency)
        return {"success": True}

    except FileNotFoundError:
        return {"success": False, "error": "Helper script not found"}
    except Exception as e:
        logger.exception("Error updating worker service")
        return {"success": False, "error": str(e)}
