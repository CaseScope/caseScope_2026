"""Dashboard API routes."""

import json
import logging
import os
import platform
import re
import subprocess
from datetime import datetime, timedelta

from flask import Blueprint, jsonify
from flask_login import login_required

from config import Config
from models.case import Case
from models.database import db
from models.user import User
from routes.route_helpers import DEFAULT_ARCHIVE_PATH, DEFAULT_ORIGINALS_PATH

logger = logging.getLogger(__name__)

dashboard_bp = Blueprint("dashboard", __name__, url_prefix="/api")

CASESCOPE_LATEST_VERSION_URL = "https://raw.githubusercontent.com/CaseScope/caseScope_2026/main/release.json"
CASESCOPE_UPDATE_CHECK_TTL = timedelta(minutes=15)
_casescope_update_cache = {
    "checked_at": None,
    "info": {
        "latest_version": None,
        "update_available": False,
    },
}


def get_folder_size_gb(path):
    """Get folder size in GB."""
    try:
        if not os.path.exists(path):
            return 0.0
        total = 0
        for dirpath, _, filenames in os.walk(path):
            for filename in filenames:
                file_path = os.path.join(dirpath, filename)
                try:
                    total += os.path.getsize(file_path)
                except (OSError, FileNotFoundError):
                    pass
        return round(total / (1024**3), 2)
    except Exception:
        return 0.0


def get_software_version(command):
    """Get software version from command."""
    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=5,
        )
        version = result.stdout.strip().split("\n")[0] if result.stdout else "Not installed"
        return version if version else "Not installed"
    except Exception:
        return "Not installed"


def format_zeek_version(raw_version):
    """Extract the Zeek semantic version from command output."""
    if not raw_version or raw_version == "Not installed":
        return "Not installed"

    match = re.search(r"(\d+\.\d+\.\d+)", raw_version)
    return match.group(1) if match else raw_version.strip()


def parse_version_tuple(version):
    """Convert a dotted version string into a comparable tuple."""
    if not version:
        return None

    parts = re.findall(r"\d+", str(version))
    if not parts:
        return None

    return tuple(int(part) for part in parts)


def is_newer_version(latest_version, current_version):
    """Return True when latest_version is newer than current_version."""
    latest = parse_version_tuple(latest_version)
    current = parse_version_tuple(current_version)
    if latest is None or current is None:
        return False

    max_length = max(len(latest), len(current))
    latest += (0,) * (max_length - len(latest))
    current += (0,) * (max_length - len(current))
    return latest > current


def get_casescope_update_info(current_version):
    """Check GitHub for the latest CaseScope version with a short-lived cache."""
    now = datetime.utcnow()
    cached_at = _casescope_update_cache["checked_at"]
    if cached_at and now - cached_at < CASESCOPE_UPDATE_CHECK_TTL:
        return _casescope_update_cache["info"]

    info = {
        "latest_version": None,
        "update_available": False,
    }

    try:
        import requests

        response = requests.get(CASESCOPE_LATEST_VERSION_URL, timeout=3)
        response.raise_for_status()
        release_info = response.json()
        latest_version = release_info.get("current_released_version") or release_info.get("version")
        info = {
            "latest_version": latest_version,
            "update_available": is_newer_version(latest_version, current_version),
        }
    except Exception as e:
        logger.debug("Unable to check GitHub for latest CaseScope version: %s", e)

    _casescope_update_cache["checked_at"] = now
    _casescope_update_cache["info"] = info
    return info


def _dashboard_integration_status(name, licensed, config_enabled, setting_enabled, connection_check):
    """Return dashboard-ready integration status after license and enabled gates."""
    status = {
        "name": name,
        "licensed": bool(licensed),
        "enabled": False,
        "status": "not_licensed",
        "label": "Not licensed",
        "badge_class": "not-activated",
    }

    if not licensed:
        return status

    if not (config_enabled and setting_enabled):
        status.update(
            {
                "status": "not_enabled",
                "label": "Not enabled",
                "badge_class": "not-activated",
            }
        )
        return status

    status["enabled"] = True
    try:
        connected = bool(connection_check())
    except Exception as exc:
        logger.debug("%s dashboard connection check failed: %s", name, exc)
        connected = False

    if connected:
        status.update(
            {
                "status": "connected",
                "label": "Connected",
                "badge_class": "activated",
            }
        )
    else:
        status.update(
            {
                "status": "failed",
                "label": "Failed",
                "badge_class": "expired",
            }
        )

    return status


def _test_opencti_dashboard_connection():
    """Run the saved OpenCTI connection test used by the settings page."""
    from models.system_settings import SettingKeys, SystemSettings, get_opencti_api_key
    from utils.opencti import OpenCTIClient

    url = SystemSettings.get(SettingKeys.OPENCTI_URL, "")
    api_key = get_opencti_api_key(log_errors=True)
    ssl_verify = SystemSettings.get(SettingKeys.OPENCTI_SSL_VERIFY, False)

    if not url or not api_key:
        return False

    client = OpenCTIClient(url, api_key, ssl_verify)
    if client.init_error:
        return False

    return client.ping()


def _test_misp_dashboard_connection():
    """Run the saved MISP connection test used by the settings page."""
    from models.system_settings import SettingKeys, SystemSettings, get_misp_api_key
    from utils.misp import MISPClient

    url = SystemSettings.get(SettingKeys.MISP_URL, "")
    api_key = get_misp_api_key(log_errors=True)
    ssl_verify = SystemSettings.get(SettingKeys.MISP_SSL_VERIFY, False)

    if not url or not api_key:
        return False

    client = MISPClient(url, api_key, ssl_verify)
    if client.init_error:
        return False

    return client.ping()


def get_dashboard_integration_statuses(licensed_features=None):
    """Return OpenCTI and MISP status rows for the system dashboard."""
    from models.system_settings import SettingKeys, SystemSettings
    from utils.licensing.license_manager import LicenseManager

    if licensed_features is None:
        licensed = LicenseManager.is_feature_activated("opencti")
    else:
        licensed = bool(licensed_features.get("opencti", False))

    return {
        "opencti": _dashboard_integration_status(
            "OpenCTI",
            licensed=licensed,
            config_enabled=getattr(Config, "OPENCTI_ENABLED", False),
            setting_enabled=SystemSettings.get(SettingKeys.OPENCTI_ENABLED, False),
            connection_check=_test_opencti_dashboard_connection,
        ),
        "misp": _dashboard_integration_status(
            "MISP",
            licensed=licensed,
            config_enabled=getattr(Config, "MISP_ENABLED", False),
            setting_enabled=SystemSettings.get(SettingKeys.MISP_ENABLED, False),
            connection_check=_test_misp_dashboard_connection,
        ),
    }


@dashboard_bp.route("/dashboard/stats")
@login_required
def dashboard_stats():
    """Get dashboard statistics."""
    try:
        import psutil
        from importlib.metadata import PackageNotFoundError, version as pkg_version
        from models.system_settings import SettingKeys, SystemSettings

        hostname = platform.node()
        os_info = f"{platform.system()} {platform.release()}"

        cpu_percent = psutil.cpu_percent(interval=0.1)
        cpu_cores = psutil.cpu_count()

        ram = psutil.virtual_memory()
        ram_total_gb = round(ram.total / (1024**3), 2)
        ram_used_gb = round(ram.used / (1024**3), 2)

        disks = []
        for partition in psutil.disk_partitions():
            if partition.device.startswith("/dev/") and not partition.mountpoint.startswith("/snap"):
                try:
                    usage = psutil.disk_usage(partition.mountpoint)
                    disks.append(
                        {
                            "device": partition.device,
                            "mountpoint": partition.mountpoint,
                            "total_gb": round(usage.total / (1024**3), 2),
                            "used_gb": round(usage.used / (1024**3), 2),
                            "percent": usage.percent,
                        }
                    )
                except PermissionError:
                    pass

        live_gb = get_folder_size_gb(Config.STORAGE_FOLDER)
        originals_gb = get_folder_size_gb(SystemSettings.get(SettingKeys.ORIGINALS_PATH, DEFAULT_ORIGINALS_PATH))
        archive_gb = get_folder_size_gb(SystemSettings.get(SettingKeys.ARCHIVE_PATH, DEFAULT_ARCHIVE_PATH))

        casescope_version = "Unknown"
        try:
            with open(os.path.join(Config.BASE_DIR, "version.json"), "r") as handle:
                casescope_version = json.load(handle).get("version", "Unknown")
        except Exception as e:
            logger.debug("Unable to read version.json for dashboard stats: %s", e)

        def safe_pkg_version(package_name):
            try:
                return pkg_version(package_name)
            except PackageNotFoundError:
                return "Not installed"

        hayabusa_ver = get_software_version("/opt/casescope/bin/hayabusa help 2>/dev/null | head -1")
        if hayabusa_ver and hayabusa_ver != "Not installed":
            match = re.search(r"v(\d+\.\d+\.\d+)", hayabusa_ver)
            hayabusa_ver = match.group(1) if match else "Not installed"

        zeek_ver = format_zeek_version(get_software_version("/opt/zeek/bin/zeek --version"))

        clickhouse_ver = "Not available"
        try:
            import clickhouse_connect

            ch_client = clickhouse_connect.get_client(
                host=Config.CLICKHOUSE_HOST,
                port=Config.CLICKHOUSE_PORT,
                username=Config.CLICKHOUSE_USER,
                password=Config.CLICKHOUSE_PASSWORD,
                database=Config.CLICKHOUSE_DATABASE,
            )
            result = ch_client.query("SELECT version()")
            clickhouse_ver = result.result_rows[0][0]
        except Exception as e:
            logger.debug("Unable to query ClickHouse version for dashboard stats: %s", e)

        postgres_ver = "Not available"
        try:
            result = db.session.execute(db.text("SELECT version()"))
            pg_version_str = result.scalar()
            if pg_version_str:
                match = re.search(r"PostgreSQL (\d+\.\d+(?:\.\d+)?)", pg_version_str)
                postgres_ver = match.group(1) if match else pg_version_str.split()[1]
        except Exception as e:
            logger.debug("Unable to query PostgreSQL version for dashboard stats: %s", e)

        qdrant_ver = "Not available"
        try:
            from qdrant_client import QdrantClient

            qdrant = QdrantClient(host=Config.QDRANT_HOST, port=Config.QDRANT_PORT, timeout=2)
            qdrant.get_collections()
            try:
                import requests

                resp = requests.get(f"http://{Config.QDRANT_HOST}:{Config.QDRANT_PORT}/", timeout=2)
                if resp.ok:
                    qdrant_ver = resp.json().get("version", "Connected")
            except Exception as e:
                logger.debug("Unable to fetch Qdrant version details for dashboard stats: %s", e)
                qdrant_ver = "Connected"
        except Exception as e:
            logger.debug("Unable to query Qdrant version for dashboard stats: %s", e)

        software = {
            "casescope": casescope_version,
            "python": platform.python_version(),
            "flask": safe_pkg_version("flask"),
            "celery": safe_pkg_version("celery"),
            "gunicorn": safe_pkg_version("gunicorn"),
            "postgresql": postgres_ver,
            "clickhouse": clickhouse_ver,
            "redis": safe_pkg_version("redis"),
            "qdrant": qdrant_ver,
            "hayabusa": hayabusa_ver,
            "zeek": zeek_ver,
            "volatility3": safe_pkg_version("volatility3"),
            "dissect": safe_pkg_version("dissect.util"),
            "sqlalchemy": safe_pkg_version("sqlalchemy"),
        }
        updates = {
            "casescope": get_casescope_update_info(casescope_version),
        }

        total_cases = Case.query.count()
        total_users = User.query.count()

        total_events = 0
        try:
            from utils.clickhouse import get_client

            ch_client = get_client()
            result = ch_client.query("SELECT count() FROM events")
            total_events = result.result_rows[0][0] if result.result_rows else 0
        except Exception as e:
            logger.debug("Unable to query ClickHouse event count for dashboard stats: %s", e)

        activation_info = {
            "status": "not_activated",
            "status_label": "Not Activated",
            "customer_name": None,
            "expires_at": None,
            "days_remaining": None,
            "grace_days_remaining": None,
            "features": {"ai": False, "opencti": False},
        }
        try:
            from utils.licensing.license_manager import LicenseManager

            info = LicenseManager.get_activation_info()
            activation_info = {
                "status": info.get("status", "not_activated"),
                "status_label": info.get("status_label", "Unknown"),
                "customer_name": info.get("license", {}).get("customer_name"),
                "expires_at": info.get("expiry", {}).get("expires_at"),
                "days_remaining": info.get("expiry", {}).get("days_remaining"),
                "grace_days_remaining": info.get("server", {}).get("grace_days_remaining"),
                "is_expiring_soon": info.get("expiry", {}).get("is_expiring_soon", False),
                "features": info.get("features", {"ai": False, "opencti": False}),
            }
        except Exception:
            pass

        integration_statuses = {
            "opencti": {
                "name": "OpenCTI",
                "licensed": False,
                "enabled": False,
                "status": "failed",
                "label": "Failed",
                "badge_class": "expired",
            },
            "misp": {
                "name": "MISP",
                "licensed": False,
                "enabled": False,
                "status": "failed",
                "label": "Failed",
                "badge_class": "expired",
            },
        }
        try:
            integration_statuses = get_dashboard_integration_statuses(activation_info.get("features", {}))
        except Exception as e:
            logger.debug("Unable to load dashboard integration statuses: %s", e)

        return jsonify(
            {
                "timestamp": datetime.utcnow().isoformat(),
                "system": {
                    "hostname": hostname,
                    "os": os_info,
                    "cpu": {"usage_percent": cpu_percent, "cores": cpu_cores},
                    "ram": {
                        "total_gb": ram_total_gb,
                        "used_gb": ram_used_gb,
                        "percent": ram.percent,
                    },
                    "disks": disks,
                    "case_storage": {
                        "live_gb": live_gb,
                        "originals_gb": originals_gb,
                        "archive_gb": archive_gb,
                    },
                    "activation": activation_info,
                    "integrations": integration_statuses,
                },
                "cases": {
                    "total_cases": total_cases,
                    "total_events": total_events,
                    "total_users": total_users,
                },
                "software": software,
                "updates": updates,
            }
        )

    except Exception as e:
        return jsonify({"error": str(e)}), 500
