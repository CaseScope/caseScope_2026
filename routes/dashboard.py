"""Dashboard API routes."""

import json
import logging
import os
import platform
import re
import subprocess
from datetime import datetime

from flask import Blueprint, jsonify
from flask_login import login_required

from config import Config
from models.case import Case
from models.database import db
from models.user import User
from routes.route_helpers import DEFAULT_ARCHIVE_PATH, DEFAULT_ORIGINALS_PATH

logger = logging.getLogger(__name__)

dashboard_bp = Blueprint("dashboard", __name__, url_prefix="/api")


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
                },
                "cases": {
                    "total_cases": total_cases,
                    "total_events": total_events,
                    "total_users": total_users,
                },
                "software": software,
            }
        )

    except Exception as e:
        return jsonify({"error": str(e)}), 500
