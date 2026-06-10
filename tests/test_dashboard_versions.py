import os
import unittest
from unittest.mock import MagicMock, patch

os.environ.setdefault("SECRET_KEY", "test-secret")

import routes.dashboard as dashboard_routes
from app import create_app
from routes.dashboard import format_zeek_version
from routes.dashboard import is_newer_version


class DashboardVersionTests(unittest.TestCase):
    def test_format_zeek_version_strips_standard_prefix(self):
        self.assertEqual(format_zeek_version("zeek version 8.0.7"), "8.0.7")

    def test_format_zeek_version_strips_path_prefixed_output(self):
        self.assertEqual(format_zeek_version("/opt/zeek/bin/zeek version 8.0.7"), "8.0.7")
        self.assertEqual(format_zeek_version("/opt/zeek/bin/8.0.7"), "8.0.7")

    def test_format_zeek_version_preserves_unknown_output(self):
        self.assertEqual(format_zeek_version("Connected"), "Connected")
        self.assertEqual(format_zeek_version("Not installed"), "Not installed")

    def test_is_newer_version_compares_semantic_versions(self):
        self.assertTrue(is_newer_version("3.337.7", "3.337.6"))
        self.assertTrue(is_newer_version("3.337.10", "3.337.7"))
        self.assertFalse(is_newer_version("3.337.6", "3.337.6"))
        self.assertFalse(is_newer_version("3.337.5", "3.337.6"))
        self.assertFalse(is_newer_version(None, "3.337.6"))

    def test_github_update_check_reports_newer_casescope_version(self):
        fake_response = MagicMock()
        fake_response.json.return_value = {"current_released_version": "3.337.7"}

        dashboard_routes._casescope_update_cache["checked_at"] = None
        with patch.dict("sys.modules", {"requests": MagicMock(get=MagicMock(return_value=fake_response))}):
            update_info = dashboard_routes.get_casescope_update_info("3.337.6")

        self.assertEqual(update_info["latest_version"], "3.337.7")
        self.assertTrue(update_info["update_available"])

    def test_github_update_check_falls_back_to_version_key(self):
        fake_response = MagicMock()
        fake_response.json.return_value = {"version": "3.337.7"}

        dashboard_routes._casescope_update_cache["checked_at"] = None
        with patch.dict("sys.modules", {"requests": MagicMock(get=MagicMock(return_value=fake_response))}):
            update_info = dashboard_routes.get_casescope_update_info("3.337.6")

        self.assertEqual(update_info["latest_version"], "3.337.7")
        self.assertTrue(update_info["update_available"])

    def test_dashboard_integration_status_stops_when_not_licensed(self):
        connection_check = MagicMock(return_value=True)

        status = dashboard_routes._dashboard_integration_status(
            "OpenCTI",
            licensed=False,
            config_enabled=True,
            setting_enabled=True,
            connection_check=connection_check,
        )

        self.assertEqual(status["status"], "not_licensed")
        self.assertEqual(status["label"], "Not licensed")
        connection_check.assert_not_called()

    def test_dashboard_integration_status_stops_when_not_enabled(self):
        connection_check = MagicMock(return_value=True)

        status = dashboard_routes._dashboard_integration_status(
            "MISP",
            licensed=True,
            config_enabled=True,
            setting_enabled=False,
            connection_check=connection_check,
        )

        self.assertEqual(status["status"], "not_enabled")
        self.assertEqual(status["label"], "Not enabled")
        connection_check.assert_not_called()

    def test_dashboard_integration_status_reports_connection_result(self):
        connected = dashboard_routes._dashboard_integration_status(
            "OpenCTI",
            licensed=True,
            config_enabled=True,
            setting_enabled=True,
            connection_check=MagicMock(return_value=True),
        )
        failed = dashboard_routes._dashboard_integration_status(
            "MISP",
            licensed=True,
            config_enabled=True,
            setting_enabled=True,
            connection_check=MagicMock(return_value=False),
        )

        self.assertEqual(connected["status"], "connected")
        self.assertEqual(connected["label"], "Connected")
        self.assertEqual(failed["status"], "failed")
        self.assertEqual(failed["label"], "Failed")

    def test_dashboard_stats_uses_module_re_import_for_software_versions(self):
        app = create_app(run_startup_bootstrap=False)

        fake_db_result = MagicMock()
        fake_db_result.scalar.return_value = "PostgreSQL 16.13 on x86_64-pc-linux-gnu"
        fake_integrations = {
            "opencti": {"status": "connected", "label": "Connected"},
            "misp": {"status": "not_enabled", "label": "Not enabled"},
        }

        with app.app_context():
            with patch.object(dashboard_routes, "get_folder_size_gb", return_value=0.0), \
                 patch.object(dashboard_routes, "get_software_version", side_effect=[
                     "Hayabusa v3.7.0",
                     "/opt/zeek/bin/zeek version 8.0.7",
                 ]), \
                 patch.object(dashboard_routes.Case.query, "count", return_value=0), \
                 patch.object(dashboard_routes.User.query, "count", return_value=0), \
                 patch.object(dashboard_routes.db.session, "execute", return_value=fake_db_result), \
                 patch.object(dashboard_routes, "get_casescope_update_info", return_value={
                     "latest_version": "3.337.7",
                     "update_available": True,
                 }), \
                 patch.object(dashboard_routes, "get_dashboard_integration_statuses", return_value=fake_integrations), \
                 patch.object(dashboard_routes, "jsonify", side_effect=lambda payload: payload):
                result = dashboard_routes.dashboard_stats.__wrapped__()

        self.assertEqual(result["software"]["hayabusa"], "3.7.0")
        self.assertEqual(result["software"]["zeek"], "8.0.7")
        self.assertEqual(result["software"]["postgresql"], "16.13")
        self.assertTrue(result["updates"]["casescope"]["update_available"])
        self.assertEqual(result["system"]["integrations"], fake_integrations)


if __name__ == "__main__":
    unittest.main()
