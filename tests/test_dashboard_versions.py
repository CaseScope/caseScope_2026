import os
import unittest
from unittest.mock import MagicMock, patch

os.environ.setdefault("SECRET_KEY", "test-secret")

import routes.dashboard as dashboard_routes
from app import create_app
from routes.dashboard import format_zeek_version


class DashboardVersionTests(unittest.TestCase):
    def test_format_zeek_version_strips_standard_prefix(self):
        self.assertEqual(format_zeek_version("zeek version 8.0.7"), "8.0.7")

    def test_format_zeek_version_strips_path_prefixed_output(self):
        self.assertEqual(format_zeek_version("/opt/zeek/bin/zeek version 8.0.7"), "8.0.7")
        self.assertEqual(format_zeek_version("/opt/zeek/bin/8.0.7"), "8.0.7")

    def test_format_zeek_version_preserves_unknown_output(self):
        self.assertEqual(format_zeek_version("Connected"), "Connected")
        self.assertEqual(format_zeek_version("Not installed"), "Not installed")

    def test_dashboard_stats_uses_module_re_import_for_software_versions(self):
        app = create_app(run_startup_bootstrap=False)

        fake_db_result = MagicMock()
        fake_db_result.scalar.return_value = "PostgreSQL 16.13 on x86_64-pc-linux-gnu"

        with app.app_context():
            with patch.object(dashboard_routes, "get_folder_size_gb", return_value=0.0), \
                 patch.object(dashboard_routes, "get_software_version", side_effect=[
                     "Hayabusa v3.7.0",
                     "/opt/zeek/bin/zeek version 8.0.7",
                 ]), \
                 patch.object(dashboard_routes.Case.query, "count", return_value=0), \
                 patch.object(dashboard_routes.User.query, "count", return_value=0), \
                 patch.object(dashboard_routes.db.session, "execute", return_value=fake_db_result), \
                 patch.object(dashboard_routes, "jsonify", side_effect=lambda payload: payload):
                result = dashboard_routes.dashboard_stats.__wrapped__()

        self.assertEqual(result["software"]["hayabusa"], "3.7.0")
        self.assertEqual(result["software"]["zeek"], "8.0.7")
        self.assertEqual(result["software"]["postgresql"], "16.13")


if __name__ == "__main__":
    unittest.main()
