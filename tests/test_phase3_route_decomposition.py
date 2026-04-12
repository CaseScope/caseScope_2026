import unittest
from pathlib import Path


class Phase3RouteDecompositionTestCase(unittest.TestCase):
    def test_ai_routes_moved_out_of_api_module(self):
        api_source = Path("/opt/casescope/routes/api.py").read_text()
        ai_source = Path("/opt/casescope/routes/ai.py").read_text()

        extracted_routes = [
            "/settings/ai",
            "/settings/ai/test-connection",
            "/settings/ai/models",
            "/settings/ai/fetch-models",
            "/settings/ai/status",
            "/reports/generate-ai/<case_uuid>",
            "/reports/generate-timeline/<case_uuid>",
        ]

        for route in extracted_routes:
            self.assertNotIn(f"@api_bp.route('{route}'", api_source)
            self.assertIn(route, ai_source)

        self.assertIn('ai_bp = Blueprint("ai", __name__, url_prefix="/api")', ai_source)

    def test_admin_settings_routes_moved_out_of_api_module(self):
        api_source = Path("/opt/casescope/routes/api.py").read_text()
        admin_source = Path("/opt/casescope/routes/admin.py").read_text()

        extracted_routes = [
            "/settings/detect-gpu",
            "/settings/workers",
            "/settings/workers/restart",
            "/settings/timezone",
        ]

        for route in extracted_routes:
            self.assertNotIn(f"@api_bp.route('{route}'", api_source)
            self.assertIn(route, admin_source)

        self.assertIn('admin_bp = Blueprint("admin", __name__, url_prefix="/api")', admin_source)
        self.assertIn("def _update_worker_service_concurrency(", admin_source)

    def test_reports_routes_moved_out_of_api_module(self):
        api_source = Path("/opt/casescope/routes/api.py").read_text()
        reports_source = Path("/opt/casescope/routes/reports.py").read_text()

        extracted_routes = [
            "/reports/templates",
            "/reports/templates/active",
            "/reports/templates/scan",
            "/reports/templates/types",
            "/reports/templates/by-type/<report_type>",
            "/reports/templates/<int:template_id>",
            "/reports/templates/<int:template_id>/placeholders",
            "/reports/generate/<case_uuid>",
            "/reports/list/<case_uuid>",
            "/reports/download/<case_uuid>/<filename>",
            "/reports/case/<case_uuid>",
            "/reports/<int:report_id>/notes",
            "/reports/<int:report_id>",
        ]

        for route in extracted_routes:
            self.assertNotIn(f"@api_bp.route('{route}'", api_source)
            self.assertIn(route, reports_source)

        self.assertIn('reports_bp = Blueprint("reports", __name__, url_prefix="/api")', reports_source)

    def test_known_systems_routes_moved_out_of_api_module(self):
        api_source = Path("/opt/casescope/routes/api.py").read_text()
        known_systems_source = Path("/opt/casescope/routes/known_systems.py").read_text()

        extracted_routes = [
            "/known-systems/list/<case_uuid>",
            "/known-systems/discover/<case_uuid>",
            "/known-systems/discover-progress/<case_uuid>",
            "/known-systems/<int:system_id>",
            "/known-systems/<int:system_id>/update",
            "/known-systems/<int:system_id>/add-ip",
            "/known-systems/<int:system_id>/add-share",
            "/known-systems/<int:system_id>/audit",
            "/known-systems/upload/<case_uuid>",
            "/known-systems/download/<case_uuid>",
            "/known-systems/bulk-update",
            "/known-systems/bulk-delete",
        ]

        for route in extracted_routes:
            self.assertNotIn(f"@api_bp.route('{route}'", api_source)
            self.assertIn(route, known_systems_source)

        self.assertIn('known_systems_bp = Blueprint("known_systems", __name__, url_prefix="/api")', known_systems_source)

    def test_known_users_routes_moved_out_of_api_module(self):
        api_source = Path("/opt/casescope/routes/api.py").read_text()
        known_users_source = Path("/opt/casescope/routes/known_users.py").read_text()

        extracted_routes = [
            "/known-users/list/<case_uuid>",
            "/known-users/discover/<case_uuid>",
            "/known-users/discover-progress/<case_uuid>",
            "/known-users/<int:user_id>",
            "/known-users/<int:user_id>/update",
            "/known-users/<int:user_id>/add-alias",
            "/known-users/<int:user_id>/add-email",
            "/known-users/<int:user_id>/audit",
            "/known-users/upload/<case_uuid>",
            "/known-users/download/<case_uuid>",
            "/known-users/bulk-update",
            "/known-users/bulk-delete",
        ]

        for route in extracted_routes:
            self.assertNotIn(f"@api_bp.route('{route}'", api_source)
            self.assertIn(route, known_users_source)

        self.assertIn('known_users_bp = Blueprint("known_users", __name__, url_prefix="/api")', known_users_source)

    def test_route_helpers_hold_shared_license_and_viewer_gates(self):
        helpers_source = Path("/opt/casescope/routes/route_helpers.py").read_text()
        api_source = Path("/opt/casescope/routes/api.py").read_text()
        ai_source = Path("/opt/casescope/routes/ai.py").read_text()
        reports_source = Path("/opt/casescope/routes/reports.py").read_text()

        self.assertIn("def _viewer_write_error(", helpers_source)
        self.assertIn("def _is_license_feature_active(", helpers_source)
        self.assertIn("def _is_threat_intel_license_active(", helpers_source)
        self.assertIn("from routes.route_helpers import (", api_source)
        self.assertIn("from routes.route_helpers import _is_license_feature_active, _viewer_write_error", ai_source)
        self.assertIn("from routes.route_helpers import _viewer_write_error", reports_source)

    def test_app_registers_extracted_ai_blueprint(self):
        app_source = Path("/opt/casescope/app.py").read_text()

        self.assertIn("from routes.ai import ai_bp", app_source)
        self.assertIn("from routes.admin import admin_bp", app_source)
        self.assertIn("from routes.known_systems import known_systems_bp", app_source)
        self.assertIn("from routes.known_users import known_users_bp", app_source)
        self.assertIn("from routes.reports import reports_bp", app_source)
        self.assertIn("app.register_blueprint(admin_bp)", app_source)
        self.assertIn("app.register_blueprint(ai_bp)", app_source)
        self.assertIn("app.register_blueprint(known_systems_bp)", app_source)
        self.assertIn("app.register_blueprint(known_users_bp)", app_source)
        self.assertIn("app.register_blueprint(reports_bp)", app_source)


if __name__ == "__main__":
    unittest.main()
