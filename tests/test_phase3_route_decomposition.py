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

    def test_route_helpers_hold_shared_license_and_viewer_gates(self):
        helpers_source = Path("/opt/casescope/routes/route_helpers.py").read_text()
        api_source = Path("/opt/casescope/routes/api.py").read_text()
        ai_source = Path("/opt/casescope/routes/ai.py").read_text()

        self.assertIn("def _viewer_write_error(", helpers_source)
        self.assertIn("def _is_license_feature_active(", helpers_source)
        self.assertIn("def _is_threat_intel_license_active(", helpers_source)
        self.assertIn("from routes.route_helpers import (", api_source)
        self.assertIn("from routes.route_helpers import _is_license_feature_active, _viewer_write_error", ai_source)

    def test_app_registers_extracted_ai_blueprint(self):
        app_source = Path("/opt/casescope/app.py").read_text()

        self.assertIn("from routes.ai import ai_bp", app_source)
        self.assertIn("from routes.admin import admin_bp", app_source)
        self.assertIn("app.register_blueprint(admin_bp)", app_source)
        self.assertIn("app.register_blueprint(ai_bp)", app_source)


if __name__ == "__main__":
    unittest.main()
