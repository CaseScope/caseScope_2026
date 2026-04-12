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

    def test_enrichment_routes_moved_out_of_api_module(self):
        api_source = Path("/opt/casescope/routes/api.py").read_text()
        enrichment_source = Path("/opt/casescope/routes/enrichment.py").read_text()

        extracted_routes = [
            "/settings/opencti",
            "/settings/opencti/test",
            "/opencti/status",
            "/opencti/connectors",
            "/settings/misp",
            "/settings/misp/test",
            "/misp/status",
        ]

        for route in extracted_routes:
            self.assertNotIn(f"@api_bp.route('{route}'", api_source)
            self.assertIn(route, enrichment_source)

        self.assertIn('enrichment_bp = Blueprint("enrichment", __name__, url_prefix="/api")', enrichment_source)

    def test_archive_routes_moved_out_of_api_module(self):
        api_source = Path("/opt/casescope/routes/api.py").read_text()
        archive_source = Path("/opt/casescope/routes/archive.py").read_text()

        extracted_routes = [
            "/case/<case_uuid>/archive",
            "/case/<case_uuid>/archive/status",
            "/case/<case_uuid>/archive/info",
            "/case/<case_uuid>/restore",
            "/case/<case_uuid>/restore/status",
            "/case/<case_uuid>/storage/size",
            "/archive/jobs/active",
        ]

        for route in extracted_routes:
            self.assertNotIn(f"@api_bp.route('{route}'", api_source)
            self.assertIn(route, archive_source)

        self.assertIn('archive_bp = Blueprint("archive", __name__, url_prefix="/api")', archive_source)

    def test_case_file_routes_moved_out_of_api_module(self):
        api_source = Path("/opt/casescope/routes/api.py").read_text()
        case_files_source = Path("/opt/casescope/routes/case_files.py").read_text()

        extracted_routes = [
            "/files/stats/<case_uuid>",
            "/case/statistics/<case_uuid>",
            "/files/list/<case_uuid>",
            "/files/progress/<case_uuid>",
            "/files/reindex/<case_uuid>",
            "/files/repair-completion/<case_uuid>",
            "/events/duplicates/preview/<case_uuid>",
            "/events/duplicates/remove/<case_uuid>",
            "/files/staging/check/<case_uuid>",
            "/files/staging/import/<case_uuid>",
            "/files/staging/delete/<case_uuid>",
            "/files/recover-stuck/<case_uuid>",
            "/files/delete/<int:file_id>",
        ]

        for route in extracted_routes:
            self.assertNotIn(f"@api_bp.route('{route}'", api_source)
            self.assertIn(route, case_files_source)

        self.assertIn('case_files_bp = Blueprint("case_files", __name__, url_prefix="/api")', case_files_source)

    def test_dashboard_route_moved_out_of_api_module(self):
        api_source = Path("/opt/casescope/routes/api.py").read_text()
        dashboard_source = Path("/opt/casescope/routes/dashboard.py").read_text()

        self.assertNotIn("@api_bp.route('/dashboard/stats')", api_source)
        self.assertIn("/dashboard/stats", dashboard_source)
        self.assertIn('dashboard_bp = Blueprint("dashboard", __name__, url_prefix="/api")', dashboard_source)
        self.assertIn("def dashboard_stats(", dashboard_source)
        self.assertIn("def get_folder_size_gb(", dashboard_source)
        self.assertIn("def get_software_version(", dashboard_source)

    def test_ingest_routes_moved_out_of_api_module(self):
        api_source = Path("/opt/casescope/routes/api.py").read_text()
        ingest_source = Path("/opt/casescope/routes/ingest.py").read_text()

        extracted_routes = [
            "/upload/scan/<case_uuid>",
            "/upload/chunk",
            "/upload/preflight",
            "/upload/ingest",
        ]

        for route in extracted_routes:
            self.assertNotIn(f"@api_bp.route('{route}'", api_source)
            self.assertIn(route, ingest_source)

        self.assertIn('ingest_bp = Blueprint("ingest", __name__, url_prefix="/api")', ingest_source)
        self.assertIn("def ensure_upload_dirs(", ingest_source)
        self.assertIn("def ingest_files(", ingest_source)

    def test_ops_routes_moved_out_of_api_module(self):
        api_source = Path("/opt/casescope/routes/api.py").read_text()
        ops_source = Path("/opt/casescope/routes/ops.py").read_text()

        extracted_routes = [
            "/logs/audit/<category>",
            "/settings/logging",
            "/settings/logging/test-path",
            "/settings/paths",
            "/settings/paths/test",
            "/logs/view/<path:log_path>",
            "/logs/case/<case_uuid>",
            "/audit-log",
            "/audit-log/entity/<entity_type>/<entity_id>",
        ]

        for route in extracted_routes:
            self.assertNotIn(f"@api_bp.route('{route}'", api_source)
            self.assertIn(route, ops_source)

        self.assertIn('ops_bp = Blueprint("ops", __name__, url_prefix="/api")', ops_source)

    def test_ioc_routes_moved_out_of_api_module(self):
        api_source = Path("/opt/casescope/routes/api.py").read_text()
        iocs_source = Path("/opt/casescope/routes/iocs.py").read_text()

        extracted_routes = [
            "/iocs/types",
            "/iocs/values/<int:case_id>",
            "/iocs/list/<case_uuid>",
            "/iocs/analyze-match-type",
            "/iocs/create/<case_uuid>",
            "/iocs/<int:ioc_id>",
            "/iocs/<int:ioc_id>/update",
            "/iocs/<int:ioc_id>/systems",
            "/iocs/<int:ioc_id>/audit",
            "/iocs/<int:ioc_id>/delete",
            "/iocs/bulk-create/<case_uuid>",
            "/iocs/extraction/check/<case_uuid>",
            "/iocs/extraction/extract/<case_uuid>",
            "/iocs/extraction/progress/<case_uuid>/<task_id>",
            "/iocs/extraction/results/<case_uuid>/<task_id>",
            "/iocs/extraction/save/<case_uuid>",
            "/iocs/find-in-events/stats/<case_uuid>",
            "/iocs/find-in-events/start/<case_uuid>",
            "/iocs/find-in-events/progress/<case_uuid>/<task_id>",
            "/iocs/find-in-events/results/<case_uuid>/<task_id>",
            "/iocs/find-in-events/save/<case_uuid>",
            "/iocs/tag-artifacts/<case_uuid>",
            "/iocs/tag-artifacts/start/<case_uuid>",
            "/iocs/tag-artifacts/<case_uuid>/progress",
            "/iocs/tag-artifacts/results/<case_uuid>/<task_id>",
            "/ioc/<int:ioc_id>/enrich",
            "/ioc/<int:ioc_id>/enrichment",
            "/iocs/bulk-enrich",
            "/iocs/bulk-update",
            "/iocs/bulk-delete/<case_uuid>",
        ]

        for route in extracted_routes:
            self.assertNotIn(f"@api_bp.route('{route}'", api_source)
            self.assertIn(route, iocs_source)

        self.assertIn('iocs_bp = Blueprint("iocs", __name__, url_prefix="/api")', iocs_source)

    def test_hunting_support_routes_moved_out_of_api_module(self):
        api_source = Path("/opt/casescope/routes/api.py").read_text()
        hunting_source = Path("/opt/casescope/routes/hunting.py").read_text()

        extracted_routes = [
            "/hunting/browser/downloads/<int:case_id>",
            "/hunting/noise/stats/<int:case_id>",
            "/hunting/noise/tag/<int:case_id>",
            "/hunting/noise/status/<task_id>",
            "/hunting/field-enhancers",
        ]

        for route in extracted_routes:
            self.assertNotIn(f"@api_bp.route('{route}'", api_source)
            self.assertIn(route, hunting_source)

        self.assertIn('hunting_bp = Blueprint("hunting", __name__, url_prefix="/api")', hunting_source)

    def test_hunting_query_routes_moved_out_of_api_module(self):
        api_source = Path("/opt/casescope/routes/api.py").read_text()
        hunting_source = Path("/opt/casescope/routes/hunting.py").read_text()

        extracted_routes = [
            "/hunting/events/<int:case_id>",
            "/hunting/event/raw/<int:case_id>",
            "/hunting/event/tag/<int:case_id>",
            "/hunting/events/bulk-tag/<int:case_id>",
            "/hunting/events/bulk-noise/<int:case_id>",
            "/hunting/events/export-tagged/<int:case_id>",
            "/hunting/events/export-view/<int:case_id>",
            "/hunting/process/children/<int:case_id>",
            "/hunting/process/parent/<int:case_id>",
            "/hunting/processes/list/<int:case_id>",
            "/hunting/processes/tree/<int:case_id>",
            "/hunting/processes/hostnames/<int:case_id>",
        ]

        for route in extracted_routes:
            self.assertNotIn(f"@api_bp.route('{route}'", api_source)
            self.assertIn(route, hunting_source)

        self.assertIn("def get_hunting_events(", hunting_source)
        self.assertIn("def get_unified_process_tree(", hunting_source)

    def test_route_helpers_hold_shared_license_and_viewer_gates(self):
        helpers_source = Path("/opt/casescope/routes/route_helpers.py").read_text()
        api_source = Path("/opt/casescope/routes/api.py").read_text()
        ai_source = Path("/opt/casescope/routes/ai.py").read_text()
        archive_source = Path("/opt/casescope/routes/archive.py").read_text()
        case_files_source = Path("/opt/casescope/routes/case_files.py").read_text()
        hunting_source = Path("/opt/casescope/routes/hunting.py").read_text()
        iocs_source = Path("/opt/casescope/routes/iocs.py").read_text()
        ops_source = Path("/opt/casescope/routes/ops.py").read_text()
        reports_source = Path("/opt/casescope/routes/reports.py").read_text()
        enrichment_source = Path("/opt/casescope/routes/enrichment.py").read_text()

        self.assertIn('DEFAULT_ARCHIVE_PATH = "/archive"', helpers_source)
        self.assertIn('DEFAULT_ORIGINALS_PATH = "/originals"', helpers_source)
        self.assertIn('API_TASK_SESSION_KEY = "api_task_access"', helpers_source)
        self.assertIn("def _viewer_write_error(", helpers_source)
        self.assertIn("def _is_license_feature_active(", helpers_source)
        self.assertIn("def _is_threat_intel_license_active(", helpers_source)
        self.assertIn("def _remember_task_access(", helpers_source)
        self.assertIn("def _task_access_allowed(", helpers_source)
        self.assertIn("from routes import hunting_query_helpers, route_helpers", api_source)
        self.assertIn("def _remember_task_access(", api_source)
        self.assertIn("def _task_access_allowed(", api_source)
        self.assertIn("from routes.route_helpers import _is_license_feature_active, _viewer_write_error", ai_source)
        self.assertIn(
            "from routes.route_helpers import DEFAULT_ARCHIVE_PATH, _viewer_write_error",
            archive_source,
        )
        self.assertIn(
            "from routes.route_helpers import _default_upload_type_label, _get_parser_hints_for_case_file",
            case_files_source,
        )
        self.assertIn(
            "from routes.route_helpers import _remember_task_access, _task_access_allowed",
            iocs_source,
        )
        self.assertIn(
            "from routes.route_helpers import _remember_task_access, _task_access_allowed, _viewer_write_error",
            hunting_source,
        )
        self.assertIn(
            "from routes.route_helpers import DEFAULT_ARCHIVE_PATH, DEFAULT_ORIGINALS_PATH",
            ops_source,
        )
        self.assertIn("from routes.route_helpers import _viewer_write_error", reports_source)
        self.assertIn(
            "from routes.route_helpers import _is_license_feature_active, _is_threat_intel_license_active",
            enrichment_source,
        )

    def test_app_registers_extracted_ai_blueprint(self):
        app_source = Path("/opt/casescope/app.py").read_text()

        self.assertIn("from routes.ai import ai_bp", app_source)
        self.assertIn("from routes.admin import admin_bp", app_source)
        self.assertIn("from routes.archive import archive_bp", app_source)
        self.assertIn("from routes.case_files import case_files_bp", app_source)
        self.assertIn("from routes.dashboard import dashboard_bp", app_source)
        self.assertIn("from routes.enrichment import enrichment_bp", app_source)
        self.assertIn("from routes.hunting import hunting_bp", app_source)
        self.assertIn("from routes.ingest import ingest_bp", app_source)
        self.assertIn("from routes.iocs import iocs_bp", app_source)
        self.assertIn("from routes.known_systems import known_systems_bp", app_source)
        self.assertIn("from routes.known_users import known_users_bp", app_source)
        self.assertIn("from routes.ops import ops_bp", app_source)
        self.assertIn("from routes.reports import reports_bp", app_source)
        self.assertIn("app.register_blueprint(admin_bp)", app_source)
        self.assertIn("app.register_blueprint(ai_bp)", app_source)
        self.assertIn("app.register_blueprint(archive_bp)", app_source)
        self.assertIn("app.register_blueprint(case_files_bp)", app_source)
        self.assertIn("app.register_blueprint(dashboard_bp)", app_source)
        self.assertIn("app.register_blueprint(enrichment_bp)", app_source)
        self.assertIn("app.register_blueprint(hunting_bp)", app_source)
        self.assertIn("app.register_blueprint(ingest_bp)", app_source)
        self.assertIn("app.register_blueprint(iocs_bp)", app_source)
        self.assertIn("app.register_blueprint(known_systems_bp)", app_source)
        self.assertIn("app.register_blueprint(known_users_bp)", app_source)
        self.assertIn("app.register_blueprint(ops_bp)", app_source)
        self.assertIn("app.register_blueprint(reports_bp)", app_source)


if __name__ == "__main__":
    unittest.main()
