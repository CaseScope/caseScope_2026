import ast
import importlib.util
import unittest
from pathlib import Path
from unittest.mock import patch


class Phase3RouteDecompositionTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location(
            'phase3_route_helpers',
            '/opt/casescope/routes/route_helpers.py',
        )
        cls.route_helpers = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.route_helpers)

    def _load_tree(self, relative_path: str) -> ast.AST:
        source = Path("/opt/casescope", relative_path).read_text()
        return ast.parse(source)

    def _route_rules(self, relative_path: str, blueprint_name: str) -> set[str]:
        tree = self._load_tree(relative_path)
        rules = set()
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for decorator in node.decorator_list:
                if not isinstance(decorator, ast.Call):
                    continue
                func = decorator.func
                if not (
                    isinstance(func, ast.Attribute)
                    and isinstance(func.value, ast.Name)
                    and func.value.id == blueprint_name
                    and func.attr == "route"
                    and decorator.args
                    and isinstance(decorator.args[0], ast.Constant)
                    and isinstance(decorator.args[0].value, str)
                ):
                    continue
                rules.add(decorator.args[0].value)
        return rules

    def _create_app_blueprint_registrations(self) -> set[str]:
        tree = self._load_tree("app.py")
        registrations = set()
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if not (
                isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "app"
                and node.func.attr == "register_blueprint"
                and node.args
                and isinstance(node.args[0], ast.Name)
            ):
                continue
            registrations.add(node.args[0].id)
        return registrations

    def test_extracted_blueprints_declare_expected_route_contracts(self):
        route_cases = [
            ("routes/ai.py", "ai_bp", {
                "/settings/ai",
                "/settings/ai/test-connection",
                "/settings/ai/models",
                "/settings/ai/fetch-models",
                "/settings/ai/status",
                "/reports/generate-ai/<case_uuid>",
                "/reports/generate-timeline/<case_uuid>",
            }),
            ("routes/admin.py", "admin_bp", {
                "/settings/detect-gpu",
                "/settings/workers",
                "/settings/workers/restart",
                "/settings/timezone",
            }),
            ("routes/reports.py", "reports_bp", {
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
            }),
            ("routes/known_systems.py", "known_systems_bp", {
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
            }),
            ("routes/known_users.py", "known_users_bp", {
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
            }),
            ("routes/enrichment.py", "enrichment_bp", {
                "/settings/opencti",
                "/settings/opencti/test",
                "/opencti/status",
                "/opencti/connectors",
                "/settings/misp",
                "/settings/misp/test",
                "/misp/status",
            }),
            ("routes/findings.py", "findings_bp", {"/findings/list/<case_uuid>"}),
            ("routes/archive.py", "archive_bp", {
                "/case/<case_uuid>/archive",
                "/case/<case_uuid>/archive/status",
                "/case/<case_uuid>/archive/info",
                "/case/<case_uuid>/restore",
                "/case/<case_uuid>/restore/status",
                "/case/<case_uuid>/storage/size",
                "/archive/jobs/active",
            }),
            ("routes/case_files.py", "case_files_bp", {
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
            }),
            ("routes/dashboard.py", "dashboard_bp", {"/dashboard/stats"}),
            ("routes/ingest.py", "ingest_bp", {
                "/upload/scan/<case_uuid>",
                "/upload/chunk",
                "/upload/preflight",
                "/upload/ingest",
            }),
            ("routes/ops.py", "ops_bp", {
                "/logs/audit/<category>",
                "/settings/logging",
                "/settings/logging/test-path",
                "/settings/paths",
                "/settings/paths/test",
                "/logs/view/<path:log_path>",
                "/logs/case/<case_uuid>",
                "/audit-log",
                "/audit-log/entity/<entity_type>/<entity_id>",
            }),
            ("routes/iocs.py", "iocs_bp", {
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
            }),
            ("routes/hunting.py", "hunting_bp", {
                "/hunting/browser/downloads/<int:case_id>",
                "/hunting/noise/stats/<int:case_id>",
                "/hunting/noise/tag/<int:case_id>",
                "/hunting/noise/status/<task_id>",
                "/hunting/field-enhancers",
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
            }),
        ]

        for relative_path, blueprint_name, expected_rules in route_cases:
            with self.subTest(path=relative_path):
                self.assertTrue(expected_rules.issubset(self._route_rules(relative_path, blueprint_name)))

    def test_route_helpers_hold_shared_runtime_contracts(self):
        route_helpers = self.route_helpers
        self.assertEqual(route_helpers.DEFAULT_ARCHIVE_PATH, "/archive")
        self.assertEqual(route_helpers.DEFAULT_ORIGINALS_PATH, "/originals")
        self.assertEqual(route_helpers.API_TASK_SESSION_KEY, "api_task_access")

        with patch.object(route_helpers, "_is_license_feature_active", return_value=True) as active_mock:
            self.assertTrue(route_helpers._is_threat_intel_license_active())
        active_mock.assert_called_once_with("opencti")

    def test_legacy_api_module_removed(self):
        self.assertFalse(Path("/opt/casescope/routes/api.py").exists())

    def test_app_factory_registers_extracted_blueprints(self):
        registrations = self._create_app_blueprint_registrations()
        expected = {
            "admin_bp",
            "ai_bp",
            "archive_bp",
            "case_files_bp",
            "dashboard_bp",
            "enrichment_bp",
            "findings_bp",
            "hunting_bp",
            "ingest_bp",
            "iocs_bp",
            "known_systems_bp",
            "known_users_bp",
            "ops_bp",
            "reports_bp",
        }
        self.assertTrue(expected.issubset(registrations))
        self.assertNotIn("api_bp", registrations)


if __name__ == "__main__":
    unittest.main()
