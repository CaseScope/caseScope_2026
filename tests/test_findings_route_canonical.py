import importlib.util
from datetime import datetime
import os
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import patch

from flask import Flask, render_template

BASE_DIR = os.path.dirname(os.path.dirname(__file__))
TEMPLATE_PATHS = [
    "static/templates/case_dashboard.html",
    "static/templates/case_hunting.html",
    "static/templates/case_hunting_network.html",
    "static/templates/case_hunting_memory.html",
    "static/templates/case_hunting_processes.html",
    "static/templates/case_analysis_results.html",
]


def _load_module(module_name: str, relative_path: str):
    spec = importlib.util.spec_from_file_location(
        module_name,
        os.path.join(BASE_DIR, relative_path),
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FindingsRouteCanonicalTestCase(unittest.TestCase):
    def test_canonical_findings_route_uses_shared_payload_builder(self):
        original_modules = {
            "flask_login": sys.modules.get("flask_login"),
            "models.case": sys.modules.get("models.case"),
        }

        try:
            sys.modules["flask_login"] = types.SimpleNamespace(login_required=lambda func: func)
            sys.modules["models.case"] = types.SimpleNamespace(Case=type("Case", (), {}))
            findings_module = _load_module("findings_route_under_test", "routes/findings.py")

            app = Flask(__name__)
            case = types.SimpleNamespace(id=17)
            with app.test_request_context("/api/findings/list/case-uuid?limit=5"):
                with patch.object(findings_module.Case, "get_by_uuid", return_value=case, create=True):
                    with patch.object(
                        findings_module,
                        "_build_unified_findings_payload",
                        return_value={"success": True, "findings": [], "summary": {"total": 0}},
                    ) as payload_mock:
                        response = findings_module.get_case_findings("case-uuid")

            self.assertEqual(response.get_json()["success"], True)
            payload_mock.assert_called_once_with(17)
        finally:
            for module_name, original_module in original_modules.items():
                if original_module is None:
                    sys.modules.pop(module_name, None)
                else:
                    sys.modules[module_name] = original_module

    def test_templates_use_canonical_findings_endpoint(self):
        app = Flask(
            __name__,
            template_folder=os.path.join(BASE_DIR, "static", "templates"),
        )
        app.secret_key = "test-secret"
        app.jinja_env.globals["url_for"] = lambda endpoint, **kwargs: f"/stub/{endpoint}"
        app.jinja_env.globals["current_user"] = types.SimpleNamespace(
            is_administrator=False,
            is_analyst=True,
            is_authenticated=True,
        )

        render_context = {
            "CASE_UUID": "case-uuid",
            "case_uuid": "case-uuid",
            "case": types.SimpleNamespace(uuid="case-uuid", id=17, name="Case Name"),
            "hunting_tabs": [],
            "event_filter_groups": [],
            "summary": types.SimpleNamespace(
                total_findings=0,
                high_confidence_count=0,
                pending_actions=0,
                attack_chains=0,
            ),
            "analysis": types.SimpleNamespace(
                completed_at=datetime(2026, 4, 21, 12, 0, 0),
                started_at=datetime(2026, 4, 21, 11, 0, 0),
                mode="standard",
                analysis_id="analysis-1",
            ),
        }

        with app.test_request_context("/"):
            for relative_path in TEMPLATE_PATHS:
                with self.subTest(relative_path=relative_path):
                    content = Path(BASE_DIR, relative_path).read_text(encoding="utf-8")
                    self.assertNotIn("/api/rag/unified-findings/", content)
                    self.assertIn("/api/findings/list/", content)


if __name__ == "__main__":
    unittest.main()
