import importlib.util
import os
import unittest

from flask import Flask, abort

BASE_DIR = os.path.dirname(os.path.dirname(__file__))


def _load_module(module_name: str, relative_path: str):
    spec = importlib.util.spec_from_file_location(
        module_name,
        os.path.join(BASE_DIR, relative_path),
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


api_errors = _load_module("api_errors_under_test", "utils/api_errors.py")


class ApiErrorShapesTestCase(unittest.TestCase):
    def test_api_routes_return_canonical_json_forbidden_shape(self):
        app = Flask(__name__)
        app.register_error_handler(403, api_errors.forbidden_error_response)

        @app.route("/api/protected")
        def protected():
            abort(403, description="Access denied")

        with app.test_client() as client:
            response = client.get("/api/protected")

        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.get_json(), {"success": False, "error": "Access denied"})


if __name__ == "__main__":
    unittest.main()
