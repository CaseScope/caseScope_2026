import importlib.util
import os
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

from flask import Flask


os.environ.setdefault("SECRET_KEY", "test-secret")
REPO_ROOT = os.path.dirname(os.path.dirname(__file__))

sys.modules.setdefault("config", types.SimpleNamespace(Config=types.SimpleNamespace()))
sys.modules.setdefault(
    "models.audit_log",
    types.SimpleNamespace(
        AuditAction=types.SimpleNamespace(PREFLIGHT="preflight"),
        AuditEntityType=types.SimpleNamespace(CASE_FILE="case_file"),
        AuditLog=types.SimpleNamespace(log=lambda **_kwargs: None),
    ),
)
sys.modules.setdefault(
    "models.case",
    types.SimpleNamespace(Case=types.SimpleNamespace(get_by_uuid=lambda _uuid: object())),
)
sys.modules.setdefault(
    "models.case_file",
    types.SimpleNamespace(
        CaseFile=types.SimpleNamespace(
            calculate_sha256=lambda _path: "",
            find_by_hash=lambda *_args, **_kwargs: None,
            is_zip_file=lambda _path: False,
        ),
        ExtractionStatus=types.SimpleNamespace(FAIL="fail", FULL="full", PARTIAL="partial", NA="na"),
    ),
)
sys.modules.setdefault(
    "models.database",
    types.SimpleNamespace(db=types.SimpleNamespace(session=types.SimpleNamespace())),
)
sys.modules.setdefault(
    "routes.route_helpers",
    types.SimpleNamespace(
        _default_upload_type_label=lambda: "Auto-detect / Other",
        _get_parser_hints_for_case_file=lambda _case_file: [],
    ),
)
sys.modules.setdefault(
    "utils.artifact_paths",
    types.SimpleNamespace(
        copy_to_directory=lambda source, _dest, _name: source,
        ensure_case_artifact_paths=lambda _case_uuid: {
            "web_upload": "/tmp",
            "sftp_upload": "/tmp",
            "staging": "/tmp",
            "storage": "/tmp",
        },
        ensure_case_originals_subdir=lambda _case_uuid: "/tmp",
        is_within_any_root=lambda path, roots: any(path.startswith(root) for root in roots),
    ),
)
sys.modules.setdefault(
    "utils.archive_extraction",
    types.SimpleNamespace(extract_zip_archive=lambda *_args, **_kwargs: {}),
)
sys.modules.setdefault(
    "flask_login",
    types.SimpleNamespace(current_user=types.SimpleNamespace(permission_level="writer"), login_required=lambda f: f),
)

module_path = os.path.join(REPO_ROOT, "routes", "ingest.py")
spec = importlib.util.spec_from_file_location("ingest_routes_under_test", module_path)
ingest_routes = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ingest_routes)


class IngestHashContractTestCase(unittest.TestCase):
    def setUp(self):
        self.app = Flask(__name__)
        self.app.config["SECRET_KEY"] = "test-secret"

    def test_upload_file_hash_key_prefers_queue_id_then_folder_path(self):
        self.assertEqual(
            ingest_routes._upload_file_hash_key(
                {"id": 17, "name": "archive.zip", "source": "folder", "path": "/tmp/archive.zip"}
            ),
            "queue:17",
        )
        self.assertEqual(
            ingest_routes._upload_file_hash_key(
                {"name": "archive.zip", "source": "folder", "path": "/tmp/archive.zip"}
            ),
            "folder:/tmp/archive.zip",
        )
        self.assertEqual(
            ingest_routes._upload_file_hash_key({"name": "archive.zip", "source": "web"}),
            "web:archive.zip",
        )

    def test_lookup_preflight_hash_supports_queue_key_and_legacy_filename(self):
        keyed_file = {"id": 9, "name": "archive.zip", "source": "web"}
        legacy_file = {"name": "legacy.zip", "source": "web"}

        self.assertEqual(
            ingest_routes._lookup_preflight_hash(keyed_file, {"queue:9": "abc123"}),
            "abc123",
        )
        self.assertEqual(
            ingest_routes._lookup_preflight_hash(legacy_file, {"legacy.zip": "def456"}),
            "def456",
        )
        self.assertIsNone(ingest_routes._lookup_preflight_hash(keyed_file, {}))

    def test_normalize_upload_file_info_derives_kape_timestamp_hostname(self):
        normalized = ingest_routes._normalize_upload_file_info(
            {
                "name": "2026-04-28T225916_BDALENE_kape.zip",
                "host": "2026-04-28T225916_BDALENE",
                "type": "kape",
            }
        )

        self.assertEqual(normalized["host"], "BDALENE")

    def test_preflight_reports_hash_errors_with_stable_lookup_keys(self):
        with tempfile.TemporaryDirectory() as temp_root:
            folder_a = os.path.join(temp_root, "a")
            folder_b = os.path.join(temp_root, "b")
            os.makedirs(folder_a, exist_ok=True)
            os.makedirs(folder_b, exist_ok=True)

            good_path = os.path.join(folder_a, "archive.zip")
            bad_path = os.path.join(folder_b, "archive.zip")
            with open(good_path, "wb") as handle:
                handle.write(b"good")
            with open(bad_path, "wb") as handle:
                handle.write(b"bad")

            files = [
                {"id": 1, "name": "archive.zip", "source": "folder", "path": good_path},
                {"id": 2, "name": "archive.zip", "source": "folder", "path": bad_path},
            ]

            def fake_sha256(path):
                if path == bad_path:
                    raise RuntimeError("hash failed")
                return "hash-good"

            with self.app.test_request_context(
                "/api/upload/preflight",
                method="POST",
                json={"caseUuid": "case-uuid", "files": files},
            ):
                with patch.object(ingest_routes.Case, "get_by_uuid", return_value=object()), patch.object(
                    ingest_routes, "ensure_upload_dirs", return_value=(temp_root, temp_root, temp_root)
                ), patch.object(
                    ingest_routes, "_allowed_case_upload_roots", return_value=[temp_root]
                ), patch.object(
                    ingest_routes, "_log_case_file_audit"
                ), patch.object(
                    ingest_routes.CaseFile, "calculate_sha256", side_effect=fake_sha256
                ), patch.object(
                    ingest_routes.CaseFile, "find_by_hash", return_value=None
                ):
                    response = ingest_routes.preflight_check()

            payload = response.get_json()
            self.assertTrue(payload["success"])
            self.assertEqual(payload["file_hashes"], {"queue:1": "hash-good"})
            self.assertEqual(len(payload["hash_errors"]), 1)
            self.assertEqual(payload["hash_errors"][0]["file"], "archive.zip")
            self.assertEqual(payload["hash_errors"][0]["lookup_key"], "queue:2")
            self.assertEqual(payload["hash_errors"][0]["error"], "hash failed")


if __name__ == "__main__":
    unittest.main()
