import importlib.util
import json
import os
import sys
import types
import unittest
from pathlib import Path

os.environ.setdefault("SECRET_KEY", "test-secret")

REPO_ROOT = os.path.dirname(os.path.dirname(__file__))


def _load_module(name: str, relative_path: str):
    module_path = os.path.join(REPO_ROOT, relative_path)
    spec = importlib.util.spec_from_file_location(name, module_path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


finding_contract = _load_module(
    "phase2_finding_contract",
    os.path.join("utils", "finding_contract.py"),
)


class _DummyQueryResult:
    def __init__(self, rows):
        self.result_rows = rows


class _DummyClickHouseClient:
    def __init__(self, query_rows=None):
        self.commands = []
        self.inserts = []
        self.query_rows = list(query_rows or [])

    def command(self, sql):
        self.commands.append(sql)

    def insert(self, table, rows, column_names=None):
        self.inserts.append(
            {
                "table": table,
                "rows": rows,
                "column_names": column_names,
            }
        )

    def query(self, sql, parameters=None):
        if self.query_rows:
            return _DummyQueryResult(self.query_rows.pop(0))
        return _DummyQueryResult([])


def _load_store_module(client):
    fake_utils = types.ModuleType("utils")
    fake_utils.__path__ = []

    fake_clickhouse = types.ModuleType("utils.clickhouse")
    fake_clickhouse.get_client = lambda: client

    previous_utils = sys.modules.get("utils")
    previous_clickhouse = sys.modules.get("utils.clickhouse")
    previous_contract = sys.modules.get("utils.finding_contract")
    sys.modules["utils"] = fake_utils
    sys.modules["utils.clickhouse"] = fake_clickhouse
    sys.modules["utils.finding_contract"] = finding_contract

    try:
        return _load_module(
            "phase2_unified_findings_store",
            os.path.join("utils", "unified_findings_store.py"),
        )
    finally:
        if previous_utils is not None:
            sys.modules["utils"] = previous_utils
        else:
            sys.modules.pop("utils", None)

        if previous_clickhouse is not None:
            sys.modules["utils.clickhouse"] = previous_clickhouse
        else:
            sys.modules.pop("utils.clickhouse", None)

        if previous_contract is not None:
            sys.modules["utils.finding_contract"] = previous_contract
        else:
            sys.modules.pop("utils.finding_contract", None)


def _load_unified_findings_module(*, load_case_findings, ai_results=None):
    fake_utils = types.ModuleType("utils")
    fake_utils.__path__ = []

    fake_store = types.ModuleType("utils.unified_findings_store")
    fake_store.load_case_findings = load_case_findings

    fake_models = types.ModuleType("models")
    fake_models.__path__ = []
    fake_database = types.ModuleType("models.database")
    fake_database.db = types.SimpleNamespace(session=types.SimpleNamespace(query=lambda *args, **kwargs: None))

    fake_rag = types.ModuleType("models.rag")

    class _FakeAIQuery:
        def __init__(self, rows):
            self.rows = rows

        def filter_by(self, **kwargs):
            return self

        def all(self):
            return list(self.rows)

    class _FakeAIAnalysisResult:
        query = _FakeAIQuery(ai_results or [])

    fake_rag.AIAnalysisResult = _FakeAIAnalysisResult
    fake_rag.PatternRuleMatch = type("PatternRuleMatch", (), {})
    fake_rag.PatternMatch = type("PatternMatch", (), {})
    fake_rag.AttackPattern = type("AttackPattern", (), {})

    previous_modules = {
        name: sys.modules.get(name)
        for name in (
            "utils",
            "utils.finding_contract",
            "utils.unified_findings_store",
            "models",
            "models.database",
            "models.rag",
        )
    }

    sys.modules["utils"] = fake_utils
    sys.modules["utils.finding_contract"] = finding_contract
    sys.modules["utils.unified_findings_store"] = fake_store
    sys.modules["models"] = fake_models
    sys.modules["models.database"] = fake_database
    sys.modules["models.rag"] = fake_rag

    try:
        module = _load_module(
            "phase2_unified_findings",
            os.path.join("utils", "unified_findings.py"),
        )
        module._phase2_previous_modules = previous_modules
        module._phase2_fake_modules = {
            "utils": fake_utils,
            "utils.finding_contract": finding_contract,
            "utils.unified_findings_store": fake_store,
            "models": fake_models,
            "models.database": fake_database,
            "models.rag": fake_rag,
        }
        return module
    finally:
        for name, previous in previous_modules.items():
            if previous is not None:
                sys.modules[name] = previous
            else:
                sys.modules.pop(name, None)


class Phase2UnifiedFindingsStoreTestCase(unittest.TestCase):
    def _activate_fake_imports(self, module):
        previous = {}
        for name, fake_module in module._phase2_fake_modules.items():
            previous[name] = sys.modules.get(name)
            sys.modules[name] = fake_module
        return previous

    def _restore_imports(self, previous):
        for name, module in previous.items():
            if module is not None:
                sys.modules[name] = module
            else:
                sys.modules.pop(name, None)

    def test_sync_case_findings_creates_table_and_inserts_canonical_rows(self):
        client = _DummyClickHouseClient()
        store = _load_store_module(client)

        inserted = store.sync_case_findings(
            case_id=42,
            analysis_id="analysis-1",
            findings=[
                {
                    "id": "gap-1",
                    "source_system": "gap_detection",
                    "finding_type": "password_spraying",
                    "summary": "Password spraying from 10.0.0.5",
                    "confidence": 91,
                    "severity": "high",
                    "entity_type": "source_ip",
                    "entity_value": "10.0.0.5",
                    "time_window_start": "2026-04-11T10:00:00",
                    "time_window_end": "2026-04-11T10:05:00",
                },
                {
                    "id": "gap-1",
                    "source_system": "gap_detection",
                    "finding_type": "password_spraying",
                    "summary": "duplicate should collapse",
                    "confidence": 91,
                },
            ],
        )

        self.assertEqual(inserted, 1)
        self.assertTrue(client.commands)
        self.assertEqual(client.inserts[0]["table"], "case_unified_findings")
        stored_row = client.inserts[0]["rows"][0]
        self.assertEqual(stored_row[0], 42)
        self.assertEqual(stored_row[1], "analysis-1")
        self.assertEqual(stored_row[3], "gap_detection")
        self.assertEqual(stored_row[8], "high")
        legacy_payload = json.loads(stored_row[19])
        self.assertEqual(legacy_payload["rule_pack"], "gap_detection")
        self.assertEqual(legacy_payload["severity"], "high")

    def test_load_case_findings_returns_latest_analysis_payload(self):
        client = _DummyClickHouseClient(
            query_rows=[
                [("analysis-2",)],
                [[json.dumps({"id": "f-1", "source_system": "gap_detection", "confidence": 88})]],
            ]
        )
        store = _load_store_module(client)

        findings = store.load_case_findings(99)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["id"], "f-1")
        self.assertEqual(findings[0]["confidence"], 88)

    def test_unified_findings_prefers_clickhouse_store(self):
        unified_findings = _load_unified_findings_module(
            load_case_findings=lambda case_id: [
                {
                    "id": "ch-1",
                    "source_system": "gap_detection",
                    "category": "password_spraying",
                    "confidence": 94,
                    "severity": "critical",
                }
            ]
        )

        unified_findings._get_system1_findings = lambda case_id: self.fail("legacy path should not be used")
        unified_findings._get_system2_findings = lambda case_id: self.fail("legacy path should not be used")
        unified_findings._get_system3_findings = lambda case_id: self.fail("legacy path should not be used")

        previous = self._activate_fake_imports(unified_findings)
        try:
            result = unified_findings.get_unified_findings(case_id=7)
        finally:
            self._restore_imports(previous)

        self.assertEqual(result["summary"]["total"], 1)
        self.assertEqual(result["findings"][0]["id"], "ch-1")

    def test_system1_legacy_reader_builds_findings_when_clickhouse_is_empty(self):
        ai_result = types.SimpleNamespace(
            id=5,
            pattern_id="pass_the_hash",
            pattern_name="Pass the Hash",
            final_confidence=92,
            ai_confidence=90,
            rule_based_confidence=85,
            evidence_package={
                "source_host": "HOST-A",
                "mitre_techniques": ["T1550.002"],
            },
            correlation_key="alice",
            events_analyzed=4,
            ai_reasoning="Likely credential theft sequence.",
            ai_iocs=["alice"],
            ai_indicators_found=["NTLM reuse"],
            window_start="2026-04-11T09:00:00",
            window_end="2026-04-11T09:10:00",
            model_used="test-model",
        )
        unified_findings = _load_unified_findings_module(
            load_case_findings=lambda case_id: None,
            ai_results=[ai_result],
        )
        unified_findings._get_system2_findings = lambda case_id: []
        unified_findings._get_system3_findings = lambda case_id: []

        previous = self._activate_fake_imports(unified_findings)
        try:
            result = unified_findings.get_unified_findings(case_id=7)
        finally:
            self._restore_imports(previous)

        self.assertEqual(result["summary"]["total"], 1)
        finding = result["findings"][0]
        self.assertEqual(finding["rule_pack"], "ai_correlation")
        self.assertEqual(finding["rule_id"], "pass_the_hash")
        self.assertEqual(finding["host"], "HOST-A")

    def test_case_analyzer_source_syncs_unified_findings_after_finalize(self):
        source = Path("/opt/casescope/utils/case_analyzer.py").read_text()
        self.assertIn("from utils.unified_findings_store import sync_case_findings", source)
        self.assertIn("mirrored_count = sync_case_findings(", source)
        self.assertIn('"finding_storage_sync"', source)


if __name__ == "__main__":
    unittest.main()
