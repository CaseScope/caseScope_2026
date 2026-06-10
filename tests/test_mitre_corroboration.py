import importlib.util
import os
import sys
import types
import unittest


REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _load_corroboration_module():
    fake_utils = types.ModuleType("utils")
    fake_clickhouse = types.ModuleType("utils.clickhouse")
    fake_event_mitre_state = types.ModuleType("utils.event_mitre_state")
    fake_clickhouse.get_client = lambda: None
    fake_event_mitre_state.MITRE_MATCH_TABLE = "event_mitre_matches"
    fake_event_mitre_state.ensure_event_mitre_state_tables = lambda _client: None
    sys.modules.setdefault("utils", fake_utils)
    sys.modules["utils.clickhouse"] = fake_clickhouse
    sys.modules["utils.event_mitre_state"] = fake_event_mitre_state

    module_path = os.path.join(REPO_ROOT, "utils", "mitre_corroboration.py")
    spec = importlib.util.spec_from_file_location("mitre_corroboration_under_test", module_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class MitreCorroborationTests(unittest.TestCase):
    def test_parent_and_subtechnique_sources_corroborate(self):
        mitre_corroboration = _load_corroboration_module()
        original_loader = mitre_corroboration._load_reference_equivalents
        original_ensure = mitre_corroboration.ensure_event_mitre_state_tables

        class _Result:
            result_rows = [
                ("T1021", ["hayabusa"]),
                ("T1021.001", ["mitre_procedure_rule"]),
            ]

        class _Client:
            def query(self, *_args, **_kwargs):
                return _Result()

        try:
            mitre_corroboration._load_reference_equivalents = lambda _ids: {
                "T1021": {"T1021", "T1021.001"}
            }
            mitre_corroboration.ensure_event_mitre_state_tables = lambda _client: None

            self.assertEqual(
                mitre_corroboration.get_corroborated_techniques(7, ["T1021"], client=_Client()),
                ["T1021"],
            )
        finally:
            mitre_corroboration._load_reference_equivalents = original_loader
            mitre_corroboration.ensure_event_mitre_state_tables = original_ensure

    def test_normalization_rejects_non_technique_values(self):
        mitre_corroboration = _load_corroboration_module()
        self.assertEqual(mitre_corroboration.normalize_technique_id(" t1021.001 "), "T1021.001")
        self.assertEqual(mitre_corroboration.normalize_technique_id("TA0008"), "")
        self.assertEqual(mitre_corroboration.parent_technique_id("T1021.001"), "T1021")


if __name__ == "__main__":
    unittest.main()
