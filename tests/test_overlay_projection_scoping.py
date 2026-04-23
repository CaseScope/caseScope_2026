import importlib.util
import os
import sys
import types
import unittest
from contextlib import contextmanager


REPO_ROOT = os.path.dirname(os.path.dirname(__file__))


@contextmanager
def _load_overlay_modules():
    original_utils = sys.modules.get("utils")
    original_clickhouse = sys.modules.get("utils.clickhouse")
    original_event_selector = sys.modules.get("utils.event_selector")

    utils_package = types.ModuleType("utils")
    clickhouse_module = types.ModuleType("utils.clickhouse")
    clickhouse_module.get_client = lambda: None
    utils_package.clickhouse = clickhouse_module
    sys.modules["utils"] = utils_package
    sys.modules["utils.clickhouse"] = clickhouse_module

    selector_path = os.path.join(REPO_ROOT, "utils", "event_selector.py")
    selector_spec = importlib.util.spec_from_file_location("utils.event_selector", selector_path)
    selector_module = importlib.util.module_from_spec(selector_spec)
    selector_spec.loader.exec_module(selector_module)
    utils_package.event_selector = selector_module
    sys.modules["utils.event_selector"] = selector_module

    modules = {}
    try:
        for module_name in ("event_analyst_state", "event_ioc_state", "event_noise_state"):
            module_path = os.path.join(REPO_ROOT, "utils", f"{module_name}.py")
            spec = importlib.util.spec_from_file_location(f"{module_name}_under_test", module_path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            modules[module_name] = module
        yield modules
    finally:
        if original_utils is None:
            sys.modules.pop("utils", None)
        else:
            sys.modules["utils"] = original_utils
        if original_clickhouse is None:
            sys.modules.pop("utils.clickhouse", None)
        else:
            sys.modules["utils.clickhouse"] = original_clickhouse
        if original_event_selector is None:
            sys.modules.pop("utils.event_selector", None)
        else:
            sys.modules["utils.event_selector"] = original_event_selector


class OverlayProjectionScopingTestCase(unittest.TestCase):
    def test_case_scoped_projections_only_scan_requested_case(self):
        with _load_overlay_modules() as modules:
            analyst_projection = modules["event_analyst_state"].build_analyst_projection(
                alias="e",
                case_id_filter_sql="{case_id:UInt32}",
            )
            ioc_projection = modules["event_ioc_state"].build_ioc_projection(
                alias="e",
                case_id_filter_sql="{case_id:UInt32}",
            )
            noise_projection = modules["event_noise_state"].build_noise_projection(
                alias="e",
                case_id_filter_sql="{case_id:UInt32}",
            )

        self.assertIn("WHERE case_id = {case_id:UInt32}", analyst_projection["join_sql"])
        self.assertIn("WHERE case_id = {case_id:UInt32}", ioc_projection["join_sql"])
        self.assertIn("WHERE state.case_id = {case_id:UInt32}", ioc_projection["join_sql"])
        self.assertIn("WHERE case_id = {case_id:UInt32}", noise_projection["join_sql"])
        self.assertIn("WHERE state.case_id = {case_id:UInt32}", noise_projection["join_sql"])


if __name__ == "__main__":
    unittest.main()
