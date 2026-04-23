import importlib.util
import os
import sys
import types
import unittest
from contextlib import contextmanager


os.environ.setdefault("SECRET_KEY", "test-secret")

REPO_ROOT = os.path.dirname(os.path.dirname(__file__))


@contextmanager
def _load_overlay_modules():
    original_utils = sys.modules.get("utils")
    original_clickhouse = sys.modules.get("utils.clickhouse")
    original_event_selector = sys.modules.get("utils.event_selector")

    utils_package = types.ModuleType("utils")
    clickhouse_module = types.ModuleType("utils.clickhouse")
    clickhouse_module.get_client = lambda: None
    clickhouse_module.clickhouse_bool_literal = lambda value: "true" if value else "false"
    clickhouse_module.clickhouse_nullable_string_literal = lambda value: "NULL" if value is None else f"'{value}'"
    clickhouse_module.clickhouse_string_array_literal = lambda values: "[" + ", ".join(f"'{value}'" for value in values) + "]"
    clickhouse_module.clickhouse_string_literal = lambda value: f"'{value}'"
    clickhouse_module.run_events_update = lambda *_args, **_kwargs: True
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
    def test_projections_resolve_direct_event_columns(self):
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

        self.assertEqual(analyst_projection["join_sql"], "")
        self.assertEqual(analyst_projection["tagged_sql"], "e.analyst_tagged")
        self.assertEqual(ioc_projection["join_sql"], "")
        self.assertEqual(ioc_projection["ioc_types_sql"], "e.ioc_types")
        self.assertEqual(noise_projection["join_sql"], "")
        self.assertEqual(noise_projection["matched_sql"], "e.noise_matched")


if __name__ == "__main__":
    unittest.main()
