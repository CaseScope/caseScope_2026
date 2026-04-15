import importlib.util
import sys
import types
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
UTILS_DIR = REPO_ROOT / "utils"


def _load_module(module_name: str, path: Path):
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load module from {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


utils_pkg = sys.modules.setdefault("utils", types.ModuleType("utils"))
utils_pkg.__path__ = [str(UTILS_DIR)]

pattern_event_mappings = _load_module(
    "utils.pattern_event_mappings",
    UTILS_DIR / "pattern_event_mappings.py",
)


class AnchorClassInvariantTestCase(unittest.TestCase):
    def test_every_pattern_is_classified_or_explicitly_legacy(self):
        for pattern_id, pattern in pattern_event_mappings.iter_patterns():
            anchor_class = pattern.get("anchor_class")
            scoring_version = pattern.get("scoring_version")
            self.assertTrue(
                anchor_class in pattern_event_mappings.VALID_ANCHOR_CLASSES
                or scoring_version == "1.0",
                msg=(
                    f"{pattern_id} must either declare anchor_class or remain explicitly "
                    f"legacy with scoring_version 1.0"
                ),
            )


if __name__ == "__main__":
    unittest.main()
