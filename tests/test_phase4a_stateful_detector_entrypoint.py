import importlib.util
import sys
import types
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
UTILS_DIR = REPO_ROOT / 'utils'


def _load_module(module_name: str, path: Path):
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f'Unable to load module from {path}')
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


utils_pkg = sys.modules.setdefault('utils', types.ModuleType('utils'))
utils_pkg.__path__ = [str(UTILS_DIR)]

models_pkg = sys.modules.setdefault('models', types.ModuleType('models'))
models_pkg.__path__ = [str(REPO_ROOT / 'models')]

database_module = types.ModuleType('models.database')
database_module.db = types.SimpleNamespace(session=types.SimpleNamespace(add=lambda item: None, commit=lambda: None))
sys.modules['models.database'] = database_module

behavioral_profiles_module = types.ModuleType('models.behavioral_profiles')
behavioral_profiles_module.GapDetectionFinding = type('GapDetectionFinding', (), {})
behavioral_profiles_module.GapFindingType = type('GapFindingType', (), {})
sys.modules['models.behavioral_profiles'] = behavioral_profiles_module

stateful_detectors = _load_module(
    'utils.stateful_detectors',
    UTILS_DIR / 'stateful_detectors' / '__init__.py',
)


class Phase4aStatefulDetectorEntrypointTestCase(unittest.TestCase):
    def test_stateful_detector_package_exports_expected_surfaces(self):
        self.assertTrue(hasattr(stateful_detectors, 'GapDetectionManager'))
        self.assertTrue(hasattr(stateful_detectors, 'BaseGapDetector'))
        self.assertTrue(hasattr(stateful_detectors, 'build_gap_detection_finding_payload'))
        self.assertTrue(hasattr(stateful_detectors, 'deduplicate_gap_detection_findings'))
        self.assertTrue(hasattr(stateful_detectors, 'get_gap_finding_severity_rank'))

    def test_call_sites_use_stateful_detector_entrypoint(self):
        rag_tasks_source = (REPO_ROOT / 'tasks' / 'rag_tasks.py').read_text()
        case_analyzer_source = (REPO_ROOT / 'utils' / 'case_analyzer.py').read_text()
        spray_source = (UTILS_DIR / 'stateful_detectors' / 'password_spraying.py').read_text()
        brute_source = (UTILS_DIR / 'stateful_detectors' / 'brute_force.py').read_text()
        anomaly_source = (UTILS_DIR / 'stateful_detectors' / 'behavioral_anomaly.py').read_text()

        self.assertIn('from utils.stateful_detectors import GapDetectionManager', rag_tasks_source)
        self.assertIn('from utils.stateful_detectors import GapDetectionManager', case_analyzer_source)
        self.assertIn('from utils.stateful_detectors import BaseGapDetector', spray_source)
        self.assertIn('from utils.stateful_detectors import BaseGapDetector', brute_source)
        self.assertIn('from utils.stateful_detectors import BaseGapDetector', anomaly_source)
        self.assertFalse((UTILS_DIR / 'gap_detectors').exists())


if __name__ == '__main__':
    unittest.main()
