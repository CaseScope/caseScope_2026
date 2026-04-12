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

gap_detectors = _load_module(
    'utils.gap_detectors',
    UTILS_DIR / 'gap_detectors' / '__init__.py',
)
stateful_detectors = _load_module(
    'utils.stateful_detectors',
    UTILS_DIR / 'stateful_detectors.py',
)


class Phase4aStatefulDetectorEntrypointTestCase(unittest.TestCase):
    def test_stateful_detector_entrypoint_reexports_gap_detector_surfaces(self):
        self.assertIs(stateful_detectors.GapDetectionManager, gap_detectors.GapDetectionManager)
        self.assertIs(stateful_detectors.BaseGapDetector, gap_detectors.BaseGapDetector)
        self.assertIs(
            stateful_detectors.build_gap_detection_finding_payload,
            gap_detectors.build_gap_detection_finding_payload,
        )
        self.assertIs(
            stateful_detectors.deduplicate_gap_detection_findings,
            gap_detectors.deduplicate_gap_detection_findings,
        )
        self.assertIs(
            stateful_detectors.get_gap_finding_severity_rank,
            gap_detectors.get_gap_finding_severity_rank,
        )

    def test_call_sites_use_stateful_detector_entrypoint(self):
        rag_tasks_source = (REPO_ROOT / 'tasks' / 'rag_tasks.py').read_text()
        case_analyzer_source = (REPO_ROOT / 'utils' / 'case_analyzer.py').read_text()
        spray_source = (UTILS_DIR / 'gap_detectors' / 'password_spraying.py').read_text()
        brute_source = (UTILS_DIR / 'gap_detectors' / 'brute_force.py').read_text()
        anomaly_source = (UTILS_DIR / 'gap_detectors' / 'behavioral_anomaly.py').read_text()

        self.assertIn('from utils.stateful_detectors import GapDetectionManager', rag_tasks_source)
        self.assertIn('from utils.stateful_detectors import GapDetectionManager', case_analyzer_source)
        self.assertIn('from utils.stateful_detectors import BaseGapDetector', spray_source)
        self.assertIn('from utils.stateful_detectors import BaseGapDetector', brute_source)
        self.assertIn('from utils.stateful_detectors import BaseGapDetector', anomaly_source)


if __name__ == '__main__':
    unittest.main()
