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


class _FakeSession:
    def __init__(self):
        self.added = []
        self.commit_count = 0

    def add(self, item):
        self.added.append(item)

    def commit(self):
        self.commit_count += 1


class _FakeGapDetectionFinding:
    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)
        self.details = getattr(self, 'details', {})
        self.evidence = getattr(self, 'evidence', {})
        self.summary = getattr(self, 'summary', '')


class _FakeDetector:
    findings = []

    def __init__(self, case_id, analysis_id):
        self.case_id = case_id
        self.analysis_id = analysis_id

    def detect(self):
        return list(self.findings)


class _FailingDetector(_FakeDetector):
    def detect(self):
        raise RuntimeError('boom')


def _install_detector_module(module_name: str, class_name: str, detector_class):
    module = types.ModuleType(module_name)
    setattr(module, class_name, detector_class)
    sys.modules[module_name] = module


utils_pkg = sys.modules.setdefault('utils', types.ModuleType('utils'))
utils_pkg.__path__ = [str(UTILS_DIR)]

models_pkg = sys.modules.setdefault('models', types.ModuleType('models'))
models_pkg.__path__ = [str(REPO_ROOT / 'models')]

fake_session = _FakeSession()
database_module = types.ModuleType('models.database')
database_module.db = types.SimpleNamespace(session=fake_session)
sys.modules['models.database'] = database_module

behavioral_profiles_module = types.ModuleType('models.behavioral_profiles')
behavioral_profiles_module.GapDetectionFinding = _FakeGapDetectionFinding
behavioral_profiles_module.GapFindingType = type('GapFindingType', (), {})
sys.modules['models.behavioral_profiles'] = behavioral_profiles_module

gap_detectors = _load_module(
    'utils.gap_detectors',
    UTILS_DIR / 'gap_detectors' / '__init__.py',
)

GapDetectionManager = gap_detectors.GapDetectionManager


class Phase4aGapDetectorManagerContractTestCase(unittest.TestCase):
    def setUp(self):
        fake_session.added.clear()
        fake_session.commit_count = 0

    def test_detector_stage_iterator_returns_materialized_stage_definitions(self):
        manager = GapDetectionManager(case_id=7, analysis_id='phase4a-test')

        first = manager._iter_detector_stages()
        second = manager._iter_detector_stages()

        self.assertIsNot(first, second)
        self.assertEqual(first, second)
        self.assertIsNot(first[0], second[0])
        self.assertEqual(
            [stage['class_name'] for stage in first],
            ['PasswordSprayingDetector', 'BruteForceDetector', 'BehavioralAnomalyDetector'],
        )

    def test_run_all_detectors_uses_shared_stage_runner_and_persists_results(self):
        class PasswordDetector(_FakeDetector):
            findings = [
                _FakeGapDetectionFinding(
                    entity_type='source_ip',
                    entity_value='10.0.0.5',
                    confidence=70,
                    severity='high',
                    finding_type='PASSWORD_SPRAYING',
                    details={},
                    evidence={},
                    summary='spray',
                )
            ]

        class BruteDetector(_FakeDetector):
            findings = [
                _FakeGapDetectionFinding(
                    entity_type='user',
                    entity_value='alice',
                    confidence=65,
                    severity='medium',
                    finding_type='BRUTE_FORCE',
                    details={},
                    evidence={},
                    summary='brute',
                )
            ]

        class AnomalyDetector(_FakeDetector):
            findings = [
                _FakeGapDetectionFinding(
                    entity_type='system',
                    entity_value='host-a',
                    confidence=80,
                    severity='high',
                    finding_type='BEHAVIORAL_ANOMALY',
                    details={},
                    evidence={},
                    summary='anomaly',
                )
            ]

        _install_detector_module(
            'utils.gap_detectors.password_spraying',
            'PasswordSprayingDetector',
            PasswordDetector,
        )
        _install_detector_module(
            'utils.gap_detectors.brute_force',
            'BruteForceDetector',
            BruteDetector,
        )
        _install_detector_module(
            'utils.gap_detectors.behavioral_anomaly',
            'BehavioralAnomalyDetector',
            AnomalyDetector,
        )

        progress_updates = []
        manager = GapDetectionManager(
            case_id=7,
            analysis_id='phase4a-test',
            progress_callback=lambda phase, percent, message: progress_updates.append(
                (phase, percent, message)
            ),
        )

        findings = manager.run_all_detectors()

        self.assertEqual(len(findings), 3)
        self.assertEqual(len(fake_session.added), 3)
        self.assertEqual(fake_session.commit_count, 1)
        self.assertEqual(
            progress_updates[:3],
            [
                ('gap_detection', 20, 'Running password spraying detection...'),
                ('gap_detection', 25, 'Running brute force detection...'),
                ('gap_detection', 30, 'Running behavioral anomaly detection...'),
            ],
        )

    def test_run_all_detectors_keeps_stage_failures_isolated(self):
        class PasswordDetector(_FakeDetector):
            findings = [
                _FakeGapDetectionFinding(
                    entity_type='source_ip',
                    entity_value='10.0.0.5',
                    confidence=70,
                    severity='high',
                    finding_type='PASSWORD_SPRAYING',
                    details={},
                    evidence={},
                    summary='spray',
                )
            ]

        class AnomalyDetector(_FakeDetector):
            findings = [
                _FakeGapDetectionFinding(
                    entity_type='system',
                    entity_value='host-a',
                    confidence=80,
                    severity='high',
                    finding_type='BEHAVIORAL_ANOMALY',
                    details={},
                    evidence={},
                    summary='anomaly',
                )
            ]

        _install_detector_module(
            'utils.gap_detectors.password_spraying',
            'PasswordSprayingDetector',
            PasswordDetector,
        )
        _install_detector_module(
            'utils.gap_detectors.brute_force',
            'BruteForceDetector',
            _FailingDetector,
        )
        _install_detector_module(
            'utils.gap_detectors.behavioral_anomaly',
            'BehavioralAnomalyDetector',
            AnomalyDetector,
        )

        manager = GapDetectionManager(case_id=7, analysis_id='phase4a-test')
        findings = manager.run_all_detectors()
        source = (UTILS_DIR / 'gap_detectors' / '__init__.py').read_text()

        self.assertEqual(len(findings), 2)
        self.assertEqual(len(fake_session.added), 2)
        self.assertEqual(fake_session.commit_count, 1)
        self.assertIn('for stage in self._iter_detector_stages():', source)
        self.assertIn('all_findings.extend(self._run_detector_stage(stage))', source)


if __name__ == '__main__':
    unittest.main()
