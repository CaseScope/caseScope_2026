"""A gap detector that crashes must not look like one that found nothing.

Every exception raised inside a detector was caught and an empty list returned,
so a detector that could not run at all was indistinguishable from one that ran
cleanly and found nothing. That is exactly how these detectors came to report
zero findings on every case in the corpus without a single phase ever being
marked as failed.
"""

import importlib.util
import sys
import types
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def _load(name, relative_path, stubs=None):
    stubs = stubs or {}
    previous = {key: sys.modules.get(key) for key in stubs}
    sys.modules.update(stubs)
    try:
        spec = importlib.util.spec_from_file_location(name, REPO_ROOT / relative_path)
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
        return module
    finally:
        for key, original in previous.items():
            if original is None:
                sys.modules.pop(key, None)
            else:
                sys.modules[key] = original


class _RecordingSession:
    def __init__(self):
        self.added = []
        self.commits = 0

    def add(self, obj):
        self.added.append(obj)

    def commit(self):
        self.commits += 1


def _load_manager():
    session = _RecordingSession()
    stubs = {
        'models.database': types.SimpleNamespace(
            db=types.SimpleNamespace(session=session)
        ),
        'models.behavioral_profiles': types.SimpleNamespace(
            GapDetectionFinding=object,
            GapFindingType=types.SimpleNamespace(),
        ),
    }
    module = _load('stateful_detectors_under_test', 'utils/stateful_detectors/__init__.py', stubs)
    return module, session


detectors_module, _ = _load_manager()


class _Finding:
    def __init__(self, name, confidence=50):
        self.entity_type = 'user'
        self.entity_value = name
        self.confidence = confidence
        self.severity = 'high'
        self.finding_type = 'brute_force'
        self.details = None
        self.evidence = None
        self.summary = f'finding for {name}'


def _detector_module(name, behaviour):
    """Register a real importable module whose detector behaves as instructed."""
    module = types.ModuleType(name)

    class Detector:
        def __init__(self, case_id, analysis_id):
            self.case_id = case_id
            self.analysis_id = analysis_id

        def detect(self):
            if isinstance(behaviour, Exception):
                raise behaviour
            return behaviour

    module.Detector = Detector
    sys.modules[name] = module
    return module


def _manager_with_stages(stage_behaviours):
    """Build a manager whose detector stages behave as instructed.

    `stage_behaviours` maps a detector name to either a list of findings or an
    exception instance to raise. The stages resolve through the real import path
    used in production, so the exception handling under test is genuinely
    exercised rather than bypassed.
    """
    module, session = _load_manager()
    manager = module.GapDetectionManager(case_id=7, analysis_id='analysis-under-test')

    stages = []
    for index, (name, behaviour) in enumerate(stage_behaviours.items()):
        module_path = f'_fake_detector_{abs(hash(name)) % 10000}_{index}'
        _detector_module(module_path, behaviour)
        stages.append({
            'progress_percent': 20 + index,
            'progress_message': f'Running {name}...',
            'module_path': module_path,
            'class_name': 'Detector',
            'log_name': name,
        })

    manager._iter_detector_stages = lambda: tuple(stages)
    return module, manager, session


class DetectorFailureVisibilityTestCase(unittest.TestCase):
    def test_successful_run_reports_no_failures(self):
        _module, manager, _session = _manager_with_stages({
            'Password spraying': [_Finding('a')],
            'Brute force': [_Finding('b')],
        })
        findings = manager.run_all_detectors()

        self.assertFalse(manager.has_failures)
        self.assertEqual(len(findings), 2)
        self.assertEqual(
            [outcome['status'] for outcome in manager.stage_outcomes],
            ['ok', 'ok'],
        )

    def test_crashed_detector_is_recorded_as_failed(self):
        _module, manager, _session = _manager_with_stages({
            'Password spraying': RuntimeError('clickhouse unreachable'),
            'Brute force': [_Finding('b')],
        })
        manager.run_all_detectors()

        self.assertTrue(manager.has_failures)
        self.assertEqual(manager.failed_stages, ['Password spraying'])
        self.assertIn('Password spraying', manager.failure_summary())

    def test_findings_from_healthy_detectors_are_still_kept(self):
        _module, manager, session = _manager_with_stages({
            'Password spraying': RuntimeError('clickhouse unreachable'),
            'Brute force': [_Finding('b')],
        })
        findings = manager.run_all_detectors()

        self.assertEqual(len(findings), 1)
        self.assertEqual(session.commits, 1)

    def test_crash_detail_is_retained_for_reporting(self):
        _module, manager, _session = _manager_with_stages({
            'Behavioral anomaly': RuntimeError('peer group table missing'),
        })
        manager.run_all_detectors()

        failed = [o for o in manager.stage_outcomes if o['status'] == 'failed']
        self.assertEqual(len(failed), 1)
        self.assertIn('peer group table missing', failed[0]['error'])

    def test_zero_findings_without_a_crash_is_not_a_failure(self):
        """A clean run that legitimately finds nothing must stay distinguishable."""
        _module, manager, _session = _manager_with_stages({
            'Password spraying': [],
            'Brute force': [],
        })
        findings = manager.run_all_detectors()

        self.assertEqual(findings, [])
        self.assertFalse(manager.has_failures)


class StageErrorContractTestCase(unittest.TestCase):
    def test_error_carries_findings_and_failed_detector_names(self):
        error = detectors_module.GapDetectionError(
            'incomplete', findings=[_Finding('a')], failed_detectors=['Brute force']
        )

        self.assertEqual(len(error.findings), 1)
        self.assertEqual(error.failed_detectors, ['Brute force'])
        self.assertIsInstance(error, RuntimeError)


class PipelineStageRaisesTestCase(unittest.TestCase):
    """The pipeline entry point must turn a detector failure into a real error."""

    def _load_stage(self, manager_factory):
        fake_detectors = types.ModuleType('utils.stateful_detectors')
        fake_detectors.GapDetectionError = detectors_module.GapDetectionError
        fake_detectors.GapDetectionManager = manager_factory

        return _load(
            'detect_anomalies_under_test',
            'pipeline/detect_anomalies.py',
            {'utils.stateful_detectors': fake_detectors},
        )

    def test_stage_raises_when_a_detector_failed(self):
        class _FailingManager:
            def __init__(self, **_kwargs):
                self.failed_stages = ['Password spraying']

            def run_all_detectors(self):
                return [_Finding('kept')]

            @property
            def has_failures(self):
                return True

            def failure_summary(self):
                return 'Password spraying'

        stage = self._load_stage(_FailingManager)

        with self.assertRaises(detectors_module.GapDetectionError) as caught:
            stage.run_detect_anomalies(case_id=7, analysis_id='analysis-1')

        self.assertEqual(len(caught.exception.findings), 1)
        self.assertEqual(caught.exception.failed_detectors, ['Password spraying'])

    def test_stage_returns_findings_when_every_detector_completed(self):
        class _HealthyManager:
            def __init__(self, **_kwargs):
                self.failed_stages = []

            def run_all_detectors(self):
                return [_Finding('a'), _Finding('b')]

            @property
            def has_failures(self):
                return False

            def failure_summary(self):
                return ''

        stage = self._load_stage(_HealthyManager)
        self.assertEqual(len(stage.run_detect_anomalies(case_id=7, analysis_id='a')), 2)


class OrchestratorDegradesRatherThanAbortsTestCase(unittest.TestCase):
    """A failed detector should degrade the run, not abort the whole analysis.

    The stage raises so the failure cannot be missed, but the orchestrator
    records a failed phase and keeps going, which puts the run into PARTIAL and
    preserves the findings the healthy detectors produced.
    """

    def _analyzer(self, stage_result):
        from tests.phase7_case_analyzer_loader import load_case_analyzer_with_stubs

        case_analyzer, restore = load_case_analyzer_with_stubs(
            'case_analyzer_gap_failure_under_test'
        )
        try:
            fake_stage = types.ModuleType('pipeline.detect_anomalies')
            fake_stage.run_detect_anomalies = stage_result
            fake_pipeline = types.ModuleType('pipeline')
            fake_pipeline.__path__ = []
            fake_pipeline.detect_anomalies = fake_stage

            fake_detectors = types.ModuleType('utils.stateful_detectors')
            fake_detectors.GapDetectionError = detectors_module.GapDetectionError

            analyzer = case_analyzer.CaseAnalyzer.__new__(case_analyzer.CaseAnalyzer)
            analyzer.case_id = 7
            analyzer.analysis_id = 'analysis-under-test'
            analyzer._update_progress = lambda *args, **kwargs: None
            analyzer._gap_progress_callback = lambda *args, **kwargs: None

            previous = {
                key: sys.modules.get(key)
                for key in ('pipeline', 'pipeline.detect_anomalies', 'utils.stateful_detectors')
            }
            sys.modules.update({
                'pipeline': fake_pipeline,
                'pipeline.detect_anomalies': fake_stage,
                'utils.stateful_detectors': fake_detectors,
            })
            try:
                return analyzer._run_gap_detection()
            finally:
                for key, original in previous.items():
                    if original is None:
                        sys.modules.pop(key, None)
                    else:
                        sys.modules[key] = original
        finally:
            if callable(restore):
                restore()

    def test_healthy_run_reports_no_failed_detectors(self):
        findings, failed = self._analyzer(lambda **_kwargs: [_Finding('a')])

        self.assertEqual(len(findings), 1)
        self.assertIsNone(failed)

    def test_failed_detector_is_returned_instead_of_raising(self):
        def _raise(**_kwargs):
            raise detectors_module.GapDetectionError(
                'incomplete',
                findings=[_Finding('kept')],
                failed_detectors=['Password spraying'],
            )

        findings, failed = self._analyzer(_raise)

        self.assertEqual(len(findings), 1, msg='healthy detectors keep their findings')
        self.assertEqual(failed, ['Password spraying'])


if __name__ == '__main__':
    unittest.main()
