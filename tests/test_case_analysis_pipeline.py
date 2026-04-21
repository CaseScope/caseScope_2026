import importlib.util
import sys
import types
import unittest
from datetime import datetime, timedelta
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def _load_module(name: str, relative_path: str):
    module_path = REPO_ROOT / relative_path
    spec = importlib.util.spec_from_file_location(name, module_path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class CaseAnalysisPipelineTestCase(unittest.TestCase):
    def test_finalize_persists_phase_outcomes_and_degraded_reasons(self):
        fake_db = types.SimpleNamespace(session=types.SimpleNamespace(commit=lambda: None))
        analysis_summary_module = types.ModuleType('utils.analysis_summary')
        analysis_summary_module.summarize_findings = lambda _findings: {
            'total_findings': 2,
            'critical_findings': 0,
            'high_findings': 1,
            'medium_findings': 1,
            'low_findings': 0,
            'high_confidence_findings': 1,
            'severity_breakdown': {'high': 1, 'medium': 1},
            'top_findings': [{'name': 'demo'}],
        }
        unified_store_module = types.ModuleType('utils.unified_findings_store')
        unified_store_module.sync_case_findings = lambda *_args, **_kwargs: 2

        previous_modules = {
            name: sys.modules.get(name)
            for name in (
                'models.database',
                'models.behavioral_profiles',
                'utils.analysis_summary',
                'utils.unified_findings_store',
            )
        }
        sys.modules['models.database'] = types.SimpleNamespace(db=fake_db)
        sys.modules['models.behavioral_profiles'] = types.SimpleNamespace(
            AnalysisStatus=types.SimpleNamespace(COMPLETE='complete', PARTIAL='partial', FAILED='failed')
        )
        sys.modules['utils.analysis_summary'] = analysis_summary_module
        sys.modules['utils.unified_findings_store'] = unified_store_module

        try:
            case_finalize = _load_module(
                'case_finalize_under_test',
                'pipeline/case_finalize.py',
            )
        finally:
            for name, previous in previous_modules.items():
                if previous is None:
                    sys.modules.pop(name, None)
                else:
                    sys.modules[name] = previous

        analysis_run = types.SimpleNamespace(
            mode='B',
            started_at=datetime(2026, 4, 21, 10, 0, 0),
            completed_at=None,
            last_progress_at=None,
            progress_percent=0,
            current_phase='',
            partial_results_available=False,
            error_message=None,
            findings_generated=0,
            high_confidence_findings=0,
            users_profiled=0,
            systems_profiled=0,
            peer_groups_created=0,
            patterns_evaluated=0,
            gap_findings=0,
            attack_chains_found=0,
            patterns_analyzed=0,
            status='running',
            summary={},
        )
        phase_outcomes = {'pattern_analysis': {'success': True}}
        degraded_reasons = ['IOC timeline build failed']

        result = case_finalize.finalize_case_analysis_run(
            analysis_run,
            case_id=9,
            analysis_id='analysis-9',
            all_findings=[{'name': 'a'}, {'name': 'b'}],
            profiling_stats={'users_profiled': 1, 'system_groups': 1},
            pattern_results=[{'pattern_id': 'p1'}],
            gap_findings=[{'finding_type': 'gap'}],
            hayabusa_findings=[{'name': 'h1'}],
            attack_chains=[{'chain': 'c1'}],
            census={'4624': 3},
            ioc_timeline={'entries': [{'ioc': 'evil'}]},
            storyline_results={'storylines': [{'title': 'story'}]},
            triage_result={},
            synthesis_result={},
            phase_outcomes=phase_outcomes,
            degraded_reasons=degraded_reasons,
            start_time=datetime.utcnow() - timedelta(seconds=5),
        )

        self.assertTrue(result)
        self.assertEqual(analysis_run.summary['phase_outcomes'], phase_outcomes)
        self.assertEqual(analysis_run.summary['degraded_reasons'], degraded_reasons)
        self.assertEqual(analysis_run.summary['attack_chains'], 1)

    def test_formatter_summary_returns_run_phase_contract(self):
        fake_query = types.SimpleNamespace(filter_by=lambda **_kwargs: types.SimpleNamespace(first=lambda: None))
        behavior_module = types.SimpleNamespace(
            CaseAnalysisRun=types.SimpleNamespace(query=fake_query),
            AnalysisMode=types.SimpleNamespace(),
            AnalysisStatus=types.SimpleNamespace(),
            UserBehaviorProfile=type('UserBehaviorProfile', (), {}),
            SystemBehaviorProfile=type('SystemBehaviorProfile', (), {}),
            PeerGroup=type('PeerGroup', (), {}),
            GapDetectionFinding=type('GapDetectionFinding', (), {'query': fake_query}),
            SuggestedAction=type('SuggestedAction', (), {'query': fake_query}),
        )
        analysis_summary_module = types.ModuleType('utils.analysis_summary')
        analysis_summary_module.summarize_findings = lambda _findings: {
            'total_findings': 1,
            'severity_breakdown': {'high': 1},
            'top_findings': [{'name': 'gap'}],
            'high_confidence_findings': 1,
        }
        finding_contract_module = types.ModuleType('utils.finding_contract')
        finding_contract_module.build_score_display_context = lambda **_kwargs: {}

        previous_modules = {
            name: sys.modules.get(name)
            for name in (
                'models.database',
                'models.behavioral_profiles',
                'utils.analysis_summary',
                'utils.finding_contract',
            )
        }
        sys.modules['models.database'] = types.SimpleNamespace(db=types.SimpleNamespace(session=None))
        sys.modules['models.behavioral_profiles'] = behavior_module
        sys.modules['utils.analysis_summary'] = analysis_summary_module
        sys.modules['utils.finding_contract'] = finding_contract_module

        try:
            formatter_module = _load_module(
                'analysis_results_formatter_under_test',
                'utils/analysis_results_formatter.py',
            )
        finally:
            for name, previous in previous_modules.items():
                if previous is None:
                    sys.modules.pop(name, None)
                else:
                    sys.modules[name] = previous

        formatter = formatter_module.AnalysisResultsFormatter('analysis-11')
        formatter._analysis_run = types.SimpleNamespace(
            case_id=11,
            mode='B',
            status='complete',
            started_at=datetime(2026, 4, 21, 10, 0, 0),
            completed_at=datetime(2026, 4, 21, 10, 1, 0),
            users_profiled=2,
            systems_profiled=1,
            peer_groups_created=1,
            patterns_analyzed=3,
            attack_chains_found=1,
            summary={
                'total_findings': 1,
                'phase_outcomes': {'pattern_analysis': {'success': True}},
                'degraded_reasons': ['IOC timeline build failed'],
                'severity_breakdown': {'high': 1},
                'top_findings': [{'name': 'gap'}],
                'high_confidence_findings': 1,
                'storyline_findings': 0,
            },
        )
        formatter._gap_findings = [types.SimpleNamespace()]
        formatter._pattern_results = []
        formatter._suggested_actions = [types.SimpleNamespace(status='pending')]

        summary = formatter.get_summary()

        self.assertEqual(summary['phase_outcomes'], {'pattern_analysis': {'success': True}})
        self.assertEqual(summary['degraded_reasons'], ['IOC timeline build failed'])
        self.assertEqual(summary['statistics']['total_findings'], 1)


if __name__ == '__main__':
    unittest.main()
