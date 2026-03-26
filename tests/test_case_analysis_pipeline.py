import pathlib
import unittest


REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]


class CaseAnalysisPipelineTestCase(unittest.TestCase):
    def test_parallel_phase_results_keep_attack_chain_summaries(self):
        content = (REPO_ROOT / 'utils' / 'case_analyzer.py').read_text()

        self.assertIn("self._attack_chains = sub_result.get('attack_chain_summaries', []) or []", content)
        self.assertIn("'phase_outcomes': self._phase_outcomes", content)
        self.assertIn("self._record_phase_outcome(", content)
        self.assertIn("self._all_findings.extend(self._pattern_results)", content)
        self.assertIn("self._storyline_results = self._run_incident_storylines()", content)
        self.assertIn("with allow_join_result():", content)
        self.assertIn("self._analysis_run.summary = self._make_json_safe(summary)", content)
        self.assertIn("db.session.rollback()", content)
        self.assertIn("value.replace('\\x00', '')", content)

    def test_status_response_includes_phase_outcomes(self):
        content = (REPO_ROOT / 'routes' / 'analysis.py').read_text()
        self.assertIn("response['phase_outcomes'] = run.summary.get('phase_outcomes', {})", content)
        self.assertIn("response['degraded_reasons'] = run.summary.get('degraded_reasons', [])", content)

    def test_formatter_summary_exposes_phase_outcomes(self):
        formatter_content = (REPO_ROOT / 'utils' / 'analysis_results_formatter.py').read_text()
        task_content = (REPO_ROOT / 'tasks' / 'rag_tasks.py').read_text()

        self.assertIn("'phase_outcomes': run_summary.get('phase_outcomes', {})", formatter_content)
        self.assertIn("'degraded_reasons': run_summary.get('degraded_reasons', [])", formatter_content)
        self.assertIn("'attack_chain_summaries': [", task_content)
        self.assertIn("'duration_seconds': round(time.time() - started, 3)", task_content)


if __name__ == '__main__':
    unittest.main()
