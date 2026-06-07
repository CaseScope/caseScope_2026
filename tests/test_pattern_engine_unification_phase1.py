import os
import unittest


REPO_ROOT = os.path.dirname(os.path.dirname(__file__))


def _read_repo_file(relative_path):
    with open(os.path.join(REPO_ROOT, relative_path), "r", encoding="utf-8") as handle:
        return handle.read()


class PatternEngineUnificationPhase1TestCase(unittest.TestCase):
    def test_legacy_task_is_disabled_archive_only_contract(self):
        source = _read_repo_file("tasks/rag_tasks.py")
        task_start = source.index("def detect_attack_patterns(")
        task_end = source.index("@celery_app.task(bind=True, name='tasks.ai_pattern_correlation')")
        task_source = source[task_start:task_end]

        self.assertIn("'disabled': True", task_source)
        self.assertIn("'archive_only': True", task_source)
        self.assertIn("'replacement': 'scoring_2_0'", task_source)
        self.assertNotIn("PatternRuleMatch(", task_source)
        self.assertNotIn(".delete()", task_source)
        self.assertNotIn("db.session.add", task_source)

    def test_legacy_counts_are_isolated_from_current_analysis_stats(self):
        source = _read_repo_file("routes/case_files.py")

        self.assertIn('analysis_stats["pattern_rule_matches"] = 0', source)
        self.assertIn('analysis_stats["legacy_pattern_rule_matches"]', source)

    def test_current_pattern_modal_uses_final_score_label(self):
        source = _read_repo_file("static/templates/case_hunting.html")
        current_modal_start = source.index("function showAICorrelationDetail")
        current_modal_end = source.index("function showAICorrelationError")
        current_modal_source = source[current_modal_start:current_modal_end]

        self.assertIn("Final Score", current_modal_source)
        self.assertNotIn("AI Confidence", current_modal_source)


if __name__ == "__main__":
    unittest.main()
