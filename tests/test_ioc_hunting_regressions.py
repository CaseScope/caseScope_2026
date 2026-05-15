import os
import unittest

from parsers import catalog as catalog_module


REPO_ROOT = os.path.dirname(os.path.dirname(__file__))


class IOCHuntingRegressionTestCase(unittest.TestCase):
    def test_browser_tab_includes_browser_download_artifacts(self):
        self.assertIn('browser_download', catalog_module.HUNTING_TAB_TYPES['browsers'])

    def test_catalog_routes_case37_text_artifacts_to_expected_tabs(self):
        self.assertIn('powershell_history', catalog_module.HUNTING_TAB_TYPES['events'])
        self.assertIn('hosts', catalog_module.HUNTING_TAB_TYPES['activity'])
        self.assertIn('setupapi', catalog_module.HUNTING_TAB_TYPES['filesystem'])
        self.assertIn('usn', catalog_module.HUNTING_TAB_TYPES['filesystem'])
        self.assertNotIn('powershell_history', catalog_module.HUNTING_TAB_TYPES['filesystem'])
        self.assertNotIn('hosts', catalog_module.HUNTING_TAB_TYPES['filesystem'])
        self.assertNotIn('hosts', catalog_module.HUNTING_TAB_TYPES['events'])

    def test_browser_downloads_endpoint_uses_stored_ioc_types(self):
        source_path = os.path.join(REPO_ROOT, 'utils', 'forensic_chat_sources.py')
        with open(source_path, 'r', encoding='utf-8') as handle:
            content = handle.read()

        self.assertIn("e.artifact_type = 'browser_download'", content)
        self.assertIn('ioc_types', content)
        self.assertIn("'has_ioc': bool(ioc_types)", content)
        self.assertNotIn('ioc_filenames', content)

    def test_hunting_search_supports_preserved_firewall_ip_fields(self):
        helper_path = os.path.join(REPO_ROOT, 'routes', 'hunting_query_helpers.py')
        with open(helper_path, 'r', encoding='utf-8') as handle:
            content = handle.read()

        self.assertIn('"src_ip_raw": ("src_ip_raw", "blob")', content)
        self.assertIn('"dst_ip_raw": ("dst_ip_raw", "blob")', content)
        self.assertIn('"src_nat_ip": ("src_nat_ip", "blob")', content)
        self.assertIn('"dst_nat_ip": ("dst_nat_ip", "blob")', content)
        self.assertIn("_build_ip_field_search_condition", content)

    def test_event_detail_shows_preserved_network_fields(self):
        template_path = os.path.join(REPO_ROOT, 'static', 'templates', 'case_hunting.html')
        with open(template_path, 'r', encoding='utf-8') as handle:
            content = handle.read()

        self.assertIn('Source IP (raw)', content)
        self.assertIn('Dest IP (raw)', content)
        self.assertIn('Source NAT IP', content)
        self.assertIn('Dest NAT IP', content)

    def test_hunt_patterns_modal_calls_existing_detail_function(self):
        template_path = os.path.join(REPO_ROOT, 'static', 'templates', 'case_hunting.html')
        with open(template_path, 'r', encoding='utf-8') as handle:
            content = handle.read()

        self.assertIn("typeof showPatternRuleDetails === 'function'", content)
        self.assertNotIn("typeof showPatternRulesDetail === 'function'", content)

    def test_hunt_patterns_modal_uses_dynamic_pattern_count(self):
        template_path = os.path.join(REPO_ROOT, 'static', 'templates', 'hunting', 'tab_events.html')
        with open(template_path, 'r', encoding='utf-8') as handle:
            content = handle.read()

        self.assertIn('id="huntPatternsAvailable"', content)
        self.assertNotIn('using 58 rule-based', content)
        self.assertNotIn('<span class="hunt-stat-value">58</span>', content)

    def test_hunt_patterns_modal_initializes_time_handler_once(self):
        template_path = os.path.join(REPO_ROOT, 'static', 'templates', 'case_hunting.html')
        with open(template_path, 'r', encoding='utf-8') as handle:
            content = handle.read()

        self.assertIn('let huntPatternsTimeRangeInitialized = false', content)
        self.assertIn('if (!huntPatternsTimeRangeInitialized)', content)

    def test_completion_task_persists_ingest_summary_inside_app_context(self):
        task_path = os.path.join(REPO_ROOT, 'tasks', 'celery_tasks.py')
        with open(task_path, 'r', encoding='utf-8') as handle:
            content = handle.read()

        self.assertIn("with app.app_context():", content)
        self.assertIn("AuditLog.log(", content)
        self.assertIn("entity_name='Case file ingest summary'", content)


if __name__ == '__main__':
    unittest.main()
