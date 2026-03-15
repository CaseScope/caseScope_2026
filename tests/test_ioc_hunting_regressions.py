import os
import unittest


REPO_ROOT = os.path.dirname(os.path.dirname(__file__))


class IOCHuntingRegressionTestCase(unittest.TestCase):
    def test_browser_tab_includes_browser_download_artifacts(self):
        template_path = os.path.join(REPO_ROOT, 'static', 'templates', 'case_hunting.html')
        with open(template_path, 'r', encoding='utf-8') as handle:
            content = handle.read()

        self.assertIn('data-tab="browsers"', content)
        self.assertIn('browser_download', content)

    def test_filesystem_tab_includes_case37_text_artifacts(self):
        template_path = os.path.join(REPO_ROOT, 'static', 'templates', 'case_hunting.html')
        with open(template_path, 'r', encoding='utf-8') as handle:
            content = handle.read()

        self.assertIn('data-tab="filesystem"', content)
        self.assertIn('powershell_history', content)
        self.assertIn('hosts', content)
        self.assertIn('setupapi', content)

    def test_browser_downloads_endpoint_uses_stored_ioc_types(self):
        api_path = os.path.join(REPO_ROOT, 'routes', 'api.py')
        with open(api_path, 'r', encoding='utf-8') as handle:
            content = handle.read()

        self.assertIn("artifact_type = 'browser_download'", content)
        self.assertIn('ioc_types', content)
        self.assertIn("'has_ioc': len(ioc_type_list) > 0", content)
        self.assertNotIn('ioc_filenames', content)

    def test_hunting_search_supports_preserved_firewall_ip_fields(self):
        api_path = os.path.join(REPO_ROOT, 'routes', 'api.py')
        with open(api_path, 'r', encoding='utf-8') as handle:
            content = handle.read()

        self.assertIn("'src_ip_raw': ('src_ip_raw', 'blob')", content)
        self.assertIn("'dst_ip_raw': ('dst_ip_raw', 'blob')", content)
        self.assertIn("'src_nat_ip': ('src_nat_ip', 'blob')", content)
        self.assertIn("'dst_nat_ip': ('dst_nat_ip', 'blob')", content)
        self.assertIn("_build_ip_field_search_condition", content)

    def test_event_detail_shows_preserved_network_fields(self):
        template_path = os.path.join(REPO_ROOT, 'static', 'templates', 'case_hunting.html')
        with open(template_path, 'r', encoding='utf-8') as handle:
            content = handle.read()

        self.assertIn('Source IP (raw)', content)
        self.assertIn('Dest IP (raw)', content)
        self.assertIn('Source NAT IP', content)
        self.assertIn('Dest NAT IP', content)

    def test_completion_task_persists_ingest_summary_inside_app_context(self):
        task_path = os.path.join(REPO_ROOT, 'tasks', 'celery_tasks.py')
        with open(task_path, 'r', encoding='utf-8') as handle:
            content = handle.read()

        self.assertIn("with app.app_context():", content)
        self.assertIn("AuditLog.log(", content)
        self.assertIn("entity_name='Case file ingest summary'", content)


if __name__ == '__main__':
    unittest.main()
