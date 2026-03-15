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


if __name__ == '__main__':
    unittest.main()
