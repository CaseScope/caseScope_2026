import importlib.util
import os
import unittest


REPO_ROOT = os.path.dirname(os.path.dirname(__file__))


class IOCHuntressExtractorRegressionTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        module_path = os.path.join(REPO_ROOT, 'utils', 'ioc_extractor.py')
        spec = importlib.util.spec_from_file_location('ioc_extractor_under_test', module_path)
        cls.extractor_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.extractor_module)

    def _read_report(self, name):
        report_path = os.path.join(REPO_ROOT, 'example_reports', 'huntress', name)
        with open(report_path, 'r', encoding='utf-8') as handle:
            return handle.read()

    def test_regex_extractor_strips_huntress_sha256_suffixes_from_file_paths(self):
        extractor = self.extractor_module.RegexIOCExtractor()

        for report_name in ('report2.txt', 'report4.txt', 'report8.txt'):
            with self.subTest(report=report_name):
                file_paths = {
                    item['value']
                    for item in extractor.extract(self._read_report(report_name))['iocs']['file_paths']
                }
                self.assertTrue(file_paths)
                self.assertFalse(
                    any('+ sha256' in path.lower() for path in file_paths),
                    msg=f"Unexpected Huntress sha256 suffix remained in {report_name}",
                )

    def test_regex_extractor_moves_quarantine_note_into_context(self):
        extractor = self.extractor_module.RegexIOCExtractor()
        report = (
            'File System\n'
            'FILE: C:\\Users\\robertss\\Downloads\\p11341.exe (Quarantined by Microsoft Defender)\n'
        )

        file_paths = extractor.extract(report)['iocs']['file_paths']

        self.assertEqual(len(file_paths), 1)
        self.assertEqual(file_paths[0]['value'], r'C:\Users\robertss\Downloads\p11341.exe')
        self.assertEqual(file_paths[0]['context'], 'Quarantined by Microsoft Defender')

    def test_ai_file_name_normalizer_strips_huntress_annotations(self):
        normalize_file_name = self.extractor_module._normalize_ai_file_name

        self.assertEqual(
            normalize_file_name('document.pdf + sha256: abc123'),
            'document.pdf',
        )
        self.assertEqual(
            normalize_file_name('p11341.exe (Quarantined by Microsoft Defender)'),
            'p11341.exe',
        )

    def test_alias_generation_uses_clean_file_path_basename(self):
        alias_result = self.extractor_module.generate_ioc_with_aliases(
            r'C:\Users\robertss\Downloads\document.pdf + sha256: abc123',
            'File Path',
        )

        self.assertEqual(alias_result['primary_value'], 'document.pdf')
        self.assertEqual(
            alias_result['aliases'],
            [r'c:\users\robertss\downloads\document.pdf'],
        )


if __name__ == '__main__':
    unittest.main()
