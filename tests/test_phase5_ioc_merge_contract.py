import importlib.util
import os
import unittest


REPO_ROOT = os.path.dirname(os.path.dirname(__file__))


def _load_module(name: str, relative_path: str):
    module_path = os.path.join(REPO_ROOT, relative_path)
    spec = importlib.util.spec_from_file_location(name, module_path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


ioc_merge = _load_module(
    'phase5_ioc_merge',
    os.path.join('utils', 'ioc_merge.py'),
)


class Phase5IOCMergeContractTestCase(unittest.TestCase):
    def test_merge_extractions_prefers_ai_and_deduplicates_regex_overlap(self):
        merged = ioc_merge.merge_extractions(
            {
                'extraction_summary': {'method': 'semantic'},
                'iocs': {
                    'domains': [{'value': 'evil.example', 'context': 'ai'}],
                    'urls': [{'value': 'https://evil.example/path'}],
                },
                'raw_artifacts': {'screenconnect_ids': ['abc123']},
            },
            {
                'iocs': {
                    'domains': [{'value': 'evil.example', 'context': 'regex'}],
                    'urls': [{'value': 'https://evil.example/path'}],
                    'hashes': [{'type': 'sha256', 'value': 'a' * 64}],
                },
                'raw_artifacts': {'screenconnect_ids': ['abc123', 'def456']},
            },
        )

        self.assertEqual(len(merged['iocs']['domains']), 1)
        self.assertEqual(merged['iocs']['domains'][0]['context'], 'ai')
        self.assertEqual(len(merged['iocs']['urls']), 1)
        self.assertEqual(merged['iocs']['hashes'][0]['type'], 'sha256')
        self.assertEqual(
            merged['raw_artifacts']['screenconnect_ids'],
            ['abc123', 'def456'],
        )

    def test_ioc_extractor_uses_shared_merge_surface(self):
        with open(
            os.path.join(REPO_ROOT, 'utils', 'ioc_extractor.py'),
            'r',
            encoding='utf-8',
        ) as handle:
            source = handle.read()

        self.assertIn('return _ioc_merge.merge_extraction_summaries(primary, secondary)', source)
        self.assertIn('return _ioc_merge.merge_ai_extractions(primary, secondary)', source)
        self.assertIn('return _ioc_merge.merge_extractions(ai, regex)', source)
        self.assertIn('return _ioc_merge.extract_dedup_key(item)', source)


if __name__ == '__main__':
    unittest.main()
