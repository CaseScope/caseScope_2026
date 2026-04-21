import importlib.util
import os
import unittest
from unittest.mock import patch


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
ioc_extractor = _load_module(
    'phase5_ioc_extractor_merge_contract',
    os.path.join('utils', 'ioc_extractor.py'),
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
        fake_merge = type(
            "FakeMerge",
            (),
            {
                "merge_extraction_summaries": staticmethod(
                    lambda primary, secondary: {"summary": (primary, secondary)}
                ),
                "merge_ai_extractions": staticmethod(
                    lambda primary, secondary: {"ai_merge": (primary, secondary)}
                ),
                "merge_extractions": staticmethod(
                    lambda ai, regex: {"merged": (ai, regex)}
                ),
                "extract_dedup_key": staticmethod(lambda item: f"dedup::{item}"),
            },
        )()

        with patch.object(ioc_extractor, "_ioc_merge", fake_merge):
            self.assertEqual(
                ioc_extractor._merge_summary_dicts({"a": 1}, {"b": 2}),
                {"summary": ({"a": 1}, {"b": 2})},
            )
            self.assertEqual(
                ioc_extractor._merge_ai_extractions({"a": 1}, {"b": 2}),
                {"ai_merge": ({"a": 1}, {"b": 2})},
            )
            self.assertEqual(
                ioc_extractor._merge_extractions({"ai": 1}, {"regex": 2}),
                {"merged": ({"ai": 1}, {"regex": 2})},
            )
            self.assertEqual(
                ioc_extractor._extract_dedup_key("demo"),
                "dedup::demo",
            )

    def test_ioc_extractor_alias_generation_uses_shared_alias_helper(self):
        fake_aliasing = type(
            "FakeAliasing",
            (),
            {
                "generate_ioc_with_aliases": staticmethod(
                    lambda value, ioc_type: {
                        "primary_value": f"{ioc_type}:{value}",
                        "primary_type": "File Name",
                        "aliases": ["alias-one"],
                        "original_value": value,
                    }
                ),
            },
        )()

        with patch.object(ioc_extractor, "_ioc_aliasing", fake_aliasing):
            self.assertEqual(
                ioc_extractor.generate_ioc_with_aliases("demo.exe", "File Path"),
                {
                    "primary_value": "File Path:demo.exe",
                    "primary_type": "File Name",
                    "aliases": ["alias-one"],
                    "original_value": "demo.exe",
                },
            )

    def test_ioc_extractor_declares_supported_public_boundary(self):
        self.assertEqual(
            ioc_extractor.__all__,
            [
                "RegexIOCExtractor",
                "extract_derived_indicator_candidates",
                "run_deterministic_ioc_extraction",
                "run_ioc_pipeline_with_provider",
                "extract_iocs_with_ai",
                "process_extraction_for_import",
                "save_extracted_iocs",
                "split_edr_reports",
                "get_report_preview",
            ],
        )


if __name__ == '__main__':
    unittest.main()
