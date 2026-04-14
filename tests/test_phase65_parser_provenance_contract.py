import os
import unittest
from pathlib import Path


REPO_ROOT = os.path.dirname(os.path.dirname(__file__))


class Phase65ParserProvenanceContractTestCase(unittest.TestCase):
    def test_parsed_event_emits_parser_provenance_metadata(self):
        with open(
            os.path.join(REPO_ROOT, 'parsers', 'base.py'),
            'r',
            encoding='utf-8',
        ) as handle:
            source = handle.read()

        self.assertIn("def _build_parser_provenance(self) -> Dict[str, Any]:", source)
        self.assertIn("'provenance_source': 'parser_emitted'", source)
        self.assertIn("payload['field_provenance']", source)
        self.assertIn("payload['emitted_provenance']", source)

    def test_runtime_surfaces_merge_parser_emitted_provenance(self):
        forensic_source = Path(
            os.path.join(REPO_ROOT, 'utils', 'forensic_chat_sources.py'),
        ).read_text(encoding='utf-8')
        chat_tools_source = Path(
            os.path.join(REPO_ROOT, 'utils', 'chat_tools.py'),
        ).read_text(encoding='utf-8')

        self.assertIn('apply_record_provenance', forensic_source)
        self.assertIn('_merge_extra_field_provenance', forensic_source)
        self.assertIn('artifact_type_key=\'_artifact_type\'', forensic_source)
        self.assertIn('apply_record_provenance', chat_tools_source)
        self.assertIn('artifact_type_key="_artifact_type"', chat_tools_source)


if __name__ == '__main__':
    unittest.main()
