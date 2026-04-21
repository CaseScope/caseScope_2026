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


ioc_text = _load_module(
    'phase5_ioc_text',
    os.path.join('utils', 'ioc_text.py'),
)
ioc_extractor = _load_module(
    'phase5_ioc_extractor',
    os.path.join('utils', 'ioc_extractor.py'),
)


class Phase5IOCTextContractTestCase(unittest.TestCase):
    def test_text_helpers_handle_defang_and_huntress_path_cleanup(self):
        self.assertEqual(
            ioc_text._defang_text('hxxps://evil[.]example/path'),
            'https://evil.example/path',
        )
        value, note = ioc_text._normalize_extracted_file_path(
            r'C:\Users\me\payload.exe (Quarantined by Microsoft Defender)'
        )
        self.assertEqual(value, r'C:\Users\me\payload.exe')
        self.assertEqual(note, 'Quarantined by Microsoft Defender')

    def test_ioc_extractor_routes_deterministic_text_helpers_through_ioc_text(self):
        fake_ioc_text = type(
            "FakeIOCText",
            (),
            {
                "_defang_text": staticmethod(lambda value: f"defanged::{value}"),
                "_normalize_extracted_file_path": staticmethod(
                    lambda value: (f"normalized::{value}", "shared-note")
                ),
            },
        )()

        with patch.object(ioc_extractor, "_ioc_text", fake_ioc_text):
            self.assertEqual(
                ioc_extractor._defang_text("hxxp://bad[.]example"),
                "defanged::hxxp://bad[.]example",
            )
            self.assertEqual(
                ioc_extractor._normalize_extracted_file_path(r"C:\Temp\payload.exe"),
                (r"normalized::C:\Temp\payload.exe", "shared-note"),
            )

        self.assertIn("run_deterministic_ioc_extraction", ioc_extractor.__all__)


if __name__ == '__main__':
    unittest.main()
