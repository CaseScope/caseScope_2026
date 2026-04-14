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


ioc_text = _load_module(
    'phase5_ioc_text',
    os.path.join('utils', 'ioc_text.py'),
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
        with open(
            os.path.join(REPO_ROOT, 'utils', 'ioc_extractor.py'),
            'r',
            encoding='utf-8',
        ) as handle:
            source = handle.read()

        self.assertIn('_ioc_text = _LazyModuleProxy("ioc_text_shared", "ioc_text.py")', source)
        self.assertIn('return _ioc_text._defang_text(value)', source)
        self.assertIn('return _ioc_text._normalize_extracted_file_path(value)', source)
        self.assertIn('"run_deterministic_ioc_extraction"', source)


if __name__ == '__main__':
    unittest.main()
