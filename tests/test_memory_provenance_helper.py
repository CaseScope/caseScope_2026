import importlib.util
import os
import sys
import types
import unittest


BASE_DIR = os.path.dirname(os.path.dirname(__file__))


def _load_module(name, relative_path):
    spec = importlib.util.spec_from_file_location(name, os.path.join(BASE_DIR, relative_path))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class MemoryProvenanceHelperTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        utils_package = types.ModuleType('utils')
        utils_package.__path__ = []
        sys.modules.setdefault('utils', utils_package)

        provenance_module = _load_module('utils.provenance', os.path.join('utils', 'provenance.py'))
        sys.modules['utils.provenance'] = provenance_module
        utils_package.provenance = provenance_module

        cls.memory_provenance = _load_module('utils.memory_provenance', os.path.join('utils', 'memory_provenance.py'))
        sys.modules['utils.memory_provenance'] = cls.memory_provenance
        utils_package.memory_provenance = cls.memory_provenance

    def test_annotate_memory_record_emits_parser_and_field_provenance(self):
        record = self.memory_provenance.annotate_memory_record(
            {
                'job_id': 77,
                'hostname': 'HOST-1',
                'pid': 4242,
                'cmdline': 'cmd.exe /c whoami',
            },
            artifact_type='memory_process',
        )

        self.assertEqual(record['field_provenance']['job_id'], 'SYSTEM_DERIVED')
        self.assertEqual(record['field_provenance']['pid'], 'SYSTEM_DERIVED')
        self.assertEqual(record['field_provenance']['cmdline'], 'ARTIFACT_TAINTED')
        self.assertEqual(record['emitted_provenance'], 'ARTIFACT_TAINTED')
        self.assertEqual(record['_provenance']['parser_name'], 'memory_parser')
        self.assertEqual(record['_provenance']['parser_version'], '1.0.1')
        self.assertEqual(record['_provenance']['artifact_family'], 'memory')

    def test_annotate_memory_record_preserves_stored_row_provenance(self):
        record = self.memory_provenance.annotate_memory_record(
            {
                'job_id': 77,
                'hostname': 'HOST-1',
                'pid': 4242,
            },
            artifact_type='memory_process',
            stored_provenance={
                'plugin_name': 'windows_pslist',
                'source_plugin': 'windows_pslist',
            },
        )

        self.assertEqual(record['_provenance']['plugin_name'], 'windows_pslist')
        self.assertEqual(record['_provenance']['source_plugin'], 'windows_pslist')


if __name__ == '__main__':
    unittest.main()
