import importlib.util
import os
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

os.environ.setdefault('SECRET_KEY', 'test-secret')

MODULE_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'utils', 'rebuilds.py')
SPEC = importlib.util.spec_from_file_location('rebuilds_under_test', MODULE_PATH)
rebuilds = importlib.util.module_from_spec(SPEC)

fake_utils_pkg = types.ModuleType('utils')
fake_artifact_paths = types.ModuleType('utils.artifact_paths')
fake_artifact_paths.copy_to_directory = lambda source_path, dest_dir, filename=None: source_path
fake_artifact_paths.ensure_case_artifact_paths = lambda case_uuid: {}
fake_artifact_paths.ensure_directory = lambda path: (os.makedirs(path, exist_ok=True) or path)
fake_artifact_paths.is_within_root = lambda path, root: bool(path and root) and (
    os.path.realpath(path) == os.path.realpath(root)
    or os.path.realpath(path).startswith(os.path.realpath(root) + os.sep)
)
fake_utils_pkg.artifact_paths = fake_artifact_paths
sys.modules.setdefault('utils', fake_utils_pkg)
sys.modules['utils.artifact_paths'] = fake_artifact_paths

SPEC.loader.exec_module(rebuilds)


class RebuildHelpersTestCase(unittest.TestCase):
    def test_ensure_case_rebuild_workspace_uses_artifact_specific_roots(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            artifact_paths = {
                'rebuild_upload': os.path.join(tmpdir, 'uploads', 'web', 'case-1', '_rebuild'),
                'pcap_rebuild_upload': os.path.join(tmpdir, 'uploads', 'pcap', 'case-1', '_rebuild'),
                'memory_rebuild_upload': os.path.join(tmpdir, 'uploads', 'sftp', 'case-1', 'memory', '_rebuild'),
            }
            with patch.object(rebuilds, 'ensure_case_artifact_paths', return_value=artifact_paths):
                standard = rebuilds.ensure_case_rebuild_workspace('case-1', 'standard', 'run-a')
                pcap = rebuilds.ensure_case_rebuild_workspace('case-1', 'pcap', 'run-b')
                memory = rebuilds.ensure_case_rebuild_workspace('case-1', 'memory', 'run-c')

            self.assertTrue(standard.endswith(os.path.join('_rebuild', 'run-a')))
            self.assertTrue(pcap.endswith(os.path.join('_rebuild', 'run-b')))
            self.assertTrue(memory.endswith(os.path.join('_rebuild', 'run-c')))
            self.assertTrue(os.path.isdir(standard))
            self.assertTrue(os.path.isdir(pcap))
            self.assertTrue(os.path.isdir(memory))

    def test_resolve_standard_rebuild_target_for_standalone_file(self):
        case_file = types.SimpleNamespace(
            source_path='/retained/file.evtx',
            file_path=None,
            is_extracted=False,
            parent=None,
        )
        case_paths = {'originals': '/retained'}
        with patch.object(rebuilds, 'ensure_case_artifact_paths', return_value=case_paths):
            target = rebuilds.resolve_standard_rebuild_target(case_file, 'case-1', 'parent_archive')

        self.assertEqual(target['mode'], rebuilds.STANDARD_REBUILD_MODE_STANDALONE)
        self.assertEqual(target['source_path'], '/retained/file.evtx')
        self.assertFalse(target['delete_parent_family'])

    def test_resolve_standard_rebuild_target_for_extracted_child_modes(self):
        parent = types.SimpleNamespace(
            id=22,
            original_filename='bundle.zip',
            source_path='/retained/bundle.zip',
            file_path=None,
        )
        case_file = types.SimpleNamespace(
            filename='bundle.zip/folder/child.evtx',
            original_filename='child.evtx',
            source_path=None,
            file_path=None,
            is_extracted=True,
            parent=parent,
        )
        case_paths = {'originals': '/retained'}
        with patch.object(rebuilds, 'ensure_case_artifact_paths', return_value=case_paths):
            single_member = rebuilds.resolve_standard_rebuild_target(
                case_file,
                'case-1',
                rebuilds.STANDARD_REBUILD_MODE_SINGLE_MEMBER,
            )
            parent_archive = rebuilds.resolve_standard_rebuild_target(
                case_file,
                'case-1',
                rebuilds.STANDARD_REBUILD_MODE_PARENT_ARCHIVE,
            )

        self.assertEqual(single_member['mode'], rebuilds.STANDARD_REBUILD_MODE_SINGLE_MEMBER)
        self.assertEqual(single_member['selected_member'], 'folder/child.evtx')
        self.assertEqual(single_member['parent_record'], parent)
        self.assertFalse(single_member['delete_parent_family'])

        self.assertEqual(parent_archive['mode'], rebuilds.STANDARD_REBUILD_MODE_PARENT_ARCHIVE)
        self.assertTrue(parent_archive['delete_parent_family'])
        self.assertEqual(parent_archive['source_path'], '/retained/bundle.zip')


if __name__ == '__main__':
    unittest.main()
