import os
import importlib.util
import tempfile
import unittest
from unittest.mock import patch

os.environ.setdefault('SECRET_KEY', 'test-secret')

MODULE_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'utils', 'artifact_paths.py')
SPEC = importlib.util.spec_from_file_location('artifact_paths_under_test', MODULE_PATH)
artifact_paths = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(artifact_paths)


class ArtifactPathsTestCase(unittest.TestCase):
    def test_case_paths_include_case_specific_bulk_and_meta_dirs(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch.multiple(
                artifact_paths.Config,
                UPLOAD_FOLDER_WEB=os.path.join(tmpdir, 'uploads', 'web'),
                UPLOAD_FOLDER_SFTP=os.path.join(tmpdir, 'uploads', 'sftp'),
                STORAGE_FOLDER=os.path.join(tmpdir, 'storage'),
                STAGING_FOLDER=os.path.join(tmpdir, 'staging'),
                EVIDENCE_FOLDER=os.path.join(tmpdir, 'evidence'),
                EVIDENCE_BULK_FOLDER=os.path.join(tmpdir, 'evidence_uploads'),
                PCAP_UPLOAD_FOLDER=os.path.join(tmpdir, 'uploads', 'pcap'),
            ):
                with patch.object(
                    artifact_paths,
                    'get_originals_base_path',
                    return_value=os.path.join(tmpdir, 'originals'),
                ):
                    paths = artifact_paths.ensure_case_artifact_paths('case-123')
                    self.assertTrue(paths['evidence_bulk'].endswith(os.path.join('evidence_uploads', 'case-123')))
                    self.assertTrue(paths['memory_upload_meta'].endswith(
                        os.path.join('uploads', 'sftp', 'case-123', 'memory', '.upload_meta')
                    ))
                    self.assertTrue(paths['rebuild_upload'].endswith(
                        os.path.join('uploads', 'web', 'case-123', '_rebuild')
                    ))
                    self.assertTrue(paths['pcap_rebuild_upload'].endswith(
                        os.path.join('uploads', 'pcap', 'case-123', '_rebuild')
                    ))
                    self.assertTrue(paths['memory_rebuild_upload'].endswith(
                        os.path.join('uploads', 'sftp', 'case-123', 'memory', '_rebuild')
                    ))
                    self.assertTrue(paths['originals'].endswith(os.path.join('case-123', 'originals')))
                    self.assertTrue(os.path.isdir(paths['pcap_storage']))
                    self.assertFalse(os.path.exists(paths['originals']))

                    originals_dir = artifact_paths.ensure_case_originals_subdir('case-123', 'pcap')
                    self.assertTrue(os.path.isdir(originals_dir))

    def test_move_from_prefix_preserves_relative_path(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            source_root = os.path.join(tmpdir, 'staging')
            dest_root = os.path.join(tmpdir, 'storage')
            source_path = os.path.join(source_root, 'case-123', 'nested', 'artifact.evtx')
            os.makedirs(os.path.dirname(source_path), exist_ok=True)
            with open(source_path, 'w', encoding='utf-8') as handle:
                handle.write('data')

            dest_path = artifact_paths.move_from_prefix(source_path, source_root, dest_root)

            self.assertEqual(
                dest_path,
                os.path.join(dest_root, 'case-123', 'nested', 'artifact.evtx')
            )
            self.assertTrue(os.path.exists(dest_path))
            self.assertFalse(os.path.exists(source_path))

    def test_move_from_prefix_with_companions_keeps_sqlite_sidecars_together(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            source_root = os.path.join(tmpdir, 'staging')
            dest_root = os.path.join(tmpdir, 'storage')
            source_path = os.path.join(source_root, 'case-123', 'Timeline', 'ActivitiesCache.db')
            os.makedirs(os.path.dirname(source_path), exist_ok=True)

            for suffix in ('', '-wal', '-shm'):
                with open(f'{source_path}{suffix}', 'w', encoding='utf-8') as handle:
                    handle.write(f'data{suffix}')

            moved_paths = artifact_paths.move_from_prefix_with_companions(source_path, source_root, dest_root)

            expected_primary = os.path.join(dest_root, 'case-123', 'Timeline', 'ActivitiesCache.db')
            self.assertEqual(moved_paths[source_path], expected_primary)
            self.assertEqual(moved_paths[f'{source_path}-wal'], f'{expected_primary}-wal')
            self.assertEqual(moved_paths[f'{source_path}-shm'], f'{expected_primary}-shm')
            self.assertTrue(os.path.exists(expected_primary))
            self.assertTrue(os.path.exists(f'{expected_primary}-wal'))
            self.assertTrue(os.path.exists(f'{expected_primary}-shm'))
            self.assertFalse(os.path.exists(source_path))

    def test_is_within_any_root_rejects_escape_paths(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = os.path.join(tmpdir, 'case-root')
            allowed = os.path.join(root, 'allowed')
            escaped = os.path.join(tmpdir, 'elsewhere', 'bad.txt')
            os.makedirs(allowed, exist_ok=True)
            os.makedirs(os.path.dirname(escaped), exist_ok=True)
            good_file = os.path.join(allowed, 'good.txt')
            with open(good_file, 'w', encoding='utf-8') as handle:
                handle.write('ok')
            with open(escaped, 'w', encoding='utf-8') as handle:
                handle.write('bad')

            self.assertTrue(artifact_paths.is_within_any_root(good_file, [root]))
            self.assertFalse(artifact_paths.is_within_any_root(escaped, [root]))


if __name__ == '__main__':
    unittest.main()
