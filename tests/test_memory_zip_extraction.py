import os
import importlib.util
import sys
import tempfile
import types
import unittest
import zipfile

os.environ.setdefault('SECRET_KEY', 'test-secret')

BASE_DIR = os.path.dirname(os.path.dirname(__file__))

artifact_paths_spec = importlib.util.spec_from_file_location(
    'utils.artifact_paths',
    os.path.join(BASE_DIR, 'utils', 'artifact_paths.py'),
)
artifact_paths_module = importlib.util.module_from_spec(artifact_paths_spec)
artifact_paths_spec.loader.exec_module(artifact_paths_module)

utils_package = types.ModuleType('utils')
utils_package.artifact_paths = artifact_paths_module
sys.modules.setdefault('utils', utils_package)
sys.modules['utils.artifact_paths'] = artifact_paths_module

celery_module = types.ModuleType('celery')
celery_module.shared_task = lambda *args, **kwargs: (lambda func: func)
sys.modules.setdefault('celery', celery_module)

redis_module = types.ModuleType('redis')
redis_module.Redis = object
sys.modules.setdefault('redis', redis_module)

memory_tasks_spec = importlib.util.spec_from_file_location(
    'memory_tasks_under_test',
    os.path.join(BASE_DIR, 'tasks', 'memory_tasks.py'),
)
memory_tasks = importlib.util.module_from_spec(memory_tasks_spec)
memory_tasks_spec.loader.exec_module(memory_tasks)
extract_memory_from_zip = memory_tasks.extract_memory_from_zip


class MemoryZipExtractionTestCase(unittest.TestCase):
    def test_extract_memory_blocks_path_traversal(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            zip_path = os.path.join(tmpdir, 'traversal.zip')
            extract_dir = os.path.join(tmpdir, 'extract')
            os.makedirs(extract_dir, exist_ok=True)

            with zipfile.ZipFile(zip_path, 'w') as archive:
                archive.writestr('../escape.raw', b'evil')

            extracted = extract_memory_from_zip(zip_path, extract_dir)

            self.assertIsNone(extracted)
            self.assertFalse(os.path.exists(os.path.join(tmpdir, 'escape.raw')))

    def test_extract_memory_flattens_nested_valid_member(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            zip_path = os.path.join(tmpdir, 'memory.zip')
            extract_dir = os.path.join(tmpdir, 'extract')
            os.makedirs(extract_dir, exist_ok=True)

            with zipfile.ZipFile(zip_path, 'w') as archive:
                archive.writestr('nested/system.raw', b'valid-memory')

            extracted = extract_memory_from_zip(zip_path, extract_dir)

            self.assertEqual(extracted, os.path.join(extract_dir, 'system.raw'))
            self.assertTrue(os.path.exists(extracted))


if __name__ == '__main__':
    unittest.main()
