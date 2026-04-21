import importlib.util
import os
import sys
import types
import unittest


REPO_ROOT = os.path.dirname(os.path.dirname(__file__))


def _load_module(name: str, relative_path: str):
    module_path = os.path.join(REPO_ROOT, relative_path)
    spec = importlib.util.spec_from_file_location(name, module_path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class IOCTrainingDatasetContractTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fake_utils = types.ModuleType("utils")
        fake_utils.__path__ = []
        fake_utils_ai = types.ModuleType("utils.ai")
        fake_utils_ai.__path__ = []
        fake_utils_ai_router = types.ModuleType("utils.ai.router")
        fake_utils_ai_router.invoke_json = lambda *args, **kwargs: {}
        fake_utils_ai_training = types.ModuleType("utils.ai_training")
        fake_utils_ai_training.build_role_system_prompt = (
            lambda route_name, extra_instructions='': extra_instructions
        )

        cls._previous_modules = {
            name: sys.modules.get(name)
            for name in ("utils", "utils.ai", "utils.ai.router", "utils.ai_training")
        }
        sys.modules["utils"] = fake_utils
        sys.modules["utils.ai"] = fake_utils_ai
        sys.modules["utils.ai.router"] = fake_utils_ai_router
        sys.modules["utils.ai_training"] = fake_utils_ai_training

        cls.ioc_text = _load_module(
            "ioc_text_under_test",
            os.path.join("utils", "ioc_text.py"),
        )
        cls.training_dataset = _load_module(
            "ioc_training_dataset_under_test",
            os.path.join("utils", "ioc_training_dataset.py"),
        )

    @classmethod
    def tearDownClass(cls):
        for name, previous in cls._previous_modules.items():
            if previous is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = previous

    def test_training_dataset_defang_uses_shared_ioc_text_rules(self):
        sample = "hxxps[:]//bad{dot}example/path"
        self.assertEqual(
            self.training_dataset.defang_text(sample),
            self.ioc_text._defang_text(sample),
        )
        self.assertEqual(
            self.training_dataset.defang_text(sample),
            "https://bad.example/path",
        )

    def test_training_dataset_normalize_path_uses_shared_huntress_cleanup(self):
        sample = r"C:\Users\me\payload.exe (Quarantined by Microsoft Defender)"
        normalized, _note = self.ioc_text._normalize_extracted_file_path(sample)
        self.assertEqual(
            self.training_dataset.normalize_path(sample),
            normalized,
        )
        self.assertEqual(
            self.training_dataset.normalize_path(sample),
            r"C:\Users\me\payload.exe",
        )


if __name__ == "__main__":
    unittest.main()
