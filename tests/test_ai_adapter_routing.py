import os
import ast
import unittest
import importlib.util
from pathlib import Path

os.environ.setdefault('SECRET_KEY', 'test-secret')


def _load_module(name: str, path: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


ai_providers = _load_module('ai_providers_direct', '/opt/casescope/utils/ai_providers.py')
global_adapter = _load_module('ai_training_global_adapter', '/opt/casescope/utils/ai_training/global_adapter.py')

_settings_hash = ai_providers._settings_hash
resolve_model_target = ai_providers.resolve_model_target
GLOBAL_ADAPTER_VERSION = global_adapter.GLOBAL_ADAPTER_VERSION
GLOBAL_CASESCOPE_SYSTEM_PROMPT = global_adapter.GLOBAL_CASESCOPE_SYSTEM_PROMPT
LOCAL_MODEL_TARGETS = global_adapter.LOCAL_MODEL_TARGETS
render_global_modelfile = global_adapter.render_global_modelfile
render_task_modelfile = global_adapter.render_task_modelfile


class AIAdapterRoutingTestCase(unittest.TestCase):
    def test_local_task_strategy_prefers_task_adapter(self):
        settings = {
            'provider_type': 'openai_compatible',
            'model_name': 'casescope-base',
            'compat_model': 'casescope-base',
            'compat_global_adapter_model': 'casescope-global',
            'compat_function_models': {},
            'compat_function_adapter_models': {'pattern_matching': 'casescope-pattern'},
            'compat_function_strategies': {'pattern_matching': 'task'},
        }

        self.assertEqual(
            resolve_model_target(settings, function='pattern_matching'),
            'casescope-pattern',
        )

    def test_local_task_strategy_falls_back_to_global_then_base(self):
        settings = {
            'provider_type': 'openai_compatible',
            'model_name': 'casescope-base',
            'compat_model': 'casescope-base',
            'compat_global_adapter_model': 'casescope-global',
            'compat_function_models': {},
            'compat_function_adapter_models': {'timeline': ''},
            'compat_function_strategies': {'timeline': 'task', 'chat': 'global'},
        }

        self.assertEqual(
            resolve_model_target(settings, function='timeline'),
            'casescope-global',
        )
        self.assertEqual(
            resolve_model_target(settings, function='chat'),
            'casescope-global',
        )

        settings['compat_global_adapter_model'] = ''
        self.assertEqual(
            resolve_model_target(settings, function='timeline'),
            'casescope-base',
        )

    def test_hosted_provider_ignores_local_adapter_fields(self):
        settings = {
            'provider_type': 'openai',
            'model_name': 'gpt-4o',
            'function_models': {'chat': 'gpt-4.1-mini'},
            'compat_model': 'casescope-base',
            'compat_global_adapter_model': 'casescope-global',
            'compat_function_models': {'chat': 'casescope-chat'},
            'compat_function_adapter_models': {'chat': 'casescope-chat'},
            'compat_function_strategies': {'chat': 'task'},
        }

        self.assertEqual(
            resolve_model_target(settings, function='chat'),
            'gpt-4.1-mini',
        )

    def test_openai_completion_only_model_falls_back(self):
        settings = {
            'provider_type': 'openai',
            'model_name': 'gpt-4o',
            'function_models': {
                'pattern_matching': 'gpt-5.3-codex',
                'chat': 'gpt-4.1-mini',
            },
        }

        self.assertEqual(
            resolve_model_target(settings, function='pattern_matching'),
            'gpt-4o',
        )

    def test_settings_hash_changes_when_adapter_fields_change(self):
        left = {
            'provider_type': 'openai_compatible',
            'api_url': 'http://127.0.0.1:11434',
            'model_name': 'casescope-base',
            'api_key': '',
            'compat_model': 'casescope-base',
            'compat_global_adapter_model': 'casescope-global',
            'compat_function_models': {'chat': ''},
            'compat_function_adapter_models': {'chat': ''},
            'compat_function_strategies': {'chat': 'global'},
            'openai_model': '',
            'openai_function_models': {},
            'claude_model': '',
            'claude_function_models': {},
        }
        right = dict(left)
        right['compat_global_adapter_model'] = 'casescope-global-v2'

        self.assertNotEqual(_settings_hash(left), _settings_hash(right))

    def test_gpu_model_config_and_descriptions_exist(self):
        source = Path('/opt/casescope/models/system_settings.py').read_text()
        self.assertIn('def get_ai_model_config(recommended_vram_mb', source)
        self.assertIn('AI_FUNCTION_DESCRIPTIONS = dict(AI_FUNCTION_LABELS)', source)

        module_ast = ast.parse(source)
        model_config = None
        for node in module_ast.body:
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id == 'AI_MODEL_CONFIG':
                        model_config = ast.literal_eval(node.value)
                        break
            if model_config is not None:
                break

        self.assertIsNotNone(model_config)
        self.assertIn('ioc_extraction', model_config['16gb'])

    def test_training_assets_render_expected_modelfiles(self):
        self.assertEqual(GLOBAL_ADAPTER_VERSION, '2026.04.02.0')
        self.assertIn('CaseScope DFIR model', GLOBAL_CASESCOPE_SYSTEM_PROMPT)
        self.assertIn('global', LOCAL_MODEL_TARGETS)

        global_modelfile = render_global_modelfile('qwen2.5:14b-instruct-q4_k_m', '/tmp/global-adapter')
        self.assertIn('FROM qwen2.5:14b-instruct-q4_k_m', global_modelfile)
        self.assertIn('ADAPTER /tmp/global-adapter', global_modelfile)

        task_modelfile = render_task_modelfile('ioc_extraction', '/tmp/ioc-adapter', 'qwen2.5:14b-instruct-q4_k_m')
        self.assertIn('Route tag: ioc_extraction', task_modelfile)
        self.assertIn('ADAPTER /tmp/ioc-adapter', task_modelfile)

        modelfile_dir = Path('/opt/casescope/utils/ai_training/modelfiles')
        self.assertTrue((modelfile_dir / 'casescope-global.Modelfile').exists())
        self.assertTrue((modelfile_dir / 'casescope-report.Modelfile').exists())
        self.assertTrue((modelfile_dir / 'casescope-timeline.Modelfile').exists())
        self.assertTrue((modelfile_dir / 'casescope-ioc.Modelfile').exists())

    def test_settings_ui_and_api_expose_local_adapter_fields(self):
        api_source = Path('/opt/casescope/routes/api.py').read_text()
        template_source = Path('/opt/casescope/static/templates/settings.html').read_text()

        self.assertIn('compat_global_adapter_model', api_source)
        self.assertIn('compat_function_adapter_models', api_source)
        self.assertIn('compat_function_strategies', api_source)
        self.assertIn('Shared Global Adapter', template_source)
        self.assertIn('Local Adapter Routing', template_source)
        self.assertIn('Hosted providers continue using model-only routing.', template_source)


if __name__ == '__main__':
    unittest.main()
