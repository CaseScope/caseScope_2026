import os
import sys
import types
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


def _load_ai_modules():
    ai_adapters_module = _load_module('ai_adapters_direct', '/opt/casescope/utils/ai_adapters.py')
    fake_utils = types.ModuleType('utils')
    fake_utils.__path__ = []

    previous_utils = sys.modules.get('utils')
    previous_ai_adapters = sys.modules.get('utils.ai_adapters')
    sys.modules['utils'] = fake_utils
    sys.modules['utils.ai_adapters'] = ai_adapters_module

    try:
        ai_providers_module = _load_module('ai_providers_direct', '/opt/casescope/utils/ai_providers.py')
    finally:
        if previous_utils is not None:
            sys.modules['utils'] = previous_utils
        else:
            sys.modules.pop('utils', None)

        if previous_ai_adapters is not None:
            sys.modules['utils.ai_adapters'] = previous_ai_adapters
        else:
            sys.modules.pop('utils.ai_adapters', None)

    return ai_providers_module, ai_adapters_module


ai_providers, ai_adapters = _load_ai_modules()

_settings_hash = ai_providers._settings_hash
resolve_model_target = ai_providers.resolve_model_target
get_model_family = ai_adapters.get_model_family
get_builtin_local_adapter_catalog = ai_adapters.get_builtin_local_adapter_catalog
resolve_local_adapter_target = ai_adapters.resolve_local_adapter_target


class AIAdapterRoutingTestCase(unittest.TestCase):
    def test_builtin_adapter_catalog_includes_qwen_and_gpt_oss_ioc_entries(self):
        catalog = get_builtin_local_adapter_catalog(function_name='ioc_extraction')
        targets = {entry['target_name'] for entry in catalog}
        families = {entry['base_model_family'] for entry in catalog}

        self.assertIn('casescope-qwen25-ioc', targets)
        self.assertIn('casescope-gptoss-ioc', targets)
        self.assertIn('qwen2.5', families)
        self.assertIn('gpt-oss', families)

    def test_model_family_detection_covers_builtin_and_custom_targets(self):
        self.assertEqual(get_model_family('qwen2.5:14b-instruct-q4_k_m'), 'qwen2.5')
        self.assertEqual(get_model_family('casescope-qwen25-ioc'), 'qwen2.5')
        self.assertEqual(get_model_family('gpt-oss:20b'), 'gpt-oss')
        self.assertEqual(get_model_family('casescope-gptoss-report'), 'gpt-oss')

    def test_local_route_uses_builtin_adapter_when_family_matches(self):
        settings = {
            'provider_type': 'openai_compatible',
            'model_name': 'qwen2.5:14b-instruct-q4_k_m',
            'compat_model': 'qwen2.5:14b-instruct-q4_k_m',
            'compat_function_models': {},
            'compat_function_adapter_models': {'ioc_extraction': 'casescope-qwen25-ioc'},
        }

        self.assertEqual(
            resolve_model_target(settings, function='ioc_extraction'),
            'casescope-qwen25-ioc',
        )

    def test_local_route_falls_back_to_base_on_family_mismatch(self):
        settings = {
            'provider_type': 'openai_compatible',
            'model_name': 'gpt-oss:20b',
            'compat_model': 'gpt-oss:20b',
            'compat_function_models': {},
            'compat_function_adapter_models': {'ioc_extraction': 'casescope-qwen25-ioc'},
        }

        self.assertEqual(
            resolve_model_target(settings, function='ioc_extraction'),
            'gpt-oss:20b',
        )

    def test_local_route_allows_custom_adapter_targets(self):
        settings = {
            'provider_type': 'openai_compatible',
            'model_name': 'qwen2.5:14b-instruct-q4_k_m',
            'compat_model': 'qwen2.5:14b-instruct-q4_k_m',
            'compat_function_models': {},
            'compat_function_adapter_models': {'ioc_extraction': 'my-qwen25-ioc-adapter'},
        }

        self.assertEqual(
            resolve_model_target(settings, function='ioc_extraction'),
            'my-qwen25-ioc-adapter',
        )

    def test_hosted_provider_ignores_local_adapter_fields(self):
        settings = {
            'provider_type': 'openai',
            'model_name': 'gpt-4o',
            'function_models': {'chat': 'gpt-4.1-mini'},
            'compat_model': 'qwen2.5:14b-instruct-q4_k_m',
            'compat_function_models': {'chat': 'qwen2.5:14b-instruct-q4_k_m'},
            'compat_function_adapter_models': {'chat': 'casescope-qwen25-chat'},
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

    def test_settings_hash_changes_when_adapter_target_changes(self):
        left = {
            'provider_type': 'openai_compatible',
            'api_url': 'http://127.0.0.1:11434',
            'model_name': 'qwen2.5:14b-instruct-q4_k_m',
            'api_key': '',
            'compat_model': 'qwen2.5:14b-instruct-q4_k_m',
            'compat_function_models': {'chat': ''},
            'compat_function_adapter_models': {'chat': 'casescope-qwen25-chat'},
            'openai_model': '',
            'openai_function_models': {},
            'claude_model': '',
            'claude_function_models': {},
        }
        right = dict(left)
        right['compat_function_adapter_models'] = {'chat': 'casescope-gptoss-chat'}

        self.assertNotEqual(_settings_hash(left), _settings_hash(right))

    def test_local_adapter_resolution_exposes_fallback_reason(self):
        resolution = resolve_local_adapter_target(
            function_name='ioc_extraction',
            base_model='gpt-oss:20b',
            adapter_target='casescope-qwen25-ioc',
        )

        self.assertEqual(resolution['status'], 'fallback_base')
        self.assertIn('does not match base model family', resolution['reason'])
        self.assertEqual(resolution['resolved_model'], 'gpt-oss:20b')

    def test_gpu_model_config_and_descriptions_exist(self):
        source = Path('/opt/casescope/models/system_settings.py').read_text()
        self.assertIn('def get_ai_model_config(recommended_vram_mb', source)
        self.assertIn('AI_FUNCTION_DESCRIPTIONS = dict(AI_FUNCTION_LABELS)', source)

    def test_settings_ui_and_api_expose_local_adapter_fields(self):
        api_source = Path('/opt/casescope/routes/api.py').read_text()
        template_source = Path('/opt/casescope/static/templates/settings.html').read_text()

        self.assertIn('compat_adapter_catalog', api_source)
        self.assertIn('compat_function_adapter_models', api_source)
        self.assertIn('Per-Function Adapter Overrides', template_source)
        self.assertIn('Custom adapter target', template_source)
        self.assertIn('toggleCustomAdapterInput', template_source)
        self.assertIn('case_review', template_source)
        self.assertIn('Case Review', template_source)

    def test_case_review_checkpoint_and_fallback_guards_exist(self):
        checkpoints_source = Path('/opt/casescope/utils/ai_checkpoints.py').read_text()

        self.assertIn("get_llm_provider(function='case_review')", checkpoints_source)
        self.assertIn("'fallback': True", checkpoints_source)
        self.assertIn("review_structured_output(", checkpoints_source)

    def test_activation_gating_and_chat_fail_closed_source_guards(self):
        api_source = Path('/opt/casescope/routes/api.py').read_text()
        chat_source = Path('/opt/casescope/routes/chat.py').read_text()

        self.assertIn("_is_license_feature_active('ai')", api_source)
        self.assertIn('AI settings are locked until a valid active AI license is available', api_source)
        self.assertIn('FeatureAvailability.is_ai_enabled()', chat_source)
        self.assertIn('AI features are not currently available', chat_source)

    def test_chat_runtime_compaction_guards_exist(self):
        chat_agent_source = Path('/opt/casescope/utils/chat_agent.py').read_text()

        self.assertIn('MAX_HISTORY_MESSAGES = 18', chat_agent_source)
        self.assertIn('def _compact_messages(', chat_agent_source)
        self.assertIn('def _serialize_tool_result_for_history(', chat_agent_source)


if __name__ == '__main__':
    unittest.main()
