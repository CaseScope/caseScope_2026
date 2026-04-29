import importlib.util
import os
import sys
import types
import unittest


REPO_ROOT = os.path.dirname(os.path.dirname(__file__))


def _load_contract_adapter():
    fake_utils = types.ModuleType('utils')
    fake_utils.__path__ = []
    fake_utils_ai = types.ModuleType('utils.ai')
    fake_utils_ai.__path__ = []
    fake_utils_ai_router = types.ModuleType('utils.ai.router')
    fake_utils_ai_router.invoke_json = lambda *args, **kwargs: {}
    fake_utils_ai_router.invoke_text = lambda *args, **kwargs: ""
    fake_ai_training = types.ModuleType('utils.ai_training')
    fake_ai_training.build_role_system_prompt = (
        lambda route_name, extra_instructions='': extra_instructions
    )

    previous_utils = sys.modules.get('utils')
    previous_utils_ai = sys.modules.get('utils.ai')
    previous_utils_ai_router = sys.modules.get('utils.ai.router')
    previous_ai_training = sys.modules.get('utils.ai_training')
    sys.modules['utils'] = fake_utils
    sys.modules['utils.ai'] = fake_utils_ai
    sys.modules['utils.ai.router'] = fake_utils_ai_router
    sys.modules['utils.ai_training'] = fake_ai_training
    module_path = os.path.join(REPO_ROOT, 'utils', 'ioc_contract_adapter.py')
    spec = importlib.util.spec_from_file_location('phase5_ioc_contract_adapter', module_path)
    module = importlib.util.module_from_spec(spec)
    try:
        assert spec.loader is not None
        spec.loader.exec_module(module)
    finally:
        if previous_utils is not None:
            sys.modules['utils'] = previous_utils
        else:
            sys.modules.pop('utils', None)
        if previous_utils_ai is not None:
            sys.modules['utils.ai'] = previous_utils_ai
        else:
            sys.modules.pop('utils.ai', None)
        if previous_utils_ai_router is not None:
            sys.modules['utils.ai.router'] = previous_utils_ai_router
        else:
            sys.modules.pop('utils.ai.router', None)
        if previous_ai_training is not None:
            sys.modules['utils.ai_training'] = previous_ai_training
        else:
            sys.modules.pop('utils.ai_training', None)
    return module


ioc_contract_adapter = _load_contract_adapter()


class Phase5IOCContractAdapterContractTestCase(unittest.TestCase):
    def test_prepare_payload_repairs_shape_and_tracks_review_reasons(self):
        original_review = ioc_contract_adapter._ai_review.review_structured_output
        ioc_contract_adapter._ai_review.review_structured_output = (
            lambda _provider, **kwargs: kwargs['payload']
        )
        try:
            payload, meta = ioc_contract_adapter.prepare_ai_extraction_payload(
                provider=object(),
                payload={'affected_hosts': ['HOST-A'], 'unexpected': ['drop-me']},
                max_tokens=2000,
                ai_review_max_tokens=3000,
                semantic_task_allowed_fields={},
            )
        finally:
            ioc_contract_adapter._ai_review.review_structured_output = original_review

        self.assertTrue(meta['review_applied'])
        self.assertIn('unexpected_field:unexpected', meta['semantic_review_reasons'])
        self.assertEqual(payload['affected_hosts'], ['HOST-A'])
        self.assertNotIn('unexpected', payload)

    def test_filter_semantic_payload_for_task_keeps_owned_fields_only(self):
        payload = ioc_contract_adapter._ioc_contract.build_empty_ioc_extraction()
        payload['process_iocs']['commands'] = [{'full_command': 'cmd.exe /c whoami'}]
        payload['authentication_iocs']['created_users'] = [{'username': 'alice'}]

        filtered, meta = ioc_contract_adapter.filter_semantic_payload_for_task(
            'semantic_process_relationships',
            payload,
            semantic_task_allowed_fields={
                'semantic_process_relationships': {
                    'process_iocs': ('commands', 'services', 'scheduled_tasks'),
                }
            },
        )

        self.assertTrue(filtered['process_iocs']['commands'])
        self.assertEqual(filtered['authentication_iocs']['created_users'], [])
        self.assertIn('authentication_iocs.created_users', meta['stripped_fields'])


if __name__ == '__main__':
    unittest.main()
