import importlib.util
import os
import sys
import types
import unittest


os.environ.setdefault("SECRET_KEY", "test-secret")


def _load_module(name: str, path: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class AiSubagentsContractTestCase(unittest.TestCase):
    def _load_ai_subagents(self):
        fake_utils = types.ModuleType('utils')
        fake_utils.__path__ = []
        fake_ai = types.ModuleType('utils.ai')
        fake_ai.__path__ = []
        fake_router = types.ModuleType('utils.ai.router')
        fake_router.invoke_text = lambda **kwargs: {
            'text': '## Summary\nDone',
            'usage': {},
            'runtime': {'max_tokens': kwargs.get('max_tokens')},
        }
        fake_training = types.ModuleType('utils.ai_training')
        fake_training.build_role_system_prompt = lambda _route, prompt: prompt
        fake_privacy = types.ModuleType('utils.privacy_aliases')
        fake_privacy.AIPrivacyContext = type('AIPrivacyContext', (), {
            'case_content': staticmethod(lambda case_id: {'case_id': case_id}),
        })

        previous = {
            name: sys.modules.get(name)
            for name in (
                'utils',
                'utils.ai',
                'utils.ai.router',
                'utils.ai_training',
                'utils.privacy_aliases',
                'utils.ai_subagents',
            )
        }
        sys.modules['utils'] = fake_utils
        sys.modules['utils.ai'] = fake_ai
        sys.modules['utils.ai.router'] = fake_router
        sys.modules['utils.ai_training'] = fake_training
        sys.modules['utils.privacy_aliases'] = fake_privacy
        try:
            return _load_module('utils.ai_subagents', '/opt/casescope/utils/ai_subagents.py')
        finally:
            for name, prior in previous.items():
                if prior is None:
                    sys.modules.pop(name, None)
                else:
                    sys.modules[name] = prior

    def test_registry_includes_hypothesis_challenger_and_report_budget(self):
        module = self._load_ai_subagents()

        challenger = module.get_subagent('hypothesis_challenger')
        report = module.get_subagent('report_drafter')

        self.assertIn('expected_but_missing', challenger.output_schema)
        self.assertIn('get_case_coverage', challenger.allowed_tools)
        self.assertEqual(report.max_tokens, 3500)

    def test_run_subagent_returns_contract_validation_and_tool_mode(self):
        module = self._load_ai_subagents()

        result = module.run_subagent(
            key='hypothesis_challenger',
            case_id=42,
            task='Challenge initial access theory',
            evidence={'events': [{'event_id': '4624'}]},
        )

        self.assertFalse(result['schema_validation']['valid'])
        self.assertIn('theory_restated', result['schema_validation']['missing_sections'])
        self.assertEqual(result['tool_contract']['execution_mode'], 'single_prompt_no_tool_loop')
        self.assertFalse(result['tool_contract']['allowed_tools_enforced'])
        self.assertEqual(result['runtime']['max_tokens'], 2000)

    def test_schema_validation_accepts_expected_headings(self):
        module = self._load_ai_subagents()
        response = """
## Theory Restated
The theory is plausible.
## Contradicting Evidence
None supplied.
## Alternative Explanations
Benign admin activity.
## Expected But Missing
No persistence evidence.
## Verdict
Unproven.
"""

        validation = module._validate_response_schema(
            response,
            module.get_subagent('hypothesis_challenger').output_schema,
        )

        self.assertTrue(validation['valid'])
        self.assertEqual(validation['missing_sections'], [])


if __name__ == '__main__':
    unittest.main()
