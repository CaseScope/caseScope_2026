import importlib.util
import sys
import types
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def _load_module(name: str, relative_path: str):
    module_path = REPO_ROOT / relative_path
    spec = importlib.util.spec_from_file_location(name, module_path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class _FakeSession:
    def __init__(self):
        self.added = []

    def add(self, item):
        self.added.append(item)


class _FakeSuggestedAction:
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)


class CaseActionsRegressionTestCase(unittest.TestCase):
    def test_generate_suggested_actions_caps_noisy_finding_sets(self):
        session = _FakeSession()
        fake_db = types.SimpleNamespace(session=session)
        fake_behavioral = types.SimpleNamespace(SuggestedAction=_FakeSuggestedAction)

        previous_modules = {
            name: sys.modules.get(name)
            for name in (
                'models.database',
                'models.behavioral_profiles',
            )
        }
        sys.modules['models.database'] = types.SimpleNamespace(db=fake_db)
        sys.modules['models.behavioral_profiles'] = fake_behavioral

        try:
            case_actions = _load_module(
                'case_actions_under_test',
                'pipeline/case_actions.py',
            )
        finally:
            for name, previous in previous_modules.items():
                if previous is None:
                    sys.modules.pop(name, None)
                else:
                    sys.modules[name] = previous

        progress_messages = []
        findings = [
            {
                'id': idx,
                'type': 'storyline',
                'confidence': 95 if idx < 600 else 30,
                'severity': 'critical' if idx < 600 else 'low',
                'entity_type': 'system',
                'entity_value': f'HOST-{idx}',
                'suggested_iocs': [
                    {'value': f'/tmp/dropper-{idx}.exe', 'reason': 'Downloaded file'}
                ],
            }
            for idx in range(1500)
        ]

        actions = case_actions.generate_suggested_actions(
            case_id=7,
            analysis_id='analysis-7',
            all_findings=findings,
            attack_chains=[],
            opencti_context={},
            progress_callback=lambda *_args: progress_messages.append(_args[-1]),
        )

        self.assertLessEqual(len(actions), case_actions.MAX_SUGGESTED_ACTIONS)
        self.assertLessEqual(
            len([action for action in actions if action.action_type == 'add_ioc']),
            case_actions.MAX_IOC_ACTIONS,
        )
        self.assertEqual(len(session.added), len(actions))
        self.assertTrue(any('lower-ranked findings skipped' in msg for msg in progress_messages))


if __name__ == '__main__':
    unittest.main()
