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
        self.commits = 0
        self.rollbacks = 0

    def add(self, item):
        self.added.append(item)

    def commit(self):
        self.commits += 1

    def rollback(self):
        self.rollbacks += 1


class _FakeSuggestedAction:
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)


def _load_case_actions(session):
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
        return _load_module('case_actions_under_test', 'pipeline/case_actions.py')
    finally:
        for name, previous in previous_modules.items():
            if previous is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = previous


class CaseActionsRegressionTestCase(unittest.TestCase):
    def test_generate_suggested_actions_caps_noisy_finding_sets(self):
        session = _FakeSession()
        case_actions = _load_case_actions(session)

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

    def test_the_stage_commits_the_actions_it_generates(self):
        """The stage staged rows and left them to whichever commit came next.

        A later phase failing therefore rolled back the analyst's whole queue.
        """
        session = _FakeSession()
        case_actions = _load_case_actions(session)

        actions = case_actions.generate_suggested_actions(
            case_id=7,
            analysis_id='analysis-7',
            all_findings=[{
                'id': 1,
                'type': 'storyline',
                'confidence': 95,
                'severity': 'critical',
                'entity_type': 'system',
                'entity_value': 'HOST-1',
            }],
            attack_chains=[],
            opencti_context={},
            progress_callback=lambda *_args: None,
        )

        self.assertTrue(actions)
        self.assertEqual(session.commits, 1)
        self.assertEqual(session.rollbacks, 0)

    def test_a_failed_commit_reports_no_actions_rather_than_phantom_ones(self):
        session = _FakeSession()

        def explode():
            session.commits += 1
            raise RuntimeError('deadlock detected')

        session.commit = explode
        case_actions = _load_case_actions(session)

        actions = case_actions.generate_suggested_actions(
            case_id=7,
            analysis_id='analysis-7',
            all_findings=[{
                'id': 1,
                'type': 'storyline',
                'confidence': 95,
                'severity': 'critical',
                'entity_type': 'system',
                'entity_value': 'HOST-1',
            }],
            attack_chains=[],
            opencti_context={},
            progress_callback=lambda *_args: None,
        )

        self.assertEqual(actions, [])
        self.assertEqual(session.rollbacks, 1)


class ChainActionTestCase(unittest.TestCase):
    """Chain-derived actions must go through the same cap as every other source.

    The chain builder used to persist and commit its own rows per chain, so the
    cap never applied to them: 215,263 of the 215,904 rows in the queue came from
    that path, one run contributing 108,377.
    """

    @staticmethod
    def _chain(index):
        return {
            'confidence': 90,
            'suggested_actions': [
                {
                    'action_type': 'investigate_host',
                    'target': f'HOST-{index}',
                    'reason': 'Host involved in attack chain',
                    'priority': 'high',
                },
                {
                    'action_type': 'investigate_user',
                    'target': f'user{index}',
                    'reason': 'User involved in chain',
                    'priority': 'high',
                },
                {
                    'action_type': 'review_timeline',
                    'target': 'Events from A to B',
                    'reason': 'Review full timeline',
                    'priority': 'high',
                },
            ],
        }

    def test_chain_actions_are_capped_with_everything_else(self):
        session = _FakeSession()
        case_actions = _load_case_actions(session)

        actions = case_actions.generate_suggested_actions(
            case_id=7,
            analysis_id='analysis-7',
            all_findings=[],
            attack_chains=[self._chain(i) for i in range(5000)],
            opencti_context={},
            progress_callback=lambda *_args: None,
        )

        self.assertLessEqual(len(actions), case_actions.MAX_SUGGESTED_ACTIONS)
        self.assertTrue(any(a.source_type == 'attack_chain' for a in actions))

    def test_the_timeline_action_repeated_by_every_chain_is_collapsed(self):
        session = _FakeSession()
        case_actions = _load_case_actions(session)

        actions = case_actions.generate_suggested_actions(
            case_id=7,
            analysis_id='analysis-7',
            all_findings=[],
            attack_chains=[self._chain(i) for i in range(50)],
            opencti_context={},
            progress_callback=lambda *_args: None,
        )

        timeline = [a for a in actions if a.action_type == 'review_timeline']
        self.assertEqual(len(timeline), 1)

    def test_chain_action_targets_are_typed_rather_than_all_system(self):
        session = _FakeSession()
        case_actions = _load_case_actions(session)

        actions = case_actions.generate_suggested_actions(
            case_id=7,
            analysis_id='analysis-7',
            all_findings=[],
            attack_chains=[self._chain(1)],
            opencti_context={},
            progress_callback=lambda *_args: None,
        )

        by_type = {a.action_type: a.target_type for a in actions}
        self.assertEqual(by_type['investigate_user'], 'user')
        self.assertEqual(by_type['investigate_host'], 'system')

    def test_a_chain_without_described_actions_contributes_nothing(self):
        session = _FakeSession()
        case_actions = _load_case_actions(session)

        actions = case_actions.generate_suggested_actions(
            case_id=7,
            analysis_id='analysis-7',
            all_findings=[],
            attack_chains=[{'confidence': 50}, {}, None, 'not-a-chain'],
            opencti_context={},
            progress_callback=lambda *_args: None,
        )

        self.assertEqual(actions, [])


class ChainBuilderPersistenceTestCase(unittest.TestCase):
    def test_the_chain_builder_no_longer_writes_or_commits_actions(self):
        source = (REPO_ROOT / 'utils/attack_chain_builder.py').read_text()
        self.assertNotIn('SuggestedAction', source)
        self.assertNotIn('db.session', source)

    def test_the_builder_still_describes_actions_on_the_chain(self):
        source = (REPO_ROOT / 'utils/attack_chain_builder.py').read_text()
        self.assertIn('chain.suggested_actions = actions', source)


if __name__ == '__main__':
    unittest.main()
