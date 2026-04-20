import importlib.util
import sys
import tempfile
import types
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
UTILS_DIR = REPO_ROOT / 'utils'


def _load_module(module_name: str, path: Path):
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f'Unable to load module from {path}')
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


utils_pkg = sys.modules.setdefault('utils', types.ModuleType('utils'))
utils_pkg.__path__ = [str(UTILS_DIR)]

pattern_event_mappings = _load_module(
    'utils.pattern_event_mappings',
    UTILS_DIR / 'pattern_event_mappings.py',
)
pattern_check_definitions = _load_module(
    'utils.pattern_check_definitions',
    UTILS_DIR / 'pattern_check_definitions.py',
)
rule_loader = _load_module(
    'utils.rules.loader',
    UTILS_DIR / 'rules' / 'loader.py',
)

RuleLoader = rule_loader.RuleLoader


class Phase4aRuleLoaderContractTestCase(unittest.TestCase):
    def test_rule_loader_discovers_pack_dirs_and_registers_python_verifiers(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            builtin_dir = Path(tmpdir) / 'builtin'
            builtin_dir.mkdir(parents=True, exist_ok=True)
            (builtin_dir / 'sigma_pack.yaml').write_text('id: sigma_pack\n', encoding='utf-8')
            (builtin_dir / 'ignore.txt').write_text('not a pack\n', encoding='utf-8')

            loader = RuleLoader(builtin_root=Path(tmpdir))
            report = loader.load_all()

        self.assertIn(str(builtin_dir.resolve()), report.catalog.declarative_packs)
        self.assertIn('sigma_pack', report.catalog.declarative_rules)
        self.assertIn(str((builtin_dir / 'ignore.txt').resolve()), report.skipped)
        self.assertIn('password_spraying', report.catalog.python_verifiers)
        self.assertEqual(
            [check.id for check in report.catalog.get_checks_for_pattern('password_spraying')],
            [check.id for check in pattern_check_definitions.get_checks_for_pattern('password_spraying')],
        )
        self.assertEqual(
            report.catalog.get_burst_config('pass_the_hash'),
            pattern_check_definitions.get_burst_config('pass_the_hash'),
        )

    def test_deterministic_engine_uses_rule_loader_surface(self):
        source = (UTILS_DIR / 'deterministic_evidence_engine.py').read_text()

        self.assertIn('from utils.rules.loader import RuleCatalog, RuleLoader', source)
        self.assertIn('self.rule_catalog = RuleLoader(self).register_with_engine()', source)
        self.assertIn('checks_defs = self.rule_catalog.get_checks_for_pattern(pattern_id)', source)
        self.assertIn('spread_config = self.rule_catalog.get_spread_config(pattern_id)', source)
        self.assertIn('config = self.rule_catalog.get_burst_config(pattern_id)', source)
        self.assertIn('config = self.rule_catalog.get_sequence_config(pattern_id)', source)
        self.assertNotIn('get_checks_for_pattern, get_burst_config, get_sequence_config,', source)

    def test_pass_the_ticket_exposes_machine_account_disqualifier(self):
        checks = pattern_check_definitions.get_checks_for_pattern('pass_the_ticket')
        by_id = {check.id: check for check in checks}

        self.assertIn('ptt_machine_account', by_id)
        self.assertTrue(by_id['ptt_machine_account'].disqualifier)
        self.assertEqual(by_id['ptt_machine_account'].role, 'context')
        self.assertEqual(by_id['ptt_machine_account'].weight, 0)


if __name__ == '__main__':
    unittest.main()
