"""Import-time contract for the case-analysis orchestrator.

The orchestrator is loaded directly from source by several contract test suites
that stub `models.database` with a lightweight namespace. A module-level import
of a `db.Model` subclass therefore breaks collection of every one of those
suites at once, silently disabling them rather than failing a single assertion.
This suite pins the boundary so that regression cannot recur unnoticed.
"""

import ast
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]

# Modules that define `db.Model` subclasses and therefore require a real
# SQLAlchemy `db` object at import time.
MODEL_MODULES_REQUIRING_REAL_DB = {
    'models.case',
    'models.known_user',
    'models.known_system',
    'models.rag',
    'models.evidence',
}


def _module_level_imports(relative_path: str) -> set:
    """Return module names imported at module scope (not inside a function)."""
    source = (REPO_ROOT / relative_path).read_text()
    tree = ast.parse(source)

    imported = set()
    for node in tree.body:
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module)
    return imported


class CaseAnalyzerImportContractTestCase(unittest.TestCase):
    def test_orchestrator_does_not_import_model_modules_at_module_scope(self):
        imported = _module_level_imports('utils/case_analyzer.py')
        offending = imported & MODEL_MODULES_REQUIRING_REAL_DB

        self.assertEqual(
            offending,
            set(),
            msg=(
                'utils/case_analyzer.py imports '
                f'{sorted(offending)} at module scope. Move the import inside the '
                'function that needs it, or the contract suites that stub '
                'models.database will fail during collection instead of running.'
            ),
        )

    def test_case_timezone_helper_defers_model_import(self):
        imported = _module_level_imports('utils/case_timezone.py')

        self.assertNotIn(
            'models.case',
            imported,
            msg=(
                'utils/case_timezone.py must import models.case lazily so it can '
                'be used from modules loaded under stubbed database modules.'
            ),
        )


if __name__ == '__main__':
    unittest.main()
