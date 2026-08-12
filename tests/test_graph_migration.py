import inspect
import unittest

from migrations import add_investigation_graph_tables as migration


class GraphMigrationContractTestCase(unittest.TestCase):
    def test_relationship_edge_constraint_converges_from_4130_shape(self):
        source = inspect.getsource(migration._ensure_relationship_edge_constraint)

        self.assertIn('DROP CONSTRAINT IF EXISTS', source)
        self.assertIn('ADD CONSTRAINT', source)
        self.assertEqual(
            migration.RELATIONSHIP_EDGE_COLUMNS,
            [
                'case_id',
                'source_entity_id',
                'relationship_type',
                'target_entity_id',
                'derivation_type',
            ],
        )
        self.assertNotIn('extractor_name', migration.RELATIONSHIP_EDGE_COLUMNS)
        self.assertNotIn('extractor_version', migration.RELATIONSHIP_EDGE_COLUMNS)


if __name__ == '__main__':
    unittest.main()
