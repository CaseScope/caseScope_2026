import inspect
import unittest

from migrations import add_investigation_graph_tables as migration
from migrations import add_graph_projection_state as projection_migration
from models.graph import GraphProjectionState


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

    def test_projection_state_migration_uses_durable_case_scoped_table(self):
        columns = {column.name for column in GraphProjectionState.__table__.columns}

        self.assertIn("case_id", columns)
        self.assertIn("case_uuid", columns)
        self.assertIn("status", columns)
        self.assertIn("last_timestamp_utc", columns)
        self.assertIn("last_evidence_record_key", columns)
        self.assertIn("events_seen", columns)
        self.assertIn("relationships_materialized", columns)
        self.assertIn("errors", columns)
        self.assertIn("task_id", columns)
        self.assertIn("GraphProjectionState", projection_migration.__dict__)


if __name__ == '__main__':
    unittest.main()
