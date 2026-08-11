import os
import unittest

import clickhouse_connect

from migrations import add_evidence_record_identity as migration
from migrations.add_events_table import fence_events_buffer_ingestion, recreate_events_buffer
from utils.clickhouse import migration_source_query_settings


@unittest.skipUnless(
    os.environ.get("CASESCOPE_RUN_CLICKHOUSE_INTEGRATION") == "1",
    "set CASESCOPE_RUN_CLICKHOUSE_INTEGRATION=1 to run real ClickHouse smoke tests",
)
class EvidenceIdentityClickHouseIntegrationTestCase(unittest.TestCase):
    def setUp(self):
        self.database = f"casescope_ei_v2_it_{os.getpid()}"
        self.admin = clickhouse_connect.get_client(
            host=os.environ.get("CLICKHOUSE_HOST", "localhost"),
            port=int(os.environ.get("CLICKHOUSE_PORT", "8123")),
            username=os.environ.get("CLICKHOUSE_USER", "default"),
            password=os.environ.get("CLICKHOUSE_PASSWORD", ""),
            connect_timeout=5,
            send_receive_timeout=30,
        )
        self.admin.command(f"CREATE DATABASE IF NOT EXISTS `{self.database}`")
        self.client = clickhouse_connect.get_client(
            host=os.environ.get("CLICKHOUSE_HOST", "localhost"),
            port=int(os.environ.get("CLICKHOUSE_PORT", "8123")),
            database=self.database,
            username=os.environ.get("CLICKHOUSE_USER", "default"),
            password=os.environ.get("CLICKHOUSE_PASSWORD", ""),
            connect_timeout=5,
            send_receive_timeout=30,
            settings=migration_source_query_settings(),
        )

    def tearDown(self):
        self.admin.command(f"DROP DATABASE IF EXISTS `{self.database}`")

    def test_schema_index_buffer_and_source_settings_parse_on_real_clickhouse(self):
        self.client.command(
            """
            CREATE TABLE events (
                case_id UInt32,
                artifact_type String,
                timestamp_utc DateTime64(3)
            )
            ENGINE = MergeTree()
            PARTITION BY case_id
            ORDER BY (case_id, timestamp_utc, artifact_type)
            """
        )
        self.client.insert(
            "events",
            [(1, "custom_log", "2026-04-21 12:00:00.000")],
            column_names=["case_id", "artifact_type", "timestamp_utc"],
        )

        migration.add_identity_columns(self.client)
        columns = migration._existing_columns(self.client, "events")
        self.assertTrue(set(migration.IDENTITY_COLUMNS).issubset(columns))

        add_index_sql = migration._add_identity_index_sql()
        self.assertIn("ADD INDEX IF NOT EXISTS idx_evidence_record_key", add_index_sql)
        self.assertNotIn("ADD INDEX IF NOT EXISTS INDEX", add_index_sql)
        migration.ensure_identity_index(self.client)
        index_rows = self.client.query(
            """
            SELECT name
            FROM system.data_skipping_indices
            WHERE database = currentDatabase()
              AND table = 'events'
              AND name = 'idx_evidence_record_key'
            """
        ).result_rows
        self.assertEqual(index_rows, [("idx_evidence_record_key",)])

        recreate_events_buffer(self.client)
        buffer_engine = migration._table_engine(self.client, "events_buffer")
        self.assertEqual(buffer_engine, "Buffer")
        fence_events_buffer_ingestion(self.client, context="integration smoke")
        self.assertFalse(migration._table_exists(self.client, "events_buffer"))

        with self.client.query_rows_stream(
            "SELECT case_id FROM events WHERE case_id = {case_id:UInt32}",
            parameters={"case_id": 1},
            settings=migration_source_query_settings(),
        ) as stream:
            self.assertEqual(list(stream), [(1,)])


if __name__ == "__main__":
    unittest.main()
