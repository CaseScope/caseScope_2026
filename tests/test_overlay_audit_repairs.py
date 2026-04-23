import os
import types
import unittest
from contextlib import nullcontext
from datetime import datetime
from unittest.mock import patch

from flask import Flask

os.environ.setdefault("SECRET_KEY", "test-secret")

IMPORT_ERROR = None

try:
    import models.rag as rag_models
    import routes.hunting as hunting_routes
    import routes.rag as rag_routes
    import tasks.rag_tasks as rag_tasks
    import utils.event_overlay_repair as overlay_repair
except ImportError as exc:  # pragma: no cover - environment dependent
    IMPORT_ERROR = exc
    rag_models = None
    hunting_routes = None
    rag_routes = None
    rag_tasks = None
    overlay_repair = None


class _FakeResult:
    def __init__(self, rows, column_names=None):
        self.result_rows = rows
        self.column_names = column_names or []


class _OverlayRepairClient:
    def __init__(self, counts):
        self.counts = counts
        self.commands = []

    def query(self, sql, parameters=None):
        table = sql.split("FROM ", 1)[1].split(" ", 1)[0].strip()
        return _FakeResult([(self.counts.get(table, 0),)])

    def command(self, sql):
        self.commands.append(sql)


class _RagTaskClient:
    def __init__(self, first_rows=None, second_rows=None):
        self.first_rows = first_rows or []
        self.second_rows = second_rows or []
        self.queries = []

    def query(self, sql, parameters=None):
        self.queries.append(sql)
        if len(self.queries) == 1:
            return _FakeResult(self.first_rows)
        return _FakeResult(self.second_rows)


class _FilterCountQuery:
    def __init__(self, count_value, first_value=None):
        self.count_value = count_value
        self.first_value = first_value
        self.last_filter_kwargs = {}

    def filter_by(self, **kwargs):
        self.last_filter_kwargs = kwargs
        return self

    def order_by(self, *_args, **_kwargs):
        return self

    def count(self):
        return self.count_value

    def first(self):
        return self.first_value


class _CampaignQuery:
    def __init__(self, total_count, critical_count, first_value=None):
        self.total_count = total_count
        self.critical_count = critical_count
        self.first_value = first_value
        self.last_filter_kwargs = {}

    def filter_by(self, **kwargs):
        self.last_filter_kwargs = kwargs
        return self

    def order_by(self, *_args, **_kwargs):
        return self

    def count(self):
        if self.last_filter_kwargs.get("severity") == "critical":
            return self.critical_count
        return self.total_count

    def first(self):
        return self.first_value


class _SortField:
    def desc(self):
        return self


class OverlayAuditRepairTestCase(unittest.TestCase):
    def setUp(self):
        if IMPORT_ERROR is not None:
            self.skipTest(f"overlay audit dependencies unavailable: {IMPORT_ERROR}")
        self.app = Flask(__name__)
        self.app.secret_key = "test-secret"

    def test_get_raw_event_data_returns_effective_overlay_fields(self):
        fake_client = types.SimpleNamespace(
            query=lambda *_args, **_kwargs: _FakeResult(
                [[
                    False,
                    [],
                    False,
                    True,
                    ["credential-access"],
                    "reviewed",
                    ["File Name"],
                    True,
                    ["KnownBenign"],
                ]],
                column_names=[
                    "analyst_tagged",
                    "ioc_types",
                    "noise_matched",
                    "analyst_tagged_effective",
                    "analyst_tags_effective",
                    "analyst_notes_effective",
                    "ioc_types_effective",
                    "noise_matched_effective",
                    "noise_rules_effective",
                ],
            )
        )

        with self.app.test_request_context(
            "/api/hunting/event/raw/7?timestamp=2026-04-21%2012:00:00"
        ):
            with patch.object(hunting_routes.Case, "get_by_id", return_value=types.SimpleNamespace(id=7)):
                with patch("utils.clickhouse.get_client", return_value=fake_client):
                    with patch.object(hunting_routes, "ensure_event_analyst_state_table"):
                        with patch.object(hunting_routes, "ensure_event_noise_state_tables"):
                            with patch.object(hunting_routes, "ensure_event_ioc_state_tables"):
                                response = hunting_routes.get_raw_event_data.__wrapped__(7)

        payload = response.get_json()
        self.assertTrue(payload["success"])
        self.assertTrue(payload["raw_data"]["analyst_tagged"])
        self.assertEqual(payload["raw_data"]["analyst_tags"], ["credential-access"])
        self.assertEqual(payload["raw_data"]["analyst_notes"], "reviewed")
        self.assertEqual(payload["raw_data"]["ioc_types"], ["File Name"])
        self.assertTrue(payload["raw_data"]["noise_matched"])
        self.assertEqual(payload["raw_data"]["noise_rules"], ["KnownBenign"])

    def test_purge_case_event_overlay_state_deletes_all_overlay_tables(self):
        counts = {
            "event_analyst_state": 2,
            "event_ioc_case_state": 1,
            "event_ioc_state": 5,
            "event_noise_case_state": 1,
            "event_noise_state": 4,
            "event_noise_manual_state": 3,
        }
        client = _OverlayRepairClient(counts)

        with patch.object(overlay_repair, "destructive_event_rewrite_guard", return_value=nullcontext()):
            with patch.object(overlay_repair, "wait_for_mutation_completion") as wait_mock:
                result = overlay_repair.purge_case_event_overlay_state(7, client=client, wait=True)

        self.assertEqual(result["commands_issued"], 6)
        self.assertEqual(result["mutations_completed"], 6)
        self.assertEqual(result["tables"]["event_ioc_state"], 5)
        self.assertEqual(
            client.commands,
            [
                "ALTER TABLE event_analyst_state DELETE WHERE case_id = 7",
                "ALTER TABLE event_ioc_case_state DELETE WHERE case_id = 7",
                "ALTER TABLE event_ioc_state DELETE WHERE case_id = 7",
                "ALTER TABLE event_noise_case_state DELETE WHERE case_id = 7",
                "ALTER TABLE event_noise_state DELETE WHERE case_id = 7",
                "ALTER TABLE event_noise_manual_state DELETE WHERE case_id = 7",
            ],
        )
        self.assertEqual(wait_mock.call_count, 6)

    def test_get_case_rag_stats_counts_overlay_backed_events(self):
        fake_client = types.SimpleNamespace(
            query=lambda *_args, **_kwargs: _FakeResult([(11, 13, 17)])
        )
        case = types.SimpleNamespace(id=7)
        last_match = types.SimpleNamespace(discovered_at=datetime(2026, 4, 22, 10, 0, 0))
        last_campaign = types.SimpleNamespace(detected_at=datetime(2026, 4, 22, 11, 0, 0))

        with self.app.test_request_context("/api/rag/stats/7"):
            with patch.object(rag_routes, "_load_case_or_404", return_value=(case, None)):
                with patch("utils.clickhouse.get_client", return_value=fake_client):
                    with patch("utils.event_analyst_state.ensure_event_analyst_state_table"):
                        with patch("utils.event_ioc_state.ensure_event_ioc_state_tables"):
                            with patch(
                                "utils.event_analyst_state.build_analyst_projection",
                                return_value={"join_sql": "LEFT JOIN analyst_state ON 1=1", "tagged_sql": "analyst_flag"},
                            ):
                                with patch(
                                    "utils.event_ioc_state.build_ioc_projection",
                                    return_value={"join_sql": "LEFT JOIN ioc_state ON 1=1", "has_ioc_sql": "ioc_flag"},
                                ):
                                    with patch.object(
                                        rag_models,
                                        "AttackPattern",
                                        types.SimpleNamespace(query=_FilterCountQuery(3)),
                                    ):
                                        with patch.object(
                                            rag_models,
                                            "PatternMatch",
                                            types.SimpleNamespace(
                                                query=_FilterCountQuery(5, first_value=last_match),
                                                discovered_at=_SortField(),
                                            ),
                                        ):
                                            with patch.object(
                                                rag_models,
                                                "AttackCampaign",
                                                types.SimpleNamespace(
                                                    query=_CampaignQuery(2, 1, first_value=last_campaign),
                                                    detected_at=_SortField(),
                                                ),
                                            ):
                                                response = rag_routes.get_case_rag_stats.__wrapped__(7)

        payload = response.get_json()
        self.assertTrue(payload["success"])
        self.assertEqual(payload["sigma_high_events"], 11)
        self.assertEqual(payload["ioc_events"], 13)
        self.assertEqual(payload["analyst_events"], 17)
        self.assertIsNone(payload["event_stats_error"])

    def test_rag_timeline_and_related_queries_include_overlay_conditions(self):
        anchor_rows = [
            (datetime(2026, 4, 22, 12, 0, 0), "HOST1", "4104", "PowerShell", "analyst", "Alert", "high"),
        ]
        related_client = _RagTaskClient(first_rows=anchor_rows, second_rows=[])
        timeline_client = _RagTaskClient(first_rows=[])

        with patch.object(rag_tasks, "get_flask_app", return_value=self.app):
            with patch.object(rag_tasks.rag_hunt_related, "update_state"):
                with patch.object(rag_tasks.rag_generate_timeline, "update_state"):
                    with patch("utils.clickhouse.get_fresh_client", side_effect=[related_client, timeline_client]):
                        with patch.object(rag_tasks, "ensure_event_analyst_state_table"):
                            with patch.object(rag_tasks, "ensure_event_ioc_state_tables"):
                                with patch.object(
                                    rag_tasks,
                                    "build_analyst_projection",
                                    return_value={"join_sql": "LEFT JOIN analyst_state ON 1=1", "tagged_sql": "analyst_flag"},
                                ):
                                    with patch.object(rag_tasks, "build_effective_has_ioc_clause", return_value="ioc_flag"):
                                        hunt_result = rag_tasks.rag_hunt_related.run(
                                            case_id=7,
                                            case_uuid="case-uuid",
                                            include_ioc=True,
                                            include_analyst=True,
                                            include_sigma_high=False,
                                        )
                                        timeline_result = rag_tasks.rag_generate_timeline.run(
                                            case_id=7,
                                            case_uuid="case-uuid",
                                            include_sigma=False,
                                            include_ioc=True,
                                            include_patterns=False,
                                            include_analyst=True,
                                        )

        self.assertTrue(hunt_result["success"])
        self.assertTrue(timeline_result["success"])
        self.assertIn("LEFT JOIN analyst_state ON 1=1", related_client.queries[0])
        self.assertIn("ioc_flag", related_client.queries[0])
        self.assertIn("analyst_flag = true", related_client.queries[0])
        self.assertIn("LEFT JOIN analyst_state ON 1=1", timeline_client.queries[0])
        self.assertIn("ioc_flag", timeline_client.queries[0])
        self.assertIn("analyst_flag = true", timeline_client.queries[0])


if __name__ == "__main__":
    unittest.main()
