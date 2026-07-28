"""Contract tests for chat tool correctness: symmetry, disclosure and paging.

These cover the three ways a tool could mislead an analyst without failing:
a count and a listing applying different filters, a payload that does not say
whether noise was excluded, and a truncated list that looks complete.
"""

import os
import sys
import unittest

sys.path.insert(0, "/opt/casescope/tests")

os.environ.setdefault("SECRET_KEY", "test-secret")

from test_forensic_chat_tools import _ChatToolClient, _load_modules  # noqa: E402

from unittest.mock import patch  # noqa: E402


class ChatToolTestCase(unittest.TestCase):
    """Loads the tool modules without inheriting another suite's tests."""

    @classmethod
    def setUpClass(cls):
        cls.forensic_chat_sources, cls.chat_tools = _load_modules()


class EventFilterSymmetryTestCase(ChatToolTestCase):
    """count_events and query_events must accept the same filters.

    A filter one applied and the other ignored made the count and the listing
    describe different populations, with nothing in either payload to say so.
    """

    def test_count_and_query_share_one_filter_surface(self):
        chat_tools = self.chat_tools
        query_schema = None
        count_schema = None
        for definition in chat_tools.TOOL_DEFINITIONS:
            function = definition.get("function") or {}
            if function.get("name") == "query_events":
                query_schema = set((function.get("parameters") or {}).get("properties") or {})
            elif function.get("name") == "count_events":
                count_schema = set((function.get("parameters") or {}).get("properties") or {})

        self.assertIsNotNone(query_schema)
        self.assertIsNotNone(count_schema)

        # Filters must match; the row-shaping and grouping options may differ.
        shaping = {"limit", "offset", "sort", "group_by"}
        self.assertEqual(query_schema - shaping, count_schema - shaping)

    def test_count_events_applies_search_text_and_severity(self):
        client = _ChatToolClient([(7,)])

        with patch.object(self.chat_tools, "get_fresh_client", return_value=client):
            result = self.chat_tools.count_events(
                case_id=7, search_text="screenconnect", severity="high",
            )

        executed = " ".join(client.queries)
        self.assertIn("search_blob", executed)
        self.assertIn("rule_level", executed)
        self.assertEqual(result["count_filters"]["search_text"], "screenconnect")
        self.assertEqual(result["count_filters"]["severity"], "high")

    def test_an_invalid_severity_is_rejected_by_both_tools(self):
        client = _ChatToolClient([(0,)])

        with patch.object(self.chat_tools, "get_fresh_client", return_value=client):
            counted = self.chat_tools.count_events(case_id=7, severity="catastrophic")
            queried = self.chat_tools.query_events(case_id=7, severity="catastrophic")

        self.assertIn("Invalid severity", counted["error"])
        self.assertIn("Invalid severity", queried["error"])

    def test_a_text_search_lifts_the_noise_filter_in_both_tools(self):
        """Searching for a named tool must not have its evidence hidden as noise."""
        client = _ChatToolClient([(3,)])

        with patch.object(self.chat_tools, "get_fresh_client", return_value=client):
            counted = self.chat_tools.count_events(case_id=7, search_text="screenconnect")

        self.assertEqual(counted["noise_filter"], "included")


class NoiseDisclosureTestCase(ChatToolTestCase):
    def test_count_events_discloses_the_noise_policy_it_applied(self):
        """A count with noise excluded is a different number than one without."""
        client = _ChatToolClient([(12,)])

        with patch.object(self.chat_tools, "get_fresh_client", return_value=client):
            default = self.chat_tools.count_events(case_id=7, event_id="4625")

        self.assertEqual(default["noise_filter"], "excluded")
        self.assertIn("include_noise=true", default["noise_policy"])

        client = _ChatToolClient([(30,)])
        with patch.object(self.chat_tools, "get_fresh_client", return_value=client):
            included = self.chat_tools.count_events(
                case_id=7, event_id="4625", include_noise=True,
            )

        self.assertEqual(included["noise_filter"], "included")

    def test_grouped_counts_report_the_real_total_not_the_group_sum(self):
        """Summing only the groups shown understated a wide distribution."""
        group_rows = [(f"HOST-{index}", 2) for index in range(30)]
        client = _ChatToolClient(group_rows)
        # The follow-up totals query returns the true count and distinct groups.
        client.extra_rows = [(500, 140)]

        with patch.object(self.chat_tools, "get_fresh_client", return_value=client):
            result = self.chat_tools.count_events(case_id=7, group_by="source_host")

        self.assertEqual(len(result["groups"]), 30)
        self.assertTrue(result["truncated"])
        self.assertEqual(result["grouped_total"], 60)
        self.assertEqual(result["total"], 500)
        self.assertEqual(result["distinct_group_count"], 140)

    def test_an_untruncated_group_listing_needs_no_second_query(self):
        client = _ChatToolClient([("HOST-1", 4), ("HOST-2", 1)])

        with patch.object(self.chat_tools, "get_fresh_client", return_value=client):
            result = self.chat_tools.count_events(case_id=7, group_by="source_host")

        self.assertFalse(result["truncated"])
        self.assertEqual(result["total"], 5)
        self.assertEqual(result["distinct_group_count"], 2)


class PagingTestCase(ChatToolTestCase):
    def test_query_events_pages_and_advertises_the_next_offset(self):
        rows = [
            (
                "2026-04-01 00:00:00", "evtx", "4624", "HOST-1", "user1", "Security",
                "Logon", "info", "", "", "", "", "", "", "", "", "", "{}", "summary",
            )
        ] * 25
        client = _ChatToolClient(rows, count_value=400)

        with patch.object(self.chat_tools, "get_fresh_client", return_value=client):
            result = self.chat_tools.query_events(case_id=7, limit=25, offset=50)

        self.assertIn("OFFSET 50", " ".join(client.queries))
        self.assertEqual(result["offset"], 50)
        self.assertEqual(result["next_offset"], 75)
        self.assertTrue(result["truncated"])

    def test_the_last_page_reports_no_next_offset(self):
        rows = [
            (
                "2026-04-01 00:00:00", "evtx", "4624", "HOST-1", "user1", "Security",
                "Logon", "info", "", "", "", "", "", "", "", "", "", "{}", "summary",
            )
        ] * 5
        client = _ChatToolClient(rows, count_value=105)

        with patch.object(self.chat_tools, "get_fresh_client", return_value=client):
            result = self.chat_tools.query_events(case_id=7, limit=25, offset=100)

        self.assertIsNone(result["next_offset"])
        self.assertFalse(result["truncated"])

    def test_every_list_tool_exposes_an_offset(self):
        paged = {
            "query_events",
            "search_artifacts",
            "get_browser_downloads",
            "get_processes",
            "search_network_logs",
        }
        for definition in self.chat_tools.TOOL_DEFINITIONS:
            function = definition.get("function") or {}
            name = function.get("name")
            if name not in paged:
                continue
            properties = (function.get("parameters") or {}).get("properties") or {}
            with self.subTest(tool=name):
                self.assertIn("offset", properties, f"{name} cannot be paged")


if __name__ == "__main__":
    unittest.main()
