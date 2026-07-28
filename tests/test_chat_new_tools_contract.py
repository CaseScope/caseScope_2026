"""Contract tests for the eight tools added to the assistant.

Each one is checked for the three things that make a tool safe to expose: it is
registered with a schema the validator accepts, it declares a policy tier and
registry metadata, and its payload carries provenance plus an honest statement
of what the result does and does not establish.
"""

import os
import sys
import types
import unittest
from unittest.mock import patch

sys.path.insert(0, "/opt/casescope/tests")

os.environ.setdefault("SECRET_KEY", "test-secret")

from test_forensic_chat_tools import _ChatToolClient, _FakeResult, _load_modules  # noqa: E402


NEW_TOOLS = (
    "get_raw_event",
    "get_authentication_summary",
    "get_entity_profile",
    "get_hunt_findings",
    "get_persistence_artifacts",
    "get_file_activity",
    "run_detector",
    "search_pattern_library",
)


class NewToolsBaseTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.forensic_chat_sources, cls.chat_tools = _load_modules()

    def _schema(self, name):
        for definition in self.chat_tools.TOOL_DEFINITIONS:
            function = definition.get("function") or {}
            if function.get("name") == name:
                return function
        return None


class NewToolRegistrationTestCase(NewToolsBaseTestCase):
    def test_every_new_tool_is_registered_and_declared(self):
        for name in NEW_TOOLS:
            with self.subTest(tool=name):
                self.assertIn(name, self.chat_tools.TOOL_REGISTRY)
                schema = self._schema(name)
                self.assertIsNotNone(schema, f"{name} has no schema")
                self.assertTrue(schema.get("description"))
                parameters = schema.get("parameters") or {}
                self.assertEqual(parameters.get("type"), "object")
                self.assertIsInstance(parameters.get("properties"), dict)
                self.assertIsInstance(parameters.get("required"), list)

    def test_every_tool_with_a_schema_has_an_implementation(self):
        """A schema the model can see but nothing can execute is a dead end."""
        for definition in self.chat_tools.TOOL_DEFINITIONS:
            name = (definition.get("function") or {}).get("name")
            with self.subTest(tool=name):
                self.assertIn(name, self.chat_tools.TOOL_REGISTRY)

    def test_every_registered_tool_has_registry_metadata(self):
        """The fallback description told the analyst nothing about the tool."""
        from utils.chat.tool_providers import _TOOL_DESCRIPTIONS, get_tool_provider

        for name in sorted(self.chat_tools.TOOL_REGISTRY):
            with self.subTest(tool=name):
                self.assertIn(name, _TOOL_DESCRIPTIONS, f"{name} has no description")
                provider = get_tool_provider(name)
                self.assertNotEqual(provider.description, "Assistant-visible CaseScope tool.")
                self.assertTrue(provider.tier.value)
                self.assertTrue(provider.provenance.value)

    def test_sensitive_new_tools_require_confirmation(self):
        from utils.chat.policy import resolve_chat_tool_policy
        from utils.chat.dispatch import ToolTier

        for name in ("get_raw_event", "get_entity_profile", "get_file_activity",
                     "get_persistence_artifacts", "run_detector"):
            tier, _provenance = resolve_chat_tool_policy(name)
            with self.subTest(tool=name):
                self.assertEqual(tier, ToolTier.READ_SENSITIVE)

    def test_pattern_library_is_gated_on_the_ai_capability(self):
        """Semantic lookup runs through the RAG stack, which is licensed."""
        from utils.chat.policy import REQUIRED_CHAT_TOOL_FEATURES

        self.assertEqual(REQUIRED_CHAT_TOOL_FEATURES.get("search_pattern_library"), "ai")

    def test_a_declared_feature_requirement_is_enforced_not_just_disclosed(self):
        from utils.chat.policy import REQUIRED_CHAT_TOOL_FEATURES
        from utils.feature_availability import FeatureAvailability

        for tool_name, feature in REQUIRED_CHAT_TOOL_FEATURES.items():
            with self.subTest(tool=tool_name, feature=feature):
                checker = {
                    "ai": "is_ai_enabled",
                    "threat_intel": "is_threat_intel_enabled",
                }[feature]
                with patch.object(FeatureAvailability, checker, return_value=False):
                    self.assertFalse(
                        FeatureAvailability.is_chat_tool_feature_enabled(tool_name),
                        f"{tool_name} declares {feature} but is not gated on it",
                    )


class RawEventTestCase(NewToolsBaseTestCase):
    def test_a_full_event_is_returned_with_its_parsed_raw_payload(self):
        row = (
            "2026-06-08 15:27:32", "2026-06-08 19:27:32", "evtx", "4624", "Security",
            "Microsoft-Windows-Security-Auditing", "HOST-1", "alice", "svchost.exe",
            r"C:\Windows\System32\svchost.exe", "services.exe", "svchost -k netsvcs",
            r"C:\Windows\Temp\payload.dll", "", "", "", 2048, "Suspicious Logon", "high",
            ["T1078"], ["Defense Evasion"], "10.0.0.5", "0.0.0.0", 3, "REMOTE-1",
            "WKSTN-9", "NTLM", "NtLmSsp", 4242, "Security.evtx", "record:4242|file:security.evtx|host:host-1",
            '{"EventData": {"TargetUserName": "alice"}}', '{"provenance": {}}',
        )
        client = _ChatToolClient([row])

        with patch.object(self.chat_tools, "get_fresh_client", return_value=client):
            result = self.chat_tools.get_raw_event(
                case_id=7, selector_key="record:4242|file:security.evtx|host:host-1",
            )

        self.assertTrue(result["found"])
        event = result["event"]
        self.assertEqual(event["raw_json"], {"EventData": {"TargetUserName": "alice"}})
        self.assertEqual(event["username"], "alice")
        self.assertEqual(event["record_id"], 4242)
        self.assertEqual(event["mitre_attack_ids"], ["T1078"])
        # An empty address must not read as a real one.
        self.assertEqual(event["dst_ip"], "")
        self.assertEqual(event["src_ip"], "10.0.0.5")
        self.assertIn("_provenance", result)

    def test_an_unidentifiable_request_says_which_identifiers_work(self):
        result = self.chat_tools.get_raw_event(case_id=7)

        self.assertIn("selector_key", result["error"])
        self.assertIn("record_id", result["error"])

    def test_a_missing_event_is_reported_as_not_found_not_as_an_error(self):
        client = _ChatToolClient([])

        with patch.object(self.chat_tools, "get_fresh_client", return_value=client):
            result = self.chat_tools.get_raw_event(case_id=7, selector_key="event_id:9999")

        self.assertFalse(result["found"])
        self.assertIn("No event", result["reason"])


class AuthenticationSummaryTestCase(NewToolsBaseTestCase):
    def test_outcomes_and_failure_rate_are_computed_from_the_corpus(self):
        class _AuthClient:
            def __init__(self):
                self.calls = []

            def query(self, query, parameters=None):
                self.calls.append(query)
                if "countIf" in query:
                    return _FakeResult([(
                        150, 100, 50, 3, 7, 12, 4,
                        "2026-06-01 00:00:00", "2026-06-09 23:00:00",
                    )])
                return _FakeResult([("3", 90), ("10", 40)])

        client = _AuthClient()
        with patch.object(self.chat_tools, "get_fresh_client", return_value=client), \
             patch.object(self.chat_tools, "ensure_event_noise_state_tables", lambda _client: None):
            result = self.chat_tools.get_authentication_summary(case_id=7)

        summary = result["summary"]
        self.assertEqual(summary["successful_logons"], 100)
        self.assertEqual(summary["failed_logons"], 50)
        self.assertEqual(summary["failure_rate_percent"], 33.3)
        self.assertEqual(summary["distinct_accounts"], 12)
        self.assertEqual(result["by_logon_type"][0], {"value": "3", "count": 90})
        self.assertEqual(result["noise_filter"], "excluded")

    def test_no_authentication_events_yields_no_failure_rate_rather_than_zero(self):
        class _EmptyAuthClient:
            def query(self, query, parameters=None):
                if "countIf" in query:
                    return _FakeResult([(0, 0, 0, 0, 0, 0, 0, None, None)])
                return _FakeResult([])

        with patch.object(self.chat_tools, "get_fresh_client", return_value=_EmptyAuthClient()), \
             patch.object(self.chat_tools, "ensure_event_noise_state_tables", lambda _client: None):
            result = self.chat_tools.get_authentication_summary(case_id=7)

        self.assertEqual(result["summary"]["total_authentication_events"], 0)
        self.assertIsNone(result["summary"]["failure_rate_percent"])


class EntityProfileTestCase(NewToolsBaseTestCase):
    def _client(self, total=42):
        class _EntityClient:
            def __init__(self):
                self.queries = []

            def query(self, query, parameters=None):
                self.queries.append(query)
                if "uniqExact" in query and "count() AS total" in query:
                    return _FakeResult([(
                        total, "2026-06-01 00:00:00", "2026-06-09 00:00:00", 2, 3, 5,
                    )])
                return _FakeResult([("evtx", 30)])

        return _EntityClient()

    def test_an_ip_entity_is_detected_and_matched_on_address_columns(self):
        client = self._client()
        with patch.object(self.chat_tools, "get_fresh_client", return_value=client), \
             patch.object(self.chat_tools, "ensure_event_noise_state_tables", lambda _c: None):
            result = self.chat_tools.get_entity_profile(case_id=7, entity="10.0.0.5")

        self.assertEqual(result["entity_type"], "ip")
        self.assertIn("src_ip", " ".join(client.queries))
        self.assertEqual(result["activity"]["total_events"], 42)
        self.assertEqual(result["activity"]["high_severity_events"], 5)

    def test_a_qualified_account_is_detected_as_a_user(self):
        client = self._client()
        with patch.object(self.chat_tools, "get_fresh_client", return_value=client), \
             patch.object(self.chat_tools, "ensure_event_noise_state_tables", lambda _c: None):
            result = self.chat_tools.get_entity_profile(case_id=7, entity="ACME\\alice")

        self.assertEqual(result["entity_type"], "user")
        self.assertIn("e.username", " ".join(client.queries))

    def test_a_bare_name_is_treated_as_a_host_and_matches_remote_columns(self):
        client = self._client()
        with patch.object(self.chat_tools, "get_fresh_client", return_value=client), \
             patch.object(self.chat_tools, "ensure_event_noise_state_tables", lambda _c: None):
            result = self.chat_tools.get_entity_profile(case_id=7, entity="WKSTN-7")

        self.assertEqual(result["entity_type"], "host")
        executed = " ".join(client.queries)
        self.assertIn("remote_host", executed)
        self.assertIn("workstation_name", executed)

    def test_an_unknown_entity_reports_not_found_with_the_scope_it_searched(self):
        client = self._client(total=0)
        with patch.object(self.chat_tools, "get_fresh_client", return_value=client), \
             patch.object(self.chat_tools, "ensure_event_noise_state_tables", lambda _c: None):
            result = self.chat_tools.get_entity_profile(case_id=7, entity="GHOST-1")

        self.assertFalse(result["found"])
        self.assertIn("No events", result["reason"])

    def test_an_unknown_entity_type_is_rejected_by_name(self):
        result = self.chat_tools.get_entity_profile(case_id=7, entity="x", entity_type="service")

        self.assertIn("entity_type", result["error"])


class HuntFindingsTestCase(NewToolsBaseTestCase):
    def _findings(self, count):
        return {
            "findings": [
                {
                    "pattern_name": f"Pattern {index}",
                    "category": "Execution",
                    "severity": "high",
                    "confidence": 80,
                    "source_label": "deterministic",
                    "source_host": "HOST-1",
                    "event_count": 3,
                    "reasoning": "Because the process chain is unusual.",
                }
                for index in range(count)
            ],
            "summary": {"total": count},
        }

    def test_findings_are_paged_and_reasoning_is_marked_model_generated(self):
        fake_module = types.ModuleType("utils.unified_findings")
        fake_module.get_unified_findings = lambda *args, **kwargs: self._findings(70)

        with patch.dict(sys.modules, {"utils.unified_findings": fake_module}):
            first = self.chat_tools.get_hunt_findings(case_id=7, limit=25)
            second = self.chat_tools.get_hunt_findings(case_id=7, limit=25, offset=25)

        self.assertEqual(first["returned_count"], 25)
        self.assertEqual(first["next_offset"], 25)
        self.assertTrue(first["truncated"])
        self.assertEqual(second["offset"], 25)
        self.assertNotEqual(first["findings"][0]["pattern"], second["findings"][0]["pattern"])
        self.assertEqual(
            first["findings"][0]["field_provenance"]["reasoning"], "MODEL_SYNTHESIZED"
        )
        self.assertIn("not itself evidence", first["detector_of_record"])

    def test_a_rule_filter_narrows_to_matching_pattern_names(self):
        payload = self._findings(3)
        payload["findings"][1]["pattern_name"] = "Kerberoasting Detected"
        fake_module = types.ModuleType("utils.unified_findings")
        fake_module.get_unified_findings = lambda *args, **kwargs: payload

        with patch.dict(sys.modules, {"utils.unified_findings": fake_module}):
            result = self.chat_tools.get_hunt_findings(case_id=7, rule="kerberoast")

        self.assertEqual(result["total_matches"], 1)
        self.assertEqual(result["findings"][0]["pattern"], "Kerberoasting Detected")

    def test_an_invalid_severity_is_rejected_before_querying(self):
        result = self.chat_tools.get_hunt_findings(case_id=7, severity="apocalyptic")

        self.assertIn("Invalid severity", result["error"])


class PersistenceAndFileActivityTestCase(NewToolsBaseTestCase):
    def _event_row(self, summary="", target_path="", event_id="4688", artifact="evtx"):
        return (
            "2026-06-08 15:27:32", artifact, event_id, "Security", "Provider", "alice",
            "svchost.exe", r"C:\Windows\svchost.exe", "services.exe", "cmd /c x",
            target_path, "", "", "", 0, "Rule", [], [], summary,
        )

    def test_persistence_rows_are_labelled_with_the_mechanism_they_match(self):
        rows = [
            self._event_row(summary=r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run set"),
            self._event_row(summary="Service created", event_id="7045"),
            self._event_row(summary="TaskCache entry written"),
            self._event_row(summary="something else entirely", event_id="4688"),
        ]
        client = _ChatToolClient(rows, count_value=4)

        with patch.object(self.chat_tools, "get_fresh_client", return_value=client), \
             patch.object(self.chat_tools, "ensure_event_noise_state_tables", lambda _c: None):
            result = self.chat_tools.get_persistence_artifacts(case_id=7)

        mechanisms = [item["persistence_mechanism"] for item in result["artifacts"]]
        self.assertEqual(
            mechanisms,
            ["registry_run_key", "service", "scheduled_task", "unclassified"],
        )
        self.assertEqual(result["mechanisms_in_page"]["registry_run_key"], 1)
        # A location match is not a confirmed mechanism, and the payload says so.
        self.assertIn("not a confirmed mechanism", result["detection_basis"])

    def test_file_activity_filters_narrow_the_query_and_page(self):
        rows = [self._event_row(target_path=r"C:\Users\alice\Downloads\evil.exe")] * 25
        client = _ChatToolClient(rows, count_value=90)

        with patch.object(self.chat_tools, "get_fresh_client", return_value=client), \
             patch.object(self.chat_tools, "ensure_event_noise_state_tables", lambda _c: None):
            result = self.chat_tools.get_file_activity(
                case_id=7, filename="evil.exe", limit=25, offset=25,
            )

        executed = " ".join(client.queries)
        self.assertIn("OFFSET", executed)
        self.assertIn("target_path", executed)
        self.assertEqual(result["offset"], 25)
        self.assertEqual(result["next_offset"], 50)
        self.assertTrue(result["truncated"])
        self.assertEqual(result["reviewed_filters"]["filename"], "evil.exe")


class RunDetectorTestCase(NewToolsBaseTestCase):
    def test_the_advertised_detectors_match_the_pipeline_stage_list(self):
        """The enum the model sees must name detectors that actually exist."""
        from utils.stateful_detectors import DETECTOR_STAGES

        pipeline_names = {
            stage["module_path"].rsplit(".", 1)[-1] for stage in DETECTOR_STAGES
        }
        self.assertEqual(set(self.chat_tools.DETECTOR_NAMES), pipeline_names)

    def test_detectors_are_resolved_from_the_pipeline_on_first_use(self):
        stages = (
            {"module_path": "utils.stateful_detectors.brute_force",
             "class_name": "BruteForceDetector"},
        )
        fake_package = types.ModuleType("utils.stateful_detectors")
        fake_package.DETECTOR_STAGES = stages

        self.chat_tools._DETECTOR_REGISTRY = None
        try:
            with patch.dict(sys.modules, {"utils.stateful_detectors": fake_package}):
                resolved = self.chat_tools.available_detectors()
        finally:
            self.chat_tools._DETECTOR_REGISTRY = None

        self.assertEqual(
            resolved,
            {"brute_force": {
                "class_name": "BruteForceDetector",
                "module_path": "utils.stateful_detectors.brute_force",
            }},
        )

    def test_an_unknown_detector_lists_the_ones_that_exist(self):
        result = self.chat_tools.run_detector(case_id=7, detector="magic")

        self.assertIn("Unknown detector", result["error"])
        self.assertIn("brute_force", result["available_detectors"])
        self.assertIn("password_spraying", result["available_detectors"])

    def test_findings_are_returned_without_being_written_to_the_ledger(self):
        class _Finding:
            def to_dict(self):
                return {
                    "id": 91,
                    "analysis_id": "should-not-leak",
                    "finding_type": "password_spraying",
                    "entity_value": "10.0.0.5",
                    "severity": "high",
                }

        class _Detector:
            def __init__(self, case_id, analysis_id):
                self.case_id = case_id
                self.analysis_id = analysis_id

            def detect(self):
                return [_Finding()]

        fake_module = types.ModuleType("utils.stateful_detectors.password_spraying")
        fake_module.PasswordSprayingDetector = _Detector
        rollbacks = []

        with patch.dict(sys.modules, {"utils.stateful_detectors.password_spraying": fake_module}), \
             patch.object(self.chat_tools.db, "session", types.SimpleNamespace(
                 rollback=lambda: rollbacks.append(True))):
            result = self.chat_tools.run_detector(case_id=7, detector="password_spraying")

        self.assertEqual(result["finding_count"], 1)
        self.assertFalse(result["persisted"])
        # The ad-hoc run is discarded rather than committed.
        self.assertTrue(rollbacks)
        finding = result["findings"][0]
        self.assertEqual(finding["finding_type"], "password_spraying")
        # A synthetic analysis id would look like a recorded run.
        self.assertNotIn("id", finding)
        self.assertNotIn("analysis_id", finding)
        self.assertIn("not recorded", result["interpretation"])

    def test_a_failing_detector_reports_the_failure_rather_than_raising(self):
        class _Detector:
            def __init__(self, case_id, analysis_id):
                pass

            def detect(self):
                raise RuntimeError("clickhouse unavailable")

        fake_module = types.ModuleType("utils.stateful_detectors.brute_force")
        fake_module.BruteForceDetector = _Detector

        with patch.dict(sys.modules, {"utils.stateful_detectors.brute_force": fake_module}):
            result = self.chat_tools.run_detector(case_id=7, detector="brute_force")

        self.assertIn("clickhouse unavailable", result["error"])
        self.assertFalse(result["persisted"])


class PatternLibraryTestCase(NewToolsBaseTestCase):
    def _install(self, matches):
        embeddings = types.ModuleType("utils.rag_embeddings")
        embeddings.embed_text = lambda text: [0.1, 0.2, 0.3]
        vectorstore = types.ModuleType("utils.rag_vectorstore")
        vectorstore.search_similar_patterns = lambda vector, limit=10, score_threshold=None: matches
        return {
            "utils.rag_embeddings": embeddings,
            "utils.rag_vectorstore": vectorstore,
        }

    def test_patterns_are_labelled_as_reference_knowledge_not_case_evidence(self):
        matches = [{
            "id": 1,
            "score": 0.8123,
            "payload": {
                "name": "Kerberoasting",
                "description": "Requesting service tickets to crack offline.",
                "mitre_technique": "T1558.003",
                "category": "Credential Access",
            },
        }]

        with patch.dict(sys.modules, self._install(matches)):
            result = self.chat_tools.search_pattern_library(
                case_id=7, question="service tickets requested in bulk",
            )

        pattern = result["patterns"][0]
        self.assertEqual(pattern["name"], "Kerberoasting")
        self.assertEqual(pattern["similarity"], 0.812)
        self.assertEqual(pattern["emitted_provenance"], "MODEL_SYNTHESIZED")
        self.assertEqual(result["evidence_status"], "not_case_evidence")
        self.assertIn("not the detector of record", result["usage"])
        self.assertEqual(result["provenance_summary"]["highest_provenance"], "MODEL_SYNTHESIZED")

    def test_an_empty_question_is_rejected(self):
        result = self.chat_tools.search_pattern_library(case_id=7, question="   ")

        self.assertIn("question is required", result["error"])

    def test_an_unavailable_vector_store_is_reported_not_raised(self):
        embeddings = types.ModuleType("utils.rag_embeddings")

        def _fail(_text):
            raise RuntimeError("embedding model not loaded")

        embeddings.embed_text = _fail
        vectorstore = types.ModuleType("utils.rag_vectorstore")
        vectorstore.search_similar_patterns = lambda *args, **kwargs: []

        with patch.dict(sys.modules, {
            "utils.rag_embeddings": embeddings,
            "utils.rag_vectorstore": vectorstore,
        }):
            result = self.chat_tools.search_pattern_library(case_id=7, question="anything")

        self.assertIn("embedding model not loaded", result["error"])


if __name__ == "__main__":
    unittest.main()
