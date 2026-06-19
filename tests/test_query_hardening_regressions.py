import os
import json
import unittest
from datetime import datetime
from unittest.mock import patch

os.environ.setdefault('SECRET_KEY', 'test-secret')

import routes.hunting_query_helpers as hunting_query_helpers
import tasks.rag_tasks as rag_tasks
import utils.chat_tools as chat_tools
import utils.ioc_artifact_tagger as ioc_artifact_tagger
from utils.deterministic_evidence_engine import DeterministicEvidenceEngine
from utils.pattern_check_definitions import CoverageAssessment


class _FakeResult:
    def __init__(self, rows):
        self.result_rows = rows


class _FakeClient:
    def __init__(self, rows):
        self.rows = rows
        self.calls = []

    def query(self, query, parameters=None):
        self.calls.append((query, parameters))
        if 'SELECT count()' in query:
            return _FakeResult([(len(self.rows),)])
        return _FakeResult(self.rows)


class QueryHardeningRegressionTestCase(unittest.TestCase):
    def test_query_events_uses_bound_parameters(self):
        client = _FakeClient([
            (
                '2026-01-01 00:00:00',
                '4624',
                'host-a',
                'alice',
                'Security',
                'Rule',
                'high',
                'cmd.exe',
                'cmd /c whoami',
                '1.2.3.4',
                '5.6.7.8',
                3,
                'remote-a',
                'workstation-a',
                'NTLM',
                'NtLmSsp',
                'summary',
            )
        ])
        malicious_host = "srv' OR 1=1 --"

        with patch.object(chat_tools, 'get_fresh_client', return_value=client):
            result = chat_tools.query_events(
                case_id=7,
                host=malicious_host,
                search_text="powershell % _",
                severity='high',
            )

        self.assertEqual(result['event_count'], 1)
        query, params = client.calls[0]
        self.assertIn('{host:String}', query)
        self.assertIn('{search_text_term_0:String}', query)
        self.assertNotIn(malicious_host, query)
        self.assertEqual(params['host'], malicious_host)
        self.assertEqual(params['search_text_term_0'], "powershell % _")

    def test_sigma_severity_filter_only_uses_allowlisted_levels(self):
        condition = hunting_query_helpers._build_sigma_alert_condition("high,critical,drop-table")

        self.assertIn("lower(rule_level) IN", condition)
        self.assertNotIn('DROP TABLE', condition)
        self.assertNotIn('drop-table', condition)
        self.assertIn("'critical'", condition)
        self.assertIn("'high'", condition)

    def test_hunting_type_filter_uses_placeholders(self):
        params = {}
        malicious_types = "evtx,foo') OR 1=1 --"

        condition = hunting_query_helpers.build_hunting_type_filter(malicious_types, params)

        self.assertIn("artifact_type IN", condition)
        self.assertNotIn("OR 1=1", condition)
        self.assertEqual(params["artifact_type_0"], "evtx")
        self.assertEqual(params["artifact_type_1"], "foo') OR 1=1 --")

    def test_hunting_type_filter_keeps_etl_trace_legacy_alias(self):
        params = {}

        condition = hunting_query_helpers.build_hunting_type_filter("etl_trace", params)

        self.assertIn("artifact_type IN", condition)
        self.assertEqual(params["artifact_type_0"], "etl_trace")
        self.assertEqual(params["artifact_type_1"], "windows_etl")
        self.assertEqual(params["artifact_type_2"], "windows_etl_event")

    def test_sequence_query_rejects_malicious_config_before_sql(self):
        class ExplodingClient:
            @staticmethod
            def query(_query, parameters=None):
                raise AssertionError("malicious sequence config reached raw SQL")

        engine = object.__new__(DeterministicEvidenceEngine)
        engine.case_id = 7
        engine.exclude_noise = False
        engine._get_ch = lambda: ExplodingClient()
        engine.rule_catalog = type(
            "Catalog",
            (),
            {
                "get_sequence_config": staticmethod(
                    lambda pattern_id: {
                        "chain": "malicious",
                        "steps": [
                            {
                                "label": "malicious_step",
                                "event_id": "4624') OR 1=1 --",
                                "direction": "before_anchor",
                                "max_offset_seconds": "5); DROP TABLE events; --",
                                "conditions": {"logon_type": "3 OR 1=1"},
                            }
                        ],
                    }
                    if pattern_id == "malicious_pattern"
                    else None
                )
            },
        )()

        sequences = engine._validate_sequences(
            "malicious_pattern",
            {
                "case_id": 7,
                "anchor_ts": datetime(2026, 6, 19, 12, 0, 0),
                "source_host": "HOST-A",
            },
            coverage=CoverageAssessment(host="HOST-A", coverage_status="full"),
            correlation_fields=["source_host"],
        )

        self.assertEqual(sequences[0].status, "inconclusive")
        self.assertEqual(sequences[0].evaluability, "query_error")
        self.assertIn("unsafe sequence event_id", sequences[0].steps[0]["error"])

    def test_windows_etl_description_is_not_source_path(self):
        description = hunting_query_helpers.build_event_description(
            "windows_etl",
            "",
            "windows_etl",
            "",
            "",
            "",
            "/opt/casescope/staging/case/ExplorerStartupLog.etl",
            "ExplorerStartupLog.etl /opt/casescope/staging/case/ExplorerStartupLog.etl",
        )

        self.assertIn("Windows ETL trace file metadata preserved", description)
        self.assertNotEqual(description, "/opt/casescope/staging/case/ExplorerStartupLog.etl")

    def test_windows_etl_event_description_uses_provider(self):
        description = hunting_query_helpers.build_event_description(
            "windows_etl_event",
            "",
            "Microsoft-Windows-TestProvider",
            "",
            "",
            "",
            "/opt/casescope/staging/case/ExplorerStartupLog.etl",
            "windows_etl_event Microsoft-Windows-TestProvider",
        )

        self.assertEqual(description, "ETL event from provider Microsoft-Windows-TestProvider")

    def test_file_triage_description_is_file_focused(self):
        description = hunting_query_helpers.build_event_description(
            "file_triage",
            "",
            "",
            "",
            "index.js",
            "",
            "/case/C/Users/User/AppData/Local/Google/Chrome/index.js",
            "index.js /case/C/Users/User/AppData/Local/Google/Chrome/index.js",
        )

        self.assertIn("File triage: index.js", description)
        self.assertNotIn("Process:", description)

    def test_jumplist_description_uses_target_and_app_metadata(self):
        description = hunting_query_helpers.build_event_description(
            "jumplist",
            "",
            "",
            "",
            "Publication2.pub",
            "",
            "C:\\Users\\cbailey\\Documents\\Publication2.pub",
            "5f7b5f1e01b83767 C:\\Users\\cbailey\\Documents\\Publication2.pub",
            extra_fields=json.dumps({
                "app_id": "5f7b5f1e01b83767",
                "entry_id": "15",
            }),
        )

        self.assertIn("Jump List referenced: Publication2.pub", description)
        self.assertIn("AppID 5f7b5f1e01b83767", description)
        self.assertNotIn("Process:", description)

    def test_jumplist_metadata_description_uses_status(self):
        description = hunting_query_helpers.build_event_description(
            "jumplist",
            "",
            "",
            "",
            "",
            "",
            "",
            "d06c94537ecaee12.automaticDestinations-ms d06c94537ecaee12 jumplist corrupt",
            extra_fields=json.dumps({
                "app_id": "d06c94537ecaee12",
                "status": "corrupt_ole",
            }),
        )

        self.assertEqual(
            description,
            "Jump List metadata: AppID d06c94537ecaee12 (corrupt ole)",
        )

    def test_wbem_repository_description_surfaces_triage_terms(self):
        description = hunting_query_helpers.build_event_description(
            "wbem_repository",
            "",
            "WMI",
            "",
            "",
            "",
            "/opt/casescope/staging/case/C/Windows/System32/wbem/Repository/OBJECTS.DATA",
            "OBJECTS.DATA __EventFilter __FilterToConsumerBinding",
            rule_title="__EventFilter | __FilterToConsumerBinding",
            extra_fields=json.dumps({
                "repository_file": "OBJECTS.DATA",
                "suspicious_term_count": 2,
                "sample_string_count": 250,
                "cim_available": False,
            }),
        )

        self.assertEqual(
            description,
            "WMI repository triage: 2 persistence terms found (__EventFilter, __FilterToConsumerBinding); 250 strings sampled; CIM decode unavailable",
        )
        self.assertNotIn("/opt/casescope/staging", description)

    def test_wbem_repository_description_handles_no_terms(self):
        description = hunting_query_helpers.build_event_description(
            "wbem_repository",
            "",
            "WMI",
            "",
            "",
            "",
            "/opt/casescope/staging/case/C/Windows/System32/wbem/Repository/INDEX.BTR",
            "INDEX.BTR NS_88591E56F7DF51C96BBDD94E4112A5C7",
            extra_fields=json.dumps({
                "repository_file": "INDEX.BTR",
                "suspicious_term_count": 0,
                "sample_string_count": 250,
                "cim_available": None,
            }),
        )

        self.assertEqual(
            description,
            "WMI repository triage: no suspicious persistence terms found; 250 strings sampled",
        )
        self.assertNotIn("INDEX.BTR", description)

    def test_defender_mplog_description_summarizes_scan_issue(self):
        description = hunting_query_helpers.build_event_description(
            "defender_mplog",
            "",
            "Microsoft Defender",
            "",
            "",
            "",
            "",
            (
                "line_number:4698 action:log message:\x00"
                "2\x000\x002\x006\x00-\x000\x006\x00-\x001\x009\x00T\x000\x006\x00:\x004\x001\x00:\x005\x006\x00.\x002\x006\x004\x00 "
                "[\x00R\x00T\x00P\x00]\x00 [\x00M\x00i\x00n\x00i\x00-\x00f\x00i\x00l\x00t\x00e\x00r\x00]\x00 "
                "U\x00n\x00s\x00u\x00c\x00c\x00e\x00s\x00s\x00f\x00u\x00l\x00 s\x00c\x00a\x00n\x00 "
                "s\x00t\x00a\x00t\x00u\x00s\x00(\x00#\x008\x000\x00)\x00:\x00 "
                "\\\x00D\x00e\x00v\x00i\x00c\x00e\x00\\\x00H\x00a\x00r\x00d\x00d\x00i\x00s\x00k\x00V\x00o\x00l\x00u\x00m\x00e\x003\x00"
                "\\\x00P\x00r\x00o\x00g\x00r\x00a\x00m\x00 F\x00i\x00l\x00e\x00s\x00 \x00(\x00x\x008\x006\x00)\x00"
                "\\\x00G\x00o\x00o\x00g\x00l\x00e\x00\\\x00G\x00o\x00o\x00g\x00l\x00e\x00U\x00p\x00d\x00a\x00t\x00e\x00r\x00"
                "\\\x00u\x00p\x00d\x00a\x00t\x00e\x00r\x00.\x00l\x00o\x00g\x00.\x00 "
                "P\x00r\x00o\x00c\x00e\x00s\x00s\x00:\x00 \x00(\x00u\x00n\x00k\x00n\x00o\x00w\x00n\x00)\x00,\x00 "
                "S\x00t\x00a\x00t\x00u\x00s\x00:\x00 \x000\x00x\x00c\x000\x000\x000\x000\x000\x004\x00b\x00,\x00 "
                "S\x00t\x00a\x00t\x00e\x00:\x00 \x000\x00,\x00 S\x00c\x00a\x00n\x00R\x00e\x00q\x00u\x00e\x00s\x00t\x00 "
                "#\x001\x00,\x00 F\x00i\x00l\x00e\x00I\x00d\x00:\x00 \x000\x00x\x001\x00,\x00 "
                "R\x00e\x00a\x00s\x00o\x00n\x00:\x00 \x00O\x00n\x00C\x00l\x00o\x00s\x00e\x00"
            ),
        )

        self.assertEqual(
            description,
            "Defender RTP scan issue: GoogleUpdater\\updater.log; status 0xc000004b; reason OnClose; process (unknown) (line 4698)",
        )

    def test_defender_mplog_description_summarizes_blocked_process_open(self):
        description = hunting_query_helpers.build_event_description(
            "defender_mplog",
            "",
            "Microsoft Defender",
            "",
            "",
            "",
            "",
            (
                "line_number:142194 action:log message:2026-06-07T01:11:53.610 "
                "[RTP] [Mini-filter] Denied OB operation OpenProcess"
                "[\\Device\\HarddiskVolume3\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.26040.7-0\\MpCmdRun.exe][Pid:7312] "
                "from process [\\Device\\HarddiskVolume3\\Windows\\System32\\conhost.exe][Pid:7260]. "
                "OriginalDesiredAccess: [0x1fffff] ResultingAccess: [0x1ff7d4]"
            ),
        )

        self.assertEqual(
            description,
            "Defender RTP blocked OpenProcess: conhost.exe -> MpCmdRun.exe; access 0x1fffff reduced to 0x1ff7d4 (line 142194)",
        )

    def test_diagnostic_log_description_surfaces_onedrive_text_sample(self):
        description = hunting_query_helpers.build_event_description(
            "diagnostic_log",
            "",
            "odl_diagnostic",
            "",
            "",
            "",
            "/opt/casescope/staging/case/C/Users/user/AppData/Local/Microsoft/OneDrive/logs/Personal/Install_2025-07-07_140847_7408-7316.loggz",
            (
                "Install_2025-07-07_140847_7408-7316.loggz "
                "/opt/casescope/staging/case/C/Users/user/AppData/Local/Microsoft/OneDrive/logs/Personal/Install_2025-07-07_140847_7408-7316.loggz "
                "odl_diagnostic "
                "0\x007\x00/\x000\x007\x00/\x002\x000\x002\x005\x00 \x001\x004\x00:\x000\x008\x00:\x004\x007\x00.\x004\x004\x006\x00 "
                "W\x00a\x00t\x00s\x00o\x00n\x00R\x00e\x00p\x00o\x00r\x00t\x00:\x00 "
                "R\x00e\x00g\x00i\x00s\x00t\x00e\x00r\x00i\x00n\x00g\x00 "
                "s\x00e\x00t\x00u\x00p\x00 l\x00o\x00g\x00 f\x00i\x00l\x00e\x00s\x00 "
                "w\x00i\x00t\x00h\x00 w\x00a\x00t\x00s\x00o\x00n\x00"
            ),
            extra_fields=json.dumps({
                "extension": ".loggz",
                "log_family": "odl_diagnostic",
            }),
        )

        self.assertEqual(
            description,
            "OneDrive diagnostic log: Install; WatsonReport: Registering setup log files with watson; extension .loggz",
        )
        self.assertNotIn("/opt/casescope/staging", description)

    def test_diagnostic_log_description_summarizes_binary_odl(self):
        description = hunting_query_helpers.build_event_description(
            "diagnostic_log",
            "",
            "odl_diagnostic",
            "",
            "",
            "",
            "/opt/casescope/staging/case/C/Users/user/AppData/Local/Microsoft/OneDrive/logs/ListSync/Business1/Nucleus-2025-07-07.1409.3460.1.odl",
            (
                "Nucleus-2025-07-07.1409.3460.1.odl "
                "/opt/casescope/staging/case/C/Users/user/AppData/Local/Microsoft/OneDrive/logs/ListSync/Business1/Nucleus-2025-07-07.1409.3460.1.odl "
                "odl_diagnostic EBFGONED\x02\x00\x00\x00\ufffd\x00\x00\x0023.081.0416.0001"
            ),
            extra_fields=json.dumps({
                "extension": ".odl",
                "log_family": "odl_diagnostic",
            }),
        )

        self.assertEqual(
            description,
            "OneDrive ODL diagnostic file: Nucleus component; binary/obfuscated sample; extension .odl",
        )
        self.assertNotIn("/opt/casescope/staging", description)

    def test_generic_evtx_description_keeps_data_out_of_primary_line(self):
        description = hunting_query_helpers.build_event_description(
            "evtx",
            "Application",
            "ExampleProvider",
            "",
            "",
            "",
            "",
            (
                "WIN11-T4VM Application 1000 provider details "
                "Data:Useful event context from EventData.Data "
                '{"EventData":{"Data":"Useful event context from EventData.Data"}}'
            ),
            event_id="1000",
        )

        self.assertEqual(
            description,
            "[Application] | ExampleProvider",
        )

    def test_msiinstaller_description_keeps_data_out_of_primary_line(self):
        description = hunting_query_helpers.build_event_description(
            "evtx",
            "Application",
            "MsiInstaller",
            "",
            "",
            "",
            "",
            (
                "WIN11-T4VM.tabinc.com Application 1035 Python 3.11.9 pip Bootstrap (64-bit), "
                "3.11.9150.0, 1033, 0, Python Software Foundation, (NULL) "
                "0x80000000000000 Data:Python 3.11.9 pip Bootstrap (64-bit), "
                "3.11.9150.0, 1033, 0, Python Software Foundation, (NULL) "
                '{"EventData":{"Data":"Python 3.11.9 pip Bootstrap (64-bit), 3.11.9150.0"}}'
            ),
            event_id="1035",
        )

        self.assertEqual(
            description,
            "[Application] | MsiInstaller",
        )

    def test_pfsense_filterlog_description_uses_structured_fields(self):
        description = hunting_query_helpers.build_event_description(
            "pfsense",
            "",
            "filterlog",
            "",
            "",
            "",
            "",
            "raw filterlog text",
            event_id="pfsense_filterlog",
            rule_title="block",
            src_ip="10.150.125.52",
            dst_ip="233.89.188.1",
            src_port=58909,
            dst_port=10001,
            extra_fields=json.dumps({
                "log_subtype": "filter",
                "interface": "hn0",
                "direction": "in",
                "protocol": "udp",
            }),
        )

        self.assertEqual(
            description,
            "Firewall blocked UDP inbound on hn0: 10.150.125.52:58909 -> 233.89.188.1:10001",
        )

    def test_pfsense_config_description_uses_summary_not_raw_blob(self):
        description = hunting_query_helpers.build_event_description(
            "pfsense",
            "",
            "config.xml",
            "",
            "",
            "",
            "",
            "log_subtype:config password_hash_present:true",
            event_id="pfsense_config_summary",
            extra_fields=json.dumps({
                "log_subtype": "config",
                "interfaces": [{"name": "wan"}, {"name": "lan"}],
                "filter_rule_count": 12,
                "ssh_enabled": True,
                "users": ["admin"],
            }),
        )

        self.assertEqual(description, "Config summary: 2 interfaces, 12 firewall rules, SSH enabled, 1 user")

    def test_sonicwall_description_uses_display_metadata(self):
        description = hunting_query_helpers.build_event_description(
            "sonicwall",
            "Audit",
            "SonicWall Audit",
            "admin",
            "",
            "",
            "",
            "raw sonicwall audit text",
            event_id="sonicwall_audit_225",
            extra_fields=json.dumps({
                "log_subtype": "audit",
                "display": {
                    "subtype": "audit",
                    "badge": "Succeeded",
                    "primary": "Audit succeeded: admin changed Original Service to HTTPS",
                    "secondary": "10.150.10.167 (51572) -> 10.150.10.1 (60443)",
                },
            }),
        )

        self.assertEqual(description, "Audit succeeded: admin changed Original Service to HTTPS")

    def test_hunting_alert_filter_rejects_unknown_mode(self):
        with self.assertRaises(ValueError):
            hunting_query_helpers._build_hunting_alert_type_filter(
                "maybe",
                "",
                "",
                "",
                "",
            )

    def test_hunting_time_filter_rejects_inverted_custom_range(self):
        params = {}

        with self.assertRaises(ValueError):
            hunting_query_helpers.build_hunting_time_filter(
                client=_FakeClient([(datetime(2026, 1, 5, 0, 0, 0),)]),
                case_id=7,
                case_tz="UTC",
                time_range="custom",
                time_start="2026-01-05T10:00",
                time_end="2026-01-05T09:00",
                params=params,
            )

    def test_hunting_search_clause_handles_mixed_group_or(self):
        params = {}

        clause = hunting_query_helpers.build_hunting_search_clause("(eventid:4625)|host:dc1", params)

        self.assertIn(" OR ", clause)
        self.assertIn("4625", params.values())
        self.assertIn("%dc1%", params.values())

    def test_process_pivot_search_matches_name_and_pid_fields(self):
        params = {}

        clause = hunting_query_helpers.build_hunting_search_clause(
            "host:ATN62288 (process:ScreenConnect.ClientService.exe|parent:ScreenConnect.ClientService.exe pid:4508|ppid:4508)",
            params,
        )

        self.assertIn("source_host ilike", clause)
        self.assertIn("process_name ilike", clause)
        self.assertIn("parent_process ilike", clause)
        self.assertIn("process_id =", clause)
        self.assertIn("parent_pid =", clause)
        self.assertNotIn("event_id =", clause)
        self.assertIn("%ATN62288%", params.values())
        self.assertIn("%ScreenConnect.ClientService.exe%", params.values())
        self.assertIn("4508", params.values())

    def test_time_filter_clause_rejects_unsupported_sql(self):
        valid = "COALESCE(timestamp_utc, timestamp) >= '2026-01-01 00:00:00'"
        self.assertEqual(rag_tasks._build_time_filter_clause(valid), f" AND {valid}")

        with self.assertRaises(ValueError):
            rag_tasks._build_time_filter_clause("1=1; DROP TABLE events")

    def test_pattern_detection_query_injects_noise_and_time_filters_into_ctes(self):
        query = """
            WITH anchors AS (
                SELECT source_host
                FROM events
                WHERE case_id = {case_id:UInt32}
                    AND event_id = '4624'
            ),
            context AS (
                SELECT username
                FROM events
                WHERE case_id = {case_id:UInt32}
                    AND event_id = '4672'
            )
            SELECT * FROM anchors
        """
        time_filter = "COALESCE(timestamp_utc, timestamp) >= '2026-01-01 00:00:00'"

        prepared = rag_tasks._prepare_pattern_detection_query(query, time_filter=time_filter)

        self.assertEqual(prepared.count("NOT (noise_matched = true)"), 2)
        self.assertEqual(prepared.count(time_filter), 2)

    def test_pattern_detection_query_scopes_filters_to_event_alias(self):
        query = """
            SELECT e.source_host
            FROM events e
            WHERE e.case_id = {case_id:UInt32}
            GROUP BY e.source_host
        """
        time_filter = "COALESCE(timestamp_utc, timestamp) >= '2026-01-01 00:00:00'"

        prepared = rag_tasks._prepare_pattern_detection_query(query, time_filter=time_filter)

        self.assertIn("NOT (e.noise_matched = true)", prepared)
        self.assertIn("COALESCE(e.timestamp_utc, e.timestamp)", prepared)

    def test_pattern_detection_query_rejects_queries_without_case_filter(self):
        with self.assertRaises(ValueError):
            rag_tasks._prepare_pattern_detection_query("SELECT * FROM events")

    def test_unsafe_regex_falls_back_to_substring_match(self):
        clause = ioc_artifact_tagger.build_regex_match_clause('(?=evil)')

        self.assertIn('LIKE', clause)
        self.assertNotIn("match(lower(", clause)


if __name__ == '__main__':
    unittest.main()
