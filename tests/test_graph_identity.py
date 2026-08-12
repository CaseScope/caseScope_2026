import unittest

from utils.graph_identity import (
    GraphEntityType,
    build_domain_entity,
    build_file_hash_entity,
    build_file_path_entity,
    build_host_entity,
    build_ip_entity,
    build_process_entity,
    build_registry_key_entity,
    build_user_entity,
)


class GraphIdentityTestCase(unittest.TestCase):
    def test_host_known_system_identity_is_stable(self):
        first = build_host_entity('WKS-1', known_system_id=42)
        second = build_host_entity('wks-1.example.local', known_system_id=42)

        self.assertEqual(first.entity_key, 'known_system:42')
        self.assertEqual(first.entity_key, second.entity_key)

    def test_hostname_alone_does_not_merge_unrelated_observed_hosts(self):
        first = build_host_entity('WKS-1', source_context='case_file:1')
        second = build_host_entity('WKS-1', source_context='case_file:2')

        self.assertNotEqual(first.entity_key, second.entity_key)

    def test_user_sid_is_strongest_identity(self):
        first = build_user_entity('CONTOSO\\jsmith', sid='S-1-5-21-1-2-3-1001', domain='CONTOSO')
        second = build_user_entity('OTHER\\renamed', sid='s-1-5-21-1-2-3-1001', domain='OTHER')

        self.assertEqual(first.entity_key, second.entity_key)
        self.assertEqual(first.entity_key, 'sid:S-1-5-21-1-2-3-1001')

    def test_same_username_with_different_authority_is_not_merged(self):
        first = build_user_entity('Administrator', domain='HOSTA')
        second = build_user_entity('Administrator', domain='HOSTB')

        self.assertNotEqual(first.entity_key, second.entity_key)

    def test_bare_username_is_rejected(self):
        with self.assertRaises(ValueError):
            build_user_entity('Administrator')

    def test_process_pid_requires_execution_anchor(self):
        first = build_process_entity(host_key='known_system:1', pid=444, start_time='2026-01-01T00:00:00')
        second = build_process_entity(host_key='known_system:1', pid=444, start_time='2026-01-01T00:05:00')
        replay = build_process_entity(host_key='known_system:1', pid=444, start_time='2026-01-01T00:00:00')

        self.assertNotEqual(first.entity_key, second.entity_key)
        self.assertEqual(first.entity_key, replay.entity_key)
        with self.assertRaises(ValueError):
            build_process_entity(host_key='known_system:1', pid=444)

    def test_file_path_and_file_hash_are_separate_identity_types(self):
        path = build_file_path_entity(r'c:/Windows//System32\cmd.exe', host_key='known_system:1')
        same_path = build_file_path_entity(r'C:\WINDOWS\System32\cmd.exe', host_key='known_system:1')
        digest = 'a' * 64
        file_hash = build_file_hash_entity('sha256', digest)

        self.assertEqual(path.entity_key, same_path.entity_key)
        self.assertEqual(path.entity_type, GraphEntityType.FILE_PATH)
        self.assertEqual(file_hash.entity_type, GraphEntityType.FILE_HASH)
        self.assertNotEqual(path.entity_key, file_hash.entity_key)

    def test_file_hash_algorithm_and_length_are_part_of_identity(self):
        sha256 = build_file_hash_entity('sha256', 'a' * 64)
        sha1 = build_file_hash_entity('sha1', 'a' * 40)

        self.assertNotEqual(sha256.entity_key, sha1.entity_key)
        with self.assertRaises(ValueError):
            build_file_hash_entity('sha256', 'a' * 40)

    def test_ip_canonicalization(self):
        self.assertEqual(build_ip_entity('10.0.0.1').canonical_value, '10.0.0.1')
        self.assertEqual(build_ip_entity('2001:0db8:0:0:0:0:0:1').canonical_value, '2001:db8::1')

    def test_domain_case_normalization(self):
        self.assertEqual(build_domain_entity('Example.COM.').entity_key, 'domain:example.com')

    def test_registry_root_normalization(self):
        hklm = build_registry_key_entity(r'HKLM\Software\Microsoft')
        full = build_registry_key_entity(r'HKEY_LOCAL_MACHINE\Software\Microsoft')

        self.assertEqual(hklm.entity_key, full.entity_key)


if __name__ == '__main__':
    unittest.main()
