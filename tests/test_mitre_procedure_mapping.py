import importlib.util
import os
import unittest


REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _load_rules_module():
    module_path = os.path.join(REPO_ROOT, "utils", "mitre_procedure_rules.py")
    spec = importlib.util.spec_from_file_location("mitre_procedure_rules_under_test", module_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class MitreProcedureRulesTests(unittest.TestCase):
    def test_seed_rules_cover_core_windows_procedures(self):
        module = _load_rules_module()
        rules = module.get_mitre_procedure_rules()
        rule_ids = {rule["id"] for rule in rules}

        self.assertGreaterEqual(len(rules), 25)
        self.assertIn("win_logon_rdp_4624_type10", rule_ids)
        self.assertIn("win_powershell_encoded_or_hidden", rule_ids)
        self.assertIn("win_certutil_download", rule_ids)
        self.assertIn("win_reg_run_key_add", rule_ids)
        self.assertIn("win_lsass_process_access", rule_ids)
        self.assertIn("win_smb_client_ipc_admin_share", rule_ids)
        self.assertIn("win_task_scheduler_action_start", rule_ids)
        self.assertIn("win_netsh_firewall_rule_modify", rule_ids)

    def test_rules_have_required_mapping_contract(self):
        module = _load_rules_module()

        for rule in module.get_mitre_procedure_rules():
            with self.subTest(rule=rule["id"]):
                self.assertTrue(rule["id"])
                self.assertTrue(rule["name"])
                self.assertTrue(rule["attack_ids"])
                self.assertIn("case_id = {case_id:UInt32}", rule["where_sql"])
                self.assertGreaterEqual(rule["mapping_confidence"], 0)
                self.assertLessEqual(rule["mapping_confidence"], 100)
                self.assertIn(rule["evidence_strength"], {"medium", "high", "very_high"})
                self.assertEqual(rule["source"], "mitre_procedure_rule")
                self.assertTrue(rule["reason"])
                self.assertTrue(rule["matched_fields"])

    def test_mapping_examples_hit_expected_attack_ids(self):
        module = _load_rules_module()
        attack_ids_by_rule = {
            rule["id"]: set(rule["attack_ids"])
            for rule in module.get_mitre_procedure_rules()
        }

        self.assertEqual(attack_ids_by_rule["win_logon_rdp_4624_type10"], {"T1021.001"})
        self.assertEqual(attack_ids_by_rule["win_whoami_discovery"], {"T1033"})
        self.assertEqual(attack_ids_by_rule["win_domain_controller_discovery"], {"T1018"})
        self.assertEqual(attack_ids_by_rule["win_regsvr32_remote_scriptlet"], {"T1218.010"})
        self.assertIn("T1003.001", attack_ids_by_rule["win_lsass_process_access"])
        self.assertEqual(attack_ids_by_rule["win_smb_client_ipc_admin_share"], {"T1021.002"})
        self.assertEqual(attack_ids_by_rule["win_task_scheduler_action_start"], {"T1053.005"})
        self.assertEqual(attack_ids_by_rule["win_service_discovery_sc_query"], {"T1007"})
        self.assertEqual(attack_ids_by_rule["win_logged_on_user_session_discovery"], {"T1033"})
        self.assertEqual(attack_ids_by_rule["win_netsh_firewall_rule_modify"], {"T1685"})


class MitreHuntingTabTests(unittest.TestCase):
    def test_mitre_is_first_class_hunting_tab(self):
        catalog_path = os.path.join(REPO_ROOT, "parsers", "catalog.py")
        template_path = os.path.join(REPO_ROOT, "static", "templates", "case_hunting.html")

        with open(catalog_path, "r", encoding="utf-8") as handle:
            catalog = handle.read()
        with open(template_path, "r", encoding="utf-8") as handle:
            template = handle.read()

        self.assertLess(catalog.index("'id': 'events'"), catalog.index("'id': 'mitre'"))
        self.assertIn("const SHARED_GRID_TABS = HUNTING_TABS.map(tab => tab.id).filter(tab => !['mitre', 'other'].includes(tab));", template)
        self.assertIn('id="tab-content-mitre"', template)
        self.assertIn("currentTab === 'mitre'", template)

    def test_event_detail_modal_is_not_inside_hidden_events_tab(self):
        template_path = os.path.join(REPO_ROOT, "static", "templates", "case_hunting.html")
        events_tab_path = os.path.join(REPO_ROOT, "static", "templates", "hunting", "tab_events.html")

        with open(template_path, "r", encoding="utf-8") as handle:
            template = handle.read()
        with open(events_tab_path, "r", encoding="utf-8") as handle:
            events_tab = handle.read()

        self.assertIn('id="event-detail-modal"', template)
        self.assertNotIn('id="event-detail-modal"', events_tab)
        self.assertLess(template.index('id="tab-content-events"'), template.index('id="event-detail-modal"'))

    def test_mitre_search_uses_tactic_dropdown_and_preserves_selected_match(self):
        template_path = os.path.join(REPO_ROOT, "static", "templates", "case_hunting.html")

        with open(template_path, "r", encoding="utf-8") as handle:
            template = handle.read()

        self.assertIn('<select id="mitreSearchTactic"', template)
        self.assertIn('<option value="Discovery">Discovery</option>', template)
        self.assertIn('<option value="Lateral Movement">Lateral Movement</option>', template)
        self.assertIn("data.event.selected_mitre_match = match", template)
        self.assertIn("Selected search match", template)
        self.assertIn("isSameMitreMatch", template)


if __name__ == "__main__":
    unittest.main()
