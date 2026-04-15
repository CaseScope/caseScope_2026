# Anchor Class Migration Matrix

## Purpose
This document is the implementation-facing contract for anchor-class migration. It translates the design rationale into per-pattern migration settings and candidate Scoring 2.0 controls.

This artifact is for:

- engineers executing pattern migration
- reviewers checking per-pattern conformance
- fixture authors building regression coverage

## Rules For Reading This Matrix
- `migration_phase` now mirrors the Phase 0 ranking artifact for case `135`: top 10 ranked patterns are `bucket_a_rank_XX`, remaining observed patterns are `bucket_b_rank_XX`, and patterns absent from the measurement window remain `defer_zero_volume`.
- The Phase 0 ranking artifact is authoritative for migration order.
- `migration_risk` estimates the complexity and failure surface of the migration itself. It is not a false-positive impact estimate.
- `required_check_ids` and `disqualifier_check_ids` are candidate starting points for engineering review. They are expected to be refined once measurement data exists.

## Credential Access
| Pattern | anchor_class | allow_anchor_only_emit | required_pass_count | Candidate required_check_ids | Candidate disqualifier_check_ids | Anchor-check rename needed | Anchor-event tightening needed | migration_risk | migration_phase | Structural notes |
|---|---|---:|---:|---|---|---|---|---|---|---|
| `pass_the_hash` | `gateway` | `false` | 1 | `pth_no_kerberos_tgt`, `pth_process_context`, `pth_multi_target` | `[]` | Yes: rename `pth_ntlm_keylength` from anchor to gateway logon | Yes: keep `4624` but bias toward remote/non-loopback variants | `high` | `defer_zero_volume` | Gateway until normal Kerberos context is absent or lateral follow-on exists |
| `pass_the_ticket` | `gateway` | `false` | 1 | `ptt_no_tgt`, `ptt_no_tgs`, `ptt_sensitive_service` | `TODO:new_machine_account_disqualifier` | Yes: `ptt_kerberos_logon` should read as gateway logon | Yes: anchor stays `4624`, but emit depends on ticket-history corroboration | `high` | `bucket_a_rank_02` | Strong splitting candidate if explicit PtT artifacts emerge |
| `dcsync` | `definitive` | `true` | 0 | `[]` | `dcs_not_dc_account`, `dcs_not_dc_host` | No | No | `low` | `defer_zero_volume` | Candidate disqualifiers are already represented as positive checks today |
| `kerberoasting` | `gateway` | `false` | 1 | `kerb_multi_spn`, `kerb_not_service_account`, `kerb_volume` | `[]` | Yes: `kerb_rc4_anchor` overstates certainty | Yes: keep `4769`, but force service-account/volume corroboration | `high` | `bucket_a_rank_03` | May split later into stronger RC4-specific vs generic mass-TGS variants |
| `lsass_memory_dump` | `gateway` | `false` | 1 | `lsass_vm_read`, `lsass_suspicious_process`, `lsass_dump_file` | `TODO:new_edr_allowlist_disqualifier` | Yes: `lsass_access_anchor` should become gateway wording | Yes: prefer Sysmon `10/8`; demote `4656/4663/3001` to corroboration | `high` | `defer_zero_volume` | Could split into definitive non-EDR LSASS read vs broader dump suspicion |
| `powershell_credential_dump` | `gateway` | `false` | 1 | `posh_minidump_api`, `posh_lsass_access`, `posh_cred_dlls` | `[]` | Yes: `posh_lsass_anchor` should become gateway wording | Yes: keep explicit PowerShell+LSASS triggers; demote generic supporting telemetry | `high` | `defer_zero_volume` | Likely benefits from later split between script-block and Sysmon-led variants |
| `comsvcs_minidump` | `definitive` | `true` | 0 | `[]` | `[]` | No | No | `low` | `defer_zero_volume` | Already close to final anchor semantics |
| `ntds_credential_dump` | `definitive` | `true` | 0 | `[]` | `[]` | Yes: current anchor name is too broad for definitive semantics | Yes: tighten to IFM/VSS/export chain before class upgrade | `medium` | `defer_zero_volume` | If anchor is not tightened, drop back to `gateway` |
| `remote_registry_sam_access` | `gateway` | `false` | 1 | `rr_sam_hive_access`, `rr_multi_hive` | `rr_not_machine_account` | Yes: `rr_winreg_anchor` should read as gateway access | Yes: keep `5145`/`winreg`, but require actual hive access | `high` | `defer_zero_volume` | Overlaps heavily with `backup_operator_abuse` after tightening |
| `backup_operator_abuse` | `gateway` | `false` | 1 | `bkop_share_access`, `TODO:new_hive_access_check` | `bkop_not_machine_account` | Yes: `bkop_privilege_anchor` is not an honest anchor | Yes: demote raw `4672` entitlement to supporting context | `high` | `bucket_a_rank_04` | Merge/suppression review with `remote_registry_sam_access` required |
| `sam_database_dump` | `gateway` | `false` | 1 | `samdump_reg_save`, `samdump_vss`, `samdump_esentutl` | `[]` | Yes: `samdump_anchor` should become gateway wording | Yes: bias anchor toward command/tool export instead of generic access | `high` | `defer_zero_volume` | Strong candidate for higher-risk migration because multiple paths are co-mingled |
| `password_spraying` | `seed` | `false` | 2 | `spray_distinct_users`, `spray_low_per_account`, `spray_total_failures` | `[]` | Yes: there is no honest anchor today | Yes: failed-auth events remain seed-only | `high` | `bucket_a_rank_06` | Should migrate only after measurement confirms the right spread semantics |
| `brute_force` | `seed` | `false` | 2 | `brute_high_failures`, `brute_followed_by_success`, `brute_account_lockout` | `[]` | Yes: there is no honest anchor today | Yes: repeated failures remain seed-only | `high` | `bucket_b_rank_14` | Candidate for later split by protocol or success-after-failure behavior |

## Lateral Movement
| Pattern | anchor_class | allow_anchor_only_emit | required_pass_count | Candidate required_check_ids | Candidate disqualifier_check_ids | Anchor-check rename needed | Anchor-event tightening needed | migration_risk | migration_phase | Structural notes |
|---|---|---:|---:|---|---|---|---|---|---|---|
| `psexec_execution` | `gateway` | `false` | 2 | `psexec_share_access`, `psexec_remote_tooling`, `psexec_network_logon` | `[]` | Yes: `psexec_service_install` should become gateway wording | Yes: keep service install but require share/tooling chain | `medium` | `bucket_a_rank_07` | Good warm-up gateway migration because checks are already explicit |
| `wmi_lateral` | `gateway` | `false` | 2 | `wmi_wmiprvse_child`, `wmi_network_logon`, `wmi_tooling` | `[]` | Yes: `wmi_anchor` should become gateway wording | Yes: drop broad WMI operational noise from anchor role | `high` | `bucket_a_rank_10` | Likely split candidate for explicit-creds vs inferred remote exec |
| `rdp_lateral` | `gateway` | `false` | 1 | `rdp_multi_host`, `rdp_1149`, `rdp_unusual_source` | `[]` | Yes: `rdp_type10_anchor` should become RDP gateway wording | Yes: demote `4778/4779/1149` out of anchor set | `high` | `bucket_a_rank_05` | Pattern meaning is currently explainability-drifted, not just noisy |
| `winrm_lateral` | `gateway` | `false` | 1 | `winrm_wsmprovhost`, `winrm_ps_remoting`, `winrm_multi_target` | `[]` | Partial: `winrm_logon_anchor` should emphasize remote-exec gateway | Yes: ensure anchor favors WinRM execution context over service noise | `medium` | `defer_zero_volume` | Could split explicit remoting vs service-led variants later |
| `dcom_lateral_movement` | `seed` | `false` | 2 | `dcom_tooling`, `dcom_rpc_activity`, `dcom_network_logon` | `[]` | Yes: `dcom_anchor` is not honest | Yes: remove `10016` from anchor semantics and treat current set as seeds | `high` | `defer_zero_volume` | Strongest splitting candidate in lateral movement |
| `smb_admin_shares` | `gateway` | `false` | 1 | `smbshare_multi_access`, `smbshare_network_logon` | `smbshare_not_local_ip` | Yes: `smbshare_anchor` should become admin-share gateway wording | Yes: plain `5140/5145` cannot remain attack-anchor semantics | `medium` | `defer_zero_volume` | Remains a useful gateway pattern once honest about its meaning |
| `lateral_tool_transfer` | `gateway` | `false` | 1 | `toolxfer_suspicious_ext`, `toolxfer_remote_logon`, `toolxfer_filecreate` | `[]` | Partial: anchor wording should emphasize staging gateway | Yes: keep admin-share transfer but require payload/write corroboration | `medium` | `bucket_b_rank_15` | Clear migration path, but still admin-heavy telemetry |

## Persistence
| Pattern | anchor_class | allow_anchor_only_emit | required_pass_count | Candidate required_check_ids | Candidate disqualifier_check_ids | Anchor-check rename needed | Anchor-event tightening needed | migration_risk | migration_phase | Structural notes |
|---|---|---:|---:|---|---|---|---|---|---|---|
| `registry_run_keys` | `gateway` | `false` | 1 | `regrun_unusual_path`, `regrun_recent_binary` | `[]` | Partial: `regrun_anchor` should read as Run-key gateway | Yes: favor autorun modifications that point to suspicious paths | `medium` | `defer_zero_volume` | Good candidate for an early low-to-medium complexity migration |
| `winlogon_helper_dll` | `definitive` | `true` | 0 | `[]` | `[]` | No | No | `low` | `defer_zero_volume` | Clean definitive case once anchor detail is preserved end-to-end |
| `wmi_persistence` | `definitive` | `true` | 0 | `[]` | `[]` | No | Minor: emphasize binding/consumer-chain event detail | `low` | `defer_zero_volume` | Strong anchor honesty and low migration risk |
| `scheduled_task_persistence` | `gateway` | `false` | 1 | `schtask_script_action`, `schtask_system_priv`, `schtask_bits_tooling` | `[]` | Yes: current `schtask_anchor` is narrower than actual mixed anchor set | Yes: make `4698` the gateway and demote task lifecycle/BITS events | `high` | `bucket_a_rank_09` | Explainability drift and mixed anchors make this high-risk |
| `service_persistence` | `gateway` | `false` | 1 | `svcpers_unusual_path`, `svcpers_localsystem` | `[]` | Yes: `svcpers_anchor` should become service-install gateway wording | Yes: plain `7045/4697` cannot remain definitive semantics | `high` | `bucket_a_rank_08` | Service install is common enough that corroboration must become explicit |
| `dll_hijacking` | `gateway` | `false` | 1 | `dllhijack_registry`, `dllhijack_suspicious_path` | `[]` | Partial: `dllhijack_anchor` should emphasize COM/DLL hijack gateway | Yes: bias toward COM/`InprocServer32` changes over generic DLL events | `medium` | `defer_zero_volume` | Stable candidate once registry-vs-load semantics are clarified |

## Defense Evasion
| Pattern | anchor_class | allow_anchor_only_emit | required_pass_count | Candidate required_check_ids | Candidate disqualifier_check_ids | Anchor-check rename needed | Anchor-event tightening needed | migration_risk | migration_phase | Structural notes |
|---|---|---:|---:|---|---|---|---|---|---|---|
| `uac_bypass` | `gateway` | `false` | 1 | `uac_child_process`, `uac_registry_hijack`, `uac_non_explorer_parent` | `[]` | Partial: `uac_anchor` should read as bypass gateway | Yes: favor explicit hijack/child-process chain over generic parentage | `medium` | `defer_zero_volume` | Could later split registry-based and binary-based variants |
| `certificate_installation` | `gateway` | `false` | 1 | `cert_non_standard_process`, `cert_certutil_usage`, `cert_multiple_stores` | `[]` | Partial: `cert_anchor` should read as cert-store gateway | Yes: keep root-store modifications but require actor/tool context | `medium` | `defer_zero_volume` | Medium risk because actor-context judgments matter |
| `log_clearing` | `definitive` | `true` | 0 | `[]` | `[]` | No | No | `low` | `bucket_b_rank_12` | Straightforward definitive migration |
| `process_injection` | `gateway` | `false` | 1 | `inject_target_process`, `inject_dual_events`, `inject_suspicious_parent` | `[]` | Partial: `inject_anchor` should read as injection gateway | Yes: keep `8/10` but require sensitivity or chain corroboration | `medium` | `defer_zero_volume` | Split candidate for LSASS-focused or browser-focused variants |
| `security_tool_tampering` | `gateway` | `false` | 1 | `sectamper_eventlog_service`, `sectamper_logging_change`, `sectamper_tooling` | `[]` | Yes: `sectamper_anchor` is too broad | Yes: current mixed anchor set should become corroborated gateway | `high` | `bucket_b_rank_16` | Mixed telemetry sources make migration risky |
| `timestomping` | `definitive` | `true` | 0 | `[]` | `[]` | No | No | `low` | `bucket_b_rank_13` | Strong anchor and simple migration |
| `amsi_bypass` | `gateway` | `false` | 1 | `amsi_bypass_strings`, `amsi_registry_change`, `amsi_offensive_ps` | `[]` | Partial: `amsi_anchor` should become bypass gateway wording | Yes: keep explicit bypass strings; demote generic policy changes | `medium` | `defer_zero_volume` | Moderate risk because offensive-context requirement must be tuned |
| `firewall_tampering` | `seed` | `false` | 2 | `fw_rdp_enable`, `fw_portproxy` | `[]` | Yes: `fw_anchor` is not honest | Yes: current `netsh`/registry signals are seed-only | `high` | `defer_zero_volume` | Split/delete review should happen before full migration |
| `evidence_deletion` | `gateway` | `false` | 1 | `evdel_multiple_keys`, `evdel_cleanup_tool` | `[]` | Partial: `evdel_anchor` should become cleanup gateway wording | Yes: keep MRU cleanup but require multi-key or tool corroboration | `medium` | `defer_zero_volume` | Medium risk because benign cleanup overlap is real |

## Privilege Escalation
| Pattern | anchor_class | allow_anchor_only_emit | required_pass_count | Candidate required_check_ids | Candidate disqualifier_check_ids | Anchor-check rename needed | Anchor-event tightening needed | migration_risk | migration_phase | Structural notes |
|---|---|---:|---:|---|---|---|---|---|---|---|
| `token_manipulation` | `gateway` | `false` | 1 | `token_sedebug`, `token_tooling` | `token_not_machine_account` | Partial: `token_anchor` should become privilege-manipulation gateway wording | Yes: demote broad privilege events unless tied to tooling or unusual actor | `medium` | `bucket_a_rank_01` | Needs careful handling so admin workflows do not backfill false positives |
| `named_pipe_impersonation` | `gateway` | `false` | 2 | `pipe_multi_events`, `pipe_tooling`, `pipe_service_trigger` | `[]` | Partial: `pipe_anchor` should become pipe-impersonation gateway wording | Yes: generic `pipe` events cannot remain sufficient | `medium` | `defer_zero_volume` | Two required corroborators keep the pattern honest without deleting it |

## Discovery
| Pattern | anchor_class | allow_anchor_only_emit | required_pass_count | Candidate required_check_ids | Candidate disqualifier_check_ids | Anchor-check rename needed | Anchor-event tightening needed | migration_risk | migration_phase | Structural notes |
|---|---|---:|---:|---|---|---|---|---|---|---|
| `bloodhound_sharphound` | `gateway` | `false` | 1 | `bh_mass_ldap`, `bh_tooling`, `bh_session_enum` | `[]` | Partial: `bh_anchor` should emphasize enumeration gateway | Yes: plain `4662`/`5145` volume should not imply tool certainty | `medium` | `defer_zero_volume` | Good candidate for data-driven tuning after Phase 0 |
| `local_group_discovery` | `seed` | `false` | 2 | `lgdisc_multi_events`, `lgdisc_tooling` | `[]` | Yes: `lgdisc_anchor` is not honest | Yes: current events/commands are seeds only | `high` | `defer_zero_volume` | Discovery pattern with strong admin overlap |
| `domain_group_discovery` | `seed` | `false` | 2 | `dgdisc_domain_admins`, `dgdisc_tooling` | `dgdisc_not_machine_account` | Yes: `dgdisc_anchor` is not honest | Yes: current events/commands are seeds only | `high` | `defer_zero_volume` | Sensitive-group focus matters more than the seed itself |
| `system_owner_discovery` | `seed` | `false` | 2 | `discovery_multi_commands`, `discovery_suspicious_parent`, `discovery_priv_enum` | `[]` | Yes: `discovery_anchor` is not honest | Yes: `whoami` and similar commands are seeds only | `high` | `defer_zero_volume` | Very high admin overlap; corroboration is the entire pattern |
| `network_scanning` | `seed` | `false` | 2 | `netscan_multi_dest`, `netscan_sequential_ports`, `netscan_burst` | `[]` | Yes: `netscan_anchor` is not honest | Yes: Sysmon `3` remains a candidate filter only | `high` | `bucket_b_rank_11` | Existing `min_anchors_per_key` was an earlier partial fix expressed in the wrong vocabulary |

## Follow-On Implementation Notes
- Add `anchor_class` declaration and default derivation in `utils/pattern_event_mappings.py`.
- Preserve actual triggering event details through `utils/candidate_extractor.py`, `utils/deterministic_evidence_engine.py`, `pipeline/pattern_analysis.py`, and `utils/finding_contract.py`.
- Add `tests/test_anchor_class_invariants.py` so patterns must eventually declare `anchor_class` or remain explicitly legacy.
- Recompute `migration_phase` from the next approved Phase 0 ranking artifact if the measurement window changes.
