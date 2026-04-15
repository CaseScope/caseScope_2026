# Anchor Class Design Rationale

## Purpose
This document records the anchor-class design rationale for all 42 current deterministic patterns. It exists to make anchor meaning explicit before Scoring 2.0 migration work begins.

This artifact is for:

- architecture review
- future pattern authors
- migration reviewers
- explainability and UI contract review

FP impact estimates in this document are hypotheses from anchor-quality analysis. Final migration priority will be set by the Phase 0 ranking artifact, not by this table.

## Anchor Design Checklist
Use these questions when deciding whether an event is a `definitive`, `gateway`, or `seed` anchor:

1. Is the event materially suspicious by itself?
2. Is the event part of the attacker action itself rather than a side effect or session marker?
3. Would removing the event collapse the pattern definition?
4. Is the event meaningfully less common in benign admin activity than the other candidate events?
5. If the event appears alone, is it still a meaningful investigative lead?

If the answer is "no" to most of these questions, the event should not be treated as a definitive anchor.

## Class Meanings
- `definitive`: anchor presence is itself technique-level evidence and may support anchor-only emit.
- `gateway`: anchor presence opens an investigation but cannot emit alone.
- `seed`: anchor presence is only a candidate filter; the meaning comes from corroborators.

## Credential Access
| Pattern | Current anchor quality | Recommended class | Recommended true anchor | Move to supporting/context | Honest anchor name? | Splitting candidate? | FP impact estimate |
|---|---|---|---|---|---|---|---|
| `pass_the_hash` | Mixed | `gateway` | `4624` type `3/9` with NTLM and `KeyLength=0`, only when paired with missing normal Kerberos context or follow-on lateral indicators | Multi-target spread, privilege, process context, off-hours | Partial | No | High |
| `pass_the_ticket` | Mixed | `gateway` | Kerberos logon reuse inconsistent with ticket-request history | No TGT/TGS, sensitive service, burst, host mismatch | Partial | Yes | High |
| `dcsync` | Strong | `definitive` | `4662` replication-rights event with DCSync GUIDs | Non-DC account/host, repetition, off-hours | Yes | No | Low |
| `kerberoasting` | Mixed | `gateway` | Suspicious `4769` service-ticket request only when tied to non-service-account or mass SPN behavior | SPN diversity, request volume, burst, account type | Partial | Yes | High |
| `lsass_memory_dump` | Mixed | `gateway` | Prefer Sysmon `10/8` against `lsass.exe` with suspicious access context, not generic file/process access alone | Dump file creation, suspicious process, technique tag, off-hours | No | Yes | High |
| `powershell_credential_dump` | Mixed | `gateway` | PowerShell directly interacting with `lsass` or explicit dump logic | DLL loads, MiniDump API, WER abuse, network download, off-hours | Partial | Yes | High |
| `comsvcs_minidump` | Strong | `definitive` | `rundll32 comsvcs.dll MiniDump` command line | Dump file creation, high access rights, process access | Yes | No | Low |
| `ntds_credential_dump` | Strong if tightened | `definitive` | IFM / VSS / ESENT chain that clearly indicates `ntds.dit` export or snapshot abuse | Hayabusa tag, path rarity, sequence breadth | Partial | No | Medium |
| `remote_registry_sam_access` | Mixed | `gateway` | Remote `IPC$\\winreg` access tied to SAM/SYSTEM/SECURITY hive access | Backup privilege, multi-hive access, account type | Partial | No | High |
| `backup_operator_abuse` | Weak | `gateway` | Actual privileged hive access or remote registry abuse, not entitlement alone | `4672` privilege assignment, network logon, share access | No | Merge candidate | High |
| `sam_database_dump` | Mixed | `gateway` | Direct SAM/SYSTEM/SECURITY dump chain with `reg save`, VSS, or `esentutl` behavior | File creation, Hayabusa rule, off-hours | Partial | No | High |
| `password_spraying` | Broad | `seed` | No single true anchor; failed-auth events are candidate seeds only | User spread, low attempts per account, protocol diversity, total volume, timing | No | No | High |
| `brute_force` | Broad | `seed` | No single true anchor; repeated failures are candidate seeds only | Follow-on success, lockout, bad-password semantics, concentration | No | No | High |

## Lateral Movement
| Pattern | Current anchor quality | Recommended class | Recommended true anchor | Move to supporting/context | Honest anchor name? | Splitting candidate? | FP impact estimate |
|---|---|---|---|---|---|---|---|
| `psexec_execution` | Mixed | `gateway` | Remote service install plus admin-share copy and remote-exec tooling | Share access alone, service state changes, file drop details | Partial | No | High |
| `wmi_lateral` | Mixed | `gateway` | Remote WMI process execution chain, not generic `wmiprvse.exe` children alone | WMI operational events, explicit creds, network logon, unusual source | No | Yes | High |
| `rdp_lateral` | Broad | `gateway` | RDP session marker is only a gateway; the finding needs multi-host, unusual-source, or suspicious follow-on evidence | `4778/4779`, `1149`, off-hours | No | No | High |
| `winrm_lateral` | Mixed | `gateway` | WinRM-specific remote execution context such as `wsmprovhost` plus tooling/logon alignment | Service events, PS remoting strings, multi-target spread | Partial | Yes | High |
| `dcom_lateral_movement` | Broad | `seed` | No honest single anchor in the current pattern; current process/DCOM events are seed filters | DCOM tooling, activation events, RPC activity, network logon | No | Yes | High |
| `smb_admin_shares` | Broad | `gateway` | Admin-share access is a gateway only when tied to remote execution, staging, or other lateral indicators | Repeated access, network logon, remote IP, off-hours | No | No | Medium |
| `lateral_tool_transfer` | Mixed | `gateway` | Suspicious payload transfer to admin shares tied to remote logon or follow-on file write | Generic file copy, off-hours | Partial | No | Medium |

## Persistence
| Pattern | Current anchor quality | Recommended class | Recommended true anchor | Move to supporting/context | Honest anchor name? | Splitting candidate? | FP impact estimate |
|---|---|---|---|---|---|---|---|
| `registry_run_keys` | Mixed | `gateway` | Explicit autorun registry modification that points to an unusual or recently dropped payload | Recent binary, actor context, off-hours | Partial | No | Medium |
| `winlogon_helper_dll` | Strong | `definitive` | Winlogon helper registry modification (`Shell`, `Userinit`, `Notify`, `Taskman`) | Suspicious path, follow-on execution | Yes | No | Medium |
| `wmi_persistence` | Strong | `definitive` | Permanent WMI subscription objects, especially binding creation | Tooling, object-chain breadth, off-hours | Yes | No | Low |
| `scheduled_task_persistence` | Mixed | `gateway` | `4698` task creation is the best gateway; current lifecycle and BITS events are too broad as co-equal anchors | Task Scheduler operational events, BITS/schtasks tooling, actor context | No | No | High |
| `service_persistence` | Mixed | `gateway` | Plain `7045/4697` is only a gateway; becomes stronger only with unusual path/arguments | LocalSystem, auto-start, off-hours | No | Yes | High |
| `dll_hijacking` | Mixed | `gateway` | COM `InprocServer32` or trusted-load hijack path, not generic DLL create/load alone | DLL path, target app load, off-hours | Partial | No | Medium |

## Defense Evasion
| Pattern | Current anchor quality | Recommended class | Recommended true anchor | Move to supporting/context | Honest anchor name? | Splitting candidate? | FP impact estimate |
|---|---|---|---|---|---|---|---|
| `uac_bypass` | Mixed | `gateway` | Auto-elevated binary plus registry hijack or suspicious child-process chain | `cmstp`/UACME tooling, off-hours | Partial | Yes | Medium |
| `certificate_installation` | Mixed | `gateway` | Root store modification by a non-standard process or suspicious `certutil` flow | Multiple-store breadth, off-hours | Partial | No | Medium |
| `log_clearing` | Strong | `definitive` | `1102/104` log-clear event | Command execution, multiple logs, non-admin actor | Yes | No | Low |
| `process_injection` | Mixed | `gateway` | Generic `8/10` injection telemetry is gateway; stronger only with sensitive target or dual telemetry | Suspicious parent, unusual DLL, target sensitivity | Partial | Yes | Medium |
| `security_tool_tampering` | Mixed | `gateway` | Logging/security tamper signal is only meaningful with the affected control and tool context | Event Log service changes, config changes, tamper tooling | No | No | High |
| `timestomping` | Strong | `definitive` | Sysmon `2` file time change event | Suspicious path, tooling, off-hours | Yes | No | Low |
| `amsi_bypass` | Mixed | `gateway` | Explicit AMSI/logging bypass content or registry change tied to offensive PowerShell | Offensive PS context, off-hours | Partial | No | Medium |
| `firewall_tampering` | Broad | `seed` | No honest single anchor today; current registry and `netsh` signals are seeds only | RDP enablement, portproxy, actual exposure change | No | Split/delete candidate | High |
| `evidence_deletion` | Broad | `gateway` | MRU/recent-item cleanup is meaningful but not anchor-only reliable | Multi-key impact, cleanup tooling, suspicious precursor activity | Partial | No | Medium |

## Privilege Escalation
| Pattern | Current anchor quality | Recommended class | Recommended true anchor | Move to supporting/context | Honest anchor name? | Splitting candidate? | FP impact estimate |
|---|---|---|---|---|---|---|---|
| `token_manipulation` | Mixed | `gateway` | Token theft or explicit privilege-enablement event tied to unusual actor/tooling | Tooling strings, machine-account exclusion, off-hours | Partial | No | Medium |
| `named_pipe_impersonation` | Mixed | `gateway` | Potato-style named-pipe impersonation chain, not generic `pipe` activity alone | Multi-event pipe telemetry, service trigger, off-hours | Partial | No | Medium |

## Discovery
| Pattern | Current anchor quality | Recommended class | Recommended true anchor | Move to supporting/context | Honest anchor name? | Splitting candidate? | FP impact estimate |
|---|---|---|---|---|---|---|---|
| `bloodhound_sharphound` | Mixed | `gateway` | Mass AD enumeration becomes meaningful when volume, session enumeration, or tooling is present | Workstation source, off-hours, admin focus | Partial | No | Medium |
| `local_group_discovery` | Broad | `seed` | No true anchor; local discovery events and commands are seed filters only | Repetition, tooling, workstation origin, off-hours | No | No | High |
| `domain_group_discovery` | Broad | `seed` | No true anchor; sensitive-group queries are seed filters only | Tooling, user-account context, off-hours | No | No | High |
| `system_owner_discovery` | Broad | `seed` | No true anchor; `whoami` and similar commands are seed filters only | Multi-command sequence, suspicious parent, privilege flags | No | No | High |
| `network_scanning` | Broad | `seed` | No true anchor; Sysmon `3` is only candidate filtering | Multi-destination spread, sequential ports, burst, lateral-port focus | No | No | High |

## Structural Notes
- `lsass_memory_dump` and `process_injection` are currently classified as `gateway` because each pattern is too coarse-grained for some sub-cases. A future split could promote narrower sub-patterns to `definitive`.
- `ntds_credential_dump` is classified as `definitive` only if the anchor is tightened to a true IFM/VSS or explicit `ntds.dit` export chain. If left as a broad ESENT bucket, it belongs closer to `gateway`.
- `backup_operator_abuse` and `remote_registry_sam_access` materially overlap once tightened around actual hive access. They should be reviewed together for suppression, merge, or one-pattern retirement.
- `firewall_tampering` may not survive as a standalone pattern. If the honest meaning lives entirely in narrower corroborators such as RDP enablement or portproxy creation, it may need splitting or deletion rather than a long-term `seed` classification.
- Check-name honesty is a separate bug class from anchor-class correctness. Any pattern marked `No` or `Partial` in the honesty column needs explainability work even if its class is otherwise correct.
