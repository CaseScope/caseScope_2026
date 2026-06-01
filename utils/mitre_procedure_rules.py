"""Deterministic observable-procedure to MITRE ATT&CK mappings.

These rules are a neutral search index. They map event evidence to ATT&CK
techniques; they do not decide whether the event is malicious.
"""
from __future__ import annotations

from typing import Dict, List


def _rule(
    rule_id: str,
    name: str,
    attack_ids: List[str],
    where_sql: str,
    *,
    mapping_confidence: int,
    evidence_strength: str,
    reason: str,
    matched_fields: List[str],
) -> Dict:
    return {
        "id": rule_id,
        "name": name,
        "attack_ids": attack_ids,
        "where_sql": " ".join(where_sql.split()),
        "mapping_confidence": mapping_confidence,
        "evidence_strength": evidence_strength,
        "reason": reason,
        "matched_fields": matched_fields,
        "source": "mitre_procedure_rule",
    }


MITRE_PROCEDURE_RULES: List[Dict] = [
    _rule(
        "win_logon_rdp_4624_type10",
        "Windows successful RDP logon",
        ["T1021.001"],
        """
        case_id = {case_id:UInt32}
        AND artifact_type = 'evtx'
        AND event_id = '4624'
        AND logon_type = 10
        """,
        mapping_confidence=90,
        evidence_strength="high",
        reason="4624 LogonType 10 indicates RemoteInteractive/RDP logon activity",
        matched_fields=["event_id", "logon_type", "src_ip", "username", "source_host"],
    ),
    _rule(
        "win_logon_network_4624_type3_admin_share",
        "Network logon with administrative share access context",
        ["T1021.002"],
        """
        case_id = {case_id:UInt32}
        AND artifact_type = 'evtx'
        AND event_id = '4624'
        AND logon_type = 3
        AND (
            positionCaseInsensitive(search_blob, 'ADMIN$') > 0
            OR positionCaseInsensitive(search_blob, 'C$') > 0
            OR positionCaseInsensitive(target_path, 'ADMIN$') > 0
            OR positionCaseInsensitive(target_path, 'C$') > 0
        )
        """,
        mapping_confidence=80,
        evidence_strength="medium",
        reason="Network logon paired with administrative share context maps to SMB/Windows Admin Shares",
        matched_fields=["event_id", "logon_type", "src_ip", "username", "target_path", "search_blob"],
    ),
    _rule(
        "win_smb_client_ipc_admin_share",
        "SMB IPC or administrative share connection",
        ["T1021.002"],
        """
        case_id = {case_id:UInt32}
        AND artifact_type = 'evtx'
        AND provider IN ('Microsoft-Windows-SMBClient', 'Microsoft-Windows-SMBServer')
        AND event_id IN ('30830', '30833')
        AND (
            positionCaseInsensitive(search_blob, 'IPC$') > 0
            OR positionCaseInsensitive(search_blob, 'ADMIN$') > 0
            OR positionCaseInsensitive(search_blob, 'C$') > 0
        )
        """,
        mapping_confidence=78,
        evidence_strength="medium",
        reason="SMB client/server telemetry records a connection to IPC or administrative shares",
        matched_fields=["event_id", "provider", "source_host", "src_ip", "dst_ip", "search_blob"],
    ),
    _rule(
        "win_explicit_credentials_4648",
        "Explicit credentials used",
        ["T1078"],
        """
        case_id = {case_id:UInt32}
        AND artifact_type = 'evtx'
        AND event_id = '4648'
        """,
        mapping_confidence=70,
        evidence_strength="medium",
        reason="4648 records logon attempts using explicit credentials",
        matched_fields=["event_id", "username", "domain", "src_ip", "process_name", "command_line"],
    ),
    _rule(
        "win_powershell_execution",
        "PowerShell execution",
        ["T1059.001"],
        """
        case_id = {case_id:UInt32}
        AND command_line != ''
        AND artifact_type != 'srum'
        AND (
            positionCaseInsensitive(command_line, 'powershell') > 0
            OR positionCaseInsensitive(command_line, 'pwsh') > 0
            OR positionCaseInsensitive(process_name, 'powershell') > 0
            OR positionCaseInsensitive(process_name, 'pwsh') > 0
        )
        """,
        mapping_confidence=70,
        evidence_strength="medium",
        reason="Command line or process metadata shows PowerShell execution",
        matched_fields=["process_name", "parent_process", "command_line", "username"],
    ),
    _rule(
        "win_powershell_encoded_or_hidden",
        "PowerShell encoded or hidden execution",
        ["T1059.001", "T1027"],
        """
        case_id = {case_id:UInt32}
        AND command_line != ''
        AND artifact_type != 'srum'
        AND (
            positionCaseInsensitive(command_line, 'powershell') > 0
            OR positionCaseInsensitive(command_line, 'pwsh') > 0
        )
        AND (
            positionCaseInsensitive(command_line, '-enc') > 0
            OR positionCaseInsensitive(command_line, '-encodedcommand') > 0
            OR positionCaseInsensitive(command_line, '-w hidden') > 0
            OR positionCaseInsensitive(command_line, '-windowstyle hidden') > 0
        )
        """,
        mapping_confidence=90,
        evidence_strength="high",
        reason="PowerShell command line contains encoded or hidden-window execution flags",
        matched_fields=["process_name", "parent_process", "command_line", "username"],
    ),
    _rule(
        "win_powershell_downloadstring_iex",
        "PowerShell remote script download and execution",
        ["T1059.001", "T1105"],
        """
        case_id = {case_id:UInt32}
        AND command_line != ''
        AND artifact_type != 'srum'
        AND (
            positionCaseInsensitive(command_line, 'powershell') > 0
            OR positionCaseInsensitive(command_line, 'pwsh') > 0
        )
        AND (
            positionCaseInsensitive(command_line, 'DownloadString') > 0
            OR positionCaseInsensitive(command_line, 'Net.WebClient') > 0
            OR positionCaseInsensitive(command_line, 'Invoke-WebRequest') > 0
            OR positionCaseInsensitive(command_line, 'iwr ') > 0
            OR positionCaseInsensitive(command_line, 'curl ') > 0
        )
        AND (
            positionCaseInsensitive(command_line, 'http://') > 0
            OR positionCaseInsensitive(command_line, 'https://') > 0
        )
        """,
        mapping_confidence=92,
        evidence_strength="high",
        reason="PowerShell command downloads content from a remote URL",
        matched_fields=["process_name", "parent_process", "command_line", "username"],
    ),
    _rule(
        "win_command_shell_execution",
        "Windows Command Shell execution",
        ["T1059.003"],
        """
        case_id = {case_id:UInt32}
        AND command_line != ''
        AND artifact_type != 'srum'
        AND (
            positionCaseInsensitive(command_line, 'cmd.exe') > 0
            OR lower(process_name) = 'cmd.exe'
        )
        """,
        mapping_confidence=70,
        evidence_strength="medium",
        reason="Command line or process metadata shows Windows Command Shell execution",
        matched_fields=["process_name", "parent_process", "command_line", "username"],
    ),
    _rule(
        "win_wmi_command_execution",
        "WMI command execution",
        ["T1047"],
        """
        case_id = {case_id:UInt32}
        AND command_line != ''
        AND artifact_type != 'srum'
        AND (
            positionCaseInsensitive(command_line, 'wmic') > 0
            OR positionCaseInsensitive(command_line, 'Invoke-WmiMethod') > 0
            OR positionCaseInsensitive(command_line, 'Get-WmiObject') > 0
            OR positionCaseInsensitive(command_line, 'Win32_Process') > 0
        )
        """,
        mapping_confidence=82,
        evidence_strength="high",
        reason="Command line contains WMI execution or WMI object usage",
        matched_fields=["process_name", "parent_process", "command_line", "username"],
    ),
    _rule(
        "win_winrm_powershell_remoting",
        "PowerShell remoting or WinRM usage",
        ["T1021.006"],
        """
        case_id = {case_id:UInt32}
        AND command_line != ''
        AND artifact_type != 'srum'
        AND (
            positionCaseInsensitive(command_line, 'Enter-PSSession') > 0
            OR positionCaseInsensitive(command_line, 'Invoke-Command') > 0
            OR positionCaseInsensitive(command_line, 'New-PSSession') > 0
            OR positionCaseInsensitive(command_line, 'winrs') > 0
            OR positionCaseInsensitive(command_line, 'winrm') > 0
        )
        """,
        mapping_confidence=86,
        evidence_strength="high",
        reason="Command line contains PowerShell remoting or WinRM usage",
        matched_fields=["process_name", "parent_process", "command_line", "username", "source_host"],
    ),
    _rule(
        "win_reg_run_key_add",
        "Registry Run key persistence",
        ["T1547.001"],
        """
        case_id = {case_id:UInt32}
        AND (
            (
                command_line != ''
                AND positionCaseInsensitive(command_line, 'reg') > 0
                AND positionCaseInsensitive(command_line, ' add ') > 0
                AND (
                    positionCaseInsensitive(command_line, '\\\\CurrentVersion\\\\Run') > 0
                    OR positionCaseInsensitive(command_line, '\\\\CurrentVersion\\\\RunOnce') > 0
                )
            )
            OR (
                reg_key != ''
                AND reg_value != ''
                AND lower(reg_value) NOT IN ('(key)', '(default)')
                AND reg_data != ''
                AND (
                    lower(reg_key) IN (
                        'software\\\\microsoft\\\\windows\\\\currentversion\\\\run',
                        'software\\\\microsoft\\\\windows\\\\currentversion\\\\runonce',
                        'wow6432node\\\\microsoft\\\\windows\\\\currentversion\\\\run',
                        'wow6432node\\\\microsoft\\\\windows\\\\currentversion\\\\runonce'
                    )
                    OR endsWith(lower(reg_key), '\\\\software\\\\microsoft\\\\windows\\\\currentversion\\\\run')
                    OR endsWith(lower(reg_key), '\\\\software\\\\microsoft\\\\windows\\\\currentversion\\\\runonce')
                )
            )
        )
        """,
        mapping_confidence=94,
        evidence_strength="high",
        reason="Registry Run or RunOnce autorun location is being created or modified",
        matched_fields=["event_id", "process_name", "command_line", "reg_key", "reg_value", "reg_data", "username"],
    ),
    _rule(
        "win_schtasks_create",
        "Scheduled task creation",
        ["T1053.005"],
        """
        case_id = {case_id:UInt32}
        AND command_line != ''
        AND artifact_type != 'srum'
        AND positionCaseInsensitive(command_line, 'schtasks') > 0
        AND (
            positionCaseInsensitive(command_line, '/create') > 0
            OR positionCaseInsensitive(command_line, ' /change ') > 0
        )
        """,
        mapping_confidence=86,
        evidence_strength="high",
        reason="schtasks command creates or changes a Windows scheduled task",
        matched_fields=["process_name", "parent_process", "command_line", "username"],
    ),
    _rule(
        "win_task_scheduler_action_start",
        "Scheduled task action execution event",
        ["T1053.005"],
        """
        case_id = {case_id:UInt32}
        AND artifact_type = 'evtx'
        AND provider = 'Microsoft-Windows-TaskScheduler'
        AND event_id = '200'
        AND positionCaseInsensitive(search_blob, 'TaskName:') > 0
        AND positionCaseInsensitive(search_blob, 'ActionName:') > 0
        """,
        mapping_confidence=82,
        evidence_strength="medium",
        reason="Task Scheduler event 200 records a scheduled task action starting",
        matched_fields=["event_id", "provider", "source_host", "process_name", "search_blob"],
    ),
    _rule(
        "win_service_creation_7045",
        "Windows service installation",
        ["T1543.003"],
        """
        case_id = {case_id:UInt32}
        AND artifact_type = 'evtx'
        AND event_id = '7045'
        """,
        mapping_confidence=88,
        evidence_strength="high",
        reason="System event 7045 records Windows service installation",
        matched_fields=["event_id", "source_host", "username", "process_name", "command_line", "target_path", "search_blob"],
    ),
    _rule(
        "win_sc_create_service",
        "Service creation via sc.exe",
        ["T1543.003"],
        """
        case_id = {case_id:UInt32}
        AND command_line != ''
        AND artifact_type != 'srum'
        AND (
            positionCaseInsensitive(command_line, 'sc.exe') > 0
            OR lower(process_name) = 'sc.exe'
        )
        AND positionCaseInsensitive(command_line, ' create ') > 0
        """,
        mapping_confidence=86,
        evidence_strength="high",
        reason="sc.exe command creates a Windows service",
        matched_fields=["process_name", "parent_process", "command_line", "username"],
    ),
    _rule(
        "win_psexec_service_execution",
        "PsExec or service-based remote execution",
        ["T1569.002"],
        """
        case_id = {case_id:UInt32}
        AND (
            positionCaseInsensitive(command_line, 'psexec') > 0
            OR positionCaseInsensitive(process_name, 'psexec') > 0
            OR positionCaseInsensitive(search_blob, 'PSEXESVC') > 0
        )
        """,
        mapping_confidence=88,
        evidence_strength="high",
        reason="Evidence references PsExec or the PsExec service execution pattern",
        matched_fields=["event_id", "process_name", "parent_process", "command_line", "search_blob", "username"],
    ),
    _rule(
        "win_regsvr32_remote_scriptlet",
        "Regsvr32 remote scriptlet execution",
        ["T1218.010"],
        """
        case_id = {case_id:UInt32}
        AND command_line != ''
        AND artifact_type != 'srum'
        AND positionCaseInsensitive(command_line, 'regsvr32') > 0
        AND positionCaseInsensitive(command_line, 'scrobj.dll') > 0
        AND (
            positionCaseInsensitive(command_line, '/i:http') > 0
            OR positionCaseInsensitive(command_line, '/i:https') > 0
        )
        """,
        mapping_confidence=98,
        evidence_strength="very_high",
        reason="regsvr32 is loading a remote scriptlet through scrobj.dll",
        matched_fields=["process_name", "parent_process", "command_line", "username"],
    ),
    _rule(
        "win_rundll32_execution",
        "Rundll32 execution",
        ["T1218.011"],
        """
        case_id = {case_id:UInt32}
        AND command_line != ''
        AND artifact_type != 'srum'
        AND (
            positionCaseInsensitive(command_line, 'rundll32') > 0
            OR lower(process_name) = 'rundll32.exe'
        )
        """,
        mapping_confidence=65,
        evidence_strength="medium",
        reason="Command line or process metadata shows rundll32 execution",
        matched_fields=["process_name", "parent_process", "command_line", "username"],
    ),
    _rule(
        "win_mshta_execution",
        "Mshta execution",
        ["T1218.005"],
        """
        case_id = {case_id:UInt32}
        AND command_line != ''
        AND artifact_type != 'srum'
        AND (
            positionCaseInsensitive(command_line, 'mshta') > 0
            OR lower(process_name) = 'mshta.exe'
        )
        """,
        mapping_confidence=82,
        evidence_strength="high",
        reason="Command line or process metadata shows mshta execution",
        matched_fields=["process_name", "parent_process", "command_line", "username"],
    ),
    _rule(
        "win_certutil_download",
        "Certutil file download",
        ["T1105"],
        """
        case_id = {case_id:UInt32}
        AND command_line != ''
        AND artifact_type != 'srum'
        AND positionCaseInsensitive(command_line, 'certutil') > 0
        AND (
            positionCaseInsensitive(command_line, '-urlcache') > 0
            OR positionCaseInsensitive(command_line, '-split') > 0
            OR positionCaseInsensitive(command_line, 'http://') > 0
            OR positionCaseInsensitive(command_line, 'https://') > 0
        )
        """,
        mapping_confidence=94,
        evidence_strength="high",
        reason="certutil command downloads or caches content from a URL",
        matched_fields=["process_name", "parent_process", "command_line", "username", "target_path"],
    ),
    _rule(
        "win_bitsadmin_transfer",
        "BITSAdmin transfer",
        ["T1197"],
        """
        case_id = {case_id:UInt32}
        AND command_line != ''
        AND artifact_type != 'srum'
        AND (
            positionCaseInsensitive(command_line, 'bitsadmin') > 0
            OR lower(process_name) = 'bitsadmin.exe'
        )
        """,
        mapping_confidence=86,
        evidence_strength="high",
        reason="bitsadmin command indicates BITS job usage",
        matched_fields=["process_name", "parent_process", "command_line", "username"],
    ),
    _rule(
        "win_whoami_discovery",
        "User context discovery",
        ["T1033"],
        """
        case_id = {case_id:UInt32}
        AND command_line != ''
        AND artifact_type != 'srum'
        AND (
            positionCaseInsensitive(command_line, 'whoami') > 0
            OR lower(process_name) = 'whoami.exe'
        )
        """,
        mapping_confidence=92,
        evidence_strength="high",
        reason="whoami command discovers current user and security context",
        matched_fields=["process_name", "parent_process", "command_line", "username"],
    ),
    _rule(
        "win_net_account_discovery",
        "Windows account discovery with net.exe",
        ["T1087"],
        """
        case_id = {case_id:UInt32}
        AND command_line != ''
        AND artifact_type != 'srum'
        AND (
            positionCaseInsensitive(command_line, 'net user') > 0
            OR positionCaseInsensitive(command_line, 'net group') > 0
            OR positionCaseInsensitive(command_line, 'net localgroup') > 0
            OR positionCaseInsensitive(command_line, 'net accounts') > 0
        )
        """,
        mapping_confidence=88,
        evidence_strength="high",
        reason="net.exe command enumerates users, groups, or account policy",
        matched_fields=["process_name", "parent_process", "command_line", "username"],
    ),
    _rule(
        "win_domain_controller_discovery",
        "Domain controller discovery",
        ["T1018"],
        """
        case_id = {case_id:UInt32}
        AND command_line != ''
        AND artifact_type != 'srum'
        AND (
            positionCaseInsensitive(command_line, 'nltest /dclist') > 0
            OR positionCaseInsensitive(command_line, 'nltest.exe /dclist') > 0
            OR positionCaseInsensitive(command_line, 'dsquery server') > 0
        )
        """,
        mapping_confidence=90,
        evidence_strength="high",
        reason="Command line enumerates domain controllers or directory servers",
        matched_fields=["process_name", "parent_process", "command_line", "username"],
    ),
    _rule(
        "win_network_share_discovery",
        "Network share discovery",
        ["T1135"],
        """
        case_id = {case_id:UInt32}
        AND command_line != ''
        AND artifact_type != 'srum'
        AND (
            positionCaseInsensitive(command_line, 'net view') > 0
            OR positionCaseInsensitive(command_line, 'Get-SmbShare') > 0
            OR positionCaseInsensitive(command_line, 'Get-SmbMapping') > 0
        )
        """,
        mapping_confidence=86,
        evidence_strength="high",
        reason="Command line enumerates network shares or SMB mappings",
        matched_fields=["process_name", "parent_process", "command_line", "username"],
    ),
    _rule(
        "win_service_discovery_sc_query",
        "Windows service discovery with sc.exe",
        ["T1007"],
        """
        case_id = {case_id:UInt32}
        AND command_line != ''
        AND artifact_type != 'srum'
        AND (
            lower(process_name) = 'sc.exe'
            OR positionCaseInsensitive(command_line, 'sc ') > 0
            OR positionCaseInsensitive(command_line, 'sc.exe') > 0
        )
        AND (
            positionCaseInsensitive(command_line, ' query') > 0
            OR positionCaseInsensitive(command_line, ' queryex') > 0
        )
        """,
        mapping_confidence=84,
        evidence_strength="high",
        reason="sc.exe query or queryex enumerates Windows services",
        matched_fields=["process_name", "parent_process", "command_line", "username", "source_host"],
    ),
    _rule(
        "win_logged_on_user_session_discovery",
        "Logged-on user session discovery",
        ["T1033"],
        """
        case_id = {case_id:UInt32}
        AND command_line != ''
        AND artifact_type != 'srum'
        AND (
            lower(process_name) = 'quser.exe'
            OR positionCaseInsensitive(command_line, 'quser') > 0
            OR positionCaseInsensitive(command_line, 'query user') > 0
        )
        """,
        mapping_confidence=86,
        evidence_strength="high",
        reason="quser or query user enumerates logged-on user sessions",
        matched_fields=["process_name", "parent_process", "command_line", "username", "source_host"],
    ),
    _rule(
        "win_ipconfig_discovery",
        "System network configuration discovery",
        ["T1016"],
        """
        case_id = {case_id:UInt32}
        AND command_line != ''
        AND artifact_type != 'srum'
        AND (
            positionCaseInsensitive(command_line, 'ipconfig') > 0
            OR positionCaseInsensitive(command_line, 'route print') > 0
            OR positionCaseInsensitive(command_line, 'netstat') > 0
        )
        """,
        mapping_confidence=82,
        evidence_strength="medium",
        reason="Command line discovers network configuration or active connections",
        matched_fields=["process_name", "parent_process", "command_line", "username"],
    ),
    _rule(
        "win_systeminfo_discovery",
        "System information discovery",
        ["T1082"],
        """
        case_id = {case_id:UInt32}
        AND command_line != ''
        AND artifact_type != 'srum'
        AND (
            positionCaseInsensitive(command_line, 'systeminfo') > 0
            OR positionCaseInsensitive(command_line, 'hostname') > 0
            OR positionCaseInsensitive(command_line, 'Get-ComputerInfo') > 0
        )
        """,
        mapping_confidence=82,
        evidence_strength="medium",
        reason="Command line queries local system information",
        matched_fields=["process_name", "parent_process", "command_line", "username"],
    ),
    _rule(
        "win_process_discovery",
        "Process discovery",
        ["T1057"],
        """
        case_id = {case_id:UInt32}
        AND command_line != ''
        AND artifact_type != 'srum'
        AND (
            positionCaseInsensitive(command_line, 'tasklist') > 0
            OR positionCaseInsensitive(command_line, 'Get-Process') > 0
            OR positionCaseInsensitive(command_line, 'wmic process') > 0
        )
        """,
        mapping_confidence=80,
        evidence_strength="medium",
        reason="Command line enumerates running processes",
        matched_fields=["process_name", "parent_process", "command_line", "username"],
    ),
    _rule(
        "win_lsass_process_access",
        "LSASS process memory access",
        ["T1003.001"],
        """
        case_id = {case_id:UInt32}
        AND (
            event_id = '10'
            OR positionCaseInsensitive(rule_title, 'lsass') > 0
            OR positionCaseInsensitive(search_blob, 'GrantedAccess') > 0
        )
        AND positionCaseInsensitive(search_blob, 'lsass.exe') > 0
        AND (
            positionCaseInsensitive(search_blob, 'dbghelp.dll') > 0
            OR positionCaseInsensitive(search_blob, 'MiniDump') > 0
            OR positionCaseInsensitive(search_blob, 'procdump') > 0
            OR positionCaseInsensitive(command_line, 'lsass') > 0
        )
        """,
        mapping_confidence=93,
        evidence_strength="very_high",
        reason="Process access evidence targets lsass.exe with dump-related context",
        matched_fields=["event_id", "process_name", "parent_process", "command_line", "search_blob", "username"],
    ),
    _rule(
        "win_procdump_lsass",
        "Procdump LSASS dump command",
        ["T1003.001"],
        """
        case_id = {case_id:UInt32}
        AND command_line != ''
        AND artifact_type != 'srum'
        AND positionCaseInsensitive(command_line, 'procdump') > 0
        AND positionCaseInsensitive(command_line, 'lsass') > 0
        """,
        mapping_confidence=96,
        evidence_strength="very_high",
        reason="Command line uses procdump against lsass",
        matched_fields=["process_name", "parent_process", "command_line", "username", "target_path"],
    ),
    _rule(
        "win_registry_hive_save",
        "Registry hive credential material access",
        ["T1003.002"],
        """
        case_id = {case_id:UInt32}
        AND command_line != ''
        AND artifact_type != 'srum'
        AND positionCaseInsensitive(command_line, 'reg') > 0
        AND positionCaseInsensitive(command_line, ' save ') > 0
        AND (
            positionCaseInsensitive(command_line, 'hklm\\\\sam') > 0
            OR positionCaseInsensitive(command_line, 'hklm\\\\security') > 0
            OR positionCaseInsensitive(command_line, 'hklm\\\\system') > 0
        )
        """,
        mapping_confidence=95,
        evidence_strength="very_high",
        reason="reg save command targets SAM, SECURITY, or SYSTEM hives",
        matched_fields=["process_name", "parent_process", "command_line", "username", "target_path"],
    ),
    _rule(
        "win_clear_security_log",
        "Windows event log clearing",
        ["T1685.005"],
        """
        case_id = {case_id:UInt32}
        AND (
            (
                artifact_type = 'evtx'
                AND (
                    (
                        event_id = '1102'
                        AND (
                            channel = 'Security'
                            OR positionCaseInsensitive(provider, 'Microsoft-Windows-Eventlog') > 0
                        )
                    )
                    OR (
                        event_id = '104'
                        AND (
                            positionCaseInsensitive(channel, 'Microsoft-Windows-Eventlog') > 0
                            OR positionCaseInsensitive(provider, 'Microsoft-Windows-Eventlog') > 0
                        )
                    )
                )
            )
            OR (
                command_line != ''
                AND (
                    positionCaseInsensitive(command_line, 'wevtutil cl') > 0
                    OR positionCaseInsensitive(command_line, 'Clear-EventLog') > 0
                    OR positionCaseInsensitive(command_line, 'Remove-EventLog') > 0
                )
            )
        )
        """,
        mapping_confidence=92,
        evidence_strength="high",
        reason="Event log clear event or command-line log clearing observed",
        matched_fields=["event_id", "process_name", "parent_process", "command_line", "username", "search_blob"],
    ),
    _rule(
        "win_defender_exclusion",
        "Microsoft Defender exclusion modification",
        ["T1685"],
        """
        case_id = {case_id:UInt32}
        AND command_line != ''
        AND artifact_type != 'srum'
        AND (
            positionCaseInsensitive(command_line, 'Add-MpPreference') > 0
            OR positionCaseInsensitive(command_line, 'Set-MpPreference') > 0
        )
        AND (
            positionCaseInsensitive(command_line, 'ExclusionPath') > 0
            OR positionCaseInsensitive(command_line, 'DisableRealtimeMonitoring') > 0
            OR positionCaseInsensitive(command_line, 'DisableBehaviorMonitoring') > 0
        )
        """,
        mapping_confidence=90,
        evidence_strength="high",
        reason="Defender preferences are modified to add exclusions or disable protections",
        matched_fields=["process_name", "parent_process", "command_line", "username"],
    ),
    _rule(
        "win_defender_event_exclusion_or_disable",
        "Microsoft Defender exclusion or protection setting event",
        ["T1685"],
        """
        case_id = {case_id:UInt32}
        AND artifact_type = 'evtx'
        AND provider = 'Microsoft-Windows-Windows Defender'
        AND event_id = '5007'
        AND (
            positionCaseInsensitive(search_blob, 'Exclusion') > 0
            OR positionCaseInsensitive(search_blob, 'DisableRealtimeMonitoring') > 0
            OR positionCaseInsensitive(search_blob, 'DisableBehaviorMonitoring') > 0
        )
        """,
        mapping_confidence=86,
        evidence_strength="high",
        reason="Defender configuration event records exclusions or disabled protection settings",
        matched_fields=["event_id", "provider", "source_host", "process_name", "search_blob"],
    ),
    _rule(
        "win_netsh_firewall_rule_modify",
        "Windows firewall rule modification",
        ["T1685"],
        """
        case_id = {case_id:UInt32}
        AND command_line != ''
        AND artifact_type != 'srum'
        AND (
            lower(process_name) = 'netsh.exe'
            OR positionCaseInsensitive(command_line, 'netsh') > 0
        )
        AND positionCaseInsensitive(command_line, 'advfirewall') > 0
        AND positionCaseInsensitive(command_line, 'firewall') > 0
        AND (
            positionCaseInsensitive(command_line, 'delete rule') > 0
            OR positionCaseInsensitive(command_line, 'set rule') > 0
            OR positionCaseInsensitive(command_line, 'add rule') > 0
        )
        """,
        mapping_confidence=88,
        evidence_strength="high",
        reason="netsh advfirewall modifies Windows firewall rules",
        matched_fields=["process_name", "parent_process", "command_line", "username", "source_host"],
    ),
    _rule(
        "win_shadow_copy_deletion",
        "Shadow copy deletion",
        ["T1490"],
        """
        case_id = {case_id:UInt32}
        AND command_line != ''
        AND artifact_type != 'srum'
        AND (
            (
                positionCaseInsensitive(command_line, 'vssadmin') > 0
                AND positionCaseInsensitive(command_line, 'delete') > 0
                AND positionCaseInsensitive(command_line, 'shadow') > 0
            )
            OR (
                positionCaseInsensitive(command_line, 'wmic') > 0
                AND positionCaseInsensitive(command_line, 'shadowcopy') > 0
                AND positionCaseInsensitive(command_line, 'delete') > 0
            )
        )
        """,
        mapping_confidence=96,
        evidence_strength="very_high",
        reason="Command line deletes volume shadow copies",
        matched_fields=["process_name", "parent_process", "command_line", "username"],
    ),
    _rule(
        "win_file_archive_creation",
        "Archive creation with command-line utility",
        ["T1560.001"],
        """
        case_id = {case_id:UInt32}
        AND command_line != ''
        AND artifact_type != 'srum'
        AND (
            positionCaseInsensitive(command_line, '7z.exe') > 0
            OR positionCaseInsensitive(command_line, 'rar.exe') > 0
            OR positionCaseInsensitive(command_line, 'Compress-Archive') > 0
            OR positionCaseInsensitive(command_line, 'tar.exe') > 0
        )
        """,
        mapping_confidence=80,
        evidence_strength="medium",
        reason="Command line uses archive tooling or PowerShell archive creation",
        matched_fields=["process_name", "parent_process", "command_line", "username", "target_path"],
    ),
]


def get_mitre_procedure_rules() -> List[Dict]:
    """Return deterministic MITRE procedure mapping rules."""
    return list(MITRE_PROCEDURE_RULES)


__all__ = ["MITRE_PROCEDURE_RULES", "get_mitre_procedure_rules"]
