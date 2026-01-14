"""Non-AI Pattern Matching Rules for CaseScope

Rule-based detection patterns for common attack techniques.
These patterns use ClickHouse queries to identify suspicious activity
without requiring AI/ML components.

Each pattern contains:
- Detection query for ClickHouse
- MITRE ATT&CK mapping
- Severity level
- Description for analysts
"""

from typing import Dict, List, Any

# ============================================================================
# CREDENTIAL ATTACKS
# ============================================================================

CREDENTIAL_ATTACK_PATTERNS = [
    {
        'id': 'pass_the_hash',
        'name': 'Pass the Hash',
        'category': 'Credential Attacks',
        'description': 'NTLM authentication (logon type 3/9) without corresponding Kerberos TGT request. Indicates credential reuse attack.',
        'severity': 'critical',
        'mitre_tactics': ['Credential Access', 'Lateral Movement'],
        'mitre_techniques': ['T1550.002'],
        'detection_query': """
            WITH ntlm_logons AS (
                SELECT 
                    source_host,
                    username,
                    timestamp,
                    logon_type,
                    row_id
                FROM events
                WHERE case_id = {case_id:UInt32}
                    AND event_id = '4624'
                    AND channel = 'Security'
                    AND logon_type IN (3, 9)
                    AND (search_blob LIKE '%NTLM%' OR search_blob LIKE '%NtLmSsp%')
            ),
            kerberos_tgt AS (
                SELECT DISTINCT username, source_host
                FROM events
                WHERE case_id = {case_id:UInt32}
                    AND event_id = '4768'
                    AND channel = 'Security'
            )
            SELECT 
                n.source_host,
                n.username,
                count() as logon_count,
                min(n.timestamp) as first_seen,
                max(n.timestamp) as last_seen,
                groupUniqArray(n.logon_type) as logon_types
            FROM ntlm_logons n
            LEFT JOIN kerberos_tgt k ON n.username = k.username
            WHERE k.username IS NULL
            GROUP BY n.source_host, n.username
            HAVING logon_count >= 1
        """,
        'indicators': [
            'Event 4624 logon type 3/9 with NTLM',
            'No corresponding Event 4768 TGT request',
            'Lateral movement to multiple systems'
        ],
        'thresholds': {'min_logons': 1}
    },
    {
        'id': 'pass_the_ticket',
        'name': 'Pass the Ticket',
        'category': 'Credential Attacks',
        'description': 'Kerberos tickets used from hosts that did not request them, or mismatched client addresses.',
        'severity': 'critical',
        'mitre_tactics': ['Credential Access', 'Lateral Movement'],
        'mitre_techniques': ['T1550.003'],
        'detection_query': """
            WITH ticket_requests AS (
                SELECT 
                    source_host,
                    username,
                    timestamp,
                    event_id
                FROM events
                WHERE case_id = {case_id:UInt32}
                    AND event_id IN ('4768', '4769')
                    AND channel = 'Security'
            ),
            logons AS (
                SELECT 
                    source_host,
                    username,
                    timestamp
                FROM events
                WHERE case_id = {case_id:UInt32}
                    AND event_id = '4624'
                    AND channel = 'Security'
                    AND logon_type = 3
                    AND search_blob LIKE '%Kerberos%'
            )
            SELECT 
                l.source_host,
                l.username,
                count() as logon_count,
                countIf(t.event_id = '4768') as tgt_requests,
                countIf(t.event_id = '4769') as tgs_requests,
                min(l.timestamp) as first_seen,
                max(l.timestamp) as last_seen
            FROM logons l
            LEFT JOIN ticket_requests t ON l.username = t.username 
                AND l.source_host = t.source_host
                AND t.timestamp < l.timestamp
                AND t.timestamp > l.timestamp - INTERVAL 1 HOUR
            GROUP BY l.source_host, l.username
            HAVING tgt_requests = 0 AND logon_count >= 1
        """,
        'indicators': [
            'Event 4769 TGS requests with RC4 encryption (0x17)',
            'Kerberos logon without corresponding 4768 on DC',
            'Mismatched client addresses'
        ],
        'thresholds': {'min_logons': 1}
    },
    {
        'id': 'password_spraying',
        'name': 'Password Spraying',
        'category': 'Credential Attacks',
        'description': 'Same password attempted against many accounts in short succession.',
        'severity': 'high',
        'mitre_tactics': ['Credential Access'],
        'mitre_techniques': ['T1110.003'],
        'detection_query': """
            SELECT 
                count(DISTINCT username) as unique_users,
                count() as total_failures,
                min(timestamp) as first_fail,
                max(timestamp) as last_fail,
                dateDiff('minute', min(timestamp), max(timestamp)) as duration_mins,
                groupUniqArray(source_host) as source_hosts,
                groupUniqArray(username) as usernames
            FROM events
            WHERE case_id = {case_id:UInt32}
                AND event_id = '4625'
                AND channel = 'Security'
            HAVING unique_users >= 10 AND total_failures >= 20 AND duration_mins <= 60
        """,
        'indicators': [
            'Event 4625 failed logon across many accounts',
            'Failure code 0xC000006A (bad password)',
            'Low attempts per account, high total',
            'Often during off-hours'
        ],
        'thresholds': {'min_users': 10, 'min_failures': 20, 'max_minutes': 60}
    },
    {
        'id': 'brute_force',
        'name': 'Brute Force Attack',
        'category': 'Credential Attacks',
        'description': 'High frequency failed login attempts against single account from single source.',
        'severity': 'high',
        'mitre_tactics': ['Credential Access'],
        'mitre_techniques': ['T1110.001'],
        'detection_query': """
            SELECT 
                username,
                source_host,
                count() as fail_count,
                min(timestamp) as first_fail,
                max(timestamp) as last_fail,
                dateDiff('second', min(timestamp), max(timestamp)) as duration_secs
            FROM events
            WHERE case_id = {case_id:UInt32}
                AND event_id = '4625'
                AND channel = 'Security'
            GROUP BY username, source_host
            HAVING fail_count >= 10 AND duration_secs <= 600
        """,
        'indicators': [
            'Event 4625 high frequency from single source',
            'Failure codes 0xC000006A or 0xC000006D',
            'Account lockouts (Event 4740)',
            'Success (4624) after multiple failures'
        ],
        'thresholds': {'min_failures': 10, 'max_seconds': 600}
    },
    {
        'id': 'credential_dumping_lsass',
        'name': 'Credential Dumping (LSASS)',
        'category': 'Credential Attacks',
        'description': 'Access to LSASS process indicating credential harvesting (mimikatz, procdump, etc.).',
        'severity': 'critical',
        'mitre_tactics': ['Credential Access'],
        'mitre_techniques': ['T1003.001'],
        'detection_query': """
            SELECT 
                source_host,
                count() as dump_events,
                groupArray(event_id) as event_ids,
                groupArray(process_name) as processes,
                min(timestamp) as first_seen,
                max(timestamp) as last_seen
            FROM events
            WHERE case_id = {case_id:UInt32}
                AND (
                    (event_id = '10' AND lower(search_blob) LIKE '%lsass%' 
                        AND (search_blob LIKE '%0x1010%' OR search_blob LIKE '%0x1038%' OR search_blob LIKE '%0x143A%'))
                    OR lower(search_blob) LIKE '%mimikatz%'
                    OR lower(search_blob) LIKE '%sekurlsa%'
                    OR lower(search_blob) LIKE '%procdump%lsass%'
                    OR lower(command_line) LIKE '%comsvcs.dll%minidump%'
                )
            GROUP BY source_host
            HAVING dump_events >= 1
        """,
        'indicators': [
            'Sysmon Event 10 with lsass.exe target',
            'GrantedAccess masks: 0x1010, 0x1038, 0x143A',
            'Event 4656/4663 on SAM/SYSTEM/SECURITY hives',
            'Memory dump file creation'
        ],
        'thresholds': {'min_events': 1}
    },
    {
        'id': 'kerberoasting',
        'name': 'Kerberoasting',
        'category': 'Credential Attacks',
        'description': 'Excessive TGS requests for service accounts with RC4 encryption indicating offline cracking attempt.',
        'severity': 'high',
        'mitre_tactics': ['Credential Access'],
        'mitre_techniques': ['T1558.003'],
        'detection_query': """
            SELECT 
                source_host,
                username,
                count() as tgs_requests,
                countIf(search_blob LIKE '%0x17%' OR search_blob LIKE '%RC4%') as rc4_requests,
                min(timestamp) as first_seen,
                max(timestamp) as last_seen,
                groupUniqArray(extractAll(search_blob, 'ServiceName[:\\s]*([^\\s,]+)')) as service_accounts
            FROM events
            WHERE case_id = {case_id:UInt32}
                AND event_id = '4769'
                AND channel = 'Security'
            GROUP BY source_host, username
            HAVING tgs_requests >= 5 AND rc4_requests >= 3
        """,
        'indicators': [
            'Event 4769 with encryption type 0x17 (RC4)',
            'High volume TGS requests from single source',
            'Requests for user account SPNs'
        ],
        'thresholds': {'min_requests': 5, 'min_rc4': 3}
    },
    {
        'id': 'asrep_roasting',
        'name': 'AS-REP Roasting',
        'category': 'Credential Attacks',
        'description': 'TGT requests for accounts without pre-authentication, indicating offline password cracking.',
        'severity': 'high',
        'mitre_tactics': ['Credential Access'],
        'mitre_techniques': ['T1558.004'],
        'detection_query': """
            SELECT 
                source_host,
                count() as tgt_requests,
                countIf(search_blob LIKE '%PreAuth%0%' OR search_blob LIKE '%0x0%') as no_preauth,
                min(timestamp) as first_seen,
                max(timestamp) as last_seen,
                groupUniqArray(username) as usernames
            FROM events
            WHERE case_id = {case_id:UInt32}
                AND event_id = '4768'
                AND channel = 'Security'
            GROUP BY source_host
            HAVING tgt_requests >= 5 AND no_preauth >= 1
        """,
        'indicators': [
            'Event 4768 with pre-auth type 0',
            'Accounts with no pre-auth flag',
            'Unusual TGT request volume with RC4'
        ],
        'thresholds': {'min_requests': 5}
    },
    {
        'id': 'golden_ticket',
        'name': 'Golden Ticket',
        'category': 'Credential Attacks',
        'description': 'Forged Kerberos TGT - TGS requests without preceding TGT request or for non-existent accounts.',
        'severity': 'critical',
        'mitre_tactics': ['Credential Access', 'Persistence'],
        'mitre_techniques': ['T1558.001'],
        'detection_query': """
            WITH tgt_requests AS (
                SELECT DISTINCT username, source_host, timestamp
                FROM events
                WHERE case_id = {case_id:UInt32}
                    AND event_id = '4768'
                    AND channel = 'Security'
            ),
            tgs_requests AS (
                SELECT 
                    source_host,
                    username,
                    timestamp,
                    row_id
                FROM events
                WHERE case_id = {case_id:UInt32}
                    AND event_id = '4769'
                    AND channel = 'Security'
            )
            SELECT 
                t.source_host,
                t.username,
                count() as orphan_tgs,
                min(t.timestamp) as first_seen,
                max(t.timestamp) as last_seen
            FROM tgs_requests t
            LEFT JOIN tgt_requests g ON t.username = g.username 
                AND g.timestamp < t.timestamp 
                AND g.timestamp > t.timestamp - INTERVAL 10 HOUR
            WHERE g.username IS NULL
            GROUP BY t.source_host, t.username
            HAVING orphan_tgs >= 3
        """,
        'indicators': [
            'Event 4769 without preceding 4768',
            'Anomalous ticket lifetimes',
            'Unusual SID history in tickets'
        ],
        'thresholds': {'min_orphan': 3}
    },
    {
        'id': 'silver_ticket',
        'name': 'Silver Ticket',
        'category': 'Credential Attacks',
        'description': 'Forged service ticket - service access without corresponding TGS request on DC.',
        'severity': 'critical',
        'mitre_tactics': ['Credential Access', 'Lateral Movement'],
        'mitre_techniques': ['T1558.002'],
        'detection_query': """
            WITH service_access AS (
                SELECT 
                    source_host,
                    username,
                    timestamp
                FROM events
                WHERE case_id = {case_id:UInt32}
                    AND event_id = '4624'
                    AND channel = 'Security'
                    AND logon_type = 3
                    AND search_blob LIKE '%Kerberos%'
            ),
            tgs_requests AS (
                SELECT DISTINCT username, source_host, timestamp
                FROM events
                WHERE case_id = {case_id:UInt32}
                    AND event_id = '4769'
                    AND channel = 'Security'
            )
            SELECT 
                s.source_host,
                s.username,
                count() as orphan_access,
                min(s.timestamp) as first_seen,
                max(s.timestamp) as last_seen
            FROM service_access s
            LEFT JOIN tgs_requests t ON s.username = t.username
                AND t.timestamp < s.timestamp
                AND t.timestamp > s.timestamp - INTERVAL 1 HOUR
            WHERE t.username IS NULL
            GROUP BY s.source_host, s.username
            HAVING orphan_access >= 2
        """,
        'indicators': [
            'Service access (4624 type 3) without 4769 TGS',
            'Anomalous service ticket parameters',
            'Access from unexpected sources'
        ],
        'thresholds': {'min_orphan': 2}
    },
]

# ============================================================================
# LATERAL MOVEMENT
# ============================================================================

LATERAL_MOVEMENT_PATTERNS = [
    {
        'id': 'psexec_remote_service',
        'name': 'PsExec / Remote Service Execution',
        'category': 'Lateral Movement',
        'description': 'Remote service installation indicating PsExec or similar tool usage.',
        'severity': 'high',
        'mitre_tactics': ['Lateral Movement', 'Execution'],
        'mitre_techniques': ['T1021.002', 'T1569.002'],
        'detection_query': """
            SELECT 
                source_host,
                count() as service_events,
                countIf(event_id = '7045') as services_installed,
                countIf(event_id = '5145') as smb_access,
                min(timestamp) as first_seen,
                max(timestamp) as last_seen,
                groupArray(search_blob) as details
            FROM events
            WHERE case_id = {case_id:UInt32}
                AND (
                    (event_id = '7045' AND (
                        lower(search_blob) LIKE '%psexe%'
                        OR lower(search_blob) LIKE '%paexec%'
                        OR length(extractAll(search_blob, 'ServiceName[:\\s]*([A-Za-z]{8})')[1]) = 8
                    ))
                    OR (event_id = '5145' AND (search_blob LIKE '%ADMIN$%' OR search_blob LIKE '%IPC$%'))
                )
            GROUP BY source_host
            HAVING services_installed >= 1 OR (services_installed >= 1 AND smb_access >= 1)
        """,
        'indicators': [
            'Event 7045 new service with random name',
            'services.exe spawning cmd/PowerShell',
            'SMB access to ADMIN$ or IPC$',
            'Event 4624 type 3 + service creation'
        ],
        'thresholds': {'min_services': 1}
    },
    {
        'id': 'wmi_lateral',
        'name': 'WMI Lateral Movement',
        'category': 'Lateral Movement',
        'description': 'Windows Management Instrumentation used for remote code execution.',
        'severity': 'high',
        'mitre_tactics': ['Lateral Movement', 'Execution'],
        'mitre_techniques': ['T1047'],
        'detection_query': """
            SELECT 
                source_host,
                count() as wmi_events,
                countIf(event_id = '4624' AND logon_type = 3) as network_logons,
                countIf(lower(search_blob) LIKE '%wmic%' OR lower(search_blob) LIKE '%wmiprvse%') as wmi_activity,
                min(timestamp) as first_seen,
                max(timestamp) as last_seen
            FROM events
            WHERE case_id = {case_id:UInt32}
                AND (
                    (channel LIKE '%WMI-Activity%' AND event_id IN ('5857', '5860', '5861'))
                    OR (lower(process_name) = 'wmiprvse.exe')
                    OR (lower(command_line) LIKE '%wmic%/node:%')
                    OR (event_id = '4648' AND lower(search_blob) LIKE '%wmi%')
                )
            GROUP BY source_host
            HAVING wmi_events >= 2
        """,
        'indicators': [
            'WMI-Activity events 5857, 5860, 5861',
            'wmiprvse.exe parent process',
            'wmic.exe with /node parameter',
            'Event 4648 with explicit credentials'
        ],
        'thresholds': {'min_events': 2}
    },
    {
        'id': 'remote_scheduled_task',
        'name': 'Remote Scheduled Task',
        'category': 'Lateral Movement',
        'description': 'Scheduled task created remotely for persistence or execution.',
        'severity': 'high',
        'mitre_tactics': ['Lateral Movement', 'Execution', 'Persistence'],
        'mitre_techniques': ['T1053.005'],
        'detection_query': """
            SELECT 
                source_host,
                count() as task_events,
                countIf(event_id = '4698') as tasks_created,
                countIf(event_id = '4624' AND logon_type = 3) as network_logons,
                min(timestamp) as first_seen,
                max(timestamp) as last_seen,
                groupArray(search_blob) as task_details
            FROM events
            WHERE case_id = {case_id:UInt32}
                AND (
                    event_id = '4698'
                    OR (lower(command_line) LIKE '%schtasks%/create%/s %')
                    OR (channel LIKE '%TaskScheduler%' AND event_id IN ('106', '140', '141'))
                )
            GROUP BY source_host
            HAVING tasks_created >= 1
        """,
        'indicators': [
            'Event 4698 scheduled task created',
            'schtasks.exe with /create /s parameters',
            'Event 4624 type 3 preceding task creation'
        ],
        'thresholds': {'min_tasks': 1}
    },
    {
        'id': 'dcom_lateral',
        'name': 'DCOM Lateral Movement',
        'category': 'Lateral Movement',
        'description': 'Distributed COM objects abused for lateral movement.',
        'severity': 'high',
        'mitre_tactics': ['Lateral Movement'],
        'mitre_techniques': ['T1021.003'],
        'detection_query': """
            SELECT 
                source_host,
                process_name,
                count() as suspicious_children,
                min(timestamp) as first_seen,
                max(timestamp) as last_seen
            FROM events
            WHERE case_id = {case_id:UInt32}
                AND (
                    (lower(parent_process) IN ('mmc.exe', 'excel.exe', 'outlook.exe', 'winword.exe') 
                        AND lower(process_name) IN ('cmd.exe', 'powershell.exe', 'pwsh.exe'))
                    OR (event_id = '4624' AND logon_type = 3 AND search_blob LIKE '%DCOM%')
                )
            GROUP BY source_host, process_name
            HAVING suspicious_children >= 1
        """,
        'indicators': [
            'Event 4624 type 3 with DCOM',
            'mmc.exe/excel.exe spawning cmd/PowerShell',
            'Network connections to RPC port 135'
        ],
        'thresholds': {'min_events': 1}
    },
    {
        'id': 'winrm_remoting',
        'name': 'WinRM / PowerShell Remoting',
        'category': 'Lateral Movement',
        'description': 'Windows Remote Management used for lateral movement.',
        'severity': 'medium',
        'mitre_tactics': ['Lateral Movement', 'Execution'],
        'mitre_techniques': ['T1021.006'],
        'detection_query': """
            SELECT 
                source_host,
                count() as winrm_events,
                countIf(lower(process_name) = 'wsmprovhost.exe') as wsmprov_spawns,
                countIf(event_id IN ('4103', '4104')) as ps_events,
                min(timestamp) as first_seen,
                max(timestamp) as last_seen
            FROM events
            WHERE case_id = {case_id:UInt32}
                AND (
                    (channel LIKE '%WinRM%' AND event_id IN ('6', '8', '15', '16', '91'))
                    OR lower(process_name) = 'wsmprovhost.exe'
                    OR (event_id = '4624' AND logon_type = 3 AND search_blob LIKE '%WSMan%')
                    OR (event_id IN ('4103', '4104') AND search_blob LIKE '%remote%')
                )
            GROUP BY source_host
            HAVING winrm_events >= 2
        """,
        'indicators': [
            'Event 4624 type 3 with network logon',
            'PowerShell Script Block (4104) remote execution',
            'WinRM operational logs (6, 8, 15, 16, 91)',
            'wsmprovhost.exe process creation'
        ],
        'thresholds': {'min_events': 2}
    },
    {
        'id': 'rdp_lateral',
        'name': 'RDP Lateral Movement',
        'category': 'Lateral Movement',
        'description': 'Remote Desktop Protocol used for lateral movement between systems.',
        'severity': 'medium',
        'mitre_tactics': ['Lateral Movement'],
        'mitre_techniques': ['T1021.001'],
        'detection_query': """
            WITH rdp_logons AS (
                SELECT 
                    source_host,
                    username,
                    timestamp,
                    logon_type
                FROM events
                WHERE case_id = {case_id:UInt32}
                    AND event_id = '4624'
                    AND channel = 'Security'
                    AND logon_type IN (10, 7)
            )
            SELECT 
                username,
                count(DISTINCT source_host) as hosts_accessed,
                count() as total_sessions,
                groupUniqArray(source_host) as host_list,
                min(timestamp) as first_access,
                max(timestamp) as last_access
            FROM rdp_logons
            GROUP BY username
            HAVING hosts_accessed >= 3
        """,
        'indicators': [
            'Event 4624 logon type 10 (RemoteInteractive)',
            'Event 4778/4779 session connect/disconnect',
            'TerminalServices logs (21, 22, 25)',
            'Multiple hosts accessed by same user'
        ],
        'thresholds': {'min_hosts': 3}
    },
]

# ============================================================================
# PERSISTENCE
# ============================================================================

PERSISTENCE_PATTERNS = [
    {
        'id': 'registry_run_keys',
        'name': 'Registry Run Key Persistence',
        'category': 'Persistence',
        'description': 'Modification of registry Run/RunOnce keys for persistence.',
        'severity': 'high',
        'mitre_tactics': ['Persistence'],
        'mitre_techniques': ['T1547.001'],
        'detection_query': """
            SELECT 
                source_host,
                count() as registry_events,
                min(timestamp) as first_seen,
                max(timestamp) as last_seen,
                groupArray(search_blob) as details
            FROM events
            WHERE case_id = {case_id:UInt32}
                AND (
                    (event_id = '13' AND channel LIKE '%Sysmon%' 
                        AND (search_blob LIKE '%\\Run%' OR search_blob LIKE '%\\RunOnce%'))
                    OR (event_id = '4657' AND (search_blob LIKE '%\\Run%' OR search_blob LIKE '%\\RunOnce%'))
                )
            GROUP BY source_host
            HAVING registry_events >= 1
        """,
        'indicators': [
            'Sysmon Event 13 for Run/RunOnce keys',
            'Event 4657 registry auditing',
            'HKLM/HKCU Software\\Microsoft\\Windows\\CurrentVersion\\Run'
        ],
        'thresholds': {'min_events': 1}
    },
    {
        'id': 'scheduled_task_persistence',
        'name': 'Scheduled Task Persistence',
        'category': 'Persistence',
        'description': 'Scheduled tasks created for persistence with suspicious characteristics.',
        'severity': 'high',
        'mitre_tactics': ['Persistence', 'Execution'],
        'mitre_techniques': ['T1053.005'],
        'detection_query': """
            SELECT 
                source_host,
                count() as task_events,
                min(timestamp) as first_seen,
                max(timestamp) as last_seen,
                groupArray(search_blob) as task_details
            FROM events
            WHERE case_id = {case_id:UInt32}
                AND event_id = '4698'
                AND (
                    search_blob LIKE '%\\Temp\\%'
                    OR search_blob LIKE '%\\AppData\\%'
                    OR search_blob LIKE '%\\Public\\%'
                    OR search_blob LIKE '%powershell%'
                    OR search_blob LIKE '%cmd.exe%'
                    OR search_blob LIKE '%.ps1%'
                    OR search_blob LIKE '%encoded%'
                )
            GROUP BY source_host
            HAVING task_events >= 1
        """,
        'indicators': [
            'Event 4698 task created with suspicious actions',
            'Tasks executing from Temp/AppData/Public',
            'Tasks running as SYSTEM from user context'
        ],
        'thresholds': {'min_events': 1}
    },
    {
        'id': 'service_persistence',
        'name': 'Service Persistence',
        'category': 'Persistence',
        'description': 'New services created for persistence with suspicious paths.',
        'severity': 'high',
        'mitre_tactics': ['Persistence'],
        'mitre_techniques': ['T1543.003'],
        'detection_query': """
            SELECT 
                source_host,
                count() as service_events,
                min(timestamp) as first_seen,
                max(timestamp) as last_seen,
                groupArray(search_blob) as service_details
            FROM events
            WHERE case_id = {case_id:UInt32}
                AND (event_id = '7045' OR event_id = '4697')
                AND (
                    search_blob LIKE '%\\Temp\\%'
                    OR search_blob LIKE '%\\AppData\\%'
                    OR search_blob LIKE '%\\Users\\%'
                    OR search_blob LIKE '%powershell%'
                    OR search_blob LIKE '%cmd /c%'
                    OR search_blob LIKE '%.ps1%'
                )
            GROUP BY source_host
            HAVING service_events >= 1
        """,
        'indicators': [
            'Event 7045 / 4697 new service created',
            'Services with unusual binary paths',
            'Services running from Temp/user directories'
        ],
        'thresholds': {'min_events': 1}
    },
    {
        'id': 'dll_hijacking',
        'name': 'DLL Hijacking / Search Order Hijacking',
        'category': 'Persistence',
        'description': 'DLLs loaded from unusual paths indicating search order hijacking.',
        'severity': 'high',
        'mitre_tactics': ['Persistence', 'Privilege Escalation', 'Defense Evasion'],
        'mitre_techniques': ['T1574.001'],
        'detection_query': """
            SELECT 
                source_host,
                count() as dll_events,
                groupUniqArray(process_name) as processes,
                min(timestamp) as first_seen,
                max(timestamp) as last_seen
            FROM events
            WHERE case_id = {case_id:UInt32}
                AND event_id = '7'
                AND channel LIKE '%Sysmon%'
                AND (
                    search_blob LIKE '%\\Temp\\%'
                    OR search_blob LIKE '%\\AppData\\%'
                    OR search_blob LIKE '%\\Users\\%'
                    OR search_blob LIKE '%\\Downloads\\%'
                )
                AND search_blob NOT LIKE '%Signed%true%'
            GROUP BY source_host
            HAVING dll_events >= 1
        """,
        'indicators': [
            'Sysmon Event 7 DLL loaded from unusual path',
            'Unsigned DLLs in paths with signed binaries',
            'Writable directories used for DLL placement'
        ],
        'thresholds': {'min_events': 1}
    },
    {
        'id': 'wmi_persistence',
        'name': 'WMI Event Subscription Persistence',
        'category': 'Persistence',
        'description': 'WMI permanent event subscriptions used for persistence.',
        'severity': 'critical',
        'mitre_tactics': ['Persistence'],
        'mitre_techniques': ['T1546.003'],
        'detection_query': """
            SELECT 
                source_host,
                count() as wmi_persistence_events,
                countIf(event_id = '19') as filter_created,
                countIf(event_id = '20') as consumer_created,
                countIf(event_id = '21') as binding_created,
                min(timestamp) as first_seen,
                max(timestamp) as last_seen
            FROM events
            WHERE case_id = {case_id:UInt32}
                AND (
                    (channel LIKE '%WMI-Activity%' AND event_id IN ('5857', '5858', '5859', '5860', '5861'))
                    OR (channel LIKE '%Sysmon%' AND event_id IN ('19', '20', '21'))
                )
            GROUP BY source_host
            HAVING wmi_persistence_events >= 1
        """,
        'indicators': [
            'WMI-Activity events 5857-5861',
            'Sysmon Event 19/20/21 WMI subscriptions',
            'CommandLineEventConsumer or ActiveScriptEventConsumer'
        ],
        'thresholds': {'min_events': 1}
    },
]

# ============================================================================
# PRIVILEGE ESCALATION
# ============================================================================

PRIV_ESC_PATTERNS = [
    {
        'id': 'token_manipulation',
        'name': 'Token Manipulation',
        'category': 'Privilege Escalation',
        'description': 'Token impersonation or theft for privilege escalation.',
        'severity': 'critical',
        'mitre_tactics': ['Privilege Escalation', 'Defense Evasion'],
        'mitre_techniques': ['T1134'],
        'detection_query': """
            SELECT 
                source_host,
                count() as token_events,
                countIf(event_id = '4672') as special_privs,
                countIf(event_id = '4624') as elevated_logons,
                min(timestamp) as first_seen,
                max(timestamp) as last_seen
            FROM events
            WHERE case_id = {case_id:UInt32}
                AND (
                    (event_id = '4672' AND search_blob LIKE '%SeDebugPrivilege%')
                    OR (event_id = '4624' AND search_blob LIKE '%elevated%')
                    OR (event_id = '10' AND channel LIKE '%Sysmon%' AND search_blob LIKE '%token%')
                )
            GROUP BY source_host
            HAVING token_events >= 1
        """,
        'indicators': [
            'Event 4624 with elevated token',
            'Event 4672 special privileges (SeDebugPrivilege)',
            'Sysmon Event 10 token handle manipulation'
        ],
        'thresholds': {'min_events': 1}
    },
    {
        'id': 'named_pipe_impersonation',
        'name': 'Named Pipe Impersonation',
        'category': 'Privilege Escalation',
        'description': 'Named pipe creation and connection for privilege escalation.',
        'severity': 'high',
        'mitre_tactics': ['Privilege Escalation'],
        'mitre_techniques': ['T1134.001'],
        'detection_query': """
            SELECT 
                source_host,
                count() as pipe_events,
                countIf(event_id = '17') as pipes_created,
                countIf(event_id = '18') as pipes_connected,
                min(timestamp) as first_seen,
                max(timestamp) as last_seen,
                groupArray(search_blob) as pipe_names
            FROM events
            WHERE case_id = {case_id:UInt32}
                AND channel LIKE '%Sysmon%'
                AND event_id IN ('17', '18')
                AND (
                    search_blob NOT LIKE '%spoolss%'
                    AND search_blob NOT LIKE '%wkssvc%'
                    AND search_blob NOT LIKE '%srvsvc%'
                )
            GROUP BY source_host
            HAVING pipe_events >= 2
        """,
        'indicators': [
            'Sysmon Event 17/18 pipe created/connected',
            'Unusual pipe names from unexpected processes',
            'Event 4624 with network credentials from local source'
        ],
        'thresholds': {'min_events': 2}
    },
    {
        'id': 'uac_bypass',
        'name': 'UAC Bypass',
        'category': 'Privilege Escalation',
        'description': 'User Account Control bypass techniques detected.',
        'severity': 'high',
        'mitre_tactics': ['Privilege Escalation', 'Defense Evasion'],
        'mitre_techniques': ['T1548.002'],
        'detection_query': """
            SELECT 
                source_host,
                count() as uac_bypass_events,
                min(timestamp) as first_seen,
                max(timestamp) as last_seen,
                groupArray(process_name) as processes
            FROM events
            WHERE case_id = {case_id:UInt32}
                AND (
                    (lower(process_name) IN ('fodhelper.exe', 'eventvwr.exe', 'sdclt.exe', 'computerdefaults.exe')
                        AND parent_process NOT LIKE '%explorer.exe%')
                    OR (event_id = '13' AND channel LIKE '%Sysmon%' 
                        AND (search_blob LIKE '%ms-settings%' OR search_blob LIKE '%mscfile%'))
                    OR (search_blob LIKE '%bypass%' AND search_blob LIKE '%uac%')
                )
            GROUP BY source_host
            HAVING uac_bypass_events >= 1
        """,
        'indicators': [
            'Auto-elevated binaries (fodhelper, eventvwr) with unusual children',
            'Registry modification to ms-settings or mscfile',
            'High-integrity process without UAC prompt'
        ],
        'thresholds': {'min_events': 1}
    },
]

# ============================================================================
# DEFENSE EVASION
# ============================================================================

DEFENSE_EVASION_PATTERNS = [
    {
        'id': 'log_clearing',
        'name': 'Log Clearing',
        'category': 'Defense Evasion',
        'description': 'Security or system logs cleared to cover tracks.',
        'severity': 'critical',
        'mitre_tactics': ['Defense Evasion'],
        'mitre_techniques': ['T1070.001'],
        'detection_query': """
            SELECT 
                source_host,
                count() as clear_events,
                countIf(event_id = '1102') as security_cleared,
                countIf(event_id = '104') as system_cleared,
                min(timestamp) as first_seen,
                max(timestamp) as last_seen
            FROM events
            WHERE case_id = {case_id:UInt32}
                AND (
                    event_id IN ('1102', '104')
                    OR (lower(command_line) LIKE '%wevtutil%' AND lower(command_line) LIKE '% cl %')
                    OR lower(command_line) LIKE '%clear-eventlog%'
                )
            GROUP BY source_host
            HAVING clear_events >= 1
        """,
        'indicators': [
            'Event 1102 Security log cleared',
            'Event 104 System log cleared',
            'wevtutil.exe with cl parameter',
            'Sudden gaps in logging'
        ],
        'thresholds': {'min_events': 1}
    },
    {
        'id': 'timestomping',
        'name': 'Timestomping',
        'category': 'Defense Evasion',
        'description': 'File timestamps modified to evade detection.',
        'severity': 'high',
        'mitre_tactics': ['Defense Evasion'],
        'mitre_techniques': ['T1070.006'],
        'detection_query': """
            SELECT 
                source_host,
                count() as stomp_events,
                min(timestamp) as first_seen,
                max(timestamp) as last_seen,
                groupArray(search_blob) as files_modified
            FROM events
            WHERE case_id = {case_id:UInt32}
                AND event_id = '2'
                AND channel LIKE '%Sysmon%'
            GROUP BY source_host
            HAVING stomp_events >= 1
        """,
        'indicators': [
            'Sysmon Event 2 file creation time changed',
            '$SI and $FN timestamp discrepancies',
            'Creation times newer than modification times'
        ],
        'thresholds': {'min_events': 1}
    },
    {
        'id': 'process_injection',
        'name': 'Process Injection',
        'category': 'Defense Evasion',
        'description': 'Code injection into remote processes detected.',
        'severity': 'critical',
        'mitre_tactics': ['Defense Evasion', 'Privilege Escalation'],
        'mitre_techniques': ['T1055'],
        'detection_query': """
            SELECT 
                source_host,
                count() as injection_events,
                countIf(event_id = '8') as remote_threads,
                countIf(event_id = '10') as process_access,
                min(timestamp) as first_seen,
                max(timestamp) as last_seen
            FROM events
            WHERE case_id = {case_id:UInt32}
                AND channel LIKE '%Sysmon%'
                AND (
                    event_id = '8'
                    OR (event_id = '10' AND search_blob LIKE '%0x1F0FFF%')
                )
            GROUP BY source_host
            HAVING injection_events >= 1
        """,
        'indicators': [
            'Sysmon Event 8 CreateRemoteThread',
            'Event 10 suspicious cross-process access',
            'Unusual parent-child process relationships',
            'Legitimate processes making unexpected network connections'
        ],
        'thresholds': {'min_events': 1}
    },
    {
        'id': 'amsi_bypass',
        'name': 'AMSI Bypass',
        'category': 'Defense Evasion',
        'description': 'Antimalware Scan Interface bypass attempts detected.',
        'severity': 'high',
        'mitre_tactics': ['Defense Evasion'],
        'mitre_techniques': ['T1562.001'],
        'detection_query': """
            SELECT 
                source_host,
                count() as amsi_events,
                min(timestamp) as first_seen,
                max(timestamp) as last_seen
            FROM events
            WHERE case_id = {case_id:UInt32}
                AND event_id IN ('4103', '4104')
                AND (
                    lower(search_blob) LIKE '%amsi%'
                    OR lower(search_blob) LIKE '%amsiinitfailed%'
                    OR lower(search_blob) LIKE '%amsicontext%'
                    OR lower(search_blob) LIKE '%amsiscanbuffer%'
                )
            GROUP BY source_host
            HAVING amsi_events >= 1
        """,
        'indicators': [
            'PowerShell Event 4104 with AMSI strings',
            'Obfuscated content in script blocks',
            'amsi.dll load failures or modifications'
        ],
        'thresholds': {'min_events': 1}
    },
]

# ============================================================================
# DISCOVERY
# ============================================================================

DISCOVERY_PATTERNS = [
    {
        'id': 'network_enumeration',
        'name': 'Network Enumeration',
        'category': 'Discovery',
        'description': 'Network scanning and host discovery activity.',
        'severity': 'medium',
        'mitre_tactics': ['Discovery'],
        'mitre_techniques': ['T1046', 'T1018'],
        'detection_query': """
            SELECT 
                source_host,
                count() as enum_events,
                min(timestamp) as first_seen,
                max(timestamp) as last_seen
            FROM events
            WHERE case_id = {case_id:UInt32}
                AND (
                    lower(command_line) LIKE '%net view%'
                    OR lower(command_line) LIKE '%net group%'
                    OR lower(command_line) LIKE '%nltest%'
                    OR lower(command_line) LIKE '%nbtstat%'
                    OR lower(command_line) LIKE '%arp -a%'
                    OR lower(command_line) LIKE '%ping -n%' 
                    OR lower(command_line) LIKE '%nmap%'
                    OR lower(command_line) LIKE '%net user /domain%'
                )
            GROUP BY source_host
            HAVING enum_events >= 3
        """,
        'indicators': [
            'Event 4648 with broad target scope',
            'Connections to many hosts on ports 445, 389, 135',
            'net.exe, nltest, nbtstat, arp, ping sweeps'
        ],
        'thresholds': {'min_events': 3}
    },
    {
        'id': 'ad_enumeration',
        'name': 'Active Directory Enumeration',
        'category': 'Discovery',
        'description': 'Active Directory reconnaissance and enumeration.',
        'severity': 'medium',
        'mitre_tactics': ['Discovery'],
        'mitre_techniques': ['T1087.002', 'T1069.002'],
        'detection_query': """
            SELECT 
                source_host,
                count() as ad_events,
                countIf(event_id = '4662') as ds_access,
                countIf(event_id = '4661') as sam_access,
                min(timestamp) as first_seen,
                max(timestamp) as last_seen
            FROM events
            WHERE case_id = {case_id:UInt32}
                AND (
                    (event_id IN ('4662', '4661', '4663'))
                    OR (lower(command_line) LIKE '%dsquery%')
                    OR (lower(command_line) LIKE '%ldapsearch%')
                    OR (lower(command_line) LIKE '%adfind%')
                    OR (lower(command_line) LIKE '%get-ad%')
                )
            GROUP BY source_host
            HAVING ad_events >= 5
        """,
        'indicators': [
            'Event 4662 directory service access',
            'LDAP queries for sensitive objects',
            'Event 4661 SAM handle requests',
            'High-volume directory queries'
        ],
        'thresholds': {'min_events': 5}
    },
    {
        'id': 'bloodhound_collection',
        'name': 'BloodHound / SharpHound Collection',
        'category': 'Discovery',
        'description': 'BloodHound or SharpHound AD enumeration tool activity.',
        'severity': 'high',
        'mitre_tactics': ['Discovery'],
        'mitre_techniques': ['T1087.002', 'T1069.002'],
        'detection_query': """
            SELECT 
                source_host,
                count() as bloodhound_events,
                min(timestamp) as first_seen,
                max(timestamp) as last_seen
            FROM events
            WHERE case_id = {case_id:UInt32}
                AND (
                    lower(search_blob) LIKE '%sharphound%'
                    OR lower(search_blob) LIKE '%bloodhound%'
                    OR lower(command_line) LIKE '%invoke-bloodhound%'
                    OR lower(command_line) LIKE '%-collectionmethod%'
                    OR (lower(command_line) LIKE '%ldap%' AND lower(command_line) LIKE '%session%')
                )
            GROUP BY source_host
            HAVING bloodhound_events >= 1
        """,
        'indicators': [
            'Event 4662/4663 AD object enumeration',
            'SMB connections to many hosts',
            'LDAP query patterns matching SharpHound',
            'sharphound.exe or bloodhound collectors'
        ],
        'thresholds': {'min_events': 1}
    },
]

# ============================================================================
# EXFILTRATION
# ============================================================================

EXFILTRATION_PATTERNS = [
    {
        'id': 'data_staging',
        'name': 'Data Staging',
        'category': 'Exfiltration',
        'description': 'Data collection and staging for exfiltration.',
        'severity': 'high',
        'mitre_tactics': ['Collection', 'Exfiltration'],
        'mitre_techniques': ['T1074.001'],
        'detection_query': """
            SELECT 
                source_host,
                count() as staging_events,
                min(timestamp) as first_seen,
                max(timestamp) as last_seen
            FROM events
            WHERE case_id = {case_id:UInt32}
                AND (
                    (event_id = '11' AND channel LIKE '%Sysmon%' AND (
                        search_blob LIKE '%.zip%'
                        OR search_blob LIKE '%.7z%'
                        OR search_blob LIKE '%.rar%'
                        OR search_blob LIKE '%.tar%'
                    ) AND (
                        search_blob LIKE '%\\Temp\\%'
                        OR search_blob LIKE '%\\AppData\\%'
                        OR search_blob LIKE '%\\Public\\%'
                    ))
                    OR (lower(command_line) LIKE '%compress-archive%')
                    OR (lower(command_line) LIKE '%7z.exe%' AND lower(command_line) LIKE '% a %')
                    OR (lower(command_line) LIKE '%rar.exe%' AND lower(command_line) LIKE '% a %')
                )
            GROUP BY source_host
            HAVING staging_events >= 1
        """,
        'indicators': [
            'Sysmon Event 11 archive files in temp dirs',
            'Large .zip/.7z/.rar files created',
            'File copy to network shares',
            'Event 5145 sensitive share access'
        ],
        'thresholds': {'min_events': 1}
    },
    {
        'id': 'dns_exfiltration',
        'name': 'DNS Exfiltration',
        'category': 'Exfiltration',
        'description': 'Data exfiltration via DNS queries with encoded data.',
        'severity': 'high',
        'mitre_tactics': ['Exfiltration'],
        'mitre_techniques': ['T1048.003'],
        'detection_query': """
            SELECT 
                source_host,
                count() as dns_events,
                min(timestamp) as first_seen,
                max(timestamp) as last_seen
            FROM events
            WHERE case_id = {case_id:UInt32}
                AND event_id = '22'
                AND channel LIKE '%Sysmon%'
                AND (
                    length(extractAll(search_blob, '([a-zA-Z0-9]{32,})')[1]) >= 32
                    OR search_blob LIKE '%TXT%'
                )
            GROUP BY source_host
            HAVING dns_events >= 10
        """,
        'indicators': [
            'Long DNS subdomain queries',
            'High volume to single domain',
            'TXT record queries with encoded data',
            'Unusual DNS from non-browser processes'
        ],
        'thresholds': {'min_events': 10}
    },
    {
        'id': 'cloud_exfiltration',
        'name': 'Cloud Storage Exfiltration',
        'category': 'Exfiltration',
        'description': 'Data upload to cloud storage services from unusual processes.',
        'severity': 'high',
        'mitre_tactics': ['Exfiltration'],
        'mitre_techniques': ['T1567.002'],
        'detection_query': """
            SELECT 
                source_host,
                count() as cloud_events,
                min(timestamp) as first_seen,
                max(timestamp) as last_seen
            FROM events
            WHERE case_id = {case_id:UInt32}
                AND (
                    (event_id = '3' AND channel LIKE '%Sysmon%' AND (
                        search_blob LIKE '%dropbox%'
                        OR search_blob LIKE '%drive.google%'
                        OR search_blob LIKE '%onedrive%'
                        OR search_blob LIKE '%mega.nz%'
                        OR search_blob LIKE '%pastebin%'
                    ) AND process_name NOT IN ('chrome.exe', 'firefox.exe', 'msedge.exe', 'iexplore.exe'))
                    OR (lower(command_line) LIKE '%rclone%')
                    OR (lower(command_line) LIKE '%megacmd%')
                )
            GROUP BY source_host
            HAVING cloud_events >= 1
        """,
        'indicators': [
            'Connections to cloud storage domains',
            'Non-browser processes accessing cloud services',
            'Large uploads via proxy logs',
            'rclone or mega tools detected'
        ],
        'thresholds': {'min_events': 1}
    },
]

# ============================================================================
# COMBINED PATTERN LIST
# ============================================================================

ALL_PATTERN_RULES: List[Dict[str, Any]] = (
    CREDENTIAL_ATTACK_PATTERNS +
    LATERAL_MOVEMENT_PATTERNS +
    PERSISTENCE_PATTERNS +
    PRIV_ESC_PATTERNS +
    DEFENSE_EVASION_PATTERNS +
    DISCOVERY_PATTERNS +
    EXFILTRATION_PATTERNS
)

# Category grouping for UI
PATTERN_CATEGORIES = {
    'Credential Attacks': CREDENTIAL_ATTACK_PATTERNS,
    'Lateral Movement': LATERAL_MOVEMENT_PATTERNS,
    'Persistence': PERSISTENCE_PATTERNS,
    'Privilege Escalation': PRIV_ESC_PATTERNS,
    'Defense Evasion': DEFENSE_EVASION_PATTERNS,
    'Discovery': DISCOVERY_PATTERNS,
    'Exfiltration': EXFILTRATION_PATTERNS,
}
