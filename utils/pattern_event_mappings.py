"""Pattern Event Mappings for AI Correlation Analysis

Defines which Windows Event IDs and conditions are relevant for each
attack pattern. Used by CandidateExtractor to pre-filter events from
large datasets before AI analysis.

Each pattern includes:
- anchor_events: Primary indicators that trigger detection
- supporting_events: Corroborating evidence
- context_events: Additional context (optional)
- anchor_conditions: Specific field conditions for anchor events
- correlation_fields: Fields used to group related events
- time_window_minutes: Maximum time span for related events
- checklist: Items for AI to verify during analysis
"""

from typing import Dict, List, Any, Optional


# =============================================================================
# CREDENTIAL ACCESS PATTERNS (MITRE ATT&CK TA0006)
# =============================================================================

CREDENTIAL_ACCESS_PATTERNS = {
    'pass_the_hash': {
        'name': 'Pass the Hash',
        'description': 'NTLM authentication using stolen password hashes instead of plaintext passwords. KeyLength=0 indicates hash-based authentication.',
        'category': 'Credential Access',
        'mitre_techniques': ['T1550.002'],
        'severity': 'critical',
        'anchor_events': ['4624'],
        'supporting_events': ['4648', '4634', '4672'],
        'context_events': ['4768', '4769', '4023'],
        'anchor_conditions': {
            '4624': {
                'logon_type': [3, 9],
                'auth_package': ['NTLM', 'NtLmSsp'],
                'key_length': '0'
            }
        },
        'correlation_fields': ['source_host', 'username', 'target_host'],
        'time_window_minutes': 60,
        'required_sources': {'Security': 'critical', 'Sysmon': 'supplementary'},
        'ai_full_threshold': 40,
        'ai_gray_threshold': 30,
        'checklist': [
            'NTLM authentication with KeyLength=0 (definitive PTH indicator)',
            'Network logon (type 3) on target or NewCredentials logon (type 9) on source',
            'Type 9 logon with logon_process seclogo (Mimikatz sekurlsa::pth indicator)',
            'No Kerberos TGT request (4768) before the logon',
            'Privileged account being used',
            'Same source IP accessing multiple targets',
            'Process context: psexec, wmic, powershell, cmd',
            'Multiple hosts accessed in short timeframe'
        ]
    },
    
    'pass_the_ticket': {
        'name': 'Pass the Ticket',
        'description': 'Kerberos ticket reuse from a different host than originally requested. Stolen TGT/TGS tickets used for lateral movement.',
        'category': 'Credential Access',
        'mitre_techniques': ['T1550.003'],
        'severity': 'critical',
        'anchor_events': ['4624'],
        'supporting_events': ['4768', '4769', '4672'],
        'context_events': [],
        'anchor_conditions': {
            '4624': {
                'logon_type': [3],
                'auth_package': ['Kerberos']
            }
        },
        'correlation_fields': ['source_host', 'username'],
        'time_window_minutes': 60,
        'required_sources': {'Security': 'critical'},
        'ai_full_threshold': 40,
        'ai_gray_threshold': 30,
        'checklist': [
            'Kerberos logon without preceding TGT request (4768) on same host',
            'Kerberos logon without preceding TGS request (4769) on same host',
            'Client address mismatch between ticket request and usage',
            'Ticket used from different host than requested',
            'Service ticket for sensitive service (CIFS, LDAP, HTTP)',
            'Privileged account access'
        ]
    },
    
    'dcsync': {
        'name': 'DCSync Attack',
        'description': 'Replication of Active Directory password data using Directory Replication Service protocol. Used to extract password hashes.',
        'category': 'Credential Access',
        'mitre_techniques': ['T1003.006'],
        'severity': 'critical',
        'anchor_events': ['4662'],
        'supporting_events': ['4624', '4672', '5136'],
        'context_events': [],
        'anchor_conditions': {
            '4662': {
                'access_mask': '0x100',
                'properties': [
                    '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2',
                    '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2',
                    '89e95b76-444d-4c62-991a-0facbeda640c'
                ]
            }
        },
        'correlation_fields': ['source_host', 'username'],
        'time_window_minutes': 30,
        'required_sources': {'Security': 'critical', 'Directory Service': 'high'},
        'ai_full_threshold': 40,
        'ai_gray_threshold': 30,
        'checklist': [
            'Replication rights (DS-Replication-Get-Changes) used',
            'Account is NOT a domain controller computer account',
            'Source host is NOT a domain controller',
            'Account not in Domain Admins, Enterprise Admins, or DC group',
            'Multiple replication requests in short time',
            'Replication for sensitive objects (users, computers)',
            'Tool indicators: mimikatz, secretsdump, SharpKatz'
        ]
    },
    
    'kerberoasting': {
        'name': 'Kerberoasting',
        'description': 'Request service tickets for SPNs to crack offline. Targets service accounts with weak passwords.',
        'category': 'Credential Access',
        'mitre_techniques': ['T1558.003'],
        'severity': 'high',
        'anchor_events': ['4769'],
        'supporting_events': ['4624', '4768'],
        'context_events': [],
        'anchor_conditions': {
            '4769': {
                'encryption_type': ['0x17', '0x18', '0x11', '0x12'],
            }
        },
        'correlation_fields': ['source_host', 'username'],
        'time_window_minutes': 60,
        'required_sources': {'Security': 'critical'},
        'ai_full_threshold': 35,
        'ai_gray_threshold': 25,
        'checklist': [
            'Multiple TGS requests (4769) for different SPNs',
            'RC4 encryption type requested (0x17/0x18) - weaker, easier to crack',
            'AES encryption type (0x11/0x12) - sophisticated Kerberoasting',
            'High volume of TGS requests from single user (volume-based)',
            'Requests for service accounts (not machine accounts)',
            'Non-service account making requests',
            'Tool indicators: Rubeus, GetUserSPNs, Invoke-Kerberoast'
        ]
    },
    
    'lsass_memory_dump': {
        'name': 'LSASS Memory Dumping',
        'description': 'Dumping LSASS process memory to extract credentials. Classic credential theft technique.',
        'category': 'Credential Access',
        'mitre_techniques': ['T1003.001'],
        'severity': 'critical',
        'anchor_events': ['10', '8', '4656', '4663', '3001'],
        'supporting_events': ['1', '11'],
        'context_events': [],
        'anchor_conditions': {
            '10': {
                'target_image': ['lsass.exe']
            },
            '8': {
                'target_image': ['lsass.exe']
            },
            '4656': {
                'search_blob_contains': ['lsass', 'process']
            },
            '4663': {
                'search_blob_contains': ['lsass', 'process']
            },
            '3001': {
                'search_blob_contains': ['lsass']
            }
        },
        'correlation_fields': ['source_host', 'username'],
        'time_window_minutes': 30,
        'required_sources': {'Sysmon': 'critical', 'Security': 'high', 'Application': 'high'},
        'ai_full_threshold': 35,
        'ai_gray_threshold': 25,
        'checklist': [
            'Process accessing lsass.exe memory (Sysmon Event 10)',
            'CreateRemoteThread targeting lsass.exe (Sysmon Event 8)',
            'Access rights include PROCESS_VM_READ',
            'Accessing process is not legitimate security tool',
            'Event 4656/4663 object access to lsass.exe process',
            'Silent Process Exit cross-process termination of lsass.exe (Event 3001)',
            'File creation of .dmp file (minidump, mdmp)',
            'Tool indicators: procdump, mimikatz, comsvcs.dll, lsassy, rdrleakdiag',
            'Task Manager, Process Explorer used suspiciously',
            'rundll32 with comsvcs.dll MiniDump',
            'LOLBin abuse: rdrleakdiag.exe with /fullmemdmp or /memdmp flags'
        ]
    },
    
    'powershell_credential_dump': {
        'name': 'PowerShell Credential Dumping',
        'description': 'PowerShell-based LSASS credential dumping detected via script block logging (4104), Sysmon DLL load events (Event 7) showing credential-dumping DLLs, or Sysmon process access (Event 10) where PowerShell directly accesses lsass.exe.',
        'category': 'Credential Access',
        'mitre_techniques': ['T1003.001'],
        'severity': 'critical',
        'anchor_events': ['4104', '7', '10'],
        'supporting_events': ['4103', '1', '3'],
        'context_events': [],
        'anchor_conditions': {
            '4104': {
                'search_blob_contains': ['lsass']
            },
            '7': {
                'image_contains': ['powershell'],
                'search_blob_contains': ['cryptdll.dll', 'samlib.dll', 'vaultcli.dll', 'winscard.dll']
            },
            '10': {
                'search_blob_contains': ['powershell'],
                'target_image': ['lsass.exe']
            }
        },
        'correlation_fields': ['source_host'],
        'time_window_minutes': 30,
        'required_sources': {'Microsoft-Windows-PowerShell': 'supplementary', 'Sysmon': 'supplementary'},
        'ai_full_threshold': 30,
        'ai_gray_threshold': 20,
        'checklist': [
            'Script block (4104) references lsass process',
            'MiniDumpWriteDump API call in script block',
            'Get-Process lsass in script content',
            'WindowsErrorReporting / WER reflection abuse',
            'Dump file path or .dmp extension referenced',
            'Script from suspicious path (Public, Temp, AppData)',
            'Sysmon Event 7: PowerShell loading credential-dumping DLLs (cryptdll.dll, samlib.dll, vaultcli.dll, WinSCard.dll)',
            'Sysmon Event 10: PowerShell directly accessing lsass.exe memory (Invoke-Mimikatz pattern)',
            'PowerShell outbound download (Event 3) shortly before lsass access',
            'Sysmon RuleName tag technique_id=T1003 on DLL load events'
        ]
    },
    
    'comsvcs_minidump': {
        'name': 'comsvcs.dll MiniDump Credential Theft',
        'description': 'Memory dump via rundll32 comsvcs.dll MiniDump. Used to dump process memory (commonly LSASS) without dropping tools to disk.',
        'category': 'Credential Access',
        'mitre_techniques': ['T1003.001'],
        'severity': 'critical',
        'anchor_events': ['1', '4688'],
        'supporting_events': ['10', '11', '7'],
        'context_events': [],
        'anchor_conditions': {
            '1': {
                'command_line_contains': ['comsvcs.dll', 'minidump']
            },
            '4688': {
                'command_line_contains': ['comsvcs.dll', 'minidump']
            }
        },
        'correlation_fields': ['source_host', 'username'],
        'time_window_minutes': 15,
        'required_sources': {'Sysmon': 'critical'},
        'ai_full_threshold': 30,
        'ai_gray_threshold': 20,
        'checklist': [
            'rundll32.exe loading comsvcs.dll with MiniDump export',
            'Process access (Sysmon 10) with high-privilege access rights',
            'Dump file creation (Sysmon 11) shortly after execution',
            'GrantedAccess 0x1FFFFF (PROCESS_ALL_ACCESS)',
            'comsvcs.dll in CallTrace of process access event',
            'Parent process: WmiPrvSE, cmd.exe, powershell — execution chain'
        ]
    },
    
    'password_spraying': {
        'name': 'Password Spraying',
        'description': 'Same password attempted against many accounts to avoid lockout. Covers NTLM (4625), Kerberos (4771 pre-auth failure, 4768 TGT failure), and MSSQL (18456) authentication protocols.',
        'category': 'Credential Access',
        'mitre_techniques': ['T1110.003'],
        'severity': 'high',
        'anchor_events': ['4625', '4771', '4768', '18456'],
        'supporting_events': ['4624', '4776'],
        'context_events': [],
        'anchor_conditions': {
            '4768': {'payload_data5_excludes': 'KDC_ERR_NONE'}
        },
        'correlation_fields': ['source_host'],
        'time_window_minutes': 60,
        'min_anchors_per_key': 3,
        'required_sources': {'Security': 'critical'},
        'ai_full_threshold': 40,
        'ai_gray_threshold': 30,
        'checklist': [
            'Failed logons (4625/18456) or Kerberos failures (4771/4768) for many different accounts',
            'Same source IP/host for all failures',
            'Sub-status 0xC000006A (bad password), KDC_ERR_PREAUTH_FAILED / KDC_ERR_C_PRINCIPAL_UNKNOWN, or MSSQL password mismatch',
            'Low attempts per account (1-3)',
            'High total attempts (10+)',
            'Attempts spread across time to avoid lockout',
            'Off-hours activity'
        ]
    },
    
    'brute_force': {
        'name': 'Brute Force Attack',
        'description': 'Multiple password attempts against single account. Covers Windows logon (4625) and MSSQL failed logon (18456).',
        'category': 'Credential Access',
        'mitre_techniques': ['T1110.001'],
        'severity': 'high',
        'anchor_events': ['4625', '18456'],
        'supporting_events': ['4624', '4740'],
        'context_events': [],
        'anchor_conditions': {},
        'correlation_fields': ['source_host', 'username'],
        'time_window_minutes': 60,
        'min_anchors_per_key': 3,
        'required_sources': {'Security': 'critical'},
        'ai_full_threshold': 40,
        'ai_gray_threshold': 30,
        'checklist': [
            'Multiple failed logons (4625/18456) for same account',
            'High frequency of attempts',
            'Sub-status 0xC000006A (bad password) or MSSQL password mismatch',
            'Eventually followed by successful logon (4624)',
            'Account lockout (4740) triggered',
            'External source IP or unusual internal source'
        ]
    }
}


# =============================================================================
# LATERAL MOVEMENT PATTERNS (MITRE ATT&CK TA0008)
# =============================================================================

LATERAL_MOVEMENT_PATTERNS = {
    'psexec_execution': {
        'name': 'PsExec/SMB Lateral Movement',
        'description': 'Remote service execution via SMB admin shares using PsExec or similar tools.',
        'category': 'Lateral Movement',
        'mitre_techniques': ['T1021.002', 'T1569.002'],
        'severity': 'high',
        'anchor_events': ['7045', '4697'],
        'supporting_events': ['4624', '5140', '5145'],
        'context_events': ['1', '4688'],
        'anchor_conditions': {},
        'correlation_fields': ['source_host', 'username', 'target_host'],
        'time_window_minutes': 30,
        'required_sources': {'Security': 'critical', 'System': 'high'},
        'ai_full_threshold': 40,
        'ai_gray_threshold': 30,
        'checklist': [
            'New service installed remotely (7045/4697)',
            'Service name pattern: PSEXESVC, CSEXEC, or random/renamed service',
            'Network logon (type 3) preceding service installation',
            'Access to ADMIN$ or C$ share (5140/5145)',
            'Service binary path with cmd.exe or powershell.exe',
            'Short-lived service (installed then quickly removed)',
            'Process: psexec.exe, paexec.exe, csexec.exe'
        ]
    },
    
    'wmi_lateral': {
        'name': 'WMI Lateral Movement',
        'description': 'Remote process execution via Windows Management Instrumentation.',
        'category': 'Lateral Movement',
        'mitre_techniques': ['T1021.003'],
        'severity': 'high',
        'anchor_events': ['1', '4688'],
        'supporting_events': ['4624', '4648'],
        'context_events': [],
        'anchor_conditions': {
            '1': {
                'parent_image': ['wmiprvse.exe']
            },
            '4688': {
                'parent_image': ['wmiprvse.exe']
            }
        },
        'correlation_fields': ['source_host', 'username'],
        'time_window_minutes': 30,
        'required_sources': {'Sysmon': 'critical', 'Security': 'high'},
        'ai_full_threshold': 40,
        'ai_gray_threshold': 25,
        'checklist': [
            'WmiPrvSE.exe spawning child processes',
            'wmic.exe /node: parameter used',
            'Network logon (type 3) preceding WMI activity — required for lateral',
            'Remote process creation via Win32_Process',
            'Processes spawned by wmiprvse.exe: powershell, cmd, script host',
            'Tool indicators: wmic, Invoke-WmiMethod, Invoke-CimMethod'
        ]
    },
    
    'rdp_lateral': {
        'name': 'RDP Lateral Movement',
        'description': 'Remote Desktop Protocol used for lateral movement between systems.',
        'category': 'Lateral Movement',
        'mitre_techniques': ['T1021.001'],
        'severity': 'medium',
        'anchor_events': ['4624', '4778', '4779'],
        'supporting_events': ['4648', '4634'],
        'context_events': [],
        'anchor_conditions': {
            '4624': {
                'logon_type': [10, 7]
            }
        },
        'correlation_fields': ['source_host', 'username', 'target_host'],
        'time_window_minutes': 120,
        'required_sources': {'Security': 'critical'},
        'ai_full_threshold': 40,
        'ai_gray_threshold': 20,
        'checklist': [
            'Interactive logon type 10 (RemoteInteractive)',
            'Single user RDP to multiple hosts',
            'RDP from unusual source (not IT workstation)',
            'RDP session followed by suspicious activity',
            'Session reconnect/disconnect patterns',
            'Off-hours RDP activity'
        ]
    },
    
    'winrm_lateral': {
        'name': 'WinRM Lateral Movement',
        'description': 'Windows Remote Management used for remote command execution.',
        'category': 'Lateral Movement',
        'mitre_techniques': ['T1021.006'],
        'severity': 'high',
        'anchor_events': ['4624', '1', '4688'],
        'supporting_events': ['4648', '91', '6'],
        'context_events': [],
        'anchor_conditions': {
            '4624': {
                'logon_type': [3],
            },
            '1': {
                'command_line_contains_any': ['wsmprovhost', 'winrshost', 'winrm', 'enter-pssession', 'invoke-command']
            },
            '4688': {
                'command_line_contains_any': ['wsmprovhost', 'winrshost', 'winrm', 'enter-pssession', 'invoke-command']
            }
        },
        'correlation_fields': ['source_host', 'username', 'target_host'],
        'time_window_minutes': 30,
        'required_sources': {'Security': 'critical', 'Sysmon': 'high'},
        'ai_full_threshold': 40,
        'ai_gray_threshold': 25,
        'checklist': [
            'wsmprovhost.exe or winrshost.exe process creation (Sysmon 1 or 4688)',
            'Network logon (type 3) associated with WinRM activity',
            'PowerShell remoting: Enter-PSSession, Invoke-Command, New-PSSession',
            'WinRM service event (91) or WSMan operational events',
            'Single source host executing commands on multiple targets',
            'Non-admin user using WinRM'
        ]
    }
}


# =============================================================================
# PERSISTENCE PATTERNS (MITRE ATT&CK TA0003)
# =============================================================================

PERSISTENCE_PATTERNS = {
    'registry_run_keys': {
        'name': 'Registry Run Key Persistence',
        'description': 'Programs added to registry run keys for persistence.',
        'category': 'Persistence',
        'mitre_techniques': ['T1547.001'],
        'severity': 'high',
        'anchor_events': ['4657', '13'],
        'supporting_events': ['1', '4688'],
        'context_events': [],
        'anchor_conditions': {},
        'correlation_fields': ['source_host', 'username'],
        'time_window_minutes': 60,
        'required_sources': {'Sysmon': 'critical', 'Security': 'supplementary'},
        'ai_full_threshold': 35,
        'ai_gray_threshold': 25,
        'checklist': [
            'Modification to Run/RunOnce registry keys',
            'HKLM or HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
            'Unusual binary path added',
            'Binary in temp, appdata, or user-writable location',
            'Recently created binary referenced',
            'Non-standard program added by non-admin process'
        ]
    },
    
    'scheduled_task_persistence': {
        'name': 'Scheduled Task Persistence',
        'description': 'Scheduled tasks created for persistent code execution.',
        'category': 'Persistence',
        'mitre_techniques': ['T1053.005'],
        'severity': 'high',
        'anchor_events': ['4698', '4699', '4700', '4701', '4702'],
        'supporting_events': ['1', '4688'],
        'context_events': [],
        'anchor_conditions': {},
        'correlation_fields': ['source_host', 'username'],
        'time_window_minutes': 60,
        'required_sources': {'Security': 'critical'},
        'ai_full_threshold': 35,
        'ai_gray_threshold': 25,
        'checklist': [
            'New scheduled task created (4698)',
            'Task runs as SYSTEM or high-privilege account',
            'Task action runs script or suspicious binary',
            'Trigger: at logon, at startup, or recurring',
            'Task created by non-admin user',
            'Action path in unusual location',
            'schtasks.exe command line analysis'
        ]
    },
    
    'service_persistence': {
        'name': 'Service Persistence',
        'description': 'Windows services created or modified for persistence.',
        'category': 'Persistence',
        'mitre_techniques': ['T1543.003'],
        'severity': 'high',
        'anchor_events': ['7045', '4697'],
        'supporting_events': ['7040', '1'],
        'context_events': [],
        'anchor_conditions': {},
        'correlation_fields': ['source_host', 'username'],
        'time_window_minutes': 60,
        'required_sources': {'System': 'critical', 'Security': 'high'},
        'ai_full_threshold': 35,
        'ai_gray_threshold': 25,
        'checklist': [
            'New service installed (7045/4697)',
            'Service binary in unusual location',
            'Service runs as LocalSystem',
            'Service start type: auto or delayed-auto',
            'sc.exe create command',
            'Service name mimics legitimate service',
            'Binary is script or has suspicious parameters'
        ]
    }
}


# =============================================================================
# DEFENSE EVASION PATTERNS (MITRE ATT&CK TA0005)
# =============================================================================

DEFENSE_EVASION_PATTERNS = {
    'uac_bypass': {
        'name': 'UAC Bypass',
        'description': 'User Account Control bypass via auto-elevated binaries (eventvwr, fodhelper, sdclt) or registry hijacking (ms-settings, mscfile).',
        'category': 'Defense Evasion',
        'mitre_techniques': ['T1548.002'],
        'severity': 'high',
        'anchor_events': ['1', '4688', '13'],
        'supporting_events': ['12', '4688'],
        'context_events': [],
        'anchor_conditions': {
            '1': {
                'command_line_contains_any': ['eventvwr', 'fodhelper', 'sdclt', 'computerdefaults']
            },
            '4688': {
                'command_line_contains_any': ['eventvwr', 'fodhelper', 'sdclt', 'computerdefaults']
            },
            '13': {
                'search_blob_contains': ['ms-settings']
            }
        },
        'correlation_fields': ['source_host', 'username'],
        'time_window_minutes': 15,
        'required_sources': {'Sysmon': 'supplementary', 'Security': 'supplementary'},
        'ai_full_threshold': 30,
        'ai_gray_threshold': 20,
        'checklist': [
            'Auto-elevated binary executed (eventvwr.exe, fodhelper.exe, sdclt.exe, computerdefaults.exe)',
            'Parent process is not explorer.exe (suspicious launch chain)',
            'Registry modification to ms-settings or mscfile handler',
            'High integrity process spawned without UAC prompt',
            'Sysmon RuleName tag contains T1088 or T1548',
            'Child process spawned by the auto-elevated binary'
        ]
    },

    'certificate_installation': {
        'name': 'Root Certificate Installation',
        'description': 'Installation of root certificates to trusted store, potentially enabling MITM attacks or code signing bypass.',
        'category': 'Defense Evasion',
        'mitre_techniques': ['T1553.004'],
        'severity': 'high',
        'anchor_events': ['12', '13'],
        'supporting_events': ['1', '4688'],
        'context_events': [],
        'anchor_conditions': {
            '12': {
                'search_blob_contains': ['SystemCertificates', 'Root']
            },
            '13': {
                'search_blob_contains': ['SystemCertificates', 'Root']
            }
        },
        'correlation_fields': ['source_host'],
        'time_window_minutes': 30,
        'required_sources': {'Sysmon': 'critical'},
        'ai_full_threshold': 30,
        'ai_gray_threshold': 20,
        'checklist': [
            'Registry key creation/modification under SystemCertificates\\Root',
            'Certificate added to trusted root store (HKLM or HKU)',
            'certutil.exe or certmgr.exe used to install certificate',
            'Non-standard process modifying certificate store',
            'Certificate installation outside of group policy update',
            'Sysmon RuleName tag contains T1130 or T1553'
        ]
    },

    'log_clearing': {
        'name': 'Security Log Clearing',
        'description': 'Windows security logs cleared to hide malicious activity.',
        'category': 'Defense Evasion',
        'mitre_techniques': ['T1070.001'],
        'severity': 'critical',
        'anchor_events': ['1102', '104'],
        'supporting_events': ['4688', '1'],
        'context_events': [],
        'anchor_conditions': {},
        'correlation_fields': ['source_host', 'username'],
        'time_window_minutes': 30,
        'required_sources': {'Security': 'critical'},
        'ai_full_threshold': 30,
        'ai_gray_threshold': 25,
        'checklist': [
            'Security log cleared (1102)',
            'System log cleared (104)',
            'wevtutil.exe cl Security command',
            'PowerShell Clear-EventLog command',
            'Log cleared by non-admin user',
            'Suspicious activity before log clearing',
            'Multiple logs cleared in sequence'
        ]
    },
    
    'process_injection': {
        'name': 'Process Injection',
        'description': 'Code injection into legitimate processes to evade detection.',
        'category': 'Defense Evasion',
        'mitre_techniques': ['T1055'],
        'severity': 'critical',
        'anchor_events': ['8', '10'],
        'supporting_events': ['1', '7'],
        'context_events': [],
        'anchor_conditions': {},
        'correlation_fields': ['source_host'],
        'time_window_minutes': 30,
        'required_sources': {'Sysmon': 'critical'},
        'ai_full_threshold': 40,
        'ai_gray_threshold': 30,
        'checklist': [
            'CreateRemoteThread call to another process (Sysmon 8)',
            'Process access with VM_WRITE + VM_OPERATION (Sysmon 10)',
            'Suspicious parent creating thread in browser/lsass/etc',
            'NtMapViewOfSection / WriteProcessMemory indicators',
            'DLL loaded from unusual path into legitimate process',
            'Code execution from non-executable memory regions'
        ]
    }
}


# =============================================================================
# DISCOVERY PATTERNS (MITRE ATT&CK TA0007)
# =============================================================================

DISCOVERY_PATTERNS = {
    'bloodhound_sharphound': {
        'name': 'BloodHound/SharpHound Enumeration',
        'description': 'Active Directory enumeration using BloodHound collection tools.',
        'category': 'Discovery',
        'mitre_techniques': ['T1087.002', 'T1069.002'],
        'severity': 'high',
        'anchor_events': ['4662', '5145'],
        'supporting_events': ['4624', '3'],
        'context_events': [],
        'anchor_conditions': {},
        'correlation_fields': ['source_host', 'username'],
        'time_window_minutes': 60,
        'required_sources': {'Security': 'critical'},
        'ai_full_threshold': 40,
        'ai_gray_threshold': 30,
        'checklist': [
            'Mass LDAP queries from single host',
            'Enumeration of all users, groups, computers',
            'Session enumeration (NetSessionEnum)',
            'Local admin enumeration across many hosts',
            'sharphound.exe or bloodhound collectors',
            'Collection methods: All, DCOnly, Group',
            'High volume of directory service queries'
        ]
    },
    
    'system_owner_discovery': {
        'name': 'System Owner/User Discovery',
        'description': 'Enumeration of system owner, logged-on users, or domain information using whoami, quser, net user, or similar tools.',
        'category': 'Discovery',
        'mitre_techniques': ['T1033', 'T1082'],
        'severity': 'medium',
        'anchor_events': ['1', '4688'],
        'supporting_events': [],
        'context_events': [],
        'anchor_conditions': {
            '1': {
                'command_line_contains': ['whoami']
            },
            '4688': {
                'command_line_contains': ['whoami']
            }
        },
        'correlation_fields': ['source_host', 'username'],
        'time_window_minutes': 30,
        'required_sources': {'Sysmon': 'supplementary', 'Security': 'supplementary'},
        'ai_full_threshold': 40,
        'ai_gray_threshold': 30,
        'checklist': [
            'whoami.exe execution (especially with /all, /user, /priv, /groups)',
            'Multiple discovery commands in sequence (whoami, hostname, ipconfig, net user)',
            'Discovery commands spawned from suspicious parent (powershell, cmd via WMI)',
            'Sysmon RuleName tag contains T1033 or T1082',
            'Executed by non-admin user or from unusual context',
            'Part of broader reconnaissance chain'
        ]
    },

    'network_scanning': {
        'name': 'Network Scanning/Port Scanning',
        'description': 'Host and port discovery across network.',
        'category': 'Discovery',
        'mitre_techniques': ['T1046'],
        'severity': 'medium',
        'anchor_events': ['3'],
        'supporting_events': ['1'],
        'context_events': [],
        'anchor_conditions': {},
        'correlation_fields': ['source_host'],
        'time_window_minutes': 60,
        'min_anchors_per_key': 5,
        'required_sources': {'Sysmon': 'critical'},
        'ai_full_threshold': 40,
        'ai_gray_threshold': 30,
        'checklist': [
            'Single host connecting to many IPs',
            'Sequential port connections',
            'Common scan ports: 445, 3389, 22, 80, 443',
            'High volume of failed connections',
            'Tool indicators: nmap, masscan, Advanced Port Scanner',
            'PowerShell Test-NetConnection mass usage'
        ]
    }
}


# =============================================================================
# COMBINED MAPPINGS
# =============================================================================

PATTERN_EVENT_MAPPINGS: Dict[str, Dict[str, Any]] = {
    **CREDENTIAL_ACCESS_PATTERNS,
    **LATERAL_MOVEMENT_PATTERNS,
    **PERSISTENCE_PATTERNS,
    **DEFENSE_EVASION_PATTERNS,
    **DISCOVERY_PATTERNS
}


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def get_pattern_by_id(pattern_id: str) -> Optional[Dict[str, Any]]:
    """Get pattern configuration by ID
    
    Args:
        pattern_id: Pattern identifier
        
    Returns:
        Pattern configuration dict or None
    """
    pattern = PATTERN_EVENT_MAPPINGS.get(pattern_id)
    if pattern:
        pattern = pattern.copy()
        pattern['id'] = pattern_id
    return pattern


def get_patterns_by_category(category: str) -> Dict[str, Dict[str, Any]]:
    """Get all patterns in a category
    
    Args:
        category: Category name (Credential Access, Lateral Movement, etc.)
        
    Returns:
        Dict of pattern_id -> pattern_config
    """
    return {
        pid: {**config, 'id': pid}
        for pid, config in PATTERN_EVENT_MAPPINGS.items()
        if config.get('category') == category
    }


def get_patterns_by_mitre(technique_id: str) -> Dict[str, Dict[str, Any]]:
    """Get all patterns matching a MITRE technique
    
    Args:
        technique_id: MITRE ATT&CK technique ID (e.g., 'T1550.002')
        
    Returns:
        Dict of pattern_id -> pattern_config
    """
    return {
        pid: {**config, 'id': pid}
        for pid, config in PATTERN_EVENT_MAPPINGS.items()
        if technique_id in config.get('mitre_techniques', [])
    }


def get_all_event_ids() -> List[str]:
    """Get all unique event IDs used across patterns
    
    Returns:
        List of unique Windows Event IDs
    """
    event_ids = set()
    for config in PATTERN_EVENT_MAPPINGS.values():
        event_ids.update(config.get('anchor_events', []))
        event_ids.update(config.get('supporting_events', []))
        event_ids.update(config.get('context_events', []))
    return sorted(list(event_ids))


def get_pattern_summary() -> Dict[str, Any]:
    """Get summary statistics about patterns
    
    Returns:
        Dict with pattern counts and categories
    """
    categories = {}
    severities = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
    
    for config in PATTERN_EVENT_MAPPINGS.values():
        cat = config.get('category', 'Unknown')
        categories[cat] = categories.get(cat, 0) + 1
        
        sev = config.get('severity', 'medium')
        severities[sev] = severities.get(sev, 0) + 1
    
    return {
        'total_patterns': len(PATTERN_EVENT_MAPPINGS),
        'by_category': categories,
        'by_severity': severities,
        'unique_event_ids': len(get_all_event_ids())
    }
