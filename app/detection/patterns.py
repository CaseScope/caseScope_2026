"""
Detection Patterns for Automated Threat Hunting
All 30 patterns with verified field names and proper index routing
"""

DETECTION_PATTERNS = [
    
    # ========================================================================
    # TIER 1: CRITICAL & HIGH-FIDELITY (10 patterns)
    # ========================================================================
    
    {
        "id": "001",
        "name": "VPN Brute Force Attack",
        "description": "Multiple failed VPN authentication attempts from single IP address",
        "mitre_technique": "T1110.001",
        "mitre_tactic": "Credential Access",
        "severity": "high",
        "data_source": "firewall",
        "target_index": "case_{case_id}",
        "query": {
            "query": {
                "bool": {
                    "must": [
                        {"match": {"fw_event": "Unknown User Login Attempt"}},
                        {"match": {"message": "login denied"}},
                        {"wildcard": {"source_file": "*.csv"}}
                    ],
                    "filter": [
                        {"range": {"normalized_timestamp": {"gte": "now-7d"}}}
                    ]
                }
            },
            "aggs": {
                "by_source_ip": {
                    "terms": {
                        "field": "src_ip.keyword",
                        "min_doc_count": 10,
                        "size": 50
                    },
                    "aggs": {
                        "unique_users": {"cardinality": {"field": "user_name.keyword"}},
                        "usernames_tried": {"terms": {"field": "user_name.keyword", "size": 20}}
                    }
                }
            },
            "size": 0
        }
    },
    
    {
        "id": "002",
        "name": "PowerShell Encoded Command Execution",
        "description": "PowerShell executed with base64-encoded commands (common malware technique)",
        "mitre_technique": "T1059.001",
        "mitre_tactic": "Execution",
        "severity": "high",
        "data_source": "edr",
        "target_index": "case_{case_id}",
        "query": {
            "query": {
                "bool": {
                    "must": [
                        {"match": {"event.category": "process"}},
                        {"wildcard": {"source_file": "*.ndjson"}}
                    ],
                    "should": [
                        {"wildcard": {"process.command_line": "*-enc*"}},
                        {"wildcard": {"process.command_line": "*-encodedcommand*"}},
                        {"wildcard": {"process.command_line": "*-e *"}},
                        {"wildcard": {"process.command_line": "*frombase64*"}},
                        {"wildcard": {"process.command_line": "*-w hidden*"}},
                        {"wildcard": {"process.command_line": "*-windowstyle hidden*"}}
                    ],
                    "minimum_should_match": 1
                }
            },
            "aggs": {
                "by_user": {
                    "terms": {"field": "process.user.name.keyword", "size": 30},
                    "aggs": {
                        "hosts": {"terms": {"field": "host.name.keyword", "size": 20}}
                    }
                }
            },
            "size": 0
        }
    },
    
    {
        "id": "003",
        "name": "Credential Dumping Tool Execution",
        "description": "Known credential theft tools (Mimikatz, ProcDump on LSASS, etc.)",
        "mitre_technique": "T1003.001",
        "mitre_tactic": "Credential Access",
        "severity": "critical",
        "data_source": "edr",
        "target_index": "case_{case_id}",
        "query": {
            "query": {
                "bool": {
                    "must": [
                        {"match": {"event.category": "process"}},
                        {"wildcard": {"source_file": "*.ndjson"}}
                    ],
                    "should": [
                        {"wildcard": {"process.command_line": "*sekurlsa*"}},
                        {"wildcard": {"process.command_line": "*logonpasswords*"}},
                        {"wildcard": {"process.command_line": "*lsadump*"}},
                        {"wildcard": {"process.command_line": "*::sam*"}},
                        {"wildcard": {"process.command_line": "*::lsa*"}},
                        {"wildcard": {"process.command_line": "*comsvcs.dll*MiniDump*"}},
                        {"wildcard": {"process.command_line": "*Invoke-Mimikatz*"}},
                        {"wildcard": {"process.command_line": "*Out-Minidump*"}},
                        {"match": {"process.name": "mimikatz.exe"}},
                        {"bool": {
                            "must": [
                                {"wildcard": {"process.name": "*procdump*"}},
                                {"wildcard": {"process.command_line": "*lsass*"}}
                            ]
                        }}
                    ],
                    "minimum_should_match": 1
                }
            },
            "aggs": {
                "by_host": {
                    "terms": {"field": "host.name.keyword", "size": 50},
                    "aggs": {
                        "users": {"terms": {"field": "process.user.name.keyword", "size": 10}}
                    }
                }
            },
            "size": 0
        }
    },
    
    {
        "id": "004",
        "name": "PSExec / Remote Execution Tool",
        "description": "PSExec or similar tools used for lateral movement",
        "mitre_technique": "T1021.002",
        "mitre_tactic": "Lateral Movement",
        "severity": "high",
        "data_source": "edr",
        "target_index": "case_{case_id}",
        "query": {
            "query": {
                "bool": {
                    "must": [
                        {"match": {"event.category": "process"}},
                        {"wildcard": {"source_file": "*.ndjson"}}
                    ],
                    "should": [
                        {"match": {"process.name": "psexec.exe"}},
                        {"match": {"process.name": "psexesvc.exe"}},
                        {"match": {"process.name": "paexec.exe"}},
                        {"wildcard": {"process.command_line": "*\\\\\\\\*ADMIN$*"}},
                        {"bool": {
                            "must": [
                                {"term": {"process.parent.name": "services.exe"}},
                                {"terms": {"process.name": ["cmd.exe", "powershell.exe"]}}
                            ]
                        }}
                    ],
                    "minimum_should_match": 1
                }
            },
            "aggs": {
                "by_user": {
                    "terms": {"field": "process.user.name.keyword", "size": 30},
                    "aggs": {
                        "target_hosts": {"terms": {"field": "host.name.keyword", "size": 30}}
                    }
                }
            },
            "size": 0
        }
    },
    
    {
        "id": "005",
        "name": "Suspicious Service Creation",
        "description": "Windows service created from unusual location",
        "mitre_technique": "T1543.003",
        "mitre_tactic": "Persistence",
        "severity": "high",
        "data_source": "edr",
        "target_index": "case_{case_id}",
        "query": {
            "query": {
                "bool": {
                    "must": [
                        {"match": {"event.category": "process"}},
                        {"wildcard": {"source_file": "*.ndjson"}}
                    ],
                    "should": [
                        {"bool": {
                            "must": [
                                {"match": {"process.name": "sc.exe"}},
                                {"wildcard": {"process.command_line": "*create*"}}
                            ]
                        }},
                        {"wildcard": {"process.command_line": "*New-Service*"}},
                        {"bool": {
                            "must": [
                                {"wildcard": {"process.command_line": "*binpath*"}},
                                {"bool": {
                                    "should": [
                                        {"wildcard": {"process.command_line": "*\\\\Temp\\\\*"}},
                                        {"wildcard": {"process.command_line": "*\\\\Users\\\\*"}},
                                        {"wildcard": {"process.command_line": "*\\\\AppData\\\\*"}},
                                        {"wildcard": {"process.command_line": "*\\\\Public\\\\*"}}
                                    ],
                                    "minimum_should_match": 1
                                }}
                            ]
                        }}
                    ],
                    "minimum_should_match": 1
                }
            },
            "aggs": {
                "by_host": {
                    "terms": {"field": "host.name.keyword", "size": 30}
                }
            },
            "size": 0
        }
    },
    
    {
        "id": "006",
        "name": "Pass-the-Hash Detection",
        "description": "NTLM network authentication without Kerberos TGT",
        "mitre_technique": "T1550.002",
        "mitre_tactic": "Lateral Movement",
        "severity": "critical",
        "data_source": "evtx",
        "target_index": "case_{case_id}",
        "query": {
            "query": {
                "bool": {
                    "must": [
                        {"term": {"normalized_event_id": "4624"}},
                        {"wildcard": {"search_blob": "*LogonType*3*"}},
                        {"wildcard": {"search_blob": "*NtLmSsp*"}}
                    ],
                    "filter": [
                        {"wildcard": {"source_file": "*.evtx"}}
                    ]
                }
            },
            "aggs": {
                "by_user": {
                    "terms": {"field": "normalized_username.keyword", "size": 50},
                    "aggs": {
                        "source_ips": {"terms": {"field": "event_data_fields.IpAddress.keyword", "size": 20}}
                    }
                }
            },
            "size": 0
        }
    },
    
    {
        "id": "007",
        "name": "Security Event Log Cleared",
        "description": "Security audit log was cleared (anti-forensics)",
        "mitre_technique": "T1070.001",
        "mitre_tactic": "Defense Evasion",
        "severity": "critical",
        "data_source": "evtx",
        "target_index": "case_{case_id}",
        "query": {
            "query": {
                "bool": {
                    "must": [
                        {"term": {"normalized_event_id": "1102"}}
                    ],
                    "filter": [
                        {"wildcard": {"source_file": "*System.evtx"}}
                    ]
                }
            },
            "aggs": {
                "by_user": {
                    "terms": {"field": "event_data_fields.SubjectUserName.keyword", "size": 20}
                },
                "time_distribution": {
                    "date_histogram": {
                        "field": "normalized_timestamp",
                        "fixed_interval": "1h"
                    }
                }
            },
            "size": 10
        }
    },
    
    {
        "id": "008",
        "name": "Failed Logon Spike (Brute Force)",
        "description": "Multiple failed login attempts indicating brute force attack",
        "mitre_technique": "T1110.001",
        "mitre_tactic": "Credential Access",
        "severity": "high",
        "data_source": "evtx",
        "target_index": "case_{case_id}",
        "query": {
            "query": {
                "bool": {
                    "must": [
                        {"term": {"normalized_event_id": "4625"}}
                    ],
                    "filter": [
                        {"wildcard": {"source_file": "*Security.evtx"}}
                    ]
                }
            },
            "aggs": {
                "by_source_ip": {
                    "terms": {
                        "field": "event_data_fields.IpAddress.keyword",
                        "min_doc_count": 10,
                        "size": 50
                    },
                    "aggs": {
                        "unique_users": {"cardinality": {"field": "normalized_username.keyword"}},
                        "failure_reasons": {"terms": {"field": "event_data_fields.SubStatus.keyword", "size": 10}}
                    }
                }
            },
            "size": 0
        }
    },
    
    {
        "id": "009",
        "name": "Suspicious Process Ancestry",
        "description": "Office apps or browsers spawning shells (macro/exploit indicator)",
        "mitre_technique": "T1059",
        "mitre_tactic": "Execution",
        "severity": "medium",
        "data_source": "edr",
        "target_index": "case_{case_id}",
        "query": {
            "query": {
                "bool": {
                    "must": [
                        {"match": {"event.category": "process"}},
                        {"wildcard": {"source_file": "*.ndjson"}},
                        {"terms": {"process.name": ["cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe"]}}
                    ],
                    "should": [
                        {"match": {"process.parent.name": "winword.exe"}},
                        {"match": {"process.parent.name": "excel.exe"}},
                        {"match": {"process.parent.name": "outlook.exe"}},
                        {"match": {"process.parent.name": "acrord32.exe"}},
                        {"match": {"process.parent.name": "chrome.exe"}},
                        {"match": {"process.parent.name": "firefox.exe"}},
                        {"match": {"process.parent.name": "msedge.exe"}}
                    ],
                    "minimum_should_match": 1
                }
            },
            "aggs": {
                "by_parent": {
                    "terms": {"field": "process.parent.name.keyword", "size": 20},
                    "aggs": {
                        "children": {"terms": {"field": "process.name.keyword", "size": 10}},
                        "users": {"terms": {"field": "process.user.name.keyword", "size": 10}}
                    }
                }
            },
            "size": 0
        }
    },
    
    {
        "id": "010",
        "name": "Network Scanning Activity",
        "description": "Single host contacting many IPs on same port (reconnaissance)",
        "mitre_technique": "T1046",
        "mitre_tactic": "Discovery",
        "severity": "medium",
        "data_source": "firewall",
        "target_index": "case_{case_id}",
        "query": {
            "query": {
                "bool": {
                    "must": [
                        {"wildcard": {"source_file": "*.csv"}}
                    ],
                    "filter": [
                        {"range": {"normalized_timestamp": {"gte": "now-24h"}}}
                    ]
                }
            },
            "aggs": {
                "by_src_ip": {
                    "terms": {"field": "src_ip.keyword", "size": 50},
                    "aggs": {
                        "unique_destinations": {"cardinality": {"field": "dst_ip.keyword"}},
                        "common_ports": {"terms": {"field": "dst_port", "size": 10}},
                        "filter_scanners": {
                            "bucket_selector": {
                                "buckets_path": {"dest_count": "unique_destinations"},
                                "script": "params.dest_count > 50"
                            }
                        }
                    }
                }
            },
            "size": 0
        }
    },
    
    # ========================================================================
    # TIER 2: HIGH VALUE (10 patterns)
    # ========================================================================
    
    {
        "id": "011",
        "name": "Living-off-the-Land Binary Abuse (LOLBins)",
        "description": "Built-in Windows tools used for malicious purposes",
        "mitre_technique": "T1218",
        "mitre_tactic": "Defense Evasion",
        "severity": "medium",
        "data_source": "edr",
        "target_index": "case_{case_id}",
        "query": {
            "query": {
                "bool": {
                    "must": [
                        {"match": {"event.category": "process"}},
                        {"wildcard": {"source_file": "*.ndjson"}}
                    ],
                    "should": [
                        {"wildcard": {"process.command_line": "*certutil*urlcache*"}},
                        {"wildcard": {"process.command_line": "*bitsadmin*transfer*"}},
                        {"wildcard": {"process.command_line": "*regsvr32*/i:http*"}},
                        {"wildcard": {"process.command_line": "*mshta*http*"}},
                        {"wildcard": {"process.command_line": "*rundll32*http*"}}
                    ],
                    "minimum_should_match": 1
                }
            },
            "aggs": {
                "by_tool": {
                    "terms": {"field": "process.name.keyword", "size": 20},
                    "aggs": {
                        "users": {"terms": {"field": "process.user.name.keyword", "size": 10}}
                    }
                }
            },
            "size": 0
        }
    },
    
    {
        "id": "012",
        "name": "WMI Remote Execution",
        "description": "WMI used to spawn processes remotely",
        "mitre_technique": "T1047",
        "mitre_tactic": "Execution",
        "severity": "high",
        "data_source": "edr",
        "target_index": "case_{case_id}",
        "query": {
            "query": {
                "bool": {
                    "must": [
                        {"match": {"event.category": "process"}},
                        {"wildcard": {"source_file": "*.ndjson"}},
                        {"match": {"process.parent.name": "wmiprvse.exe"}},
                        {"terms": {"process.name": ["cmd.exe", "powershell.exe", "cscript.exe"]}}
                    ]
                }
            },
            "aggs": {
                "by_host": {
                    "terms": {"field": "host.name.keyword", "size": 30}
                }
            },
            "size": 0
        }
    },
    
    {
        "id": "013",
        "name": "Scheduled Task Creation",
        "description": "New scheduled tasks created (persistence mechanism)",
        "mitre_technique": "T1053.005",
        "mitre_tactic": "Persistence",
        "severity": "medium",
        "data_source": "evtx",
        "target_index": "case_{case_id}",
        "query": {
            "query": {
                "bool": {
                    "should": [
                        {"term": {"normalized_event_id": "4698"}},
                        {"bool": {
                            "must": [
                                {"match": {"event.category": "process"}},
                                {"wildcard": {"process.command_line": "*schtasks*create*"}}
                            ]
                        }}
                    ]
                }
            },
            "aggs": {
                "by_user": {
                    "terms": {"field": "normalized_username.keyword", "size": 30}
                }
            },
            "size": 0
        }
    },
    
    {
        "id": "014",
        "name": "Kerberoasting",
        "description": "Service ticket requests with RC4 encryption (credential theft)",
        "mitre_technique": "T1558.003",
        "mitre_tactic": "Credential Access",
        "severity": "high",
        "data_source": "evtx",
        "target_index": "case_{case_id}",
        "query": {
            "query": {
                "bool": {
                    "must": [
                        {"term": {"normalized_event_id": "4769"}},
                        {"wildcard": {"search_blob": "*0x17*"}}
                    ]
                }
            },
            "aggs": {
                "by_account": {
                    "terms": {"field": "normalized_username.keyword", "min_doc_count": 5, "size": 30}
                }
            },
            "size": 0
        }
    },
    
    {
        "id": "015",
        "name": "RDP Brute Force",
        "description": "Failed RDP login attempts",
        "mitre_technique": "T1021.001",
        "mitre_tactic": "Lateral Movement",
        "severity": "high",
        "data_source": "evtx",
        "target_index": "case_{case_id}",
        "query": {
            "query": {
                "bool": {
                    "must": [
                        {"term": {"normalized_event_id": "4625"}},
                        {"wildcard": {"search_blob": "*LogonType*10*"}}
                    ]
                }
            },
            "aggs": {
                "by_source": {
                    "terms": {"field": "event_data_fields.IpAddress.keyword", "min_doc_count": 5, "size": 30}
                }
            },
            "size": 0
        }
    },
    
    {
        "id": "016",
        "name": "New User Account Creation",
        "description": "New user accounts created",
        "mitre_technique": "T1136.001",
        "mitre_tactic": "Persistence",
        "severity": "high",
        "data_source": "evtx",
        "target_index": "case_{case_id}",
        "query": {
            "query": {
                "term": {"normalized_event_id": "4720"}
            },
            "aggs": {
                "by_creator": {
                    "terms": {"field": "event_data_fields.SubjectUserName.keyword", "size": 20}
                }
            },
            "size": 10
        }
    },
    
    {
        "id": "017",
        "name": "Unusual Outbound Data Transfer",
        "description": "Large data transfers to external IPs (exfiltration)",
        "mitre_technique": "T1041",
        "mitre_tactic": "Exfiltration",
        "severity": "high",
        "data_source": "firewall",
        "target_index": "case_{case_id}",
        "query": {
            "query": {
                "bool": {
                    "must": [
                        {"wildcard": {"source_file": "*.csv"}},
                        {"exists": {"field": "sent_bytes"}}
                    ]
                }
            },
            "aggs": {
                "by_dest_ip": {
                    "terms": {"field": "dst_ip.keyword", "size": 50},
                    "aggs": {
                        "total_bytes": {"sum": {"field": "sent_bytes"}},
                        "filter_large": {
                            "bucket_selector": {
                                "buckets_path": {"total": "total_bytes"},
                                "script": "params.total > 524288000"
                            }
                        }
                    }
                }
            },
            "size": 0
        }
    },
    
    {
        "id": "018",
        "name": "Prefetch Analysis - Suspicious Execution",
        "description": "Prefetch files for known hacking tools",
        "mitre_technique": "T1059",
        "mitre_tactic": "Execution",
        "severity": "medium",
        "data_source": "prefetch",
        "target_index": "case_{case_id}",
        "query": {
            "query": {
                "bool": {
                    "must": [
                        {"wildcard": {"source_file": "*.pf"}}
                    ],
                    "should": [
                        {"wildcard": {"executable_name": "*mimikatz*"}},
                        {"wildcard": {"executable_name": "*psexec*"}},
                        {"wildcard": {"executable_name": "*bloodhound*"}},
                        {"wildcard": {"executable_name": "*sharphound*"}},
                        {"wildcard": {"executable_name": "*procdump*"}}
                    ],
                    "minimum_should_match": 1
                }
            },
            "size": 10
        }
    },
    
    {
        "id": "019",
        "name": "Registry Run Key Persistence",
        "description": "Suspicious entries in registry autorun keys",
        "mitre_technique": "T1547.001",
        "mitre_tactic": "Persistence",
        "severity": "medium",
        "data_source": "registry",
        "target_index": "case_{case_id}_persistence",
        "query": {
            "query": {
                "bool": {
                    "must": [
                        {"wildcard": {"key_path": "*\\\\Run*"}}
                    ],
                    "should": [
                        {"wildcard": {"value_data": "*\\\\Temp\\\\*"}},
                        {"wildcard": {"value_data": "*\\\\AppData\\\\*"}},
                        {"wildcard": {"value_data": "*\\\\Users\\\\Public\\\\*"}},
                        {"wildcard": {"value_data": "*.vbs"}},
                        {"wildcard": {"value_data": "*.js"}}
                    ],
                    "minimum_should_match": 1
                }
            },
            "size": 10
        }
    },
    
    {
        "id": "020",
        "name": "Antivirus Evasion / Disabling",
        "description": "Attempts to disable Windows Defender or security tools",
        "mitre_technique": "T1562.001",
        "mitre_tactic": "Defense Evasion",
        "severity": "critical",
        "data_source": "edr",
        "target_index": "case_{case_id}",
        "query": {
            "query": {
                "bool": {
                    "must": [
                        {"match": {"event.category": "process"}},
                        {"wildcard": {"source_file": "*.ndjson"}}
                    ],
                    "should": [
                        {"wildcard": {"process.command_line": "*Set-MpPreference*DisableRealtimeMonitoring*"}},
                        {"wildcard": {"process.command_line": "*sc*stop*WinDefend*"}},
                        {"wildcard": {"process.command_line": "*Uninstall-WindowsFeature*Defender*"}},
                        {"wildcard": {"process.command_line": "*Remove-WindowsFeature*Defender*"}}
                    ],
                    "minimum_should_match": 1
                }
            },
            "aggs": {
                "by_host": {
                    "terms": {"field": "host.name.keyword", "size": 30}
                }
            },
            "size": 10
        }
    },
    
    # ========================================================================
    # TIER 3: SPECIALIZED (10 patterns)
    # ========================================================================
    
    {
        "id": "021",
        "name": "Web Shell Activity",
        "description": "Suspicious POST requests to web shells",
        "mitre_technique": "T1505.003",
        "mitre_tactic": "Persistence",
        "severity": "critical",
        "data_source": "iis",
        "target_index": "case_{case_id}",
        "query": {
            "query": {
                "bool": {
                    "must": [
                        {"wildcard": {"source_file": "*iis*.log"}},
                        {"match": {"method": "POST"}}
                    ],
                    "should": [
                        {"wildcard": {"uri": "*.aspx*"}},
                        {"wildcard": {"uri": "*.php*"}},
                        {"wildcard": {"uri": "*cmd*"}},
                        {"wildcard": {"uri": "*eval*"}}
                    ],
                    "minimum_should_match": 1
                }
            },
            "size": 10
        }
    },
    
    {
        "id": "022",
        "name": "DNS Tunneling / C2 Communication",
        "description": "Unusual DNS query patterns indicating data exfiltration",
        "mitre_technique": "T1071.004",
        "mitre_tactic": "Command and Control",
        "severity": "high",
        "data_source": "firewall",
        "target_index": "case_{case_id}",
        "query": {
            "query": {
                "bool": {
                    "must": [
                        {"wildcard": {"source_file": "*.csv"}},
                        {"exists": {"field": "dns_query"}}
                    ]
                }
            },
            "aggs": {
                "long_queries": {
                    "terms": {"field": "dns_query", "size": 50},
                    "aggs": {
                        "query_length": {
                            "scripted_metric": {
                                "init_script": "state.lengths = []",
                                "map_script": "state.lengths.add(doc['dns_query'].value.length())",
                                "combine_script": "return state.lengths",
                                "reduce_script": "return params._aggs.stream().mapToInt(Integer::intValue).average().getAsDouble()"
                            }
                        }
                    }
                }
            },
            "size": 0
        }
    },
    
    {
        "id": "023",
        "name": "Ransomware - Volume Shadow Copy Deletion",
        "description": "Deletion of volume shadow copies (ransomware preparation)",
        "mitre_technique": "T1490",
        "mitre_tactic": "Impact",
        "severity": "critical",
        "data_source": "edr",
        "target_index": "case_{case_id}",
        "query": {
            "query": {
                "bool": {
                    "must": [
                        {"match": {"event.category": "process"}},
                        {"wildcard": {"source_file": "*.ndjson"}}
                    ],
                    "should": [
                        {"wildcard": {"process.command_line": "*vssadmin*delete*shadows*"}},
                        {"wildcard": {"process.command_line": "*wmic*shadowcopy*delete*"}},
                        {"wildcard": {"process.command_line": "*bcdedit*/set*recoveryenabled*No*"}}
                    ],
                    "minimum_should_match": 1
                }
            },
            "size": 10
        }
    },
    
    {
        "id": "024",
        "name": "Mass File Modification (Ransomware Indicator)",
        "description": "Process modifying large numbers of files",
        "mitre_technique": "T1486",
        "mitre_tactic": "Impact",
        "severity": "critical",
        "data_source": "edr",
        "target_index": "case_{case_id}",
        "query": {
            "query": {
                "bool": {
                    "must": [
                        {"match": {"event.category": "file"}},
                        {"wildcard": {"source_file": "*.ndjson"}}
                    ]
                }
            },
            "aggs": {
                "by_process": {
                    "terms": {"field": "process.name.keyword", "size": 30},
                    "aggs": {
                        "file_count": {"value_count": {"field": "file.path"}},
                        "filter_mass": {
                            "bucket_selector": {
                                "buckets_path": {"count": "file_count"},
                                "script": "params.count > 100"
                            }
                        }
                    }
                }
            },
            "size": 0
        }
    },
    
    {
        "id": "025",
        "name": "Bloodhound / SharpHound AD Reconnaissance",
        "description": "Active Directory enumeration tools",
        "mitre_technique": "T1087.002",
        "mitre_tactic": "Discovery",
        "severity": "high",
        "data_source": "edr",
        "target_index": "case_{case_id}",
        "query": {
            "query": {
                "bool": {
                    "must": [
                        {"match": {"event.category": "process"}},
                        {"wildcard": {"source_file": "*.ndjson"}}
                    ],
                    "should": [
                        {"wildcard": {"process.name": "*sharphound*"}},
                        {"wildcard": {"process.name": "*bloodhound*"}},
                        {"wildcard": {"process.command_line": "*Invoke-BloodHound*"}},
                        {"wildcard": {"process.command_line": "*SharpHound.exe*"}}
                    ],
                    "minimum_should_match": 1
                }
            },
            "size": 10
        }
    },
    
    {
        "id": "026",
        "name": "DLL Hijacking / Side-Loading",
        "description": "Legitimate process loading suspicious DLLs",
        "mitre_technique": "T1574.002",
        "mitre_tactic": "Defense Evasion",
        "severity": "medium",
        "data_source": "edr",
        "target_index": "case_{case_id}",
        "query": {
            "query": {
                "bool": {
                    "must": [
                        {"match": {"event.category": "process"}},
                        {"wildcard": {"source_file": "*.ndjson"}},
                        {"exists": {"field": "process.pe.original_file_name"}},
                        {"exists": {"field": "process.name.keyword"}}
                    ]
                }
            },
            "aggs": {
                "renamed_processes": {
                    "scripted_metric": {
                        "init_script": "state.mismatches = []",
                        "map_script": "if (doc['process.name'].value.toLowerCase() != doc['process.pe.original_file_name'].value.toLowerCase()) { state.mismatches.add(doc['process.name'].value) }",
                        "combine_script": "return state.mismatches",
                        "reduce_script": "return params._aggs.stream().flatMap(List::stream).collect(Collectors.toList())"
                    }
                }
            },
            "size": 0
        }
    },
    
    {
        "id": "027",
        "name": "Token Impersonation / Privilege Escalation",
        "description": "Sensitive privileges assigned to user accounts",
        "mitre_technique": "T1134",
        "mitre_tactic": "Privilege Escalation",
        "severity": "high",
        "data_source": "evtx",
        "target_index": "case_{case_id}",
        "query": {
            "query": {
                "bool": {
                    "must": [
                        {"term": {"normalized_event_id": "4672"}},
                        {"wildcard": {"search_blob": "*SeDebugPrivilege*"}}
                    ],
                    "must_not": [
                        {"wildcard": {"search_blob": "*S-1-5-18*"}},
                        {"wildcard": {"search_blob": "*SYSTEM*"}}
                    ]
                }
            },
            "aggs": {
                "by_user": {
                    "terms": {"field": "normalized_username.keyword", "size": 30}
                }
            },
            "size": 0
        }
    },
    
    {
        "id": "028",
        "name": "Browser Credential Theft",
        "description": "Process accessing browser credential storage",
        "mitre_technique": "T1555.003",
        "mitre_tactic": "Credential Access",
        "severity": "high",
        "data_source": "edr",
        "target_index": "case_{case_id}",
        "query": {
            "query": {
                "bool": {
                    "must": [
                        {"match": {"event.category": "process"}},
                        {"wildcard": {"source_file": "*.ndjson"}}
                    ],
                    "should": [
                        {"wildcard": {"process.command_line": "*Login Data*"}},
                        {"wildcard": {"process.command_line": "*logins.json*"}},
                        {"wildcard": {"process.command_line": "*key4.db*"}},
                        {"wildcard": {"process.command_line": "*Cookies*"}}
                    ],
                    "minimum_should_match": 1
                }
            },
            "size": 10
        }
    },
    
    {
        "id": "029",
        "name": "NTDS.dit Extraction (DC Credential Theft)",
        "description": "Attempts to extract Active Directory credentials",
        "mitre_technique": "T1003.003",
        "mitre_tactic": "Credential Access",
        "severity": "critical",
        "data_source": "edr",
        "target_index": "case_{case_id}",
        "query": {
            "query": {
                "bool": {
                    "must": [
                        {"match": {"event.category": "process"}},
                        {"wildcard": {"source_file": "*.ndjson"}}
                    ],
                    "should": [
                        {"wildcard": {"process.command_line": "*ntdsutil*"}},
                        {"wildcard": {"process.command_line": "*ntds.dit*"}},
                        {"bool": {
                            "must": [
                                {"wildcard": {"process.command_line": "*vssadmin*"}},
                                {"wildcard": {"process.command_line": "*NTDS*"}}
                            ]
                        }}
                    ],
                    "minimum_should_match": 1
                }
            },
            "size": 10
        }
    },
    
    {
        "id": "030",
        "name": "Suspicious PowerShell Profile Modification",
        "description": "Modifications to PowerShell profile scripts (persistence)",
        "mitre_technique": "T1546.013",
        "mitre_tactic": "Persistence",
        "severity": "medium",
        "data_source": "edr",
        "target_index": "case_{case_id}",
        "query": {
            "query": {
                "bool": {
                    "must": [
                        {"match": {"event.category": "process"}},
                        {"wildcard": {"source_file": "*.ndjson"}}
                    ],
                    "should": [
                        {"wildcard": {"process.command_line": "*profile.ps1*"}},
                        {"wildcard": {"process.command_line": "*Microsoft.PowerShell_profile*"}},
                        {"wildcard": {"process.command_line": "*$PROFILE*"}}
                    ],
                    "minimum_should_match": 1
                }
            },
            "size": 10
        }
    }
]


def get_pattern_by_id(pattern_id):
    """Get specific pattern by ID"""
    for pattern in DETECTION_PATTERNS:
        if pattern['id'] == pattern_id:
            return pattern
    return None


def get_patterns_by_severity(severity):
    """Get all patterns of specific severity"""
    return [p for p in DETECTION_PATTERNS if p['severity'] == severity]


def get_patterns_by_tier(tier):
    """Get patterns by tier (1, 2, or 3)"""
    pattern_id_map = {int(p['id']): p for p in DETECTION_PATTERNS}
    
    if tier == 1:
        return [pattern_id_map[i] for i in range(1, 11) if i in pattern_id_map]
    elif tier == 2:
        return [pattern_id_map[i] for i in range(11, 21) if i in pattern_id_map]
    elif tier == 3:
        return [pattern_id_map[i] for i in range(21, 31) if i in pattern_id_map]
    
    return DETECTION_PATTERNS

