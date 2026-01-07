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
    },
    
    # ========================================================================
    # TIER 4-8: ADDITIONAL 50 PATTERNS (31-80)
    # Extended coverage for comprehensive threat detection
    # ========================================================================
    
    # EXECUTION TECHNIQUES (31-40)
    
    {
        "id": "031",
        "name": "WMIC Remote Process Execution",
        "description": "WMIC used to execute commands on remote systems",
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
                        {"match": {"process.name.keyword": "wmic.exe"}},
                        {"wildcard": {"source_file": "*.ndjson"}}
                    ],
                    "should": [
                        {"wildcard": {"process.command_line": "*process call create*"}},
                        {"wildcard": {"process.command_line": "*/node:*"}},
                        {"wildcard": {"process.command_line": "*node:*"}}
                    ],
                    "minimum_should_match": 1
                }
            },
            "aggs": {
                "by_user": {
                    "terms": {"field": "process.user.name.keyword", "size": 30}
                }
            },
            "size": 0
        }
    },
    
    {
        "id": "032",
        "name": "Command Line Obfuscation",
        "description": "Heavily obfuscated command lines using carets, quotes, or concatenation",
        "mitre_technique": "T1027",
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
                        {"wildcard": {"process.command_line": "*^*^*^*^*"}},
                        {"wildcard": {"process.command_line": "*[char]*[char]*[char]*"}}
                    ],
                    "minimum_should_match": 1
                }
            },
            "aggs": {
                "by_process": {
                    "terms": {"field": "process.name.keyword", "size": 20}
                }
            },
            "size": 0
        }
    },
    
    {
        "id": "033",
        "name": "Mshta.exe Suspicious Execution",
        "description": "Mshta.exe executing remote scripts or unusual content",
        "mitre_technique": "T1218.005",
        "mitre_tactic": "Defense Evasion",
        "severity": "high",
        "data_source": "edr",
        "target_index": "case_{case_id}",
        "query": {
            "query": {
                "bool": {
                    "must": [
                        {"match": {"event.category": "process"}},
                        {"match": {"process.name.keyword": "mshta.exe"}},
                        {"wildcard": {"source_file": "*.ndjson"}}
                    ],
                    "should": [
                        {"wildcard": {"process.command_line": "*http://*"}},
                        {"wildcard": {"process.command_line": "*https://*"}},
                        {"wildcard": {"process.command_line": "*javascript:*"}},
                        {"wildcard": {"process.command_line": "*vbscript:*"}}
                    ],
                    "minimum_should_match": 1
                }
            },
            "aggs": {
                "by_parent": {
                    "terms": {"field": "process.parent.name.keyword", "size": 20}
                }
            },
            "size": 0
        }
    },
    
    {
        "id": "034",
        "name": "Regsvr32 Suspicious Usage",
        "description": "Regsvr32.exe used to execute malicious scripts (Squiblydoo)",
        "mitre_technique": "T1218.010",
        "mitre_tactic": "Defense Evasion",
        "severity": "high",
        "data_source": "edr",
        "target_index": "case_{case_id}",
        "query": {
            "query": {
                "bool": {
                    "must": [
                        {"match": {"event.category": "process"}},
                        {"match": {"process.name.keyword": "regsvr32.exe"}},
                        {"wildcard": {"source_file": "*.ndjson"}}
                    ],
                    "should": [
                        {"wildcard": {"process.command_line": "*/i:http*"}},
                        {"wildcard": {"process.command_line": "*scrobj.dll*"}},
                        {"bool": {
                            "must": [
                                {"wildcard": {"process.command_line": "*/s*"}},
                                {"wildcard": {"process.command_line": "*/u*"}}
                            ]
                        }}
                    ],
                    "minimum_should_match": 1
                }
            },
            "aggs": {
                "by_command": {
                    "terms": {"field": "process.command_line.keyword", "size": 30}
                }
            },
            "size": 0
        }
    },
    
    {
        "id": "035",
        "name": "Rundll32 Suspicious DLL Loading",
        "description": "Rundll32.exe loading DLLs from unusual locations",
        "mitre_technique": "T1218.011",
        "mitre_tactic": "Defense Evasion",
        "severity": "medium",
        "data_source": "edr",
        "target_index": "case_{case_id}",
        "query": {
            "query": {
                "bool": {
                    "must": [
                        {"match": {"event.category": "process"}},
                        {"match": {"process.name.keyword": "rundll32.exe"}},
                        {"wildcard": {"source_file": "*.ndjson"}}
                    ],
                    "should": [
                        {"wildcard": {"process.command_line": "*\\\\Temp\\\\*"}},
                        {"wildcard": {"process.command_line": "*\\\\AppData\\\\*"}},
                        {"wildcard": {"process.command_line": "*\\\\Users\\\\Public\\\\*"}},
                        {"wildcard": {"process.command_line": "*http://*"}},
                        {"wildcard": {"process.command_line": "*https://*"}}
                    ],
                    "minimum_should_match": 1
                }
            },
            "aggs": {
                "by_dll_path": {
                    "terms": {"field": "process.command_line.keyword", "size": 30}
                }
            },
            "size": 0
        }
    },
    
    {
        "id": "036",
        "name": "InstallUtil.exe Code Execution",
        "description": "InstallUtil.exe used to execute code (LOLBAS)",
        "mitre_technique": "T1218.004",
        "mitre_tactic": "Defense Evasion",
        "severity": "medium",
        "data_source": "edr",
        "target_index": "case_{case_id}",
        "query": {
            "query": {
                "bool": {
                    "must": [
                        {"match": {"event.category": "process"}},
                        {"match": {"process.name.keyword": "installutil.exe"}},
                        {"wildcard": {"source_file": "*.ndjson"}}
                    ],
                    "should": [
                        {"wildcard": {"process.command_line": "*/u*"}},
                        {"wildcard": {"process.command_line": "*\\\\Temp\\\\*"}},
                        {"wildcard": {"process.command_line": "*\\\\AppData\\\\*"}}
                    ],
                    "minimum_should_match": 1
                }
            },
            "aggs": {
                "by_assembly": {
                    "terms": {"field": "process.command_line.keyword", "size": 20}
                }
            },
            "size": 0
        }
    },
    
    {
        "id": "037",
        "name": "MSBuild.exe Suspicious Execution",
        "description": "MSBuild.exe executing malicious project files",
        "mitre_technique": "T1127.001",
        "mitre_tactic": "Defense Evasion",
        "severity": "medium",
        "data_source": "edr",
        "target_index": "case_{case_id}",
        "query": {
            "query": {
                "bool": {
                    "must": [
                        {"match": {"event.category": "process"}},
                        {"match": {"process.name.keyword": "msbuild.exe"}},
                        {"wildcard": {"source_file": "*.ndjson"}}
                    ],
                    "should": [
                        {"wildcard": {"process.command_line": "*\\\\Temp\\\\*"}},
                        {"wildcard": {"process.command_line": "*\\\\AppData\\\\*"}},
                        {"wildcard": {"process.command_line": "*.xml*"}}
                    ],
                    "minimum_should_match": 1,
                    "must_not": [
                        {"wildcard": {"process.command_line": "*Program Files*"}},
                        {"wildcard": {"process.command_line": "*Visual Studio*"}}
                    ]
                }
            },
            "aggs": {
                "by_project": {
                    "terms": {"field": "process.command_line.keyword", "size": 20}
                }
            },
            "size": 0
        }
    },
    
    {
        "id": "038",
        "name": "CMSTP.exe UAC Bypass",
        "description": "CMSTP.exe used to bypass UAC",
        "mitre_technique": "T1218.003",
        "mitre_tactic": "Defense Evasion",
        "severity": "high",
        "data_source": "edr",
        "target_index": "case_{case_id}",
        "query": {
            "query": {
                "bool": {
                    "must": [
                        {"match": {"event.category": "process"}},
                        {"match": {"process.name.keyword": "cmstp.exe"}},
                        {"wildcard": {"source_file": "*.ndjson"}}
                    ],
                    "should": [
                        {"wildcard": {"process.command_line": "*/s*"}},
                        {"wildcard": {"process.command_line": "*.inf*"}}
                    ],
                    "minimum_should_match": 1
                }
            },
            "aggs": {
                "by_inf_file": {
                    "terms": {"field": "process.command_line.keyword", "size": 20}
                }
            },
            "size": 0
        }
    },
    
    {
        "id": "039",
        "name": "Certutil Download and Decode",
        "description": "Certutil.exe abused to download files or decode malware",
        "mitre_technique": "T1105",
        "mitre_tactic": "Command and Control",
        "severity": "high",
        "data_source": "edr",
        "target_index": "case_{case_id}",
        "query": {
            "query": {
                "bool": {
                    "must": [
                        {"match": {"event.category": "process"}},
                        {"match": {"process.name.keyword": "certutil.exe"}},
                        {"wildcard": {"source_file": "*.ndjson"}}
                    ],
                    "should": [
                        {"wildcard": {"process.command_line": "*-urlcache*"}},
                        {"wildcard": {"process.command_line": "*-decode*"}},
                        {"wildcard": {"process.command_line": "*-split*"}},
                        {"wildcard": {"process.command_line": "*http://*"}},
                        {"wildcard": {"process.command_line": "*https://*"}}
                    ],
                    "minimum_should_match": 1
                }
            },
            "aggs": {
                "by_url": {
                    "terms": {"field": "process.command_line.keyword", "size": 30}
                }
            },
            "size": 0
        }
    },
    
    {
        "id": "040",
        "name": "BITSAdmin Download",
        "description": "BITSAdmin used to download files",
        "mitre_technique": "T1105",
        "mitre_tactic": "Command and Control",
        "severity": "high",
        "data_source": "edr",
        "target_index": "case_{case_id}",
        "query": {
            "query": {
                "bool": {
                    "must": [
                        {"match": {"event.category": "process"}},
                        {"match": {"process.name.keyword": "bitsadmin.exe"}},
                        {"wildcard": {"source_file": "*.ndjson"}}
                    ],
                    "should": [
                        {"wildcard": {"process.command_line": "*/transfer*"}},
                        {"wildcard": {"process.command_line": "*/download*"}},
                        {"wildcard": {"process.command_line": "*http://*"}},
                        {"wildcard": {"process.command_line": "*https://*"}}
                    ],
                    "minimum_should_match": 1
                }
            },
            "aggs": {
                "by_transfer": {
                    "terms": {"field": "process.command_line.keyword", "size": 30}
                }
            },
            "size": 0
        }
    },
    
    # CREDENTIAL ACCESS (41-50)
    
    {
        "id": "041",
        "name": "DCSync Attack",
        "description": "Domain Controller replication abuse to extract credentials",
        "mitre_technique": "T1003.006",
        "mitre_tactic": "Credential Access",
        "severity": "critical",
        "data_source": "edr",
        "target_index": "case_{case_id}",
        "query": {
            "query": {
                "bool": {
                    "must": [
                        {"wildcard": {"source_file": "*.ndjson"}}
                    ],
                    "should": [
                        {"wildcard": {"process.command_line": "*lsadump::dcsync*"}},
                        {"wildcard": {"process.command_line": "*Get-ADReplAccount*"}},
                        {"bool": {
                            "must": [
                                {"match": {"process.name.keyword": "repadmin.exe"}},
                                {"wildcard": {"process.command_line": "*/syncall*"}}
                            ]
                        }}
                    ],
                    "minimum_should_match": 1
                }
            },
            "aggs": {
                "by_user": {
                    "terms": {"field": "process.user.name.keyword", "size": 20}
                }
            },
            "size": 10
        }
    },
    
    {
        "id": "042",
        "name": "SAM Registry Hive Access",
        "description": "Attempts to access SAM registry hive",
        "mitre_technique": "T1003.002",
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
                        {"wildcard": {"process.command_line": "*reg*save*HKLM\\\\SAM*"}},
                        {"wildcard": {"process.command_line": "*reg*save*HKLM\\\\SYSTEM*"}},
                        {"wildcard": {"process.command_line": "*copy*\\\\Windows\\\\System32\\\\config\\\\SAM*"}},
                        {"wildcard": {"process.command_line": "*\\\\GLOBALROOT\\\\Device\\\\*\\\\config\\\\SAM*"}}
                    ],
                    "minimum_should_match": 1
                }
            },
            "aggs": {
                "by_method": {
                    "terms": {"field": "process.name.keyword", "size": 20}
                }
            },
            "size": 10
        }
    },
    
    {
        "id": "043",
        "name": "LaZagne Password Stealer",
        "description": "LaZagne credential theft tool execution",
        "mitre_technique": "T1555",
        "mitre_tactic": "Credential Access",
        "severity": "critical",
        "data_source": "edr",
        "target_index": "case_{case_id}",
        "query": {
            "query": {
                "bool": {
                    "must": [
                        {"wildcard": {"source_file": "*.ndjson"}}
                    ],
                    "should": [
                        {"wildcard": {"process.name": "*lazagne*"}},
                        {"wildcard": {"process.command_line": "*lazagne*all*"}},
                        {"wildcard": {"process.command_line": "*LaZagne.py*"}}
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
    
    {
        "id": "044",
        "name": "Password Filter DLL Installation",
        "description": "Malicious password filter DLL for credential harvesting",
        "mitre_technique": "T1556.002",
        "mitre_tactic": "Credential Access",
        "severity": "critical",
        "data_source": "edr",
        "target_index": "case_{case_id}",
        "query": {
            "query": {
                "bool": {
                    "must": [
                        {"wildcard": {"source_file": "*.ndjson"}}
                    ],
                    "should": [
                        {"wildcard": {"process.command_line": "*Lsa\\\\Notification Packages*"}},
                        {"bool": {
                            "must": [
                                {"wildcard": {"process.command_line": "*copy*System32*.dll*"}},
                                {"wildcard": {"process.command_line": "*password*"}}
                            ]
                        }}
                    ],
                    "minimum_should_match": 1
                }
            },
            "aggs": {
                "by_dll": {
                    "terms": {"field": "process.command_line.keyword", "size": 20}
                }
            },
            "size": 10
        }
    },
    
    {
        "id": "045",
        "name": "WiFi Credential Extraction",
        "description": "Extraction of stored WiFi passwords",
        "mitre_technique": "T1555.001",
        "mitre_tactic": "Credential Access",
        "severity": "low",
        "data_source": "edr",
        "target_index": "case_{case_id}",
        "query": {
            "query": {
                "bool": {
                    "must": [
                        {"match": {"process.name.keyword": "netsh.exe"}},
                        {"wildcard": {"source_file": "*.ndjson"}}
                    ],
                    "should": [
                        {"wildcard": {"process.command_line": "*wlan*show*profile*key=clear*"}},
                        {"wildcard": {"process.command_line": "*wlan*export*profile*"}}
                    ],
                    "minimum_should_match": 1
                }
            },
            "aggs": {
                "by_user": {
                    "terms": {"field": "process.user.name.keyword", "size": 20}
                }
            },
            "size": 0
        }
    },
    
    {
        "id": "046",
        "name": "Credential Manager Access",
        "description": "Access to Windows Credential Manager",
        "mitre_technique": "T1555.004",
        "mitre_tactic": "Credential Access",
        "severity": "medium",
        "data_source": "edr",
        "target_index": "case_{case_id}",
        "query": {
            "query": {
                "bool": {
                    "must": [
                        {"wildcard": {"source_file": "*.ndjson"}}
                    ],
                    "should": [
                        {"wildcard": {"process.command_line": "*cmdkey*/list*"}},
                        {"wildcard": {"process.command_line": "*PasswordVault*"}},
                        {"match": {"process.name.keyword": "vaultcmd.exe"}}
                    ],
                    "minimum_should_match": 1
                }
            },
            "aggs": {
                "by_method": {
                    "terms": {"field": "process.name.keyword", "size": 20}
                }
            },
            "size": 0
        }
    },
    
    {
        "id": "047",
        "name": "Group Policy Preferences Password",
        "description": "Extraction of passwords from GPP",
        "mitre_technique": "T1552.006",
        "mitre_tactic": "Credential Access",
        "severity": "high",
        "data_source": "edr",
        "target_index": "case_{case_id}",
        "query": {
            "query": {
                "bool": {
                    "must": [
                        {"wildcard": {"source_file": "*.ndjson"}}
                    ],
                    "should": [
                        {"wildcard": {"process.command_line": "*Get-GPPPassword*"}},
                        {"wildcard": {"process.command_line": "*findstr*cpassword*"}},
                        {"wildcard": {"process.command_line": "*Groups.xml*"}},
                        {"wildcard": {"process.command_line": "*\\\\SYSVOL\\\\*Groups.xml*"}}
                    ],
                    "minimum_should_match": 1
                }
            },
            "aggs": {
                "by_technique": {
                    "terms": {"field": "process.command_line.keyword", "size": 20}
                }
            },
            "size": 0
        }
    },
    
    {
        "id": "048",
        "name": "Clipboard Credential Theft",
        "description": "Tools monitoring clipboard for credentials",
        "mitre_technique": "T1115",
        "mitre_tactic": "Collection",
        "severity": "medium",
        "data_source": "edr",
        "target_index": "case_{case_id}",
        "query": {
            "query": {
                "bool": {
                    "must": [
                        {"wildcard": {"source_file": "*.ndjson"}}
                    ],
                    "should": [
                        {"wildcard": {"process.command_line": "*Get-Clipboard*"}},
                        {"wildcard": {"process.command_line": "*System.Windows.Forms.Clipboard*"}},
                        {"match": {"process.name": "clipboardlogger.exe"}}
                    ],
                    "minimum_should_match": 1
                }
            },
            "aggs": {
                "by_technique": {
                    "terms": {"field": "process.name.keyword", "size": 20}
                }
            },
            "size": 0
        }
    },
    
    {
        "id": "049",
        "name": "Cached Credential Access",
        "description": "Tools accessing cached domain credentials",
        "mitre_technique": "T1003.005",
        "mitre_tactic": "Credential Access",
        "severity": "high",
        "data_source": "edr",
        "target_index": "case_{case_id}",
        "query": {
            "query": {
                "bool": {
                    "must": [
                        {"wildcard": {"source_file": "*.ndjson"}}
                    ],
                    "should": [
                        {"match": {"process.name": "cachedump.exe"}},
                        {"wildcard": {"process.command_line": "*HKLM\\\\SECURITY\\\\Cache*"}},
                        {"wildcard": {"process.command_line": "*lsadump::cache*"}}
                    ],
                    "minimum_should_match": 1
                }
            },
            "aggs": {
                "by_tool": {
                    "terms": {"field": "process.name.keyword", "size": 20}
                }
            },
            "size": 0
        }
    },
    
    {
        "id": "050",
        "name": "NTDS.dit Extraction via ntdsutil",
        "description": "Active Directory database extraction",
        "mitre_technique": "T1003.003",
        "mitre_tactic": "Credential Access",
        "severity": "critical",
        "data_source": "edr",
        "target_index": "case_{case_id}",
        "query": {
            "query": {
                "bool": {
                    "must": [
                        {"wildcard": {"source_file": "*.ndjson"}}
                    ],
                    "should": [
                        {"wildcard": {"process.command_line": "*ntdsutil*create full*"}},
                        {"wildcard": {"process.command_line": "*ntdsutil*IFM*"}},
                        {"wildcard": {"process.command_line": "*copy*ntds.dit*"}},
                        {"bool": {
                            "must": [
                                {"match": {"process.name.keyword": "diskshadow.exe"}},
                                {"wildcard": {"process.command_line": "*ntds*"}}
                            ]
                        }}
                    ],
                    "minimum_should_match": 1
                }
            },
            "aggs": {
                "by_host": {
                    "terms": {"field": "host.name.keyword", "size": 10}
                }
            },
            "size": 10
        }
    },
    
    # LATERAL MOVEMENT (51-60)
    
    {
        "id": "051",
        "name": "Remote Desktop Login Frequency Spike",
        "description": "Unusual spike in RDP connections",
        "mitre_technique": "T1021.001",
        "mitre_tactic": "Lateral Movement",
        "severity": "medium",
        "data_source": "evtx",
        "target_index": "case_{case_id}",
        "query": {
            "query": {
                "bool": {
                    "must": [
                        {"term": {"normalized_event_id": "4624"}},
                        {"wildcard": {"search_blob": "*LogonType*10*"}},
                        {"wildcard": {"source_file": "*.evtx"}}
                    ]
                }
            },
            "aggs": {
                "by_user": {
                    "terms": {"field": "normalized_username.keyword", "size": 30},
                    "aggs": {
                        "target_systems": {
                            "terms": {"field": "normalized_computer.keyword", "size": 50}
                        }
                    }
                }
            },
            "size": 0
        }
    },
    
    {
        "id": "052",
        "name": "Windows Admin Shares Enumeration",
        "description": "Enumeration of admin shares (C$, ADMIN$)",
        "mitre_technique": "T1021.002",
        "mitre_tactic": "Lateral Movement",
        "severity": "medium",
        "data_source": "evtx",
        "target_index": "case_{case_id}",
        "query": {
            "query": {
                "bool": {
                    "must": [
                        {"terms": {"normalized_event_id": ["5140", "5145"]}},
                        {"wildcard": {"source_file": "*.evtx"}}
                    ],
                    "should": [
                        {"match": {"search_blob": "ADMIN$"}},
                        {"match": {"search_blob": "C$"}},
                        {"match": {"search_blob": "IPC$"}}
                    ],
                    "minimum_should_match": 1
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
        "id": "053",
        "name": "PowerShell Remoting (PSRemoting)",
        "description": "PowerShell remoting for lateral movement",
        "mitre_technique": "T1021.006",
        "mitre_tactic": "Lateral Movement",
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
                        {"wildcard": {"process.command_line": "*Enter-PSSession*"}},
                        {"wildcard": {"process.command_line": "*Invoke-Command*-ComputerName*"}},
                        {"bool": {
                            "must": [
                                {"match": {"process.parent.name.keyword": "wsmprovhost.exe"}},
                                {"match": {"process.name.keyword": "powershell.exe"}}
                            ]
                        }}
                    ],
                    "minimum_should_match": 1
                }
            },
            "aggs": {
                "by_user": {
                    "terms": {"field": "process.user.name.keyword", "size": 30}
                }
            },
            "size": 0
        }
    },
    
    {
        "id": "054",
        "name": "Remote Service Creation",
        "description": "Services created remotely via sc.exe",
        "mitre_technique": "T1021.002",
        "mitre_tactic": "Lateral Movement",
        "severity": "high",
        "data_source": "edr",
        "target_index": "case_{case_id}",
        "query": {
            "query": {
                "bool": {
                    "must": [
                        {"match": {"process.name.keyword": "sc.exe"}},
                        {"wildcard": {"process.command_line": "*create*"}},
                        {"wildcard": {"source_file": "*.ndjson"}}
                    ],
                    "should": [
                        {"wildcard": {"process.command_line": "*/s*"}},
                        {"wildcard": {"process.command_line": "*\\\\\\\\*"}}
                    ],
                    "minimum_should_match": 1
                }
            },
            "aggs": {
                "by_target": {
                    "terms": {"field": "process.command_line.keyword", "size": 30}
                }
            },
            "size": 0
        }
    },
    
    {
        "id": "055",
        "name": "SMB Beacon (Cobalt Strike)",
        "description": "Named pipe patterns indicating Cobalt Strike",
        "mitre_technique": "T1071.002",
        "mitre_tactic": "Command and Control",
        "severity": "critical",
        "data_source": "edr",
        "target_index": "case_{case_id}",
        "query": {
            "query": {
                "bool": {
                    "must": [
                        {"wildcard": {"source_file": "*.ndjson"}}
                    ],
                    "should": [
                        {"wildcard": {"process.command_line": "*\\\\pipe\\\\MSSE-*"}},
                        {"wildcard": {"process.command_line": "*\\\\pipe\\\\status_*"}},
                        {"wildcard": {"process.command_line": "*\\\\pipe\\\\postex_*"}},
                        {"wildcard": {"process.command_line": "*\\\\pipe\\\\msagent_*"}}
                    ],
                    "minimum_should_match": 1
                }
            },
            "aggs": {
                "by_pipe": {
                    "terms": {"field": "process.command_line.keyword", "size": 20}
                }
            },
            "size": 10
        }
    },
    
    {
        "id": "056",
        "name": "Pass-the-Ticket Attack",
        "description": "Kerberos ticket manipulation (Golden/Silver Ticket)",
        "mitre_technique": "T1550.003",
        "mitre_tactic": "Lateral Movement",
        "severity": "critical",
        "data_source": "edr",
        "target_index": "case_{case_id}",
        "query": {
            "query": {
                "bool": {
                    "must": [
                        {"wildcard": {"source_file": "*.ndjson"}}
                    ],
                    "should": [
                        {"wildcard": {"process.command_line": "*kerberos::golden*"}},
                        {"wildcard": {"process.command_line": "*kerberos::ptt*"}},
                        {"wildcard": {"process.command_line": "*Rubeus*ptt*"}},
                        {"wildcard": {"process.command_line": "*Rubeus*golden*"}},
                        {"wildcard": {"process.command_line": "*ticketer.py*"}}
                    ],
                    "minimum_should_match": 1
                }
            },
            "aggs": {
                "by_tool": {
                    "terms": {"field": "process.name.keyword", "size": 20}
                }
            },
            "size": 10
        }
    },
    
    {
        "id": "057",
        "name": "Remote Task Scheduling",
        "description": "Scheduled tasks created remotely",
        "mitre_technique": "T1053.005",
        "mitre_tactic": "Lateral Movement",
        "severity": "high",
        "data_source": "edr",
        "target_index": "case_{case_id}",
        "query": {
            "query": {
                "bool": {
                    "must": [
                        {"match": {"process.name.keyword": "schtasks.exe"}},
                        {"wildcard": {"process.command_line": "*/create*"}},
                        {"wildcard": {"source_file": "*.ndjson"}}
                    ],
                    "should": [
                        {"wildcard": {"process.command_line": "*/s*"}},
                        {"wildcard": {"process.command_line": "*\\\\\\\\*"}}
                    ],
                    "minimum_should_match": 1
                }
            },
            "aggs": {
                "by_target": {
                    "terms": {"field": "process.command_line.keyword", "size": 30}
                }
            },
            "size": 0
        }
    },
    
    {
        "id": "058",
        "name": "SSH Lateral Movement",
        "description": "SSH used for lateral movement on Windows",
        "mitre_technique": "T1021.004",
        "mitre_tactic": "Lateral Movement",
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
                        {"match": {"process.name.keyword": "ssh.exe"}},
                        {"match": {"process.name.keyword": "plink.exe"}},
                        {"wildcard": {"process.command_line": "*New-SSHSession*"}}
                    ],
                    "minimum_should_match": 1
                }
            },
            "aggs": {
                "by_destination": {
                    "terms": {"field": "process.command_line.keyword", "size": 30}
                }
            },
            "size": 0
        }
    },
    
    {
        "id": "059",
        "name": "DCOM Lateral Movement",
        "description": "DCOM used for lateral movement",
        "mitre_technique": "T1021.003",
        "mitre_tactic": "Lateral Movement",
        "severity": "high",
        "data_source": "edr",
        "target_index": "case_{case_id}",
        "query": {
            "query": {
                "bool": {
                    "must": [
                        {"wildcard": {"source_file": "*.ndjson"}}
                    ],
                    "should": [
                        {"wildcard": {"process.command_line": "*MMC20.Application*"}},
                        {"wildcard": {"process.command_line": "*ShellWindows*"}},
                        {"wildcard": {"process.command_line": "*ShellBrowserWindow*"}}
                    ],
                    "minimum_should_match": 1
                }
            },
            "aggs": {
                "by_dcom_object": {
                    "terms": {"field": "process.command_line.keyword", "size": 20}
                }
            },
            "size": 0
        }
    },
    
    {
        "id": "060",
        "name": "RDP Tunneling",
        "description": "RDP tunneled through SSH or other protocols",
        "mitre_technique": "T1090.001",
        "mitre_tactic": "Command and Control",
        "severity": "medium",
        "data_source": "edr",
        "target_index": "case_{case_id}",
        "query": {
            "query": {
                "bool": {
                    "must": [
                        {"wildcard": {"source_file": "*.ndjson"}}
                    ],
                    "should": [
                        {"wildcard": {"process.command_line": "*ssh*-L*3389*"}},
                        {"wildcard": {"process.command_line": "*plink*-L*3389*"}},
                        {"wildcard": {"process.command_line": "*chisel*3389*"}},
                        {"wildcard": {"process.command_line": "*ngrok*tcp*3389*"}}
                    ],
                    "minimum_should_match": 1
                }
            },
            "aggs": {
                "by_tunnel_method": {
                    "terms": {"field": "process.name.keyword", "size": 20}
                }
            },
            "size": 0
        }
    },
    
    # PERSISTENCE (61-70)
    
    {
        "id": "061",
        "name": "Startup Folder Persistence",
        "description": "Files added to Startup folder",
        "mitre_technique": "T1547.001",
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
                        {"wildcard": {"process.command_line": "*\\\\Startup\\\\*"}},
                        {"wildcard": {"process.command_line": "*Start Menu\\\\Programs\\\\Startup*"}}
                    ],
                    "filter": [
                        {
                            "bool": {
                                "should": [
                                    {"wildcard": {"process.command_line": "*copy*"}},
                                    {"wildcard": {"process.command_line": "*move*"}},
                                    {"wildcard": {"process.command_line": "*Out-File*"}}
                                ],
                                "minimum_should_match": 1
                            }
                        }
                    ],
                    "minimum_should_match": 1
                }
            },
            "aggs": {
                "by_file": {
                    "terms": {"field": "process.command_line.keyword", "size": 30}
                }
            },
            "size": 0
        }
    },
    
    {
        "id": "062",
        "name": "WMI Event Subscription Persistence",
        "description": "WMI event subscriptions for stealthy persistence",
        "mitre_technique": "T1546.003",
        "mitre_tactic": "Persistence",
        "severity": "high",
        "data_source": "edr",
        "target_index": "case_{case_id}",
        "query": {
            "query": {
                "bool": {
                    "must": [
                        {"wildcard": {"source_file": "*.ndjson"}}
                    ],
                    "should": [
                        {"wildcard": {"process.command_line": "*Register-WmiEvent*"}},
                        {"wildcard": {"process.command_line": "*__EventFilter*"}},
                        {"wildcard": {"process.command_line": "*__EventConsumer*"}},
                        {"bool": {
                            "must": [
                                {"match": {"process.name.keyword": "mofcomp.exe"}},
                                {"wildcard": {"process.command_line": "*.mof*"}}
                            ]
                        }}
                    ],
                    "minimum_should_match": 1
                }
            },
            "aggs": {
                "by_technique": {
                    "terms": {"field": "process.name.keyword", "size": 20}
                }
            },
            "size": 0
        }
    },
    
    {
        "id": "063",
        "name": "Accessibility Features Backdoor",
        "description": "Replacement of accessibility binaries for backdoor",
        "mitre_technique": "T1546.008",
        "mitre_tactic": "Persistence",
        "severity": "critical",
        "data_source": "edr",
        "target_index": "case_{case_id}",
        "query": {
            "query": {
                "bool": {
                    "must": [
                        {"wildcard": {"source_file": "*.ndjson"}}
                    ],
                    "should": [
                        {"bool": {
                            "must": [
                                {"wildcard": {"process.command_line": "*copy*cmd.exe*"}},
                                {"bool": {
                                    "should": [
                                        {"wildcard": {"process.command_line": "*sethc.exe*"}},
                                        {"wildcard": {"process.command_line": "*utilman.exe*"}},
                                        {"wildcard": {"process.command_line": "*osk.exe*"}}
                                    ],
                                    "minimum_should_match": 1
                                }}
                            ]
                        }},
                        {"wildcard": {"process.command_line": "*Image File Execution Options\\\\sethc.exe*"}}
                    ],
                    "minimum_should_match": 1
                }
            },
            "aggs": {
                "by_target": {
                    "terms": {"field": "process.command_line.keyword", "size": 20}
                }
            },
            "size": 10
        }
    },
    
    {
        "id": "064",
        "name": "AppInit DLLs Persistence",
        "description": "AppInit_DLLs registry modification",
        "mitre_technique": "T1546.010",
        "mitre_tactic": "Persistence",
        "severity": "high",
        "data_source": "edr",
        "target_index": "case_{case_id}",
        "query": {
            "query": {
                "bool": {
                    "must": [
                        {"wildcard": {"process.command_line": "*AppInit_DLLs*"}},
                        {"wildcard": {"source_file": "*.ndjson"}}
                    ],
                    "should": [
                        {"wildcard": {"process.command_line": "*reg*add*"}},
                        {"wildcard": {"process.command_line": "*Set-ItemProperty*"}}
                    ],
                    "minimum_should_match": 1
                }
            },
            "aggs": {
                "by_dll": {
                    "terms": {"field": "process.command_line.keyword", "size": 20}
                }
            },
            "size": 0
        }
    },
    
    {
        "id": "065",
        "name": "Screensaver Persistence",
        "description": "Screensaver modification for persistence",
        "mitre_technique": "T1546.002",
        "mitre_tactic": "Persistence",
        "severity": "medium",
        "data_source": "edr",
        "target_index": "case_{case_id}",
        "query": {
            "query": {
                "bool": {
                    "must": [
                        {"wildcard": {"process.command_line": "*SCRNSAVE.EXE*"}},
                        {"wildcard": {"source_file": "*.ndjson"}}
                    ]
                }
            },
            "aggs": {
                "by_screensaver": {
                    "terms": {"field": "process.command_line.keyword", "size": 20}
                }
            },
            "size": 0
        }
    },
    
    {
        "id": "066",
        "name": "Print Monitors Persistence",
        "description": "Print monitor DLL registration",
        "mitre_technique": "T1547.010",
        "mitre_tactic": "Persistence",
        "severity": "high",
        "data_source": "edr",
        "target_index": "case_{case_id}",
        "query": {
            "query": {
                "bool": {
                    "must": [
                        {"wildcard": {"process.command_line": "*Print\\\\Monitors\\\\*"}},
                        {"wildcard": {"source_file": "*.ndjson"}}
                    ],
                    "should": [
                        {"wildcard": {"process.command_line": "*reg*add*"}},
                        {"wildcard": {"process.command_line": "*Set-ItemProperty*"}}
                    ],
                    "minimum_should_match": 1
                }
            },
            "aggs": {
                "by_monitor": {
                    "terms": {"field": "process.command_line.keyword", "size": 20}
                }
            },
            "size": 0
        }
    },
    
    {
        "id": "067",
        "name": "Time Provider Persistence",
        "description": "W32Time time provider DLL persistence",
        "mitre_technique": "T1547.003",
        "mitre_tactic": "Persistence",
        "severity": "high",
        "data_source": "edr",
        "target_index": "case_{case_id}",
        "query": {
            "query": {
                "bool": {
                    "must": [
                        {"wildcard": {"process.command_line": "*W32Time\\\\TimeProviders\\\\*"}},
                        {"wildcard": {"source_file": "*.ndjson"}}
                    ],
                    "should": [
                        {"wildcard": {"process.command_line": "*DllName*"}},
                        {"wildcard": {"process.command_line": "*reg*add*"}}
                    ],
                    "minimum_should_match": 1
                }
            },
            "aggs": {
                "by_provider": {
                    "terms": {"field": "process.command_line.keyword", "size": 20}
                }
            },
            "size": 0
        }
    },
    
    {
        "id": "068",
        "name": "Netsh Helper DLL Persistence",
        "description": "Netsh helper DLL registration",
        "mitre_technique": "T1546.007",
        "mitre_tactic": "Persistence",
        "severity": "high",
        "data_source": "edr",
        "target_index": "case_{case_id}",
        "query": {
            "query": {
                "bool": {
                    "must": [
                        {"match": {"process.name.keyword": "netsh.exe"}},
                        {"wildcard": {"source_file": "*.ndjson"}}
                    ],
                    "should": [
                        {"wildcard": {"process.command_line": "*add*helper*"}},
                        {"wildcard": {"process.command_line": "*.dll*"}}
                    ],
                    "minimum_should_match": 1
                }
            },
            "aggs": {
                "by_dll": {
                    "terms": {"field": "process.command_line.keyword", "size": 20}
                }
            },
            "size": 0
        }
    },
    
    {
        "id": "069",
        "name": "COM Hijacking Persistence",
        "description": "COM object hijacking for persistence",
        "mitre_technique": "T1546.015",
        "mitre_tactic": "Persistence",
        "severity": "medium",
        "data_source": "edr",
        "target_index": "case_{case_id}",
        "query": {
            "query": {
                "bool": {
                    "must": [
                        {"wildcard": {"process.command_line": "*CLSID\\\\*"}},
                        {"wildcard": {"source_file": "*.ndjson"}}
                    ],
                    "should": [
                        {"wildcard": {"process.command_line": "*InprocServer32*"}},
                        {"wildcard": {"process.command_line": "*LocalServer32*"}}
                    ],
                    "minimum_should_match": 1
                }
            },
            "aggs": {
                "by_clsid": {
                    "terms": {"field": "process.command_line.keyword", "size": 30}
                }
            },
            "size": 0
        }
    },
    
    {
        "id": "070",
        "name": "Browser Extension Persistence",
        "description": "Browser extension installation for persistence",
        "mitre_technique": "T1176",
        "mitre_tactic": "Persistence",
        "severity": "medium",
        "data_source": "edr",
        "target_index": "case_{case_id}",
        "query": {
            "query": {
                "bool": {
                    "must": [
                        {"wildcard": {"source_file": "*.ndjson"}}
                    ],
                    "should": [
                        {"wildcard": {"process.command_line": "*\\\\Extensions\\\\*"}},
                        {"wildcard": {"process.command_line": "*ExtensionInstallForcelist*"}}
                    ],
                    "filter": [
                        {
                            "bool": {
                                "should": [
                                    {"wildcard": {"process.command_line": "*copy*"}},
                                    {"wildcard": {"process.command_line": "*reg*add*"}}
                                ],
                                "minimum_should_match": 1
                            }
                        }
                    ],
                    "minimum_should_match": 1
                }
            },
            "aggs": {
                "by_browser": {
                    "terms": {"field": "process.command_line.keyword", "size": 30}
                }
            },
            "size": 0
        }
    },
    
    # DEFENSE EVASION (71-80)
    
    {
        "id": "071",
        "name": "Windows Defender Exclusion Added",
        "description": "Exclusions added to Windows Defender",
        "mitre_technique": "T1562.001",
        "mitre_tactic": "Defense Evasion",
        "severity": "high",
        "data_source": "edr",
        "target_index": "case_{case_id}",
        "query": {
            "query": {
                "bool": {
                    "must": [
                        {"wildcard": {"source_file": "*.ndjson"}}
                    ],
                    "should": [
                        {"wildcard": {"process.command_line": "*Add-MpPreference*"}},
                        {"wildcard": {"process.command_line": "*Set-MpPreference*-ExclusionPath*"}},
                        {"wildcard": {"process.command_line": "*Set-MpPreference*-ExclusionProcess*"}},
                        {"wildcard": {"process.command_line": "*sc*config*WinDefend*start=disabled*"}}
                    ],
                    "minimum_should_match": 1
                }
            },
            "aggs": {
                "by_exclusion_type": {
                    "terms": {"field": "process.command_line.keyword", "size": 30}
                }
            },
            "size": 0
        }
    },
    
    {
        "id": "072",
        "name": "Timestomping",
        "description": "File timestamp modification to evade detection",
        "mitre_technique": "T1070.006",
        "mitre_tactic": "Defense Evasion",
        "severity": "medium",
        "data_source": "edr",
        "target_index": "case_{case_id}",
        "query": {
            "query": {
                "bool": {
                    "must": [
                        {"wildcard": {"source_file": "*.ndjson"}}
                    ],
                    "should": [
                        {"wildcard": {"process.command_line": "*CreationTime*"}},
                        {"wildcard": {"process.command_line": "*LastWriteTime*"}},
                        {"wildcard": {"process.command_line": "*LastAccessTime*"}},
                        {"match": {"process.name": "timestomp.exe"}}
                    ],
                    "minimum_should_match": 1
                }
            },
            "aggs": {
                "by_tool": {
                    "terms": {"field": "process.name.keyword", "size": 20}
                }
            },
            "size": 0
        }
    },
    
    {
        "id": "073",
        "name": "Secure File Deletion",
        "description": "Secure file deletion tools to prevent recovery",
        "mitre_technique": "T1070.004",
        "mitre_tactic": "Defense Evasion",
        "severity": "medium",
        "data_source": "edr",
        "target_index": "case_{case_id}",
        "query": {
            "query": {
                "bool": {
                    "must": [
                        {"wildcard": {"source_file": "*.ndjson"}}
                    ],
                    "should": [
                        {"match": {"process.name": "sdelete.exe"}},
                        {"match": {"process.name": "sdelete64.exe"}},
                        {"wildcard": {"process.command_line": "*cipher*/w*"}},
                        {"wildcard": {"process.command_line": "*Clear-RecycleBin*-Force*"}}
                    ],
                    "minimum_should_match": 1
                }
            },
            "aggs": {
                "by_tool": {
                    "terms": {"field": "process.name.keyword", "size": 20}
                }
            },
            "size": 0
        }
    },
    
    {
        "id": "074",
        "name": "Process Hollowing Indicators",
        "description": "Indicators of process hollowing (code injection)",
        "mitre_technique": "T1055.012",
        "mitre_tactic": "Defense Evasion",
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
                                {"term": {"process.name.keyword": "svchost.exe"}},
                                {"bool": {
                                    "must_not": [
                                        {"wildcard": {"process.executable": "*\\\\System32\\\\svchost.exe"}}
                                    ]
                                }}
                            ]
                        }},
                        {"bool": {
                            "must": [
                                {"term": {"process.name.keyword": "explorer.exe"}},
                                {"bool": {
                                    "must_not": [
                                        {"wildcard": {"process.executable": "*\\\\Windows\\\\explorer.exe"}}
                                    ]
                                }}
                            ]
                        }}
                    ],
                    "minimum_should_match": 1
                }
            },
            "aggs": {
                "by_process_path": {
                    "terms": {"field": "process.executable.keyword", "size": 30}
                }
            },
            "size": 0
        }
    },
    
    {
        "id": "075",
        "name": "Hidden Files/Directories Creation",
        "description": "Creation of hidden files or directories",
        "mitre_technique": "T1564.001",
        "mitre_tactic": "Defense Evasion",
        "severity": "medium",
        "data_source": "edr",
        "target_index": "case_{case_id}",
        "query": {
            "query": {
                "bool": {
                    "must": [
                        {"wildcard": {"source_file": "*.ndjson"}}
                    ],
                    "should": [
                        {"wildcard": {"process.command_line": "*attrib*+h*"}},
                        {"wildcard": {"process.command_line": "*attrib*+s*"}},
                        {"wildcard": {"process.command_line": "*Hidden*FileAttributes*"}},
                        {"wildcard": {"process.command_line": "*New-Item*-Hidden*"}}
                    ],
                    "minimum_should_match": 1
                }
            },
            "aggs": {
                "by_path": {
                    "terms": {"field": "process.command_line.keyword", "size": 30}
                }
            },
            "size": 0
        }
    },
    
    {
        "id": "076",
        "name": "Code Signing Certificate Theft",
        "description": "Attempts to steal code signing certificates",
        "mitre_technique": "T1553.002",
        "mitre_tactic": "Defense Evasion",
        "severity": "critical",
        "data_source": "edr",
        "target_index": "case_{case_id}",
        "query": {
            "query": {
                "bool": {
                    "must": [
                        {"wildcard": {"source_file": "*.ndjson"}}
                    ],
                    "should": [
                        {"wildcard": {"process.command_line": "*certutil*-exportPFX*"}},
                        {"wildcard": {"process.command_line": "*Export-PfxCertificate*"}},
                        {"wildcard": {"process.command_line": "*Cert:\\\\*\\\\My*"}}
                    ],
                    "minimum_should_match": 1
                }
            },
            "aggs": {
                "by_method": {
                    "terms": {"field": "process.name.keyword", "size": 20}
                }
            },
            "size": 0
        }
    },
    
    {
        "id": "077",
        "name": "Alternate Data Streams Abuse",
        "description": "Files hidden in alternate data streams",
        "mitre_technique": "T1564.004",
        "mitre_tactic": "Defense Evasion",
        "severity": "medium",
        "data_source": "edr",
        "target_index": "case_{case_id}",
        "query": {
            "query": {
                "bool": {
                    "must": [
                        {"wildcard": {"source_file": "*.ndjson"}}
                    ],
                    "should": [
                        {"wildcard": {"process.command_line": "*:*>*"}},
                        {"wildcard": {"process.command_line": "*Out-File*:*"}},
                        {"wildcard": {"process.command_line": "*wscript*:*"}},
                        {"wildcard": {"process.command_line": "*cscript*:*"}}
                    ],
                    "minimum_should_match": 1
                }
            },
            "aggs": {
                "by_technique": {
                    "terms": {"field": "process.command_line.keyword", "size": 30}
                }
            },
            "size": 0
        }
    },
    
    {
        "id": "078",
        "name": "Binary Padding (Large File Size)",
        "description": "Unusually large executables (binary padding)",
        "mitre_technique": "T1027.001",
        "mitre_tactic": "Defense Evasion",
        "severity": "low",
        "data_source": "edr",
        "target_index": "case_{case_id}",
        "query": {
            "query": {
                "bool": {
                    "must": [
                        {"match": {"event.category": "process"}},
                        {"wildcard": {"source_file": "*.ndjson"}},
                        {"range": {"process.pe.size": {"gte": 50000000}}}
                    ],
                    "must_not": [
                        {"wildcard": {"process.executable": "*Program Files*"}},
                        {"wildcard": {"process.executable": "*Windows\\\\*"}}
                    ]
                }
            },
            "aggs": {
                "by_process": {
                    "terms": {"field": "process.executable.keyword", "size": 30}
                }
            },
            "size": 0
        }
    },
    
    {
        "id": "079",
        "name": "DLL Search Order Hijacking",
        "description": "DLLs placed in paths to exploit search order",
        "mitre_technique": "T1574.001",
        "mitre_tactic": "Defense Evasion",
        "severity": "high",
        "data_source": "edr",
        "target_index": "case_{case_id}",
        "query": {
            "query": {
                "bool": {
                    "must": [
                        {"wildcard": {"source_file": "*.ndjson"}}
                    ],
                    "should": [
                        {"bool": {
                            "must": [
                                {"wildcard": {"process.command_line": "*copy*.dll*"}},
                                {"wildcard": {"process.command_line": "*\\\\Users\\\\*"}}
                            ]
                        }},
                        {"wildcard": {"process.command_line": "*version.dll*"}},
                        {"wildcard": {"process.command_line": "*wlbsctrl.dll*"}}
                    ],
                    "minimum_should_match": 1
                }
            },
            "aggs": {
                "by_dll": {
                    "terms": {"field": "process.command_line.keyword", "size": 30}
                }
            },
            "size": 0
        }
    },
    
    {
        "id": "080",
        "name": "Masquerading - Renamed System Binaries",
        "description": "System binaries renamed to evade detection",
        "mitre_technique": "T1036.003",
        "mitre_tactic": "Defense Evasion",
        "severity": "medium",
        "data_source": "edr",
        "target_index": "case_{case_id}",
        "query": {
            "query": {
                "bool": {
                    "must": [
                        {"match": {"event.category": "process"}},
                        {"exists": {"field": "process.pe.original_file_name"}},
                        {"wildcard": {"source_file": "*.ndjson"}}
                    ],
                    "should": [
                        {"term": {"process.pe.original_file_name.keyword": "cmd.exe"}},
                        {"term": {"process.pe.original_file_name.keyword": "powershell.exe"}},
                        {"term": {"process.pe.original_file_name.keyword": "rundll32.exe"}}
                    ],
                    "minimum_should_match": 1
                }
            },
            "aggs": {
                "by_original_name": {
                    "terms": {"field": "process.pe.original_file_name.keyword", "size": 30},
                    "aggs": {
                        "renamed_to": {
                            "terms": {"field": "process.name.keyword", "size": 30}
                        }
                    }
                }
            },
            "size": 0
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
    """Get patterns by tier (1-8)"""
    pattern_id_map = {int(p['id']): p for p in DETECTION_PATTERNS}
    
    if tier == 1:
        return [pattern_id_map[i] for i in range(1, 11) if i in pattern_id_map]
    elif tier == 2:
        return [pattern_id_map[i] for i in range(11, 21) if i in pattern_id_map]
    elif tier == 3:
        return [pattern_id_map[i] for i in range(21, 31) if i in pattern_id_map]
    elif tier == 4:
        return [pattern_id_map[i] for i in range(31, 41) if i in pattern_id_map]
    elif tier == 5:
        return [pattern_id_map[i] for i in range(41, 51) if i in pattern_id_map]
    elif tier == 6:
        return [pattern_id_map[i] for i in range(51, 61) if i in pattern_id_map]
    elif tier == 7:
        return [pattern_id_map[i] for i in range(61, 71) if i in pattern_id_map]
    elif tier == 8:
        return [pattern_id_map[i] for i in range(71, 81) if i in pattern_id_map]
    
    return DETECTION_PATTERNS


def get_pattern_count_by_tactic():
    """Get count of patterns by MITRE tactic"""
    tactics = {}
    for pattern in DETECTION_PATTERNS:
        tactic = pattern['mitre_tactic']
        tactics[tactic] = tactics.get(tactic, 0) + 1
    return tactics

