{
  "extraction_summary": {
    "report_type": "EDR Incident Report (Huntress)",
    "total_iocs": 18,
    "extraction_notes": "Pre-ransomware activity detected. Domain in WinRAR password parameter may be C2 or exfil destination."
  },
  "network": {
    "ip_v4": ["10.100.0.6"],
    "ip_v6": [],
    "domains": ["ctlobby.com"],
    "urls": [],
    "emails": [],
    "user_agents": []
  },
  "file": {
    "md5": [],
    "sha1": [],
    "sha256": [],
    "sha512": [],
    "ssdeep": [],
    "imphash": [],
    "file_names": [
      "WinRAR.exe",
      "CMD.exe",
      "rdpclip.exe",
      "veeam.backup.shell.exe",
      "WinRAR-713.exe",
      "Uninstall.exe",
      "whoami.exe",
      "DATA.rar"
    ],
    "file_paths": [
      "c:\\Program Files\\WinRAR\\WinRAR.exe",
      "C:\\Windows\\System32\\CMD.exe",
      "C:\\Windows\\System32\\rdpclip.exe",
      "E:\\Program Files\\Veeam\\Backup and Replication\\Console\\veeam.backup.shell.exe",
      "C:\\Users\\tabadmin\\Downloads\\WinRAR-713.exe",
      "C:\\Program Files\\Huntress\\Uninstall.exe",
      "C:\\Program Files\\WinRAR\\uninstall.exe",
      "C:\\Windows\\system32\\whoami.exe",
      "C:\\DATA\\done\\DATA.rar",
      "C:\\DATA"
    ]
  },
  "host": {
    "hostnames": ["SL-DC-01"],
    "registry_keys": [],
    "registry_values": [],
    "command_lines": [
      "winrar.exe a -m0 -v3g -tn1000d -n*.txt -n*.pdf -n*.xls -n*.doc -n*.xlsx -n*.docx -hpctlobby.com \"C:\\DATA\\done\\DATA.rar\" \"C:\\DATA\"",
      "/C \"whoami\"",
      "\"C:\\Program Files\\WinRAR\\uninstall.exe\" /setup"
    ],
    "process_names": [
      "WinRAR.exe",
      "CMD.exe",
      "rdpclip.exe",
      "veeam.backup.shell.exe",
      "whoami.exe"
    ],
    "service_names": [],
    "scheduled_tasks": [],
    "mutexes": [],
    "named_pipes": []
  },
  "identity": {
    "usernames": ["tabadmin", "SL\\tabadmin"],
    "sids": ["S-1-5-21-2554046153-4285503646-2850861276-5162"],
    "compromised_accounts": ["SL\\tabadmin"]
  },
  "threat_intel": {
    "cves": [],
    "mitre_attack": [
      "T1560.001 - Archive via Utility",
      "T1021.001 - Remote Desktop Protocol",
      "T1082 - System Information Discovery",
      "T1562.001 - Disable or Modify Tools",
      "T1490 - Inhibit System Recovery"
    ],
    "malware_families": [],
    "threat_actors": [],
    "yara_rules": [],
    "sigma_rules": []
  },
  "cryptocurrency": {
    "btc_addresses": [],
    "eth_addresses": [],
    "xmr_addresses": []
  },
  "timeline": [
    {
      "timestamp": "2025-08-02T07:07:41Z",
      "event": "User tabadmin logged onto SL-DC-01 from unmanaged host",
      "iocs_involved": ["tabadmin", "SL-DC-01", "10.100.0.6"]
    },
    {
      "timestamp": "2025-08-02T07:27:33Z",
      "event": "WinRAR archive creation started with password",
      "iocs_involved": ["WinRAR.exe", "ctlobby.com", "DATA.rar"]
    },
    {
      "timestamp": "2025-08-02T07:27:48Z",
      "event": "Archive activity detected by EDR",
      "iocs_involved": ["WinRAR.exe"]
    },
    {
      "timestamp": "2025-08-02T07:28:00Z",
      "event": "Reconnaissance and defense evasion commands executed",
      "iocs_involved": ["whoami.exe", "Uninstall.exe"]
    }
  ]
}