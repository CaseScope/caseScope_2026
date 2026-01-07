# Detection Pattern Strategy - Based on Actual Data Sources

## Available Data Sources Summary

### 1. EDR Telemetry (NDJSON - Huntress)
**What we have:**
- ✅ Process execution events with **full command lines**
- ✅ Parent-child process relationships  
- ✅ File hashes (MD5, SHA1, SHA256)
- ✅ Code signature validation
- ✅ User context (SID, domain, name)
- ✅ Process paths and executable locations
- ✅ PE metadata (imphash, original filename, compile time)
- ✅ Exit codes and execution status

**Detection Capabilities:**
- Malicious process execution patterns
- PowerShell/scripting abuse
- Living-off-the-land binaries (LOLBins)
- Process injection indicators
- Credential dumping tools
- Lateral movement tools (PSExec, WMI, etc.)
- Persistence mechanisms (services, scheduled tasks via command line)
- Suspicious parent-child relationships

**Sample Event:**
```json
{
  "event": {"category": "process", "type": ["start"]},
  "process": {
    "pid": "21856",
    "command_line": "powershell.exe -enc <base64>",
    "name": "powershell.exe",
    "executable": "C:\\Windows\\System32\\powershell.exe",
    "parent": {
      "name": "cmd.exe",
      "command_line": "cmd.exe /c whoami"
    },
    "hash": {
      "sha256": "abc123..."
    },
    "code_signature": {
      "valid": true,
      "subject_name": "Microsoft Corporation"
    },
    "user": {
      "name": "DOMAIN\\user",
      "id": "S-1-5-21-..."
    }
  }
}
```

### 2. Sonicwall Firewall Logs (CSV)
**What we have:**
- ✅ VPN authentication attempts (successes/failures)
- ✅ Source/Destination IPs and ports
- ✅ Protocol information
- ✅ Firewall actions (allow/deny)
- ✅ Application detection
- ✅ Bytes transferred (RX/TX)
- ✅ URL/HTTP request details
- ✅ Usernames for VPN/auth events

**Detection Capabilities:**
- VPN brute force attacks
- Port scanning
- C2 beaconing
- Data exfiltration (large outbound transfers)
- Geographic anomalies (connections from unexpected countries)
- Blocked malicious traffic
- Web application attacks

**Sample Event:**
```csv
Time: 09/05/2025 06:01:28
Event: Unknown User Login Attempt
Src. IP: 185.93.89.38
User Name: hereward
Message: User login denied due to bad credentials
```

### 3. CyLR Forensic Artifacts
**What we have:**
- ✅ Windows Event Logs (Security, System, Application, PowerShell)
- ✅ Registry hives (SYSTEM, SAM, SECURITY, NTUSER.DAT)
- ✅ Prefetch files (execution artifacts)
- ✅ MFT (file system timeline)
- ✅ Browser history
- ✅ Jump lists / Recent items
- ✅ SRUM (network usage, app execution)
- ✅ Amcache (program execution history)

**Detection Capabilities:**
- Failed/successful logon events (4624/4625)
- Account creation/modification (4720/4722/4738)
- Privilege escalation (4672)
- Service installation (7045)
- Scheduled task creation (4698)
- Log clearing (1102)
- Kerberos anomalies (4768/4769/4771)
- Historical program execution (Prefetch, Amcache)
- Persistence via registry Run keys
- File access patterns (MFT timeline)

---

## Top 30 Detection Patterns (Prioritized by Data Availability + Impact)

### TIER 1: Critical & High-Fidelity (10 patterns)

#### 1. VPN Brute Force Attack
- **MITRE**: T1110.001 (Brute Force)
- **Severity**: HIGH
- **Data Source**: Sonicwall CSV
- **Detection Logic**:
  ```
  Event: "Unknown User Login Attempt" OR "User login denied"
  Aggregation: Group by Src. IP
  Threshold: >10 failures in 5 minutes
  ```
- **Fields**: Time, Src. IP, User Name, Message
- **False Positive Rate**: Very Low
- **Evidence**: We saw this LIVE in the sample data (185.93.89.38, 185.93.89.31, etc.)

#### 2. PowerShell Encoded Command Execution
- **MITRE**: T1059.001 (PowerShell)
- **Severity**: HIGH
- **Data Source**: EDR NDJSON
- **Detection Logic**:
  ```
  process.name: "powershell.exe" OR "pwsh.exe"
  process.command_line contains: "-enc" OR "-encodedcommand" OR "frombase64"
  ```
- **Fields**: process.command_line, process.name, process.user.name
- **False Positive Rate**: Low (some legit scripts use encoding)

#### 3. Credential Dumping Tools (Mimikatz, etc.)
- **MITRE**: T1003.001 (LSASS Memory)
- **Severity**: CRITICAL
- **Data Source**: EDR NDJSON
- **Detection Logic**:
  ```
  process.command_line contains: "sekurlsa" OR "lsadump" OR "logonpasswords"
  OR process.hash.sha256 in [known Mimikatz hashes]
  OR process.name: "procdump.exe" AND process.args contains "lsass"
  ```
- **Fields**: process.name, process.command_line, process.hash.*
- **False Positive Rate**: Very Low

#### 4. PSExec / PsExec-style Lateral Movement
- **MITRE**: T1021.002 (SMB/Windows Admin Shares)
- **Severity**: HIGH
- **Data Source**: EDR NDJSON
- **Detection Logic**:
  ```
  process.name: "psexec.exe" OR "psexesvc.exe" OR "paexec.exe"
  OR (process.command_line contains "\\\\ADMIN$" OR "\\\\C$")
  OR (process.parent.name: "services.exe" AND process.command_line contains "cmd" AND process.working_directory: "C:\\Windows")
  ```
- **Fields**: process.name, process.command_line, process.parent.name
- **False Positive Rate**: Low

#### 5. Suspicious Service Creation
- **MITRE**: T1543.003 (Windows Service)
- **Severity**: HIGH
- **Data Source**: EDR NDJSON + CyLR Event 7045
- **Detection Logic**:
  ```
  process.command_line contains: "sc create" OR "New-Service"
  AND process.executable NOT in whitelist (C:\\Program Files, System32)
  OR Event 7045 with ServiceFileName from unusual path
  ```
- **Fields**: process.command_line, event_data.ServiceFileName
- **False Positive Rate**: Medium (installers create services)

#### 6. Pass-the-Hash Detection
- **MITRE**: T1550.002 (Pass the Hash)
- **Severity**: CRITICAL  
- **Data Source**: CyLR Event Logs (4624)
- **Detection Logic**:
  ```
  Event 4624 (Successful Logon)
  LogonType: 3 (Network) OR 9 (NewCredentials)
  AuthenticationPackageName: NTLM
  AND NOT preceded by Event 4768 (Kerberos TGT) for same user within 5 min
  ```
- **Fields**: LogonType, AuthenticationPackageName, TargetUserName, IpAddress
- **False Positive Rate**: Medium (legacy apps use NTLM)

#### 7. Security Event Log Cleared
- **MITRE**: T1070.001 (Clear Windows Event Logs)
- **Severity**: CRITICAL
- **Data Source**: CyLR Event Logs (1102)
- **Detection Logic**:
  ```
  Event 1102 (Security log was cleared)
  ANY occurrence
  ```
- **Fields**: TimeCreated, SubjectUserName
- **False Positive Rate**: Very Low (rarely legitimate during incident)

#### 8. Failed Logon Spike (Brute Force)
- **MITRE**: T1110.001 (Brute Force)
- **Severity**: HIGH
- **Data Source**: CyLR Event Logs (4625)
- **Detection Logic**:
  ```
  Event 4625 (Failed Logon)
  Aggregation: Group by IpAddress
  Threshold: >10 in 5 minutes
  ```
- **Fields**: IpAddress, TargetUserName, LogonType, FailureReason
- **False Positive Rate**: Low

#### 9. Suspicious Process Ancestry
- **MITRE**: T1059 (Command and Scripting Interpreter)
- **Severity**: MEDIUM
- **Data Source**: EDR NDJSON
- **Detection Logic**:
  ```
  Unusual parent-child combinations:
  - Office apps (winword.exe, excel.exe) spawning cmd.exe/powershell.exe
  - Browser spawning wscript.exe/cscript.exe
  - Adobe Reader spawning shells
  ```
- **Fields**: process.name, process.parent.name, process.command_line
- **False Positive Rate**: Medium (some macros are legitimate)

#### 10. Network Scanning Activity
- **MITRE**: T1046 (Network Service Discovery)
- **Severity**: MEDIUM
- **Data Source**: Sonicwall CSV
- **Detection Logic**:
  ```
  Single Src. IP contacting >50 unique Dst. IP on same Dst. Port
  within 10 minutes
  Common scan ports: 22, 23, 80, 443, 445, 3389, etc.
  ```
- **Fields**: Src. IP, Dst. IP, Dst. Port, Time
- **False Positive Rate**: Medium (vulnerability scanners, monitoring tools)

---

### TIER 2: High Value (10 patterns)

#### 11. Living-off-the-Land Binary Abuse (LOLBins)
- **MITRE**: T1218 (System Binary Proxy Execution)
- **Severity**: MEDIUM
- **Data Source**: EDR NDJSON
- **Detection Logic**:
  ```
  Suspicious use of built-in Windows tools:
  - regsvr32.exe with /s /u /i:http
  - rundll32.exe loading from non-standard paths
  - mshta.exe executing remote URLs
  - certutil.exe with -urlcache -split -f
  - bitsadmin.exe /transfer
  ```
- **False Positive Rate**: Medium

#### 12. WMI Remote Execution
- **MITRE**: T1047 (Windows Management Instrumentation)
- **Severity**: HIGH
- **Data Source**: EDR NDJSON
- **Detection Logic**:
  ```
  process.parent.name: "wmiprvse.exe"
  AND process.name in [cmd.exe, powershell.exe, cscript.exe, wscript.exe]
  OR process.command_line contains "wmic /node:"
  ```
- **False Positive Rate**: Medium

#### 13. Scheduled Task Creation (Persistence)
- **MITRE**: T1053.005 (Scheduled Task)
- **Severity**: MEDIUM
- **Data Source**: EDR NDJSON + CyLR Event 4698
- **Detection Logic**:
  ```
  process.command_line contains: "schtasks /create" OR "Register-ScheduledTask"
  OR Event 4698 (Scheduled task created)
  Filter out known management tasks
  ```
- **False Positive Rate**: High (needs whitelist)

#### 14. Kerberoasting
- **MITRE**: T1558.003 (Steal or Forge Kerberos Tickets)
- **Severity**: HIGH
- **Data Source**: CyLR Event Logs (4769)
- **Detection Logic**:
  ```
  Event 4769 (Kerberos TGS Request)
  TicketEncryptionType: 0x17 (RC4)
  ServiceName: NOT krbtgt
  Aggregation: >5 service tickets in 10 min from one account
  ```
- **False Positive Rate**: Low

#### 15. RDP Brute Force
- **MITRE**: T1021.001 (Remote Desktop Protocol)
- **Severity**: HIGH
- **Data Source**: CyLR Event Logs (4625)
- **Detection Logic**:
  ```
  Event 4625 (Failed Logon)
  LogonType: 10 (RemoteInteractive)
  Aggregation: >5 failures from same IP in 10 min
  ```
- **False Positive Rate**: Low

#### 16. New User Account Creation
- **MITRE**: T1136.001 (Local Account)
- **Severity**: HIGH
- **Data Source**: CyLR Event Logs (4720)
- **Detection Logic**:
  ```
  Event 4720 (User account created)
  Especially if added to privileged groups (Event 4732)
  ```
- **False Positive Rate**: Low (context-dependent)

#### 17. Unusual Outbound Data Transfer
- **MITRE**: T1041 (Exfiltration Over C2 Channel)
- **Severity**: HIGH
- **Data Source**: Sonicwall CSV
- **Detection Logic**:
  ```
  TX Bytes > 500MB in single session
  OR sustained high bandwidth to single external IP
  Filter: exclude known backup/cloud services
  ```
- **False Positive Rate**: Medium

#### 18. Prefetch Analysis - Suspicious Execution
- **MITRE**: T1059 (Execution)
- **Severity**: MEDIUM
- **Data Source**: CyLR Prefetch files
- **Detection Logic**:
  ```
  Prefetch files for:
  - Known hacking tools (mimikatz, psexec, bloodhound)
  - Processes executed from temp directories
  - Unusual system tools (procdump, process hacker)
  ```
- **False Positive Rate**: Low

#### 19. Registry Run Key Persistence
- **MITRE**: T1547.001 (Registry Run Keys)
- **Severity**: MEDIUM
- **Data Source**: CyLR Registry Hives
- **Detection Logic**:
  ```
  Analyze NTUSER.DAT and SOFTWARE hives:
  - HKCU\Software\Microsoft\Windows\CurrentVersion\Run
  - HKLM\Software\Microsoft\Windows\CurrentVersion\Run
  Look for unusual executables, scripts, or paths
  ```
- **False Positive Rate**: High (many legit apps)

#### 20. Antivirus Evasion / Disabling
- **MITRE**: T1562.001 (Impair Defenses)
- **Severity**: CRITICAL
- **Data Source**: EDR NDJSON + CyLR Event Logs
- **Detection Logic**:
  ```
  process.command_line contains:
  - "Set-MpPreference -DisableRealtimeMonitoring"
  - "sc stop WinDefend"
  - "Uninstall-WindowsFeature Windows-Defender"
  OR Windows Defender Event 5001 (real-time protection disabled)
  ```
- **False Positive Rate**: Low

---

### TIER 3: Specialized (10 patterns)

#### 21. Web Application Attacks
- **MITRE**: T1190 (Exploit Public-Facing Application)
- **Severity**: HIGH
- **Data Source**: Sonicwall CSV (if has HTTP inspection)
- **Detection Logic**:
  ```
  URL contains SQL injection patterns: ' OR 1=1, UNION SELECT
  OR XSS patterns: <script>, javascript:
  OR command injection: ; whoami, | nc
  ```
- **False Positive Rate**: Medium

#### 22. DNS Tunneling / C2 Communication
- **MITRE**: T1071.004 (Application Layer Protocol: DNS)
- **Severity**: HIGH
- **Data Source**: Sonicwall CSV (DNS logs if available)
- **Detection Logic**:
  ```
  Unusually long DNS queries (>50 chars)
  OR high volume of DNS queries to single domain
  OR queries to suspicious TLDs (.tk, .ml, etc.)
  ```
- **False Positive Rate**: Medium

#### 23. Ransomware - Volume Shadow Copy Deletion
- **MITRE**: T1490 (Inhibit System Recovery)
- **Severity**: CRITICAL
- **Data Source**: EDR NDJSON
- **Detection Logic**:
  ```
  process.command_line contains:
  - "vssadmin delete shadows"
  - "wmic shadowcopy delete"
  - "bcdedit /set {default} recoveryenabled No"
  ```
- **False Positive Rate**: Very Low

#### 24. Mass File Modification (Ransomware Indicator)
- **MITRE**: T1486 (Data Encrypted for Impact)
- **Severity**: CRITICAL
- **Data Source**: EDR NDJSON (if file events available) + MFT Timeline
- **Detection Logic**:
  ```
  Process modifying >100 files in <5 minutes
  File extensions changed to .encrypted, .locked, etc.
  OR analysis of MFT timeline showing mass file modifications
  ```
- **False Positive Rate**: Low

#### 25. Bloodhound / SharpHound AD Reconnaissance
- **MITRE**: T1087.002 (Domain Account Discovery)
- **Severity**: HIGH
- **Data Source**: EDR NDJSON
- **Detection Logic**:
  ```
  process.name contains: "sharphound" OR "bloodhound"
  OR process.command_line contains: "Invoke-BloodHound"
  ```
- **False Positive Rate**: Very Low

#### 26. DLL Hijacking / Side-Loading
- **MITRE**: T1574.002 (DLL Side-Loading)
- **Severity**: MEDIUM
- **Data Source**: EDR NDJSON (parent/child relationships)
- **Detection Logic**:
  ```
  Legitimate signed process loading unsigned DLL from unusual path
  OR process.pe.original_file_name != process.name (renamed executable)
  ```
- **False Positive Rate**: Medium

#### 27. Token Impersonation / Privilege Escalation
- **MITRE**: T1134 (Access Token Manipulation)
- **Severity**: HIGH
- **Data Source**: CyLR Event Logs (4672)
- **Detection Logic**:
  ```
  Event 4672 (Special privileges assigned)
  SubjectUserSid: User account (not SYSTEM)
  PrivilegeList includes: SeDebugPrivilege, SeTcbPrivilege
  ```
- **False Positive Rate**: Medium

#### 28. Browser Credential Theft
- **MITRE**: T1555.003 (Credentials from Web Browsers)
- **Severity**: HIGH
- **Data Source**: EDR NDJSON
- **Detection Logic**:
  ```
  process.command_line accessing browser credential files:
  - %APPDATA%\Google\Chrome\User Data\Default\Login Data
  - %APPDATA%\Mozilla\Firefox\Profiles\*.default\logins.json
  ```
- **False Positive Rate**: Low

#### 29. NTDS.dit Extraction (DC Credential Theft)
- **MITRE**: T1003.003 (NTDS)
- **Severity**: CRITICAL
- **Data Source**: EDR NDJSON
- **Detection Logic**:
  ```
  process.command_line contains:
  - "ntdsutil" AND "create full"
  - "vssadmin create shadow" AND command references C:\Windows\NTDS
  - "copy" AND "ntds.dit"
  ```
- **False Positive Rate**: Very Low

#### 30. Suspicious PowerShell Profile Modification
- **MITRE**: T1546.013 (PowerShell Profile)
- **Severity**: MEDIUM
- **Data Source**: EDR NDJSON + CyLR File System
- **Detection Logic**:
  ```
  File modifications to PowerShell profiles:
  - $PROFILE (various paths)
  - Microsoft.PowerShell_profile.ps1
  Check for unusual commands in profile scripts
  ```
- **False Positive Rate**: Low

---

## Detection Coverage Matrix

| MITRE Tactic | # Patterns | Primary Data Source |
|--------------|-----------|-------------------|
| Initial Access | 3 | Sonicwall, Event Logs |
| Execution | 7 | EDR NDJSON |
| Persistence | 4 | EDR, Event Logs, Registry |
| Privilege Escalation | 3 | Event Logs, EDR |
| Defense Evasion | 4 | EDR, Event Logs |
| Credential Access | 6 | EDR, Event Logs |
| Discovery | 3 | Sonicwall, EDR |
| Lateral Movement | 4 | EDR, Event Logs |
| Collection | 1 | CyLR File System |
| Exfiltration | 2 | Sonicwall |
| Impact | 3 | EDR, MFT |

---

## Implementation Priority

**Week 1: Implement Top 10 (Tier 1)**
- Covers most common attacks
- Low false positive rates
- Uses all three data sources

**Week 2: Add Tier 2 patterns**
- Broader ATT&CK coverage
- Some tuning needed

**Week 3: Add Tier 3 specialized patterns**
- Environment-specific
- Advanced threats

**Week 4: Testing & Tuning**
- Run against real case data
- Build whitelists
- Adjust thresholds
