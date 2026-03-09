#!/usr/bin/env python3
"""Build IOC extraction training data from example Huntress reports.

Directly extracts IOCs using regex + heuristics (no teacher model needed).
Outputs ShareGPT-formatted JSONL for LoRA training.
"""
import os, json, glob, re, random

random.seed(42)

REPORTS_DIR = "/opt/casescope/example_reports"
OUTPUT_FILE = "/opt/casescope/training_data/ioc_training_raw.jsonl"

SYSTEM_PROMPT = """You are an expert SOC analyst extracting ALL Indicators of Compromise from Huntress EDR security incident reports. Your goal is MAXIMUM extraction - capture EVERYTHING that could be useful for threat hunting.

CRITICAL RULES:
1. Return ONLY valid JSON. No markdown, no explanation, no code blocks.
2. Extract ONLY from the user's report content - NEVER extract from this prompt's examples or schema.
3. If a field has no data in the report, use an empty array [] - do not invent values.

## DEFANG CONVERSION (ALWAYS APPLY)
Convert these patterns back to clean values:
- hxxp:// or hxxps:// -> http:// or https://
- [.] or (.) or [dot] -> .
- [:] -> :
- [@] or [at] -> @
- [://] -> ://

## OUTPUT STRUCTURE

{
  "extraction_summary": {
    "report_date": "...",
    "affected_hosts": ["..."],
    "affected_users": [{"username": "...", "sid": "...", "domain": "..."}],
    "attack_type": "...",
    "severity": "critical|high|medium|low",
    "threat_families": ["..."],
    "isolated": true|false
  },
  "network_iocs": {
    "ipv4": [{"value": "...", "port": 0, "context": "...", "direction": "inbound|outbound"}],
    "ipv6": [{"value": "...", "context": "..."}],
    "domains": [{"value": "...", "type": "c2|malware|phishing|unknown", "context": "..."}],
    "urls": [{"value": "...", "type": "payload_download|c2|phishing|unknown", "context": "..."}],
    "cloudflare_tunnels": ["..."]
  },
  "file_iocs": {
    "hashes": [{"value": "...", "type": "md5|sha1|sha256", "filename": "...", "context": "..."}],
    "file_paths": [{"value": "...", "action": "executed|created|deleted", "context": "..."}],
    "file_names": ["..."]
  },
  "process_iocs": {
    "commands": [{
      "full_command": "...",
      "executable": "...",
      "arguments": "...",
      "parent_process": "...",
      "user": "...",
      "pid": "...",
      "context": "..."
    }],
    "services": [{"name": "...", "display_name": "...", "path": "...", "action": "delete|create"}],
    "scheduled_tasks": [{"name": "...", "path": "...", "command": "...", "action": "delete|create"}],
    "parent_child_chains": [{"parent": "...", "children": ["..."], "context": "..."}]
  },
  "persistence_iocs": {
    "registry": [{"key": "...", "value_name": "...", "value_data": "...", "action": "delete|create", "context": "..."}],
    "credential_theft_indicators": [{"type": "...", "registry_key": "...", "value": "...", "data": "...", "context": "..."}]
  },
  "authentication_iocs": {
    "compromised_users": [{"username": "...", "sid": "...", "domain": "...", "context": "..."}],
    "created_users": [{"username": "...", "password": "...", "groups": ["..."], "context": "..."}],
    "passwords_observed": [{"username": "...", "password": "...", "context": "..."}]
  },
  "vulnerability_iocs": {
    "cves": ["CVE-XXXX-XXXXX"],
    "exchange_version": "...",
    "exposed_services": ["..."],
    "webshells": [{"path": "...", "context": "..."}]
  },
  "threat_intel": {
    "malware_families": ["..."],
    "threat_names": ["..."],
    "rmm_tools": ["..."],
    "techniques": ["..."]
  },
  "timestamps": [{"time": "...", "event": "...", "user": "..."}],
  "raw_artifacts": {
    "encoded_powershell": ["..."],
    "vnc_connection_ids": ["..."],
    "screenconnect_relay_params": ["..."]
  },
  "mitre_attack": [{"technique_id": "T####.###", "technique_name": "...", "evidence": "..."}]
}

Use EMPTY arrays [] for sections with no data from the report. Never invent or hallucinate values."""

USER_PROMPTS = [
    "Extract ALL IOCs from this security report. Be thorough - capture everything:\n\n{}",
    "Analyze this Huntress EDR incident report and extract every Indicator of Compromise:\n\n{}",
    "Parse the following security incident report and return all IOCs in structured JSON:\n\n{}",
    "Extract all indicators of compromise from this MDR security report:\n\n{}",
    "Review this security report and extract ALL network, file, process, and persistence IOCs:\n\n{}",
]

NEGATIVE_TEXTS = [
    "Meeting Notes - Q3 Budget Review\n\nAttendees: John Smith, Sarah Lee\nDate: 2025-03-15\n\nDiscussed quarterly budget allocation for the IT department. Agreed to increase cloud spending by 15%. Next meeting scheduled for April 2.",
    "Weekly Status Update\n\nProject Alpha is on track. Development completed sprint 14. QA testing begins Monday. No blockers reported. Team velocity: 42 story points.",
    "Employee Onboarding Checklist\n\n1. Complete HR paperwork\n2. Set up workstation\n3. Request badge access\n4. Schedule orientation\n5. Review company policies\n\nContact IT helpdesk at ext. 4200 for equipment issues.",
    "Server Maintenance Window\n\nScheduled: Saturday 2AM-6AM EST\nAffected systems: Email server, file shares\nExpected downtime: 2 hours\nContact: NOC team\n\nAll patches have been tested in staging. No security incidents to report.",
    "Product Release Notes v3.2.1\n\nBug fixes:\n- Fixed login timeout issue\n- Resolved CSV export formatting\n- Updated dashboard widget alignment\n\nNew features:\n- Dark mode support\n- Export to PDF\n\nNo security vulnerabilities addressed in this release.",
]

# MITRE technique keyword mapping for Huntress report patterns
MITRE_KEYWORDS = {
    "screenconnect": [("T1219", "Remote Access Software")],
    "rogue screenconnect": [("T1219", "Remote Access Software")],
    "anydesk": [("T1219", "Remote Access Software")],
    "simplehelp": [("T1219", "Remote Access Software")],
    "remote management tool": [("T1219", "Remote Access Software")],
    "rmm": [("T1219", "Remote Access Software")],
    "itarian": [("T1219", "Remote Access Software")],
    "lateral mov": [("T1021", "Remote Services")],
    "cobalt strike": [("T1071.001", "Web Protocols"), ("T1059.001", "PowerShell")],
    "powershell": [("T1059.001", "PowerShell")],
    "cmd.exe": [("T1059.003", "Windows Command Shell")],
    "wscript": [("T1059.005", "Visual Basic")],
    "mshta": [("T1218.005", "Mshta")],
    "msbuild": [("T1127.001", "MSBuild")],
    "rundll32": [("T1218.011", "Rundll32")],
    "msiexec": [("T1218.007", "Msiexec")],
    "scheduled task": [("T1053.005", "Scheduled Task")],
    "registry": [("T1547.001", "Registry Run Keys")],
    "run key": [("T1547.001", "Registry Run Keys")],
    "startup folder": [("T1547.001", "Registry Run Keys")],
    "persistence": [("T1547", "Boot or Logon Autostart Execution")],
    "credential": [("T1003", "OS Credential Dumping")],
    "lsass": [("T1003.001", "LSASS Memory")],
    "brute force": [("T1110", "Brute Force")],
    "password spray": [("T1110.003", "Password Spraying")],
    "phishing": [("T1566", "Phishing")],
    "infostealer": [("T1555", "Credentials from Password Stores")],
    "info stealer": [("T1555", "Credentials from Password Stores")],
    "defender exclusion": [("T1562.001", "Disable or Modify Tools")],
    "disabling.*security": [("T1562.001", "Disable or Modify Tools")],
    "whoami": [("T1033", "System Owner/User Discovery")],
    "nltest": [("T1482", "Domain Trust Discovery")],
    "ipconfig": [("T1016", "System Network Configuration Discovery")],
    "enumeration": [("T1087", "Account Discovery")],
    "rat": [("T1219", "Remote Access Software")],
    "remote access trojan": [("T1219", "Remote Access Software")],
    "cloudflare tunnel": [("T1572", "Protocol Tunneling")],
    "encoded powershell": [("T1027", "Obfuscated Files or Information"), ("T1059.001", "PowerShell")],
    "base64": [("T1027", "Obfuscated Files or Information")],
    "webshell": [("T1505.003", "Web Shell")],
    "exchange": [("T1190", "Exploit Public-Facing Application")],
    "proxyshell": [("T1190", "Exploit Public-Facing Application")],
    "cve-": [("T1190", "Exploit Public-Facing Application")],
    "ransomware": [("T1486", "Data Encrypted for Impact")],
}

THREAT_SEVERITY = {
    "cobalt strike": "critical",
    "ransomware": "critical",
    "lateral mov": "critical",
    "lsass": "critical",
    "credential": "critical",
    "rat": "high",
    "remote access trojan": "high",
    "infostealer": "high",
    "info stealer": "high",
    "webshell": "critical",
    "brute force": "high",
    "password spray": "high",
    "screenconnect": "high",
    "rogue": "high",
    "phishing": "medium",
    "persistence": "medium",
    "enumeration": "medium",
}


def defang_to_clean(text):
    """Convert defanged indicators back to clean values."""
    text = text.replace("hxxps://", "https://").replace("hxxp://", "http://")
    text = text.replace("hxxps[://]", "https://").replace("hxxp[://]", "http://")
    text = re.sub(r'\[:\]', ':', text)
    text = re.sub(r'\[\.?\]', '.', text)
    text = re.sub(r'\(\.?\)', '.', text)
    text = re.sub(r'\[dot\]', '.', re.IGNORECASE, string=text) if '[dot]' in text.lower() else text
    text = re.sub(r'\[at\]', '@', text)
    text = re.sub(r'\[@\]', '@', text)
    text = re.sub(r'\[://\]', '://', text)
    return text


def extract_ips(text):
    """Extract IPv4 addresses, excluding common private/local ones that aren't IOCs."""
    clean = defang_to_clean(text)
    ips = re.findall(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', clean)
    results = []
    seen = set()
    for ip in ips:
        if ip in seen:
            continue
        seen.add(ip)
        octets = [int(o) for o in ip.split('.')]
        if octets[0] == 127 or octets[0] == 0:
            continue
        if all(0 <= o <= 255 for o in octets):
            ctx_match = re.search(rf'(?:from|to|address|IP|connecting|communicat\w+|reaching|outbound|inbound).{{0,80}}{re.escape(ip)}|{re.escape(ip)}.{{0,80}}(?:C2|malicious|adversar|command|control|suspicious|external)', clean, re.IGNORECASE)
            context = ctx_match.group(0).strip()[:120] if ctx_match else ""
            is_private = (octets[0] == 10 or
                         (octets[0] == 172 and 16 <= octets[1] <= 31) or
                         (octets[0] == 192 and octets[1] == 168))
            direction = "inbound" if is_private else "outbound"
            port_match = re.search(rf'{re.escape(ip)}.*?(?:port|:)\s*(\d{{2,5}})', clean, re.IGNORECASE)
            port = int(port_match.group(1)) if port_match else 0
            results.append({"value": ip, "port": port, "context": context, "direction": direction})
    return results


def extract_domains(text):
    """Extract domains from report text."""
    clean = defang_to_clean(text)
    domains = set()
    for m in re.finditer(r'(?:domain|communicat\w+\s+(?:with\s+)?(?:domain\s+)?|reaches?\s+out\s+to\s+|hosted\s+on\s+|connects?\s+to\s+)["\']?([a-zA-Z0-9][-a-zA-Z0-9.]*\.[a-zA-Z]{2,})', clean, re.IGNORECASE):
        domains.add(m.group(1).strip("'\".,"))
    for m in re.finditer(r'(?:https?://)?([a-zA-Z0-9][-a-zA-Z0-9]*\.(?:top|ru|xyz|tk|ml|ga|cf|gq|buzz|work|click|club|online|site|icu|cam|live|info|store|best|quest|fun|sbs|cfd|rest))\b', clean, re.IGNORECASE):
        domains.add(m.group(1))
    for m in re.finditer(r'(?:h=|host=)([a-zA-Z0-9][-a-zA-Z0-9.]*\.[a-zA-Z]{2,})', clean):
        domains.add(m.group(1))
    skip = {"huntress.io", "tabinc.huntress.io", "amazonaws.com", "microsoft.com",
            "windowsupdate.com", "google.com", "trycloudflare.com"}
    results = []
    for d in domains:
        if any(d.endswith(s) or d == s for s in skip):
            continue
        dtype = "c2" if any(k in text.lower() for k in ["c2", "command and control", "c&c"]) else "unknown"
        ctx_match = re.search(rf'.{{0,60}}{re.escape(d)}.{{0,60}}', clean, re.IGNORECASE)
        context = ctx_match.group(0).strip()[:120] if ctx_match else ""
        results.append({"value": d, "type": dtype, "context": context})
    return results


def extract_urls(text):
    """Extract URLs from report text."""
    clean = defang_to_clean(text)
    urls = set()
    for m in re.finditer(r'(https?://[^\s"\'<>\]]+)', clean):
        u = m.group(1).rstrip(".,;)")
        if "huntress.io" not in u and "windowsupdate" not in u:
            urls.add(u)
    results = []
    for u in urls:
        utype = "payload_download" if any(k in u.lower() for k in [".exe", ".msi", ".zip", ".dll", ".ps1", ".js", ".bat"]) else \
                "c2" if any(k in text.lower() for k in ["c2", "command and control"]) else \
                "phishing" if any(k in text.lower() for k in ["phish", "captcha", "lure"]) else "unknown"
        ctx_match = re.search(rf'.{{0,40}}{re.escape(u[:40])}.{{0,40}}', clean, re.IGNORECASE)
        context = ctx_match.group(0).strip()[:120] if ctx_match else ""
        results.append({"value": u, "type": utype, "context": context})
    return results


def extract_hashes(text):
    """Extract file hashes (MD5, SHA1, SHA256)."""
    results = []
    seen = set()
    for m in re.finditer(r'(?:SHA-?256|sha256)[:\s]*["\']?([a-fA-F0-9]{64})["\']?', text):
        h = m.group(1).lower()
        if h not in seen:
            seen.add(h)
            fname_match = re.search(rf'([^\s/\\]+\.(?:exe|dll|js|ps1|msi|zip|vbs|bat|cmd))\s*.*?{h[:16]}|{h[:16]}.*?([^\s/\\]+\.(?:exe|dll|js|ps1|msi|zip|vbs|bat|cmd))', text, re.IGNORECASE)
            fname = (fname_match.group(1) or fname_match.group(2)) if fname_match else ""
            results.append({"value": h, "type": "sha256", "filename": fname, "context": ""})
    for m in re.finditer(r'\b([a-fA-F0-9]{64})\b', text):
        h = m.group(1).lower()
        if h not in seen:
            seen.add(h)
            results.append({"value": h, "type": "sha256", "filename": "", "context": ""})
    for m in re.finditer(r'(?:SHA-?1|sha1)[:\s]*["\']?([a-fA-F0-9]{40})["\']?', text):
        h = m.group(1).lower()
        if h not in seen:
            seen.add(h)
            results.append({"value": h, "type": "sha1", "filename": "", "context": ""})
    for m in re.finditer(r'(?:MD5|md5)[:\s]*["\']?([a-fA-F0-9]{32})["\']?', text):
        h = m.group(1).lower()
        if h not in seen:
            seen.add(h)
            results.append({"value": h, "type": "md5", "filename": "", "context": ""})
    return results


def extract_file_paths(text):
    """Extract Windows file paths."""
    results = []
    seen = set()
    for m in re.finditer(r'(?:path|file|executable|process)[:\s]*["\']?([A-Za-z]:\\[^\s"\'<>|*]+)', text, re.IGNORECASE):
        p = m.group(1).rstrip(".,;)")
        if p.lower() not in seen:
            seen.add(p.lower())
            action = "deleted" if re.search(r'delet', text[max(0, m.start()-50):m.start()], re.IGNORECASE) else \
                     "executed" if re.search(r'execut|ran|running|spawn|launch|command', text[max(0, m.start()-50):m.start()], re.IGNORECASE) else \
                     "created" if re.search(r'creat|install|drop|download', text[max(0, m.start()-50):m.start()], re.IGNORECASE) else "executed"
            results.append({"value": p, "action": action, "context": ""})
    for m in re.finditer(r'"([A-Za-z]:\\[^"]+)"', text):
        p = m.group(1)
        if p.lower() not in seen:
            seen.add(p.lower())
            results.append({"value": p, "action": "executed", "context": ""})
    for m in re.finditer(r'(?<!\w)([A-Za-z]:\\(?:Users|Windows|Program Files|ProgramData)[^\s"\'<>|*,]+\.\w{2,4})\b', text):
        p = m.group(1)
        if p.lower() not in seen:
            seen.add(p.lower())
            results.append({"value": p, "action": "executed", "context": ""})
    return results


def extract_users(text):
    """Extract user accounts and SIDs."""
    users = []
    seen = set()
    for m in re.finditer(r'["\']?([\w.-]+\\[\w.-]+)["\']?\s*(?:\(|\s)?\s*(?:SID:\s*)?(S-1-5-[\d-]+)', text):
        domain_user = m.group(1)
        sid = m.group(2)
        parts = domain_user.split("\\")
        domain = parts[0] if len(parts) > 1 else ""
        username = parts[-1]
        key = sid.lower()
        if key not in seen:
            seen.add(key)
            users.append({"username": username, "sid": sid, "domain": domain})
    for m in re.finditer(r'user\s+(?:account\s+)?["\']([^"\']+)["\'].*?(S-1-5-[\d-]+)', text, re.IGNORECASE):
        username = m.group(1)
        sid = m.group(2)
        if sid.lower() not in seen:
            seen.add(sid.lower())
            users.append({"username": username, "sid": sid, "domain": ""})
    for m in re.finditer(r'(?:SID:\s*)(S-1-5-[\d-]+)', text):
        sid = m.group(1)
        if sid.lower() not in seen:
            seen.add(sid.lower())
            user_match = re.search(rf'["\']([^"\']+)["\'].*?{re.escape(sid)}', text)
            username = user_match.group(1) if user_match else ""
            users.append({"username": username, "sid": sid, "domain": ""})
    return users


def extract_timestamps(text):
    """Extract timestamps with event context."""
    results = []
    for m in re.finditer(r'(?:At|at|on|On)\s+["\']?((?:\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\s*(?:UTC)?)|(?:\d{4}-\d{2}-\d{2}))["\']?\s*[,:]?\s*(.{10,120}?)(?:\.|$)', text):
        ts = m.group(1).strip()
        event = m.group(2).strip()[:100]
        user_match = re.search(r'user\s+["\']?([^"\',(]+)', event, re.IGNORECASE)
        user = user_match.group(1).strip() if user_match else ""
        results.append({"time": ts, "event": event, "user": user})
    for m in re.finditer(r'(?:Detected At|Start Time|Remediated At):\s*(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\s*(?:UTC)?)', text):
        label_match = re.search(r'(Detected At|Start Time|Remediated At)', text[max(0, m.start()-20):m.start()+20])
        label = label_match.group(1) if label_match else "detected"
        results.append({"time": m.group(1).strip(), "event": label, "user": ""})
    return results


def extract_services(text):
    """Extract Windows services mentioned in remediations."""
    results = []
    for m in re.finditer(r'Delete Service\s*-\s*name:\s*(.+?)(?:\n|$)', text):
        name = m.group(1).strip()
        results.append({"name": name, "display_name": name, "path": "", "action": "delete"})
    return results


def extract_scheduled_tasks(text):
    """Extract scheduled tasks from remediations."""
    results = []
    for m in re.finditer(r'Delete Scheduled Task\s*-\s*name:\s*(.+?)(?:\n|$)', text):
        name = m.group(1).strip()
        results.append({"name": name, "path": "", "command": "", "action": "delete"})
    return results


def extract_registry(text):
    """Extract registry keys from remediations."""
    results = []
    for m in re.finditer(r'Delete Registry (?:Key|Value)\s*-\s*key:\s*(.+?)(?:\s*\+\s*value:\s*(.+?))?(?:\n|$)', text):
        key = m.group(1).strip()
        value = m.group(2).strip() if m.group(2) else ""
        results.append({"key": key, "value_name": value, "value_data": "", "action": "delete", "context": ""})
    return results


def extract_commands(text):
    """Extract command lines from Lead Signal and report body."""
    results = []
    cmd_match = re.search(r'Command:\s*(.+?)(?:\n|$)', text)
    exe_match = re.search(r'Executable:\s*(.+?)(?:\n|$)', text)
    parent_match = re.search(r'Parent Process:\s*(.+?)(?:\n|$)', text)
    user_match = re.search(r'User:\s*(.+?)(?:\n|$)', text)
    pid_match = re.search(r'Process ID:\s*(.+?)(?:\n|$)', text)

    if cmd_match:
        cmd = cmd_match.group(1).strip().strip('"')
        exe = exe_match.group(1).strip() if exe_match else ""
        parent = parent_match.group(1).strip() if parent_match else ""
        user = user_match.group(1).strip() if user_match else ""
        pid = pid_match.group(1).strip() if pid_match else ""
        args = cmd.replace(exe, "").strip().strip('"').strip() if exe and exe in cmd else ""
        results.append({
            "full_command": cmd,
            "executable": exe,
            "arguments": args,
            "parent_process": parent,
            "user": user,
            "pid": pid,
            "context": ""
        })

    for m in re.finditer(r'Kill Process\s*-\s*path:\s*(.+?)\s*\+\s*pid:\s*(\d+)', text):
        path = m.group(1).strip()
        pid = m.group(2).strip()
        if not any(r["executable"] == path for r in results):
            results.append({
                "full_command": path,
                "executable": path,
                "arguments": "",
                "parent_process": "",
                "user": "",
                "pid": pid,
                "context": "killed during remediation"
            })
    return results


def extract_cloudflare_tunnels(text):
    """Extract Cloudflare tunnel URLs."""
    clean = defang_to_clean(text)
    tunnels = []
    for m in re.finditer(r'(https?://[^\s"\']*trycloudflare\.com[^\s"\']*)', clean):
        tunnels.append(m.group(1).rstrip(".,;)'"))
    return tunnels


def extract_encoded_powershell(text):
    """Extract base64-encoded PowerShell commands."""
    results = []
    for m in re.finditer(r'-(?:enc|EncodedCommand)\s+([A-Za-z0-9+/=]{20,})', text):
        results.append(m.group(1))
    return results


def extract_screenconnect_params(text):
    """Extract ScreenConnect relay parameters."""
    results = []
    for m in re.finditer(r'\?e=Access&[^\s"\']+', text):
        results.append(m.group(0)[:200])
    return results


def determine_attack_type(text):
    """Determine the attack type from report content."""
    lower = text.lower()
    if "cobalt strike" in lower:
        return "Command and Control - Cobalt Strike"
    if "ransomware" in lower:
        return "Ransomware"
    if "lateral mov" in lower:
        return "Lateral Movement"
    if "brute force" in lower or "password spray" in lower:
        return "Credential Attack"
    if "infostealer" in lower or "info stealer" in lower:
        return "InfoStealer"
    if "remote access trojan" in lower or "rat" in lower.split():
        return "Remote Access Trojan"
    if "rogue screenconnect" in lower or "rogue simplehelp" in lower or "malicious remote management" in lower:
        return "Rogue Remote Management Tool"
    if "phishing" in lower or "captcha" in lower:
        return "Phishing / Social Engineering"
    if "webshell" in lower:
        return "Web Shell"
    if "enumeration" in lower:
        return "Reconnaissance / Enumeration"
    if "persistence" in lower:
        return "Persistence"
    if "malicious download" in lower:
        return "Malware Download"
    return "malware"


def determine_severity(text):
    lower = text.lower()
    for keyword, sev in THREAT_SEVERITY.items():
        if keyword in lower:
            return sev
    return "medium"


def extract_mitre(text):
    """Map report content to MITRE ATT&CK techniques."""
    lower = text.lower()
    seen = set()
    results = []
    for keyword, techniques in MITRE_KEYWORDS.items():
        if re.search(keyword, lower):
            for tid, tname in techniques:
                if tid not in seen:
                    seen.add(tid)
                    evidence_match = re.search(rf'.{{0,80}}{keyword}.{{0,80}}', lower)
                    evidence = evidence_match.group(0).strip()[:120] if evidence_match else ""
                    results.append({"technique_id": tid, "technique_name": tname, "evidence": evidence})
    return results[:10]


def extract_threat_families(text):
    """Extract threat/malware family names."""
    families = []
    lower = text.lower()
    known = [
        ("Cobalt Strike", "cobalt strike"),
        ("ScreenConnect", "rogue screenconnect"),
        ("AnyDesk", "anydesk"),
        ("SimpleHelp", "simplehelp"),
        ("ITarian", "itarian"),
        ("GoTo Assist", "goto assist"),
        ("TeamViewer", "teamviewer"),
    ]
    for name, pattern in known:
        if pattern in lower:
            families.append(name)
    for m in re.finditer(r'Malware Family[:\s]+["\']?([^"\'.\n]+)', text, re.IGNORECASE):
        f = m.group(1).strip()
        if f and f not in families:
            families.append(f)
    for m in re.finditer(r'Threat Name:\s*(.+?)(?:\n|$)', text):
        f = m.group(1).strip()
        if f and f not in families and len(f) < 80:
            families.append(f)
    return families


def extract_rmm_tools(text):
    """Extract RMM tools mentioned."""
    tools = []
    lower = text.lower()
    rmm_list = [
        ("ScreenConnect", "screenconnect"),
        ("AnyDesk", "anydesk"),
        ("SimpleHelp", "simplehelp"),
        ("ITarian", "itarian"),
        ("GoTo Assist", "goto assist"),
        ("TeamViewer", "teamviewer"),
        ("Splashtop", "splashtop"),
        ("Atera", "atera"),
        ("NetSupport", "netsupport"),
    ]
    for name, pattern in rmm_list:
        if pattern in lower:
            tools.append(name)
    return tools


def extract_report_date(text):
    """Extract the primary date from the report."""
    m = re.search(r'(\d{4}-\d{2}-\d{2})', text)
    return m.group(1) if m else ""


def extract_hostnames(text):
    """Extract affected host names."""
    hosts = set()
    for m in re.finditer(r'(?:host|endpoint|machine|Host Name:)\s*["\']?([A-Z0-9][-A-Z0-9]{3,20})["\']?', text, re.IGNORECASE):
        h = m.group(1).strip()
        if h.upper() not in ("UTC", "SYSTEM", "NONE", "UNKNOWN", "NULL"):
            hosts.add(h)
    return list(hosts)


def extract_cves(text):
    """Extract CVE identifiers."""
    return list(set(re.findall(r'(CVE-\d{4}-\d{4,7})', text, re.IGNORECASE)))


def extract_exposed_services(text):
    """Extract exposed services mentioned."""
    services = []
    lower = text.lower()
    if "rdp" in lower or "rds" in lower or "rdweb" in lower or "rdg" in lower:
        services.append("RDP/RDS")
    if "exchange" in lower:
        services.append("Exchange")
    if "vpn" in lower:
        services.append("VPN")
    return services


def process_report(report_text):
    """Extract all IOCs from a single report."""
    users = extract_users(report_text)
    ips = extract_ips(report_text)
    domains = extract_domains(report_text)
    urls = extract_urls(report_text)
    hashes = extract_hashes(report_text)
    file_paths = extract_file_paths(report_text)
    commands = extract_commands(report_text)
    services = extract_services(report_text)
    tasks = extract_scheduled_tasks(report_text)
    registry = extract_registry(report_text)
    timestamps = extract_timestamps(report_text)
    mitre = extract_mitre(report_text)
    threat_families = extract_threat_families(report_text)
    rmm_tools = extract_rmm_tools(report_text)
    cloudflare = extract_cloudflare_tunnels(report_text)
    encoded_ps = extract_encoded_powershell(report_text)
    sc_params = extract_screenconnect_params(report_text)
    cves = extract_cves(report_text)
    exposed = extract_exposed_services(report_text)
    hostnames = extract_hostnames(report_text)

    is_isolated = bool(re.search(r'(?:has been|been|was)\s+isolated', report_text, re.IGNORECASE))

    file_names = list(set(
        os.path.basename(fp["value"]) for fp in file_paths
        if os.path.basename(fp["value"]) and "." in os.path.basename(fp["value"])
    ))

    return {
        "extraction_summary": {
            "report_date": extract_report_date(report_text),
            "affected_hosts": hostnames,
            "affected_users": users,
            "attack_type": determine_attack_type(report_text),
            "severity": determine_severity(report_text),
            "threat_families": threat_families,
            "isolated": is_isolated
        },
        "network_iocs": {
            "ipv4": ips,
            "ipv6": [],
            "domains": domains,
            "urls": urls,
            "cloudflare_tunnels": cloudflare
        },
        "file_iocs": {
            "hashes": hashes,
            "file_paths": file_paths,
            "file_names": file_names
        },
        "process_iocs": {
            "commands": commands,
            "services": services,
            "scheduled_tasks": tasks,
            "parent_child_chains": []
        },
        "persistence_iocs": {
            "registry": registry,
            "credential_theft_indicators": []
        },
        "authentication_iocs": {
            "compromised_users": [{"username": u["username"], "sid": u["sid"], "domain": u["domain"], "context": "compromised account"} for u in users],
            "created_users": [],
            "passwords_observed": []
        },
        "vulnerability_iocs": {
            "cves": cves,
            "exchange_version": "",
            "exposed_services": exposed,
            "webshells": []
        },
        "threat_intel": {
            "malware_families": threat_families,
            "threat_names": [f["value"] for f in extract_threat_families(report_text)] if False else threat_families,
            "rmm_tools": rmm_tools,
            "techniques": [f"{t['technique_id']} - {t['technique_name']}" for t in mitre]
        },
        "timestamps": timestamps,
        "raw_artifacts": {
            "encoded_powershell": encoded_ps,
            "vnc_connection_ids": [],
            "screenconnect_relay_params": sc_params[:3]
        },
        "mitre_attack": mitre
    }


def count_iocs(extraction):
    count = 0
    net = extraction.get("network_iocs", {})
    count += len(net.get("ipv4", [])) + len(net.get("domains", []))
    count += len(net.get("urls", []))
    fi = extraction.get("file_iocs", {})
    count += len(fi.get("hashes", [])) + len(fi.get("file_paths", []))
    pi = extraction.get("process_iocs", {})
    count += len(pi.get("commands", [])) + len(pi.get("services", []))
    pe = extraction.get("persistence_iocs", {})
    count += len(pe.get("registry", []))
    count += len(extraction.get("timestamps", []))
    count += len(extraction.get("mitre_attack", []))
    return count


def make_sample(report_text, extraction_json, prompt_idx=0):
    user_prompt = USER_PROMPTS[prompt_idx % len(USER_PROMPTS)].format(report_text)
    return {
        "conversations": [
            {"from": "system", "value": SYSTEM_PROMPT},
            {"from": "human", "value": user_prompt},
            {"from": "gpt", "value": json.dumps(extraction_json, indent=2)},
        ]
    }


def build_empty_extraction():
    return {
        "extraction_summary": {
            "report_date": "", "affected_hosts": [], "affected_users": [],
            "attack_type": "", "severity": "", "threat_families": [], "isolated": False
        },
        "network_iocs": {"ipv4": [], "ipv6": [], "domains": [], "urls": [], "cloudflare_tunnels": []},
        "file_iocs": {"hashes": [], "file_paths": [], "file_names": []},
        "process_iocs": {"commands": [], "services": [], "scheduled_tasks": [], "parent_child_chains": []},
        "persistence_iocs": {"registry": [], "credential_theft_indicators": []},
        "authentication_iocs": {"compromised_users": [], "created_users": [], "passwords_observed": []},
        "vulnerability_iocs": {"cves": [], "exchange_version": "", "exposed_services": [], "webshells": []},
        "threat_intel": {"malware_families": [], "threat_names": [], "rmm_tools": [], "techniques": []},
        "timestamps": [],
        "raw_artifacts": {"encoded_powershell": [], "vnc_connection_ids": [], "screenconnect_relay_params": []},
        "mitre_attack": []
    }


def main():
    report_files = sorted(glob.glob(os.path.join(REPORTS_DIR, "**/*.txt"), recursive=True))
    print(f"Found {len(report_files)} reports", flush=True)
    samples = []
    failed = []

    for i, filepath in enumerate(report_files):
        basename = os.path.relpath(filepath, REPORTS_DIR)
        with open(filepath, 'r', errors='replace') as f:
            report_text = f.read().strip()
        if len(report_text) < 50:
            print(f"  [{i+1}/{len(report_files)}] Skipping {basename} (too short)", flush=True)
            continue

        try:
            extraction = process_report(report_text)
            ioc_count = count_iocs(extraction)
            print(f"  [{i+1}/{len(report_files)}] {basename}: {ioc_count} IOCs", flush=True)

            samples.append(make_sample(report_text, extraction, prompt_idx=0))
            alt_idx = random.randint(1, len(USER_PROMPTS) - 1)
            samples.append(make_sample(report_text, extraction, prompt_idx=alt_idx))
            if ioc_count >= 8:
                alt_idx2 = random.choice([j for j in range(len(USER_PROMPTS)) if j not in (0, alt_idx)])
                samples.append(make_sample(report_text, extraction, prompt_idx=alt_idx2))
        except Exception as e:
            print(f"  [{i+1}/{len(report_files)}] FAILED {basename}: {e}", flush=True)
            failed.append(basename)

    print(f"\nAdding {len(NEGATIVE_TEXTS)} negative examples...", flush=True)
    empty = build_empty_extraction()
    for neg_text in NEGATIVE_TEXTS:
        for p in range(2):
            samples.append(make_sample(neg_text, empty, prompt_idx=p))

    random.shuffle(samples)
    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    with open(OUTPUT_FILE, 'w') as f:
        for sample in samples:
            f.write(json.dumps(sample) + '\n')

    print(f"\n{'='*60}", flush=True)
    print(f"TRAINING DATA SUMMARY", flush=True)
    print(f"{'='*60}", flush=True)
    print(f"  Reports processed: {len(report_files) - len(failed)}/{len(report_files)}", flush=True)
    print(f"  Failed: {len(failed)}", flush=True)
    print(f"  Total samples: {len(samples)}", flush=True)
    print(f"  Negative samples: {len(NEGATIVE_TEXTS) * 2}", flush=True)
    print(f"  Output: {OUTPUT_FILE}", flush=True)
    if failed:
        print(f"  Failed files: {failed}", flush=True)


if __name__ == '__main__':
    main()
