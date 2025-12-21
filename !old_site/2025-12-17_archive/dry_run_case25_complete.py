#!/usr/bin/env python3
"""
AI Triage Search - COMPLETE Dry Run - Case 25
Following EXACTLY the methodology from ai_triage_search_methodology.md
"""

import json
import re
from datetime import datetime, timedelta
from opensearchpy import OpenSearch

# Connect to OpenSearch
opensearch_client = OpenSearch(
    hosts=[{"host": "localhost", "port": 9200}],
    http_auth=None,
    use_ssl=False
)

case_id = 25
index_name = f"case_{case_id}"

print("=" * 80)
print("AI TRIAGE SEARCH - COMPLETE DRY RUN - CASE 25")
print("Following ai_triage_search_methodology.md EXACTLY")
print("=" * 80)

# The EDR report from case description
report = r"""
Evidence suggests that the user tabadmin (S-1-5-21-2922803321-3646860260-2870289857-1142) has been compromised. Huntress observed the following timeline: 

- At 2025-08-12 06:57 UTC, tabadmin authenticated to CM-DC01 from the internal IP 192.168.0.254, this suggests the use of a gateway device. There is a Sonicwall gateway device in place on 96.78.213.49:60443. Huntress recommends auditing this device as a potential point of initial access.
- At 07:01 UTC, tabadmin authenticated to CM-DC01 from the internal IP 172.16.10.25
- At 07:01 UTC, tabadmin authenticated to CM-DC01 from the internal host CM-VMHOST (192.168.0.8)
- At 07:10 UTC, tabadmin authenticated to CM-DC01 from the internal host WIN-HU67JDG9MF1 (172.16.10.26). Huntress has associated this hostname with malicious intrusions. 
- 07:12 UTC, tabadmin enumerated the domain trusts
- 07:13 UTC, tabadmin accessed the files C:\ProgramData\AdUsers.txt and C:\ProgramData\AdComp.txt 
- 07:14 UTC, tabadmin executed C:\Users\tabadmin\AppData\Local\Temp\2\Advanced IP Scanner 2\advanced_ip_scanner.exe to enumerate the network 
"""

# Report timestamp for 24h window
report_timestamp = datetime(2025, 8, 12, 7, 13, 0)  # 2025-08-12 07:13 UTC
window_start = (report_timestamp - timedelta(hours=24)).isoformat() + "Z"
window_end = (report_timestamp + timedelta(hours=24)).isoformat() + "Z"

print(f"\nReport Timestamp: {report_timestamp}")
print(f"24h Window: {window_start} to {window_end}")

# ============================================================================
# PHASE 1: IOC EXTRACTION FROM REPORT
# ============================================================================
print("\n" + "=" * 80)
print("PHASE 1: IOC EXTRACTION FROM REPORT")
print("=" * 80)

iocs = {
    "ips": [],
    "hostnames": [],
    "usernames": [],
    "sids": [],
    "paths": [],
    "processes": [],
    "commands": [],
    "threats": [],
    "hashes": [],
    "tools": []
}

# IPs
ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
iocs["ips"] = list(set(re.findall(ip_pattern, report)))

# Hostnames - multiple patterns
hostname_matches = []
# Pattern: "to CM-DC01" or "host CM-VMHOST"
hostname_matches += re.findall(r"to\s+([A-Z][A-Z0-9-]{2,14})\b", report, re.IGNORECASE)
hostname_matches += re.findall(r"host\s+([A-Z][A-Z0-9-]{2,14})\b", report, re.IGNORECASE)
# Pattern: "(192.168.0.8)" preceded by hostname
hostname_matches += re.findall(r"([A-Z][A-Z0-9-]{2,14})\s*\(\d+\.\d+\.\d+\.\d+\)", report, re.IGNORECASE)
NOT_HOSTNAMES = ['UTC', 'THE', 'FROM', 'THIS', 'THAT', 'ENUMERATE', 'SID', 'INTERNAL', 'SUGGESTS', 'OBSERVED']
for m in hostname_matches:
    if m.upper() not in NOT_HOSTNAMES and len(m) > 2:
        iocs["hostnames"].append(m.upper())
iocs["hostnames"] = list(set(iocs["hostnames"]))

# Usernames - pattern: "user tabadmin" or "user 'tabadmin'"
username_matches = re.findall(r"user\s+['\"]?([a-zA-Z][a-zA-Z0-9_]{2,19})['\"]?", report, re.IGNORECASE)
for m in username_matches:
    if m.lower() not in ["the", "this", "that", "from", "account", "has", "been"]:
        iocs["usernames"].append(m.lower())
iocs["usernames"] = list(set(iocs["usernames"]))

# SIDs
sid_pattern = r'S-1-5-21-\d+-\d+-\d+-\d+'
iocs["sids"] = list(set(re.findall(sid_pattern, report)))

# Paths (files accessed)
path_pattern = r"[A-Z]:\\[^\s'\"]+\.(?:exe|txt|dll|bat|ps1|cmd)"
iocs["paths"] = list(set(re.findall(path_pattern, report, re.IGNORECASE)))

# Processes (extract from paths)
for path in iocs["paths"]:
    if path.lower().endswith(".exe"):
        proc = path.split("\\")[-1]
        iocs["processes"].append(proc)
iocs["processes"] = list(set(iocs["processes"]))

# Tools mentioned
if "Advanced IP Scanner" in report:
    iocs["tools"].append("Advanced IP Scanner")
if "nltest" in report.lower() or "domain trusts" in report.lower():
    iocs["commands"].append("nltest /domain_trusts")

print("\n📋 EXTRACTED IOCs FROM REPORT:")
print("-" * 40)
for ioc_type, values in iocs.items():
    if values:
        print(f"  {ioc_type.upper()}:")
        for v in values:
            print(f"    - {v}")

# ============================================================================
# PHASE 2: IOC CLASSIFICATION (SPECIFIC vs BROAD)
# ============================================================================
print("\n" + "=" * 80)
print("PHASE 2: IOC CLASSIFICATION")
print("=" * 80)

specific_iocs = {
    "processes": iocs.get("processes", []),
    "paths": iocs.get("paths", []),
    "hashes": iocs.get("hashes", []),
    "commands": iocs.get("commands", []),
    "threats": iocs.get("threats", []),
    "tools": iocs.get("tools", [])
}

broad_iocs = {
    "usernames": iocs.get("usernames", []),
    "hostnames": iocs.get("hostnames", []),
    "ips": iocs.get("ips", []),
    "sids": iocs.get("sids", [])
}

print("\n🎯 SPECIFIC IOCs (will AUTO-TAG):")
for k, v in specific_iocs.items():
    if v:
        print(f"  {k}: {v}")

print("\n🔍 BROAD IOCs (AGGREGATION ONLY):")
for k, v in broad_iocs.items():
    if v:
        print(f"  {k}: {v}")

# ============================================================================
# PHASE 3: ITERATIVE SNOWBALL HUNTING (24h window)
# ============================================================================
print("\n" + "=" * 80)
print("PHASE 3: ITERATIVE SNOWBALL HUNTING")
print(f"Window: ±24h from {report_timestamp}")
print("=" * 80)

discovered = {
    "hostnames": set(),
    "usernames": set(),
    "ips": set()
}

# Track what we've already searched
searched_ips = set()
searched_hostnames = set()

def search_and_extract(search_term, search_type):
    """Search for a term and extract new IOCs from results"""
    new_hostnames = set()
    new_usernames = set()
    new_ips = set()
    
    query = {
        "query": {
            "bool": {
                "must": [
                    {"query_string": {"query": f'"{search_term}"', "default_operator": "AND"}},
                    {"range": {"@timestamp": {"gte": window_start, "lte": window_end}}}
                ]
            }
        },
        "size": 500,
        "aggs": {
            "hosts": {"terms": {"field": "normalized_computer.keyword", "size": 50}},
            "users": {"terms": {"field": "process.user.name.keyword", "size": 50}},
            "ips": {"terms": {"field": "host.ip.keyword", "size": 50}}
        }
    }
    
    try:
        result = opensearch_client.search(index=index_name, body=query)
        hit_count = result["hits"]["total"]["value"]
        
        # Extract from aggregations
        for bucket in result.get("aggregations", {}).get("hosts", {}).get("buckets", []):
            if bucket["key"] and bucket["key"] not in ["-", ""]:
                new_hostnames.add(bucket["key"])
        
        for bucket in result.get("aggregations", {}).get("users", {}).get("buckets", []):
            if bucket["key"] and bucket["key"] not in ["-", "", "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE"]:
                if not bucket["key"].endswith("$"):  # Filter machine accounts
                    new_usernames.add(bucket["key"])
        
        for bucket in result.get("aggregations", {}).get("ips", {}).get("buckets", []):
            if bucket["key"] and not bucket["key"].startswith("127."):
                new_ips.add(bucket["key"])
        
        # Also extract from hits for EDR nested fields
        for hit in result["hits"]["hits"]:
            src = hit["_source"]
            
            # Hostname from normalized_computer or host.hostname
            hostname = src.get("normalized_computer") or src.get("host", {}).get("hostname")
            if hostname and hostname not in ["-", ""]:
                new_hostnames.add(hostname)
            
            # Username from process.user.name
            user = src.get("process", {}).get("user", {}).get("name")
            if user and user not in ["SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "-", ""] and not user.endswith("$"):
                new_usernames.add(user)
            
            # IP from various fields
            for ip_field in [src.get("host", {}).get("ip"), src.get("source", {}).get("ip")]:
                if ip_field:
                    if isinstance(ip_field, list):
                        for ip in ip_field:
                            if ip and not ip.startswith("127."):
                                new_ips.add(ip)
                    elif not ip_field.startswith("127."):
                        new_ips.add(ip_field)
        
        return hit_count, new_hostnames, new_usernames, new_ips
    except Exception as e:
        print(f"    Error: {e}")
        return 0, set(), set(), set()

# Round 1: Search IPs from report
print("\n🔄 ROUND 1: Hunting IPs from report")
print("-" * 40)
for ip in iocs["ips"]:
    if ip in searched_ips:
        continue
    searched_ips.add(ip)
    
    count, hosts, users, ips = search_and_extract(ip, "ip")
    print(f"  IP: {ip}")
    print(f"    → {count:,} events in 24h window")
    print(f"    → Hosts: {list(hosts)[:5]}")
    print(f"    → Users: {list(users)[:5]}")
    print(f"    → IPs: {list(ips)[:5]}")
    
    discovered["hostnames"].update(hosts)
    discovered["usernames"].update(users)
    discovered["ips"].update(ips)

# Round 1: Search hostnames from report
print("\n🔄 ROUND 1: Hunting hostnames from report")
print("-" * 40)
for hostname in iocs["hostnames"]:
    if hostname in searched_hostnames:
        continue
    searched_hostnames.add(hostname)
    
    count, hosts, users, ips = search_and_extract(hostname, "hostname")
    print(f"  Hostname: {hostname}")
    print(f"    → {count:,} events in 24h window")
    print(f"    → Users: {list(users)[:5]}")
    print(f"    → IPs: {list(ips)[:5]}")
    
    discovered["usernames"].update(users)
    discovered["ips"].update(ips)

# Round 2: Search NEW hostnames discovered in Round 1
print("\n🔄 ROUND 2: Hunting NEW hostnames from Round 1")
print("-" * 40)
new_hostnames_r1 = discovered["hostnames"] - set(iocs["hostnames"])
for hostname in list(new_hostnames_r1)[:10]:  # Limit to 10 for performance
    if hostname in searched_hostnames:
        continue
    searched_hostnames.add(hostname)
    
    count, hosts, users, ips = search_and_extract(hostname, "hostname")
    if count > 0:
        print(f"  NEW Hostname: {hostname}")
        print(f"    → {count:,} events")
        print(f"    → Users: {list(users)[:3]}")
        print(f"    → IPs: {list(ips)[:3]}")
        
        discovered["usernames"].update(users)
        discovered["ips"].update(ips)

# Summary of discovered IOCs
print("\n📊 SNOWBALL HUNTING SUMMARY:")
print("-" * 40)
print(f"  Started with:")
print(f"    - {len(iocs['ips'])} IPs")
print(f"    - {len(iocs['hostnames'])} hostnames")
print(f"    - {len(iocs['usernames'])} usernames")
print(f"\n  Discovered:")
print(f"    - {len(discovered['hostnames'])} total hostnames")
print(f"    - {len(discovered['usernames'])} total usernames")
print(f"    - {len(discovered['ips'])} total IPs")
print(f"\n  NEW IOCs found:")
new_hosts = discovered["hostnames"] - set(iocs["hostnames"])
new_users = discovered["usernames"] - set(iocs["usernames"])
new_ips = discovered["ips"] - set(iocs["ips"])
print(f"    - {len(new_hosts)} new hostnames: {list(new_hosts)[:10]}")
print(f"    - {len(new_users)} new usernames: {list(new_users)[:10]}")
print(f"    - {len(new_ips)} new IPs: {list(new_ips)[:10]}")

# ============================================================================
# PHASE 4: MALWARE/RECON HUNTING
# ============================================================================
print("\n" + "=" * 80)
print("PHASE 4: MALWARE/RECON HUNTING")
print("=" * 80)

# Search for specific recon commands and tools
recon_searches = [
    ("nltest", "Domain Trust Enumeration"),
    ("whoami", "User Discovery"),
    ("ipconfig", "Network Config Discovery"),
    ("advanced_ip_scanner", "Network Scanning Tool"),
    ("AdUsers.txt", "User List Access"),
    ("AdComp.txt", "Computer List Access"),
]

recon_events = []
print("\n🔍 Searching for recon/malware indicators:")
print("-" * 40)

for term, description in recon_searches:
    query = {
        "query": {
            "bool": {
                "must": [
                    {"query_string": {"query": f"*{term}*", "default_operator": "AND"}},
                    {"range": {"@timestamp": {"gte": window_start, "lte": window_end}}}
                ]
            }
        },
        "sort": [{"@timestamp": "asc"}],
        "size": 100
    }
    
    try:
        result = opensearch_client.search(index=index_name, body=query)
        count = result["hits"]["total"]["value"]
        print(f"  {term} ({description}): {count:,} events")
        
        for hit in result["hits"]["hits"]:
            recon_events.append({
                "id": hit["_id"],
                "source": hit["_source"],
                "term": term,
                "description": description
            })
    except Exception as e:
        print(f"  {term}: Error - {e}")

# ============================================================================
# PHASE 5: SPECIFIC IOC SEARCH + AUTO-TAG COUNT
# ============================================================================
print("\n" + "=" * 80)
print("PHASE 5: SPECIFIC IOC SEARCH (Auto-Tag Candidates)")
print("=" * 80)

auto_tag_events = []
for ioc_type, values in specific_iocs.items():
    for value in values:
        if not value:
            continue
        
        query = {
            "query": {
                "bool": {
                    "must": [
                        {"query_string": {"query": f"*{value}*", "default_operator": "AND"}},
                        {"range": {"@timestamp": {"gte": window_start, "lte": window_end}}}
                    ]
                }
            },
            "size": 1000
        }
        
        try:
            result = opensearch_client.search(index=index_name, body=query)
            count = result["hits"]["total"]["value"]
            print(f"  {ioc_type}: '{value}' → {count:,} events")
            
            for hit in result["hits"]["hits"]:
                auto_tag_events.append({
                    "id": hit["_id"],
                    "source": hit["_source"],
                    "ioc_type": ioc_type,
                    "matched_ioc": value
                })
        except Exception as e:
            print(f"  Error: {e}")

print(f"\n  🏷️ TOTAL EVENTS TO AUTO-TAG: {len(auto_tag_events)}")

# ============================================================================
# PHASE 6: TIME WINDOW ANALYSIS (±5 min around key events)
# ============================================================================
print("\n" + "=" * 80)
print("PHASE 6: TIME WINDOW ANALYSIS (±5 min around key events)")
print("=" * 80)

# Key timestamps from report
key_timestamps = [
    ("2025-08-12T06:57:00Z", "CM-DC01", "Initial auth from gateway"),
    ("2025-08-12T07:10:00Z", "CM-DC01", "Auth from malicious host WIN-HU67JDG9MF1"),
    ("2025-08-12T07:12:00Z", "CM-DC01", "Domain trust enumeration"),
    ("2025-08-12T07:13:00Z", "CM-DC01", "AdUsers/AdComp access"),
    ("2025-08-12T07:14:00Z", "CM-DC01", "Advanced IP Scanner execution"),
]

window_events = []
print("\n⏱️ Analyzing time windows:")
print("-" * 40)

for ts, hostname, description in key_timestamps:
    anchor_time = datetime.fromisoformat(ts.replace('Z', ''))
    start = (anchor_time - timedelta(minutes=5)).isoformat() + "Z"
    end = (anchor_time + timedelta(minutes=5)).isoformat() + "Z"
    
    query = {
        "query": {
            "bool": {
                "must": [
                    {"term": {"normalized_computer.keyword": hostname}},
                    {"range": {"@timestamp": {"gte": start, "lte": end}}}
                ]
            }
        },
        "sort": [{"@timestamp": "asc"}],
        "size": 500
    }
    
    try:
        result = opensearch_client.search(index=index_name, body=query)
        count = result["hits"]["total"]["value"]
        print(f"  {ts[:19]} | {hostname} | {description}")
        print(f"    → {count:,} events in ±5 min window")
        
        for hit in result["hits"]["hits"]:
            window_events.append(hit["_source"])
    except Exception as e:
        print(f"    Error: {e}")

print(f"\n  Total events in time windows: {len(window_events):,}")

# ============================================================================
# PHASE 7: PROCESS TREE BUILDING
# ============================================================================
print("\n" + "=" * 80)
print("PHASE 7: PROCESS TREE BUILDING")
print("=" * 80)

# Find cmd.exe or powershell.exe parent processes
suspicious_parents = {}
for event in window_events:
    proc = event.get("process", {})
    parent = proc.get("parent", {})
    parent_name = (parent.get("name") or "").lower()
    parent_pid = parent.get("pid")
    proc_name = (proc.get("name") or "").lower()
    hostname = event.get("normalized_computer")
    
    if parent_name in ["cmd.exe", "powershell.exe"] and parent_pid and hostname:
        key = f"{hostname}|{parent_pid}"
        if key not in suspicious_parents:
            suspicious_parents[key] = {
                "parent_name": parent_name,
                "parent_pid": parent_pid,
                "hostname": hostname,
                "children": []
            }
        suspicious_parents[key]["children"].append({
            "name": proc_name,
            "command_line": proc.get("command_line", ""),
            "timestamp": event.get("@timestamp")
        })

print(f"\n🌳 Process Trees Found: {len(suspicious_parents)}")
print("-" * 40)

for key, tree in list(suspicious_parents.items())[:5]:
    print(f"\n  {tree['parent_name']} (PID: {tree['parent_pid']}) on {tree['hostname']}")
    for child in sorted(tree["children"], key=lambda x: x.get("timestamp", "")):
        ts = child.get("timestamp", "")[:19] if child.get("timestamp") else ""
        cmd = child.get("command_line", "")[:60]
        print(f"    └── {ts} | {child['name']} | {cmd}")

# ============================================================================
# PHASE 8: MITRE ATT&CK PATTERN MATCHING
# ============================================================================
print("\n" + "=" * 80)
print("PHASE 8: MITRE ATT&CK PATTERN MATCHING")
print("=" * 80)

MITRE_PATTERNS = {
    'T1033': {'name': 'System Owner/User Discovery', 'processes': ['whoami.exe', 'quser.exe'], 'indicators': ['whoami', '/all']},
    'T1482': {'name': 'Domain Trust Discovery', 'processes': ['nltest.exe'], 'indicators': ['domain_trusts', '/all_trusts']},
    'T1018': {'name': 'Remote System Discovery', 'processes': ['nltest.exe', 'ping.exe', 'nslookup.exe'], 'indicators': ['dclist', 'ping', 'net view', 'advanced_ip_scanner']},
    'T1016': {'name': 'System Network Config Discovery', 'processes': ['ipconfig.exe', 'netsh.exe'], 'indicators': ['ipconfig', 'netsh']},
    'T1087': {'name': 'Account Discovery', 'indicators': ['AdUsers', 'net user', 'net group', 'AdComp']},
    'T1078': {'name': 'Valid Accounts', 'indicators': ['tabadmin', 'logon']},
}

techniques_found = {}
technique_events = {}

for event in window_events + [e["source"] for e in recon_events]:
    proc = event.get("process", {})
    proc_name = (proc.get("name") or "").lower()
    cmd_line = (proc.get("command_line") or "").lower()
    search_blob = (event.get("search_blob") or "").lower()
    
    for tech_id, pattern in MITRE_PATTERNS.items():
        matched = False
        
        # Check process name
        for proc_pattern in pattern.get("processes", []):
            if proc_pattern.lower() in proc_name:
                matched = True
                break
        
        # Check indicators in command line or search_blob
        for indicator in pattern.get("indicators", []):
            if indicator.lower() in cmd_line or indicator.lower() in search_blob:
                matched = True
                break
        
        if matched:
            if tech_id not in techniques_found:
                techniques_found[tech_id] = {"name": pattern["name"], "count": 0}
                technique_events[tech_id] = []
            techniques_found[tech_id]["count"] += 1
            technique_events[tech_id].append(event)

print("\n🎯 MITRE ATT&CK Techniques Identified:")
print("-" * 40)
for tech_id, data in sorted(techniques_found.items()):
    print(f"  {tech_id} - {data['name']}: {data['count']} events")

# ============================================================================
# FINAL: BUILD ATTACK TIMELINE
# ============================================================================
print("\n" + "=" * 80)
print("ATTACK TIMELINE")
print("=" * 80)

# Collect all relevant events with timestamps
timeline_events = []

# From recon events
for event in recon_events:
    src = event["source"]
    ts = src.get("@timestamp", "")
    proc = src.get("process", {})
    timeline_events.append({
        "timestamp": ts,
        "hostname": src.get("normalized_computer", ""),
        "user": proc.get("user", {}).get("name", ""),
        "process": proc.get("name", ""),
        "command": proc.get("command_line", ""),
        "description": event["description"],
        "source": "recon_hunt"
    })

# From window events (filter to interesting ones)
interesting_procs = ["nltest.exe", "whoami.exe", "ipconfig.exe", "ping.exe", "cmd.exe", "powershell.exe", "advanced_ip_scanner.exe"]
for event in window_events:
    proc = event.get("process", {})
    proc_name = (proc.get("name") or "").lower()
    
    if any(p in proc_name for p in interesting_procs):
        timeline_events.append({
            "timestamp": event.get("@timestamp", ""),
            "hostname": event.get("normalized_computer", ""),
            "user": proc.get("user", {}).get("name", ""),
            "process": proc.get("name", ""),
            "command": proc.get("command_line", ""),
            "description": "Window event",
            "source": "time_window"
        })

# Deduplicate and sort
seen = set()
unique_timeline = []
for event in timeline_events:
    key = f"{event['timestamp']}|{event['command']}"
    if key not in seen:
        seen.add(key)
        unique_timeline.append(event)

unique_timeline.sort(key=lambda x: x.get("timestamp", ""))

print("\n📅 RECONSTRUCTED ATTACK TIMELINE:")
print("-" * 80)
for event in unique_timeline[:30]:
    ts = event.get("timestamp", "")[:19] if event.get("timestamp") else "N/A"
    host = event.get("hostname", "")[:15]
    user = event.get("user", "")[:12]
    proc = event.get("process", "")[:20]
    cmd = (event.get("command") or "")[:50]
    print(f"  {ts} | {host:15} | {user:12} | {proc:20} | {cmd}")

# ============================================================================
# FINAL SUMMARY
# ============================================================================
print("\n" + "=" * 80)
print("FINAL SUMMARY - CASE 25 AI TRIAGE SEARCH")
print("=" * 80)

print(f"""
📋 PHASE 1 - IOC EXTRACTION FROM REPORT:
   IPs: {len(iocs['ips'])} - {iocs['ips']}
   Hostnames: {len(iocs['hostnames'])} - {iocs['hostnames']}
   Usernames: {len(iocs['usernames'])} - {iocs['usernames']}
   SIDs: {len(iocs['sids'])}
   Paths: {len(iocs['paths'])} - {iocs['paths']}
   Processes: {len(iocs['processes'])} - {iocs['processes']}
   Commands: {len(iocs['commands'])} - {iocs['commands']}
   Tools: {len(iocs['tools'])} - {iocs['tools']}

📊 PHASE 2 - IOC CLASSIFICATION:
   SPECIFIC (auto-tag): {sum(len(v) for v in specific_iocs.values())} items
   BROAD (aggregation): {sum(len(v) for v in broad_iocs.values())} items

🔄 PHASE 3 - SNOWBALL HUNTING (24h window):
   Started with: {len(iocs['ips'])} IPs, {len(iocs['hostnames'])} hosts, {len(iocs['usernames'])} users
   Discovered: {len(discovered['hostnames'])} hosts, {len(discovered['usernames'])} users, {len(discovered['ips'])} IPs
   NEW: {len(new_hosts)} hosts, {len(new_users)} users, {len(new_ips)} IPs

🔍 PHASE 4 - MALWARE/RECON HUNTING:
   Recon events found: {len(recon_events)}

🏷️ PHASE 5 - AUTO-TAG CANDIDATES:
   Events to auto-tag: {len(auto_tag_events)}

⏱️ PHASE 6 - TIME WINDOW ANALYSIS:
   Events in ±5 min windows: {len(window_events):,}

🌳 PHASE 7 - PROCESS TREES:
   Trees built: {len(suspicious_parents)}

🎯 PHASE 8 - MITRE TECHNIQUES:
   Techniques identified: {len(techniques_found)}
   {', '.join([f"{k}: {v['name']}" for k, v in techniques_found.items()])}

📅 TIMELINE:
   Unique events: {len(unique_timeline)}
""")

print("=" * 80)
print("WHAT THE SYSTEM WOULD DO:")
print("=" * 80)
print(f"""
1. CREATE IOCs in database:
   - {len(iocs['ips'])} IPs (active)
   - {len(iocs['hostnames'])} hostnames (active) + Systems table
   - {len(iocs['usernames'])} usernames (active)
   - {len(iocs['sids'])} SIDs (INACTIVE)
   - {len(iocs['paths'])} paths (active)
   - {len(iocs['processes'])} processes (active)
   - {len(iocs['commands'])} commands (inactive - reference)
   - {len(iocs['tools'])} tools (inactive - reference)

2. ADD discovered IOCs:
   - {len(new_hosts)} new hostnames
   - {len(new_users)} new usernames
   - {len(new_ips)} new IPs

3. AUTO-TAG {len(auto_tag_events)} events (purple tags)
   (SPECIFIC IOCs: processes, paths, commands, tools)

4. BUILD {len(suspicious_parents)} process trees

5. IDENTIFY {len(techniques_found)} MITRE techniques
""")

