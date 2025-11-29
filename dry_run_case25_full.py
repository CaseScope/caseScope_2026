#!/usr/bin/env python3
"""
AI Triage Search - FULL Dry Run - Case 25
Following EXACTLY the methodology from search_notes/ai_triage_search_methodology.md
and search_notes/ai_triage_search_implementation.md
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
print("AI TRIAGE SEARCH - FULL DRY RUN - CASE 25")
print("Following exact methodology from documentation")
print("=" * 80)

# ============================================================================
# PHASE 1: DETERMINE ENTRY POINT
# ============================================================================
print("\n" + "=" * 80)
print("PHASE 1: DETERMINE ENTRY POINT")
print("=" * 80)

# Check what we have
# EDR Report exists (we know this from earlier)
has_report = True
print(f"  Has EDR Report: {has_report}")
print(f"  Entry Point: FULL TRIAGE (EDR Report Available)")

# The EDR report
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

# ============================================================================
# PHASE 2: IOC EXTRACTION FROM REPORT (using regex - simulating extract_iocs_with_regex)
# ============================================================================
print("\n" + "=" * 80)
print("PHASE 2: IOC EXTRACTION FROM REPORT")
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
    "hashes": []
}

# IPs
ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
iocs["ips"] = list(set(re.findall(ip_pattern, report)))

# Hostnames
hostname_matches = []
hostname_matches += re.findall(r"to\s+'([A-Z][A-Z0-9-]{2,14})'", report, re.IGNORECASE)
hostname_matches += re.findall(r'host\s+"?([A-Z][A-Z0-9-]{2,14})"?', report, re.IGNORECASE)
hostname_matches += re.findall(r'\(([A-Z][A-Z0-9-]{2,14})\)', report)
NOT_HOSTNAMES = ['UTC', 'THE', 'FROM', 'THIS', 'THAT', 'ENUMERATE', 'SID']
for m in hostname_matches:
    if m.upper() not in NOT_HOSTNAMES:
        iocs["hostnames"].append(m.upper())
iocs["hostnames"] = list(set(iocs["hostnames"]))

# Usernames
username_matches = re.findall(r"user\s+'([a-zA-Z][a-zA-Z0-9_]{2,19})'", report, re.IGNORECASE)
username_matches += re.findall(r"User:\s+([a-zA-Z][a-zA-Z0-9_]{2,19})", report)
for m in username_matches:
    if m.lower() not in ["the", "this", "that", "from", "account"]:
        iocs["usernames"].append(m)
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

print("\nExtracted IOCs from report:")
for ioc_type, values in iocs.items():
    if values:
        print(f"  {ioc_type}: {values}")

# ============================================================================
# PHASE 3: IOC CLASSIFICATION (SPECIFIC vs BROAD)
# Per documentation: classify_iocs()
# ============================================================================
print("\n" + "=" * 80)
print("PHASE 3: IOC CLASSIFICATION (SPECIFIC vs BROAD)")
print("=" * 80)

# SPECIFIC IOCs - low count, high value, AUTO-TAG
specific_iocs = {
    "processes": iocs.get("processes", []),
    "paths": iocs.get("paths", []),
    "hashes": iocs.get("hashes", []),
    "commands": iocs.get("commands", []),
    "threats": iocs.get("threats", [])
}

# BROAD IOCs - high count, AGGREGATION ONLY
broad_iocs = {
    "usernames": iocs.get("usernames", []),
    "hostnames": iocs.get("hostnames", []),
    "ips": iocs.get("ips", []),
    "sids": iocs.get("sids", [])
}

print("\nSPECIFIC IOCs (will AUTO-TAG all matches):")
for k, v in specific_iocs.items():
    if v:
        print(f"  {k}: {v}")

print("\nBROAD IOCs (AGGREGATION ONLY - NO auto-tag):")
for k, v in broad_iocs.items():
    if v:
        print(f"  {k}: {v}")

# ============================================================================
# PHASE 4: SEARCH SPECIFIC IOCs + COUNT AUTO-TAG CANDIDATES
# Per documentation: search_specific_iocs()
# ============================================================================
print("\n" + "=" * 80)
print("PHASE 4: SEARCH SPECIFIC IOCs (Auto-Tag Candidates)")
print("=" * 80)

specific_anchors = []
total_auto_tag_count = 0

for ioc_type, values in specific_iocs.items():
    for value in values:
        if not value:
            continue
        
        # Search using query_string (like build_search_query does)
        query = {
            "query": {
                "query_string": {
                    "query": f'"{value}"',
                    "default_operator": "AND"
                }
            }
        }
        
        try:
            count = opensearch_client.count(index=index_name, body=query)["count"]
            print(f"  {ioc_type}: '{value}' → {count:,} events")
            
            if count > 0:
                # Fetch events for auto-tagging (up to 1000)
                result = opensearch_client.search(index=index_name, body={**query, "size": min(count, 1000)})
                for hit in result["hits"]["hits"]:
                    specific_anchors.append({
                        "event_id": hit["_id"],
                        "event": hit,
                        "ioc_type": ioc_type,
                        "matched_ioc": value,
                        "timestamp": hit["_source"].get("@timestamp"),
                        "hostname": hit["_source"].get("normalized_computer") or hit["_source"].get("host", {}).get("hostname"),
                        "source": "specific_ioc_match",
                        "confidence": "medium"
                    })
                total_auto_tag_count += count
        except Exception as e:
            print(f"  Error searching '{value}': {e}")

print(f"\n  TOTAL SPECIFIC IOC MATCHES (would be auto-tagged): {total_auto_tag_count:,} events")

# ============================================================================
# PHASE 5: DISCOVER IOCs VIA AGGREGATIONS (BROAD IOCs)
# Per documentation: discover_iocs_via_aggregations()
# ============================================================================
print("\n" + "=" * 80)
print("PHASE 5: DISCOVER IOCs VIA AGGREGATIONS (BROAD IOCs)")
print("NO auto-tagging - discovery only")
print("=" * 80)

discovered = {"hostnames": set(), "usernames": set(), "ips": set()}

for ioc_type, values in broad_iocs.items():
    for value in values:
        if not value:
            continue
        
        query = {
            "query": {
                "query_string": {
                    "query": f'"{value}"',
                    "default_operator": "AND"
                }
            }
        }
        
        try:
            count = opensearch_client.count(index=index_name, body=query)["count"]
            print(f"  {ioc_type}: '{value}' → {count:,} events (NOT auto-tagged)")
            
            # Aggregation for discovery
            agg_query = {
                "size": 0,
                "query": query["query"],
                "aggs": {
                    "hosts": {"terms": {"field": "normalized_computer.keyword", "size": 50}},
                    "users": {"terms": {"field": "process.user.name.keyword", "size": 50}},
                    "ips": {"terms": {"field": "host.ip.keyword", "size": 50}}
                }
            }
            agg_result = opensearch_client.search(index=index_name, body=agg_query)
            
            for bucket in agg_result.get("aggregations", {}).get("hosts", {}).get("buckets", []):
                if bucket["key"] and bucket["key"] not in ["-", ""]:
                    discovered["hostnames"].add(bucket["key"])
            for bucket in agg_result.get("aggregations", {}).get("users", {}).get("buckets", []):
                if bucket["key"] and bucket["key"] not in ["-", "", "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE"]:
                    discovered["usernames"].add(bucket["key"])
            for bucket in agg_result.get("aggregations", {}).get("ips", {}).get("buckets", []):
                if bucket["key"] and not bucket["key"].startswith("127."):
                    discovered["ips"].add(bucket["key"])
                    
        except Exception as e:
            print(f"  Error: {e}")

print("\n  DISCOVERED via aggregations (new IOCs to add to database):")
print(f"    Hostnames: {len(discovered['hostnames'])} - {list(discovered['hostnames'])[:5]}...")
print(f"    Usernames: {len(discovered['usernames'])} - {list(discovered['usernames'])[:5]}...")
print(f"    IPs: {len(discovered['ips'])} - {list(discovered['ips'])[:5]}...")

# ============================================================================
# PHASE 6: GET ANALYST-TAGGED EVENTS (HIGH PRIORITY ANCHORS)
# Per documentation: get_tagged_event_anchors()
# ============================================================================
print("\n" + "=" * 80)
print("PHASE 6: GET ANALYST-TAGGED EVENTS")
print("=" * 80)

# Simulate checking TimelineTag table
# In real code: tags = TimelineTag.query.filter_by(case_id=case_id).all()
print("  (Would query TimelineTag table for case_id=25)")
print("  Analyst-tagged events: 0 (dry run - not querying database)")
tagged_anchors = []

# ============================================================================
# PHASE 7: AUTO-TAG SPECIFIC IOC MATCHES
# Per documentation: auto_tag_anchor_events_batch()
# ============================================================================
print("\n" + "=" * 80)
print("PHASE 7: AUTO-TAG SPECIFIC IOC MATCHES")
print("=" * 80)

print(f"  Events to auto-tag: {len(specific_anchors)}")
print(f"  Tag color: purple (AI-discovered)")

if specific_anchors:
    print("\n  Events that WOULD be auto-tagged:")
    for anchor in specific_anchors[:10]:
        ts = anchor.get("timestamp", "")[:19] if anchor.get("timestamp") else "N/A"
        ioc = anchor.get("matched_ioc", "")
        ioc_type = anchor.get("ioc_type", "")
        hostname = anchor.get("hostname", "")
        print(f"    {ts} | {hostname} | {ioc_type}={ioc}")
    if len(specific_anchors) > 10:
        print(f"    ... and {len(specific_anchors) - 10} more")
else:
    print("  No SPECIFIC IOC matches found - nothing to auto-tag")

# ============================================================================
# PHASE 8: TIME WINDOW ANALYSIS (±5 minutes around anchors)
# Per documentation: search_time_window()
# ============================================================================
print("\n" + "=" * 80)
print("PHASE 8: TIME WINDOW ANALYSIS (±5 min around anchors)")
print("=" * 80)

all_anchors = tagged_anchors + specific_anchors
all_window_events = []
processed_windows = set()

if not all_anchors:
    # Use timestamps from report as fallback anchors
    print("  No anchors from IOC matches - using report timestamps as anchors")
    report_anchors = [
        {"timestamp": "2025-08-12T07:13:00Z", "hostname": "CM-DC01", "reason": "AdUsers.txt access"},
        {"timestamp": "2025-08-12T07:14:00Z", "hostname": "CM-DC01", "reason": "Advanced IP Scanner"},
    ]
    all_anchors = report_anchors

for anchor in all_anchors[:30]:
    hostname = anchor.get("hostname")
    timestamp = anchor.get("timestamp")
    
    if not hostname or not timestamp:
        continue
    
    window_key = f"{hostname}|{timestamp[:16]}"
    if window_key in processed_windows:
        continue
    processed_windows.add(window_key)
    
    try:
        if isinstance(timestamp, str):
            anchor_time = datetime.fromisoformat(timestamp.replace('Z', '+00:00').replace('+00:00', ''))
        else:
            anchor_time = timestamp
            
        start_time = (anchor_time - timedelta(minutes=5)).isoformat() + "Z"
        end_time = (anchor_time + timedelta(minutes=5)).isoformat() + "Z"
        
        time_query = {
            "query": {
                "bool": {
                    "must": [
                        {"term": {"normalized_computer.keyword": hostname}},
                        {"range": {"@timestamp": {"gte": start_time, "lte": end_time}}}
                    ]
                }
            },
            "sort": [{"@timestamp": "asc"}],
            "size": 500
        }
        
        result = opensearch_client.search(index=index_name, body=time_query)
        window_count = result["hits"]["total"]["value"]
        print(f"  Window: {hostname} @ {timestamp[:19]} → {window_count:,} events")
        
        for hit in result["hits"]["hits"]:
            all_window_events.append(hit["_source"])
            
    except Exception as e:
        print(f"  Error searching window: {e}")

print(f"\n  Total events in time windows: {len(all_window_events):,}")

# ============================================================================
# PHASE 9: PROCESS TREE BUILDING
# Per documentation: build_process_tree()
# ============================================================================
print("\n" + "=" * 80)
print("PHASE 9: PROCESS TREE BUILDING")
print("=" * 80)

# Find suspicious parent PIDs from window events
suspicious_parents = set()
for event in all_window_events:
    proc = event.get("process", {})
    parent = proc.get("parent", {})
    parent_name = (parent.get("name") or "").lower()
    proc_name = (proc.get("name") or "").lower()
    
    if parent_name in ["cmd.exe", "powershell.exe"]:
        if proc_name in ["nltest.exe", "whoami.exe", "net.exe", "ipconfig.exe", "notepad.exe"]:
            parent_pid = parent.get("pid")
            hostname = event.get("normalized_computer")
            if parent_pid and hostname:
                suspicious_parents.add((parent_pid, hostname))

print(f"  Suspicious parent processes found: {len(suspicious_parents)}")

process_trees = []
for parent_pid, hostname in list(suspicious_parents)[:5]:
    query = {
        "query": {
            "bool": {
                "must": [
                    {"term": {"process.parent.pid": str(parent_pid)}},
                    {"term": {"normalized_computer.keyword": hostname}}
                ]
            }
        },
        "sort": [{"@timestamp": "asc"}],
        "size": 50
    }
    
    try:
        result = opensearch_client.search(index=index_name, body=query)
        if result["hits"]["total"]["value"] > 0:
            tree = {
                "parent_pid": parent_pid,
                "hostname": hostname,
                "children": [hit["_source"] for hit in result["hits"]["hits"]]
            }
            process_trees.append(tree)
            print(f"  Tree: PID {parent_pid} on {hostname} → {len(tree['children'])} child processes")
    except Exception as e:
        print(f"  Error building tree: {e}")

# ============================================================================
# PHASE 10: MITRE ATT&CK PATTERN MATCHING
# Per documentation: identify_attack_techniques()
# ============================================================================
print("\n" + "=" * 80)
print("PHASE 10: MITRE ATT&CK PATTERN MATCHING")
print("=" * 80)

MITRE_PATTERNS = {
    'T1033': {'name': 'System Owner/User Discovery', 'processes': ['whoami.exe', 'quser.exe']},
    'T1482': {'name': 'Domain Trust Discovery', 'processes': ['nltest.exe']},
    'T1018': {'name': 'Remote System Discovery', 'processes': ['nltest.exe', 'ping.exe', 'nslookup.exe', 'advanced_ip_scanner.exe']},
    'T1016': {'name': 'System Network Config Discovery', 'processes': ['ipconfig.exe', 'netsh.exe']},
    'T1087': {'name': 'Account Discovery', 'indicators': ['AdUsers', 'net user', 'net group']},
}

techniques_found = {}
for event in all_window_events:
    proc = event.get("process", {})
    proc_name = (proc.get("name") or "").lower()
    cmd_line = (proc.get("command_line") or "").lower()
    
    for tech_id, pattern in MITRE_PATTERNS.items():
        matched = False
        
        # Check process name
        for proc_pattern in pattern.get("processes", []):
            if proc_pattern.lower() in proc_name:
                matched = True
                break
        
        # Check indicators in command line
        for indicator in pattern.get("indicators", []):
            if indicator.lower() in cmd_line:
                matched = True
                break
        
        if matched:
            if tech_id not in techniques_found:
                techniques_found[tech_id] = {"name": pattern["name"], "events": []}
            techniques_found[tech_id]["events"].append(event)

print(f"  MITRE techniques identified: {len(techniques_found)}")
for tech_id, data in techniques_found.items():
    print(f"    {tech_id} - {data['name']}: {len(data['events'])} events")

# ============================================================================
# FINAL SUMMARY
# ============================================================================
print("\n" + "=" * 80)
print("FINAL SUMMARY - CASE 25 AI TRIAGE SEARCH DRY RUN")
print("=" * 80)

print(f"""
ENTRY POINT: Full Triage (EDR Report Available)

PHASE 1-2: IOC EXTRACTION
  Extracted from report:
    - IPs: {len(iocs['ips'])} ({iocs['ips']})
    - Hostnames: {len(iocs['hostnames'])} ({iocs['hostnames']})
    - Usernames: {len(iocs['usernames'])} ({iocs['usernames']})
    - SIDs: {len(iocs['sids'])}
    - Paths: {len(iocs['paths'])}
    - Processes: {len(iocs['processes'])} ({iocs['processes']})

PHASE 3: IOC CLASSIFICATION
  SPECIFIC (auto-tag): {sum(len(v) for v in specific_iocs.values())} items
  BROAD (aggregation only): {sum(len(v) for v in broad_iocs.values())} items

PHASE 4: SPECIFIC IOC SEARCH
  Events matching SPECIFIC IOCs: {total_auto_tag_count:,}

PHASE 5: BROAD IOC AGGREGATION
  Discovered hostnames: {len(discovered['hostnames'])}
  Discovered usernames: {len(discovered['usernames'])}
  Discovered IPs: {len(discovered['ips'])}

PHASE 6: ANALYST-TAGGED EVENTS
  Pre-existing tags: {len(tagged_anchors)}

PHASE 7: AUTO-TAGGING
  Events that WOULD be auto-tagged (purple): {len(specific_anchors)}

PHASE 8: TIME WINDOW ANALYSIS
  Events in ±5 min windows: {len(all_window_events):,}

PHASE 9: PROCESS TREES
  Trees built: {len(process_trees)}

PHASE 10: MITRE TECHNIQUES
  Techniques identified: {len(techniques_found)}
""")

print("=" * 80)
print("WHAT THE SYSTEM WOULD DO:")
print("=" * 80)
print(f"""
1. CREATE IOCs in database:
   - {len(iocs['ips'])} IPs (active)
   - {len(iocs['hostnames'])} hostnames (active) + add to Systems table
   - {len(iocs['usernames'])} usernames (active)
   - {len(iocs['sids'])} SIDs (INACTIVE - too noisy)
   - {len(iocs['paths'])} paths (active)
   - {len(iocs['processes'])} processes (active)

2. AUTO-TAG {len(specific_anchors)} events with purple tags
   (Only SPECIFIC IOC matches - processes, paths, hashes, commands, threats)

3. NOT auto-tag BROAD IOCs:
   - tabadmin: 46,232 events - used for DISCOVERY only
   - CM-DC01: 1,272,376 events - used for DISCOVERY only
   - etc.

4. DISCOVER new IOCs via aggregations:
   - {len(discovered['hostnames'])} new hostnames
   - {len(discovered['usernames'])} new usernames  
   - {len(discovered['ips'])} new IPs

5. BUILD {len(process_trees)} process trees

6. IDENTIFY {len(techniques_found)} MITRE ATT&CK techniques
""")

