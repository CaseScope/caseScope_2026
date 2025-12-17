#!/usr/bin/env python3
"""
AI Triage Search - Dry Run - Case 25
Following the methodology from search_notes/ai_triage_search_methodology.md
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
print("AI TRIAGE SEARCH - DRY RUN - CASE 25")
print("=" * 80)

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

print("\n" + "=" * 80)
print("PHASE 1: IOC EXTRACTION FROM REPORT")
print("=" * 80)

# Extract IOCs using regex
iocs = {
    "ips": [],
    "hostnames": [],
    "usernames": [],
    "sids": [],
    "paths": [],
    "processes": [],
    "commands": []
}

# IPs
ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
iocs["ips"] = list(set(re.findall(ip_pattern, report)))

# Hostnames - look for specific patterns
hostname_matches = re.findall(r"to\s+'?([A-Z][A-Z0-9-]{2,14})'?", report, re.IGNORECASE)
hostname_matches += re.findall(r"host\s+'?([A-Z][A-Z0-9-]{2,14})'?", report, re.IGNORECASE)
hostname_matches += re.findall(r'\(([A-Z][A-Z0-9-]{2,14})\)', report)
for m in hostname_matches:
    if m.upper() not in ["UTC", "THE", "FROM", "THIS", "THAT"]:
        iocs["hostnames"].append(m.upper())
iocs["hostnames"] = list(set(iocs["hostnames"]))

# Usernames
username_matches = re.findall(r"user\s+'?([a-zA-Z][a-zA-Z0-9_]{2,19})'?", report, re.IGNORECASE)
username_matches += re.findall(r"User:\s+([a-zA-Z][a-zA-Z0-9_]{2,19})", report)
for m in username_matches:
    if m.lower() not in ["the", "this", "that", "from", "account"]:
        iocs["usernames"].append(m)
iocs["usernames"] = list(set(iocs["usernames"]))

# SIDs
sid_pattern = r'S-1-5-21-\d+-\d+-\d+-\d+'
iocs["sids"] = list(set(re.findall(sid_pattern, report)))

# Paths - look for Windows paths
path_pattern = r'[A-Z]:\\[^\s"\'<>]+\.(?:exe|txt|dll|bat|ps1|cmd)'
iocs["paths"] = list(set(re.findall(path_pattern, report, re.IGNORECASE)))

# Processes (from paths)
for path in iocs["paths"]:
    if path.lower().endswith(".exe"):
        proc = path.split("\\")[-1]
        iocs["processes"].append(proc)
iocs["processes"] = list(set(iocs["processes"]))

print("\nExtracted IOCs:")
for ioc_type, values in iocs.items():
    if values:
        print(f"  {ioc_type}: {values}")

print("\n" + "=" * 80)
print("PHASE 2: IOC CLASSIFICATION (SPECIFIC vs BROAD)")
print("=" * 80)

specific_iocs = {
    "processes": iocs.get("processes", []),
    "paths": iocs.get("paths", []),
    "commands": iocs.get("commands", [])
}

broad_iocs = {
    "usernames": iocs.get("usernames", []),
    "hostnames": iocs.get("hostnames", []),
    "ips": iocs.get("ips", []),
    "sids": iocs.get("sids", [])
}

print("\nSPECIFIC IOCs (will auto-tag):")
for k, v in specific_iocs.items():
    if v:
        print(f"  {k}: {v}")

print("\nBROAD IOCs (aggregation only):")
for k, v in broad_iocs.items():
    if v:
        print(f"  {k}: {v}")

print("\n" + "=" * 80)
print("PHASE 3: SEARCH SPECIFIC IOCs")
print("=" * 80)

specific_matches = {}
for ioc_type, values in specific_iocs.items():
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
            if count > 0:
                specific_matches[value] = count
                print(f"  {ioc_type}: {value} → {count:,} events")
        except Exception as e:
            print(f"  Error searching {value}: {e}")

print(f"\nTotal SPECIFIC IOC matches: {sum(specific_matches.values()):,} events")

print("\n" + "=" * 80)
print("PHASE 4: AGGREGATE BROAD IOCs (Discovery Only)")
print("=" * 80)

discovered = {"hostnames": set(), "usernames": set(), "ips": set()}

for ioc_type, values in broad_iocs.items():
    for value in values:
        if not value:
            continue
        
        # Count first
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
            print(f"  {ioc_type}: {value} → {count:,} events")
            
            # Aggregation for discovery
            agg_query = {
                "size": 0,
                "query": query["query"],
                "aggs": {
                    "hosts": {"terms": {"field": "normalized_computer.keyword", "size": 20}},
                    "users": {"terms": {"field": "process.user.name.keyword", "size": 20}},
                    "ips": {"terms": {"field": "host.ip.keyword", "size": 20}}
                }
            }
            agg_result = opensearch_client.search(index=index_name, body=agg_query)
            
            for bucket in agg_result.get("aggregations", {}).get("hosts", {}).get("buckets", []):
                if bucket["key"] and bucket["key"] not in ["-", ""]:
                    discovered["hostnames"].add(bucket["key"])
            for bucket in agg_result.get("aggregations", {}).get("users", {}).get("buckets", []):
                if bucket["key"] and bucket["key"] not in ["-", "", "SYSTEM", "LOCAL SERVICE"]:
                    discovered["usernames"].add(bucket["key"])
            for bucket in agg_result.get("aggregations", {}).get("ips", {}).get("buckets", []):
                if bucket["key"] and not bucket["key"].startswith("127."):
                    discovered["ips"].add(bucket["key"])
                    
        except Exception as e:
            print(f"  Error: {e}")

print("\nDiscovered via aggregations:")
print(f"  Hostnames: {list(discovered['hostnames'])[:10]}")
print(f"  Usernames: {list(discovered['usernames'])[:10]}")
print(f"  IPs: {list(discovered['ips'])[:10]}")

print("\n" + "=" * 80)
print("PHASE 5: TIME WINDOW ANALYSIS")
print("=" * 80)

# Anchor time from report: 2025-08-12 07:13 UTC
anchor_time = datetime(2025, 8, 12, 7, 13, 0)
start_time = (anchor_time - timedelta(minutes=10)).isoformat() + "Z"
end_time = (anchor_time + timedelta(minutes=10)).isoformat() + "Z"

# Search for events around the anchor time
time_query = {
    "query": {
        "bool": {
            "must": [
                {"range": {"@timestamp": {"gte": start_time, "lte": end_time}}}
            ]
        }
    },
    "sort": [{"@timestamp": "asc"}],
    "size": 100,
    "_source": ["@timestamp", "process.name", "process.command_line", "process.user.name", 
                "process.parent.name", "normalized_computer", "Event.System.EventID"]
}

try:
    result = opensearch_client.search(index=index_name, body=time_query)
    print(f"\nEvents in ±10 min window around 07:13 UTC: {result['hits']['total']['value']:,}")
    
    print("\nSample events from time window:")
    for hit in result["hits"]["hits"][:15]:
        src = hit["_source"]
        ts = src.get("@timestamp", "")[:19]
        proc = src.get("process", {}).get("name", "")
        if not proc:
            proc = str(src.get("Event", {}).get("System", {}).get("EventID", ""))
        cmd = (src.get("process", {}).get("command_line", "") or "")[:60]
        user = src.get("process", {}).get("user", {}).get("name", "")
        computer = src.get("normalized_computer", "")
        print(f"  {ts} | {computer} | {proc} | {user} | {cmd}")
except Exception as e:
    print(f"Error: {e}")

print("\n" + "=" * 80)
print("PHASE 6: SEARCH FOR RECON COMMANDS")
print("=" * 80)

recon_terms = ["nltest", "whoami", "ipconfig", "net user", "net group", "advanced_ip_scanner"]
for term in recon_terms:
    query = {"query": {"query_string": {"query": term}}}
    try:
        count = opensearch_client.count(index=index_name, body=query)["count"]
        if count > 0:
            print(f"  {term}: {count:,} events")
    except:
        pass

print("\n" + "=" * 80)
print("PHASE 7: SEARCH FOR SUSPICIOUS FILE ACCESS")
print("=" * 80)

file_terms = ["AdUsers.txt", "AdComp.txt"]
for term in file_terms:
    query = {"query": {"query_string": {"query": f'"{term}"'}}}
    try:
        count = opensearch_client.count(index=index_name, body=query)["count"]
        print(f"  {term}: {count:,} events")
        
        if count > 0 and count < 20:
            result = opensearch_client.search(index=index_name, body={**query, "size": 5})
            for hit in result["hits"]["hits"]:
                src = hit["_source"]
                ts = src.get("@timestamp", "")[:19]
                proc = src.get("process", {}).get("name", "")
                cmd = (src.get("process", {}).get("command_line", "") or "")[:80]
                print(f"    {ts} | {proc} | {cmd}")
    except Exception as e:
        print(f"  Error: {e}")

print("\n" + "=" * 80)
print("SUMMARY")
print("=" * 80)

print(f"""
Entry Point: Full Triage (EDR Report Available)

IOCs Extracted:
  - SPECIFIC (auto-tag): {sum(len(v) for v in specific_iocs.values())} items
    - Processes: {specific_iocs['processes']}
    - Paths: {len(specific_iocs['paths'])} paths
  - BROAD (aggregation): {sum(len(v) for v in broad_iocs.values())} items
    - Username: {broad_iocs['usernames']}
    - Hostnames: {broad_iocs['hostnames']}
    - IPs: {broad_iocs['ips']}

Auto-Tag Candidates:
  - Total from SPECIFIC IOCs: {sum(specific_matches.values()):,} events

Discovery via Aggregations:
  - Hostnames found: {len(discovered['hostnames'])}
  - Usernames found: {len(discovered['usernames'])}
  - IPs found: {len(discovered['ips'])}

Attack Timeline (from report):
  06:57 UTC - tabadmin auth to CM-DC01 from 192.168.0.254 (gateway)
  07:01 UTC - tabadmin auth from 172.16.10.25
  07:01 UTC - tabadmin auth from CM-VMHOST (192.168.0.8)
  07:10 UTC - tabadmin auth from WIN-HU67JDG9MF1 (172.16.10.26) [MALICIOUS HOST]
  07:12 UTC - Domain trust enumeration
  07:13 UTC - Accessed AdUsers.txt, AdComp.txt
  07:14 UTC - Executed Advanced IP Scanner

MITRE ATT&CK Techniques:
  - T1087 - Account Discovery (AdUsers.txt)
  - T1018 - Remote System Discovery (Advanced IP Scanner)
  - T1482 - Domain Trust Discovery (domain enumeration)
  - T1078 - Valid Accounts (tabadmin compromised)
""")

