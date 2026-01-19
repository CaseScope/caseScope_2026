#!/usr/bin/env python3
"""Hostname Correlation Script

Compares hostnames between ClickHouse (source_host from events)
and PostgreSQL (known_systems.hostname) to find:
1. Systems that may have been renamed (ClickHouse has different name than DB)
2. Hostnames in ClickHouse not registered in known_systems

Run with: cd /opt/casescope && python -m migrations.correlate_hostnames
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app
from models.database import db
from models.case import Case
from models.known_system import KnownSystem, KnownSystemAlias
from utils.clickhouse import get_client


def get_clickhouse_hostnames():
    """Get all source_host values from ClickHouse grouped by case_id
    
    Returns: {case_id: {hostname: count, ...}, ...}
    """
    client = get_client()
    
    result = client.query("""
        SELECT case_id, source_host, count() as cnt
        FROM events
        WHERE source_host != ''
        GROUP BY case_id, source_host
        ORDER BY case_id, cnt DESC
    """)
    
    hostnames_by_case = {}
    for row in result.result_rows:
        case_id = row[0]
        hostname = row[1].strip().upper() if row[1] else ''
        count = row[2]
        
        if not hostname:
            continue
            
        if case_id not in hostnames_by_case:
            hostnames_by_case[case_id] = {}
        hostnames_by_case[case_id][hostname] = count
    
    return hostnames_by_case


def get_db_hostnames():
    """Get all hostnames from known_systems grouped by case_id
    
    Returns: {case_id: {'hostnames': set, 'aliases': set}, ...}
    """
    hostnames_by_case = {}
    
    # Get all known systems with their aliases
    systems = KnownSystem.query.all()
    
    for system in systems:
        case_id = system.case_id
        if case_id not in hostnames_by_case:
            hostnames_by_case[case_id] = {'hostnames': set(), 'aliases': set()}
        
        # Add primary hostname
        hostnames_by_case[case_id]['hostnames'].add(system.hostname.upper())
        
        # Add aliases
        for alias in system.aliases:
            hostnames_by_case[case_id]['aliases'].add(alias.alias.upper())
    
    return hostnames_by_case


def extract_netbios(hostname):
    """Extract NETBIOS name from FQDN"""
    if '.' in hostname:
        return hostname.split('.')[0]
    return hostname


def correlate_hostnames():
    """Main correlation function
    
    Finds:
    1. source_hosts in ClickHouse not in known_systems (missing from DB)
    2. source_hosts that differ from DB hostname (potential renames)
    """
    print("=" * 80)
    print("HOSTNAME CORRELATION: ClickHouse vs PostgreSQL")
    print("=" * 80)
    print()
    
    # Get data from both sources
    print("[1/3] Fetching hostnames from ClickHouse...")
    ch_hostnames = get_clickhouse_hostnames()
    total_ch_cases = len(ch_hostnames)
    total_ch_hosts = sum(len(hosts) for hosts in ch_hostnames.values())
    print(f"      Found {total_ch_hosts} unique hostnames across {total_ch_cases} cases")
    
    print("[2/3] Fetching hostnames from PostgreSQL...")
    db_hostnames = get_db_hostnames()
    total_db_cases = len(db_hostnames)
    total_db_hosts = sum(len(h['hostnames']) for h in db_hostnames.values())
    print(f"      Found {total_db_hosts} hostnames across {total_db_cases} cases")
    
    print("[3/3] Correlating hostnames...")
    print()
    
    # Results containers
    missing_from_db = {}      # In CH but not in DB
    potential_renames = {}    # In CH with different NETBIOS than DB
    
    for case_id, ch_hosts in ch_hostnames.items():
        db_data = db_hostnames.get(case_id, {'hostnames': set(), 'aliases': set()})
        db_hosts = db_data['hostnames']
        db_aliases = db_data['aliases']
        all_db_names = db_hosts | db_aliases
        
        # Get case info
        case = Case.query.get(case_id)
        case_name = case.name if case else f"Unknown (ID: {case_id})"
        
        for ch_hostname, count in ch_hosts.items():
            netbios = extract_netbios(ch_hostname)
            
            # Check if in DB (exact match on hostname or alias)
            in_db = ch_hostname in all_db_names or netbios in all_db_names
            
            if not in_db:
                # Check if NETBIOS matches any DB hostname
                netbios_match = None
                for db_host in db_hosts:
                    db_netbios = extract_netbios(db_host)
                    if netbios == db_netbios:
                        netbios_match = db_host
                        break
                
                if netbios_match:
                    # NETBIOS matches but full name differs - potential FQDN variant
                    continue  # Skip - just an FQDN variant
                
                # Check for similar names (potential rename)
                # Compare first 4+ chars for similarity
                possible_rename = None
                for db_host in db_hosts:
                    # Check if one is a prefix of another (common in renames)
                    if len(netbios) >= 4 and len(db_host) >= 4:
                        if netbios[:4] == db_host[:4]:
                            possible_rename = db_host
                            break
                
                if possible_rename:
                    # Record as potential rename
                    if case_id not in potential_renames:
                        potential_renames[case_id] = {'case_name': case_name, 'renames': []}
                    potential_renames[case_id]['renames'].append({
                        'clickhouse_host': ch_hostname,
                        'db_host': possible_rename,
                        'event_count': count
                    })
                else:
                    # Record as missing from DB
                    if case_id not in missing_from_db:
                        missing_from_db[case_id] = {'case_name': case_name, 'hosts': []}
                    missing_from_db[case_id]['hosts'].append({
                        'hostname': ch_hostname,
                        'event_count': count
                    })
    
    # Print Results
    print("=" * 80)
    print("POTENTIAL SYSTEM RENAMES (Different hostnames with similar patterns)")
    print("=" * 80)
    
    if potential_renames:
        for case_id, data in sorted(potential_renames.items()):
            print(f"\nCase: {data['case_name']} (ID: {case_id})")
            print("-" * 60)
            for rename in sorted(data['renames'], key=lambda x: -x['event_count']):
                print(f"  ClickHouse: {rename['clickhouse_host']:30} → DB: {rename['db_host']:30} ({rename['event_count']:,} events)")
    else:
        print("\n  No potential renames detected.")
    
    print()
    print("=" * 80)
    print("HOSTNAMES IN CLICKHOUSE BUT NOT IN KNOWN_SYSTEMS")
    print("=" * 80)
    
    if missing_from_db:
        for case_id, data in sorted(missing_from_db.items()):
            print(f"\nCase: {data['case_name']} (ID: {case_id})")
            print("-" * 60)
            # Sort by event count, show top 20
            sorted_hosts = sorted(data['hosts'], key=lambda x: -x['event_count'])[:20]
            for host_data in sorted_hosts:
                print(f"  {host_data['hostname']:40} ({host_data['event_count']:,} events)")
            if len(data['hosts']) > 20:
                print(f"  ... and {len(data['hosts']) - 20} more")
    else:
        print("\n  All ClickHouse hostnames are registered in known_systems.")
    
    print()
    print("=" * 80)
    print("SUMMARY")
    print("=" * 80)
    total_renames = sum(len(d['renames']) for d in potential_renames.values())
    total_missing = sum(len(d['hosts']) for d in missing_from_db.values())
    print(f"  Potential renames detected: {total_renames}")
    print(f"  Hostnames missing from DB:  {total_missing}")
    print()
    
    return {
        'potential_renames': potential_renames,
        'missing_from_db': missing_from_db
    }


def deep_correlation():
    """More thorough correlation looking at actual EVTX hostname fields
    
    Specifically looks at:
    - source_host field vs extra_fields.host_hostname (from NDJSON/EDR)
    - Computer name from raw_json in EVTX
    """
    print()
    print("=" * 80)
    print("DEEP CORRELATION: Checking for hostname discrepancies within events")
    print("=" * 80)
    print()
    
    client = get_client()
    
    # Find events where source_host differs from Computer in raw_json
    # This catches renames where EVTX has old name but other sources have new name
    result = client.query("""
        SELECT 
            case_id,
            source_host,
            JSONExtractString(raw_json, 'Computer') as evtx_computer,
            JSONExtractString(extra_fields, 'host_hostname') as edr_hostname,
            count() as cnt
        FROM events
        WHERE source_host != ''
          AND (
              (JSONExtractString(raw_json, 'Computer') != '' 
               AND JSONExtractString(raw_json, 'Computer') != source_host)
              OR
              (JSONExtractString(extra_fields, 'host_hostname') != ''
               AND JSONExtractString(extra_fields, 'host_hostname') != source_host)
          )
        GROUP BY case_id, source_host, evtx_computer, edr_hostname
        HAVING cnt > 10
        ORDER BY case_id, cnt DESC
        LIMIT 200
    """)
    
    discrepancies = {}
    for row in result.result_rows:
        case_id = row[0]
        source_host = row[1]
        evtx_computer = row[2]
        edr_hostname = row[3]
        count = row[4]
        
        case = Case.query.get(case_id)
        case_name = case.name if case else f"Unknown (ID: {case_id})"
        
        if case_id not in discrepancies:
            discrepancies[case_id] = {'case_name': case_name, 'items': []}
        
        discrepancies[case_id]['items'].append({
            'source_host': source_host,
            'evtx_computer': evtx_computer,
            'edr_hostname': edr_hostname,
            'event_count': count
        })
    
    if discrepancies:
        for case_id, data in sorted(discrepancies.items()):
            print(f"\nCase: {data['case_name']} (ID: {case_id})")
            print("-" * 80)
            print(f"{'source_host':25} {'EVTX Computer':25} {'EDR Hostname':25} Count")
            print("-" * 80)
            for item in sorted(data['items'], key=lambda x: -x['event_count'])[:15]:
                print(f"{item['source_host']:25} {item['evtx_computer']:25} {item['edr_hostname']:25} {item['event_count']:,}")
    else:
        print("  No hostname discrepancies found within events.")
    
    return discrepancies


if __name__ == '__main__':
    app = create_app()
    with app.app_context():
        results = correlate_hostnames()
        deep_results = deep_correlation()
        
        print()
        print("Correlation complete.")
