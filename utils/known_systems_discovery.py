"""Known Systems Discovery Module

Modular function to discover and populate known systems from artifacts.
Can be called from:
1. File ingestion process (after files are ingested)
2. UI button click ("Find in Artifacts")
"""
import logging
from datetime import datetime
from typing import Dict, List, Tuple, Optional
from sqlalchemy.exc import IntegrityError

from models.database import db
from models.known_system import (
    KnownSystem, KnownSystemIP, KnownSystemAlias, 
    KnownSystemAudit, KnownSystemCase
)
from config import Config

logger = logging.getLogger(__name__)


def init_discovery_progress(case_uuid: str, total: int):
    """Initialize systems discovery progress using unified progress module"""
    from utils.progress import set_phase
    set_phase(case_uuid, 'systems', total=total)


def update_discovery_progress(case_uuid: str, processed: int, created: int, updated: int, current: str = ''):
    """Update systems discovery progress using unified progress module"""
    from utils.progress import increment_phase, set_current_item
    # Only increment, don't set absolute value (increment is called per-item now)
    set_current_item(case_uuid, current)


def complete_discovery_progress(case_uuid: str, results: dict):
    """Mark systems discovery as complete"""
    from utils.progress import get_redis_client
    
    try:
        client = get_redis_client()
        key = f"processing_progress:{case_uuid}"
        client.hset(key, 'status', 'complete')
    except Exception as e:
        logger.warning(f"Failed to set systems discovery complete status: {e}")


def get_discovery_progress(case_uuid: str) -> Optional[dict]:
    """Get current discovery progress from unified progress module"""
    from utils.progress import get_progress
    progress = get_progress(case_uuid)
    if progress and progress.get('phase') == 'systems':
        return {
            'status': 'running' if progress.get('status') == 'discovering_systems' else progress.get('status'),
            'total': progress['systems']['total'],
            'processed': progress['systems']['completed'],
            'created': 0,  # Not tracked in unified progress
            'updated': 0,
            'current_hostname': progress.get('current_item', '')
        }
    return None


def discover_known_systems(case_id: int, case_uuid: str, username: str = 'system', track_progress: bool = False) -> Dict:
    """Discover and populate known systems from artifacts for a case
    
    Sources:
    1. case_files table - hostname field
    2. ClickHouse events - hostname field
    
    Args:
        case_id: PostgreSQL case.id (also used for ClickHouse)
        case_uuid: Case UUID for querying case_files
        username: User performing the discovery (for audit)
        track_progress: Whether to track progress in Redis
    
    Returns:
        Dict with discovery results
    """
    results = {
        'success': True,
        'systems_created': 0,
        'systems_updated': 0,
        'aliases_added': 0,
        'ips_added': 0,
        'case_links_added': 0,
        'hostnames_processed': 0,
        'errors': []
    }
    
    try:
        # Collect hostname stats from all sources
        # Format: {hostname: {'count': N, 'last_seen': datetime}}
        
        # Source 1: case_files table
        file_stats = _get_hostnames_from_case_files(case_uuid)
        logger.info(f"Found {len(file_stats)} unique hostnames from case_files")
        
        # Source 2: ClickHouse events (source hosts)
        event_stats = _get_hostnames_from_events(case_id)
        logger.info(f"Found {len(event_stats)} unique source hostnames from events")
        
        # Source 3: Destination hosts from UNC paths (servers accessed)
        dest_stats, server_shares = _get_destination_hosts_and_shares(case_id)
        logger.info(f"Found {len(dest_stats)} unique destination hosts, {len(server_shares)} servers with shares")
        
        # Source 4: Remote workstations from logon events (systems that connected TO our systems)
        # CRITICAL for threat hunting - includes attacker workstations!
        remote_stats = _get_remote_workstations_from_logon_events(case_id)
        logger.info(f"Found {len(remote_stats)} unique remote workstations from logon events")
        
        # Merge all stats: combine counts and take latest last_seen
        all_hostname_stats = {}
        
        # Helper to merge hostname stats
        def merge_stats(hostname, stats, source_type):
            if not hostname:
                return
            hostname = hostname.upper()
            if hostname in all_hostname_stats:
                all_hostname_stats[hostname]['count'] += stats['count']
                # Track all sources that contributed to this hostname
                all_hostname_stats[hostname]['sources'].add(source_type)
                # Take the later last_seen (handle timezone-aware vs naive)
                new_ts = stats['last_seen']
                old_ts = all_hostname_stats[hostname]['last_seen']
                if new_ts:
                    if hasattr(new_ts, 'replace') and new_ts.tzinfo:
                        new_ts = new_ts.replace(tzinfo=None)
                    if old_ts and hasattr(old_ts, 'replace') and old_ts.tzinfo:
                        old_ts = old_ts.replace(tzinfo=None)
                    if not old_ts or new_ts > old_ts:
                        all_hostname_stats[hostname]['last_seen'] = stats['last_seen']
                # Merge IP addresses from remote logon events
                if 'ip_addresses' in stats:
                    if 'ip_addresses' not in all_hostname_stats[hostname]:
                        all_hostname_stats[hostname]['ip_addresses'] = set()
                    all_hostname_stats[hostname]['ip_addresses'].update(stats['ip_addresses'])
            else:
                all_hostname_stats[hostname] = {
                    'count': stats['count'],
                    'last_seen': stats['last_seen'],
                    'sources': {source_type},
                    'ip_addresses': set(stats.get('ip_addresses', []))
                }
        
        # Merge from case_files (now includes file_type as sources)
        for hostname, stats in file_stats.items():
            file_sources = stats.get('sources', set())
            for source in file_sources:
                merge_stats(hostname, stats, source)
        
        # Merge from source events (EVTX, NDJSON, etc. - source_host field)
        # Now contains artifact_type sources directly
        for hostname, stats in event_stats.items():
            # Event stats now include sources from artifact_type
            event_sources = stats.get('sources', set())
            for source in event_sources:
                merge_stats(hostname, stats, source)
        
        # Merge from destination hosts (UNC paths in events)
        for hostname, stats in dest_stats.items():
            merge_stats(hostname, stats, 'unc_paths')
        
        # Merge from remote workstations (attackers, admins connecting remotely)
        for hostname, stats in remote_stats.items():
            merge_stats(hostname, stats, 'logon_events')
        
        total_hostnames = len(all_hostname_stats)
        results['hostnames_processed'] = total_hostnames
        logger.info(f"Processing {total_hostnames} total unique hostnames (source + destination)")
        
        # Initialize progress tracking
        if track_progress:
            init_discovery_progress(case_uuid, total_hostnames)
        
        # Process each hostname with its stats
        processed = 0
        for hostname, stats in all_hostname_stats.items():
            try:
                # Get shares for this host (if it's a server)
                host_shares = server_shares.get(hostname, [])
                
                # Get IPs from remote logon events (for systems we don't have EDR data on)
                logon_ips = list(stats.get('ip_addresses', set()))
                
                # Get sources that contributed to this hostname
                host_sources = list(stats.get('sources', set()))
                
                created, updated, alias_added = _process_hostname(
                    hostname, case_id, username,
                    artifact_count=stats['count'],
                    last_seen=stats['last_seen'],
                    shares=host_shares,
                    logon_ips=logon_ips,
                    sources=host_sources
                )
                
                if created:
                    results['systems_created'] += 1
                if updated:
                    results['systems_updated'] += 1
                if alias_added:
                    results['aliases_added'] += 1
                
                processed += 1
                
                # Update progress atomically
                if track_progress:
                    from utils.progress import increment_phase, set_current_item
                    increment_phase(case_uuid, 'systems')
                    # Update current item every 10 hostnames to reduce Redis calls
                    if processed % 10 == 0 or processed == total_hostnames:
                        set_current_item(case_uuid, hostname)
                    
            except IntegrityError:
                # Race condition - another process created this system
                # This is expected and safe - just rollback and retry as update
                db.session.rollback()
                try:
                    created, updated, alias_added = _process_hostname(
                        hostname, case_id, username
                    )
                    if updated:
                        results['systems_updated'] += 1
                    if alias_added:
                        results['aliases_added'] += 1
                    processed += 1
                except Exception as e2:
                    logger.warning(f"Retry failed for '{hostname}': {e2}")
                    
            except Exception as e:
                logger.error(f"Error processing hostname '{hostname}': {e}")
                results['errors'].append(f"Error with '{hostname}': {str(e)}")
                processed += 1
        
        # Commit all changes
        db.session.commit()
        
        # Count case links added
        results['case_links_added'] = KnownSystemCase.query.filter_by(case_id=case_id).count()
        
        # Mark progress complete
        if track_progress:
            complete_discovery_progress(case_uuid, results)
        
    except Exception as e:
        logger.exception("Error in discover_known_systems")
        results['success'] = False
        results['errors'].append(str(e))
        db.session.rollback()
    
    return results


def _get_hostnames_from_case_files(case_uuid: str) -> dict:
    """Get hostname stats from case_files table
    
    Returns dict: {hostname: {'count': N, 'last_seen': datetime, 'sources': set}}
    
    Tracks file_type as source (CyLR, Huntress NDJSON, etc.)
    """
    from models.case_file import CaseFile
    from sqlalchemy import func
    
    hostname_stats = {}
    
    # Query hostname with file_type, count and max uploaded_at
    rows = db.session.query(
        CaseFile.hostname,
        CaseFile.file_type,
        func.count(CaseFile.id).label('count'),
        func.max(CaseFile.uploaded_at).label('last_seen')
    ).filter(
        CaseFile.case_uuid == case_uuid,
        CaseFile.hostname.isnot(None),
        CaseFile.hostname != ''
    ).group_by(CaseFile.hostname, CaseFile.file_type).all()
    
    for row in rows:
        hostname = row[0].strip() if row[0] else None
        file_type = row[1]
        count = row[2]
        last_seen = row[3]
        
        if not hostname:
            continue
        
        # Normalize file_type to source identifier
        source = _normalize_file_type_to_source(file_type) if file_type else 'case_files'
        
        if hostname in hostname_stats:
            hostname_stats[hostname]['count'] += count
            hostname_stats[hostname]['sources'].add(source)
            if last_seen and (not hostname_stats[hostname]['last_seen'] or last_seen > hostname_stats[hostname]['last_seen']):
                hostname_stats[hostname]['last_seen'] = last_seen
        else:
            hostname_stats[hostname] = {
                'count': count,
                'last_seen': last_seen,
                'sources': {source}
            }
    
    return hostname_stats


def _normalize_file_type_to_source(file_type: str) -> str:
    """Normalize file_type from case_files to a source identifier
    
    Maps file types like 'CyLR', 'Huntress NDJSON' to source identifiers
    """
    if not file_type:
        return 'case_files'
    
    file_type_lower = file_type.lower()
    
    # Map common file types to source identifiers
    if 'ndjson' in file_type_lower or 'huntress' in file_type_lower:
        return 'ndjson'
    elif 'cylr' in file_type_lower:
        return 'cylr'
    elif 'iis' in file_type_lower:
        return 'iis'
    elif 'sonicwall' in file_type_lower:
        return 'sonicwall'
    else:
        return file_type_lower.replace(' ', '_')


def _get_system_details_from_events(case_id: int, hostname: str) -> dict:
    """Get additional system details from ClickHouse events
    
    Extracts: IPs, MACs, OS type, OS version, domain aliases
    Also checks extra_fields JSON for rich data from NDJSON sources (Huntress, etc.)
    
    IMPORTANT: Only extracts IPs/MACs that belong TO this system (from host_ip/host_mac
    in EDR data), NOT from src_ip which could be remote systems accessing this machine.
    
    Note: Shares are handled separately via _get_destination_hosts_and_shares
    """
    from utils.clickhouse import get_client
    
    details = {
        'ip_addresses': [],
        'mac_addresses': [],
        'os_type': None,
        'os_version': None,
        'aliases': []
    }
    
    try:
        client = get_client()
        
        # NOTE: We intentionally do NOT use src_ip from events because that could be
        # the IP of a remote system accessing this machine (e.g., an attacker).
        # Instead, we only use host_ip from extra_fields which is the system's own IP
        # as reported by the EDR agent running on that system.
        
        # Get host_ip from extra_fields (from NDJSON sources like Huntress)
        # This is the system's actual IP as reported by the EDR agent
        extra_ip_result = client.query(
            """SELECT DISTINCT JSONExtractString(extra_fields, 'host_ip') as ip
               FROM events 
               WHERE case_id = {case_id:UInt32} 
                 AND source_host = {hostname:String}
                 AND extra_fields != ''
                 AND extra_fields != '{}'
                 AND JSONExtractString(extra_fields, 'host_ip') != ''
               LIMIT 10""",
            parameters={'case_id': case_id, 'hostname': hostname}
        )
        for row in extra_ip_result.result_rows:
            ip = row[0]
            if ip and ip not in ('0.0.0.0', '127.0.0.1') and ip not in details['ip_addresses']:
                details['ip_addresses'].append(ip)
        
        # Get host_mac from extra_fields (from NDJSON sources like Huntress)
        # This is an array of the system's MAC addresses
        mac_result = client.query(
            """SELECT DISTINCT JSONExtractString(extra_fields, 'host_mac') as macs
               FROM events 
               WHERE case_id = {case_id:UInt32} 
                 AND source_host = {hostname:String}
                 AND extra_fields != ''
                 AND extra_fields != '{}'
                 AND JSONExtractString(extra_fields, 'host_mac') != ''
                 AND JSONExtractString(extra_fields, 'host_mac') != '[]'
               LIMIT 1""",
            parameters={'case_id': case_id, 'hostname': hostname}
        )
        for row in mac_result.result_rows:
            mac_str = row[0]
            if mac_str:
                # Parse JSON array of MACs: ["aa:bb:cc:dd:ee:ff", ...]
                try:
                    import json
                    mac_list = json.loads(mac_str)
                    if isinstance(mac_list, list):
                        for mac in mac_list:
                            if mac and mac not in details['mac_addresses']:
                                details['mac_addresses'].append(mac)
                except (json.JSONDecodeError, TypeError):
                    pass
        
        # Detect OS type from artifact types
        os_result = client.query(
            """SELECT artifact_type, count() as cnt
               FROM events 
               WHERE case_id = {case_id:UInt32} 
                 AND source_host = {hostname:String}
               GROUP BY artifact_type
               ORDER BY cnt DESC
               LIMIT 5""",
            parameters={'case_id': case_id, 'hostname': hostname}
        )
        for row in os_result.result_rows:
            artifact_type = row[0]
            if artifact_type in ('evtx', 'registry', 'prefetch', 'mft', 'jumplist', 'lnk', 'srum'):
                details['os_type'] = 'Windows'
                break
        
        # Check extra_fields for detailed OS info (from NDJSON sources like Huntress)
        # host_os contains full name like "Windows 10 Pro"
        # host_os_version contains version like "10.0.19045"
        os_extra_result = client.query(
            """SELECT 
                 JSONExtractString(extra_fields, 'host_os') as os_full,
                 JSONExtractString(extra_fields, 'host_os_version') as os_ver
               FROM events 
               WHERE case_id = {case_id:UInt32} 
                 AND source_host = {hostname:String}
                 AND extra_fields != ''
                 AND extra_fields != '{}'
                 AND (JSONExtractString(extra_fields, 'host_os') != '' 
                      OR JSONExtractString(extra_fields, 'host_os_version') != '')
               LIMIT 1""",
            parameters={'case_id': case_id, 'hostname': hostname}
        )
        for row in os_extra_result.result_rows:
            os_full = row[0]  # e.g., "Windows 10 Pro"
            os_ver = row[1]   # e.g., "10.0.19045"
            
            # Set OS type from full name if not already set
            if os_full and not details['os_type']:
                if 'windows' in os_full.lower():
                    details['os_type'] = 'Windows'
                elif 'linux' in os_full.lower():
                    details['os_type'] = 'Linux'
                elif 'mac' in os_full.lower() or 'darwin' in os_full.lower():
                    details['os_type'] = 'macOS'
            
            # Build detailed OS version string
            if os_full and os_ver:
                details['os_version'] = f"{os_full} ({os_ver})"
            elif os_full:
                details['os_version'] = os_full
            elif os_ver:
                details['os_version'] = os_ver
        
        # Get domain for alias (hostname.domain)
        domain_result = client.query(
            """SELECT DISTINCT domain
               FROM events 
               WHERE case_id = {case_id:UInt32} 
                 AND source_host = {hostname:String}
                 AND domain != ''
                 AND domain != {hostname:String}
                 AND domain NOT IN ('NT AUTHORITY', 'Builtin', 'Font Driver Host', 'Window Manager')
               LIMIT 5""",
            parameters={'case_id': case_id, 'hostname': hostname}
        )
        for row in domain_result.result_rows:
            domain = row[0]
            if domain and '.' in domain:
                # Add FQDN as alias
                fqdn = f"{hostname}.{domain}".upper()
                if fqdn not in details['aliases']:
                    details['aliases'].append(fqdn)
        
        # Also check extra_fields for host_domain to build FQDN alias
        domain_extra_result = client.query(
            """SELECT DISTINCT JSONExtractString(extra_fields, 'host_domain') as domain
               FROM events 
               WHERE case_id = {case_id:UInt32} 
                 AND source_host = {hostname:String}
                 AND extra_fields != ''
                 AND JSONExtractString(extra_fields, 'host_domain') != ''
               LIMIT 5""",
            parameters={'case_id': case_id, 'hostname': hostname}
        )
        for row in domain_extra_result.result_rows:
            domain = row[0]
            if domain and domain.upper() != hostname.upper():
                # Add hostname.domain as FQDN alias
                fqdn = f"{hostname}.{domain}".upper()
                if fqdn not in details['aliases']:
                    details['aliases'].append(fqdn)
                
    except Exception as e:
        logger.warning(f"Error getting system details for {hostname}: {e}")
    
    return details


def _get_destination_hosts_and_shares(case_id: int) -> Tuple[dict, dict]:
    """Extract destination hostnames and their shares from UNC paths in events
    
    Returns:
        - dest_stats: {hostname: {'count': N, 'last_seen': datetime}}
        - server_shares: {hostname: [share1, share2, ...]}
    """
    import re
    from utils.clickhouse import get_client
    
    dest_stats = {}
    server_shares = {}
    
    # Pattern to extract server and share from UNC paths: \server\share (single backslash in data)
    # Data format: "ServerName: \James-fs1\AS9100_Documents"
    unc_pattern = re.compile(r'\\([^\\]+)\\([^\\]+)$')
    
    try:
        client = get_client()
        
        logger.debug(f"Querying destination hosts for case_id={case_id}")
        
        # Get UNC paths from SMB events (use position() not LIKE for clickhouse-connect)
        result = client.query(
            """SELECT target_path, max(timestamp) as last_ts
               FROM events 
               WHERE case_id = {case_id:UInt32} 
                 AND position(target_path, 'ServerName:') > 0
               GROUP BY target_path
               LIMIT 500""",
            parameters={'case_id': case_id}
        )
        
        logger.info(f"Destination hosts query returned {len(result.result_rows)} rows for case_id={case_id}")
        
        for row in result.result_rows:
            target_path = row[0]
            last_ts = row[1]
            if target_path:
                match = unc_pattern.search(target_path)
                if match:
                    server = match.group(1).upper()
                    share = match.group(2)
                    
                    # Extract NETBIOS from FQDN (JAMES-DC1.JamesMFG.local -> JAMES-DC1)
                    if '.' in server:
                        netbios = server.split('.')[0]
                    else:
                        netbios = server
                    
                    # Track server as a destination host
                    if netbios not in dest_stats:
                        dest_stats[netbios] = {'count': 0, 'last_seen': None}
                    dest_stats[netbios]['count'] += 1
                    if last_ts and (not dest_stats[netbios]['last_seen'] or last_ts > dest_stats[netbios]['last_seen']):
                        dest_stats[netbios]['last_seen'] = last_ts
                    
                    # Track shares for this server (only exclude hidden admin shares)
                    hidden_shares = ('IPC$', 'ADMIN$', 'C$', 'D$', 'E$', 'F$')
                    if share.upper() not in hidden_shares:
                        if netbios not in server_shares:
                            server_shares[netbios] = set()
                        server_shares[netbios].add(share)
                        
    except Exception as e:
        logger.warning(f"Error getting destination hosts: {e}")
    
    # Convert sets to lists
    for server in server_shares:
        server_shares[server] = list(server_shares[server])
    
    return dest_stats, server_shares


def _get_remote_workstations_from_logon_events(case_id: int) -> dict:
    """Extract remote workstation names from logon events (4624)
    
    These are systems that CONNECTED TO our monitored systems - critical for
    threat hunting as they may include attacker workstations.
    
    Extracts WorkstationName AND IpAddress from Event 4624 (Logon) events where:
    - LogonType is 3 (Network) or 10 (RemoteInteractive/RDP)
    - WorkstationName is not empty/'-'
    
    Returns dict: {hostname: {'count': N, 'last_seen': datetime, 'source': 'remote_logon', 'ip_addresses': [...]}}
    """
    from utils.clickhouse import get_client
    
    workstation_stats = {}
    
    try:
        client = get_client()
        
        # Query for workstation names AND their IPs from logon events
        # WorkstationName and IpAddress are stored in raw_json EventData
        result = client.query(
            """SELECT 
                 JSONExtractString(JSONExtractString(raw_json, 'EventData'), 'WorkstationName') as workstation,
                 JSONExtractString(JSONExtractString(raw_json, 'EventData'), 'IpAddress') as ip_addr,
                 count() as cnt,
                 max(timestamp) as last_ts
               FROM events 
               WHERE case_id = {case_id:UInt32} 
                 AND event_id = '4624'
                 AND artifact_type = 'evtx'
               GROUP BY workstation, ip_addr
               HAVING workstation != '' AND workstation != '-'
               LIMIT 1000""",
            parameters={'case_id': case_id}
        )
        
        for row in result.result_rows:
            workstation = row[0]
            ip_addr = row[1]
            count = row[2]
            last_ts = row[3]
            
            if workstation and workstation not in ('-', '', 'null'):
                # Normalize hostname
                workstation = workstation.strip().upper()
                
                # Skip if it looks like an IP address (some events put IP in WorkstationName)
                if workstation.replace('.', '').isdigit():
                    continue
                
                # Skip localhost references
                if workstation in ('LOCALHOST', '127.0.0.1', '-'):
                    continue
                
                if workstation not in workstation_stats:
                    workstation_stats[workstation] = {
                        'count': 0,
                        'last_seen': None,
                        'source': 'remote_logon',
                        'ip_addresses': set()
                    }
                
                workstation_stats[workstation]['count'] += count
                
                # Track last_seen
                if last_ts:
                    current_ls = workstation_stats[workstation]['last_seen']
                    if not current_ls or last_ts > current_ls:
                        workstation_stats[workstation]['last_seen'] = last_ts
                
                # Track IP addresses (the IP this workstation connected FROM)
                if ip_addr and ip_addr not in ('-', '', '127.0.0.1', '::1', 'null'):
                    workstation_stats[workstation]['ip_addresses'].add(ip_addr)
        
        # Convert sets to lists
        for ws in workstation_stats:
            workstation_stats[ws]['ip_addresses'] = list(workstation_stats[ws]['ip_addresses'])
        
        logger.info(f"Found {len(workstation_stats)} unique remote workstations from logon events")
                
    except Exception as e:
        logger.warning(f"Error getting remote workstations from logon events: {e}")
    
    return workstation_stats


def _get_hostnames_from_events(case_id: int) -> dict:
    """Get hostname stats from ClickHouse events table
    
    Returns dict: {hostname: {'count': N, 'last_seen': datetime, 'sources': set}}
    
    Now tracks artifact_type as source (evtx, ndjson, sonicwall, etc.)
    """
    from utils.clickhouse import get_client
    
    hostname_stats = {}
    
    try:
        client = get_client()
        
        # Query source_host with artifact_type for proper source tracking
        result = client.query(
            """SELECT source_host, artifact_type, count() as cnt, max(timestamp) as last_ts
               FROM events 
               WHERE case_id = {case_id:UInt32} 
                 AND source_host != ''
               GROUP BY source_host, artifact_type
               LIMIT 50000""",
            parameters={'case_id': case_id}
        )
        
        for row in result.result_rows:
            hostname = row[0].strip() if row[0] else None
            artifact_type = row[1].lower() if row[1] else 'unknown'
            count = row[2]
            last_ts = row[3]
            
            if not hostname:
                continue
            
            if hostname in hostname_stats:
                hostname_stats[hostname]['count'] += count
                hostname_stats[hostname]['sources'].add(artifact_type)
                if last_ts and (not hostname_stats[hostname]['last_seen'] or last_ts > hostname_stats[hostname]['last_seen']):
                    hostname_stats[hostname]['last_seen'] = last_ts
            else:
                hostname_stats[hostname] = {
                    'count': count,
                    'last_seen': last_ts,
                    'sources': {artifact_type}
                }
                
    except Exception as e:
        logger.warning(f"Error querying ClickHouse for hostnames: {e}")
    
    return hostname_stats


def _process_hostname(hostname: str, case_id: int, username: str,
                      artifact_count: int = 1, last_seen: datetime = None,
                      shares: List[str] = None, logon_ips: List[str] = None,
                      sources: List[str] = None) -> Tuple[bool, bool, bool]:
    """Process a single hostname through deduplication logic
    
    Args:
        hostname: The hostname to process
        case_id: Case ID for linking
        username: User performing discovery
        artifact_count: Number of artifacts referencing this hostname
        last_seen: Timestamp of most recent artifact with this hostname
        shares: List of shares hosted by this system (from UNC paths)
        logon_ips: List of IPs this system connected FROM (from logon events)
        sources: List of data sources (case_files, events, unc_paths, logon_events)
    
    Returns: (created, updated, alias_added)
    """
    if shares is None:
        shares = []
    if logon_ips is None:
        logon_ips = []
    if sources is None:
        sources = []
    created = False
    updated = False
    alias_added = False
    
    # Extract NETBIOS name
    netbios, fqdn = KnownSystem.extract_netbios_name(hostname)
    
    if not netbios:
        return created, updated, alias_added
    
    # Get additional details from ClickHouse events
    details = _get_system_details_from_events(case_id, hostname)
    
    # Find existing system within this case
    system, match_type = KnownSystem.find_by_hostname_or_alias(hostname, case_id=case_id)
    
    if system:
        # Update existing system
        updated = True
        
        # Update last_seen to artifact timestamp (not now)
        if last_seen:
            # Handle timezone comparison
            system_ls = system.last_seen
            compare_ls = last_seen
            if compare_ls and hasattr(compare_ls, 'tzinfo') and compare_ls.tzinfo:
                compare_ls = compare_ls.replace(tzinfo=None)
            if system_ls and hasattr(system_ls, 'tzinfo') and system_ls.tzinfo:
                system_ls = system_ls.replace(tzinfo=None)
            if not system_ls or compare_ls > system_ls:
                system.last_seen = last_seen
        
        # Set artifact count to actual value found in this case
        system.artifacts_with_hostname = artifact_count
        
        # Auto-populate OS type if not set
        if not system.os_type and details.get('os_type'):
            system.os_type = details['os_type']
            KnownSystemAudit.log_change(
                system_id=system.id,
                changed_by=username,
                field_name='os_type',
                action='update',
                old_value=None,
                new_value=details['os_type']
            )
        
        # Auto-populate OS version if not set (from NDJSON sources)
        if not system.os_version and details.get('os_version'):
            system.os_version = details['os_version']
            KnownSystemAudit.log_change(
                system_id=system.id,
                changed_by=username,
                field_name='os_version',
                action='update',
                old_value=None,
                new_value=details['os_version']
            )
        
        # Add discovered IPs (only from host_ip, NOT src_ip)
        for ip in details.get('ip_addresses', []):
            if system.add_ip_address(ip):
                KnownSystemAudit.log_change(
                    system_id=system.id,
                    changed_by=username,
                    field_name='ip_addresses',
                    action='create',
                    new_value=ip
                )
        
        # Add IPs from logon events (for systems we saw connecting to our hosts)
        for ip in logon_ips:
            if system.add_ip_address(ip):
                KnownSystemAudit.log_change(
                    system_id=system.id,
                    changed_by=username,
                    field_name='ip_addresses',
                    action='create',
                    new_value=f"{ip} (from logon events)"
                )
        
        # Add discovered MACs (from host_mac in EDR data)
        for mac in details.get('mac_addresses', []):
            if system.add_mac_address(mac):
                KnownSystemAudit.log_change(
                    system_id=system.id,
                    changed_by=username,
                    field_name='mac_addresses',
                    action='create',
                    new_value=mac
                )
        
        # Add discovered aliases
        for alias in details.get('aliases', []):
            if system.add_alias(alias):
                alias_added = True
                KnownSystemAudit.log_change(
                    system_id=system.id,
                    changed_by=username,
                    field_name='aliases',
                    action='create',
                    new_value=alias
                )
        
        # Add shares hosted by this system
        for share in shares:
            if system.add_share(share):
                KnownSystemAudit.log_change(
                    system_id=system.id,
                    changed_by=username,
                    field_name='found_shares',
                    action='create',
                    new_value=share
                )
        
        # Add FQDN as alias if different from hostname
        if fqdn and fqdn != system.hostname.upper():
            if system.add_alias(fqdn):
                alias_added = True
                KnownSystemAudit.log_change(
                    system_id=system.id,
                    changed_by=username,
                    field_name='aliases',
                    action='create',
                    new_value=fqdn
                )
        
        # Also add the original hostname as alias if different
        if hostname.upper() != system.hostname.upper() and hostname.upper() != fqdn:
            if system.add_alias(hostname.upper()):
                alias_added = True
                KnownSystemAudit.log_change(
                    system_id=system.id,
                    changed_by=username,
                    field_name='aliases',
                    action='create',
                    new_value=hostname.upper()
                )
        
        # Add data sources
        for source in sources:
            system.add_source(source)
        
        # Link to case
        system.link_to_case(case_id)
        
    else:
        # Create new system with NETBIOS name as hostname
        created = True
        
        system = KnownSystem(
            case_id=case_id,
            hostname=netbios,
            artifacts_with_hostname=artifact_count,
            added_on=datetime.utcnow(),
            last_seen=last_seen if last_seen else datetime.utcnow(),
            os_type=details.get('os_type'),  # Auto-set from artifacts
            os_version=details.get('os_version'),  # Auto-set from NDJSON sources
            sources=sources  # Track data sources
        )
        db.session.add(system)
        db.session.flush()  # Get the ID
        
        # Log creation
        KnownSystemAudit.log_change(
            system_id=system.id,
            changed_by=username,
            field_name='system',
            action='create',
            new_value=netbios
        )
        
        # Add FQDN as alias if we had one
        if fqdn:
            system.add_alias(fqdn)
            alias_added = True
            KnownSystemAudit.log_change(
                system_id=system.id,
                changed_by=username,
                field_name='aliases',
                action='create',
                new_value=fqdn
            )
        
        # Add discovered IPs (only from host_ip, NOT src_ip)
        for ip in details.get('ip_addresses', []):
            system.add_ip_address(ip)
            KnownSystemAudit.log_change(
                system_id=system.id,
                changed_by=username,
                field_name='ip_addresses',
                action='create',
                new_value=ip
            )
        
        # Add IPs from logon events (for systems we saw connecting to our hosts)
        for ip in logon_ips:
            system.add_ip_address(ip)
            KnownSystemAudit.log_change(
                system_id=system.id,
                changed_by=username,
                field_name='ip_addresses',
                action='create',
                new_value=f"{ip} (from logon events)"
            )
        
        # Add discovered MACs (from host_mac in EDR data)
        for mac in details.get('mac_addresses', []):
            system.add_mac_address(mac)
            KnownSystemAudit.log_change(
                system_id=system.id,
                changed_by=username,
                field_name='mac_addresses',
                action='create',
                new_value=mac
            )
        
        # Add discovered aliases
        for alias in details.get('aliases', []):
            if system.add_alias(alias):
                alias_added = True
                KnownSystemAudit.log_change(
                    system_id=system.id,
                    changed_by=username,
                    field_name='aliases',
                    action='create',
                    new_value=alias
                )
        
        # Add shares hosted by this system
        for share in shares:
            system.add_share(share)
            KnownSystemAudit.log_change(
                system_id=system.id,
                changed_by=username,
                field_name='found_shares',
                action='create',
                new_value=share
            )
        
        # Link to case
        system.link_to_case(case_id)
    
    return created, updated, alias_added


def add_ip_to_system(system_id: int, ip_address: str, username: str) -> bool:
    """Add an IP address to a system with audit logging"""
    system = KnownSystem.query.get(system_id)
    if not system:
        return False
    
    if system.add_ip_address(ip_address):
        KnownSystemAudit.log_change(
            system_id=system_id,
            changed_by=username,
            field_name='ip_addresses',
            action='create',
            new_value=ip_address
        )
        db.session.commit()
        return True
    return False


def add_share_to_system(system_id: int, share_name: str, share_path: str, username: str) -> bool:
    """Add a share to a system with audit logging"""
    system = KnownSystem.query.get(system_id)
    if not system:
        return False
    
    if system.add_share(share_name, share_path):
        KnownSystemAudit.log_change(
            system_id=system_id,
            changed_by=username,
            field_name='shares',
            action='create',
            new_value=f"{share_name} ({share_path})" if share_path else share_name
        )
        db.session.commit()
        return True
    return False


def update_system_field(system_id: int, field_name: str, new_value, username: str) -> bool:
    """Update a system field with audit logging
    
    Allowed fields: os_type, os_version, system_type, notes, compromised, hidden
    """
    allowed_fields = ['os_type', 'os_version', 'system_type', 'notes', 'compromised', 'hidden']
    
    if field_name not in allowed_fields:
        return False
    
    system = KnownSystem.query.get(system_id)
    if not system:
        return False
    
    old_value = getattr(system, field_name)
    
    # Don't log if value hasn't changed
    if old_value == new_value:
        return True
    
    setattr(system, field_name, new_value)
    
    KnownSystemAudit.log_change(
        system_id=system_id,
        changed_by=username,
        field_name=field_name,
        action='update',
        old_value=old_value,
        new_value=new_value
    )
    
    db.session.commit()
    return True


def get_systems_for_case(case_id: int) -> List[Dict]:
    """Get all known systems for a case"""
    systems = []
    
    # Systems are now directly associated with cases via case_id column
    for system in KnownSystem.query.filter_by(case_id=case_id).all():
        system_dict = system.to_dict()
        system_dict['first_seen_in_case'] = system.added_on.isoformat() if system.added_on else None
        systems.append(system_dict)
    
    return systems


def get_system_audit_history(system_id: int) -> List[Dict]:
    """Get audit history for a system"""
    audits = KnownSystemAudit.query.filter_by(
        system_id=system_id
    ).order_by(KnownSystemAudit.changed_on.desc()).all()
    
    return [audit.to_dict() for audit in audits]
