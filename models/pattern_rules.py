"""Complete Non-AI Pattern Matching Rules for CaseScope

COMPREHENSIVE EDITION - January 18, 2026
Includes ALL MITRE ATT&CK v18 patterns from threat intelligence integration

Rule-based detection patterns for common attack techniques.
These patterns use ClickHouse queries to identify suspicious activity
without requiring AI/ML components.

PATTERN TYPES:
==============
1. SIMPLE PATTERNS: Basic event filtering (legacy)
   - Just finds matching events, groups by host
   - Prone to false positives over long timeframes

2. TEMPORAL PATTERNS: Correlated attack detection (preferred)
   - Anchor event: Primary indicator that triggers detection
   - Supporting indicators: Must occur within time window of anchor
   - Attack window grouping: Clusters nearby detections
   - Much higher accuracy, lower false positives

TEMPORAL PATTERN STRUCTURE:
===========================
{
    'id': 'pattern_id',
    'name': 'Pattern Name',
    'temporal': True,  # Marks this as temporal pattern
    'anchor': {
        'description': 'What triggers the detection',
        'event_ids': ['4648'],  # Primary event IDs
        'conditions': "channel = 'Security'"  # Additional SQL conditions
    },
    'supporting': [
        {
            'name': 'indicator_name',
            'required': True,  # Must be present for detection
            'window_seconds': 300,  # ±5 minutes from anchor
            'event_ids': ['4624'],
            'conditions': "logon_type = 3"
        }
    ],
    'attack_window_minutes': 30,  # Group anchors within this time
    'detection_query': "..."  # ClickHouse query with temporal logic
}
"""

from typing import Dict, List, Any

# ============================================================================
# CREDENTIAL ACCESS PATTERNS (MITRE ATT&CK TA0006)
# ============================================================================

CREDENTIAL_ATTACK_PATTERNS = [
    # ========== T1550.002: Pass the Hash (TEMPORAL) ==========
    {
        'id': 'pass_the_hash',
        'name': 'Pass the Hash',
        'category': 'Credential Access',
        'description': 'NTLM authentication with KeyLength=0 (hash-based) without corresponding Kerberos TGT or explicit credentials within attack window. Strong indicator of Pass-the-Hash attack using stolen NTLM hashes.',
        'severity': 'critical',
        'mitre_tactics': ['Credential Access', 'Lateral Movement'],
        'mitre_techniques': ['T1550.002'],
        'temporal': True,
        'anchor': {
            'description': 'NTLM logon with KeyLength=0 (hash-based auth)',
            'event_ids': ['4624'],
            'conditions': "logon_type IN (3, 9) AND search_blob LIKE '%NTLM%' AND JSONExtractString(raw_json, 'EventData', 'KeyLength') = '0'"
        },
        'supporting': [
            {
                'name': 'kerberos_tgt',
                'required': False,  # ABSENCE strengthens detection
                'negate': True,  # If present, reduces confidence
                'window_seconds': 0,  # Check entire case for this user
                'event_ids': ['4768'],
                'conditions': None
            },
            {
                'name': 'explicit_credentials',
                'required': False,
                'negate': True,  # If present within window, reduces confidence
                'window_seconds': 600,  # ±10 minutes
                'event_ids': ['4648'],
                'conditions': None
            }
        ],
        'attack_window_minutes': 60,
        'detection_query': """
            WITH 
            -- Anchor: NTLM logons with KeyLength=0 (definitive PTH indicator)
            ntlm_logons AS (
                SELECT 
                    source_host,
                    username,
                    timestamp as anchor_time,
                    logon_type,
                    JSONExtractString(raw_json, 'EventData', 'IpAddress') as src_ip,
                    JSONExtractString(raw_json, 'EventData', 'WorkstationName') as workstation
                FROM events
                WHERE case_id = {case_id:UInt32}
                    AND event_id = '4624'
                    AND channel = 'Security'
                    AND logon_type IN (3, 9)
                    AND (search_blob LIKE '%NTLM%' OR search_blob LIKE '%NtLmSsp%')
                    AND JSONExtractString(raw_json, 'EventData', 'KeyLength') = '0'
            ),
            -- Group into attack windows (1 hour) - detect ALL KeyLength=0 events
            attack_windows AS (
                SELECT 
                    source_host,
                    username,
                    min(anchor_time) as first_seen,
                    max(anchor_time) as last_seen,
                    count() as pth_attempts,
                    count(DISTINCT src_ip) as unique_sources,
                    count(DISTINCT workstation) as unique_workstations,
                    groupUniqArray(logon_type) as logon_types,
                    groupUniqArray(src_ip) as source_ips
                FROM ntlm_logons
                GROUP BY 
                    source_host, 
                    username,
                    toStartOfInterval(anchor_time, INTERVAL 1 HOUR)
            )
            SELECT 
                source_host,
                username,
                first_seen,
                last_seen,
                pth_attempts as ntlm_attempts,
                unique_sources,
                unique_workstations,
                logon_types,
                source_ips,
                dateDiff('minute', first_seen, last_seen) as duration_minutes
            FROM attack_windows
            WHERE pth_attempts >= 1
            ORDER BY pth_attempts DESC, first_seen ASC
        """,
        'indicators': [
            'Event 4624 logon type 3/9 with NTLM and KeyLength=0',
            'KeyLength=0 is definitive proof of hash-based authentication',
            'Network logon (type 3) or new credentials logon (type 9)',
            'Grouped into 1-hour attack windows',
            'Multiple sources/workstations increases confidence'
        ],
        'thresholds': {
            'min_logons': 1,
            'key_length': '0',
            'max_explicit_cred_delay': 600
        }
    },
    
    # ========== CUSTOM: NTLMv1 Protocol Downgrade (TEMPORAL) ==========
    {
        'id': 'ntlmv1_downgrade',
        'name': 'NTLMv1 Protocol Downgrade Attack',
        'category': 'Credential Access',
        'description': 'Use of insecure NTLMv1 authentication protocol detected. NTLMv1 is vulnerable to rainbow table attacks and should never be used. Often indicates active credential theft or severely misconfigured legacy system.',
        'severity': 'critical',
        'mitre_tactics': ['Credential Access', 'Defense Evasion'],
        'mitre_techniques': ['T1550.002', 'T1112'],
        'temporal': True,
        'anchor': {
            'description': 'NTLMv1 downgrade event (4023)',
            'event_ids': ['4023'],
            'conditions': None
        },
        'supporting': [
            {
                'name': 'successful_logon',
                'required': False,
                'negate': False,
                'window_seconds': 300,
                'event_ids': ['4624'],
                'conditions': None
            }
        ],
        'attack_window_minutes': 30,
        'detection_query': """
            WITH 
            -- Anchor: NTLMv1 downgrade events
            ntlmv1_events AS (
                SELECT 
                    source_host,
                    username,
                    timestamp as anchor_time,
                    JSONExtractString(raw_json, 'EventData', 'WorkstationName') as workstation,
                    JSONExtractString(raw_json, 'EventData', 'IpAddress') as src_ip
                FROM events
                WHERE case_id = {case_id:UInt32}
                    AND event_id = '4023'
                    AND channel = 'Security'
            ),
            -- Successful logons for correlation
            recent_logons AS (
                SELECT username, source_host, timestamp
                FROM events
                WHERE case_id = {case_id:UInt32}
                    AND event_id = '4624'
                    AND channel = 'Security'
            ),
            -- Correlate: find NTLMv1 with nearby successful logons
            correlated AS (
                SELECT 
                    n.source_host,
                    n.username,
                    n.anchor_time,
                    n.workstation,
                    n.src_ip,
                    -- Check for successful logon within 5 minutes after NTLMv1
                    (SELECT count() FROM recent_logons l 
                     WHERE l.username = n.username 
                     AND l.source_host = n.source_host
                     AND l.timestamp BETWEEN n.anchor_time AND n.anchor_time + INTERVAL 5 MINUTE) as nearby_logons
                FROM ntlmv1_events n
            ),
            -- Group into attack windows (30 minutes)
            attack_windows AS (
                SELECT 
                    source_host,
                    username,
                    min(anchor_time) as first_seen,
                    max(anchor_time) as last_seen,
                    count() as ntlmv1_count,
                    sum(nearby_logons) as successful_logons_after,
                    groupUniqArray(workstation) as workstations,
                    groupUniqArray(src_ip) as source_ips
                FROM correlated
                GROUP BY 
                    source_host, 
                    username,
                    toStartOfInterval(anchor_time, INTERVAL 30 MINUTE)
            )
            SELECT 
                source_host,
                username,
                first_seen,
                last_seen,
                ntlmv1_count,
                successful_logons_after,
                workstations,
                source_ips,
                dateDiff('minute', first_seen, last_seen) as duration_minutes
            FROM attack_windows
            WHERE ntlmv1_count >= 1
            ORDER BY successful_logons_after DESC, ntlmv1_count DESC, first_seen ASC
        """,
        'indicators': [
            'Event 4023: Downgrade to NTLMv1 detected (anchor)',
            'Grouped into 30-minute attack windows',
            'NTLMv1 is deprecated since 2006',
            'Extremely vulnerable to rainbow table attacks',
            'Often indicates active credential theft'
        ],
        'thresholds': {
            'min_events': 1,
            'severity_multiplier_if_successful': 2.0
        }
    },
    
    # ========== T1550.003: Pass the Ticket (TEMPORAL) ==========
    {
        'id': 'pass_the_ticket',
        'name': 'Pass the Ticket',
        'category': 'Credential Access',
        'description': 'Kerberos tickets used from hosts that did not request them, or mismatched client addresses. Indicates stolen TGT/TGS ticket reuse.',
        'severity': 'critical',
        'mitre_tactics': ['Credential Access', 'Lateral Movement'],
        'mitre_techniques': ['T1550.003'],
        'temporal': True,
        'anchor': {
            'description': 'Kerberos logon (4624 type 3) without preceding TGT request',
            'event_ids': ['4624'],
            'conditions': "logon_type = 3 AND search_blob LIKE '%Kerberos%'"
        },
        'supporting': [
            {
                'name': 'missing_tgt',
                'required': False,
                'negate': True,
                'window_seconds': 3600,
                'event_ids': ['4768'],
                'conditions': None
            },
            {
                'name': 'missing_tgs',
                'required': False,
                'negate': True,
                'window_seconds': 3600,
                'event_ids': ['4769'],
                'conditions': None
            }
        ],
        'attack_window_minutes': 60,
        'detection_query': """
            WITH 
            -- Anchor: Kerberos logons (type 3 network logon with Kerberos)
            kerberos_logons AS (
                SELECT 
                    source_host,
                    username,
                    timestamp as anchor_time,
                    JSONExtractString(raw_json, 'EventData', 'IpAddress') as logon_ip
                FROM events
                WHERE case_id = {case_id:UInt32}
                    AND event_id = '4624'
                    AND channel = 'Security'
                    AND logon_type = 3
                    AND search_blob LIKE '%Kerberos%'
            ),
            -- TGT requests (4768) within 1 hour before logon
            tgt_requests AS (
                SELECT username, source_host, timestamp
                FROM events
                WHERE case_id = {case_id:UInt32}
                    AND event_id = '4768'
                    AND channel = 'Security'
            ),
            -- TGS requests (4769) within 1 hour before logon  
            tgs_requests AS (
                SELECT username, source_host, timestamp
                FROM events
                WHERE case_id = {case_id:UInt32}
                    AND event_id = '4769'
                    AND channel = 'Security'
            ),
            -- Correlate: find logons without preceding ticket requests
            correlated AS (
                SELECT 
                    k.source_host,
                    k.username,
                    k.anchor_time,
                    k.logon_ip,
                    -- Check for TGT within 1 hour before logon
                    (SELECT count() FROM tgt_requests t 
                     WHERE t.username = k.username 
                     AND t.source_host = k.source_host
                     AND t.timestamp BETWEEN k.anchor_time - INTERVAL 1 HOUR AND k.anchor_time) as nearby_tgt,
                    -- Check for TGS within 1 hour before logon
                    (SELECT count() FROM tgs_requests s
                     WHERE s.username = k.username
                     AND s.source_host = k.source_host
                     AND s.timestamp BETWEEN k.anchor_time - INTERVAL 1 HOUR AND k.anchor_time) as nearby_tgs
                FROM kerberos_logons k
            ),
            -- Filter: only keep logons WITHOUT preceding ticket requests (Pass the Ticket indicator)
            filtered AS (
                SELECT * FROM correlated
                WHERE nearby_tgt = 0 AND nearby_tgs = 0
            ),
            -- Group into attack windows (1 hour)
            attack_windows AS (
                SELECT 
                    source_host,
                    username,
                    min(anchor_time) as first_seen,
                    max(anchor_time) as last_seen,
                    count() as ptt_logons,
                    count(DISTINCT logon_ip) as unique_ips,
                    groupUniqArray(logon_ip) as logon_ips
                FROM filtered
                GROUP BY 
                    source_host, 
                    username,
                    toStartOfInterval(anchor_time, INTERVAL 1 HOUR)
            )
            SELECT 
                source_host,
                username,
                first_seen,
                last_seen,
                ptt_logons as logon_count,
                unique_ips,
                logon_ips,
                0 as tgt_requests,
                0 as tgs_requests,
                dateDiff('minute', first_seen, last_seen) as duration_minutes
            FROM attack_windows
            WHERE ptt_logons >= 1
            ORDER BY ptt_logons DESC, first_seen ASC
        """,
        'indicators': [
            'Event 4624 Kerberos logon without Event 4768 TGT within 1 hour (anchor)',
            'Event 4624 Kerberos logon without Event 4769 TGS within 1 hour (anchor)',
            'Grouped into 1-hour attack windows',
            'Ticket usage from unexpected hosts without local request'
        ],
        'thresholds': {'min_logons': 1}
    },

    # ========== T1003.006: DCSync Attack ==========
    {
        'id': 'dcsync_attack',
        'name': 'DCSync - Domain Replication Credential Theft',
        'category': 'Credential Access',
        'description': 'Abuse of Directory Replication Service (DRS) to request password data from Domain Controller. Mimikatz DCSync technique. Does not require code execution on DC.',
        'severity': 'critical',
        'mitre_tactics': ['Credential Access'],
        'mitre_techniques': ['T1003.006'],
        'detection_query': """
            WITH replication_requests AS (
                SELECT 
                    source_host,
                    username,
                    timestamp,
                    JSONExtractString(raw_json, 'EventData', 'Properties') as properties,
                    JSONExtractString(raw_json, 'EventData', 'AccessMask') as access_mask
                FROM events
                WHERE case_id = {case_id:UInt32}
                    AND event_id = '4662'
                    AND channel = 'Security'
                    AND (
                        lower(search_blob) LIKE '%1131f6aa-9c07-11d1-f79f-00c04fc2dcd2%'
                        OR lower(search_blob) LIKE '%1131f6ad-9c07-11d1-f79f-00c04fc2dcd2%'
                        OR lower(search_blob) LIKE '%89e95b76-444d-4c62-991a-0facbeda640c%'
                    )
            ),
            non_dc_systems AS (
                SELECT DISTINCT source_host
                FROM events
                WHERE case_id = {case_id:UInt32}
                    AND source_host NOT LIKE '%DC%'
                    AND source_host NOT LIKE '%DOMAINCONTROLLER%'
            )
            SELECT 
                r.source_host,
                r.username,
                COUNT() as replication_requests,
                MIN(r.timestamp) as first_seen,
                MAX(r.timestamp) as last_seen,
                dateDiff('second', MIN(r.timestamp), MAX(r.timestamp)) as duration_seconds
            FROM replication_requests r
            INNER JOIN non_dc_systems n ON r.source_host = n.source_host
            GROUP BY r.source_host, r.username
            HAVING replication_requests >= 1
            ORDER BY replication_requests DESC
        """,
        'indicators': [
            'Event 4662 with DS-Replication-Get-Changes GUIDs from non-DC',
            'GUID 1131f6aa: DS-Replication-Get-Changes permission',
            'GUID 1131f6ad: DS-Replication-Get-Changes-All (includes passwords)',
            'Requests from workstations/servers, not Domain Controllers',
            'Tools: Mimikatz lsadump::dcsync, Invoke-Mimikatz'
        ],
        'thresholds': {
            'min_events': 1,
            'exclude_dc_hosts': True
        }
    },
    
    # ========== T1003.001: LSASS Memory Dumping ==========
    {
        'id': 'credential_dumping_lsass',
        'name': 'Credential Dumping (LSASS)',
        'category': 'Credential Access',
        'description': 'Access to LSASS process indicating credential harvesting (mimikatz, procdump, etc.).',
        'severity': 'critical',
        'mitre_tactics': ['Credential Access'],
        'mitre_techniques': ['T1003.001'],
        'detection_query': """
            SELECT 
                source_host,
                count() as dump_events,
                groupArray(event_id) as event_ids,
                groupArray(process_name) as processes,
                min(timestamp) as first_seen,
                max(timestamp) as last_seen
            FROM events
            WHERE case_id = {case_id:UInt32}
                AND (
                    (event_id = '10' AND lower(search_blob) LIKE '%lsass%' 
                        AND (search_blob LIKE '%0x1010%' OR search_blob LIKE '%0x1038%' OR search_blob LIKE '%0x143A%'))
                    OR lower(search_blob) LIKE '%mimikatz%'
                    OR lower(search_blob) LIKE '%sekurlsa%'
                    OR lower(search_blob) LIKE '%procdump%lsass%'
                    OR lower(command_line) LIKE '%comsvcs.dll%minidump%'
                )
            GROUP BY source_host
            HAVING dump_events >= 1
        """,
        'indicators': [
            'Sysmon Event 10 with lsass.exe target',
            'GrantedAccess masks: 0x1010, 0x1038, 0x143A',
            'Event 4656/4663 on SAM/SYSTEM/SECURITY hives',
            'Memory dump file creation'
        ],
        'thresholds': {'min_events': 1}
    },

    # ========== T1003.002: SAM Database Dumping ==========
    {
        'id': 'sam_database_dump',
        'name': 'SAM Database Credential Dumping',
        'category': 'Credential Access',
        'description': 'Access to Security Account Manager (SAM) database files to extract local account password hashes. Often done via registry hive copying or volume shadow copies.',
        'severity': 'critical',
        'mitre_tactics': ['Credential Access'],
        'mitre_techniques': ['T1003.002'],
        'detection_query': """
            SELECT 
                source_host,
                username,
                COUNT() as sam_access_events,
                groupArray(DISTINCT event_id) as event_ids,
                groupArray(DISTINCT process_name) as processes,
                MIN(timestamp) as first_seen,
                MAX(timestamp) as last_seen
            FROM events
            WHERE case_id = {case_id:UInt32}
                AND (
                    (event_id IN ('4656', '4663', '4658') 
                        AND (lower(search_blob) LIKE '%\\config\\sam%' 
                            OR lower(search_blob) LIKE '%\\system32\\config\\sam%'))
                    OR (event_id = '4657' 
                        AND lower(search_blob) LIKE '%\\sam\\sam\\%')
                    OR (lower(command_line) LIKE '%reg%save%hklm\\sam%'
                        OR lower(command_line) LIKE '%reg%save%hklm\\system%'
                        OR lower(command_line) LIKE '%reg%save%hklm\\security%')
                    OR (lower(command_line) LIKE '%vssadmin%create%shadow%'
                        AND lower(search_blob) LIKE '%sam%')
                    OR (event_id = '11' 
                        AND (lower(search_blob) LIKE '%sam.sav%'
                            OR lower(search_blob) LIKE '%system.sav%'
                            OR lower(search_blob) LIKE '%security.sav%'))
                )
            GROUP BY source_host, username
            HAVING sam_access_events >= 1
            ORDER BY sam_access_events DESC
        """,
        'indicators': [
            'Event 4656/4663: SAM/SYSTEM/SECURITY hive access',
            'Event 4657: Registry SAM modifications',
            'Reg.exe save commands for hive extraction',
            'Sysmon Event 11: .sav file creation',
            'Volume Shadow Copy Service usage'
        ],
        'thresholds': {'min_events': 1}
    },

    # ========== T1003.003: NTDS.dit Credential Dumping ==========
    {
        'id': 'ntds_credential_dump',
        'name': 'NTDS.dit Domain Credential Dumping',
        'category': 'Credential Access',
        'description': 'Extraction of Active Directory database (NTDS.dit) containing domain account hashes. Extreme severity - indicates full domain compromise attempt.',
        'severity': 'critical',
        'mitre_tactics': ['Credential Access'],
        'mitre_techniques': ['T1003.003'],
        'detection_query': """
            SELECT 
                source_host,
                username,
                COUNT() as ntds_access_events,
                groupArray(DISTINCT event_id) as event_ids,
                groupArray(DISTINCT process_name) as processes,
                MIN(timestamp) as first_seen,
                MAX(timestamp) as last_seen
            FROM events
            WHERE case_id = {case_id:UInt32}
                AND (
                    (event_id IN ('4656', '4663', '4658') 
                        AND lower(search_blob) LIKE '%ntds.dit%')
                    OR (lower(process_name) = 'ntdsutil.exe'
                        OR lower(command_line) LIKE '%ntdsutil%')
                    OR (lower(command_line) LIKE '%vssadmin%create%shadow%'
                        AND source_host LIKE '%DC%')
                    OR lower(command_line) LIKE '%ntdsutil%ifm%create%'
                    OR (event_id = '11' 
                        AND lower(search_blob) LIKE '%ntds.dit%')
                    OR (event_id = '5145' 
                        AND lower(search_blob) LIKE '%ntds.dit%')
                )
            GROUP BY source_host, username
            HAVING ntds_access_events >= 1
            ORDER BY ntds_access_events DESC
        """,
        'indicators': [
            'Event 4656/4663: NTDS.dit file access on Domain Controller',
            'ntdsutil.exe execution',
            'IFM (Install From Media) creation',
            'Sysmon Event 11: NTDS.dit copy',
            'Event 5145: Network share access to NTDS.dit'
        ],
        'thresholds': {'min_events': 1}
    },

    # ========== T1003.004: LSA Secrets Dumping (NEW!) ==========
    {
        'id': 'lsa_secrets_dump',
        'name': 'LSA Secrets Credential Dumping',
        'category': 'Credential Access',
        'description': 'Extraction of LSA (Local Security Authority) secrets containing service account passwords, auto-logon credentials, and other sensitive data stored by Windows. Often targeted after initial compromise.',
        'severity': 'high',
        'mitre_tactics': ['Credential Access'],
        'mitre_techniques': ['T1003.004'],
        'detection_query': """
            SELECT 
                source_host,
                username,
                COUNT() as lsa_access_events,
                groupArray(DISTINCT event_id) as event_ids,
                groupArray(DISTINCT process_name) as processes,
                MIN(timestamp) as first_seen,
                MAX(timestamp) as last_seen
            FROM events
            WHERE case_id = {case_id:UInt32}
                AND (
                    -- Registry access to LSA secrets
                    (event_id = '4657' 
                        AND (lower(search_blob) LIKE '%\\policy\\secrets%'
                            OR lower(search_blob) LIKE '%lsa\\secrets%'))
                    -- Reg.exe LSA operations
                    OR (lower(command_line) LIKE '%reg%query%lsa%secrets%'
                        OR lower(command_line) LIKE '%reg%save%lsa%')
                    -- File creation of LSA dumps
                    OR (event_id = '11' 
                        AND (lower(search_blob) LIKE '%lsa.sav%'
                            OR lower(search_blob) LIKE '%secrets.sav%'))
                    -- Mimikatz LSA operations
                    OR (lower(command_line) LIKE '%lsadump::secrets%'
                        OR lower(search_blob) LIKE '%lsadump::secrets%')
                    -- Direct LSA process access
                    OR (event_id = '4663' 
                        AND lower(search_blob) LIKE '%\\policy\\secrets%')
                )
            GROUP BY source_host, username
            HAVING lsa_access_events >= 1
            ORDER BY lsa_access_events DESC
        """,
        'indicators': [
            'Event 4657: Registry modifications to LSA\\Secrets',
            'Sysmon Event 11: LSA secrets file creation',
            'Event 4663: Object access to Policy\\Secrets',
            'Reg.exe queries to LSA secrets location',
            'Mimikatz lsadump::secrets command',
            'Common targets: DPAPI keys, service passwords, auto-logon credentials'
        ],
        'thresholds': {'min_events': 1}
    },

    # ========== T1003.005: Cached Domain Credentials (TEMPORAL) ==========
    {
        'id': 'cached_credentials_dump',
        'name': 'Cached Domain Credentials Dumping',
        'category': 'Credential Access',
        'description': 'Extraction of cached domain credentials (DCC/DCC2) from HKLM\\Security\\Cache. These hashes allow offline cracking of domain passwords and are stored on workstations for offline logon capability.',
        'severity': 'high',
        'mitre_tactics': ['Credential Access'],
        'mitre_techniques': ['T1003.005'],
        'temporal': True,
        'anchor': {
            'description': 'Access to cached credentials registry or dump file',
            'event_ids': ['4656', '4663', '4657', '11'],
            'conditions': "lower(search_blob) LIKE '%\\security\\cache%' OR lower(search_blob) LIKE '%\\cache\\nl$%'"
        },
        'supporting': [],
        'attack_window_minutes': 30,
        'detection_query': """
            WITH cache_events AS (
                SELECT 
                    source_host,
                    username,
                    timestamp,
                    event_id,
                    process_name
                FROM events
                WHERE case_id = {case_id:UInt32}
                    AND (
                        -- Registry access to cache location
                        (event_id IN ('4656', '4663') 
                            AND (lower(search_blob) LIKE '%\\security\\cache%'
                                OR lower(search_blob) LIKE '%\\cache\\nl$%'))
                        -- Registry modifications
                        OR (event_id = '4657' 
                            AND lower(search_blob) LIKE '%\\cache\\nl$%')
                        -- Reg.exe cache operations
                        OR (lower(command_line) LIKE '%reg%save%security%cache%'
                            OR lower(command_line) LIKE '%reg%query%security%cache%')
                        -- File creation for cache dumps
                        OR (event_id = '11' 
                            AND lower(search_blob) LIKE '%cache.sav%')
                        -- Known tools
                        OR (lower(search_blob) LIKE '%cachedump%'
                            OR lower(command_line) LIKE '%cachedump%')
                    )
            ),
            -- Group into 30-minute attack windows
            attack_windows AS (
                SELECT 
                    source_host,
                    username,
                    COUNT() as cache_access_events,
                    groupArray(DISTINCT event_id) as event_ids,
                    groupArray(DISTINCT process_name) as processes,
                    MIN(timestamp) as first_seen,
                    MAX(timestamp) as last_seen
                FROM cache_events
                GROUP BY 
                    source_host, 
                    username,
                    toStartOfInterval(timestamp, INTERVAL 30 MINUTE)
            )
            SELECT 
                source_host,
                username,
                cache_access_events,
                event_ids,
                processes,
                first_seen,
                last_seen,
                dateDiff('minute', first_seen, last_seen) as duration_minutes
            FROM attack_windows
            WHERE cache_access_events >= 1
            ORDER BY cache_access_events DESC, first_seen ASC
        """,
        'indicators': [
            'Event 4656/4663: Access to SECURITY\\Cache registry',
            'Event 4657: Modifications to NL$ cache entries',
            'Reg.exe operations on cached credentials',
            'Sysmon Event 11: Cache dump file creation',
            'Tools: cachedump, Mimikatz, gsecdump',
            'DCC2 hashes can be cracked offline',
            'Grouped into 30-minute attack windows'
        ],
        'thresholds': {'min_events': 1}
    },

    # ========== T1110.003: Password Spraying (TEMPORAL) ==========
    {
        'id': 'password_spraying',
        'name': 'Password Spraying',
        'category': 'Credential Access',
        'description': 'Same password attempted against many accounts in short succession. Detects campaigns within time windows to avoid aggregating separate attacks.',
        'severity': 'high',
        'mitre_tactics': ['Credential Access'],
        'mitre_techniques': ['T1110.003'],
        'temporal': True,
        'anchor': {
            'description': 'Failed login attempt (4625) with bad password code',
            'event_ids': ['4625'],
            'conditions': None
        },
        'supporting': [],
        'attack_window_minutes': 60,
        'detection_query': """
            WITH 
            -- Failed login attempts
            failed_logins AS (
                SELECT 
                    source_host,
                    username,
                    timestamp as anchor_time,
                    JSONExtractString(raw_json, 'EventData', 'SubStatus') as substatus
                FROM events
                WHERE case_id = {case_id:UInt32}
                    AND event_id = '4625'
                    AND channel = 'Security'
            ),
            -- Group into attack windows (1 hour) - by source host
            attack_windows AS (
                SELECT 
                    source_host,
                    min(anchor_time) as first_fail,
                    max(anchor_time) as last_fail,
                    count() as total_failures,
                    count(DISTINCT username) as unique_users,
                    dateDiff('minute', min(anchor_time), max(anchor_time)) as duration_mins,
                    groupUniqArray(username) as usernames,
                    avg(IF(substatus = '0xC000006A', 1, 0)) as bad_password_ratio
                FROM failed_logins
                GROUP BY 
                    source_host,
                    toStartOfInterval(anchor_time, INTERVAL 1 HOUR)
            )
            SELECT 
                source_host,
                first_fail as first_seen,
                last_fail as last_seen,
                total_failures,
                unique_users,
                duration_mins as duration_minutes,
                usernames,
                bad_password_ratio
            FROM attack_windows
            WHERE unique_users >= 10 AND total_failures >= 20 AND duration_mins <= 60
            ORDER BY total_failures DESC, first_fail ASC
        """,
        'indicators': [
            'Event 4625 failed logon across many accounts',
            'Grouped into 1-hour attack windows by source',
            'Failure code 0xC000006A (bad password)',
            'Low attempts per account, high total',
            'Often during off-hours'
        ],
        'thresholds': {'min_users': 10, 'min_failures': 20, 'max_minutes': 60}
    },

    # ========== T1110.001: Brute Force Attack (TEMPORAL) ==========
    {
        'id': 'brute_force',
        'name': 'Brute Force Attack',
        'category': 'Credential Access',
        'description': 'High frequency failed login attempts against single account from single source. Detects bursts of password guessing attacks.',
        'severity': 'high',
        'mitre_tactics': ['Credential Access'],
        'mitre_techniques': ['T1110.001'],
        'temporal': True,
        'anchor': {
            'description': 'Failed login attempt (4625)',
            'event_ids': ['4625'],
            'conditions': None
        },
        'supporting': [],
        'attack_window_minutes': 10,
        'detection_query': """
            WITH 
            -- Failed login attempts
            failed_logins AS (
                SELECT 
                    username,
                    source_host,
                    timestamp as anchor_time,
                    JSONExtractString(raw_json, 'EventData', 'SubStatus') as substatus
                FROM events
                WHERE case_id = {case_id:UInt32}
                    AND event_id = '4625'
                    AND channel = 'Security'
            ),
            -- Group into attack windows (10 minutes - brute force is fast)
            attack_windows AS (
                SELECT 
                    username,
                    source_host,
                    min(anchor_time) as first_fail,
                    max(anchor_time) as last_fail,
                    count() as fail_count,
                    dateDiff('second', min(anchor_time), max(anchor_time)) as duration_secs,
                    groupUniqArray(substatus) as failure_codes
                FROM failed_logins
                GROUP BY 
                    username, 
                    source_host,
                    toStartOfInterval(anchor_time, INTERVAL 10 MINUTE)
            )
            SELECT 
                username,
                source_host,
                first_fail as first_seen,
                last_fail as last_seen,
                fail_count,
                duration_secs,
                failure_codes,
                dateDiff('minute', first_fail, last_fail) as duration_minutes
            FROM attack_windows
            WHERE fail_count >= 10 AND duration_secs <= 600
            ORDER BY fail_count DESC, first_fail ASC
        """,
        'indicators': [
            'Event 4625 high frequency from single source',
            'Burst detection: grouped into 10-minute windows',
            'Failure codes 0xC000006A or 0xC000006D',
            'Account lockouts (Event 4740)',
            'Success (4624) after multiple failures'
        ],
        'thresholds': {'min_failures': 10, 'max_seconds': 600}
    },

    # ========== T1110.004: Credential Stuffing (TEMPORAL) ==========
    {
        'id': 'credential_stuffing',
        'name': 'Credential Stuffing Attack',
        'category': 'Credential Access',
        'description': 'Use of breached username/password pairs from external sources against domain accounts. Similar to password spraying but uses stolen credentials from data breaches.',
        'severity': 'high',
        'mitre_tactics': ['Credential Access'],
        'mitre_techniques': ['T1110.004'],
        'temporal': True,
        'anchor': {
            'description': 'Failed login attempts (4625) from same source',
            'event_ids': ['4625'],
            'conditions': None
        },
        'supporting': [
            {
                'name': 'successful_logon',
                'required': False,
                'negate': False,
                'window_seconds': 3600,
                'event_ids': ['4624'],
                'conditions': None
            }
        ],
        'attack_window_minutes': 60,
        'detection_query': """
            WITH 
            -- Anchor: Failed login attempts with timestamp for windowing
            failed_attempts AS (
                SELECT 
                    username,
                    source_host,
                    timestamp as anchor_time,
                    JSONExtractString(raw_json, 'EventData', 'SubStatus') as substatus
                FROM events
                WHERE case_id = {case_id:UInt32}
                    AND event_id = '4625'
                    AND channel = 'Security'
            ),
            -- Successful logons for correlation
            successful_logons AS (
                SELECT username, source_host, timestamp
                FROM events
                WHERE case_id = {case_id:UInt32}
                    AND event_id = '4624'
                    AND channel = 'Security'
            ),
            -- Group failed attempts into 1-hour attack windows first
            attack_windows AS (
                SELECT 
                    source_host,
                    username,
                    min(anchor_time) as first_attempt,
                    max(anchor_time) as last_attempt,
                    count() as attempts,
                    count(DISTINCT substatus) as unique_substatus,
                    toStartOfInterval(anchor_time, INTERVAL 1 HOUR) as window_start
                FROM failed_attempts
                GROUP BY 
                    source_host, 
                    username,
                    toStartOfInterval(anchor_time, INTERVAL 1 HOUR)
            ),
            -- Correlate with successful logons within window
            correlated AS (
                SELECT 
                    aw.source_host,
                    aw.username,
                    aw.first_attempt as first_seen,
                    aw.last_attempt as last_seen,
                    aw.attempts as total_attempts,
                    aw.unique_substatus,
                    -- Check for successful logon within 1 hour after last failure
                    (SELECT count() FROM successful_logons s 
                     WHERE s.username = aw.username 
                     AND s.source_host = aw.source_host
                     AND s.timestamp BETWEEN aw.first_attempt AND aw.last_attempt + INTERVAL 1 HOUR) as successful_compromises
                FROM attack_windows aw
            )
            SELECT 
                source_host,
                username,
                first_seen,
                last_seen,
                total_attempts,
                unique_substatus,
                successful_compromises,
                dateDiff('minute', first_seen, last_seen) as duration_minutes
            FROM correlated
            WHERE total_attempts >= 5
            ORDER BY successful_compromises DESC, total_attempts DESC, first_seen ASC
        """,
        'indicators': [
            'Event 4625 failed logins grouped into 1-hour attack windows',
            'Mixed SubStatus codes (trying different passwords)',
            'Event 4624 successes after failures indicate credential match',
            'Often uses VPN or proxy sources',
            'Lower velocity than brute force (avoiding detection)'
        ],
        'thresholds': {
            'min_attempts': 5,
            'success_indicates_breach': True
        }
    },

    # ========== T1558.002: Silver Ticket Attack (TEMPORAL) ==========
    {
        'id': 'silver_ticket',
        'name': 'Silver Ticket - Forged Service Ticket',
        'category': 'Credential Access',
        'description': 'Forged Kerberos service ticket (TGS) used for service access without proper TGT. Requires service account hash. Harder to detect than Golden Ticket.',
        'severity': 'critical',
        'mitre_tactics': ['Credential Access', 'Persistence'],
        'mitre_techniques': ['T1558.002'],
        'temporal': True,
        'anchor': {
            'description': 'TGS request (4769) without preceding TGT request (4768)',
            'event_ids': ['4769'],
            'conditions': None
        },
        'supporting': [
            {
                'name': 'missing_tgt',
                'required': True,
                'negate': True,
                'window_seconds': 600,
                'event_ids': ['4768'],
                'conditions': None
            }
        ],
        'attack_window_minutes': 30,
        'detection_query': """
            WITH 
            -- Anchor: TGS service ticket requests
            service_tickets AS (
                SELECT 
                    source_host,
                    username,
                    timestamp as anchor_time,
                    JSONExtractString(raw_json, 'EventData', 'ServiceName') as service_name,
                    JSONExtractString(raw_json, 'EventData', 'TicketOptions') as ticket_options,
                    JSONExtractString(raw_json, 'EventData', 'TicketEncryptionType') as encryption_type
                FROM events
                WHERE case_id = {case_id:UInt32}
                    AND event_id = '4769'
                    AND channel = 'Security'
                    AND username != 'ANONYMOUS LOGON'
            ),
            -- TGT requests for correlation
            tgt_requests AS (
                SELECT username, source_host, timestamp
                FROM events
                WHERE case_id = {case_id:UInt32}
                    AND event_id = '4768'
                    AND channel = 'Security'
            ),
            -- Correlate: find TGS without preceding TGT
            correlated AS (
                SELECT 
                    st.source_host,
                    st.username,
                    st.anchor_time,
                    st.service_name,
                    st.encryption_type,
                    -- Check for TGT within 10 minutes before TGS
                    (SELECT count() FROM tgt_requests tgt 
                     WHERE tgt.username = st.username 
                     AND tgt.source_host = st.source_host
                     AND tgt.timestamp BETWEEN st.anchor_time - INTERVAL 10 MINUTE AND st.anchor_time) as nearby_tgt
                FROM service_tickets st
            ),
            -- Filter: only TGS without preceding TGT (Silver Ticket indicator)
            filtered AS (
                SELECT * FROM correlated
                WHERE nearby_tgt = 0
            ),
            -- Group into attack windows (30 minutes)
            attack_windows AS (
                SELECT 
                    source_host,
                    username,
                    min(anchor_time) as first_seen,
                    max(anchor_time) as last_seen,
                    count() as tgs_requests,
                    count(DISTINCT service_name) as unique_services,
                    groupUniqArray(service_name) as services,
                    countIf(encryption_type = '0x17') as rc4_count
                FROM filtered
                GROUP BY 
                    source_host, 
                    username,
                    toStartOfInterval(anchor_time, INTERVAL 30 MINUTE)
            )
            SELECT 
                source_host,
                username,
                first_seen,
                last_seen,
                tgs_requests,
                unique_services,
                services,
                rc4_count,
                dateDiff('minute', first_seen, last_seen) as duration_minutes
            FROM attack_windows
            WHERE tgs_requests >= 3
            ORDER BY rc4_count DESC, tgs_requests DESC, first_seen ASC
        """,
        'indicators': [
            'Event 4769 TGS requests without Event 4768 TGT within 10 min (anchor)',
            'RC4 encryption (0x17) often used with forged tickets',
            'Multiple service ticket requests grouped into 30-min windows',
            'Ticket appears valid but no prior TGT request'
        ],
        'thresholds': {'min_tgs_requests': 3}
    },

    # ========== T1558.001: Golden Ticket (TEMPORAL) ==========
    {
        'id': 'golden_ticket',
        'name': 'Golden Ticket - Forged TGT',
        'category': 'Credential Access',
        'description': 'Forged Kerberos TGT - TGS requests without preceding TGT request or for non-existent accounts. Requires KRBTGT hash compromise.',
        'severity': 'critical',
        'mitre_tactics': ['Credential Access', 'Persistence'],
        'mitre_techniques': ['T1558.001'],
        'temporal': True,
        'anchor': {
            'description': 'TGS request (4769) without preceding TGT request (4768) in 12-hour window',
            'event_ids': ['4769'],
            'conditions': None
        },
        'supporting': [
            {
                'name': 'missing_tgt',
                'required': True,
                'negate': True,
                'window_seconds': 43200,
                'event_ids': ['4768'],
                'conditions': None
            }
        ],
        'attack_window_minutes': 60,
        'detection_query': """
            WITH 
            -- TGT requests aggregated by user/host/12-hour windows for join
            tgt_windows AS (
                SELECT 
                    username, 
                    source_host, 
                    toStartOfInterval(timestamp, INTERVAL 12 HOUR) as time_window,
                    count() as tgt_count
                FROM events
                WHERE case_id = {case_id:UInt32}
                    AND event_id = '4768'
                    AND channel = 'Security'
                GROUP BY username, source_host, time_window
            ),
            -- Anchor: TGS requests
            tgs_requests AS (
                SELECT 
                    username,
                    source_host,
                    timestamp as anchor_time,
                    toStartOfInterval(timestamp, INTERVAL 12 HOUR) as time_window,
                    JSONExtractString(raw_json, 'EventData', 'TicketEncryptionType') as encryption_type
                FROM events
                WHERE case_id = {case_id:UInt32}
                    AND event_id = '4769'
                    AND channel = 'Security'
            ),
            -- Join to filter: TGS without preceding TGT in same 12-hour window
            filtered AS (
                SELECT tgs.*
                FROM tgs_requests tgs
                LEFT JOIN tgt_windows tgt 
                    ON tgs.username = tgt.username 
                    AND tgs.source_host = tgt.source_host
                    AND tgs.time_window = tgt.time_window
                WHERE tgt.username IS NULL
            ),
            -- Group into attack windows (1 hour)
            attack_windows AS (
                SELECT 
                    source_host,
                    username,
                    min(anchor_time) as first_seen,
                    max(anchor_time) as last_seen,
                    count() as tgs_count,
                    countIf(encryption_type = '0x17') as rc4_tickets
                FROM filtered
                GROUP BY 
                    source_host, 
                    username,
                    toStartOfInterval(anchor_time, INTERVAL 1 HOUR)
            )
            SELECT 
                source_host,
                username,
                first_seen,
                last_seen,
                tgs_count,
                rc4_tickets,
                dateDiff('minute', first_seen, last_seen) as duration_minutes
            FROM attack_windows
            WHERE tgs_count >= 1
            ORDER BY tgs_count DESC, first_seen ASC
        """,
        'indicators': [
            'Event 4769 without Event 4768 in 12-hour window (anchor)',
            'TGS requests grouped into 1-hour attack windows',
            'Unusual ticket lifetimes (10+ years)',
            'RC4 encryption common with forged tickets'
        ],
        'thresholds': {'min_events': 1}
    },

    # ========== T1558.003: Kerberoasting (TEMPORAL) ==========
    {
        'id': 'kerberoasting',
        'name': 'Kerberoasting',
        'category': 'Credential Access',
        'description': 'Burst of TGS requests for service accounts with RC4 encryption indicating offline cracking attempt. Detects enumeration bursts, not scattered activity.',
        'severity': 'high',
        'mitre_tactics': ['Credential Access'],
        'mitre_techniques': ['T1558.003'],
        'temporal': True,
        'anchor': {
            'description': 'TGS request (4769) with RC4 encryption',
            'event_ids': ['4769'],
            'conditions': "search_blob LIKE '%0x17%' OR search_blob LIKE '%RC4%'"
        },
        'supporting': [],
        'attack_window_minutes': 15,
        'detection_query': """
            WITH 
            -- TGS requests with RC4 encryption
            tgs_requests AS (
                SELECT 
                    source_host,
                    username,
                    timestamp as anchor_time,
                    JSONExtractString(raw_json, 'EventData', 'ServiceName') as service_name,
                    CASE WHEN search_blob LIKE '%0x17%' OR search_blob LIKE '%RC4%' THEN 1 ELSE 0 END as is_rc4
                FROM events
                WHERE case_id = {case_id:UInt32}
                    AND event_id = '4769'
                    AND channel = 'Security'
            ),
            -- Group into attack windows (15 minutes - Kerberoasting is typically fast)
            attack_windows AS (
                SELECT 
                    source_host,
                    username,
                    min(anchor_time) as first_seen,
                    max(anchor_time) as last_seen,
                    count() as tgs_requests,
                    sum(is_rc4) as rc4_requests,
                    count(DISTINCT service_name) as unique_services,
                    groupUniqArray(service_name) as service_accounts
                FROM tgs_requests
                GROUP BY 
                    source_host, 
                    username,
                    toStartOfInterval(anchor_time, INTERVAL 15 MINUTE)
            )
            SELECT 
                source_host,
                username,
                first_seen,
                last_seen,
                tgs_requests,
                rc4_requests,
                unique_services,
                service_accounts,
                dateDiff('minute', first_seen, last_seen) as duration_minutes
            FROM attack_windows
            WHERE tgs_requests >= 5 AND rc4_requests >= 3
            ORDER BY rc4_requests DESC, tgs_requests DESC, first_seen ASC
        """,
        'indicators': [
            'Event 4769 with encryption type 0x17 (RC4)',
            'Burst detection: grouped into 15-minute windows',
            'High volume TGS requests from single source',
            'Requests for user account SPNs'
        ],
        'thresholds': {'min_requests': 5, 'min_rc4': 3}
    },

    # ========== T1558.004: AS-REP Roasting (TEMPORAL) ==========
    {
        'id': 'asrep_roasting',
        'name': 'AS-REP Roasting',
        'category': 'Credential Access',
        'description': 'Burst of TGT requests for accounts without pre-authentication, indicating offline password cracking attempt.',
        'severity': 'high',
        'mitre_tactics': ['Credential Access'],
        'mitre_techniques': ['T1558.004'],
        'temporal': True,
        'anchor': {
            'description': 'TGT request (4768) potentially without pre-auth',
            'event_ids': ['4768'],
            'conditions': None
        },
        'supporting': [],
        'attack_window_minutes': 15,
        'detection_query': """
            WITH 
            -- TGT requests
            tgt_requests AS (
                SELECT 
                    source_host,
                    username,
                    timestamp as anchor_time,
                    CASE WHEN search_blob LIKE '%PreAuth%0%' OR search_blob LIKE '%0x0%' THEN 1 ELSE 0 END as is_no_preauth
                FROM events
                WHERE case_id = {case_id:UInt32}
                    AND event_id = '4768'
                    AND channel = 'Security'
            ),
            -- Group into attack windows (15 minutes - AS-REP roasting is typically fast)
            attack_windows AS (
                SELECT 
                    source_host,
                    min(anchor_time) as first_seen,
                    max(anchor_time) as last_seen,
                    count() as tgt_requests,
                    sum(is_no_preauth) as no_preauth,
                    count(DISTINCT username) as unique_users,
                    groupUniqArray(username) as usernames
                FROM tgt_requests
                GROUP BY 
                    source_host,
                    toStartOfInterval(anchor_time, INTERVAL 15 MINUTE)
            )
            SELECT 
                source_host,
                first_seen,
                last_seen,
                tgt_requests,
                no_preauth,
                unique_users,
                usernames,
                dateDiff('minute', first_seen, last_seen) as duration_minutes
            FROM attack_windows
            WHERE tgt_requests >= 5 AND no_preauth >= 1
            ORDER BY no_preauth DESC, tgt_requests DESC, first_seen ASC
        """,
        'indicators': [
            'Event 4768 with pre-auth type 0',
            'Burst detection: grouped into 15-minute windows',
            'Accounts with DONT_REQUIRE_PREAUTH flag',
            'Unusual TGT request volume with RC4'
        ],
        'thresholds': {'min_requests': 5}
    },

    # ========== T1552.001: Credentials in Files ==========
    {
        'id': 'credentials_in_files',
        'name': 'Credentials Stored in Files',
        'category': 'Credential Access',
        'description': 'Detection of credential access from commonly targeted files like web.config, appsettings.json, .env files, scripts, etc.',
        'severity': 'medium',
        'mitre_tactics': ['Credential Access'],
        'mitre_techniques': ['T1552.001'],
        'detection_query': """
            SELECT 
                source_host,
                username,
                COUNT() as credential_file_access,
                groupArray(DISTINCT event_id) as event_ids,
                MIN(timestamp) as first_seen,
                MAX(timestamp) as last_seen,
                groupArray(DISTINCT 
                    JSONExtractString(raw_json, 'EventData', 'TargetFilename')
                ) as accessed_files
            FROM events
            WHERE case_id = {case_id:UInt32}
                AND event_id IN ('4663', '11')
                AND (
                    lower(search_blob) LIKE '%web.config%'
                    OR lower(search_blob) LIKE '%appsettings.json%'
                    OR lower(search_blob) LIKE '%.env%'
                    OR lower(search_blob) LIKE '%database.yml%'
                    OR lower(search_blob) LIKE '%wp-config.php%'
                    OR lower(search_blob) LIKE '%.credentials%'
                    OR lower(search_blob) LIKE '%unattend.xml%'
                    OR lower(search_blob) LIKE '%sysprep.inf%'
                    OR (lower(search_blob) LIKE '%.ps1%' AND search_blob LIKE '%password%')
                    OR (lower(search_blob) LIKE '%.bat%' AND search_blob LIKE '%password%')
                )
            GROUP BY source_host, username
            HAVING credential_file_access >= 1
            ORDER BY credential_file_access DESC
        """,
        'indicators': [
            'Event 4663: Access to credential files',
            'Sysmon Event 11: Creation of credential files',
            'Common files: web.config, .env, database.yml',
            'Unattend.xml, sysprep.inf (deployment credentials)'
        ],
        'thresholds': {'min_events': 1}
    },

    # ========== T1552.002: Credentials in Registry ==========
    {
        'id': 'credentials_in_registry',
        'name': 'Credentials Stored in Registry',
        'category': 'Credential Access',
        'description': 'Detection of plaintext or weakly encrypted credentials stored in Windows Registry.',
        'severity': 'high',
        'mitre_tactics': ['Credential Access'],
        'mitre_techniques': ['T1552.002'],
        'detection_query': """
            SELECT 
                source_host,
                username,
                COUNT() as registry_cred_access,
                groupArray(DISTINCT event_id) as event_ids,
                MIN(timestamp) as first_seen,
                MAX(timestamp) as last_seen,
                groupArray(DISTINCT 
                    JSONExtractString(raw_json, 'EventData', 'ObjectName')
                ) as registry_paths
            FROM events
            WHERE case_id = {case_id:UInt32}
                AND event_id IN ('4657', '13')
                AND (
                    lower(search_blob) LIKE '%password%'
                    OR lower(search_blob) LIKE '%passwd%'
                    OR lower(search_blob) LIKE '%pwd%'
                    OR lower(search_blob) LIKE '%credential%'
                    OR lower(search_blob) LIKE '%secret%'
                    OR lower(search_blob) LIKE '%apikey%'
                    OR lower(search_blob) LIKE '%token%'
                )
                AND search_blob NOT LIKE '%PasswordPolicy%'
                AND search_blob NOT LIKE '%PasswordAge%'
            GROUP BY source_host, username
            HAVING registry_cred_access >= 1
            ORDER BY registry_cred_access DESC
        """,
        'indicators': [
            'Event 4657: Registry value modification with credential keywords',
            'Sysmon Event 13: RegistrySetValue with passwords',
            'Common paths: HKLM\\Software, HKCU\\Software'
        ],
        'thresholds': {'min_events': 1}
    },

    # ========== T1552.004: Private Keys ==========
    {
        'id': 'private_key_theft',
        'name': 'Private Key/Certificate Theft',
        'category': 'Credential Access',
        'description': 'Access to private keys (.key, .pem, .pfx files) or certificate stores. Can be used for authentication or decryption.',
        'severity': 'high',
        'mitre_tactics': ['Credential Access'],
        'mitre_techniques': ['T1552.004'],
        'detection_query': """
            SELECT 
                source_host,
                username,
                COUNT() as key_access_events,
                groupArray(DISTINCT event_id) as event_ids,
                MIN(timestamp) as first_seen,
                MAX(timestamp) as last_seen,
                groupArray(DISTINCT process_name) as processes
            FROM events
            WHERE case_id = {case_id:UInt32}
                AND (
                    (event_id IN ('4663', '11') 
                        AND (lower(search_blob) LIKE '%.key%'
                            OR lower(search_blob) LIKE '%.pem%'
                            OR lower(search_blob) LIKE '%.pfx%'
                            OR lower(search_blob) LIKE '%.p12%'
                            OR lower(search_blob) LIKE '%id_rsa%'
                            OR lower(search_blob) LIKE '%id_dsa%'))
                    OR (event_id = '4656' 
                        AND lower(search_blob) LIKE '%\\microsoft\\systemcertificates%')
                )
            GROUP BY source_host, username
            HAVING key_access_events >= 1
            ORDER BY key_access_events DESC
        """,
        'indicators': [
            'Event 4663: Access to .key, .pem, .pfx files',
            'Sysmon Event 11: Private key file creation',
            'Event 4656: Certificate store access',
            'Common targets: SSH keys, SSL certificates, code signing certs'
        ],
        'thresholds': {'min_events': 1}
    },

    # ========== T1552.006: Group Policy Preferences ==========
    {
        'id': 'gpp_password_theft',
        'name': 'Group Policy Preferences Password Extraction',
        'category': 'Credential Access',
        'description': 'Access to Group Policy Preferences XML files containing cPassword (encrypted passwords). Legacy but still found in old environments.',
        'severity': 'high',
        'mitre_tactics': ['Credential Access'],
        'mitre_techniques': ['T1552.006'],
        'detection_query': """
            SELECT 
                source_host,
                username,
                COUNT() as gpp_access_events,
                groupArray(DISTINCT event_id) as event_ids,
                MIN(timestamp) as first_seen,
                MAX(timestamp) as last_seen
            FROM events
            WHERE case_id = {case_id:UInt32}
                AND (
                    (event_id IN ('4663', '5145') 
                        AND (lower(search_blob) LIKE '%\\sysvol%'
                            AND (lower(search_blob) LIKE '%groups.xml%'
                                OR lower(search_blob) LIKE '%scheduledtasks.xml%'
                                OR lower(search_blob) LIKE '%services.xml%'
                                OR lower(search_blob) LIKE '%datasources.xml%'
                                OR lower(search_blob) LIKE '%printers.xml%'
                                OR lower(search_blob) LIKE '%drives.xml%')))
                    OR search_blob LIKE '%cpassword%'
                    OR lower(command_line) LIKE '%findstr%cpassword%'
                )
            GROUP BY source_host, username
            HAVING gpp_access_events >= 1
            ORDER BY gpp_access_events DESC
        """,
        'indicators': [
            'Event 4663/5145: Access to SYSVOL GPP XML files',
            'Search for cPassword attribute',
            'Common files: groups.xml, scheduledtasks.xml',
            'MS14-025 patched this but old GPOs may remain'
        ],
        'thresholds': {'min_events': 1}
    },

    # ========== T1556.002: Password Filter DLL ==========
    {
        'id': 'password_filter_dll',
        'name': 'Malicious Password Filter DLL',
        'category': 'Credential Access',
        'description': 'Installation of password filter DLL to capture plaintext passwords during password changes. Loads into LSASS on Domain Controllers.',
        'severity': 'critical',
        'mitre_tactics': ['Credential Access', 'Persistence'],
        'mitre_techniques': ['T1556.002'],
        'detection_query': """
            SELECT 
                source_host,
                username,
                COUNT() as filter_events,
                groupArray(DISTINCT event_id) as event_ids,
                MIN(timestamp) as first_seen,
                MAX(timestamp) as last_seen,
                groupArray(DISTINCT process_name) as processes
                FROM events
                WHERE case_id = {case_id:UInt32}
                AND (
                    -- Registry modification for password filters
                    (event_id IN ('4657', '13') 
                        AND lower(search_blob) LIKE '%\\control\\lsa\\notification packages%')
                    -- DLL loaded into LSASS
                    OR (event_id = '7' 
                        AND lower(search_blob) LIKE '%lsass.exe%'
                        AND search_blob NOT LIKE '%\\windows\\system32%'
                        AND lower(search_blob) LIKE '%.dll%')
                    -- File creation of suspicious DLLs
                    OR (event_id = '11' 
                        AND lower(search_blob) LIKE '%\\system32%'
                        AND lower(search_blob) LIKE '%.dll%'
                        AND search_blob NOT LIKE '%microsoft%')
                )
            GROUP BY source_host, username
            HAVING filter_events >= 1
            ORDER BY filter_events DESC
        """,
        'indicators': [
            'Event 4657/13: Modification to Notification Packages registry',
            'Sysmon Event 7: Suspicious DLL load into lsass.exe',
            'Sysmon Event 11: New DLL in System32',
            'Captures plaintext passwords on password change',
            'Requires Domain Admin or SYSTEM privileges'
        ],
        'thresholds': {'min_events': 1}
    },
]

# ============================================================================
# LATERAL MOVEMENT PATTERNS (MITRE ATT&CK TA0008)
# ============================================================================

LATERAL_MOVEMENT_PATTERNS = [
    # ========== T1021.001: Remote Desktop Protocol ==========
    {
        'id': 'rdp_lateral_movement',
        'name': 'Lateral Movement via RDP',
        'category': 'Lateral Movement',
        'description': 'Remote Desktop Protocol connections used for lateral movement. Event 4624 Type 10 indicates RDP logon.',
        'severity': 'medium',
        'mitre_tactics': ['Lateral Movement'],
        'mitre_techniques': ['T1021.001'],
        'detection_query': """
            WITH rdp_logons AS (
                SELECT 
                    source_host,
                    username,
                    timestamp,
                    JSONExtractString(raw_json, 'EventData', 'IpAddress') as src_ip
                FROM events
                WHERE case_id = {case_id:UInt32}
                    AND event_id = '4624'
                    AND logon_type = 10
                    AND channel = 'Security'
            )
            SELECT 
                source_host,
                username,
                COUNT() as rdp_sessions,
                COUNT(DISTINCT src_ip) as unique_sources,
                MIN(timestamp) as first_seen,
                MAX(timestamp) as last_seen,
                groupUniqArray(src_ip) as source_ips
            FROM rdp_logons
            GROUP BY source_host, username
            HAVING rdp_sessions >= 1
            ORDER BY unique_sources DESC, rdp_sessions DESC
        """,
        'indicators': [
            'Event 4624 Logon Type 10 (RemoteInteractive)',
            'Event 4778/4779: Session connect/disconnect',
            'Multiple systems accessed from same source',
            'Off-hours RDP activity'
        ],
        'thresholds': {'min_sessions': 1}
    },

    # ========== T1021.002: SMB/Windows Admin Shares ==========
    {
        'id': 'smb_admin_shares',
        'name': 'Lateral Movement via SMB Admin Shares',
        'category': 'Lateral Movement',
        'description': 'Access to administrative shares (C$, ADMIN$, IPC$) for lateral movement. Common precursor to remote code execution.',
        'severity': 'medium',
        'mitre_tactics': ['Lateral Movement'],
        'mitre_techniques': ['T1021.002'],
        'detection_query': """
                SELECT 
                    source_host,
                    username,
                COUNT() as share_access_count,
                COUNT(DISTINCT JSONExtractString(raw_json, 'EventData', 'ShareName')) as unique_shares,
                MIN(timestamp) as first_seen,
                MAX(timestamp) as last_seen,
                groupUniqArray(JSONExtractString(raw_json, 'EventData', 'ShareName')) as shares_accessed,
                groupUniqArray(JSONExtractString(raw_json, 'EventData', 'IpAddress')) as source_ips
            FROM events
            WHERE case_id = {case_id:UInt32}
                AND event_id IN ('5140', '5145')
                AND (
                    search_blob LIKE '%\\\\C$%'
                    OR search_blob LIKE '%\\\\ADMIN$%'
                    OR search_blob LIKE '%\\\\IPC$%'
                )
            GROUP BY source_host, username
            HAVING share_access_count >= 3
            ORDER BY unique_shares DESC, share_access_count DESC
        """,
        'indicators': [
            'Event 5140: Network share object accessed (C$, ADMIN$)',
            'Event 5145: Shared object access check',
            'Multiple admin shares from single source',
            'Precursor to PsExec, WMI, or file copy'
        ],
        'thresholds': {'min_accesses': 3}
    },

    # ========== T1021.003: Distributed Component Object Model (TEMPORAL) ==========
    {
        'id': 'dcom_lateral_movement',
        'name': 'Lateral Movement via DCOM',
        'category': 'Lateral Movement',
        'description': 'DCOM used for lateral movement and remote code execution. Often abuses MMC20.Application or ShellWindows.',
        'severity': 'high',
        'mitre_tactics': ['Lateral Movement', 'Execution'],
        'mitre_techniques': ['T1021.003'],
        'temporal': True,
        'anchor': {
            'description': 'DCOM logon or execution event',
            'event_ids': ['4624', '1', '4688'],
            'conditions': None
        },
        'supporting': [],
        'attack_window_minutes': 30,
        'detection_query': """
            WITH 
            -- DCOM events
            dcom_events AS (
                SELECT 
                    source_host,
                    username,
                    timestamp as anchor_time,
                    event_id,
                    process_name
                FROM events
                WHERE case_id = {case_id:UInt32}
                    AND (
                        (event_id = '4624' AND logon_type = 3 
                            AND search_blob LIKE '%DCOM%')
                        OR (event_id = '1' 
                            AND (lower(command_line) LIKE '%mmc20.application%'
                                OR lower(command_line) LIKE '%shellwindows%'
                                OR lower(command_line) LIKE '%shellbrowserwindow%'))
                        OR (event_id = '4688'
                            AND lower(command_line) LIKE '%-activationarguments%')
                    )
            ),
            -- Group into attack windows (30 minutes)
            attack_windows AS (
                SELECT 
                    source_host,
                    username,
                    min(anchor_time) as first_seen,
                    max(anchor_time) as last_seen,
                    count() as dcom_events,
                    groupUniqArray(event_id) as event_types,
                    groupUniqArray(process_name) as processes
                FROM dcom_events
                GROUP BY 
                    source_host, 
                    username,
                    toStartOfInterval(anchor_time, INTERVAL 30 MINUTE)
            )
            SELECT 
                source_host,
                username,
                first_seen,
                last_seen,
                dcom_events,
                event_types,
                processes,
                dateDiff('minute', first_seen, last_seen) as duration_minutes
            FROM attack_windows
            WHERE dcom_events >= 1
            ORDER BY dcom_events DESC, first_seen ASC
        """,
        'indicators': [
            'Event 4624 Type 3 with DCOM',
            'Grouped into 30-minute attack windows',
            'Sysmon Event 1: MMC20.Application instantiation',
            'Event 4688: Process with -ActivationArguments',
            'Tools: Invoke-DCOM, lateral movement frameworks'
        ],
        'thresholds': {'min_events': 1}
    },

    # ========== T1021.006: Windows Remote Management (TEMPORAL) ==========
    {
        'id': 'winrm_lateral_movement',
        'name': 'Lateral Movement via WinRM',
        'category': 'Lateral Movement',
        'description': 'Windows Remote Management (PowerShell Remoting) used for lateral movement. Event 4624 Type 3 with wsmprovhost.exe.',
        'severity': 'medium',
        'mitre_tactics': ['Lateral Movement'],
        'mitre_techniques': ['T1021.006'],
        'temporal': True,
        'anchor': {
            'description': 'WinRM logon (4624 Type 3 with WinRM/wsmprovhost)',
            'event_ids': ['4624'],
            'conditions': "logon_type = 3 AND (search_blob LIKE '%wsmprovhost%' OR search_blob LIKE '%WinRM%')"
        },
        'supporting': [
            {
                'name': 'wsmprovhost_process',
                'required': False,
                'negate': False,
                'window_seconds': 60,
                'event_ids': ['1', '4688'],
                'conditions': "process_name = 'wsmprovhost.exe'"
            }
        ],
        'attack_window_minutes': 30,
        'detection_query': """
            WITH 
            -- Anchor: WinRM logons
            winrm_logons AS (
                SELECT 
                    source_host,
                    username,
                    timestamp as anchor_time,
                    JSONExtractString(raw_json, 'EventData', 'IpAddress') as src_ip
                FROM events
                WHERE case_id = {case_id:UInt32}
                    AND event_id = '4624'
                    AND logon_type = 3
                    AND (search_blob LIKE '%wsmprovhost%' OR search_blob LIKE '%WinRM%')
            ),
            -- WinRM processes for correlation
            winrm_processes AS (
                SELECT source_host, timestamp
                FROM events
                WHERE case_id = {case_id:UInt32}
                    AND event_id IN ('1', '4688')
                    AND lower(process_name) = 'wsmprovhost.exe'
            ),
            -- Correlate: find WinRM logons with nearby process creation
            correlated AS (
                SELECT 
                    w.source_host,
                    w.username,
                    w.anchor_time,
                    w.src_ip,
                    -- Check for wsmprovhost process within ±1 minute
                    (SELECT count() FROM winrm_processes p 
                     WHERE p.source_host = w.source_host
                     AND p.timestamp BETWEEN w.anchor_time - INTERVAL 1 MINUTE AND w.anchor_time + INTERVAL 1 MINUTE) as nearby_processes
                FROM winrm_logons w
            ),
            -- Group into attack windows (30 minutes)
            attack_windows AS (
                SELECT 
                    source_host,
                    username,
                    min(anchor_time) as first_seen,
                    max(anchor_time) as last_seen,
                    count() as winrm_sessions,
                    count(DISTINCT src_ip) as unique_sources,
                    sum(nearby_processes) as corroborating_processes,
                    groupUniqArray(src_ip) as source_ips
                FROM correlated
                GROUP BY 
                    source_host, 
                    username,
                    toStartOfInterval(anchor_time, INTERVAL 30 MINUTE)
            )
            SELECT 
                source_host,
                username,
                first_seen,
                last_seen,
                winrm_sessions,
                unique_sources,
                corroborating_processes,
                source_ips,
                dateDiff('minute', first_seen, last_seen) as duration_minutes
            FROM attack_windows
            WHERE winrm_sessions >= 1
            ORDER BY unique_sources DESC, first_seen ASC
        """,
        'indicators': [
            'Event 4624 Type 3 with wsmprovhost.exe/WinRM (anchor)',
            'Grouped into 30-minute attack windows',
            'Sysmon Event 1: wsmprovhost.exe process creation',
            'Event 4648: Explicit credentials (Enter-PSSession)',
            'Network connections on TCP 5985/5986'
        ],
        'thresholds': {'min_sessions': 1}
    },

    # ========== T1570: Lateral Tool Transfer (TEMPORAL) ==========
    {
        'id': 'lateral_tool_transfer',
        'name': 'Lateral Tool Transfer',
        'category': 'Lateral Movement',
        'description': 'Tools transferred to remote systems via SMB shares, often precedes execution. Common in Living off the Land attacks.',
        'severity': 'medium',
        'mitre_tactics': ['Lateral Movement'],
        'mitre_techniques': ['T1570'],
        'temporal': True,
        'anchor': {
            'description': 'File write to admin share (5145)',
            'event_ids': ['5145'],
            'conditions': "executable file types to admin shares"
        },
        'supporting': [],
        'attack_window_minutes': 30,
        'detection_query': """
            WITH 
            -- File transfers to admin shares
            file_transfers AS (
                SELECT 
                    source_host,
                    username,
                    timestamp as anchor_time,
                    JSONExtractString(raw_json, 'EventData', 'ShareName') as share_name,
                    JSONExtractString(raw_json, 'EventData', 'RelativeTargetName') as file_name
                FROM events
                WHERE case_id = {case_id:UInt32}
                    AND event_id = '5145'
                    AND (
                        lower(search_blob) LIKE '%.exe%'
                        OR lower(search_blob) LIKE '%.dll%'
                        OR lower(search_blob) LIKE '%.ps1%'
                        OR lower(search_blob) LIKE '%.bat%'
                        OR lower(search_blob) LIKE '%.vbs%'
                    )
                    AND (
                        search_blob LIKE '%C$%'
                        OR search_blob LIKE '%ADMIN$%'
                        OR search_blob LIKE '%\\Windows\\Temp%'
                        OR search_blob LIKE '%\\ProgramData%'
                    )
            ),
            -- Group into attack windows (30 minutes)
            attack_windows AS (
                SELECT 
                    source_host,
                    username,
                    min(anchor_time) as first_seen,
                    max(anchor_time) as last_seen,
                    count() as file_writes,
                    count(DISTINCT share_name) as unique_shares,
                    groupUniqArray(file_name) as files_written
                FROM file_transfers
                GROUP BY 
                    source_host, 
                    username,
                    toStartOfInterval(anchor_time, INTERVAL 30 MINUTE)
            )
            SELECT 
                source_host,
                username,
                first_seen,
                last_seen,
                file_writes,
                unique_shares,
                files_written,
                dateDiff('minute', first_seen, last_seen) as duration_minutes
            FROM attack_windows
            WHERE file_writes >= 3
            ORDER BY file_writes DESC, first_seen ASC
        """,
        'indicators': [
            'Event 5145: Write access to remote shares',
            'Grouped into 30-minute attack windows',
            'Executables written to C$, ADMIN$',
            'Tools: PsExec, Cobalt Strike, Metasploit',
            'Common paths: \\Windows\\Temp, \\ProgramData'
        ],
        'thresholds': {'min_writes': 3}
    },
    # ========== T1021.002/T1569.002: PsExec Remote Service (TEMPORAL) ==========
    {
        'id': 'psexec_remote_service',
        'name': 'PsExec / Remote Service Execution',
        'category': 'Lateral Movement',
        'description': 'Remote service installation with network logon and SMB access within attack window. High-confidence PsExec or similar tool detection.',
        'severity': 'high',
        'mitre_tactics': ['Lateral Movement', 'Execution'],
        'mitre_techniques': ['T1021.002', 'T1569.002'],
        'temporal': True,
        'anchor': {
            'description': 'New service installed (Event 7045)',
            'event_ids': ['7045'],
            'conditions': None
        },
        'supporting': [
            {
                'name': 'network_logon',
                'required': True,  # PsExec requires network logon
                'window_seconds': 120,
                'event_ids': ['4624'],
                'conditions': "logon_type = 3"
            },
            {
                'name': 'smb_admin_share',
                'required': False,
                'window_seconds': 120,
                'event_ids': ['5145'],
                'conditions': "search_blob LIKE '%ADMIN$%' OR search_blob LIKE '%IPC$%'"
            }
        ],
        'attack_window_minutes': 15,
        'detection_query': """
            WITH 
            -- Anchor: Service installation events
            service_installs AS (
            SELECT 
                source_host,
                    timestamp as anchor_time,
                    username,
                    search_blob,
                    -- Check for PsExec-style naming
                    CASE 
                        WHEN lower(search_blob) LIKE '%psexe%' THEN 'psexec'
                        WHEN lower(search_blob) LIKE '%paexec%' THEN 'paexec'
                        WHEN lower(search_blob) LIKE '%remcom%' THEN 'remcom'
                        ELSE 'unknown_service'
                    END as tool_type
            FROM events
            WHERE case_id = {case_id:UInt32}
                    AND event_id = '7045'
            ),
            -- Supporting: Network logons within ±2 min
            network_logons AS (
                SELECT source_host, timestamp, username
                FROM events
                WHERE case_id = {case_id:UInt32}
                    AND event_id = '4624'
                    AND logon_type = 3
            ),
            -- Supporting: SMB access to admin shares within ±2 min
            smb_access AS (
                SELECT source_host, timestamp
                FROM events
                WHERE case_id = {case_id:UInt32}
                    AND event_id = '5145'
                    AND (search_blob LIKE '%ADMIN$%' OR search_blob LIKE '%IPC$%')
            ),
            -- Correlate: Only services with nearby network logon
            correlated AS (
                SELECT 
                    s.source_host,
                    s.anchor_time,
                    s.username,
                    s.tool_type,
                    (SELECT count() FROM network_logons n 
                     WHERE n.source_host = s.source_host 
                     AND n.timestamp BETWEEN s.anchor_time - INTERVAL 2 MINUTE AND s.anchor_time + INTERVAL 2 MINUTE) as nearby_logons,
                    (SELECT count() FROM smb_access a 
                     WHERE a.source_host = s.source_host 
                     AND a.timestamp BETWEEN s.anchor_time - INTERVAL 2 MINUTE AND s.anchor_time + INTERVAL 2 MINUTE) as nearby_smb
                FROM service_installs s
            ),
            -- Group into attack windows
            attack_windows AS (
                SELECT 
                    source_host,
                    username,
                    min(anchor_time) as first_seen,
                    max(anchor_time) as last_seen,
                    count() as service_count,
                    any(tool_type) as tool_type,
                    sum(nearby_logons) as total_logons,
                    sum(nearby_smb) as total_smb,
                    (CASE WHEN sum(nearby_logons) > 0 THEN 1 ELSE 0 END +
                     CASE WHEN sum(nearby_smb) > 0 THEN 1 ELSE 0 END) as indicator_count
                FROM correlated
                WHERE nearby_logons > 0  -- REQUIRE network logon for PsExec
                GROUP BY 
                    source_host, 
                    username,
                    toStartOfInterval(anchor_time, INTERVAL 15 MINUTE)
            )
            SELECT 
                source_host,
                username,
                first_seen,
                last_seen,
                service_count as services_installed,
                tool_type,
                total_logons as network_logons,
                total_smb as smb_access,
                indicator_count
            FROM attack_windows
            ORDER BY indicator_count DESC, service_count DESC, first_seen ASC
        """,
        'indicators': [
            'Event 7045 new service installed (anchor)',
            'Network logon 4624 type 3 within ±2 min (required)',
            'SMB access to ADMIN$/IPC$ within ±2 min',
            'PsExec/PAExec/RemCom service name patterns'
        ],
        'thresholds': {'min_services': 1, 'require_network_logon': True, 'window_minutes': 15}
    },
    # ========== T1047: WMI Lateral Movement (TEMPORAL) ==========
    {
        'id': 'wmi_lateral',
        'name': 'WMI Lateral Movement',
        'category': 'Lateral Movement',
        'description': 'Windows Management Instrumentation used for remote code execution. Detects correlated WMI activity with network logon and explicit credentials within attack window.',
        'severity': 'high',
        'mitre_tactics': ['Lateral Movement', 'Execution'],
        'mitre_techniques': ['T1047'],
        'temporal': True,
        'anchor': {
            'description': 'WMI-Activity operational event (provider load/query)',
            'event_ids': ['5857', '5860', '5861'],
            'conditions': "channel LIKE '%WMI-Activity%'"
        },
        'supporting': [
            {
                'name': 'network_logon',
                'required': False,  # Strengthens detection but not required
                'window_seconds': 300,
                'event_ids': ['4624'],
                'conditions': "logon_type = 3"
            },
            {
                'name': 'explicit_credentials',
                'required': False,
                'window_seconds': 300,
                'event_ids': ['4648'],
                'conditions': None
            },
            {
                'name': 'wmic_execution',
                'required': False,
                'window_seconds': 120,
                'event_ids': ['1', '4688'],  # Sysmon or Security process creation
                'conditions': "lower(command_line) LIKE '%wmic%' AND lower(command_line) LIKE '%/node:%'"
            }
        ],
        'attack_window_minutes': 30,
        'detection_query': """
            WITH 
            -- Find anchor events: WMI-Activity operational events
            wmi_anchors AS (
                SELECT 
                    source_host,
                    timestamp as anchor_time,
                    username,
                    search_blob
                FROM events
                WHERE case_id = {case_id:UInt32}
                    AND channel LIKE '%WMI-Activity%'
                    AND event_id IN ('5857', '5860', '5861')
            ),
            -- Supporting: network logons aggregated by host/5-min window
            network_logon_windows AS (
                SELECT 
                    source_host, 
                    toStartOfInterval(timestamp, INTERVAL 5 MINUTE) as time_window,
                    count() as logon_count
                FROM events
                WHERE case_id = {case_id:UInt32}
                    AND event_id = '4624'
                    AND logon_type = 3
                GROUP BY source_host, time_window
            ),
            -- Supporting: explicit creds aggregated by host/5-min window
            explicit_cred_windows AS (
                SELECT 
                    source_host, 
                    toStartOfInterval(timestamp, INTERVAL 5 MINUTE) as time_window,
                    count() as cred_count
                FROM events  
                WHERE case_id = {case_id:UInt32}
                    AND event_id = '4648'
                GROUP BY source_host, time_window
            ),
            -- Supporting: wmic execution aggregated by host/2-min window
            wmic_windows AS (
                SELECT 
                    source_host, 
                    toStartOfInterval(timestamp, INTERVAL 2 MINUTE) as time_window,
                    count() as wmic_count
                FROM events
                WHERE case_id = {case_id:UInt32}
                    AND event_id IN ('1', '4688')
                    AND lower(command_line) LIKE '%wmic%'
                    AND lower(command_line) LIKE '%/node:%'
                GROUP BY source_host, time_window
            ),
            -- Join anchors with supporting indicators via windows
            correlated AS (
                SELECT 
                    a.source_host as source_host,
                    a.anchor_time as anchor_time,
                    a.username as username,
                    coalesce(n.logon_count, 0) as nearby_logons,
                    coalesce(e.cred_count, 0) as nearby_creds,
                    coalesce(w.wmic_count, 0) as nearby_wmic
                FROM wmi_anchors a
                LEFT JOIN network_logon_windows n 
                    ON a.source_host = n.source_host 
                    AND toStartOfInterval(a.anchor_time, INTERVAL 5 MINUTE) = n.time_window
                LEFT JOIN explicit_cred_windows e 
                    ON a.source_host = e.source_host 
                    AND toStartOfInterval(a.anchor_time, INTERVAL 5 MINUTE) = e.time_window
                LEFT JOIN wmic_windows w 
                    ON a.source_host = w.source_host 
                    AND toStartOfInterval(a.anchor_time, INTERVAL 2 MINUTE) = w.time_window
            ),
            -- Group into attack windows (30 min clusters)
            attack_windows AS (
                SELECT 
                    source_host,
                    username,
                    min(anchor_time) as first_seen,
                    max(anchor_time) as last_seen,
                    count() as anchor_count,
                    sum(nearby_logons) as total_logons,
                    sum(nearby_creds) as total_creds,
                    sum(nearby_wmic) as total_wmic,
                    -- Confidence boost for corroborating indicators
                    (CASE WHEN sum(nearby_logons) > 0 THEN 1 ELSE 0 END +
                     CASE WHEN sum(nearby_creds) > 0 THEN 1 ELSE 0 END +
                     CASE WHEN sum(nearby_wmic) > 0 THEN 1 ELSE 0 END) as indicator_count
                FROM correlated
                GROUP BY 
                    source_host, 
                    username,
                    toStartOfInterval(anchor_time, INTERVAL 30 MINUTE)
            )
            SELECT 
                source_host,
                username,
                first_seen,
                last_seen,
                anchor_count as wmi_events,
                total_logons as network_logons,
                total_creds as explicit_creds,
                total_wmic as wmic_commands,
                indicator_count,
                -- Higher indicator count = more confident this is real attack
                (anchor_count + total_logons + total_creds + total_wmic * 2) as attack_score
            FROM attack_windows
            WHERE anchor_count >= 1
            ORDER BY indicator_count DESC, attack_score DESC, first_seen ASC
        """,
        'indicators': [
            'WMI-Activity events 5857, 5860, 5861 (anchor)',
            'Network logon 4624 type 3 within ±5 min',
            'Explicit credentials 4648 within ±5 min',
            'wmic.exe /node: execution within ±2 min'
        ],
        'thresholds': {'min_anchors': 1, 'window_minutes': 30}
    },
    # ========== T1053.005: Remote Scheduled Task ==========
    {
        'id': 'remote_scheduled_task',
        'name': 'Remote Scheduled Task',
        'category': 'Lateral Movement',
        'description': 'Scheduled task created remotely for persistence or execution.',
        'severity': 'high',
        'mitre_tactics': ['Lateral Movement', 'Execution', 'Persistence'],
        'mitre_techniques': ['T1053.005'],
        'detection_query': """
            SELECT 
                source_host,
                count() as task_events,
                countIf(event_id = '4698') as tasks_created,
                countIf(event_id = '4624' AND logon_type = 3) as network_logons,
                min(timestamp) as first_seen,
                max(timestamp) as last_seen,
                groupArray(search_blob) as task_details
            FROM events
            WHERE case_id = {case_id:UInt32}
                AND (
                    event_id = '4698'
                    OR (lower(command_line) LIKE '%schtasks%/create%/s %')
                    OR (channel LIKE '%TaskScheduler%' AND event_id IN ('106', '140', '141'))
                )
            GROUP BY source_host
            HAVING tasks_created >= 1
        """,
        'indicators': [
            'Event 4698 scheduled task created',
            'schtasks.exe with /create /s parameters',
            'Event 4624 type 3 preceding task creation'
        ],
        'thresholds': {'min_tasks': 1}
    },
]

# ============================================================================
# PERSISTENCE PATTERNS (MITRE ATT&CK TA0003)
# ============================================================================

PERSISTENCE_PATTERNS = [
    # ========== T1547.001: Registry Run Keys / Startup Folder ==========
    {
        'id': 'registry_run_keys',
        'name': 'Registry Run Keys Persistence',
        'category': 'Persistence',
        'description': 'Modification of registry run keys to achieve persistence. Programs execute at user logon.',
        'severity': 'medium',
        'mitre_tactics': ['Persistence', 'Privilege Escalation'],
        'mitre_techniques': ['T1547.001'],
        'detection_query': """
            SELECT 
                source_host,
                username,
                COUNT() as registry_modifications,
                MIN(timestamp) as first_seen,
                MAX(timestamp) as last_seen,
                groupArray(DISTINCT JSONExtractString(raw_json, 'EventData', 'ObjectName')) as registry_keys,
                groupArray(DISTINCT process_name) as processes
            FROM events
            WHERE case_id = {case_id:UInt32}
                AND event_id IN ('4657', '13')
                AND (
                    lower(search_blob) LIKE '%\\software\\microsoft\\windows\\currentversion\\run%'
                    OR lower(search_blob) LIKE '%\\software\\microsoft\\windows\\currentversion\\runonce%'
                    OR lower(search_blob) LIKE '%\\software\\wow6432node\\microsoft\\windows\\currentversion\\run%'
                )
            GROUP BY source_host, username
            HAVING registry_modifications >= 1
            ORDER BY registry_modifications DESC
        """,
        'indicators': [
            'Event 4657: Registry value modification',
            'Sysmon Event 13: RegistrySetValue',
            'Keys: Run, RunOnce, RunOnceEx',
            'Both HKLM and HKCU locations'
        ],
        'thresholds': {'min_events': 1}
    },

    # ========== T1547.002: Authentication Package ==========
    {
        'id': 'authentication_package',
        'name': 'Authentication Package DLL',
        'category': 'Persistence',
        'description': 'Registration of malicious authentication package DLL loaded by LSA at boot. Provides password theft and persistence.',
        'severity': 'critical',
        'mitre_tactics': ['Persistence', 'Privilege Escalation'],
        'mitre_techniques': ['T1547.002'],
        'detection_query': """
            SELECT 
                source_host,
                username,
                COUNT() as auth_package_events,
                MIN(timestamp) as first_seen,
                MAX(timestamp) as last_seen,
                groupArray(DISTINCT event_id) as event_ids
            FROM events
            WHERE case_id = {case_id:UInt32}
                AND (
                    (event_id IN ('4657', '13') 
                        AND lower(search_blob) LIKE '%\\control\\lsa\\authentication packages%')
                    OR (event_id = '7' 
                        AND lower(search_blob) LIKE '%lsass.exe%'
                        AND search_blob NOT LIKE '%\\windows\\system32\\%')
                )
            GROUP BY source_host, username
            HAVING auth_package_events >= 1
            ORDER BY auth_package_events DESC
        """,
        'indicators': [
            'Event 4657/13: Modification to Authentication Packages registry',
            'Sysmon Event 7: Suspicious DLL load into lsass.exe',
            'Registry: HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa',
            'DLL loads at every system boot'
        ],
        'thresholds': {'min_events': 1}
    },

    # ========== T1547.004: Winlogon Helper DLL ==========
    {
        'id': 'winlogon_helper_dll',
        'name': 'Winlogon Helper DLL Persistence',
        'category': 'Persistence',
        'description': 'Modification of Winlogon registry keys to load malicious DLLs at logon. Classic persistence technique.',
        'severity': 'high',
        'mitre_tactics': ['Persistence', 'Privilege Escalation'],
        'mitre_techniques': ['T1547.004'],
        'detection_query': """
                SELECT 
                    source_host,
                    username,
                COUNT() as winlogon_modifications,
                MIN(timestamp) as first_seen,
                MAX(timestamp) as last_seen,
                groupArray(DISTINCT JSONExtractString(raw_json, 'EventData', 'ObjectName')) as registry_keys
                FROM events
                WHERE case_id = {case_id:UInt32}
                AND event_id IN ('4657', '13')
                AND (
                    lower(search_blob) LIKE '%\\microsoft\\windows nt\\currentversion\\winlogon\\notify%'
                    OR lower(search_blob) LIKE '%\\microsoft\\windows nt\\currentversion\\winlogon\\userinit%'
                    OR lower(search_blob) LIKE '%\\microsoft\\windows nt\\currentversion\\winlogon\\shell%'
                )
            GROUP BY source_host, username
            HAVING winlogon_modifications >= 1
            ORDER BY winlogon_modifications DESC
        """,
        'indicators': [
            'Event 4657/13: Winlogon registry modifications',
            'Keys: Notify, Userinit, Shell',
            'Executes with SYSTEM privileges',
            'Runs at every user logon'
        ],
        'thresholds': {'min_events': 1}
    },

    # ========== T1543.003: Windows Service ==========
    {
        'id': 'malicious_service_creation',
        'name': 'Malicious Windows Service Creation',
        'category': 'Persistence',
        'description': 'Creation of new Windows services for persistence. Services run with elevated privileges.',
        'severity': 'medium',
        'mitre_tactics': ['Persistence', 'Privilege Escalation'],
        'mitre_techniques': ['T1543.003'],
        'detection_query': """
            SELECT 
                source_host,
                username,
                COUNT() as service_creations,
                MIN(timestamp) as first_seen,
                MAX(timestamp) as last_seen,
                groupArray(DISTINCT JSONExtractString(raw_json, 'EventData', 'ServiceName')) as services_created
            FROM events
            WHERE case_id = {case_id:UInt32}
                AND event_id IN ('7045', '4697')
                AND channel = 'Security'
            GROUP BY source_host, username
            HAVING service_creations >= 1
            ORDER BY service_creations DESC
        """,
        'indicators': [
            'Event 7045: Service installed',
            'Event 4697: Service installed (Security log)',
            'Suspicious service names or paths',
            'Services pointing to temp directories'
        ],
        'thresholds': {'min_events': 1}
    },

    # ========== T1053.005: Scheduled Task ==========
    {
        'id': 'scheduled_task_persistence',
        'name': 'Scheduled Task Persistence',
        'category': 'Persistence',
        'description': 'Creation of scheduled tasks for persistence. Tasks can run with SYSTEM privileges.',
        'severity': 'medium',
        'mitre_tactics': ['Persistence', 'Execution', 'Privilege Escalation'],
        'mitre_techniques': ['T1053.005'],
        'detection_query': """
            SELECT 
                source_host,
                username,
                COUNT() as task_events,
                MIN(timestamp) as first_seen,
                MAX(timestamp) as last_seen,
                groupArray(DISTINCT process_name) as processes
            FROM events
            WHERE case_id = {case_id:UInt32}
                AND (
                    (event_id = '4698' AND channel = 'Security')
                    OR (event_id = '106' AND channel = 'Microsoft-Windows-TaskScheduler/Operational')
                    OR (event_id = '1' AND lower(process_name) = 'schtasks.exe')
                    OR lower(command_line) LIKE '%schtasks%/create%'
                )
            GROUP BY source_host, username
            HAVING task_events >= 1
            ORDER BY task_events DESC
        """,
        'indicators': [
            'Event 4698: Scheduled task created',
            'Event 106: Task registered',
            'Sysmon Event 1: schtasks.exe execution',
            'Tasks with suspicious paths or triggers'
        ],
        'thresholds': {'min_events': 1}
    },
    # ========== T1543.003: Service Persistence ==========
    {
        'id': 'service_persistence',
        'name': 'Service Persistence',
        'category': 'Persistence',
        'description': 'New services created for persistence with suspicious paths.',
        'severity': 'high',
        'mitre_tactics': ['Persistence'],
        'mitre_techniques': ['T1543.003'],
        'detection_query': """
            SELECT 
                source_host,
                count() as service_events,
                min(timestamp) as first_seen,
                max(timestamp) as last_seen,
                groupArray(search_blob) as service_details
            FROM events
            WHERE case_id = {case_id:UInt32}
                AND (event_id = '7045' OR event_id = '4697')
                AND (
                    search_blob LIKE '%\\Temp\\%'
                    OR search_blob LIKE '%\\AppData\\%'
                    OR search_blob LIKE '%\\Users\\%'
                    OR search_blob LIKE '%powershell%'
                    OR search_blob LIKE '%cmd /c%'
                    OR search_blob LIKE '%.ps1%'
                )
            GROUP BY source_host
            HAVING service_events >= 1
        """,
        'indicators': [
            'Event 7045 / 4697 new service created',
            'Services with unusual binary paths',
            'Services running from Temp/user directories'
        ],
        'thresholds': {'min_events': 1}
    },
    # ========== T1574.001: DLL Hijacking ==========
    {
        'id': 'dll_hijacking',
        'name': 'DLL Hijacking / Search Order Hijacking',
        'category': 'Persistence',
        'description': 'DLLs loaded from unusual paths indicating search order hijacking.',
        'severity': 'high',
        'mitre_tactics': ['Persistence', 'Privilege Escalation', 'Defense Evasion'],
        'mitre_techniques': ['T1574.001'],
        'detection_query': """
            SELECT 
                source_host,
                count() as dll_events,
                groupUniqArray(process_name) as processes,
                min(timestamp) as first_seen,
                max(timestamp) as last_seen
            FROM events
            WHERE case_id = {case_id:UInt32}
                AND event_id = '7'
                AND channel LIKE '%Sysmon%'
                AND (
                    search_blob LIKE '%\\Temp\\%'
                    OR search_blob LIKE '%\\AppData\\%'
                    OR search_blob LIKE '%\\Users\\%'
                    OR search_blob LIKE '%\\Downloads\\%'
                )
                AND search_blob NOT LIKE '%Signed%true%'
            GROUP BY source_host
            HAVING dll_events >= 1
        """,
        'indicators': [
            'Sysmon Event 7 DLL loaded from unusual path',
            'Unsigned DLLs in paths with signed binaries',
            'Writable directories used for DLL placement'
        ],
        'thresholds': {'min_events': 1}
    },
    # ========== T1546.003: WMI Event Subscription ==========
    {
        'id': 'wmi_persistence',
        'name': 'WMI Event Subscription Persistence',
        'category': 'Persistence',
        'description': 'WMI permanent event subscriptions used for persistence.',
        'severity': 'critical',
        'mitre_tactics': ['Persistence'],
        'mitre_techniques': ['T1546.003'],
        'detection_query': """
            SELECT 
                source_host,
                count() as wmi_persistence_events,
                countIf(event_id = '19') as filter_created,
                countIf(event_id = '20') as consumer_created,
                countIf(event_id = '21') as binding_created,
                min(timestamp) as first_seen,
                max(timestamp) as last_seen
            FROM events
            WHERE case_id = {case_id:UInt32}
                AND (
                    (channel LIKE '%WMI-Activity%' AND event_id IN ('5857', '5858', '5859', '5860', '5861'))
                    OR (channel LIKE '%Sysmon%' AND event_id IN ('19', '20', '21'))
                )
            GROUP BY source_host
            HAVING wmi_persistence_events >= 1
        """,
        'indicators': [
            'WMI-Activity events 5857-5861',
            'Sysmon Event 19/20/21 WMI subscriptions',
            'CommandLineEventConsumer or ActiveScriptEventConsumer'
        ],
        'thresholds': {'min_events': 1}
    },
]

# ============================================================================
# PRIVILEGE ESCALATION PATTERNS (MITRE ATT&CK TA0004)
# ============================================================================

PRIV_ESC_PATTERNS = [
    # ========== T1134: Token Manipulation (TEMPORAL) ==========
    # NOTE: 4672 SeDebugPrivilege fires for EVERY admin logon - not useful alone
    # Real token manipulation requires LSASS access or suspicious process patterns
    {
        'id': 'token_manipulation',
        'name': 'Token Manipulation',
        'category': 'Privilege Escalation',
        'description': 'Token impersonation detected via LSASS process access with token rights. Normal 4672 SeDebugPrivilege events are excluded - only suspicious LSASS access patterns are reported.',
        'severity': 'critical',
        'mitre_tactics': ['Privilege Escalation', 'Defense Evasion'],
        'mitre_techniques': ['T1134'],
        'temporal': True,
        'anchor': {
            'description': 'Sysmon Event 10 (Process Access) to LSASS with token rights',
            'event_ids': ['10'],
            'conditions': "channel LIKE '%Sysmon%' AND lower(search_blob) LIKE '%lsass%'"
        },
        'supporting': [
            {
                'name': 'debug_privilege',
                'required': False,
                'window_seconds': 60,
                'event_ids': ['4672'],
                'conditions': "search_blob LIKE '%SeDebugPrivilege%'"
            }
        ],
        'attack_window_minutes': 15,
        'detection_query': """
            WITH 
            -- Anchor: Sysmon Event 10 accessing LSASS (the real indicator)
            lsass_access AS (
                SELECT 
                    source_host,
                    timestamp as anchor_time,
                    username,
                    process_name as source_process,
                    command_line,
                    -- Extract target process from search_blob
                    search_blob
                FROM events
                WHERE case_id = {case_id:UInt32}
                    AND event_id = '10'
                    AND channel LIKE '%Sysmon%'
                    AND lower(search_blob) LIKE '%lsass.exe%'
                    -- Exclude known legitimate processes
                    AND lower(process_name) NOT IN (
                        'csrss.exe', 'services.exe', 'svchost.exe', 'lsass.exe',
                        'smss.exe', 'wininit.exe', 'msiexec.exe', 'wmiprvse.exe'
                    )
            ),
            -- Supporting: SeDebugPrivilege within 1 min (confirms elevated context)
            debug_privs AS (
                SELECT source_host, timestamp, username
                FROM events
                WHERE case_id = {case_id:UInt32}
                    AND event_id = '4672'
                    AND search_blob LIKE '%SeDebugPrivilege%'
            ),
            -- Correlate
            correlated AS (
                SELECT 
                    l.source_host,
                    l.anchor_time,
                    l.username,
                    l.source_process,
                    l.command_line,
                    (SELECT count() FROM debug_privs d 
                     WHERE d.source_host = l.source_host 
                     AND d.timestamp BETWEEN l.anchor_time - INTERVAL 1 MINUTE AND l.anchor_time + INTERVAL 1 MINUTE) as nearby_debug_priv
                FROM lsass_access l
            ),
            -- Group into attack windows
            attack_windows AS (
                SELECT 
                    source_host,
                    username,
                    min(anchor_time) as first_seen,
                    max(anchor_time) as last_seen,
                    count() as lsass_access_count,
                    any(source_process) as source_process,
                    sum(nearby_debug_priv) as debug_priv_events,
                    groupUniqArray(command_line) as command_lines
                FROM correlated
                GROUP BY 
                    source_host, 
                    username,
                    toStartOfInterval(anchor_time, INTERVAL 15 MINUTE)
            )
            SELECT 
                source_host,
                username,
                first_seen,
                last_seen,
                lsass_access_count as token_events,
                source_process,
                debug_priv_events,
                command_lines
            FROM attack_windows
            WHERE lsass_access_count >= 1
            ORDER BY lsass_access_count DESC, first_seen ASC
        """,
        'indicators': [
            'Sysmon Event 10: Non-system process accessing LSASS (anchor)',
            'Event 4672 SeDebugPrivilege within ±1 min (supporting)',
            'Excludes legitimate system processes (csrss, services, svchost)',
            'Grouped into 15-minute attack windows'
        ],
        'thresholds': {'min_lsass_access': 1, 'window_minutes': 15}
    },
    # ========== T1134.001: Named Pipe Impersonation ==========
    {
        'id': 'named_pipe_impersonation',
        'name': 'Named Pipe Impersonation',
        'category': 'Privilege Escalation',
        'description': 'Named pipe creation and connection for privilege escalation (Potato attacks).',
        'severity': 'high',
        'mitre_tactics': ['Privilege Escalation'],
        'mitre_techniques': ['T1134.001'],
        'detection_query': """
            SELECT 
                source_host,
                count() as pipe_events,
                countIf(event_id = '17') as pipes_created,
                countIf(event_id = '18') as pipes_connected,
                min(timestamp) as first_seen,
                max(timestamp) as last_seen,
                groupArray(search_blob) as pipe_names
            FROM events
            WHERE case_id = {case_id:UInt32}
                AND channel LIKE '%Sysmon%'
                AND event_id IN ('17', '18')
                AND (
                    search_blob NOT LIKE '%spoolss%'
                    AND search_blob NOT LIKE '%wkssvc%'
                    AND search_blob NOT LIKE '%srvsvc%'
                )
            GROUP BY source_host
            HAVING pipe_events >= 2
        """,
        'indicators': [
            'Sysmon Event 17/18 pipe created/connected',
            'Unusual pipe names from unexpected processes',
            'Event 4624 with network credentials from local source'
        ],
        'thresholds': {'min_events': 2}
    },
    # ========== T1548.002: UAC Bypass ==========
    {
        'id': 'uac_bypass',
        'name': 'UAC Bypass',
        'category': 'Privilege Escalation',
        'description': 'User Account Control bypass techniques detected.',
        'severity': 'high',
        'mitre_tactics': ['Privilege Escalation', 'Defense Evasion'],
        'mitre_techniques': ['T1548.002'],
        'detection_query': """
            SELECT 
                source_host,
                count() as uac_bypass_events,
                min(timestamp) as first_seen,
                max(timestamp) as last_seen,
                groupArray(process_name) as processes
            FROM events
            WHERE case_id = {case_id:UInt32}
                AND (
                    (lower(process_name) IN ('fodhelper.exe', 'eventvwr.exe', 'sdclt.exe', 'computerdefaults.exe')
                        AND parent_process NOT LIKE '%explorer.exe%')
                    OR (event_id = '13' AND channel LIKE '%Sysmon%' 
                        AND (search_blob LIKE '%ms-settings%' OR search_blob LIKE '%mscfile%'))
                    OR (search_blob LIKE '%bypass%' AND search_blob LIKE '%uac%')
                )
            GROUP BY source_host
            HAVING uac_bypass_events >= 1
        """,
        'indicators': [
            'Auto-elevated binaries (fodhelper, eventvwr) with unusual children',
            'Registry modification to ms-settings or mscfile',
            'High-integrity process without UAC prompt'
        ],
        'thresholds': {'min_events': 1}
    },
]

# ============================================================================
# DEFENSE EVASION PATTERNS (MITRE ATT&CK TA0005)
# ============================================================================

DEFENSE_EVASION_PATTERNS = [
    # ========== T1562.002: Disable Windows Event Logging ==========
    {
        'id': 'event_log_clearing',
        'name': 'Event Log Clearing/Disabling',
        'category': 'Defense Evasion',
        'description': 'Clearing or disabling Windows event logs to hide tracks. Critical incident indicator.',
        'severity': 'critical',
        'mitre_tactics': ['Defense Evasion'],
        'mitre_techniques': ['T1562.002'],
        'detection_query': """
            SELECT 
                source_host,
                username,
                COUNT() as log_events,
                MIN(timestamp) as first_seen,
                MAX(timestamp) as last_seen,
                groupArray(DISTINCT event_id) as event_ids
            FROM events
            WHERE case_id = {case_id:UInt32}
                AND (
                    event_id IN ('1102', '1100', '104')
                    OR (event_id = '1' AND lower(command_line) LIKE '%wevtutil%cl%')
                    OR (event_id = '7040' AND lower(search_blob) LIKE '%eventlog%disabled%')
                )
            GROUP BY source_host, username
            HAVING log_events >= 1
            ORDER BY log_events DESC
        """,
        'indicators': [
            'Event 1102: Audit log cleared',
            'Event 1100: Event Log service shutdown',
            'Event 104: System log cleared',
            'wevtutil cl commands',
            'Event 7040: EventLog service disabled'
        ],
        'thresholds': {'min_events': 1}
    },

    # ========== T1562.001: Disable or Modify Tools ==========
    {
        'id': 'security_tool_tampering',
        'name': 'Security Tool Tampering',
        'category': 'Defense Evasion',
        'description': 'Disabling or modifying antivirus, EDR, or other security tools.',
        'severity': 'high',
        'mitre_tactics': ['Defense Evasion'],
        'mitre_techniques': ['T1562.001'],
        'detection_query': """
            SELECT 
                source_host,
                username,
                COUNT() as tampering_events,
                MIN(timestamp) as first_seen,
                MAX(timestamp) as last_seen,
                groupArray(DISTINCT event_id) as event_ids,
                groupArray(DISTINCT process_name) as processes
            FROM events
            WHERE case_id = {case_id:UInt32}
                AND (
                    (event_id IN ('4657', '13') 
                        AND (lower(search_blob) LIKE '%\\windows defender%disablean%'
                            OR lower(search_blob) LIKE '%\\policies\\microsoft\\windows defender%'))
                    OR (event_id = '7040' 
                        AND (lower(search_blob) LIKE '%windefend%'
                            OR lower(search_blob) LIKE '%sense%'
                            OR lower(search_blob) LIKE '%mpssvc%'))
                    OR (event_id IN ('1', '4688')
                        AND (lower(command_line) LIKE '%set-mppreference%'
                            OR lower(command_line) LIKE '%stop-service%windefend%'
                            OR lower(command_line) LIKE '%uninstall-windowsfeature%'))
                )
            GROUP BY source_host, username
            HAVING tampering_events >= 1
            ORDER BY tampering_events DESC
        """,
        'indicators': [
            'Event 4657/13: Windows Defender registry modifications',
            'Event 7040: Security services stopped',
            'PowerShell: Set-MpPreference, Stop-Service',
            'Disabling real-time protection, tamper protection'
        ],
        'thresholds': {'min_events': 1}
    },

    # ========== T1070.001: Clear Windows Event Logs (via wevtutil) ==========
    {
        'id': 'wevtutil_log_clearing',
        'name': 'Event Log Clearing via Wevtutil',
        'category': 'Defense Evasion',
        'description': 'Use of wevtutil.exe to clear event logs. Common post-exploitation activity.',
        'severity': 'critical',
        'mitre_tactics': ['Defense Evasion'],
        'mitre_techniques': ['T1070.001'],
        'detection_query': """
            SELECT 
                source_host,
                username,
                COUNT() as clear_events,
                MIN(timestamp) as first_seen,
                MAX(timestamp) as last_seen,
                groupArray(command_line) as commands_executed
            FROM events
            WHERE case_id = {case_id:UInt32}
                AND event_id IN ('1', '4688')
                AND (
                    lower(command_line) LIKE '%wevtutil%cl%'
                    OR lower(command_line) LIKE '%wevtutil%clear-log%'
                    OR lower(command_line) LIKE '%clear-eventlog%'
                )
            GROUP BY source_host, username
            HAVING clear_events >= 1
            ORDER BY clear_events DESC
        """,
        'indicators': [
            'Sysmon Event 1: wevtutil.exe execution',
            'Event 4688: wevtutil process creation',
            'PowerShell: Clear-EventLog cmdlet',
            'Common post-exploitation cleanup'
        ],
        'thresholds': {'min_events': 1}
    },

    # ========== T1070.004: File Deletion ==========
    {
        'id': 'evidence_deletion',
        'name': 'Evidence Deletion',
        'category': 'Defense Evasion',
        'description': 'Deletion of files to remove evidence. Includes log files, tools, and forensic artifacts.',
        'severity': 'medium',
        'mitre_tactics': ['Defense Evasion'],
        'mitre_techniques': ['T1070.004'],
        'detection_query': """
            SELECT 
                source_host,
                username,
                COUNT() as deletion_events,
                MIN(timestamp) as first_seen,
                MAX(timestamp) as last_seen,
                groupArray(DISTINCT process_name) as processes
            FROM events
            WHERE case_id = {case_id:UInt32}
                AND (
                    event_id = '4660'
                    OR (event_id IN ('1', '4688') 
                        AND (lower(command_line) LIKE '%del %/f%'
                            OR lower(command_line) LIKE '%remove-item%force%'
                            OR lower(command_line) LIKE '%cipher%/w:%'))
                )
            GROUP BY source_host, username
            HAVING deletion_events >= 5
            ORDER BY deletion_events DESC
        """,
        'indicators': [
            'Event 4660: Object deleted',
            'Del commands with /f flag',
            'PowerShell Remove-Item -Force',
            'Cipher /w for secure deletion'
        ],
        'thresholds': {'min_events': 5}
    },

    # ========== T1562.004: Disable or Modify System Firewall ==========
    {
        'id': 'firewall_tampering',
        'name': 'Firewall Rule Modification',
        'category': 'Defense Evasion',
        'description': 'Modification or disabling of Windows Firewall rules to allow malicious traffic.',
        'severity': 'high',
        'mitre_tactics': ['Defense Evasion'],
        'mitre_techniques': ['T1562.004'],
        'detection_query': """
            SELECT 
                source_host,
                username,
                COUNT() as firewall_events,
                MIN(timestamp) as first_seen,
                MAX(timestamp) as last_seen,
                groupArray(DISTINCT event_id) as event_ids
            FROM events
            WHERE case_id = {case_id:UInt32}
                AND (
                    event_id IN ('4946', '4947', '4948', '4950', '4954', '4956')
                    OR (event_id IN ('1', '4688') 
                        AND (lower(command_line) LIKE '%netsh%firewall%'
                            OR lower(command_line) LIKE '%netsh%advfirewall%'
                            OR lower(command_line) LIKE '%set-netfirewallprofile%'))
                )
            GROUP BY source_host, username
            HAVING firewall_events >= 1
            ORDER BY firewall_events DESC
        """,
        'indicators': [
            'Event 4946-4956: Firewall rule changes',
            'Netsh advfirewall commands',
            'PowerShell: Set-NetFirewallProfile',
            'Disabling firewall or adding allow rules'
        ],
        'thresholds': {'min_events': 1}
    },
    # ========== T1070.006: Timestomping ==========
    {
        'id': 'timestomping',
        'name': 'Timestomping',
        'category': 'Defense Evasion',
        'description': 'File timestamps modified to evade detection.',
        'severity': 'high',
        'mitre_tactics': ['Defense Evasion'],
        'mitre_techniques': ['T1070.006'],
        'detection_query': """
            SELECT 
                source_host,
                count() as stomp_events,
                min(timestamp) as first_seen,
                max(timestamp) as last_seen,
                groupArray(search_blob) as files_modified
            FROM events
            WHERE case_id = {case_id:UInt32}
                AND event_id = '2'
                AND channel LIKE '%Sysmon%'
            GROUP BY source_host
            HAVING stomp_events >= 1
        """,
        'indicators': [
            'Sysmon Event 2 file creation time changed',
            '$SI and $FN timestamp discrepancies',
            'Creation times newer than modification times'
        ],
        'thresholds': {'min_events': 1}
    },
    # ========== T1055: Process Injection ==========
    {
        'id': 'process_injection',
        'name': 'Process Injection',
        'category': 'Defense Evasion',
        'description': 'Code injection into remote processes detected.',
        'severity': 'critical',
        'mitre_tactics': ['Defense Evasion', 'Privilege Escalation'],
        'mitre_techniques': ['T1055'],
        'detection_query': """
            SELECT 
                source_host,
                count() as injection_events,
                countIf(event_id = '8') as remote_threads,
                countIf(event_id = '10') as process_access,
                min(timestamp) as first_seen,
                max(timestamp) as last_seen
            FROM events
            WHERE case_id = {case_id:UInt32}
                AND channel LIKE '%Sysmon%'
                AND (
                    event_id = '8'
                    OR (event_id = '10' AND search_blob LIKE '%0x1F0FFF%')
                )
            GROUP BY source_host
            HAVING injection_events >= 1
        """,
        'indicators': [
            'Sysmon Event 8 CreateRemoteThread',
            'Event 10 suspicious cross-process access',
            'Unusual parent-child process relationships',
            'Legitimate processes making unexpected network connections'
        ],
        'thresholds': {'min_events': 1}
    },
    # ========== T1562.001: AMSI Bypass ==========
    {
        'id': 'amsi_bypass',
        'name': 'AMSI Bypass',
        'category': 'Defense Evasion',
        'description': 'Antimalware Scan Interface bypass attempts detected.',
        'severity': 'high',
        'mitre_tactics': ['Defense Evasion'],
        'mitre_techniques': ['T1562.001'],
        'detection_query': """
            SELECT 
                source_host,
                count() as amsi_events,
                min(timestamp) as first_seen,
                max(timestamp) as last_seen
            FROM events
            WHERE case_id = {case_id:UInt32}
                AND event_id IN ('4103', '4104')
                AND (
                    lower(search_blob) LIKE '%amsi%'
                    OR lower(search_blob) LIKE '%amsiinitfailed%'
                    OR lower(search_blob) LIKE '%amsicontext%'
                    OR lower(search_blob) LIKE '%amsiscanbuffer%'
                )
            GROUP BY source_host
            HAVING amsi_events >= 1
        """,
        'indicators': [
            'PowerShell Event 4104 with AMSI strings',
            'Obfuscated content in script blocks',
            'amsi.dll load failures or modifications'
        ],
        'thresholds': {'min_events': 1}
    },
]

# ============================================================================
# DISCOVERY PATTERNS (MITRE ATT&CK TA0007)
# ============================================================================

DISCOVERY_PATTERNS = [
    # ========== T1069.001: Local Groups Discovery ==========
    {
        'id': 'local_group_discovery',
        'name': 'Local Group Discovery',
        'category': 'Discovery',
        'description': 'Enumeration of local groups to identify privileged accounts. Common reconnaissance activity.',
        'severity': 'low',
        'mitre_tactics': ['Discovery'],
        'mitre_techniques': ['T1069.001'],
        'detection_query': """
            SELECT 
                source_host,
                username,
                COUNT() as discovery_events,
                MIN(timestamp) as first_seen,
                MAX(timestamp) as last_seen,
                groupArray(DISTINCT command_line) as commands
            FROM events
            WHERE case_id = {case_id:UInt32}
                AND event_id IN ('1', '4688')
                AND (
                    lower(command_line) LIKE '%net localgroup%'
                    OR lower(command_line) LIKE '%get-localgroupmember%'
                    OR lower(command_line) LIKE '%wmic%group%'
                )
            GROUP BY source_host, username
            HAVING discovery_events >= 3
            ORDER BY discovery_events DESC
        """,
        'indicators': [
            'Net localgroup commands',
            'PowerShell: Get-LocalGroupMember',
            'WMIC group queries',
            'Targeting administrators group'
        ],
        'thresholds': {'min_events': 3}
    },

    # ========== T1069.002: Domain Groups Discovery ==========
    {
        'id': 'domain_group_discovery',
        'name': 'Domain Group Discovery',
        'category': 'Discovery',
        'description': 'Enumeration of domain groups to map AD structure and identify high-value targets.',
        'severity': 'low',
        'mitre_tactics': ['Discovery'],
        'mitre_techniques': ['T1069.002'],
        'detection_query': """
            SELECT 
                source_host,
                username,
                COUNT() as discovery_events,
                MIN(timestamp) as first_seen,
                MAX(timestamp) as last_seen,
                groupArray(DISTINCT command_line) as commands
            FROM events
            WHERE case_id = {case_id:UInt32}
                AND (
                    (event_id IN ('1', '4688') 
                        AND (lower(command_line) LIKE '%net group%/domain%'
                            OR lower(command_line) LIKE '%get-adgroup%'
                            OR lower(command_line) LIKE '%dsquery group%'))
                    OR (event_id = '4661' 
                        AND lower(search_blob) LIKE '%group%')
                )
            GROUP BY source_host, username
            HAVING discovery_events >= 3
            ORDER BY discovery_events DESC
        """,
        'indicators': [
            'Net group /domain commands',
            'PowerShell: Get-ADGroup',
            'Dsquery group queries',
            'Event 4661: AD object access'
        ],
        'thresholds': {'min_events': 3}
    },

    # ========== T1087.002: Domain Account Discovery ==========
    {
        'id': 'domain_account_discovery',
        'name': 'Domain Account Discovery',
        'category': 'Discovery',
        'description': 'Enumeration of domain user accounts via LDAP queries or net commands.',
        'severity': 'low',
        'mitre_tactics': ['Discovery'],
        'mitre_techniques': ['T1087.002'],
        'detection_query': """
            SELECT 
                source_host,
                username,
                COUNT() as discovery_events,
                MIN(timestamp) as first_seen,
                MAX(timestamp) as last_seen,
                groupArray(DISTINCT command_line) as commands
            FROM events
            WHERE case_id = {case_id:UInt32}
                AND event_id IN ('1', '4688')
                AND (
                    lower(command_line) LIKE '%net user%/domain%'
                    OR lower(command_line) LIKE '%get-aduser%'
                    OR lower(command_line) LIKE '%dsquery user%'
                    OR lower(command_line) LIKE '%ldapsearch%'
                )
            GROUP BY source_host, username
            HAVING discovery_events >= 3
            ORDER BY discovery_events DESC
        """,
        'indicators': [
            'Net user /domain commands',
            'PowerShell: Get-ADUser',
            'Dsquery user queries',
            'LDAP enumeration'
        ],
        'thresholds': {'min_events': 3}
    },

    # ========== T1082: System Information Discovery ==========
    {
        'id': 'system_info_discovery',
        'name': 'System Information Discovery',
        'category': 'Discovery',
        'description': 'Collection of system information (OS version, hostname, domain). Standard reconnaissance.',
        'severity': 'low',
        'mitre_tactics': ['Discovery'],
        'mitre_techniques': ['T1082'],
        'detection_query': """
            SELECT 
                source_host,
                username,
                COUNT() as discovery_commands,
                MIN(timestamp) as first_seen,
                MAX(timestamp) as last_seen,
                COUNT(DISTINCT process_name) as unique_tools
            FROM events
            WHERE case_id = {case_id:UInt32}
                AND event_id IN ('1', '4688')
                AND (
                    lower(process_name) IN ('systeminfo.exe', 'hostname.exe', 'ver.exe')
                    OR lower(command_line) LIKE '%get-computerinfo%'
                    OR lower(command_line) LIKE '%wmic%os%'
                )
            GROUP BY source_host, username
            HAVING discovery_commands >= 3
            ORDER BY unique_tools DESC
        """,
        'indicators': [
            'Systeminfo.exe execution',
            'Hostname.exe, ver.exe',
            'PowerShell: Get-ComputerInfo',
            'WMIC os get queries'
        ],
        'thresholds': {'min_commands': 3}
    },

    # ========== T1018: Remote System Discovery ==========
    {
        'id': 'network_scanning',
        'name': 'Network/Remote System Discovery',
        'category': 'Discovery',
        'description': 'Scanning for other systems on the network. Precursor to lateral movement.',
        'severity': 'medium',
        'mitre_tactics': ['Discovery'],
        'mitre_techniques': ['T1018'],
        'detection_query': """
            SELECT 
                source_host,
                username,
                COUNT() as scan_events,
                MIN(timestamp) as first_seen,
                MAX(timestamp) as last_seen,
                groupArray(DISTINCT process_name) as tools_used
            FROM events
            WHERE case_id = {case_id:UInt32}
                AND event_id IN ('1', '4688')
                AND (
                    lower(command_line) LIKE '%net view%'
                    OR lower(command_line) LIKE '%ping -%'
                    OR lower(command_line) LIKE '%arp -a%'
                    OR lower(process_name) IN ('nslookup.exe', 'nmap.exe')
                )
            GROUP BY source_host, username
            HAVING scan_events >= 5
            ORDER BY scan_events DESC
        """,
        'indicators': [
            'Net view commands',
            'Ping sweeps',
            'ARP -a queries',
            'Nslookup, nmap usage'
        ],
        'thresholds': {'min_events': 5}
    },
    # ========== T1087.002/T1069.002: Active Directory Enumeration ==========
    {
        'id': 'ad_enumeration',
        'name': 'Active Directory Enumeration',
        'category': 'Discovery',
        'description': 'Active Directory reconnaissance and enumeration.',
        'severity': 'medium',
        'mitre_tactics': ['Discovery'],
        'mitre_techniques': ['T1087.002', 'T1069.002'],
        'detection_query': """
            SELECT 
                source_host,
                count() as ad_events,
                countIf(event_id = '4662') as ds_access,
                countIf(event_id = '4661') as sam_access,
                min(timestamp) as first_seen,
                max(timestamp) as last_seen
            FROM events
            WHERE case_id = {case_id:UInt32}
                AND (
                    (event_id IN ('4662', '4661', '4663'))
                    OR (lower(command_line) LIKE '%dsquery%')
                    OR (lower(command_line) LIKE '%ldapsearch%')
                    OR (lower(command_line) LIKE '%adfind%')
                    OR (lower(command_line) LIKE '%get-ad%')
                )
            GROUP BY source_host
            HAVING ad_events >= 5
        """,
        'indicators': [
            'Event 4662 directory service access',
            'LDAP queries for sensitive objects',
            'Event 4661 SAM handle requests',
            'High-volume directory queries'
        ],
        'thresholds': {'min_events': 5}
    },
    # ========== T1087.002/T1069.002: BloodHound Collection ==========
    {
        'id': 'bloodhound_collection',
        'name': 'BloodHound / SharpHound Collection',
        'category': 'Discovery',
        'description': 'BloodHound or SharpHound AD enumeration tool activity.',
        'severity': 'high',
        'mitre_tactics': ['Discovery'],
        'mitre_techniques': ['T1087.002', 'T1069.002'],
        'detection_query': """
            SELECT 
                source_host,
                count() as bloodhound_events,
                min(timestamp) as first_seen,
                max(timestamp) as last_seen
            FROM events
            WHERE case_id = {case_id:UInt32}
                AND (
                    lower(search_blob) LIKE '%sharphound%'
                    OR lower(search_blob) LIKE '%bloodhound%'
                    OR lower(command_line) LIKE '%invoke-bloodhound%'
                    OR lower(command_line) LIKE '%-collectionmethod%'
                    OR (lower(command_line) LIKE '%ldap%' AND lower(command_line) LIKE '%session%')
                )
            GROUP BY source_host
            HAVING bloodhound_events >= 1
        """,
        'indicators': [
            'Event 4662/4663 AD object enumeration',
            'SMB connections to many hosts',
            'LDAP query patterns matching SharpHound',
            'sharphound.exe or bloodhound collectors'
        ],
        'thresholds': {'min_events': 1}
    },
]

# ============================================================================
# EXFILTRATION PATTERNS (MITRE ATT&CK TA0010)
# ============================================================================

EXFILTRATION_PATTERNS = [
    # ========== T1567.002: Exfiltration to Cloud Storage ==========
    {
        'id': 'cloud_exfiltration',
        'name': 'Exfiltration to Cloud Storage',
        'category': 'Exfiltration',
        'description': 'Data transfer to cloud storage services (Dropbox, OneDrive, Google Drive, Mega, etc.).',
        'severity': 'high',
        'mitre_tactics': ['Exfiltration'],
        'mitre_techniques': ['T1567.002'],
        'detection_query': """
            SELECT 
                source_host,
                COUNT() as cloud_events,
                MIN(timestamp) as first_seen,
                MAX(timestamp) as last_seen,
                groupArray(DISTINCT process_name) as processes
            FROM events
            WHERE case_id = {case_id:UInt32}
                AND (
                    (event_id = '3' AND (
                        lower(search_blob) LIKE '%dropbox.com%'
                        OR lower(search_blob) LIKE '%onedrive.live.com%'
                        OR lower(search_blob) LIKE '%drive.google.com%'
                        OR lower(search_blob) LIKE '%mega.nz%'
                        OR lower(search_blob) LIKE '%box.com%'
                        OR lower(search_blob) LIKE '%wetransfer.com%'
                    ) AND process_name NOT IN ('chrome.exe', 'firefox.exe', 'msedge.exe', 'iexplore.exe'))
                    OR (lower(command_line) LIKE '%rclone%')
                    OR (lower(command_line) LIKE '%megacmd%')
                )
            GROUP BY source_host
            HAVING cloud_events >= 1
        """,
        'indicators': [
            'Sysmon Event 3: Connections to cloud storage',
            'Non-browser processes accessing cloud services',
            'Rclone, Mega tools detected',
            'Large uploads via proxy logs'
        ],
        'thresholds': {'min_events': 1}
    },
    # ========== T1074.001: Data Staging ==========
    {
        'id': 'data_staging',
        'name': 'Data Staging',
        'category': 'Exfiltration',
        'description': 'Data collection and staging for exfiltration.',
        'severity': 'high',
        'mitre_tactics': ['Collection', 'Exfiltration'],
        'mitre_techniques': ['T1074.001'],
        'detection_query': """
            SELECT 
                source_host,
                count() as staging_events,
                min(timestamp) as first_seen,
                max(timestamp) as last_seen
            FROM events
            WHERE case_id = {case_id:UInt32}
                AND (
                    (event_id = '11' AND channel LIKE '%Sysmon%' AND (
                        search_blob LIKE '%.zip%'
                        OR search_blob LIKE '%.7z%'
                        OR search_blob LIKE '%.rar%'
                        OR search_blob LIKE '%.tar%'
                    ) AND (
                        search_blob LIKE '%\\Temp\\%'
                        OR search_blob LIKE '%\\AppData\\%'
                        OR search_blob LIKE '%\\Public\\%'
                    ))
                    OR (lower(command_line) LIKE '%compress-archive%')
                    OR (lower(command_line) LIKE '%7z.exe%' AND lower(command_line) LIKE '% a %')
                    OR (lower(command_line) LIKE '%rar.exe%' AND lower(command_line) LIKE '% a %')
                )
            GROUP BY source_host
            HAVING staging_events >= 1
        """,
        'indicators': [
            'Sysmon Event 11 archive files in temp dirs',
            'Large .zip/.7z/.rar files created',
            'File copy to network shares',
            'Event 5145 sensitive share access'
        ],
        'thresholds': {'min_events': 1}
    },
    # ========== T1048.003: DNS Exfiltration ==========
    {
        'id': 'dns_exfiltration',
        'name': 'DNS Exfiltration',
        'category': 'Exfiltration',
        'description': 'Data exfiltration via DNS queries with encoded data.',
        'severity': 'high',
        'mitre_tactics': ['Exfiltration'],
        'mitre_techniques': ['T1048.003'],
        'detection_query': """
            SELECT 
                source_host,
                count() as dns_events,
                min(timestamp) as first_seen,
                max(timestamp) as last_seen
            FROM events
            WHERE case_id = {case_id:UInt32}
                AND event_id = '22'
                AND channel LIKE '%Sysmon%'
                AND (
                    length(extractAll(search_blob, '([a-zA-Z0-9]{32,})')[1]) >= 32
                    OR search_blob LIKE '%TXT%'
                )
            GROUP BY source_host
            HAVING dns_events >= 10
        """,
        'indicators': [
            'Long DNS subdomain queries',
            'High volume to single domain',
            'TXT record queries with encoded data',
            'Unusual DNS from non-browser processes'
        ],
        'thresholds': {'min_events': 10}
    },
]

# ============================================================================
# COMBINED PATTERN LIST
# ============================================================================

ALL_PATTERN_RULES: List[Dict[str, Any]] = (
    CREDENTIAL_ATTACK_PATTERNS +
    LATERAL_MOVEMENT_PATTERNS +
    PERSISTENCE_PATTERNS +
    PRIV_ESC_PATTERNS +
    DEFENSE_EVASION_PATTERNS +
    DISCOVERY_PATTERNS +
    EXFILTRATION_PATTERNS
)

# Category grouping for UI
PATTERN_CATEGORIES = {
    'Credential Access': CREDENTIAL_ATTACK_PATTERNS,
    'Lateral Movement': LATERAL_MOVEMENT_PATTERNS,
    'Persistence': PERSISTENCE_PATTERNS,
    'Privilege Escalation': PRIV_ESC_PATTERNS,
    'Defense Evasion': DEFENSE_EVASION_PATTERNS,
    'Discovery': DISCOVERY_PATTERNS,
    'Exfiltration': EXFILTRATION_PATTERNS,
}

# Quick stats
PATTERN_STATS = {
    'total_patterns': len(ALL_PATTERN_RULES),
    'credential_access': len(CREDENTIAL_ATTACK_PATTERNS),
    'lateral_movement': len(LATERAL_MOVEMENT_PATTERNS),
    'persistence': len(PERSISTENCE_PATTERNS),
    'priv_esc': len(PRIV_ESC_PATTERNS),
    'defense_evasion': len(DEFENSE_EVASION_PATTERNS),
    'discovery': len(DISCOVERY_PATTERNS),
    'exfiltration': len(EXFILTRATION_PATTERNS),
    'critical_severity': len([p for p in ALL_PATTERN_RULES if p['severity'] == 'critical']),
    'high_severity': len([p for p in ALL_PATTERN_RULES if p['severity'] == 'high']),
    'medium_severity': len([p for p in ALL_PATTERN_RULES if p['severity'] == 'medium']),
    'low_severity': len([p for p in ALL_PATTERN_RULES if p['severity'] == 'low']),
}
