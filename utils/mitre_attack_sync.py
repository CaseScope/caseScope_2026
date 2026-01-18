"""MITRE ATT&CK Integration for CaseScope

This module automatically syncs MITRE ATT&CK patterns and converts them
to CaseScope detection rules with ClickHouse queries.

Author: CaseScope Enhanced
Date: January 18, 2026
"""

import requests
import json
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime

logger = logging.getLogger(__name__)


class MitreAttackSync:
    """Sync MITRE ATT&CK patterns to CaseScope format"""
    
    # MITRE ATT&CK STIX 2.0 Data Source
    ATTACK_STIX_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
    
    # Event ID to Data Source mapping
    EVENT_ID_MAPPING = {
        # Logon/Logoff Events
        '4624': 'Logon Session: Logon Session Creation',
        '4625': 'Logon Session: Logon Session Creation',
        '4634': 'Logon Session: Logon Session Metadata',
        '4647': 'Logon Session: Logon Session Metadata',
        '4648': 'User Account: User Account Authentication',
        
        # Kerberos Events
        '4768': 'Logon Session: Logon Session Creation',
        '4769': 'Active Directory: Active Directory Credential Request',
        '4770': 'Active Directory: Active Directory Credential Request',
        '4771': 'User Account: User Account Authentication',
        '4776': 'User Account: User Account Authentication',
        
        # Account Management
        '4720': 'User Account: User Account Creation',
        '4722': 'User Account: User Account Modification',
        '4723': 'User Account: User Account Modification',
        '4724': 'User Account: User Account Modification',
        '4725': 'User Account: User Account Modification',
        '4726': 'User Account: User Account Deletion',
        '4738': 'User Account: User Account Modification',
        '4740': 'User Account: User Account Modification',
        
        # Object Access
        '4656': 'File: File Access',
        '4658': 'File: File Access',
        '4660': 'File: File Deletion',
        '4663': 'File: File Access',
        '4662': 'Active Directory: Active Directory Object Access',
        
        # Registry Events
        '4657': 'Windows Registry: Windows Registry Key Modification',
        
        # Process Events (Sysmon)
        '1': 'Process: Process Creation',
        '3': 'Network Traffic: Network Connection Creation',
        '7': 'Module: Module Load',
        '8': 'Process: Process Access',
        '10': 'Process: OS API Execution',
        '11': 'File: File Creation',
        '12': 'Windows Registry: Windows Registry Key Creation',
        '13': 'Windows Registry: Windows Registry Key Modification',
        '15': 'File: File Stream Creation',
        
        # Service Events
        '7045': 'Service: Service Creation',
        '4697': 'Service: Service Creation',
        
        # Security Events
        '1102': 'Application Log: Application Log Content',
        '4688': 'Process: Process Creation',
        '4689': 'Process: Process Termination',
    }
    
    def __init__(self):
        self.attack_data = None
        self.techniques = []
        
    def fetch_attack_data(self) -> bool:
        """Download latest ATT&CK STIX data"""
        try:
            logger.info(f"Fetching MITRE ATT&CK data from {self.ATTACK_STIX_URL}")
            response = requests.get(self.ATTACK_STIX_URL, timeout=30)
            response.raise_for_status()
            
            self.attack_data = response.json()
            logger.info(f"Successfully fetched ATT&CK data: {len(self.attack_data.get('objects', []))} objects")
            return True
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to fetch ATT&CK data: {e}")
            return False
    
    def filter_windows_techniques(self) -> List[Dict[str, Any]]:
        """Filter for Windows-applicable techniques with Event Log data sources"""
        if not self.attack_data:
            return []
        
        filtered = []
        for obj in self.attack_data.get('objects', []):
            # Only process attack-pattern objects
            if obj.get('type') != 'attack-pattern':
                continue
            
            # Check if revoked or deprecated
            if obj.get('revoked') or obj.get('x_mitre_deprecated'):
                continue
            
            # Must target Windows platform
            platforms = obj.get('x_mitre_platforms', [])
            if 'Windows' not in platforms:
                continue
            
            # Check for Windows Event Log data sources
            data_sources = obj.get('x_mitre_data_sources', [])
            has_event_logs = any(
                'Windows Event Log' in str(ds) or
                'Event Log' in str(ds) or
                any(event_id in str(ds) for event_id in self.EVENT_ID_MAPPING.keys())
                for ds in data_sources
            )
            
            if has_event_logs or data_sources:  # Include if has any data sources
                filtered.append(obj)
        
        self.techniques = filtered
        logger.info(f"Filtered {len(filtered)} Windows-applicable techniques")
        return filtered
    
    def extract_event_ids(self, technique: Dict[str, Any]) -> List[str]:
        """Extract Event IDs from technique description and data sources"""
        event_ids = set()
        
        # Check description for Event ID references
        description = technique.get('description', '')
        for event_id in self.EVENT_ID_MAPPING.keys():
            if f"Event {event_id}" in description or f"EventID {event_id}" in description:
                event_ids.add(event_id)
        
        # Check data sources
        data_sources = technique.get('x_mitre_data_sources', [])
        for ds in data_sources:
            ds_str = str(ds)
            for event_id, mapping in self.EVENT_ID_MAPPING.items():
                if event_id in ds_str or mapping in ds_str:
                    event_ids.add(event_id)
        
        return sorted(list(event_ids))
    
    def generate_detection_query(self, technique: Dict[str, Any], event_ids: List[str]) -> str:
        """Generate ClickHouse SQL query based on technique and event IDs"""
        
        technique_id = self.get_technique_id(technique)
        name = technique.get('name', 'Unknown')
        description = technique.get('description', '')
        
        # Extract key indicators from description
        indicators = self.extract_indicators(description)
        
        # Build query based on technique category
        if not event_ids:
            # Generic query if no specific event IDs
            return self._generate_generic_query(technique_id, name, indicators)
        
        # Credential Access techniques
        if 'T1003' in technique_id:  # Credential Dumping
            return self._generate_credential_dump_query(technique_id, event_ids, indicators)
        elif 'T1110' in technique_id:  # Brute Force
            return self._generate_brute_force_query(technique_id, event_ids)
        elif 'T1550' in technique_id:  # Use Alternate Authentication
            return self._generate_alternate_auth_query(technique_id, event_ids)
        elif 'T1558' in technique_id:  # Kerberos attacks
            return self._generate_kerberos_query(technique_id, event_ids)
        else:
            # Standard event-based query
            return self._generate_standard_query(event_ids, indicators)
    
    def _generate_standard_query(self, event_ids: List[str], indicators: List[str]) -> str:
        """Generate standard detection query"""
        event_list = "', '".join(event_ids)
        
        # Build indicator conditions
        indicator_conditions = []
        for indicator in indicators[:5]:  # Limit to top 5
            if len(indicator) > 3:  # Skip very short terms
                indicator_conditions.append(f"search_blob LIKE '%{indicator}%'")
        
        indicator_clause = ""
        if indicator_conditions:
            indicator_clause = f"\n                    AND ({' OR '.join(indicator_conditions)})"
        
        return f"""
            SELECT 
                source_host,
                username,
                COUNT() as event_count,
                groupArray(DISTINCT event_id) as event_ids,
                MIN(timestamp) as first_seen,
                MAX(timestamp) as last_seen
            FROM events
            WHERE case_id = {{case_id:UInt32}}
                AND event_id IN ('{event_list}')
                AND channel = 'Security'{indicator_clause}
            GROUP BY source_host, username
            HAVING event_count >= 1
            ORDER BY event_count DESC
        """
    
    def _generate_credential_dump_query(self, technique_id: str, event_ids: List[str], indicators: List[str]) -> str:
        """Generate query for credential dumping techniques"""
        event_list = "', '".join(event_ids) if event_ids else '4656', '4663', '10'
        
        return f"""
            SELECT 
                source_host,
                username,
                COUNT() as dump_attempts,
                groupArray(DISTINCT event_id) as event_ids,
                groupArray(DISTINCT process_name) as processes,
                MIN(timestamp) as first_seen,
                MAX(timestamp) as last_seen
            FROM events
            WHERE case_id = {{case_id:UInt32}}
                AND (
                    event_id IN ('{event_list}')
                    OR lower(search_blob) LIKE '%lsass%'
                    OR lower(search_blob) LIKE '%sam%'
                    OR lower(search_blob) LIKE '%ntds.dit%'
                    OR lower(search_blob) LIKE '%mimikatz%'
                )
            GROUP BY source_host, username
            HAVING dump_attempts >= 1
            ORDER BY dump_attempts DESC
        """
    
    def _generate_brute_force_query(self, technique_id: str, event_ids: List[str]) -> str:
        """Generate query for brute force attacks"""
        return """
            SELECT 
                username,
                source_host,
                COUNT() as failure_count,
                MIN(timestamp) as first_attempt,
                MAX(timestamp) as last_attempt,
                dateDiff('second', MIN(timestamp), MAX(timestamp)) as duration_seconds
            FROM events
            WHERE case_id = {case_id:UInt32}
                AND event_id = '4625'
                AND channel = 'Security'
            GROUP BY username, source_host
            HAVING failure_count >= 10 AND duration_seconds <= 600
            ORDER BY failure_count DESC
        """
    
    def _generate_alternate_auth_query(self, technique_id: str, event_ids: List[str]) -> str:
        """Generate query for alternate authentication (PtH, PtT)"""
        if 'T1550.002' in technique_id:  # Pass the Hash
            return """
                WITH ntlm_logons AS (
                    SELECT 
                        source_host,
                        username,
                        timestamp,
                        JSONExtractString(raw_json, 'EventData', 'KeyLength') as key_length
                    FROM events
                    WHERE case_id = {case_id:UInt32}
                        AND event_id = '4624'
                        AND logon_type IN (3, 9)
                        AND search_blob LIKE '%NTLM%'
                        AND JSONExtractString(raw_json, 'EventData', 'KeyLength') = '0'
                ),
                kerberos_tgt AS (
                    SELECT DISTINCT username FROM events
                    WHERE case_id = {case_id:UInt32} AND event_id = '4768'
                )
                SELECT n.* FROM ntlm_logons n
                LEFT JOIN kerberos_tgt k ON n.username = k.username
                WHERE k.username IS NULL
            """
        else:  # Pass the Ticket
            return """
                SELECT source_host, username, COUNT() as ticket_uses
                FROM events
                WHERE case_id = {case_id:UInt32}
                    AND event_id IN ('4768', '4769')
                GROUP BY source_host, username
                HAVING ticket_uses >= 3
            """
    
    def _generate_kerberos_query(self, technique_id: str, event_ids: List[str]) -> str:
        """Generate query for Kerberos attacks"""
        return """
            SELECT 
                source_host,
                username,
                COUNT() as kerberos_events,
                MIN(timestamp) as first_seen,
                MAX(timestamp) as last_seen
            FROM events
            WHERE case_id = {case_id:UInt32}
                AND event_id IN ('4768', '4769', '4770')
                AND channel = 'Security'
            GROUP BY source_host, username
            HAVING kerberos_events >= 5
            ORDER BY kerberos_events DESC
        """
    
    def _generate_generic_query(self, technique_id: str, name: str, indicators: List[str]) -> str:
        """Generic fallback query"""
        return """
            SELECT 
                source_host,
                COUNT() as event_count,
                MIN(timestamp) as first_seen,
                MAX(timestamp) as last_seen
            FROM events
            WHERE case_id = {case_id:UInt32}
                AND channel = 'Security'
            GROUP BY source_host
            HAVING event_count >= 10
        """
    
    def extract_indicators(self, description: str) -> List[str]:
        """Extract key indicators from technique description"""
        # Common indicator keywords
        keywords = [
            'mimikatz', 'lsass', 'ntlm', 'kerberos', 'sam', 'ntds',
            'ticket', 'hash', 'credential', 'password', 'authentication',
            'registry', 'service', 'process', 'file', 'network'
        ]
        
        indicators = []
        desc_lower = description.lower()
        for keyword in keywords:
            if keyword in desc_lower:
                indicators.append(keyword)
        
        return indicators
    
    def get_technique_id(self, technique: Dict[str, Any]) -> str:
        """Extract technique ID (e.g., T1003.001)"""
        for ref in technique.get('external_references', []):
            if ref.get('source_name') == 'mitre-attack':
                return ref.get('external_id', 'Unknown')
        return 'Unknown'
    
    def convert_to_casescope_pattern(self, technique: Dict[str, Any]) -> Dict[str, Any]:
        """Convert ATT&CK technique to CaseScope pattern format"""
        
        technique_id = self.get_technique_id(technique)
        name = technique.get('name', 'Unknown')
        description = technique.get('description', '')
        
        # Extract event IDs
        event_ids = self.extract_event_ids(technique)
        
        # Determine category from tactics
        tactics = [obj.get('name', '') for obj in self.attack_data.get('objects', [])
                  if obj.get('type') == 'x-mitre-tactic' and 
                  obj.get('x_mitre_shortname') in technique.get('kill_chain_phases', [{}])[0].get('phase_name', '')]
        
        category = tactics[0] if tactics else 'General Detection'
        
        # Map to CaseScope severity
        severity = 'medium'
        if 'credential' in name.lower() or 'privilege' in name.lower():
            severity = 'high'
        if 'pass the hash' in name.lower() or 'dcsync' in name.lower() or 'golden ticket' in name.lower():
            severity = 'critical'
        
        # Generate detection query
        detection_query = self.generate_detection_query(technique, event_ids)
        
        # Extract indicators
        indicators = self.extract_indicators(description)
        
        pattern = {
            'id': f"attack_{technique_id.lower().replace('.', '_')}",
            'name': name,
            'category': category,
            'description': description[:500] + ('...' if len(description) > 500 else ''),
            'severity': severity,
            'mitre_tactics': [phase.get('phase_name', '') for phase in technique.get('kill_chain_phases', [])],
            'mitre_techniques': [technique_id],
            'source': 'mitre_attack_v18',
            'detection_query': detection_query,
            'indicators': indicators[:10],  # Top 10 indicators
            'event_ids': event_ids,
            'thresholds': {'min_events': 1},
            'created_at': datetime.utcnow().isoformat(),
        }
        
        return pattern
    
    def sync_patterns(self, categories: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """
        Sync ATT&CK patterns to CaseScope format
        
        Args:
            categories: Optional list of tactic names to filter (e.g., ['credential-access'])
        
        Returns:
            List of CaseScope pattern dictionaries
        """
        # Fetch latest ATT&CK data
        if not self.fetch_attack_data():
            logger.error("Failed to fetch ATT&CK data")
            return []
        
        # Filter for Windows techniques
        techniques = self.filter_windows_techniques()
        
        # Filter by categories if specified
        if categories:
            techniques = [t for t in techniques 
                         if any(phase.get('phase_name') in categories 
                               for phase in t.get('kill_chain_phases', []))]
        
        # Convert to CaseScope patterns
        patterns = []
        for technique in techniques:
            try:
                pattern = self.convert_to_casescope_pattern(technique)
                patterns.append(pattern)
            except Exception as e:
                logger.error(f"Failed to convert technique {self.get_technique_id(technique)}: {e}")
                continue
        
        logger.info(f"Successfully synced {len(patterns)} ATT&CK patterns")
        return patterns


def sync_attack_credential_patterns() -> List[Dict[str, Any]]:
    """
    Convenience function to sync only credential access patterns
    
    Returns:
        List of credential access patterns in CaseScope format
    """
    syncer = MitreAttackSync()
    return syncer.sync_patterns(categories=['credential-access'])


def sync_all_attack_patterns() -> List[Dict[str, Any]]:
    """
    Convenience function to sync all Windows ATT&CK patterns
    
    Returns:
        List of all Windows patterns in CaseScope format
    """
    syncer = MitreAttackSync()
    return syncer.sync_patterns()


if __name__ == '__main__':
    # Test sync
    logging.basicConfig(level=logging.INFO)
    
    print("Testing MITRE ATT&CK sync...")
    syncer = MitreAttackSync()
    patterns = syncer.sync_patterns(categories=['credential-access'])
    
    print(f"\nSynced {len(patterns)} credential access patterns:")
    for pattern in patterns[:5]:  # Show first 5
        print(f"  - {pattern['name']} ({pattern['mitre_techniques'][0]})")
    
    # Save to JSON for inspection
    with open('/tmp/attack_patterns.json', 'w') as f:
        json.dump(patterns, f, indent=2)
    print(f"\nSaved patterns to /tmp/attack_patterns.json")
