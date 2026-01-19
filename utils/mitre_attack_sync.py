"""MITRE ATT&CK Integration for CaseScope

This module automatically syncs MITRE ATT&CK patterns and converts them
to CaseScope detection rules with ClickHouse queries.

Enhanced to parse:
- attack-pattern objects (techniques)
- x-mitre-data-source objects (data sources)
- x-mitre-data-component objects (data components)
- relationship objects (technique → data component mappings)

Author: CaseScope Enhanced
Date: January 19, 2026
"""

import requests
import json
import logging
import re
from typing import List, Dict, Any, Optional, Set, Tuple
from datetime import datetime

logger = logging.getLogger(__name__)


# Enhanced Event ID to Data Component mapping
# Maps Windows Event IDs to MITRE Data Components for structured detection
DATA_COMPONENT_EVENT_IDS = {
    # Process Data Source
    'Process Creation': {
        'windows': ['4688'],
        'sysmon': ['1']
    },
    'Process Termination': {
        'windows': ['4689'],
        'sysmon': ['5']
    },
    'Process Access': {
        'windows': [],
        'sysmon': ['10']
    },
    'OS API Execution': {
        'windows': [],
        'sysmon': ['10']
    },
    # File Data Source
    'File Creation': {
        'windows': [],
        'sysmon': ['11']
    },
    'File Modification': {
        'windows': [],
        'sysmon': ['2']
    },
    'File Deletion': {
        'windows': ['4660'],
        'sysmon': ['23', '26']
    },
    'File Access': {
        'windows': ['4656', '4663'],
        'sysmon': []
    },
    # Logon Session Data Source
    'Logon Session Creation': {
        'windows': ['4624', '4625', '4768'],
        'sysmon': []
    },
    'Logon Session Metadata': {
        'windows': ['4634', '4647', '4672'],
        'sysmon': []
    },
    # User Account Data Source
    'User Account Creation': {
        'windows': ['4720'],
        'sysmon': []
    },
    'User Account Modification': {
        'windows': ['4722', '4723', '4724', '4725', '4738', '4740'],
        'sysmon': []
    },
    'User Account Deletion': {
        'windows': ['4726'],
        'sysmon': []
    },
    'User Account Authentication': {
        'windows': ['4648', '4771', '4776'],
        'sysmon': []
    },
    # Active Directory Data Source
    'Active Directory Credential Request': {
        'windows': ['4768', '4769', '4770'],
        'sysmon': []
    },
    'Active Directory Object Access': {
        'windows': ['4662'],
        'sysmon': []
    },
    # Service Data Source
    'Service Creation': {
        'windows': ['4697', '7045'],
        'sysmon': []
    },
    'Service Modification': {
        'windows': ['4697'],
        'sysmon': []
    },
    # Windows Registry Data Source
    'Windows Registry Key Creation': {
        'windows': [],
        'sysmon': ['12']
    },
    'Windows Registry Key Modification': {
        'windows': ['4657'],
        'sysmon': ['13', '14']
    },
    'Windows Registry Key Deletion': {
        'windows': [],
        'sysmon': ['12']
    },
    # Network Traffic Data Source
    'Network Connection Creation': {
        'windows': ['5156', '5157'],
        'sysmon': ['3']
    },
    'Network Traffic Flow': {
        'windows': ['5156'],
        'sysmon': ['3']
    },
    # Module Data Source
    'Module Load': {
        'windows': [],
        'sysmon': ['7']
    },
    # Command Data Source
    'Command Execution': {
        'windows': ['4103', '4104'],
        'sysmon': ['1']
    },
    # Scheduled Job Data Source
    'Scheduled Job Creation': {
        'windows': ['4698'],
        'sysmon': []
    },
    'Scheduled Job Modification': {
        'windows': ['4702'],
        'sysmon': []
    },
    # Application Log Data Source
    'Application Log Content': {
        'windows': ['1102', '104'],
        'sysmon': []
    },
    # Driver Data Source
    'Driver Load': {
        'windows': [],
        'sysmon': ['6']
    },
    # Named Pipe Data Source
    'Named Pipe Creation': {
        'windows': [],
        'sysmon': ['17', '18']
    },
    # WMI Data Source
    'WMI Creation': {
        'windows': ['5857', '5858', '5859', '5860', '5861'],
        'sysmon': ['19', '20', '21']
    },
}


class MitreAttackSync:
    """Sync MITRE ATT&CK patterns to CaseScope format
    
    Enhanced to parse:
    - attack-pattern objects with full descriptions and detection guidance
    - x-mitre-data-source objects
    - x-mitre-data-component objects
    - relationship objects for technique→data component mappings
    """
    
    # MITRE ATT&CK STIX 2.1 Data Source
    ATTACK_STIX_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
    
    # Legacy Event ID to Data Source mapping (fallback for prose parsing)
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
        self.data_sources = {}  # stix_id -> data source object
        self.data_components = {}  # stix_id -> data component object
        self.relationships = []  # technique -> data component relationships
        
    def fetch_attack_data(self) -> bool:
        """Download latest ATT&CK STIX data"""
        try:
            logger.info(f"Fetching MITRE ATT&CK data from {self.ATTACK_STIX_URL}")
            response = requests.get(self.ATTACK_STIX_URL, timeout=60)
            response.raise_for_status()
            
            self.attack_data = response.json()
            objects = self.attack_data.get('objects', [])
            logger.info(f"Successfully fetched ATT&CK data: {len(objects)} objects")
            
            # Parse all object types
            self._parse_data_sources()
            self._parse_data_components()
            self._parse_relationships()
            
            return True
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to fetch ATT&CK data: {e}")
            return False
    
    def _parse_data_sources(self):
        """Parse x-mitre-data-source objects from STIX bundle"""
        if not self.attack_data:
            return
        
        count = 0
        for obj in self.attack_data.get('objects', []):
            if obj.get('type') == 'x-mitre-data-source':
                if obj.get('revoked') or obj.get('x_mitre_deprecated'):
                    continue
                
                self.data_sources[obj.get('id')] = {
                    'stix_id': obj.get('id'),
                    'name': obj.get('name'),
                    'description': obj.get('description'),
                    'platforms': obj.get('x_mitre_platforms', []),
                    'collection_layers': obj.get('x_mitre_collection_layers', [])
                }
                count += 1
        
        logger.info(f"Parsed {count} data sources")
    
    def _parse_data_components(self):
        """Parse x-mitre-data-component objects from STIX bundle"""
        if not self.attack_data:
            return
        
        count = 0
        for obj in self.attack_data.get('objects', []):
            if obj.get('type') == 'x-mitre-data-component':
                if obj.get('revoked') or obj.get('x_mitre_deprecated'):
                    continue
                
                # Find parent data source
                data_source_ref = obj.get('x_mitre_data_source_ref')
                component_name = obj.get('name', '')
                
                # Look up event IDs from our mapping
                windows_event_ids = []
                sysmon_event_ids = []
                if component_name in DATA_COMPONENT_EVENT_IDS:
                    mapping = DATA_COMPONENT_EVENT_IDS[component_name]
                    windows_event_ids = mapping.get('windows', [])
                    sysmon_event_ids = mapping.get('sysmon', [])
                
                self.data_components[obj.get('id')] = {
                    'stix_id': obj.get('id'),
                    'name': component_name,
                    'description': obj.get('description'),
                    'data_source_ref': data_source_ref,
                    'windows_event_ids': windows_event_ids,
                    'sysmon_event_ids': sysmon_event_ids
                }
                count += 1
        
        logger.info(f"Parsed {count} data components")
    
    def _parse_relationships(self):
        """Parse relationship objects linking techniques to data components"""
        if not self.attack_data:
            return
        
        count = 0
        for obj in self.attack_data.get('objects', []):
            if obj.get('type') != 'relationship':
                continue
            
            # We want 'detects' relationships: data-component detects attack-pattern
            rel_type = obj.get('relationship_type')
            if rel_type != 'detects':
                continue
            
            source_ref = obj.get('source_ref', '')  # data component
            target_ref = obj.get('target_ref', '')  # attack pattern
            
            # Validate refs
            if not source_ref.startswith('x-mitre-data-component--'):
                continue
            if not target_ref.startswith('attack-pattern--'):
                continue
            
            self.relationships.append({
                'data_component_ref': source_ref,
                'technique_ref': target_ref,
                'description': obj.get('description')
            })
            count += 1
        
        logger.info(f"Parsed {count} detection relationships")
    
    def get_technique_data_components(self, technique_stix_id: str) -> List[Dict]:
        """Get all data components that can detect a technique"""
        components = []
        for rel in self.relationships:
            if rel['technique_ref'] == technique_stix_id:
                comp_id = rel['data_component_ref']
                if comp_id in self.data_components:
                    comp = self.data_components[comp_id].copy()
                    comp['detection_description'] = rel.get('description')
                    
                    # Add data source name
                    ds_ref = comp.get('data_source_ref')
                    if ds_ref and ds_ref in self.data_sources:
                        comp['data_source_name'] = self.data_sources[ds_ref]['name']
                    
                    components.append(comp)
        return components
    
    def get_event_ids_from_components(self, technique_stix_id: str) -> Tuple[List[str], List[str]]:
        """Get Windows and Sysmon event IDs for a technique via data components"""
        windows_ids = set()
        sysmon_ids = set()
        
        for comp in self.get_technique_data_components(technique_stix_id):
            windows_ids.update(comp.get('windows_event_ids', []))
            sysmon_ids.update(comp.get('sysmon_event_ids', []))
        
        return sorted(list(windows_ids)), sorted(list(sysmon_ids))
    
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
        """Convert ATT&CK technique to CaseScope pattern format
        
        Enhanced to:
        - Include full description (no truncation for richer embeddings)
        - Include x_mitre_detection guidance
        - Use structured data component mapping for event IDs
        - Include procedure examples when available
        """
        
        technique_id = self.get_technique_id(technique)
        technique_stix_id = technique.get('id', '')
        name = technique.get('name', 'Unknown')
        description = technique.get('description', '')
        
        # Get detection guidance from x_mitre_detection (the key missing field!)
        detection_guidance = technique.get('x_mitre_detection', '')
        
        # Get event IDs from structured data component mapping first
        windows_event_ids, sysmon_event_ids = self.get_event_ids_from_components(technique_stix_id)
        
        # Combine and fall back to prose parsing if empty
        event_ids = list(set(windows_event_ids + sysmon_event_ids))
        if not event_ids:
            event_ids = self.extract_event_ids(technique)
        
        # Get data components for this technique
        data_components = self.get_technique_data_components(technique_stix_id)
        data_component_names = [c.get('name') for c in data_components]
        
        # Determine category from tactics
        tactics = []
        kill_chain = technique.get('kill_chain_phases', [])
        for phase in kill_chain:
            phase_name = phase.get('phase_name', '')
            for obj in self.attack_data.get('objects', []):
                if obj.get('type') == 'x-mitre-tactic':
                    if obj.get('x_mitre_shortname') == phase_name:
                        tactics.append(obj.get('name', phase_name))
        
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
        
        # Extract procedure examples (from external_references of type 'uses')
        procedure_examples = self._extract_procedure_examples(technique_stix_id)
        
        pattern = {
            'id': f"attack_{technique_id.lower().replace('.', '_')}",
            'name': name,
            'category': category,
            # FULL description for richer embeddings (no truncation!)
            'description': description,
            # Detection guidance from MITRE (the missing x_mitre_detection field)
            'detection_guidance': detection_guidance,
            'severity': severity,
            'mitre_tactics': [phase.get('phase_name', '') for phase in technique.get('kill_chain_phases', [])],
            'mitre_techniques': [technique_id],
            'source': 'mitre_attack_v18',
            'detection_query': detection_query,
            'indicators': indicators[:10],
            'event_ids': event_ids,
            'data_components': data_component_names,
            'procedure_examples': procedure_examples[:5],  # Top 5 examples
            'thresholds': {'min_events': 1},
            'created_at': datetime.utcnow().isoformat(),
        }
        
        return pattern
    
    def _extract_procedure_examples(self, technique_stix_id: str) -> List[Dict[str, str]]:
        """Extract real-world procedure examples from threat groups
        
        MITRE includes relationships showing how threat groups use techniques.
        """
        if not self.attack_data:
            return []
        
        examples = []
        
        # Build a map of intrusion-set IDs to names
        intrusion_sets = {}
        for obj in self.attack_data.get('objects', []):
            if obj.get('type') == 'intrusion-set':
                intrusion_sets[obj.get('id')] = obj.get('name', 'Unknown')
        
        # Find 'uses' relationships: intrusion-set uses attack-pattern
        for obj in self.attack_data.get('objects', []):
            if obj.get('type') != 'relationship':
                continue
            if obj.get('relationship_type') != 'uses':
                continue
            
            source_ref = obj.get('source_ref', '')
            target_ref = obj.get('target_ref', '')
            
            if target_ref != technique_stix_id:
                continue
            if not source_ref.startswith('intrusion-set--'):
                continue
            
            group_name = intrusion_sets.get(source_ref, 'Unknown')
            description = obj.get('description', '')
            
            if description:
                examples.append({
                    'group': group_name,
                    'description': description[:500]  # Truncate for storage
                })
        
        return examples
    
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


def sync_data_sources_to_db() -> Dict[str, int]:
    """
    Sync MITRE Data Sources and Data Components to database
    
    Creates MitreDataSource, MitreDataComponent, and TechniqueDataComponentMap records.
    
    Returns:
        Dict with counts of synced objects
    """
    from models.database import db
    from models.rag import MitreDataSource, MitreDataComponent, TechniqueDataComponentMap
    
    syncer = MitreAttackSync()
    if not syncer.fetch_attack_data():
        return {'error': 'Failed to fetch ATT&CK data'}
    
    counts = {
        'data_sources': 0,
        'data_components': 0,
        'technique_maps': 0
    }
    
    # Sync Data Sources
    for stix_id, ds in syncer.data_sources.items():
        existing = MitreDataSource.query.filter_by(stix_id=stix_id).first()
        if existing:
            existing.name = ds['name']
            existing.description = ds.get('description')
            existing.platforms = ds.get('platforms')
            existing.collection_layers = ds.get('collection_layers')
            existing.last_synced_at = datetime.utcnow()
        else:
            new_ds = MitreDataSource(
                stix_id=stix_id,
                name=ds['name'],
                description=ds.get('description'),
                platforms=ds.get('platforms'),
                collection_layers=ds.get('collection_layers')
            )
            db.session.add(new_ds)
            counts['data_sources'] += 1
    
    db.session.flush()  # Get IDs for foreign keys
    
    # Build stix_id to db_id map for data sources
    ds_id_map = {ds.stix_id: ds.id for ds in MitreDataSource.query.all()}
    
    # Sync Data Components
    for stix_id, dc in syncer.data_components.items():
        ds_ref = dc.get('data_source_ref')
        ds_db_id = ds_id_map.get(ds_ref)
        
        if not ds_db_id:
            logger.warning(f"No data source found for component {dc['name']}")
            continue
        
        existing = MitreDataComponent.query.filter_by(stix_id=stix_id).first()
        if existing:
            existing.name = dc['name']
            existing.description = dc.get('description')
            existing.windows_event_ids = dc.get('windows_event_ids')
            existing.sysmon_event_ids = dc.get('sysmon_event_ids')
            existing.last_synced_at = datetime.utcnow()
        else:
            new_dc = MitreDataComponent(
                stix_id=stix_id,
                data_source_id=ds_db_id,
                name=dc['name'],
                description=dc.get('description'),
                windows_event_ids=dc.get('windows_event_ids'),
                sysmon_event_ids=dc.get('sysmon_event_ids')
            )
            db.session.add(new_dc)
            counts['data_components'] += 1
    
    db.session.flush()
    
    # Build stix_id to db_id map for data components
    dc_id_map = {dc.stix_id: dc.id for dc in MitreDataComponent.query.all()}
    
    # Sync Technique → Data Component mappings
    for rel in syncer.relationships:
        dc_stix_id = rel['data_component_ref']
        technique_stix_id = rel['technique_ref']
        
        dc_db_id = dc_id_map.get(dc_stix_id)
        if not dc_db_id:
            continue
        
        # Get technique ID (e.g., T1003.001) from technique_stix_id
        technique_id = None
        for obj in syncer.attack_data.get('objects', []):
            if obj.get('id') == technique_stix_id and obj.get('type') == 'attack-pattern':
                technique_id = syncer.get_technique_id(obj)
                break
        
        if not technique_id:
            continue
        
        # Check if mapping exists
        existing = TechniqueDataComponentMap.query.filter_by(
            technique_id=technique_id,
            data_component_id=dc_db_id
        ).first()
        
        if not existing:
            new_map = TechniqueDataComponentMap(
                technique_id=technique_id,
                data_component_id=dc_db_id,
                relationship_type='detects',
                detection_guidance=rel.get('description')
            )
            db.session.add(new_map)
            counts['technique_maps'] += 1
    
    db.session.commit()
    
    logger.info(f"Synced: {counts['data_sources']} data sources, "
                f"{counts['data_components']} data components, "
                f"{counts['technique_maps']} technique mappings")
    
    return counts


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
