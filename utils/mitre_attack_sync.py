"""MITRE ATT&CK Enterprise STIX import helpers."""
from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.request import Request, urlopen

from models.database import db
from models.mitre_attack import MitreAttackMetadata, MitreAttackObject


ENTERPRISE_ATTACK_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    "master/enterprise-attack/enterprise-attack.json"
)


def _fetch_json(url: str = ENTERPRISE_ATTACK_URL, timeout: int = 60) -> Dict[str, Any]:
    request = Request(
        url,
        headers={
            "Accept": "application/json",
            "User-Agent": "CaseScope MITRE ATT&CK Sync",
        },
    )
    with urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def _first_attack_external_ref(stix_object: Dict[str, Any]) -> Dict[str, Any]:
    for ref in stix_object.get("external_references") or []:
        if ref.get("source_name") == "mitre-attack":
            return ref
    return {}


def _is_active(stix_object: Dict[str, Any]) -> bool:
    return not bool(stix_object.get("revoked") or stix_object.get("x_mitre_deprecated"))


def _extract_collection_metadata(bundle: Dict[str, Any]) -> Dict[str, Optional[str]]:
    objects = bundle.get("objects") or []
    collection = next(
        (
            obj
            for obj in objects
            if obj.get("type") in {"x-mitre-collection", "x_mitre_collection"}
            and "enterprise" in str(obj.get("name", "")).lower()
        ),
        None,
    )
    if not collection:
        collection = next(
            (
                obj
                for obj in objects
                if obj.get("type") in {"x-mitre-collection", "x_mitre_collection"}
            ),
            None,
        )

    attack_version = None
    attack_spec_version = None
    source_modified = None
    if collection:
        attack_version = collection.get("x_mitre_version")
        attack_spec_version = collection.get("x_mitre_attack_spec_version")
        source_modified = collection.get("modified")

    if not attack_spec_version:
        attack_spec_version = bundle.get("spec_version")
    if not source_modified:
        source_modified = bundle.get("modified")

    return {
        "attack_version": attack_version,
        "attack_spec_version": attack_spec_version,
        "source_modified": source_modified,
    }


def fetch_remote_metadata(url: str = ENTERPRISE_ATTACK_URL) -> Dict[str, Any]:
    """Fetch remote bundle metadata without importing objects."""
    bundle = _fetch_json(url=url)
    metadata = _extract_collection_metadata(bundle)
    metadata.update(
        {
            "source_url": url,
            "raw_object_count": len(bundle.get("objects") or []),
        }
    )
    return metadata


def check_for_mitre_update(url: str = ENTERPRISE_ATTACK_URL) -> Dict[str, Any]:
    """Compare the local MITRE version with the current remote version."""
    remote = fetch_remote_metadata(url=url)
    metadata = MitreAttackMetadata.ensure_enterprise()
    local_version = metadata.attack_version
    latest_version = remote.get("attack_version")

    update_available = bool(
        latest_version
        and local_version
        and latest_version != local_version
    )
    if not local_version and latest_version:
        update_available = True

    metadata.source_url = metadata.source_url or url
    metadata.last_checked_at = datetime.utcnow()
    metadata.latest_available_version = latest_version
    metadata.update_available = update_available
    db.session.commit()

    return {
        "success": True,
        "local_version": local_version,
        "latest_available_version": latest_version,
        "update_available": update_available,
        "raw_object_count": remote.get("raw_object_count", 0),
        "source_modified": remote.get("source_modified"),
        "checked_at": metadata.last_checked_at.isoformat(),
    }


def _build_tactic_rows(objects: Iterable[Dict[str, Any]]) -> Tuple[List[MitreAttackObject], Dict[str, Dict[str, Any]]]:
    rows: List[MitreAttackObject] = []
    tactic_by_shortname: Dict[str, Dict[str, Any]] = {}

    for obj in objects:
        if obj.get("type") != "x-mitre-tactic" or not _is_active(obj):
            continue

        external_ref = _first_attack_external_ref(obj)
        shortname = obj.get("x_mitre_shortname")
        tactic_by_shortname[shortname] = obj
        rows.append(
            MitreAttackObject(
                domain="enterprise",
                object_type="tactic",
                stix_id=obj.get("id"),
                external_id=external_ref.get("external_id"),
                name=obj.get("name") or shortname or obj.get("id"),
                description=obj.get("description"),
                tactic_shortname=shortname,
                tactic_name=obj.get("name"),
                url=external_ref.get("url"),
                version=obj.get("x_mitre_version"),
                stix_created=obj.get("created"),
                stix_modified=obj.get("modified"),
                metadata_json={"stix_type": obj.get("type")},
            )
        )

    return rows, tactic_by_shortname


def _build_technique_rows(
    objects: Iterable[Dict[str, Any]],
    tactic_by_shortname: Dict[str, Dict[str, Any]],
) -> Tuple[List[MitreAttackObject], Dict[str, Dict[str, Any]], Dict[str, str]]:
    rows: List[MitreAttackObject] = []
    technique_by_stix_id: Dict[str, Dict[str, Any]] = {}
    technique_external_by_stix_id: Dict[str, str] = {}

    for obj in objects:
        if obj.get("type") != "attack-pattern" or not _is_active(obj):
            continue

        external_ref = _first_attack_external_ref(obj)
        external_id = external_ref.get("external_id")
        is_subtechnique = bool(obj.get("x_mitre_is_subtechnique"))
        tactic_shortnames = [
            phase.get("phase_name")
            for phase in obj.get("kill_chain_phases") or []
            if phase.get("kill_chain_name") == "mitre-attack" and phase.get("phase_name")
        ]
        tactic_names = [
            tactic_by_shortname.get(shortname, {}).get("name", shortname)
            for shortname in tactic_shortnames
        ]

        technique_by_stix_id[obj.get("id")] = obj
        if external_id:
            technique_external_by_stix_id[obj.get("id")] = external_id

        rows.append(
            MitreAttackObject(
                domain="enterprise",
                object_type="sub_technique" if is_subtechnique else "technique",
                stix_id=obj.get("id"),
                external_id=external_id,
                name=obj.get("name") or external_id or obj.get("id"),
                description=obj.get("description"),
                tactic_shortname=", ".join(tactic_shortnames) if tactic_shortnames else None,
                tactic_name=", ".join(tactic_names) if tactic_names else None,
                platforms=obj.get("x_mitre_platforms") or [],
                data_sources=obj.get("x_mitre_data_sources") or [],
                permissions_required=obj.get("x_mitre_permissions_required") or [],
                detection=obj.get("x_mitre_detection"),
                url=external_ref.get("url"),
                version=obj.get("x_mitre_version"),
                stix_created=obj.get("created"),
                stix_modified=obj.get("modified"),
                metadata_json={
                    "stix_type": obj.get("type"),
                    "is_subtechnique": is_subtechnique,
                    "kill_chain_phases": obj.get("kill_chain_phases") or [],
                },
            )
        )

    return rows, technique_by_stix_id, technique_external_by_stix_id


def _build_procedure_rows(
    objects: Iterable[Dict[str, Any]],
    technique_by_stix_id: Dict[str, Dict[str, Any]],
    technique_external_by_stix_id: Dict[str, str],
) -> List[MitreAttackObject]:
    source_objects = {
        obj.get("id"): obj
        for obj in objects
        if obj.get("id") and obj.get("type") in {"intrusion-set", "malware", "tool", "campaign"}
    }
    rows: List[MitreAttackObject] = []

    for obj in objects:
        if (
            obj.get("type") != "relationship"
            or obj.get("relationship_type") != "uses"
            or not _is_active(obj)
        ):
            continue

        target_ref = obj.get("target_ref")
        technique = technique_by_stix_id.get(target_ref)
        if not technique:
            continue

        source = source_objects.get(obj.get("source_ref"), {})
        source_name = source.get("name") or obj.get("source_ref") or "Unknown source"
        technique_external_id = technique_external_by_stix_id.get(target_ref)
        technique_name = technique.get("name") or technique_external_id or target_ref
        description = obj.get("description")
        if not description:
            continue

        rows.append(
            MitreAttackObject(
                domain="enterprise",
                object_type="procedure",
                stix_id=obj.get("id"),
                external_id=technique_external_id,
                name=f"{source_name} uses {technique_name}",
                description=description,
                technique_stix_id=target_ref,
                technique_external_id=technique_external_id,
                source_name=source_name,
                source_type=source.get("type"),
                version=obj.get("x_mitre_version"),
                stix_created=obj.get("created"),
                stix_modified=obj.get("modified"),
                metadata_json={
                    "stix_type": obj.get("type"),
                    "relationship_type": obj.get("relationship_type"),
                    "source_ref": obj.get("source_ref"),
                    "target_ref": target_ref,
                },
            )
        )

    return rows


def import_mitre_enterprise_attack(
    *,
    updated_by: str = "system",
    url: str = ENTERPRISE_ATTACK_URL,
) -> Dict[str, Any]:
    """Replace the local Enterprise ATT&CK reference snapshot."""
    bundle = _fetch_json(url=url, timeout=120)
    objects = bundle.get("objects") or []
    metadata_values = _extract_collection_metadata(bundle)

    tactic_rows, tactic_by_shortname = _build_tactic_rows(objects)
    technique_rows, technique_by_stix_id, technique_external_by_stix_id = _build_technique_rows(
        objects,
        tactic_by_shortname,
    )
    procedure_rows = _build_procedure_rows(
        objects,
        technique_by_stix_id,
        technique_external_by_stix_id,
    )
    all_rows = tactic_rows + technique_rows + procedure_rows

    MitreAttackObject.query.filter_by(domain="enterprise").delete(synchronize_session=False)
    if all_rows:
        db.session.bulk_save_objects(all_rows)

    metadata = MitreAttackMetadata.ensure_enterprise()
    metadata.attack_version = metadata_values.get("attack_version")
    metadata.attack_spec_version = metadata_values.get("attack_spec_version")
    metadata.source_url = url
    metadata.source_modified = metadata_values.get("source_modified")
    metadata.raw_object_count = len(objects)
    metadata.last_updated_at = datetime.utcnow()
    metadata.last_checked_at = metadata.last_updated_at
    metadata.latest_available_version = metadata.attack_version
    metadata.update_available = False
    metadata.updated_by = updated_by
    db.session.commit()

    stats = MitreAttackObject.get_stats()
    stats.update(
        {
            "success": True,
            "message": "MITRE ATT&CK Enterprise database updated",
            "updated": len(all_rows),
        }
    )
    return stats
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
        """Parse x-mitre-data-source objects from STIX bundle
        
        Note: MITRE has deprecated data source objects, but we still parse them
        because data components reference them and they're useful for our mapping.
        """
        if not self.attack_data:
            return
        
        count = 0
        for obj in self.attack_data.get('objects', []):
            if obj.get('type') == 'x-mitre-data-source':
                # Only skip if revoked, NOT if deprecated (most are deprecated but still useful)
                if obj.get('revoked'):
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
        """Parse x-mitre-data-component objects from STIX bundle
        
        Note: x_mitre_data_source_ref is often empty in current STIX data.
        We use name-based matching with multiple strategies.
        """
        if not self.attack_data:
            return
        
        # Build data source name to stix_id mapping
        ds_name_to_id = {ds['name']: stix_id for stix_id, ds in self.data_sources.items()}
        
        # Sort data source names by length (longest first) to match more specific names first
        ds_names_sorted = sorted(ds_name_to_id.keys(), key=len, reverse=True)
        
        # Manual mappings for non-obvious component -> source relationships
        COMPONENT_TO_SOURCE = {
            'Network Connection Creation': 'Network Traffic',
            'Network Traffic Flow': 'Network Traffic',
            'Network Traffic Content': 'Network Traffic',
            'Response Content': 'Network Traffic',
            'Response Metadata': 'Network Traffic',
            'Active DNS': 'Domain Name',
            'Passive DNS': 'Domain Name',
            'Domain Registration': 'Domain Name',
            'Social Media': 'Persona',
            'Host Status': 'Sensor Health',
        }
        
        count = 0
        matched = 0
        for obj in self.attack_data.get('objects', []):
            if obj.get('type') == 'x-mitre-data-component':
                if obj.get('revoked') or obj.get('x_mitre_deprecated'):
                    continue
                
                component_name = obj.get('name', '')
                
                # Try explicit ref first
                data_source_ref = obj.get('x_mitre_data_source_ref')
                
                # If empty, try name-based matching strategies
                if not data_source_ref:
                    # Strategy 1: Manual mapping
                    if component_name in COMPONENT_TO_SOURCE:
                        ds_name = COMPONENT_TO_SOURCE[component_name]
                        if ds_name in ds_name_to_id:
                            data_source_ref = ds_name_to_id[ds_name]
                            matched += 1
                    
                    # Strategy 2: Prefix match (longest data source name first)
                    if not data_source_ref:
                        for ds_name in ds_names_sorted:
                            if component_name.startswith(ds_name + ' ') or component_name == ds_name:
                                data_source_ref = ds_name_to_id[ds_name]
                                matched += 1
                                break
                    
                    # Strategy 3: First word match (e.g., "File" in "File Creation")
                    if not data_source_ref:
                        first_word = component_name.split()[0] if component_name else ''
                        if first_word in ds_name_to_id:
                            data_source_ref = ds_name_to_id[first_word]
                            matched += 1
                
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
        
        logger.info(f"Parsed {count} data components ({matched} matched to sources)")
    
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
        """Filter for Windows-applicable techniques
        
        Note: MITRE has deprecated x_mitre_data_sources on techniques.
        We now include all Windows techniques and use the data component
        relationships for event ID mapping.
        """
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
            
            # Include all Windows techniques (data sources are now in relationships)
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
        event_list = "', '".join(event_ids) if event_ids else "', '".join(['4656', '4663', '10'])
        
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
