#!/usr/bin/env python3
"""
OpenCTI API Client for CaseScope
Handles all communication with OpenCTI for threat intelligence enrichment
"""

import logging
import json
from typing import Optional, Dict, List, Any
from datetime import datetime

logger = logging.getLogger(__name__)


class OpenCTIClient:
    """
    Client for interacting with OpenCTI API for indicator enrichment
    
    OpenCTI API Reference: https://docs.opencti.io/
    """
    
    def __init__(self, url: str, api_key: str, ssl_verify: bool = False):
        """
        Initialize OpenCTI client using pycti library
        
        Args:
            url: OpenCTI server URL (e.g., https://opencti.company.com)
            api_key: API authentication key
            ssl_verify: Verify SSL certificates (default: False for self-signed certs)
        """
        try:
            from pycti import OpenCTIApiClient
            
            self.url = url.rstrip('/')
            self.api_key = api_key
            self.client = None
            self.init_error = None
            
            # Initialize the official pycti client
            try:
                self.client = OpenCTIApiClient(
                    url=self.url,
                    token=api_key,
                    ssl_verify=ssl_verify
                )
                logger.info(f"[OpenCTI] Client initialized: {self.url}")
            except ValueError as e:
                error_str = str(e)
                if 'AUTH_REQUIRED' in error_str:
                    self.init_error = "Authentication failed - Invalid API key"
                    logger.warning(f"[OpenCTI] Authentication failed for {self.url}")
                elif 'not reachable' in error_str or 'Waiting for' in error_str:
                    self.init_error = "OpenCTI API is not reachable - Check URL"
                    logger.warning(f"[OpenCTI] API not reachable: {self.url}")
                else:
                    self.init_error = f"Connection failed: {error_str}"
                    logger.warning(f"[OpenCTI] Connection error: {error_str}")
            except Exception as e:
                self.init_error = f"Unexpected error: {str(e)}"
                logger.warning(f"[OpenCTI] Initialization error: {str(e)}")
            
        except ImportError:
            logger.error("[OpenCTI] pycti library not installed. Run: pip install pycti")
            raise Exception("pycti library required for OpenCTI integration")
        except Exception as e:
            logger.error(f"[OpenCTI] Failed to initialize client: {str(e)}")
            raise
    
    # ============================================================================
    # HEALTH CHECK
    # ============================================================================
    
    def ping(self) -> bool:
        """
        Test connection to OpenCTI
        
        Returns:
            True if connected and authenticated, False otherwise
        """
        if self.init_error:
            logger.error(f"[OpenCTI] Connection failed: {self.init_error}")
            return False
        
        if not self.client:
            logger.error("[OpenCTI] Client not initialized")
            return False
        
        try:
            result = self.client.health_check()
            logger.info("[OpenCTI] Connection successful")
            return True
        except Exception as e:
            logger.error(f"[OpenCTI] Connection failed: {str(e)}")
            return False
    
    def get_error(self) -> Optional[str]:
        """Get initialization error if any"""
        return self.init_error
    
    # ============================================================================
    # IOC TYPE MAPPING
    # ============================================================================
    
    def _map_ioc_type_to_opencti(self, casescope_type: str) -> str:
        """
        Map CaseScope IOC types to OpenCTI observable types
        
        Args:
            casescope_type: IOC type from CaseScope
            
        Returns:
            OpenCTI observable type string
        """
        type_mapping = {
            # Network
            'IP Address (IPv4)': 'IPv4-Addr',
            'IP Address (IPv6)': 'IPv6-Addr',
            'Domain': 'Domain-Name',
            'FQDN': 'Domain-Name',
            'Hostname': 'Hostname',
            'URL': 'Url',
            'Port': 'Text',
            'User-Agent': 'User-Agent',
            'JA3 Hash': 'Text',
            'JA3S Hash': 'Text',
            'SSL Certificate Hash': 'X509-Certificate',
            'ASN': 'Autonomous-System',
            
            # File
            'MD5 Hash': 'StixFile',
            'SHA1 Hash': 'StixFile',
            'SHA256 Hash': 'StixFile',
            'File Name': 'StixFile',
            'File Path': 'StixFile',
            'Imphash': 'StixFile',
            
            # Email
            'Email Address': 'Email-Addr',
            'X-Originating-IP': 'IPv4-Addr',
            
            # Registry
            'Registry Key': 'Windows-Registry-Key',
            'Registry Value': 'Windows-Registry-Value-Type',
            
            # Process
            'Process Name': 'Process',
            'Command Line': 'Text',
            'Service Name': 'Text',
            
            # Authentication
            'Username': 'User-Account',
            'SID': 'User-Account',
            
            # Malware
            'Malware Family': 'Malware',
            
            # Cryptocurrency
            'Bitcoin Address': 'Cryptocurrency-Wallet',
            'Ethereum Address': 'Cryptocurrency-Wallet',
            'Monero Address': 'Cryptocurrency-Wallet',
        }
        
        return type_mapping.get(casescope_type, 'Text')
    
    # ============================================================================
    # INDICATOR ENRICHMENT
    # ============================================================================
    
    def check_indicator(self, ioc_value: str, ioc_type: str) -> Dict[str, Any]:
        """
        Check if indicator exists in OpenCTI and get enrichment data
        
        Args:
            ioc_value: The indicator value (IP, domain, hash, etc.)
            ioc_type: CaseScope IOC type
            
        Returns:
            Dict containing enrichment data
        """
        if self.init_error or not self.client:
            error_msg = self.init_error or "Client not initialized"
            logger.error(f"[OpenCTI] Cannot check indicator: {error_msg}")
            return {
                'found': False,
                'error': error_msg,
                'checked_at': datetime.utcnow().isoformat()
            }
        
        try:
            logger.info(f"[OpenCTI] Checking indicator: {ioc_type}={ioc_value}")
            
            opencti_type = self._map_ioc_type_to_opencti(ioc_type)
            result = self._search_indicator(ioc_value, opencti_type)
            
            if not result:
                logger.info(f"[OpenCTI] Indicator not found: {ioc_value}")
                return {
                    'found': False,
                    'message': 'Not found in OpenCTI',
                    'checked_at': datetime.utcnow().isoformat()
                }
            
            enrichment = self._parse_indicator_data(result)
            enrichment['found'] = True
            enrichment['checked_at'] = datetime.utcnow().isoformat()
            
            logger.info(f"[OpenCTI] Indicator found: {ioc_value} (Score: {enrichment.get('score', 'N/A')})")
            
            return enrichment
            
        except Exception as e:
            logger.error(f"[OpenCTI] Error checking indicator: {str(e)}")
            return {
                'found': False,
                'error': str(e),
                'checked_at': datetime.utcnow().isoformat()
            }
    
    def _search_indicator(self, value: str, observable_type: str) -> Optional[Dict]:
        """
        Search for indicator/observable in OpenCTI
        """
        try:
            # Try searching as an Indicator first
            indicators = self.client.indicator.list(
                filters={
                    "mode": "and",
                    "filters": [
                        {"key": "pattern", "values": [value], "operator": "match"}
                    ],
                    "filterGroups": []
                },
                first=10
            )
            
            if indicators and len(indicators) > 0:
                logger.debug(f"[OpenCTI] Found as Indicator: {value}")
                return indicators[0]
            
            # Try searching as Observable
            observables = self.client.stix_cyber_observable.list(
                filters={
                    "mode": "and",
                    "filters": [
                        {"key": "value", "values": [value], "operator": "eq"}
                    ],
                    "filterGroups": []
                },
                first=10
            )
            
            if observables and len(observables) > 0:
                logger.debug(f"[OpenCTI] Found as Observable: {value}")
                return observables[0]
            
            return None
            
        except Exception as e:
            logger.warning(f"[OpenCTI] Search failed: {str(e)}")
            return None
    
    def _parse_indicator_data(self, data: Dict) -> Dict[str, Any]:
        """
        Parse OpenCTI indicator data into structured enrichment
        """
        enrichment = {
            'indicator_id': data.get('id', ''),
            'name': data.get('name') or data.get('value', 'Unknown'),
            'description': data.get('description', ''),
            'score': self._calculate_score(data),
            'labels': self._extract_labels(data),
            'threat_actors': self._extract_related_entities(data, 'Threat-Actor'),
            'campaigns': self._extract_related_entities(data, 'Campaign'),
            'malware_families': self._extract_related_entities(data, 'Malware'),
            'created_at': data.get('created_at', ''),
            'updated_at': data.get('updated_at', ''),
            'tlp': self._extract_tlp(data),
            'confidence': data.get('confidence', 0),
            'indicator_types': data.get('indicator_types', [])
        }
        
        return enrichment
    
    def _calculate_score(self, data: Dict) -> int:
        """
        Calculate a risk score (0-100) based on OpenCTI data
        """
        score = 0
        
        confidence = data.get('confidence', 0)
        if confidence:
            score += min(confidence, 50)
        
        indicator_types = data.get('indicator_types', [])
        malicious_types = ['malicious-activity', 'anomalous-activity', 'compromised']
        if any(t in str(indicator_types).lower() for t in malicious_types):
            score += 30
        
        if data.get('objectRefs') or data.get('relationships'):
            score += 20
        
        return min(score, 100)
    
    def _extract_labels(self, data: Dict) -> List[str]:
        """Extract labels/tags from indicator data"""
        labels = []
        
        if 'objectLabel' in data:
            obj_labels = data['objectLabel']
            if isinstance(obj_labels, list):
                labels.extend([l.get('value', '') for l in obj_labels if l.get('value')])
            elif isinstance(obj_labels, dict):
                if 'edges' in obj_labels:
                    labels.extend([edge['node']['value'] for edge in obj_labels['edges'] if 'node' in edge])
        
        if 'labels' in data:
            if isinstance(data['labels'], list):
                labels.extend(data['labels'])
        
        return list(set(labels))
    
    def _extract_related_entities(self, data: Dict, entity_type: str) -> List[str]:
        """Extract related entities of specific type"""
        entities = []
        
        if 'objectRefs' in data:
            refs = data['objectRefs']
            if isinstance(refs, list):
                for ref in refs:
                    if isinstance(ref, dict) and ref.get('entity_type') == entity_type:
                        name = ref.get('name') or ref.get('value', '')
                        if name:
                            entities.append(name)
        
        return entities
    
    def _extract_tlp(self, data: Dict) -> str:
        """Extract TLP (Traffic Light Protocol) marking"""
        if 'objectMarking' in data:
            markings = data['objectMarking']
            if isinstance(markings, list):
                for marking in markings:
                    if isinstance(marking, dict):
                        definition = marking.get('definition', '')
                        if 'TLP' in definition.upper():
                            return definition
            elif isinstance(markings, dict) and 'edges' in markings:
                for edge in markings['edges']:
                    if 'node' in edge:
                        definition = edge['node'].get('definition', '')
                        if 'TLP' in definition.upper():
                            return definition
        
        return 'TLP:CLEAR'
    
    # ============================================================================
    # BATCH ENRICHMENT
    # ============================================================================
    
    def check_indicators_batch(self, iocs: List[Dict[str, str]]) -> Dict[str, Dict[str, Any]]:
        """
        Check multiple indicators at once
        
        Args:
            iocs: List of dicts with 'value' and 'type' keys
            
        Returns:
            Dict mapping ioc_value to enrichment data
        """
        results = {}
        
        for ioc in iocs:
            value = ioc.get('value')
            ioc_type = ioc.get('type')
            
            if value and ioc_type:
                try:
                    enrichment = self.check_indicator(value, ioc_type)
                    results[value] = enrichment
                except Exception as e:
                    logger.error(f"[OpenCTI] Error enriching {value}: {str(e)}")
                    results[value] = {
                        'found': False,
                        'error': str(e)
                    }
        
        return results
    
    # ============================================================================
    # STATISTICS
    # ============================================================================
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get OpenCTI instance statistics"""
        try:
            stats = {
                'connected': True,
                'url': self.url,
                'indicators_count': 0,
                'observables_count': 0
            }
            
            try:
                indicators = self.client.indicator.list(first=1)
                stats['indicators_available'] = len(indicators) > 0
            except:
                pass
            
            return stats
            
        except Exception as e:
            logger.error(f"[OpenCTI] Error getting statistics: {str(e)}")
            return {
                'connected': False,
                'error': str(e)
            }
    
    # ============================================================================
    # RAG PATTERN METHODS
    # ============================================================================
    
    def get_attack_patterns(self, limit: int = 500) -> List[Dict[str, Any]]:
        """
        Pull Attack Patterns (MITRE ATT&CK techniques) from OpenCTI
        
        Args:
            limit: Maximum patterns to retrieve
            
        Returns:
            List of attack pattern dictionaries
        """
        if self.init_error or not self.client:
            logger.warning("[OpenCTI] Cannot get attack patterns: client not initialized")
            return []
        
        try:
            patterns = self.client.attack_pattern.list(first=limit)
            
            results = []
            for pattern in patterns:
                kill_chain_phases = []
                if pattern.get('killChainPhases'):
                    for kcp in pattern['killChainPhases']:
                        if isinstance(kcp, dict):
                            kill_chain_phases.append(kcp.get('phase_name', ''))
                
                results.append({
                    'name': pattern.get('name'),
                    'description': pattern.get('description'),
                    'mitre_id': pattern.get('x_mitre_id'),
                    'kill_chain_phases': kill_chain_phases,
                    'platforms': pattern.get('x_mitre_platforms', []),
                    'detection': pattern.get('x_mitre_detection', ''),
                    'opencti_id': pattern.get('id'),
                })
            
            logger.info(f"[OpenCTI] Retrieved {len(results)} attack patterns")
            return results
            
        except Exception as e:
            logger.error(f"[OpenCTI] Error getting attack patterns: {e}")
            return []
    
    def get_intrusion_sets_with_ttps(self, limit: int = 200) -> List[Dict[str, Any]]:
        """
        Get threat actor groups and their associated TTPs
        
        Args:
            limit: Maximum intrusion sets to retrieve
            
        Returns:
            List of intrusion set dictionaries with attack patterns
        """
        if self.init_error or not self.client:
            return []
        
        try:
            intrusion_sets = self.client.intrusion_set.list(first=limit)
            
            results = []
            for actor in intrusion_sets:
                # Get attack patterns used by this actor
                attack_patterns = []
                try:
                    relationships = self.client.stix_core_relationship.list(
                        fromId=actor['id'],
                        relationship_type='uses',
                        toTypes=['Attack-Pattern'],
                        first=100
                    )
                    
                    for rel in relationships:
                        if rel.get('to'):
                            attack_patterns.append({
                                'name': rel['to'].get('name'),
                                'mitre_id': rel['to'].get('x_mitre_id')
                            })
                except Exception:
                    pass  # Continue without relationships
                
                results.append({
                    'name': actor.get('name'),
                    'aliases': actor.get('aliases', []),
                    'description': actor.get('description'),
                    'attack_patterns': attack_patterns,
                    'opencti_id': actor.get('id'),
                })
            
            logger.info(f"[OpenCTI] Retrieved {len(results)} intrusion sets")
            return results
            
        except Exception as e:
            logger.error(f"[OpenCTI] Error getting intrusion sets: {e}")
            return []
    
    def get_indicators_with_patterns(self, limit: int = 500) -> List[Dict[str, Any]]:
        """
        Get indicators that have STIX/Sigma/YARA detection patterns
        
        Args:
            limit: Maximum indicators to retrieve
            
        Returns:
            List of indicator dictionaries with patterns
        """
        if self.init_error or not self.client:
            return []
        
        try:
            # Query for indicators with detection patterns
            indicators = self.client.indicator.list(
                first=limit,
                filters={
                    "mode": "or",
                    "filters": [
                        {"key": "pattern_type", "values": ["stix"], "operator": "eq"},
                        {"key": "pattern_type", "values": ["sigma"], "operator": "eq"},
                        {"key": "pattern_type", "values": ["yara"], "operator": "eq"}
                    ],
                    "filterGroups": []
                }
            )
            
            results = []
            for ind in indicators:
                kill_chain_phases = []
                if ind.get('killChainPhases'):
                    for kcp in ind['killChainPhases']:
                        if isinstance(kcp, dict):
                            kill_chain_phases.append(kcp.get('phase_name', ''))
                
                results.append({
                    'name': ind.get('name'),
                    'pattern': ind.get('pattern'),
                    'pattern_type': ind.get('pattern_type'),
                    'valid_from': ind.get('valid_from'),
                    'valid_until': ind.get('valid_until'),
                    'score': ind.get('x_opencti_score'),
                    'labels': self._extract_labels(ind),
                    'kill_chain_phases': kill_chain_phases,
                    'opencti_id': ind.get('id'),
                })
            
            logger.info(f"[OpenCTI] Retrieved {len(results)} indicators with patterns")
            return results
            
        except Exception as e:
            logger.error(f"[OpenCTI] Error getting indicators: {e}")
            return []
    
    def get_sigma_indicators(self, limit: int = 500) -> List[Dict[str, Any]]:
        """
        Get Sigma detection rules stored as Indicators in OpenCTI.
        These contain actual detection logic that can be converted to executable patterns.
        
        Args:
            limit: Maximum indicators to retrieve
            
        Returns:
            List of indicator dictionaries with Sigma rules
        """
        if self.init_error or not self.client:
            logger.warning("[OpenCTI] Cannot get Sigma indicators: client not initialized")
            return []
        
        try:
            indicators = self.client.indicator.list(
                first=limit,
                filters={
                    "mode": "and",
                    "filters": [
                        {"key": "pattern_type", "values": ["sigma"], "operator": "eq"}
                    ],
                    "filterGroups": []
                }
            )
            
            results = []
            for ind in indicators:
                if not ind.get('pattern'):
                    continue
                
                kill_chain_phases = []
                if ind.get('killChainPhases'):
                    for kcp in ind['killChainPhases']:
                        if isinstance(kcp, dict):
                            kill_chain_phases.append(kcp.get('phase_name', ''))
                
                results.append({
                    'name': ind.get('name'),
                    'sigma_rule': ind.get('pattern'),  # The actual Sigma YAML
                    'valid_from': ind.get('valid_from'),
                    'valid_until': ind.get('valid_until'),
                    'score': ind.get('x_opencti_score', 50),
                    'labels': self._extract_labels(ind),
                    'kill_chain_phases': kill_chain_phases,
                    'opencti_id': ind.get('id'),
                })
            
            logger.info(f"[OpenCTI] Found {len(results)} Sigma indicators")
            return results
            
        except Exception as e:
            logger.error(f"[OpenCTI] Error fetching Sigma indicators: {e}")
            return []
    
    def get_stix_indicators(self, limit: int = 500) -> List[Dict[str, Any]]:
        """
        Get STIX pattern indicators that can be converted to search queries.
        STIX patterns like: [process:name = 'mimikatz.exe']
        
        Args:
            limit: Maximum indicators to retrieve
            
        Returns:
            List of indicator dictionaries with STIX patterns
        """
        if self.init_error or not self.client:
            logger.warning("[OpenCTI] Cannot get STIX indicators: client not initialized")
            return []
        
        try:
            indicators = self.client.indicator.list(
                first=limit,
                filters={
                    "mode": "and",
                    "filters": [
                        {"key": "pattern_type", "values": ["stix"], "operator": "eq"}
                    ],
                    "filterGroups": []
                }
            )
            
            results = []
            for ind in indicators:
                if not ind.get('pattern'):
                    continue
                
                results.append({
                    'name': ind.get('name'),
                    'stix_pattern': ind.get('pattern'),
                    'indicator_types': ind.get('indicator_types', []),
                    'score': ind.get('x_opencti_score', 50),
                    'labels': self._extract_labels(ind),
                    'opencti_id': ind.get('id'),
                })
            
            logger.info(f"[OpenCTI] Found {len(results)} STIX indicators")
            return results
            
        except Exception as e:
            logger.error(f"[OpenCTI] Error fetching STIX indicators: {e}")
            return []
    
    def get_reports_with_attack_context(self, days: int = 90, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Get recent threat reports with attack pattern mappings
        
        Args:
            days: Number of days to look back
            limit: Maximum reports to retrieve
            
        Returns:
            List of report dictionaries with attack context
        """
        if self.init_error or not self.client:
            return []
        
        try:
            from datetime import datetime, timedelta
            
            cutoff = (datetime.utcnow() - timedelta(days=days)).strftime('%Y-%m-%dT%H:%M:%S.000Z')
            
            reports = self.client.report.list(
                first=limit,
                filters={
                    "mode": "and",
                    "filters": [
                        {"key": "published", "values": [cutoff], "operator": "gt"}
                    ],
                    "filterGroups": []
                }
            )
            
            results = []
            for report in reports:
                # Get attack patterns referenced in report
                attack_patterns = []
                try:
                    objects = self.client.stix_core_relationship.list(
                        fromId=report['id'],
                        toTypes=['Attack-Pattern'],
                        first=50
                    )
                    for obj in objects:
                        if obj.get('to'):
                            attack_patterns.append({
                                'name': obj['to'].get('name'),
                                'mitre_id': obj['to'].get('x_mitre_id')
                            })
                except Exception:
                    pass
                
                description = report.get('description', '')
                if len(description) > 500:
                    description = description[:500] + '...'
                
                results.append({
                    'name': report.get('name'),
                    'published': report.get('published'),
                    'description': description,
                    'attack_patterns': attack_patterns,
                    'confidence': report.get('confidence'),
                    'report_types': report.get('report_types', []),
                    'opencti_id': report.get('id'),
                })
            
            logger.info(f"[OpenCTI] Retrieved {len(results)} recent reports")
            return results
            
        except Exception as e:
            logger.error(f"[OpenCTI] Error getting reports: {e}")
            return []


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def get_opencti_client():
    """
    Get an OpenCTI client using current settings
    
    Returns:
        OpenCTIClient instance or None if not configured
    """
    from models.system_settings import SystemSettings, SettingKeys
    
    enabled = SystemSettings.get(SettingKeys.OPENCTI_ENABLED, False)
    if not enabled:
        return None
    
    url = SystemSettings.get(SettingKeys.OPENCTI_URL, '')
    api_key = SystemSettings.get(SettingKeys.OPENCTI_API_KEY, '')
    ssl_verify = SystemSettings.get(SettingKeys.OPENCTI_SSL_VERIFY, False)
    
    if not url or not api_key:
        return None
    
    try:
        return OpenCTIClient(url, api_key, ssl_verify)
    except Exception as e:
        logger.error(f"[OpenCTI] Failed to create client: {e}")
        return None


def enrich_ioc(ioc) -> bool:
    """
    Enrich a single IOC with OpenCTI threat intelligence
    
    Args:
        ioc: IOC model instance
        
    Returns:
        True if enrichment succeeded, False otherwise
    """
    from models.database import db
    from models.system_settings import SystemSettings, SettingKeys
    
    # Skip enrichment for command-line IOCs (environment-specific)
    if ioc.ioc_type.lower() == 'command line':
        logger.debug("[OpenCTI] Enrichment skipped - Command Line IOCs are not enriched")
        return False
    
    client = get_opencti_client()
    if not client:
        logger.debug("[OpenCTI] Enrichment skipped - OpenCTI not configured or disabled")
        return False
    
    try:
        enrichment = client.check_indicator(ioc.value, ioc.ioc_type)
        
        ioc.opencti_enrichment = json.dumps(enrichment)
        ioc.opencti_enriched_at = datetime.utcnow()
        db.session.commit()
        
        logger.info(f"[OpenCTI] IOC enriched: {ioc.value} (Found: {enrichment.get('found', False)})")
        return True
        
    except Exception as e:
        logger.error(f"[OpenCTI] Enrichment failed for {ioc.value}: {e}")
        return False


def enrich_iocs_batch(iocs: List) -> Dict[str, Any]:
    """
    Enrich multiple IOCs with OpenCTI threat intelligence
    
    Args:
        iocs: List of IOC model instances
        
    Returns:
        Dict with results summary
    """
    from models.database import db
    
    client = get_opencti_client()
    if not client:
        return {
            'success': False,
            'error': 'OpenCTI not configured or disabled',
            'enriched_count': 0
        }
    
    enriched = 0
    found = 0
    not_found = 0
    errors = 0
    skipped = 0
    
    for ioc in iocs:
        # Skip command-line IOCs
        if ioc.ioc_type.lower() == 'command line':
            skipped += 1
            continue
        
        try:
            enrichment = client.check_indicator(ioc.value, ioc.ioc_type)
            
            ioc.opencti_enrichment = json.dumps(enrichment)
            ioc.opencti_enriched_at = datetime.utcnow()
            
            if enrichment.get('found'):
                found += 1
            else:
                not_found += 1
            
            enriched += 1
            
        except Exception as e:
            errors += 1
            logger.error(f"[OpenCTI] Error enriching IOC {ioc.value}: {e}")
    
    db.session.commit()
    
    return {
        'success': True,
        'enriched_count': enriched,
        'found_count': found,
        'not_found_count': not_found,
        'error_count': errors,
        'skipped_count': skipped,
        'message': f'Enriched {enriched} IOC(s): {found} found, {not_found} not found'
    }
