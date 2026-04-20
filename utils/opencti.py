#!/usr/bin/env python3
"""
OpenCTI API Client for CaseScope
Handles all communication with OpenCTI for threat intelligence enrichment
"""

import logging
import json
import os
import re
import importlib.util
import time
from typing import Optional, Dict, List, Any
from datetime import datetime

logger = logging.getLogger(__name__)


OPENCTI_ENRICHMENT_SCHEMA_VERSION = 3
THREAT_INTEL_ENRICHMENT_SCHEMA_VERSION = 4

# Persisted OpenCTI enrichment should stay focused on exact, high-signal IOCs.
ENRICHABLE_IOC_TYPES = {
    'IP Address (IPv4)',
    'IP Address (IPv6)',
    'Domain',
    'FQDN',
    'Hostname',
    'URL',
    'MD5 Hash',
    'SHA1 Hash',
    'SHA256 Hash',
    'Imphash',
    'Email Address',
    'X-Originating-IP',
    'Registry Key',
    'Registry Value',
    'SID',
    'Bitcoin Address',
    'Ethereum Address',
    'Monero Address',
}

CONNECTOR_SCOPE_HINTS = {
    'IP Address (IPv4)': {'ipv4-addr'},
    'IP Address (IPv6)': {'ipv6-addr'},
    'X-Originating-IP': {'ipv4-addr'},
    'Domain': {'domain-name'},
    'FQDN': {'domain-name'},
    'Hostname': {'hostname', 'domain-name'},
    'URL': {'url'},
    'MD5 Hash': {'stixfile', 'artifact'},
    'SHA1 Hash': {'stixfile', 'artifact'},
    'SHA256 Hash': {'stixfile', 'artifact'},
    'Imphash': {'stixfile', 'artifact'},
    'File Name': {'stixfile', 'artifact'},
    'File Path': {'stixfile', 'artifact'},
}

THREAT_INTEL_CATEGORY_EXACT = 'exact_ioc_match'
THREAT_INTEL_CATEGORY_THREAT_NAME = 'threat_name_match'
THREAT_INTEL_CATEGORY_MALWARE_FAMILY = 'malware_family_match'
THREAT_INTEL_CATEGORY_DERIVED = 'derived_indicator_match'
THREAT_INTEL_CATEGORY_CONTEXTUAL_TOOL = 'contextual_tool_match'
THREAT_INTEL_CATEGORY_NOT_APPLICABLE = 'not_applicable'
THREAT_INTEL_CATEGORY_NO_MATCH = 'no_match'
THREAT_INTEL_CATEGORY_LOOKUP_ERROR = 'lookup_error'

CONNECTOR_CACHE_TTL_SECONDS = 300

THREAT_NAME_IOC_TYPES = {'Threat Name', 'Malware Family'}
DERIVED_CONTEXT_IOC_TYPES = {
    'File Path',
    'Process Path',
    'Command Line',
    'Service Name',
    'Scheduled Task',
    'Registry Key',
    'Registry Value',
    'File Name',
    'Process Name',
}

GENERIC_THREAT_NAME_TOKENS = {
    'agent', 'apt', 'backdoor', 'behavior', 'dropper', 'family', 'file',
    'generic', 'hacktool', 'injector', 'loader', 'malware', 'msr', 'packer',
    'packed', 'phish', 'potentially', 'program', 'pua', 'ransom', 'ransomware',
    'remote', 'riskware', 'spyware', 'stealer', 'suspicious', 'threat',
    'tool', 'trojan', 'variant', 'virus', 'win32', 'w32',
}

CONTEXTUAL_TOOL_PATTERNS = {
    'AnyDesk': [r'\banydesk\b'],
    'Atera': [r'\batera\b'],
    'Bomgar': [r'\bbomgar\b'],
    'Cobalt Strike': [r'\bcobalt[\s_-]*strike\b'],
    'ConnectWise ScreenConnect': [r'\bscreenconnect\b', r'\bconnectwise\b'],
    'Datto RMM': [r'\bdatto\b', r'\bcentrastage\b'],
    'GoToAssist': [r'\bgotoassist\b'],
    'LogMeIn': [r'\blogmein\b'],
    'NetSupport': [r'\bnetsupport\b'],
    'PDQ Deploy': [r'\bpdq(?:deploy)?\b'],
    'PsExec': [r'\bpsexec(?:svc)?\b', r'\bpsexesvc\b'],
    'SimpleHelp': [r'\bsimplehelp\b'],
    'Splashtop': [r'\bsplashtop\b'],
    'TeamViewer': [r'\bteamviewer\b'],
    'UltraVNC': [r'\bultravnc\b', r'\buvnc\b'],
}


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
            self._connector_catalog = None
            self._connector_catalog_fetched_at = 0.0
            
            # Initialize the official pycti client
            try:
                self.client = OpenCTIApiClient(
                    url=self.url,
                    token=api_key,
                    ssl_verify=ssl_verify,
                    perform_health_check=False,
                )
                if self._perform_health_check():
                    logger.info(f"[OpenCTI] Client initialized: {self.url}")
            except Exception as e:
                self.init_error = self._classify_connection_error(e)
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

    def _classify_connection_error(self, error: Any) -> str:
        """Normalize OpenCTI/pycti errors into user-facing connection messages."""
        error_str = str(error or '')
        lowered = error_str.lower()

        auth_markers = (
            'auth_required',
            'you must be logged in to do this',
            'invalid api key',
            'http_status',
            '401',
        )
        if any(marker in lowered for marker in auth_markers):
            return 'Authentication failed - OpenCTI rejected the API token'

        reachability_markers = (
            'not reachable',
            'waiting for opencti api to start',
            'failed to establish a new connection',
            'max retries exceeded',
            'name or service not known',
            'connection refused',
            'connection aborted',
            'timed out',
        )
        if any(marker in lowered for marker in reachability_markers):
            return 'OpenCTI API is not reachable - Check URL'

        return f'Connection failed: {error_str}'

    def _perform_health_check(self) -> bool:
        """Run a GraphQL health check and preserve the actual auth/network error."""
        if not self.client:
            self.init_error = 'Client not initialized'
            return False

        try:
            response = self.client.query(
                """
                  query healthCheck {
                    about {
                      version
                    }
                  }
                """
            )
            about = (response or {}).get('data', {}).get('about') or {}
            if about.get('version'):
                self.init_error = None
                return True

            self.init_error = 'Connection failed: OpenCTI health check returned no version'
            return False
        except Exception as exc:
            self.init_error = self._classify_connection_error(exc)
            logger.warning(f"[OpenCTI] Health check failed: {exc}")
            return False
    
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
            result = self._perform_health_check()
            if result:
                logger.info("[OpenCTI] Connection successful")
            return result
        except Exception as e:
            logger.error(f"[OpenCTI] Connection failed: {str(e)}")
            return False
    
    def get_error(self) -> Optional[str]:
        """Get initialization error if any"""
        return self.init_error

    # ============================================================================
    # CONNECTOR METADATA
    # ============================================================================

    def _graphql_query(self, query: str) -> Dict[str, Any]:
        """Run a raw GraphQL query against OpenCTI."""
        if not self.client:
            return {}
        try:
            return self.client.query(query) or {}
        except Exception as exc:
            logger.debug(f"[OpenCTI] GraphQL query failed: {exc}")
            return {}

    def _normalize_scope_key(self, value: str) -> str:
        """Normalize connector scope values for case-insensitive matching."""
        return (value or '').strip().lower().replace('_', '-')

    def get_connectors(self, include_inactive: bool = False) -> List[Dict[str, Any]]:
        """Return OpenCTI connector metadata for admin visibility and IOC hints."""
        if self.init_error or not self.client:
            return []

        connector_cache = getattr(self, '_connector_catalog', None)
        connector_cache_fetched_at = float(getattr(self, '_connector_catalog_fetched_at', 0.0) or 0.0)
        cache_is_fresh = (time.time() - connector_cache_fetched_at) < CONNECTOR_CACHE_TTL_SECONDS
        if connector_cache is not None and cache_is_fresh and not include_inactive:
            return list(connector_cache)

        response = self._graphql_query(
            """
              query connectorCatalog {
                connectors {
                  id
                  name
                  active
                  auto
                  connector_type
                  connector_scope
                  only_contextual
                  updated_at
                }
              }
            """
        )
        connectors = (response.get('data') or {}).get('connectors') or []
        normalized = []
        for connector in connectors:
            scopes = [
                self._normalize_scope_key(scope)
                for scope in (connector.get('connector_scope') or [])
                if self._normalize_scope_key(scope) not in {'', 'not-applicable'}
            ]
            item = {
                'id': connector.get('id', ''),
                'name': connector.get('name', ''),
                'active': bool(connector.get('active')),
                'auto': bool(connector.get('auto')),
                'connector_type': connector.get('connector_type', ''),
                'connector_scope': scopes,
                'only_contextual': bool(connector.get('only_contextual')),
                'updated_at': connector.get('updated_at', ''),
            }
            if include_inactive or item['active']:
                normalized.append(item)

        normalized.sort(
            key=lambda item: (
                item.get('connector_type', ''),
                item.get('name', '').lower(),
            )
        )
        if not include_inactive:
            self._connector_catalog = list(normalized)
            self._connector_catalog_fetched_at = time.time()
        return normalized

    def get_connector_status_summary(self) -> Dict[str, Any]:
        """Summarize active connector coverage for admin views."""
        connectors = self.get_connectors(include_inactive=True)
        active = [connector for connector in connectors if connector.get('active')]
        by_type: Dict[str, int] = {}
        for connector in active:
            connector_type = connector.get('connector_type') or 'unknown'
            by_type[connector_type] = by_type.get(connector_type, 0) + 1
        return {
            'total_connectors': len(connectors),
            'active_connectors': len(active),
            'by_type': by_type,
            'connectors': connectors,
        }

    def get_applicable_connectors(self, ioc_type: str) -> List[Dict[str, Any]]:
        """Return active connectors whose scope applies to the IOC type."""
        if self.init_error or not self.client:
            return []

        observable_type = self._map_ioc_type_to_opencti(ioc_type)
        candidate_scopes = {
            self._normalize_scope_key(observable_type),
            self._normalize_scope_key(ioc_type),
        }
        candidate_scopes.update(CONNECTOR_SCOPE_HINTS.get(ioc_type, set()))
        candidate_scopes.discard('')

        matches = []
        for connector in self.get_connectors(include_inactive=False):
            connector_scopes = set(connector.get('connector_scope', []))
            if connector_scopes & candidate_scopes:
                matches.append({
                    'name': connector.get('name', ''),
                    'connector_type': connector.get('connector_type', ''),
                    'auto': bool(connector.get('auto')),
                    'only_contextual': bool(connector.get('only_contextual')),
                    'scopes_matched': sorted(connector_scopes & candidate_scopes),
                })
        return matches
    
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

    def _normalize_lookup_value(self, value: str, ioc_type: str) -> str:
        """Normalize IOC values consistently before exact lookup."""
        try:
            from models.ioc import IOC
            return IOC.normalize_value(value, ioc_type)
        except Exception:
            value = (value or '').strip()
            lowercase_types = {
                'MD5 Hash', 'SHA1 Hash', 'SHA256 Hash', 'Imphash',
                'Domain', 'FQDN', 'URL', 'Hostname', 'Email Address',
                'File Path', 'Process Path'
            }
            return value.lower() if ioc_type in lowercase_types else value

    def _resolve_ioc_type(self, value: str, ioc_type: str) -> str:
        """Infer a concrete IOC type when callers pass Unknown or omit a type."""
        if ioc_type and ioc_type not in ('Unknown', 'Text'):
            return ioc_type

        try:
            from models.ioc import detect_ioc_type_from_value
            detected = detect_ioc_type_from_value(value or '')
            return detected or 'Unknown'
        except Exception:
            return ioc_type or 'Unknown'

    def _is_enrichable_type(self, ioc_type: str) -> bool:
        """Return True when this IOC type is eligible for strict enrichment."""
        return ioc_type in ENRICHABLE_IOC_TYPES

    def _build_base_result(
        self,
        value: str,
        requested_type: str,
        resolved_type: str,
        status: str,
        message: str = '',
        match_source: Optional[str] = None,
        match_category: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Common shape for OpenCTI enrichment responses."""
        return {
            'provider': 'opencti',
            'provider_label': 'OpenCTI',
            'found': False,
            'status': status,
            'message': message,
            'schema_version': OPENCTI_ENRICHMENT_SCHEMA_VERSION,
            'lookup_value': value,
            'lookup_type': requested_type or resolved_type or 'Unknown',
            'resolved_ioc_type': resolved_type or requested_type or 'Unknown',
            'match_source': match_source,
            'match_category': match_category or (
                THREAT_INTEL_CATEGORY_LOOKUP_ERROR if status == 'error'
                else THREAT_INTEL_CATEGORY_NOT_APPLICABLE if status == 'not_applicable'
                else THREAT_INTEL_CATEGORY_NO_MATCH
            ),
            'checked_at': datetime.utcnow().isoformat(),
            'available_connectors': [],
            'connector_count': 0,
            'matched_entities': [],
            'derived_matches': [],
            'derived_indicators': [],
            'contextual_tools': [],
            'labels': [],
            'threat_actors': [],
            'campaigns': [],
            'malware_families': [],
            'external_references': [],
        }

    def _escape_stix_string(self, value: str) -> str:
        """Escape STIX pattern string values."""
        return (value or '').replace('\\', '\\\\').replace("'", "\\'")

    def _build_exact_indicator_patterns(self, value: str, ioc_type: str) -> List[str]:
        """Build exact STIX indicator patterns for supported IOC types."""
        escaped = self._escape_stix_string(value)
        pattern_map = {
            'IP Address (IPv4)': [f"[ipv4-addr:value = '{escaped}']"],
            'IP Address (IPv6)': [f"[ipv6-addr:value = '{escaped}']"],
            'Domain': [f"[domain-name:value = '{escaped}']"],
            'FQDN': [f"[domain-name:value = '{escaped}']"],
            'Hostname': [f"[hostname:value = '{escaped}']"],
            'URL': [f"[url:value = '{escaped}']"],
            'Email Address': [f"[email-addr:value = '{escaped}']"],
            'X-Originating-IP': [f"[ipv4-addr:value = '{escaped}']"],
            'MD5 Hash': [f"[file:hashes.MD5 = '{escaped}']"],
            'SHA1 Hash': [f"[file:hashes.'SHA-1' = '{escaped}']"],
            'SHA256 Hash': [f"[file:hashes.'SHA-256' = '{escaped}']"],
            'Imphash': [f"[file:hashes.IMPHASH = '{escaped}']"],
            'Registry Key': [f"[windows-registry-key:key = '{escaped}']"],
            'Registry Value': [f"[windows-registry-key:values.data = '{escaped}']"],
            'SID': [f"[user-account:user_id = '{escaped}']"],
            'Bitcoin Address': [f"[cryptocurrency-wallet:address = '{escaped}']"],
            'Ethereum Address': [f"[cryptocurrency-wallet:address = '{escaped}']"],
            'Monero Address': [f"[cryptocurrency-wallet:address = '{escaped}']"],
        }
        return pattern_map.get(ioc_type, [])

    def _search_indicator_exact_patterns(self, patterns: List[str]) -> Optional[Dict[str, Any]]:
        """Search for exact STIX indicator pattern matches."""
        for pattern in patterns:
            try:
                indicators = self.client.indicator.list(
                    filters={
                        "mode": "and",
                        "filters": [
                            {"key": "pattern", "values": [pattern], "operator": "eq"}
                        ],
                        "filterGroups": []
                    },
                    first=10
                )
            except Exception as exc:
                logger.debug(f"[OpenCTI] Exact indicator lookup failed for pattern {pattern}: {exc}")
                continue

            if indicators:
                logger.debug("[OpenCTI] Found exact indicator pattern match")
                return {
                    'data': indicators[0],
                    'match_source': 'indicator_exact',
                    'matched_pattern': pattern,
                }

        return None

    def _observable_matches_type(self, observable: Dict[str, Any], observable_type: str) -> bool:
        """Ensure value-based matches also line up with the expected observable type."""
        if not observable_type:
            return True

        entity_type = observable.get('entity_type') or observable.get('entityType')
        if not entity_type:
            return True

        return entity_type == observable_type

    def _search_observable_exact(self, value: str, observable_type: str) -> Optional[Dict[str, Any]]:
        """Search exact observables by value and filter to the expected type."""
        try:
            observables = self.client.stix_cyber_observable.list(
                filters={
                    "mode": "and",
                    "filters": [
                        {"key": "value", "values": [value], "operator": "eq"}
                    ],
                    "filterGroups": []
                },
                first=20
            )
        except Exception as exc:
            logger.debug(f"[OpenCTI] Exact observable lookup failed for {value}: {exc}")
            return None

        for observable in observables or []:
            if self._observable_matches_type(observable, observable_type):
                logger.debug(f"[OpenCTI] Found exact observable match: {value}")
                return {
                    'data': observable,
                    'match_source': 'observable_exact',
                    'matched_pattern': None,
                }

        return None
    
    # ============================================================================
    # INDICATOR ENRICHMENT
    # ============================================================================
    
    def check_indicator(self, ioc_value: str, ioc_type: str, allow_pattern_fallback: bool = False) -> Dict[str, Any]:
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
            result = self._build_base_result(
                ioc_value,
                ioc_type,
                ioc_type or 'Unknown',
                status='error',
                message='OpenCTI client is not available',
            )
            result['error'] = error_msg
            return result
        
        try:
            resolved_type = self._resolve_ioc_type(ioc_value, ioc_type)
            normalized_value = self._normalize_lookup_value(ioc_value, resolved_type)
            available_connectors = self.get_applicable_connectors(resolved_type)

            logger.info(f"[OpenCTI] Checking indicator: {resolved_type}={normalized_value}")

            if not self._is_enrichable_type(resolved_type):
                result = self._build_base_result(
                    normalized_value,
                    ioc_type,
                    resolved_type,
                    status='not_applicable',
                    message=f'{resolved_type} is not eligible for exact OpenCTI enrichment',
                    match_source='not_applicable',
                    match_category=THREAT_INTEL_CATEGORY_NOT_APPLICABLE,
                )
                result['available_connectors'] = available_connectors
                result['connector_count'] = len(available_connectors)
                return result

            opencti_type = self._map_ioc_type_to_opencti(resolved_type)
            result = self._search_indicator(
                normalized_value,
                resolved_type,
                opencti_type,
                allow_pattern_fallback=allow_pattern_fallback,
            )

            if not result:
                logger.info(f"[OpenCTI] Indicator not found: {normalized_value}")
                result = self._build_base_result(
                    normalized_value,
                    ioc_type,
                    resolved_type,
                    status='not_found',
                    message='No exact OpenCTI match found',
                    match_category=THREAT_INTEL_CATEGORY_NO_MATCH,
                )
                result['available_connectors'] = available_connectors
                result['connector_count'] = len(available_connectors)
                return result

            enrichment = self._parse_indicator_data(result['data'])
            enrichment['provider'] = 'opencti'
            enrichment['provider_label'] = 'OpenCTI'
            enrichment['found'] = True
            enrichment['checked_at'] = datetime.utcnow().isoformat()
            enrichment['status'] = 'found'
            enrichment['schema_version'] = OPENCTI_ENRICHMENT_SCHEMA_VERSION
            enrichment['lookup_value'] = normalized_value
            enrichment['lookup_type'] = ioc_type or resolved_type
            enrichment['resolved_ioc_type'] = resolved_type
            enrichment['match_source'] = result.get('match_source')
            enrichment['match_category'] = THREAT_INTEL_CATEGORY_EXACT
            enrichment['matched_pattern'] = result.get('matched_pattern')
            enrichment['available_connectors'] = available_connectors
            enrichment['connector_count'] = len(available_connectors)
            enrichment['matched_entities'] = []
            enrichment['derived_matches'] = []
            enrichment['derived_indicators'] = []
            enrichment['contextual_tools'] = []

            logger.info(f"[OpenCTI] Indicator found: {normalized_value} (Score: {enrichment.get('score', 'N/A')})")
            
            return enrichment
            
        except Exception as e:
            logger.error(f"[OpenCTI] Error checking indicator: {str(e)}")
            resolved_type = self._resolve_ioc_type(ioc_value, ioc_type)
            normalized_value = self._normalize_lookup_value(ioc_value, resolved_type)
            result = self._build_base_result(
                normalized_value,
                ioc_type,
                resolved_type,
                status='error',
                message='OpenCTI lookup failed',
                match_category=THREAT_INTEL_CATEGORY_LOOKUP_ERROR,
            )
            result['error'] = str(e)
            result['available_connectors'] = self.get_applicable_connectors(resolved_type)
            result['connector_count'] = len(result['available_connectors'])
            return result
    
    def _search_indicator(
        self,
        value: str,
        ioc_type: str,
        observable_type: str,
        allow_pattern_fallback: bool = False,
    ) -> Optional[Dict[str, Any]]:
        """
        Search OpenCTI using exact indicator and observable matches.
        """
        try:
            exact_indicator = self._search_indicator_exact_patterns(
                self._build_exact_indicator_patterns(value, ioc_type)
            )
            if exact_indicator:
                return exact_indicator

            exact_observable = self._search_observable_exact(value, observable_type)
            if exact_observable:
                return exact_observable

            if allow_pattern_fallback:
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
                if indicators:
                    logger.debug(f"[OpenCTI] Found fuzzy indicator pattern match: {value}")
                    return {
                        'data': indicators[0],
                        'match_source': 'indicator_pattern_match',
                        'matched_pattern': indicators[0].get('pattern'),
                    }

            return None
            
        except Exception as e:
            logger.warning(f"[OpenCTI] Search failed: {str(e)}")
            return None

    def _normalize_name_key(self, value: str) -> str:
        return re.sub(r'[^a-z0-9]+', '', (value or '').lower())

    def _extract_entity_aliases(self, entity: Dict[str, Any]) -> List[str]:
        aliases = entity.get('aliases') or entity.get('x_opencti_aliases') or []
        if isinstance(aliases, list):
            return [str(alias).strip() for alias in aliases if str(alias).strip()]
        if isinstance(aliases, str) and aliases.strip():
            return [aliases.strip()]
        return []

    def _entity_matches_candidate(self, entity: Dict[str, Any], candidate: str) -> bool:
        candidate_key = self._normalize_name_key(candidate)
        values = [entity.get('name') or entity.get('value') or '']
        values.extend(self._extract_entity_aliases(entity))
        return any(self._normalize_name_key(value) == candidate_key for value in values if value)

    def _iter_search_terms(self, value: str, ioc_type: str) -> List[str]:
        candidates: List[str] = []
        raw_value = (value or '').strip()
        if raw_value:
            candidates.append(raw_value)

        if ioc_type == 'Threat Name':
            split_values = re.split(r'[:/!._\-\s]+', raw_value)
            for token in split_values:
                cleaned = token.strip()
                if len(cleaned) < 4:
                    continue
                if cleaned.lower() in GENERIC_THREAT_NAME_TOKENS:
                    continue
                if cleaned.upper().startswith('MS') and len(cleaned) <= 4:
                    continue
                candidates.append(cleaned)

        unique_candidates: List[str] = []
        seen = set()
        for candidate in candidates:
            key = self._normalize_name_key(candidate)
            if not key or key in seen:
                continue
            seen.add(key)
            unique_candidates.append(candidate)
        return unique_candidates[:6]

    def _list_malware_entities(self, search_value: str) -> List[Dict[str, Any]]:
        malware_api = getattr(self.client, 'malware', None)
        if not malware_api or not hasattr(malware_api, 'list'):
            return []

        try:
            results = malware_api.list(search=search_value, first=20)
        except TypeError:
            results = malware_api.list(first=20)
        except Exception as exc:
            logger.debug(f"[OpenCTI] Malware entity search failed for {search_value}: {exc}")
            return []

        if isinstance(results, list):
            return results
        return []

    def _parse_entity_data(self, data: Dict[str, Any], match_category: str) -> Dict[str, Any]:
        entity_name = data.get('name') or data.get('value', 'Unknown')
        enrichment = {
            'name': entity_name,
            'description': data.get('description', ''),
            'score': self._calculate_score(data),
            'labels': self._extract_labels(data),
            'threat_actors': self._extract_related_entities(data, 'Threat-Actor'),
            'campaigns': self._extract_related_entities(data, 'Campaign'),
            'malware_families': [entity_name] if match_category == THREAT_INTEL_CATEGORY_MALWARE_FAMILY else self._extract_related_entities(data, 'Malware'),
            'created_at': data.get('created_at', ''),
            'updated_at': data.get('updated_at', ''),
            'tlp': self._extract_tlp(data),
            'confidence': data.get('confidence', 0),
            'external_references': self._extract_external_references(data),
            'matched_entities': [{
                'name': entity_name,
                'entity_type': data.get('entity_type') or data.get('entityType') or 'Malware',
                'aliases': self._extract_entity_aliases(data),
                'description': data.get('description', ''),
            }],
        }
        return enrichment

    def check_threat_name(self, ioc_value: str, ioc_type: str) -> Dict[str, Any]:
        """Search malware entities by exact name or alias for threat-name style IOC values."""
        if self.init_error or not self.client:
            error_msg = self.init_error or "Client not initialized"
            result = self._build_base_result(
                ioc_value,
                ioc_type,
                ioc_type or 'Unknown',
                status='error',
                message='OpenCTI client is not available',
                match_category=THREAT_INTEL_CATEGORY_LOOKUP_ERROR,
            )
            result['error'] = error_msg
            return result

        resolved_type = ioc_type or 'Unknown'
        if resolved_type not in THREAT_NAME_IOC_TYPES:
            return self._build_base_result(
                ioc_value,
                ioc_type,
                resolved_type,
                status='not_applicable',
                message=f'{resolved_type} is not eligible for OpenCTI entity-name enrichment',
                match_source='not_applicable',
                match_category=THREAT_INTEL_CATEGORY_NOT_APPLICABLE,
            )

        candidates = self._iter_search_terms(ioc_value, resolved_type)
        match_category = (
            THREAT_INTEL_CATEGORY_MALWARE_FAMILY
            if resolved_type == 'Malware Family'
            else THREAT_INTEL_CATEGORY_THREAT_NAME
        )

        try:
            for candidate in candidates:
                for entity in self._list_malware_entities(candidate):
                    if not self._entity_matches_candidate(entity, candidate):
                        continue

                    enrichment = self._parse_entity_data(entity, match_category)
                    enrichment.update({
                        'provider': 'opencti',
                        'provider_label': 'OpenCTI',
                        'found': True,
                        'status': 'found',
                        'schema_version': OPENCTI_ENRICHMENT_SCHEMA_VERSION,
                        'lookup_value': ioc_value,
                        'lookup_type': ioc_type or resolved_type,
                        'resolved_ioc_type': resolved_type,
                        'match_source': 'opencti_malware_name',
                        'match_category': match_category,
                        'checked_at': datetime.utcnow().isoformat(),
                        'available_connectors': [],
                        'connector_count': 0,
                        'matched_name': candidate,
                    })
                    return enrichment

            return self._build_base_result(
                ioc_value,
                ioc_type,
                resolved_type,
                status='not_found',
                message='No OpenCTI entity-name match found',
                match_source='opencti_malware_name',
                match_category=THREAT_INTEL_CATEGORY_NO_MATCH,
            )
        except Exception as exc:
            logger.error(f"[OpenCTI] Error checking threat name {ioc_value}: {exc}")
            result = self._build_base_result(
                ioc_value,
                ioc_type,
                resolved_type,
                status='error',
                message='OpenCTI entity-name lookup failed',
                match_source='opencti_malware_name',
                match_category=THREAT_INTEL_CATEGORY_LOOKUP_ERROR,
            )
            result['error'] = str(exc)
            return result
    
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
            'indicator_types': data.get('indicator_types', []),
            'external_references': self._extract_external_references(data),
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

    def _extract_external_references(self, data: Dict) -> List[Dict[str, str]]:
        """Extract a compact list of external references for UI display."""
        references = []
        raw_refs = (
            data.get('externalReferences')
            or data.get('external_references')
            or data.get('external_references_refs')
            or []
        )
        if isinstance(raw_refs, dict) and 'edges' in raw_refs:
            raw_refs = [edge.get('node', {}) for edge in raw_refs.get('edges', [])]

        for ref in raw_refs:
            if not isinstance(ref, dict):
                continue
            references.append({
                'source_name': ref.get('source_name', ''),
                'url': ref.get('url', ''),
                'description': ref.get('description', ''),
            })
        return references[:5]
    
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

    def get_vulnerabilities_by_cve(self, cve_ids: List[str], limit: int = 10) -> List[Dict[str, Any]]:
        """Get vulnerability intelligence for CVE identifiers when available."""
        if self.init_error or not self.client or not cve_ids:
            return []

        results = []
        for cve_id in sorted({(cve or '').strip().upper() for cve in cve_ids if cve}):
            if not cve_id:
                continue
            try:
                vulnerabilities = self.client.vulnerability.list(
                    filters={
                        "mode": "and",
                        "filters": [
                            {"key": "name", "values": [cve_id], "operator": "eq"}
                        ],
                        "filterGroups": []
                    },
                    first=1
                )
                if not vulnerabilities:
                    continue

                vulnerability = vulnerabilities[0]
                results.append({
                    'name': vulnerability.get('name', cve_id),
                    'description': (vulnerability.get('description') or '')[:300],
                    'base_score': (
                        vulnerability.get('x_opencti_cvss_base_score')
                        or vulnerability.get('cvss_base_score')
                        or vulnerability.get('base_score')
                    ),
                    'labels': self._extract_labels(vulnerability),
                    'external_references': self._extract_external_references(vulnerability),
                })
                if len(results) >= limit:
                    break
            except Exception as exc:
                logger.debug(f"[OpenCTI] Vulnerability lookup failed for {cve_id}: {exc}")
                continue
        return results


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def get_opencti_client():
    """
    Get an OpenCTI client using current settings
    
    Returns:
        OpenCTIClient instance or None if not configured
    """
    from models.system_settings import (
        SystemSettings,
        SettingKeys,
        get_opencti_api_key,
    )
    from utils.licensing.license_manager import LicenseManager

    if not LicenseManager.is_feature_activated('opencti'):
        return None

    enabled = SystemSettings.get(SettingKeys.OPENCTI_ENABLED, False)
    if not enabled:
        return None
    
    url = SystemSettings.get(SettingKeys.OPENCTI_URL, '')
    api_key = get_opencti_api_key(log_errors=True)
    ssl_verify = SystemSettings.get(SettingKeys.OPENCTI_SSL_VERIFY, False)
    
    if not url or not api_key:
        return None
    
    try:
        return OpenCTIClient(url, api_key, ssl_verify)
    except Exception as e:
        logger.error(f"[OpenCTI] Failed to create client: {e}")
        return None


def is_opencti_auto_enrich_enabled() -> bool:
    """Return True when IOC auto-enrichment should run."""
    from models.system_settings import SystemSettings, SettingKeys
    from utils.licensing.license_manager import LicenseManager

    if not LicenseManager.is_feature_activated('opencti'):
        return False

    return (
        SystemSettings.get(SettingKeys.OPENCTI_ENABLED, False)
        and SystemSettings.get(SettingKeys.OPENCTI_AUTO_ENRICH, False)
    )


def _get_enabled_threat_intel_clients() -> Dict[str, Any]:
    """Return active threat-intel clients keyed by provider name."""
    clients: Dict[str, Any] = {}

    opencti_client = get_opencti_client()
    if opencti_client:
        clients['opencti'] = opencti_client

    try:
        from utils.misp import get_misp_client
        misp_client = get_misp_client()
        if misp_client:
            clients['misp'] = misp_client
    except Exception as exc:
        logger.warning(f"[ThreatIntel] Failed to initialize MISP client: {exc}")

    return clients


def is_threat_intel_auto_enrich_enabled() -> bool:
    """Return True when any enabled threat-intel provider should auto-enrich."""
    try:
        from utils.misp import is_misp_auto_enrich_enabled
    except Exception:
        is_misp_auto_enrich_enabled = lambda: False

    return is_opencti_auto_enrich_enabled() or is_misp_auto_enrich_enabled()


def _tlp_rank(value: str) -> int:
    mapping = {
        'TLP:CLEAR': 0,
        'TLP:GREEN': 1,
        'TLP:AMBER': 2,
        'TLP:AMBER+STRICT': 3,
        'TLP:RED': 4,
    }
    return mapping.get((value or '').upper(), 0)


def _merge_tlp(values: List[str]) -> str:
    candidates = [value for value in values if value]
    if not candidates:
        return 'TLP:CLEAR'
    return max(candidates, key=_tlp_rank)


def _collect_unique_strings(values: List[Any], limit: int = 20) -> List[str]:
    seen = set()
    results: List[str] = []
    for value in values:
        if not value:
            continue
        normalized = str(value).strip()
        key = normalized.lower()
        if not normalized or key in seen:
            continue
        seen.add(key)
        results.append(normalized)
        if len(results) >= limit:
            break
    return results


def _collect_unique_dicts(items: List[Dict[str, Any]], key_fields: List[str], limit: int = 20) -> List[Dict[str, Any]]:
    seen = set()
    results: List[Dict[str, Any]] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        key = tuple(str(item.get(field, '')).strip().lower() for field in key_fields)
        if not any(key):
            continue
        if key in seen:
            continue
        seen.add(key)
        results.append(item)
        if len(results) >= limit:
            break
    return results


def _merge_external_references(provider_results: Dict[str, Dict[str, Any]]) -> List[Dict[str, str]]:
    seen = set()
    merged: List[Dict[str, str]] = []
    for result in provider_results.values():
        for reference in result.get('external_references', []) or []:
            if not isinstance(reference, dict):
                continue
            key = (
                reference.get('source_name', ''),
                reference.get('url', ''),
                reference.get('description', ''),
            )
            if key in seen:
                continue
            seen.add(key)
            merged.append({
                'source_name': reference.get('source_name', ''),
                'url': reference.get('url', ''),
                'description': reference.get('description', ''),
            })
            if len(merged) >= 8:
                return merged
    return merged


def _build_provider_error_result(provider: str, ioc_value: str, ioc_type: str, exc: Exception) -> Dict[str, Any]:
    provider_label = 'OpenCTI' if provider == 'opencti' else 'MISP' if provider == 'misp' else provider.upper()
    return {
        'provider': provider,
        'provider_label': provider_label,
        'found': False,
        'status': 'error',
        'message': f'{provider_label} lookup failed',
        'error': str(exc),
        'checked_at': datetime.utcnow().isoformat(),
        'lookup_value': ioc_value,
        'lookup_type': ioc_type or 'Unknown',
        'resolved_ioc_type': ioc_type or 'Unknown',
        'match_category': THREAT_INTEL_CATEGORY_LOOKUP_ERROR,
        'matched_entities': [],
        'derived_matches': [],
        'derived_indicators': [],
        'contextual_tools': [],
        'labels': [],
        'threat_actors': [],
        'campaigns': [],
        'malware_families': [],
        'external_references': [],
        'available_connectors': [],
        'connector_count': 0,
    }


def _get_result_priority(match_category: str) -> int:
    priorities = {
        THREAT_INTEL_CATEGORY_EXACT: 5,
        THREAT_INTEL_CATEGORY_DERIVED: 4,
        THREAT_INTEL_CATEGORY_MALWARE_FAMILY: 3,
        THREAT_INTEL_CATEGORY_THREAT_NAME: 2,
        THREAT_INTEL_CATEGORY_CONTEXTUAL_TOOL: 1,
    }
    return priorities.get(match_category or '', 0)


def _select_primary_match_category(found_results: List[Dict[str, Any]], contextual_tools: List[Dict[str, Any]]) -> str:
    if found_results:
        return max(
            [result.get('match_category') for result in found_results],
            key=_get_result_priority,
        )
    if contextual_tools:
        return THREAT_INTEL_CATEGORY_CONTEXTUAL_TOOL
    return THREAT_INTEL_CATEGORY_NO_MATCH


def _extract_contextual_tools(values: List[str]) -> List[Dict[str, Any]]:
    matches: List[Dict[str, Any]] = []
    for value in values:
        if not isinstance(value, str) or not value.strip():
            continue
        lowered = value.lower()
        for tool_name, patterns in CONTEXTUAL_TOOL_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, lowered, re.IGNORECASE):
                    matches.append({
                        'tool_name': tool_name,
                        'source_value': value[:300],
                        'match_pattern': pattern,
                    })
                    break
    return _collect_unique_dicts(matches, ['tool_name', 'source_value'], limit=12)


def _load_ioc_boundary_helper():
    """Load the canonical IOC derived-indicator helper.

    Prefer the package import in the full application, but keep a direct
    file-load path for isolated contexts that cannot import the full
    `utils` package tree.
    """
    try:
        from utils.ioc_extractor import extract_derived_indicator_candidates

        return extract_derived_indicator_candidates
    except Exception:
        try:
            module_path = os.path.join(os.path.dirname(__file__), 'ioc_extractor.py')
            spec = importlib.util.spec_from_file_location('ioc_extractor_canonical', module_path)
            ioc_extractor = importlib.util.module_from_spec(spec)
            assert spec.loader is not None
            spec.loader.exec_module(ioc_extractor)
            return ioc_extractor.extract_derived_indicator_candidates
        except Exception:
            return None


def _extract_derived_indicator_candidates(ioc_value: str, context_values: Optional[List[str]] = None) -> List[Dict[str, str]]:
    helper = _load_ioc_boundary_helper()
    if helper is None:
        return []

    return helper(
        ioc_value,
        context_values=context_values,
    )


def _build_derived_provider_result(
    provider: str,
    client: Any,
    ioc_value: str,
    ioc_type: str,
    derived_indicators: List[Dict[str, str]],
) -> Dict[str, Any]:
    provider_label = 'OpenCTI' if provider == 'opencti' else 'MISP'
    hits: List[Dict[str, Any]] = []
    statuses: List[str] = []
    available_connectors: List[Dict[str, Any]] = []

    for indicator in derived_indicators:
        result = client.check_indicator(indicator['extracted_value'], indicator['extracted_type'])
        statuses.append(result.get('status'))
        available_connectors.extend(result.get('available_connectors', []) or [])
        if not result.get('found'):
            continue

        hits.append({
            'provider': provider,
            'provider_label': provider_label,
            'source_value': indicator['source_value'],
            'source_type': ioc_type,
            'extracted_value': indicator['extracted_value'],
            'extracted_type': indicator['extracted_type'],
            'score': result.get('score', 0),
            'tlp': result.get('tlp'),
            'match_source': result.get('match_source'),
            'description': result.get('description', ''),
            'labels': result.get('labels', []),
            'malware_families': result.get('malware_families', []),
            'threat_actors': result.get('threat_actors', []),
            'campaigns': result.get('campaigns', []),
            'external_references': result.get('external_references', []),
        })

    base = {
        'provider': provider,
        'provider_label': provider_label,
        'found': bool(hits),
        'status': 'found' if hits else (
            'error' if any(status == 'error' for status in statuses)
            else 'not_found' if derived_indicators
            else 'not_applicable'
        ),
        'message': 'Derived indicator matches found' if hits else (
            'No derived indicators extracted for threat-intel enrichment'
            if not derived_indicators else 'No provider matches for derived indicators'
        ),
        'schema_version': THREAT_INTEL_ENRICHMENT_SCHEMA_VERSION,
        'lookup_value': ioc_value,
        'lookup_type': ioc_type or 'Unknown',
        'resolved_ioc_type': ioc_type or 'Unknown',
        'checked_at': datetime.utcnow().isoformat(),
        'match_source': f'{provider}_derived_exact',
        'match_category': THREAT_INTEL_CATEGORY_DERIVED if hits else (
            THREAT_INTEL_CATEGORY_NOT_APPLICABLE if not derived_indicators
            else THREAT_INTEL_CATEGORY_NO_MATCH
        ),
        'available_connectors': available_connectors,
        'connector_count': len({
            connector.get('name', '')
            for connector in available_connectors
            if isinstance(connector, dict) and connector.get('name')
        }),
        'matched_entities': [],
        'derived_matches': hits,
        'derived_indicators': derived_indicators,
        'contextual_tools': [],
        'labels': _collect_unique_strings([
            label
            for hit in hits
            for label in (hit.get('labels') or [])
        ], limit=20),
        'threat_actors': _collect_unique_strings([
            actor
            for hit in hits
            for actor in (hit.get('threat_actors') or [])
        ], limit=12),
        'campaigns': _collect_unique_strings([
            campaign
            for hit in hits
            for campaign in (hit.get('campaigns') or [])
        ], limit=12),
        'malware_families': _collect_unique_strings([
            family
            for hit in hits
            for family in (hit.get('malware_families') or [])
        ], limit=12),
        'external_references': _collect_unique_dicts([
            reference
            for hit in hits
            for reference in (hit.get('external_references') or [])
            if isinstance(reference, dict)
        ], ['source_name', 'url', 'description'], limit=8),
        'score': max([hit.get('score', 0) for hit in hits], default=0),
        'tlp': _merge_tlp([hit.get('tlp') for hit in hits]),
        'description': next((hit.get('description') for hit in hits if hit.get('description')), ''),
    }
    return base


def merge_threat_intel_results(
    ioc_value: str,
    ioc_type: str,
    provider_results: Dict[str, Dict[str, Any]],
    lookup_path: str = 'exact',
    contextual_tools: Optional[List[Dict[str, Any]]] = None,
    derived_indicators: Optional[List[Dict[str, str]]] = None,
) -> Dict[str, Any]:
    """Merge provider-specific enrichment into one persisted threat-intel shape."""
    contextual_tools = contextual_tools or []
    derived_indicators = derived_indicators or []
    checked_providers = list(provider_results.keys())
    found_results = [
        result for result in provider_results.values()
        if isinstance(result, dict) and result.get('found')
    ]
    statuses = [result.get('status') for result in provider_results.values() if isinstance(result, dict)]

    if found_results or contextual_tools:
        status = 'found'
    elif checked_providers and all(status == 'not_applicable' for status in statuses):
        status = 'not_applicable'
    elif any(status == 'error' for status in statuses):
        status = 'error'
    else:
        status = 'not_found'

    primary_category = _select_primary_match_category(found_results, contextual_tools)
    category_values = [
        result.get('match_category')
        for result in found_results
        if result.get('match_category')
    ]
    if contextual_tools:
        category_values.append(THREAT_INTEL_CATEGORY_CONTEXTUAL_TOOL)
    match_categories = _collect_unique_strings(category_values or [primary_category], limit=8)

    available_connectors = []
    for result in provider_results.values():
        available_connectors.extend(result.get('available_connectors', []) or [])
    connector_names = {
        connector.get('name', '')
        for connector in available_connectors
        if isinstance(connector, dict) and connector.get('name')
    }

    merged = {
        'found': bool(found_results or contextual_tools),
        'status': status,
        'schema_version': THREAT_INTEL_ENRICHMENT_SCHEMA_VERSION,
        'lookup_value': ioc_value,
        'lookup_type': ioc_type,
        'lookup_path': lookup_path,
        'resolved_ioc_type': next(
            (result.get('resolved_ioc_type') for result in found_results if result.get('resolved_ioc_type')),
            next((result.get('resolved_ioc_type') for result in provider_results.values() if result.get('resolved_ioc_type')), ioc_type or 'Unknown')
        ),
        'checked_at': datetime.utcnow().isoformat(),
        'providers_checked': checked_providers,
        'providers_found': [
            provider for provider, result in provider_results.items()
            if isinstance(result, dict) and result.get('found')
        ],
        'provider_results': provider_results,
        'score': max([result.get('score', 0) for result in found_results], default=35 if contextual_tools else 0),
        'tlp': _merge_tlp([result.get('tlp') for result in found_results]),
        'labels': _collect_unique_strings([
            label
            for result in found_results
            for label in (result.get('labels') or [])
        ], limit=20),
        'threat_actors': _collect_unique_strings([
            actor
            for result in found_results
            for actor in (result.get('threat_actors') or [])
        ], limit=12),
        'campaigns': _collect_unique_strings([
            campaign
            for result in found_results
            for campaign in (result.get('campaigns') or [])
        ], limit=12),
        'malware_families': _collect_unique_strings([
            family
            for result in found_results
            for family in (result.get('malware_families') or [])
        ], limit=12),
        'description': next((result.get('description') for result in found_results if result.get('description')), ''),
        'external_references': _merge_external_references(provider_results),
        'available_connectors': available_connectors,
        'connector_count': len(connector_names),
        'match_category': primary_category,
        'match_categories': match_categories,
        'matched_entities': _collect_unique_dicts([
            dict(entity, provider=result.get('provider'), provider_label=result.get('provider_label'))
            for result in found_results
            for entity in (result.get('matched_entities') or [])
            if isinstance(entity, dict)
        ], ['provider', 'name', 'entity_type'], limit=12),
        'derived_matches': _collect_unique_dicts([
            hit
            for result in found_results
            for hit in (result.get('derived_matches') or [])
            if isinstance(hit, dict)
        ], ['provider', 'extracted_value', 'extracted_type', 'source_value'], limit=20),
        'derived_indicators': _collect_unique_dicts(derived_indicators, ['extracted_value', 'extracted_type'], limit=20),
        'contextual_tools': contextual_tools,
        'match_source': 'multi_source_exact' if len(found_results) > 1 and primary_category == THREAT_INTEL_CATEGORY_EXACT else (
            found_results[0].get('match_source') if found_results else next(
                (result.get('match_source') for result in provider_results.values() if result.get('match_source')),
                'local_contextual_tool' if contextual_tools else None,
            )
        ),
    }

    if not merged['found']:
        merged['message'] = next(
            (result.get('message') for result in provider_results.values() if result.get('message')),
            'No threat intelligence match found',
        )
    elif not found_results and contextual_tools:
        merged['message'] = 'Matched contextual tooling from artifact content'
    return merged


def _check_ioc_with_active_providers(
    ioc_value: str,
    ioc_type: str,
    context_values: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Query all active threat-intel providers and merge their results."""
    clients = _get_enabled_threat_intel_clients()
    provider_results: Dict[str, Dict[str, Any]] = {}
    lookup_path = 'exact'
    contextual_tools = _extract_contextual_tools([ioc_value] + list(context_values or []))
    derived_indicators: List[Dict[str, str]] = []

    if ioc_type in THREAT_NAME_IOC_TYPES:
        lookup_path = 'name'
        for provider, client in clients.items():
            try:
                provider_results[provider] = client.check_threat_name(ioc_value, ioc_type)
            except Exception as exc:
                logger.warning(f"[ThreatIntel] {provider} threat-name lookup failed for {ioc_value}: {exc}")
                provider_results[provider] = _build_provider_error_result(provider, ioc_value, ioc_type, exc)
        return merge_threat_intel_results(
            ioc_value,
            ioc_type,
            provider_results,
            lookup_path=lookup_path,
            contextual_tools=contextual_tools,
        )

    for provider, client in clients.items():
        try:
            provider_results[provider] = client.check_indicator(ioc_value, ioc_type)
        except Exception as exc:
            logger.warning(f"[ThreatIntel] {provider} lookup failed for {ioc_value}: {exc}")
            provider_results[provider] = _build_provider_error_result(provider, ioc_value, ioc_type, exc)

    if any(result.get('found') for result in provider_results.values()):
        return merge_threat_intel_results(
            ioc_value,
            ioc_type,
            provider_results,
            lookup_path=lookup_path,
            contextual_tools=contextual_tools,
        )

    if ioc_type in DERIVED_CONTEXT_IOC_TYPES or context_values:
        lookup_path = 'derived'
        derived_indicators = _extract_derived_indicator_candidates(ioc_value, context_values)
        provider_results = {}
        for provider, client in clients.items():
            try:
                provider_results[provider] = _build_derived_provider_result(
                    provider,
                    client,
                    ioc_value,
                    ioc_type,
                    derived_indicators,
                )
            except Exception as exc:
                logger.warning(f"[ThreatIntel] {provider} derived lookup failed for {ioc_value}: {exc}")
                provider_results[provider] = _build_provider_error_result(provider, ioc_value, ioc_type, exc)

    return merge_threat_intel_results(
        ioc_value,
        ioc_type,
        provider_results,
        lookup_path=lookup_path,
        contextual_tools=contextual_tools,
        derived_indicators=derived_indicators,
    )


def lookup_threat_intel(
    ioc_value: str,
    ioc_type: str,
    context_values: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Public helper for threat-intel enrichment outside IOC persistence flows."""
    return _check_ioc_with_active_providers(ioc_value, ioc_type, context_values=context_values)


def maybe_auto_enrich_ioc(ioc) -> Dict[str, Any]:
    """Best-effort auto-enrich a single IOC without breaking the caller."""
    if not is_threat_intel_auto_enrich_enabled():
        return {'attempted': False, 'reason': 'auto_enrich_disabled'}

    try:
        success = enrich_ioc(ioc)
        return {'attempted': True, 'success': success}
    except Exception as exc:
        logger.warning(f"[OpenCTI] Auto-enrich skipped for {getattr(ioc, 'value', '?')}: {exc}")
        return {'attempted': True, 'success': False, 'error': str(exc)}


def maybe_auto_enrich_iocs(iocs: List) -> Dict[str, Any]:
    """Best-effort auto-enrich a batch of IOCs without breaking the caller."""
    if not iocs:
        return {'attempted': False, 'reason': 'no_iocs'}

    if not is_threat_intel_auto_enrich_enabled():
        return {'attempted': False, 'reason': 'auto_enrich_disabled'}

    try:
        result = enrich_iocs_batch(iocs)
        result['attempted'] = True
        return result
    except Exception as exc:
        logger.warning(f"[OpenCTI] Batch auto-enrich skipped: {exc}")
        return {'attempted': True, 'success': False, 'error': str(exc)}


def is_ioc_type_enrichable(ioc_type: str, value: str = '') -> bool:
    """Check whether an IOC type is eligible for strict persisted enrichment."""
    resolved_type = ioc_type or 'Unknown'
    if resolved_type in ('Unknown', 'Text') and value:
        try:
            from models.ioc import detect_ioc_type_from_value
            resolved_type = detect_ioc_type_from_value(value) or resolved_type
        except Exception:
            pass
    return resolved_type in ENRICHABLE_IOC_TYPES


def is_legacy_unverified_enrichment(enrichment: Optional[Dict[str, Any]]) -> bool:
    """Return True when a stored positive enrichment predates exact-match provenance."""
    if not isinstance(enrichment, dict):
        return False
    if not enrichment.get('found'):
        return False
    schema_version = enrichment.get('schema_version')
    return not schema_version or schema_version < OPENCTI_ENRICHMENT_SCHEMA_VERSION


def _get_ioc_context_values(ioc: Any) -> List[str]:
    values: List[str] = []
    aliases = getattr(ioc, 'aliases', None) or []
    if isinstance(aliases, list):
        values.extend([alias for alias in aliases if isinstance(alias, str)])
    notes = getattr(ioc, 'notes', None)
    if isinstance(notes, str) and notes.strip():
        values.append(notes)
    return values[:10]


def enrich_ioc(ioc) -> bool:
    """
    Enrich a single IOC with OpenCTI threat intelligence
    
    Args:
        ioc: IOC model instance
        
    Returns:
        True if enrichment succeeded, False otherwise
    """
    from models.database import db
    
    if not _get_enabled_threat_intel_clients():
        logger.debug("[ThreatIntel] Enrichment skipped - no active providers configured")
        return False
    
    try:
        enrichment = _check_ioc_with_active_providers(
            ioc.value,
            ioc.ioc_type,
            context_values=_get_ioc_context_values(ioc),
        )
        
        ioc.opencti_enrichment = json.dumps(enrichment)
        ioc.opencti_enriched_at = datetime.utcnow()
        db.session.commit()
        
        logger.info(
            "[ThreatIntel] IOC enriched: %s (Found: %s, Providers: %s)",
            ioc.value,
            enrichment.get('found', False),
            ', '.join(enrichment.get('providers_checked', [])) or 'none',
        )
        return True
        
    except Exception as e:
        logger.error(f"[ThreatIntel] Enrichment failed for {ioc.value}: {e}")
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
    
    if not _get_enabled_threat_intel_clients():
        return {
            'success': False,
            'error': 'No threat intelligence provider is active or configured',
            'enriched_count': 0
        }
    
    enriched = 0
    found = 0
    not_found = 0
    not_applicable = 0
    errors = 0
    legacy_revalidated = 0
    available_connectors = set()
    providers_checked = set()
    match_category_counts = {
        THREAT_INTEL_CATEGORY_EXACT: 0,
        THREAT_INTEL_CATEGORY_THREAT_NAME: 0,
        THREAT_INTEL_CATEGORY_MALWARE_FAMILY: 0,
        THREAT_INTEL_CATEGORY_DERIVED: 0,
        THREAT_INTEL_CATEGORY_CONTEXTUAL_TOOL: 0,
        THREAT_INTEL_CATEGORY_NOT_APPLICABLE: 0,
        THREAT_INTEL_CATEGORY_NO_MATCH: 0,
        THREAT_INTEL_CATEGORY_LOOKUP_ERROR: 0,
    }
    
    for ioc in iocs:
        try:
            previous_enrichment = None
            if ioc.opencti_enrichment:
                try:
                    previous_enrichment = json.loads(ioc.opencti_enrichment)
                except (TypeError, json.JSONDecodeError):
                    previous_enrichment = None

            enrichment = _check_ioc_with_active_providers(
                ioc.value,
                ioc.ioc_type,
                context_values=_get_ioc_context_values(ioc),
            )
            providers_checked.update(enrichment.get('providers_checked', []))
            
            ioc.opencti_enrichment = json.dumps(enrichment)
            ioc.opencti_enriched_at = datetime.utcnow()

            if is_legacy_unverified_enrichment(previous_enrichment):
                legacy_revalidated += 1

            for connector in enrichment.get('available_connectors', []):
                connector_name = connector.get('name')
                if connector_name:
                    available_connectors.add(connector_name)

            match_category = enrichment.get('match_category')
            if match_category in match_category_counts:
                match_category_counts[match_category] += 1
            
            if enrichment.get('found'):
                found += 1
            elif enrichment.get('status') == 'not_applicable':
                not_applicable += 1
            else:
                not_found += 1
            
            enriched += 1
            
        except Exception as e:
            errors += 1
            logger.error(f"[ThreatIntel] Error enriching IOC {ioc.value}: {e}")
    
    db.session.commit()
    
    return {
        'success': True,
        'enriched_count': enriched,
        'found_count': found,
        'not_found_count': not_found,
        'not_applicable_count': not_applicable,
        'error_count': errors,
        'legacy_revalidated_count': legacy_revalidated,
        'skipped_count': 0,
        'available_connector_count': len(available_connectors),
        'available_connectors': sorted(available_connectors),
        'providers_checked': sorted(providers_checked),
        'match_category_counts': match_category_counts,
        'message': (
            f'Enriched {enriched} IOC(s): {found} match(es), '
            f'{not_found} no match, {not_applicable} not applicable'
        )
    }
