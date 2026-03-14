"""OpenCTI Context Provider for CaseScope Enhanced Analysis System

Provides threat intelligence context from OpenCTI for analysis enrichment.
Caches responses to avoid repeated API calls during analysis runs.
Gracefully handles OpenCTI being unavailable.
"""

import logging
import hashlib
import json
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional

from models.database import db
from models.behavioral_profiles import OpenCTICache
from config import Config

logger = logging.getLogger(__name__)


class OpenCTIContextProvider:
    """
    Provides threat intelligence context from OpenCTI.
    
    Caches responses to avoid repeated API calls during analysis.
    Gracefully handles OpenCTI being unavailable.
    """
    
    def __init__(self, case_id: int, analysis_id: str = None):
        """
        Args:
            case_id: Used for caching context to case
            analysis_id: Optional analysis run ID for cache management
        """
        self.case_id = case_id
        self.analysis_id = analysis_id
        self._client = None
        self._client_checked = False
        self._available = None
        self._ioc_cache_version = 2
        
        # Cache TTL - use config or default to 24 hours
        self.cache_ttl_hours = getattr(Config, 'OPENCTI_CACHE_TTL_HOURS', 24)
    
    def _get_client(self):
        """Lazy-load OpenCTI client"""
        if not self._client_checked:
            self._client_checked = True
            try:
                from utils.opencti import get_opencti_client
                self._client = get_opencti_client()
            except Exception as e:
                logger.warning(f"[OpenCTI Context] Failed to get client: {e}")
                self._client = None
        return self._client
    
    def is_available(self) -> bool:
        """
        Check if OpenCTI is licensed, enabled, and connected.
        
        Returns:
            bool: True if OpenCTI can be used
        """
        if self._available is not None:
            return self._available
        
        # Check license activation first
        try:
            from utils.feature_availability import FeatureAvailability
            if not FeatureAvailability.is_activated('opencti'):
                self._available = False
                return False
        except Exception:
            pass
        
        # Check config
        if not getattr(Config, 'OPENCTI_ENABLED', False):
            self._available = False
            return False
        
        # Check system settings
        try:
            from models.system_settings import SystemSettings, SettingKeys
            if not SystemSettings.get(SettingKeys.OPENCTI_ENABLED, False):
                self._available = False
                return False
        except Exception:
            pass  # System settings may not exist
        
        # Check client connectivity
        client = self._get_client()
        if not client:
            self._available = False
            return False
        
        try:
            self._available = client.ping()
        except Exception:
            self._available = False
        
        return self._available
    
    def clear_cache(self):
        """Clear cache for this case (called at start of new analysis)"""
        try:
            OpenCTICache.query.filter_by(case_id=self.case_id).delete()
            db.session.commit()
            logger.info(f"[OpenCTI Context] Cleared cache for case {self.case_id}")
        except Exception as e:
            logger.warning(f"[OpenCTI Context] Failed to clear cache: {e}")
            db.session.rollback()
    
    def _hash_params(self, params: Any) -> str:
        """Create hash of query parameters for cache key"""
        param_str = json.dumps(params, sort_keys=True, default=str)
        return hashlib.sha256(param_str.encode()).hexdigest()
    
    def _get_cached(self, query_type: str, params: Any) -> Optional[Any]:
        """Get cached response if available and not expired"""
        params_hash = self._hash_params(params)
        
        cutoff = datetime.utcnow() - timedelta(hours=self.cache_ttl_hours)
        
        cached = OpenCTICache.query.filter_by(
            case_id=self.case_id,
            query_type=query_type,
            query_params_hash=params_hash
        ).filter(
            OpenCTICache.cached_at >= cutoff
        ).first()
        
        if cached:
            return cached.response_json
        
        return None
    
    def _set_cached(self, query_type: str, params: Any, response: Any):
        """Store response in cache"""
        try:
            params_hash = self._hash_params(params)
            
            # Update or insert
            existing = OpenCTICache.query.filter_by(
                case_id=self.case_id,
                query_type=query_type,
                query_params_hash=params_hash
            ).first()
            
            if existing:
                existing.response_json = response
                existing.cached_at = datetime.utcnow()
            else:
                cache_entry = OpenCTICache(
                    case_id=self.case_id,
                    query_type=query_type,
                    query_params_hash=params_hash,
                    response_json=response
                )
                db.session.add(cache_entry)
            
            db.session.commit()
        except Exception as e:
            logger.warning(f"[OpenCTI Context] Failed to cache response: {e}")
            db.session.rollback()
    
    def get_attack_pattern_context(self, mitre_technique_id: str) -> Dict[str, Any]:
        """
        Get context for a MITRE technique.
        
        Args:
            mitre_technique_id: MITRE technique ID (e.g., T1003, T1059.001)
            
        Returns:
            dict: {
                'technique_name': str,
                'description': str,
                'detection_guidance': str,  # x_mitre_detection field
                'platforms': list,
                'threat_actors': list,  # Actors known to use this
                'related_techniques': list
            }
        
        Caches result for this case.
        """
        if not self.is_available():
            return self._empty_attack_pattern_context()
        
        # Check cache
        cached = self._get_cached('attack_pattern', mitre_technique_id)
        if cached is not None:
            return cached
        
        client = self._get_client()
        if not client:
            return self._empty_attack_pattern_context()
        
        try:
            # Get attack patterns
            patterns = client.get_attack_patterns(limit=500)
            
            # Find matching pattern
            matching = None
            for pattern in patterns:
                if pattern.get('mitre_id') == mitre_technique_id:
                    matching = pattern
                    break
            
            if not matching:
                result = self._empty_attack_pattern_context()
                self._set_cached('attack_pattern', mitre_technique_id, result)
                return result
            
            # Get threat actors using this technique
            threat_actors = []
            try:
                intrusion_sets = client.get_intrusion_sets_with_ttps(limit=100)
                for actor in intrusion_sets:
                    for ap in actor.get('attack_patterns', []):
                        if ap.get('mitre_id') == mitre_technique_id:
                            threat_actors.append({
                                'name': actor.get('name'),
                                'aliases': actor.get('aliases', [])
                            })
                            break
            except Exception:
                pass
            
            result = {
                'technique_id': mitre_technique_id,
                'technique_name': matching.get('name', ''),
                'description': matching.get('description', ''),
                'detection_guidance': matching.get('detection', ''),
                'platforms': matching.get('platforms', []),
                'kill_chain_phases': matching.get('kill_chain_phases', []),
                'threat_actors': threat_actors,
                'related_techniques': []
            }
            
            self._set_cached('attack_pattern', mitre_technique_id, result)
            return result
            
        except Exception as e:
            logger.error(f"[OpenCTI Context] Failed to get attack pattern context: {e}")
            return self._empty_attack_pattern_context()
    
    def _empty_attack_pattern_context(self) -> Dict:
        """Return empty attack pattern context structure"""
        return {
            'technique_id': '',
            'technique_name': '',
            'description': '',
            'detection_guidance': '',
            'platforms': [],
            'kill_chain_phases': [],
            'threat_actors': [],
            'related_techniques': []
        }
    
    def get_threat_actor_context(self, technique_ids: List[str]) -> List[Dict[str, Any]]:
        """
        Get threat actors known to use these techniques.
        
        Args:
            technique_ids: List of MITRE technique IDs
            
        Returns:
            list[dict]: [{
                'name': str,
                'aliases': list,
                'description': str,
                'techniques_used': list  # From the input list
            }]
        """
        if not self.is_available() or not technique_ids:
            return []
        
        # Check cache
        cache_key = sorted(set(technique_ids))
        cached = self._get_cached('threat_actors', cache_key)
        if cached is not None:
            return cached
        
        client = self._get_client()
        if not client:
            return []
        
        try:
            intrusion_sets = client.get_intrusion_sets_with_ttps(limit=200)
            
            matching_actors = []
            technique_set = set(technique_ids)
            
            for actor in intrusion_sets:
                actor_techniques = []
                for ap in actor.get('attack_patterns', []):
                    if ap.get('mitre_id') in technique_set:
                        actor_techniques.append(ap.get('mitre_id'))
                
                if actor_techniques:
                    matching_actors.append({
                        'name': actor.get('name'),
                        'aliases': actor.get('aliases', []),
                        'description': actor.get('description', '')[:500] if actor.get('description') else '',
                        'techniques_used': actor_techniques
                    })
            
            # Sort by number of matching techniques
            matching_actors.sort(key=lambda a: len(a['techniques_used']), reverse=True)
            
            self._set_cached('threat_actors', cache_key, matching_actors)
            return matching_actors
            
        except Exception as e:
            logger.error(f"[OpenCTI Context] Failed to get threat actor context: {e}")
            return []
    
    def get_sigma_rules_not_in_hayabusa(self, technique_id: str) -> List[Dict[str, Any]]:
        """
        Get Sigma rules from OpenCTI that may not be in Hayabusa's ruleset.
        
        Compares by rule name/id to avoid duplicates.
        
        Args:
            technique_id: MITRE technique ID
            
        Returns:
            list[dict]: [{
                'name': str,
                'sigma_rule': str,  # YAML content
                'description': str
            }]
        """
        if not self.is_available():
            return []
        
        # Check cache
        cached = self._get_cached('sigma_rules', technique_id)
        if cached is not None:
            return cached
        
        client = self._get_client()
        if not client:
            return []
        
        try:
            # Get Sigma indicators from OpenCTI
            sigma_indicators = client.get_sigma_indicators(limit=500)
            
            # Get known Hayabusa rule names for comparison
            hayabusa_rules = self._get_hayabusa_rule_names()
            
            # Find rules not in Hayabusa
            gap_rules = []
            for ind in sigma_indicators:
                rule_name = ind.get('name', '')
                
                # Check if this rule is already in Hayabusa
                if self._is_in_hayabusa(rule_name, hayabusa_rules):
                    continue
                
                # Check if related to the technique (by kill chain or labels)
                kill_chain = ind.get('kill_chain_phases', [])
                labels = ind.get('labels', [])
                
                # Simple matching - could be enhanced
                technique_lower = technique_id.lower()
                if any(technique_lower in str(kc).lower() for kc in kill_chain) or \
                   any(technique_lower in str(l).lower() for l in labels):
                    gap_rules.append({
                        'name': rule_name,
                        'sigma_rule': ind.get('sigma_rule', ''),
                        'description': f"Sigma rule from OpenCTI for technique {technique_id}",
                        'score': ind.get('score', 50)
                    })
            
            self._set_cached('sigma_rules', technique_id, gap_rules)
            return gap_rules
            
        except Exception as e:
            logger.error(f"[OpenCTI Context] Failed to get Sigma rules: {e}")
            return []
    
    def _get_hayabusa_rule_names(self) -> set:
        """Get set of known Hayabusa rule names from database"""
        try:
            from models.rag import AttackPattern
            patterns = AttackPattern.query.filter_by(source='hayabusa').all()
            return {p.name.lower() for p in patterns if p.name}
        except Exception:
            return set()
    
    def _is_in_hayabusa(self, rule_name: str, hayabusa_rules: set) -> bool:
        """Check if a rule name is already in Hayabusa"""
        if not rule_name:
            return False
        
        rule_lower = rule_name.lower()
        
        # Direct match
        if rule_lower in hayabusa_rules:
            return True
        
        # Fuzzy match - check if significant portion matches
        for hr in hayabusa_rules:
            if len(hr) > 10 and len(rule_lower) > 10:
                # Check if >70% of words match
                hr_words = set(hr.split())
                rule_words = set(rule_lower.split())
                if hr_words and rule_words:
                    overlap = len(hr_words & rule_words) / max(len(hr_words), len(rule_words))
                    if overlap > 0.7:
                        return True
        
        return False
    
    def enrich_ioc(self, ioc_value: str, ioc_type: str) -> Dict[str, Any]:
        """
        Check if IOC is known in OpenCTI threat feeds.
        
        Args:
            ioc_value: The IOC value (IP, hash, domain, etc.)
            ioc_type: CaseScope IOC type
            
        Returns:
            dict: {
                'found': bool,
                'threat_actors': list,
                'campaigns': list,
                'confidence': int,
                'labels': list
            }
        """
        if not self.is_available():
            return {'found': False, 'error': 'OpenCTI not available'}
        
        # Check cache
        cache_key = {
            'version': self._ioc_cache_version,
            'ioc_type': ioc_type,
            'ioc_value': ioc_value,
        }
        cached = self._get_cached('ioc_enrichment', cache_key)
        if cached is not None:
            return cached
        
        client = self._get_client()
        if not client:
            return {'found': False, 'error': 'OpenCTI client not available'}
        
        try:
            enrichment = client.check_indicator(ioc_value, ioc_type)
            
            result = {
                'found': enrichment.get('found', False),
                'status': enrichment.get('status', 'not_found'),
                'threat_actors': enrichment.get('threat_actors', []),
                'campaigns': enrichment.get('campaigns', []),
                'confidence': enrichment.get('confidence', 0),
                'labels': enrichment.get('labels', []),
                'score': enrichment.get('score', 0),
                'tlp': enrichment.get('tlp', 'TLP:CLEAR'),
                'match_source': enrichment.get('match_source'),
                'schema_version': enrichment.get('schema_version'),
            }
            
            self._set_cached('ioc_enrichment', cache_key, result)
            return result
            
        except Exception as e:
            logger.error(f"[OpenCTI Context] Failed to enrich IOC: {e}")
            return {'found': False, 'error': str(e)}
    
    def get_campaign_context(self, technique_ids: List[str], days_back: int = 90) -> List[Dict[str, Any]]:
        """
        Get recent threat reports/campaigns using these techniques.
        
        Args:
            technique_ids: List of MITRE technique IDs
            days_back: Number of days to look back
            
        Returns:
            list[dict]: [{
                'name': str,
                'published': datetime,
                'description': str,
                'techniques': list
            }]
        """
        if not self.is_available() or not technique_ids:
            return []
        
        # Check cache
        cache_key = {'techniques': sorted(set(technique_ids)), 'days': days_back}
        cached = self._get_cached('campaigns', cache_key)
        if cached is not None:
            return cached
        
        client = self._get_client()
        if not client:
            return []
        
        try:
            reports = client.get_reports_with_attack_context(days=days_back, limit=100)
            
            technique_set = set(technique_ids)
            matching_reports = []
            
            for report in reports:
                matching_techniques = []
                for ap in report.get('attack_patterns', []):
                    if ap.get('mitre_id') in technique_set:
                        matching_techniques.append(ap.get('mitre_id'))
                
                if matching_techniques:
                    matching_reports.append({
                        'name': report.get('name', ''),
                        'published': report.get('published', ''),
                        'description': report.get('description', ''),
                        'techniques': matching_techniques,
                        'report_types': report.get('report_types', []),
                        'confidence': report.get('confidence', 0)
                    })
            
            # Sort by recency
            matching_reports.sort(
                key=lambda r: r.get('published', ''),
                reverse=True
            )
            
            self._set_cached('campaigns', cache_key, matching_reports)
            return matching_reports
            
        except Exception as e:
            logger.error(f"[OpenCTI Context] Failed to get campaign context: {e}")
            return []
    
    def get_context_for_findings(self, findings: List) -> Dict[str, Any]:
        """
        Get aggregated OpenCTI context for a list of findings.
        
        Args:
            findings: List of GapDetectionFinding or similar objects
            
        Returns:
            dict: Aggregated context data
        """
        if not self.is_available():
            return {'available': False}
        
        # Collect all unique techniques and IOCs from findings
        all_techniques = set()
        all_iocs = []
        
        for finding in findings:
            # Get techniques from finding
            if hasattr(finding, 'mitre_techniques'):
                for t in (finding.mitre_techniques or []):
                    all_techniques.add(t)
            elif isinstance(finding, dict):
                for t in finding.get('mitre_techniques', []):
                    all_techniques.add(t)
            
            # Get suggested IOCs
            if hasattr(finding, 'suggested_iocs'):
                for ioc in (finding.suggested_iocs or []):
                    all_iocs.append(ioc)
            elif isinstance(finding, dict):
                for ioc in finding.get('suggested_iocs', []):
                    all_iocs.append(ioc)
        
        context = {
            'available': True,
            'techniques': {},
            'threat_actors': [],
            'campaigns': [],
            'ioc_enrichment': {}
        }
        
        # Get context for each technique
        for tech in list(all_techniques)[:10]:  # Limit to 10
            tech_context = self.get_attack_pattern_context(tech)
            if tech_context.get('technique_name'):
                context['techniques'][tech] = tech_context
        
        # Get threat actors
        if all_techniques:
            context['threat_actors'] = self.get_threat_actor_context(list(all_techniques))
        
        # Get campaigns
        if all_techniques:
            context['campaigns'] = self.get_campaign_context(list(all_techniques))
        
        # Enrich IOCs
        for ioc in all_iocs[:20]:  # Limit to 20
            ioc_value = ioc.get('value') if isinstance(ioc, dict) else str(ioc)
            ioc_type = ioc.get('type', 'Unknown') if isinstance(ioc, dict) else 'Unknown'
            if ioc_value:
                enrichment = self.enrich_ioc(ioc_value, ioc_type)
                if enrichment.get('found'):
                    context['ioc_enrichment'][ioc_value] = enrichment
        
        return context


def build_opencti_context_section(
    provider: OpenCTIContextProvider,
    mitre_techniques: List[str]
) -> str:
    """
    Build OpenCTI context section for AI prompts.
    
    Args:
        provider: OpenCTIContextProvider instance
        mitre_techniques: List of MITRE technique IDs
        
    Returns:
        str: Formatted context section for prompt inclusion
    """
    if not provider.is_available():
        return ""
    
    sections = []
    
    for tech in mitre_techniques[:5]:  # Limit to 5
        ctx = provider.get_attack_pattern_context(tech)
        if ctx.get('technique_name'):
            section = f"\nMITRE Technique: {tech} - {ctx['technique_name']}"
            
            if ctx.get('detection_guidance'):
                guidance = ctx['detection_guidance'][:300]
                section += f"\n- Detection Guidance: {guidance}"
            
            if ctx.get('threat_actors'):
                actors = [a['name'] for a in ctx['threat_actors'][:3]]
                section += f"\n- Associated Threat Actors: {', '.join(actors)}"
            
            sections.append(section)
    
    # Get gap rules
    for tech in mitre_techniques[:3]:
        gap_rules = provider.get_sigma_rules_not_in_hayabusa(tech)
        if gap_rules:
            rule_names = [r['name'] for r in gap_rules[:3]]
            sections.append(f"\nRelated Sigma Rules Not in Hayabusa: {', '.join(rule_names)}")
    
    if not sections:
        return ""
    
    return "\n═══════════════════════════════════════════════════════════════════════════════\n" + \
           "THREAT INTELLIGENCE CONTEXT (from OpenCTI)\n" + \
           "═══════════════════════════════════════════════════════════════════════════════\n" + \
           "\n".join(sections)
