"""Attack Chain Builder for CaseScope

Builds and persists attack chain models from correlated Hayabusa detections.

An attack chain represents a sequence of related attacker activities
that form a coherent attack narrative.
"""

import logging
from datetime import datetime
from typing import List, Dict, Any, Optional
from uuid import uuid4

from models.database import db
from models.behavioral_profiles import SuggestedAction
from config import Config

logger = logging.getLogger(__name__)


# MITRE tactic to phase mapping
TACTIC_PHASE_MAP = {
    'reconnaissance': 'pre-attack',
    'resource-development': 'pre-attack',
    'initial-access': 'initial',
    'execution': 'establish',
    'persistence': 'establish',
    'privilege-escalation': 'escalate',
    'defense-evasion': 'maintain',
    'credential-access': 'escalate',
    'discovery': 'explore',
    'lateral-movement': 'spread',
    'collection': 'action',
    'command-and-control': 'maintain',
    'exfiltration': 'action',
    'impact': 'action'
}


class AttackChain:
    """
    Represents a complete attack chain with all analysis results.
    """
    
    def __init__(self, chain_id: str, case_id: int, analysis_id: str):
        self.chain_id = chain_id
        self.case_id = case_id
        self.analysis_id = analysis_id
        
        # Core data
        self.detection_groups: List[Dict] = []
        self.time_start: Optional[datetime] = None
        self.time_end: Optional[datetime] = None
        
        # Attack narrative
        self.title: str = ''
        self.description: str = ''
        self.severity: str = 'medium'
        self.confidence: float = 0.0
        
        # Kill chain coverage
        self.phases_covered: List[str] = []
        self.tactics_observed: List[str] = []
        self.techniques_observed: List[str] = []
        
        # Entities
        self.primary_user: Optional[str] = None
        self.primary_host: Optional[str] = None
        self.involved_users: List[str] = []
        self.involved_hosts: List[str] = []
        self.involved_ips: List[str] = []
        
        # Analysis context
        self.behavioral_anomalies: List[str] = []
        self.suggested_actions: List[Dict] = []
        
        # AI analysis (if available)
        self.ai_analysis: Optional[Dict] = None
    
    def add_detection_group(self, group_dict: Dict):
        """Add a correlated detection group to this chain"""
        self.detection_groups.append(group_dict)
        
        # Update time range
        if group_dict.get('time_start'):
            ts = datetime.fromisoformat(group_dict['time_start']) if isinstance(
                group_dict['time_start'], str
            ) else group_dict['time_start']
            if self.time_start is None or ts < self.time_start:
                self.time_start = ts
        
        if group_dict.get('time_end'):
            te = datetime.fromisoformat(group_dict['time_end']) if isinstance(
                group_dict['time_end'], str
            ) else group_dict['time_end']
            if self.time_end is None or te > self.time_end:
                self.time_end = te
        
        # Aggregate tactics
        for tactic in group_dict.get('mitre_tactics', []):
            if tactic and tactic not in self.tactics_observed:
                self.tactics_observed.append(tactic)
        
        # Aggregate techniques
        for tech in group_dict.get('mitre_techniques', []):
            if tech and tech not in self.techniques_observed:
                self.techniques_observed.append(tech)
        
        # Aggregate entities
        entities = group_dict.get('entities', {})
        for user in entities.get('usernames', []):
            if user and user not in self.involved_users:
                self.involved_users.append(user)
        for host in entities.get('source_hosts', []):
            if host and host not in self.involved_hosts:
                self.involved_hosts.append(host)
        for ip in entities.get('source_ips', []):
            if ip and ip not in self.involved_ips:
                self.involved_ips.append(ip)
        
        # Aggregate anomaly flags
        for flag in group_dict.get('anomaly_flags', []):
            if flag and flag not in self.behavioral_anomalies:
                self.behavioral_anomalies.append(flag)
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for serialization"""
        return {
            'chain_id': self.chain_id,
            'case_id': self.case_id,
            'analysis_id': self.analysis_id,
            'title': self.title,
            'description': self.description,
            'severity': self.severity,
            'confidence': self.confidence,
            'time_start': self.time_start.isoformat() if self.time_start else None,
            'time_end': self.time_end.isoformat() if self.time_end else None,
            'duration_seconds': (self.time_end - self.time_start).total_seconds()
                if self.time_start and self.time_end else 0,
            'phases_covered': self.phases_covered,
            'tactics_observed': self.tactics_observed,
            'techniques_observed': self.techniques_observed,
            'primary_user': self.primary_user,
            'primary_host': self.primary_host,
            'involved_users': self.involved_users,
            'involved_hosts': self.involved_hosts,
            'involved_ips': self.involved_ips,
            'behavioral_anomalies': self.behavioral_anomalies,
            'suggested_actions': self.suggested_actions,
            'detection_group_count': len(self.detection_groups),
            'total_event_count': sum(g.get('event_count', 0) for g in self.detection_groups),
            'ai_analysis': self.ai_analysis
        }


class AttackChainBuilder:
    """
    Builds attack chains from correlated detection groups.
    
    Responsibilities:
    - Merge related detection groups into attack chains
    - Generate attack narratives
    - Calculate chain-level severity and confidence
    - Generate suggested investigation actions
    """
    
    def __init__(self, case_id: int, analysis_id: str):
        self.case_id = case_id
        self.analysis_id = analysis_id
    
    def build_chains(self, detection_groups: List) -> List[AttackChain]:
        """
        Build attack chains from correlated detection groups.
        
        Args:
            detection_groups: List of CorrelatedDetectionGroup objects
            
        Returns:
            list[AttackChain]: Built attack chains
        """
        if not detection_groups:
            return []
        
        # Convert groups to dicts if needed
        group_dicts = []
        for g in detection_groups:
            if hasattr(g, 'to_dict'):
                group_dicts.append(g.to_dict())
            else:
                group_dicts.append(g)
        
        # Merge related groups into chains
        chains = self._merge_into_chains(group_dicts)
        
        # Analyze each chain
        for chain in chains:
            self._analyze_chain(chain)
            self._generate_suggested_actions(chain)
        
        logger.info(f"Built {len(chains)} attack chains from {len(detection_groups)} detection groups")
        
        return chains
    
    def _merge_into_chains(self, group_dicts: List[Dict]) -> List[AttackChain]:
        """
        Merge detection groups that share entities into attack chains.
        
        Groups are merged if they share:
        - Primary user AND are within time proximity
        - Primary host AND share tactics
        """
        if not group_dicts:
            return []
        
        chains = []
        used_indices = set()
        
        # Sort by chain_score (highest first) for primary chain selection
        sorted_groups = sorted(
            enumerate(group_dicts),
            key=lambda x: x[1].get('chain_score', 0),
            reverse=True
        )
        
        for idx, group in sorted_groups:
            if idx in used_indices:
                continue
            
            # Start new chain
            chain = AttackChain(
                chain_id=str(uuid4()),
                case_id=self.case_id,
                analysis_id=self.analysis_id
            )
            chain.add_detection_group(group)
            used_indices.add(idx)
            
            # Find related groups to merge
            for other_idx, other_group in enumerate(group_dicts):
                if other_idx in used_indices:
                    continue
                
                if self._should_merge(group, other_group, chain):
                    chain.add_detection_group(other_group)
                    used_indices.add(other_idx)
            
            chains.append(chain)
        
        return chains
    
    def _should_merge(self, group1: Dict, group2: Dict, chain: AttackChain) -> bool:
        """
        Determine if two detection groups should be merged into same chain.
        """
        # Check entity overlap
        entities1 = group1.get('entities', {})
        entities2 = group2.get('entities', {})
        
        users1 = set(entities1.get('usernames', []))
        users2 = set(entities2.get('usernames', []))
        
        hosts1 = set(entities1.get('source_hosts', []))
        hosts2 = set(entities2.get('source_hosts', []))
        
        # Merge if same primary user
        if users1 & users2:
            # Check time proximity (within 4 hours)
            if self._check_time_proximity(group1, group2, hours=4):
                return True
        
        # Merge if same host and related tactics
        if hosts1 & hosts2:
            tactics1 = set(group1.get('mitre_tactics', []))
            tactics2 = set(group2.get('mitre_tactics', []))
            
            # Check if tactics form a progression
            if self._tactics_form_progression(tactics1, tactics2):
                return True
        
        return False
    
    def _check_time_proximity(self, group1: Dict, group2: Dict, hours: int = 4) -> bool:
        """Check if two groups are within time proximity"""
        try:
            t1_end = group1.get('time_end')
            t2_start = group2.get('time_start')
            
            if not t1_end or not t2_start:
                return False
            
            if isinstance(t1_end, str):
                t1_end = datetime.fromisoformat(t1_end)
            if isinstance(t2_start, str):
                t2_start = datetime.fromisoformat(t2_start)
            
            diff = abs((t2_start - t1_end).total_seconds())
            return diff <= hours * 3600
            
        except Exception:
            return False
    
    def _tactics_form_progression(self, tactics1: set, tactics2: set) -> bool:
        """Check if tactics from two groups form a kill chain progression"""
        from utils.hayabusa_correlator import MITRE_TACTIC_ORDER
        
        # Get indices
        indices1 = [MITRE_TACTIC_ORDER.index(t) for t in tactics1 if t in MITRE_TACTIC_ORDER]
        indices2 = [MITRE_TACTIC_ORDER.index(t) for t in tactics2 if t in MITRE_TACTIC_ORDER]
        
        if not indices1 or not indices2:
            return False
        
        max1 = max(indices1)
        min2 = min(indices2)
        
        # Group2 tactics follow group1 tactics
        return min2 >= max1 - 1  # Allow some overlap
    
    def _analyze_chain(self, chain: AttackChain):
        """
        Analyze the attack chain to generate narrative and metrics.
        """
        # Determine primary entities
        if chain.involved_users:
            # Primary user = most mentioned user
            user_counts = {}
            for user in chain.involved_users:
                user_counts[user] = user_counts.get(user, 0) + 1
            chain.primary_user = max(user_counts.keys(), key=lambda u: user_counts[u])
        
        if chain.involved_hosts:
            host_counts = {}
            for host in chain.involved_hosts:
                host_counts[host] = host_counts.get(host, 0) + 1
            chain.primary_host = max(host_counts.keys(), key=lambda h: host_counts[h])
        
        # Determine phases covered
        chain.phases_covered = list(set(
            TACTIC_PHASE_MAP.get(t, 'unknown') 
            for t in chain.tactics_observed 
            if t in TACTIC_PHASE_MAP
        ))
        
        # Calculate overall severity
        chain.severity = self._calculate_chain_severity(chain)
        
        # Calculate confidence
        chain.confidence = self._calculate_chain_confidence(chain)
        
        # Generate title and description
        chain.title = self._generate_chain_title(chain)
        chain.description = self._generate_chain_description(chain)
    
    def _calculate_chain_severity(self, chain: AttackChain) -> str:
        """Calculate overall chain severity"""
        # Get highest severity from detection groups
        severity_order = ['informational', 'low', 'medium', 'high', 'critical']
        max_severity = 'informational'
        
        for group in chain.detection_groups:
            group_sev = group.get('combined_severity', 'informational')
            if group_sev in severity_order:
                if severity_order.index(group_sev) > severity_order.index(max_severity):
                    max_severity = group_sev
        
        # Upgrade if chain shows significant progression
        if len(chain.phases_covered) >= 4 and max_severity in ['medium', 'high']:
            max_severity = 'critical'
        elif len(chain.phases_covered) >= 3 and max_severity == 'medium':
            max_severity = 'high'
        
        # Upgrade if late-stage tactics observed
        late_tactics = {'exfiltration', 'impact', 'collection'}
        if late_tactics & set(chain.tactics_observed):
            if max_severity in ['medium']:
                max_severity = 'high'
            elif max_severity in ['high']:
                max_severity = 'critical'
        
        return max_severity
    
    def _calculate_chain_confidence(self, chain: AttackChain) -> float:
        """Calculate confidence score for the chain"""
        confidence = 0.0
        
        # Base confidence from detection group scores
        if chain.detection_groups:
            avg_score = sum(g.get('chain_score', 0) for g in chain.detection_groups) / len(chain.detection_groups)
            confidence = avg_score * 0.5  # Scale to 0-50
        
        # Bonus for multi-phase chains
        if len(chain.phases_covered) >= 4:
            confidence += 20
        elif len(chain.phases_covered) >= 3:
            confidence += 15
        elif len(chain.phases_covered) >= 2:
            confidence += 10
        
        # Bonus for behavioral anomalies
        if chain.behavioral_anomalies:
            confidence += min(15, len(chain.behavioral_anomalies) * 5)
        
        # Bonus for multiple detection groups (corroborating evidence)
        if len(chain.detection_groups) >= 3:
            confidence += 10
        elif len(chain.detection_groups) >= 2:
            confidence += 5
        
        return min(100, confidence)
    
    def _generate_chain_title(self, chain: AttackChain) -> str:
        """Generate a descriptive title for the chain"""
        # Determine attack type from phases
        if 'action' in chain.phases_covered:
            if 'exfiltration' in chain.tactics_observed:
                attack_type = "Data Exfiltration"
            elif 'impact' in chain.tactics_observed:
                attack_type = "System Impact"
            else:
                attack_type = "Objective Achievement"
        elif 'spread' in chain.phases_covered:
            attack_type = "Lateral Movement Campaign"
        elif 'escalate' in chain.phases_covered:
            attack_type = "Privilege Escalation"
        elif 'establish' in chain.phases_covered:
            attack_type = "Foothold Establishment"
        elif 'initial' in chain.phases_covered:
            attack_type = "Initial Compromise"
        else:
            attack_type = "Suspicious Activity Chain"
        
        # Add target context
        if chain.primary_user:
            target = f"targeting {chain.primary_user}"
        elif chain.primary_host:
            target = f"on {chain.primary_host}"
        else:
            target = ""
        
        return f"{attack_type} {target}".strip()
    
    def _generate_chain_description(self, chain: AttackChain) -> str:
        """Generate a narrative description of the attack chain"""
        parts = []
        
        # Opening
        event_count = sum(g.get('event_count', 0) for g in chain.detection_groups)
        parts.append(f"Detected {event_count} related security events in "
                    f"{len(chain.detection_groups)} correlated groups.")
        
        # Time span
        if chain.time_start and chain.time_end:
            duration = (chain.time_end - chain.time_start).total_seconds()
            if duration < 60:
                time_desc = f"{int(duration)} seconds"
            elif duration < 3600:
                time_desc = f"{int(duration/60)} minutes"
            else:
                time_desc = f"{duration/3600:.1f} hours"
            parts.append(f"Activity spanned {time_desc}.")
        
        # Tactics covered
        if chain.tactics_observed:
            tactics_str = ", ".join(t.replace('-', ' ') for t in chain.tactics_observed[:5])
            parts.append(f"MITRE ATT&CK tactics observed: {tactics_str}.")
        
        # Entity involvement
        if chain.primary_user:
            parts.append(f"Primary user involved: {chain.primary_user}.")
        if chain.primary_host:
            parts.append(f"Primary host: {chain.primary_host}.")
        
        # Behavioral anomalies
        if chain.behavioral_anomalies:
            parts.append(f"Behavioral anomalies detected: {len(chain.behavioral_anomalies)}.")
        
        return " ".join(parts)
    
    def _generate_suggested_actions(self, chain: AttackChain):
        """Generate suggested investigation actions for the chain"""
        actions = []
        
        # Always suggest timeline review
        actions.append({
            'action_type': 'review_timeline',
            'target': f"Events from {chain.time_start} to {chain.time_end}",
            'reason': 'Review full timeline of correlated events',
            'priority': 'high'
        })
        
        # User investigation for involved users
        for user in chain.involved_users[:3]:
            if not user.endswith('$'):  # Skip machine accounts
                actions.append({
                    'action_type': 'investigate_user',
                    'target': user,
                    'reason': f"User involved in {chain.title}",
                    'priority': 'high' if user == chain.primary_user else 'medium'
                })
        
        # Host investigation
        for host in chain.involved_hosts[:3]:
            actions.append({
                'action_type': 'investigate_host',
                'target': host,
                'reason': f"Host involved in attack chain",
                'priority': 'high' if host == chain.primary_host else 'medium'
            })
        
        # Specific actions based on tactics
        if 'credential-access' in chain.tactics_observed:
            actions.append({
                'action_type': 'credential_review',
                'target': chain.primary_user or 'All involved users',
                'reason': 'Credential access tactics detected - check for compromised credentials',
                'priority': 'critical'
            })
        
        if 'lateral-movement' in chain.tactics_observed:
            actions.append({
                'action_type': 'lateral_movement_trace',
                'target': ', '.join(chain.involved_hosts[:5]),
                'reason': 'Trace lateral movement path through network',
                'priority': 'critical'
            })
        
        if 'exfiltration' in chain.tactics_observed:
            actions.append({
                'action_type': 'data_exposure_assessment',
                'target': chain.primary_host or 'Involved hosts',
                'reason': 'Assess potential data exposure from exfiltration activity',
                'priority': 'critical'
            })
        
        if 'persistence' in chain.tactics_observed:
            actions.append({
                'action_type': 'persistence_check',
                'target': ', '.join(chain.involved_hosts[:3]),
                'reason': 'Check for persistence mechanisms on affected hosts',
                'priority': 'high'
            })
        
        chain.suggested_actions = actions
        
        # Also create SuggestedAction records in database
        try:
            for action in actions:
                db_action = SuggestedAction(
                    case_id=self.case_id,
                    analysis_id=self.analysis_id,
                    source_type='attack_chain',
                    source_id=0,  # Will be updated when chain is saved
                    action_type=action['action_type'],
                    target_type='system',
                    target_value=action['target'],
                    reason=action['reason'],
                    confidence=chain.confidence,
                    status='pending'
                )
                db.session.add(db_action)
            
            db.session.commit()
        except Exception as e:
            logger.error(f"[AttackChainBuilder] Failed to save suggested actions: {e}")
            db.session.rollback()
