"""Stateful Behavioral Anomaly Detector for CaseScope

Finds users and systems behaving outside their baseline and peer group norms.

This catches attacks that don't trigger specific Sigma rules but represent
significant deviations from normal behavior.

Key insight: A compromised user's OWN baseline may be polluted, so we also
compare to PEER behavior to catch anomalies.
"""

import logging
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional

from models.database import db
from models.behavioral_profiles import (
    GapDetectionFinding, GapFindingType,
    UserBehaviorProfile, SystemBehaviorProfile,
    PeerGroup, PeerGroupMember
)
from models.known_user import KnownUser
from models.known_system import KnownSystem
from utils.peer_statistics import resolve_threshold
from utils.stateful_detectors import BaseGapDetector
from config import Config

logger = logging.getLogger(__name__)


class BehavioralAnomalyDetector(BaseGapDetector):
    """
    Detects entities behaving anomalously compared to their baseline and peers.
    
    This catches attacks that don't trigger specific Sigma rules but represent
    significant deviations from normal behavior.
    """
    
    # Anomaly type weights for composite scoring
    ANOMALY_WEIGHTS = {
        'auth_volume': 0.30,
        'failure_rate': 0.25,
        'off_hours': 0.15,
        'new_targets': 0.20,
        'auth_method_change': 0.10
    }
    
    def __init__(self, case_id: int, analysis_id: str, z_score_threshold: float = None):
        super().__init__(case_id, analysis_id)
        
        # Z-score threshold for anomaly detection
        self.z_score_threshold = z_score_threshold or getattr(
            Config, 'ANALYSIS_ANOMALY_Z_THRESHOLD', 3.0
        )
    
    def detect(self) -> List[GapDetectionFinding]:
        """
        Iterate through all profiled users and systems.
        Flag those with high z-scores vs peers.
        
        Returns:
            list[GapDetectionFinding]: Anomaly findings
        """
        findings = []
        
        # Detect user anomalies
        user_findings = self._detect_user_anomalies()
        findings.extend(user_findings)
        
        # Detect system anomalies
        system_findings = self._detect_system_anomalies()
        findings.extend(system_findings)
        
        logger.info(f"Behavioral anomaly detection complete: {len(findings)} findings "
                   f"({len(user_findings)} user, {len(system_findings)} system)")
        
        return findings
    
    def _load_peer_context(self, profiles: List, entity_type: str) -> tuple:
        """Load every peer group and member for these profiles in two queries.

        Looking each one up per profile issued two queries per entity, which on
        a case with a few hundred profiled accounts was hundreds of round trips
        for data that fits in two.
        """
        group_ids = {profile.peer_group_id for profile in profiles if profile.peer_group_id}
        if not group_ids:
            return {}, {}

        groups = PeerGroup.query.filter(PeerGroup.id.in_(group_ids)).all()
        groups_by_id = {group.id: group for group in groups}

        members = PeerGroupMember.query.filter(
            PeerGroupMember.peer_group_id.in_(group_ids),
            PeerGroupMember.entity_type == entity_type,
        ).all()
        members_by_key = {
            (member.peer_group_id, member.entity_id): member for member in members
        }
        return groups_by_id, members_by_key

    def _detect_user_anomalies(self) -> List[GapDetectionFinding]:
        """Detect anomalous user behavior"""
        findings = []
        
        # Get all user profiles with peer groups
        profiles = UserBehaviorProfile.query.filter_by(case_id=self.case_id).all()
        groups_by_id, members_by_key = self._load_peer_context(profiles, 'user')
        
        for profile in profiles:
            if not profile.peer_group_id:
                continue
            
            peer_group = groups_by_id.get(profile.peer_group_id)
            if not peer_group or not peer_group.profile_data:
                continue
            
            member = members_by_key.get((peer_group.id, profile.user_id))
            
            if not member or not member.z_scores:
                continue
            
            # Analyze anomalies
            anomaly_result = self._analyze_user_anomalies(profile, peer_group, member.z_scores)
            
            if anomaly_result:
                finding = self._create_user_anomaly_finding(profile, peer_group, anomaly_result)
                if finding:
                    findings.append(finding)
        
        return findings
    
    def _detect_system_anomalies(self) -> List[GapDetectionFinding]:
        """Detect anomalous system behavior"""
        findings = []
        
        # Get all system profiles with peer groups
        profiles = SystemBehaviorProfile.query.filter_by(case_id=self.case_id).all()
        groups_by_id, members_by_key = self._load_peer_context(profiles, 'system')
        
        for profile in profiles:
            if not profile.peer_group_id:
                continue
            
            peer_group = groups_by_id.get(profile.peer_group_id)
            if not peer_group or not peer_group.profile_data:
                continue
            
            member = members_by_key.get((peer_group.id, profile.system_id))
            
            if not member or not member.z_scores:
                continue
            
            # Analyze anomalies
            anomaly_result = self._analyze_system_anomalies(profile, peer_group, member.z_scores)
            
            if anomaly_result:
                finding = self._create_system_anomaly_finding(profile, peer_group, anomaly_result)
                if finding:
                    findings.append(finding)
        
        return findings
    
    def _analyze_user_anomalies(self, profile: UserBehaviorProfile, 
                                peer_group: PeerGroup, z_scores: Dict) -> Optional[Dict]:
        """
        Check each metric against peer group.
        Flag if any z-score exceeds threshold.
        
        Anomaly types:
        - Volume spike (auth count z-score > 3)
        - Failure spike (failure count z-score > 3)
        - Off-hours activity (off-hours % z-score > 3)
        - New target access (hosts not in typical_target_hosts)
        - Auth method change (switched Kerberos → NTLM)
        """
        return self._analyze_deviation_scores(peer_group, z_scores)
    
    def _analyze_system_anomalies(self, profile: SystemBehaviorProfile,
                                  peer_group: PeerGroup, z_scores: Dict) -> Optional[Dict]:
        """
        Same analysis for systems.
        """
        return self._analyze_deviation_scores(peer_group, z_scores)

    def _effective_threshold(self, peer_group: PeerGroup) -> Optional[float]:
        """Threshold for this group, capped to what its size can express.

        A group of three members cannot produce a deviation of 3.0 no matter
        what its members do, so applying the configured threshold unchanged
        made every small group permanently silent.
        """
        return resolve_threshold(
            peer_group.member_count or 0,
            configured_threshold=self.z_score_threshold,
        )

    def _analyze_deviation_scores(
        self, peer_group: PeerGroup, z_scores: Dict
    ) -> Optional[Dict]:
        """Flag the metrics whose deviation exceeds this group's threshold."""
        threshold = self._effective_threshold(peer_group)
        if threshold is None:
            return None

        anomalies_detected = []
        anomaly_details = {}
        max_z_score = 0
        
        for metric, z_score in z_scores.items():
            if abs(z_score) >= threshold:
                anomalies_detected.append(metric)
                anomaly_details[metric] = {
                    'z_score': z_score,
                    'direction': 'high' if z_score > 0 else 'low',
                    'threshold': round(threshold, 2),
                }
                max_z_score = max(max_z_score, abs(z_score))
        
        if not anomalies_detected:
            return None
        
        composite_score = self._calculate_composite_anomaly_score(z_scores, threshold)
        primary_anomaly = self._identify_anomaly_type(z_scores, anomalies_detected)
        
        return {
            'anomalies_detected': anomalies_detected,
            'anomaly_details': anomaly_details,
            'max_z_score': max_z_score,
            'composite_score': composite_score,
            'primary_anomaly': primary_anomaly,
            'threshold': threshold,
        }
    
    def _calculate_composite_anomaly_score(
        self, z_scores: Dict, threshold: Optional[float] = None
    ) -> float:
        """
        Weighted combination of individual deviation scores.
        """
        score = 0
        total_weight = 0
        
        for metric, weight in self.ANOMALY_WEIGHTS.items():
            if metric in z_scores:
                # Use absolute deviation, capped at 10
                z = min(abs(z_scores[metric]), 10)
                score += z * weight
                total_weight += weight
            elif metric == 'auth_volume' and 'daily_logons' in z_scores:
                z = min(abs(z_scores['daily_logons']), 10)
                score += z * weight
                total_weight += weight
        
        # Normalize to 0-100 scale, where a deviation sitting exactly on the
        # threshold scores 50 and twice the threshold scores 100. Scaling
        # against the threshold rather than a fixed z of 3 keeps the scale
        # meaningful for groups whose threshold had to be lowered to something
        # their size can express.
        if total_weight > 0:
            effective = threshold or self.z_score_threshold
            if effective <= 0:
                return 0
            normalized = (score / total_weight) * (50.0 / effective)
            return min(100, normalized)
        
        return 0

    def _confidence_from_deviation(self, anomaly_result: Dict) -> float:
        """Confidence for a finding, scaled against the group's own threshold.

        The tiers were absolute deviations of 3, 4 and 5, which no small group
        could reach. They are now multiples of whatever threshold applied to
        this group, so the boundaries land in the same place as before when the
        full configured threshold was used.
        """
        max_z = anomaly_result['max_z_score']
        composite = anomaly_result['composite_score']
        threshold = anomaly_result.get('threshold') or self.z_score_threshold

        ratio = (max_z / threshold) if threshold else 0

        if ratio >= 5 / 3:
            return min(95, 70 + composite * 0.25)
        if ratio >= 4 / 3:
            return min(85, 55 + composite * 0.3)
        if ratio >= 1:
            return min(70, 40 + composite * 0.3)
        return 30 + composite * 0.2
    
    def _identify_anomaly_type(self, z_scores: Dict, anomalies: List[str]) -> str:
        """
        Categorize the primary anomaly type for reporting.
        """
        if not anomalies:
            return 'unknown'
        
        # Find the metric with highest absolute z-score
        max_metric = max(anomalies, key=lambda m: abs(z_scores.get(m, 0)))
        
        type_map = {
            'daily_logons': GapFindingType.VOLUME_SPIKE,
            'auth_volume': GapFindingType.VOLUME_SPIKE,
            'failure_rate': GapFindingType.VOLUME_SPIKE,  # Failure spike
            'off_hours': GapFindingType.OFF_HOURS_ACTIVITY,
            'unique_hosts': GapFindingType.NEW_TARGET_ACCESS,
            'unique_users': GapFindingType.VOLUME_SPIKE
        }
        
        return type_map.get(max_metric, GapFindingType.ANOMALOUS_USER)
    
    def _create_user_anomaly_finding(self, profile: UserBehaviorProfile,
                                     peer_group: PeerGroup,
                                     anomaly_result: Dict) -> Optional[GapDetectionFinding]:
        """Create finding for user anomaly"""
        
        confidence = self._confidence_from_deviation(anomaly_result)
        
        if confidence < 35:
            return None
        
        # Determine severity
        anomaly_type = anomaly_result['primary_anomaly']
        if confidence >= 75:
            severity = 'high'
        elif confidence >= 50:
            severity = 'medium'
        else:
            severity = 'low'
        
        # Build summary
        anomalies = anomaly_result['anomalies_detected']
        summary = f"Anomalous behavior for user {profile.username}: "
        summary += ", ".join([f"{a} (z={anomaly_result['anomaly_details'][a]['z_score']:.1f})" 
                             for a in anomalies[:3]])
        
        # Build details
        details = {
            'username': profile.username,
            'peer_group': peer_group.group_name,
            'peer_group_size': peer_group.member_count,
            'anomalies': anomaly_result['anomaly_details'],
            'composite_score': round(anomaly_result['composite_score'], 1),
            'max_z_score': round(anomaly_result['max_z_score'], 2)
        }
        
        # Build peer comparison
        peer_comparison = {
            'peer_group_name': peer_group.group_name,
            'peer_medians': {
                'daily_logons': peer_group.median_daily_logons,
                'failure_rate': peer_group.median_failure_rate,
                'off_hours_pct': peer_group.median_off_hours_pct
            },
            'user_values': {
                'avg_daily_logons': profile.avg_daily_logons,
                'failure_rate': profile.failure_rate,
                'off_hours_percentage': profile.off_hours_percentage
            },
            'z_scores': anomaly_result['anomaly_details']
        }
        
        # Behavioral context
        behavioral_context = {
            'profile_period': {
                'start': profile.profile_period_start.isoformat() if profile.profile_period_start else None,
                'end': profile.profile_period_end.isoformat() if profile.profile_period_end else None
            },
            'total_events': profile.total_events,
            'avg_daily_logons': profile.avg_daily_logons,
            'peer_median_logons': peer_group.median_daily_logons
        }
        
        return self._create_finding(
            finding_type=anomaly_type,
            severity=severity,
            confidence=confidence,
            entity_type='user',
            entity_value=profile.username,
            entity_id=profile.user_id,
            summary=summary,
            details=details,
            behavioral_context=behavioral_context,
            peer_comparison=peer_comparison,
            time_window_start=profile.profile_period_start,
            time_window_end=profile.profile_period_end,
            event_count=profile.total_events
        )
    
    def _create_system_anomaly_finding(self, profile: SystemBehaviorProfile,
                                       peer_group: PeerGroup,
                                       anomaly_result: Dict) -> Optional[GapDetectionFinding]:
        """Create finding for system anomaly"""
        
        confidence = self._confidence_from_deviation(anomaly_result)
        
        if confidence < 35:
            return None
        
        if confidence >= 75:
            severity = 'high'
        elif confidence >= 50:
            severity = 'medium'
        else:
            severity = 'low'
        
        anomalies = anomaly_result['anomalies_detected']
        summary = f"Anomalous behavior for system {profile.hostname}: "
        summary += ", ".join([f"{a} (z={anomaly_result['anomaly_details'][a]['z_score']:.1f})" 
                             for a in anomalies[:3]])
        
        details = {
            'hostname': profile.hostname,
            'system_role': profile.system_role,
            'peer_group': peer_group.group_name,
            'peer_group_size': peer_group.member_count,
            'anomalies': anomaly_result['anomaly_details'],
            'composite_score': round(anomaly_result['composite_score'], 1),
            'max_z_score': round(anomaly_result['max_z_score'], 2)
        }
        
        peer_comparison = {
            'peer_group_name': peer_group.group_name,
            'z_scores': anomaly_result['anomaly_details']
        }
        
        behavioral_context = {
            'profile_period': {
                'start': profile.profile_period_start.isoformat() if profile.profile_period_start else None,
                'end': profile.profile_period_end.isoformat() if profile.profile_period_end else None
            },
            'total_events': profile.total_events,
            'unique_users': profile.unique_users
        }
        
        return self._create_finding(
            finding_type=GapFindingType.ANOMALOUS_SYSTEM,
            severity=severity,
            confidence=confidence,
            entity_type='system',
            entity_value=profile.hostname,
            entity_id=profile.system_id,
            summary=summary,
            details=details,
            behavioral_context=behavioral_context,
            peer_comparison=peer_comparison,
            time_window_start=profile.profile_period_start,
            time_window_end=profile.profile_period_end,
            event_count=profile.total_events
        )
