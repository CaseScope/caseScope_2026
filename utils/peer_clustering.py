"""Peer Group Clustering for CaseScope

Clusters users and systems into peer groups based on behavioral similarity.
Uses K-means clustering on behavioral feature vectors.
Peer groups enable "this user is acting differently than similar users" analysis.
"""

import logging
from datetime import datetime
from typing import Dict, List, Optional, Any

import numpy as np
from sklearn.cluster import KMeans
from sklearn.metrics import silhouette_score
from sklearn.preprocessing import MinMaxScaler

from models.database import db
from models.behavioral_profiles import (
    UserBehaviorProfile, SystemBehaviorProfile,
    PeerGroup, PeerGroupMember
)
from utils.peer_statistics import build_metric_baseline, compute_group_deviations
from config import Config

# Smallest difference from the peer median that counts as a deviation, per
# metric. Without these, a tightly grouped population has a robust spread near
# zero and reaching two hosts where the median is one scores as a large
# deviation, which buries the analyst in differences too small to act on.
DEVIATION_FLOORS = {
    'daily_logons': 5.0,
    'failure_rate': 10.0,      # percentage points
    'unique_hosts': 3.0,
    'off_hours': 15.0,         # percentage points
    'auth_volume': 5.0,
    'unique_users': 3.0,
}

# Unbounded counts are lognormal across a population, so they are compared in
# log space. Percentages are already bounded and stay on their own scale.
LOG_SCALED_METRICS = ('daily_logons', 'unique_hosts', 'auth_volume', 'unique_users')

logger = logging.getLogger(__name__)


class PeerGroupBuilder:
    """
    Clusters users and systems into peer groups based on behavioral similarity.
    
    Uses K-means clustering on behavioral feature vectors.
    Peer groups enable "this user is acting differently than similar users" analysis.
    """
    
    def __init__(self, case_id: int, analysis_id: str):
        self.case_id = case_id
        self.analysis_id = analysis_id
        
        # Configuration
        self.min_group_size = getattr(Config, 'ANALYSIS_PEER_GROUP_MIN_SIZE', 3)
        self.outlier_threshold = 4.0  # Std devs from cluster center to be outlier
        self.anomaly_threshold = getattr(Config, 'ANALYSIS_ANOMALY_Z_THRESHOLD', 3.0)
    
    def build_all_peer_groups(self) -> Dict[str, int]:
        """
        Build peer groups for both users and systems.
        
        Returns:
            dict: {
                'user_groups': int,
                'system_groups': int
            }
        """
        # Clear existing peer groups for this case
        self._clear_existing_groups()
        
        user_groups = self.build_user_peer_groups()
        system_groups = self.build_system_peer_groups()
        
        db.session.commit()
        
        return {
            'user_groups': user_groups,
            'system_groups': system_groups
        }
    
    def build_user_peer_groups(self) -> int:
        """
        Cluster users based on behavioral similarity.
        
        Features used:
        - avg_daily_logons
        - failure_rate
        - unique_hosts_accessed
        - off_hours_percentage
        - auth_type_distribution (encoded)
        
        Returns:
            int: Number of peer groups created
        """
        profiles = UserBehaviorProfile.query.filter_by(case_id=self.case_id).all()
        
        if len(profiles) < self.min_group_size:
            logger.info(f"Not enough user profiles ({len(profiles)}) for clustering")
            return 0
        
        # Extract features
        features, profile_ids = self._extract_user_features(profiles)
        
        if features is None or len(features) < self.min_group_size:
            return 0
        
        # Cluster
        labels, cluster_centers, scaler = self._cluster(features)
        
        # Create peer groups
        groups_created = self._create_peer_groups(
            'user', profiles, profile_ids, labels, cluster_centers, features, scaler
        )
        
        return groups_created
    
    def build_system_peer_groups(self) -> int:
        """
        Cluster systems based on behavioral similarity.
        
        Features used:
        - auth_volume (mean daily)
        - unique_users
        - system_role (encoded)
        
        Returns:
            int: Number of peer groups created
        """
        profiles = SystemBehaviorProfile.query.filter_by(case_id=self.case_id).all()
        
        if len(profiles) < self.min_group_size:
            logger.info(f"Not enough system profiles ({len(profiles)}) for clustering")
            return 0
        
        # Extract features
        features, profile_ids = self._extract_system_features(profiles)
        
        if features is None or len(features) < self.min_group_size:
            return 0
        
        # Cluster
        labels, cluster_centers, scaler = self._cluster(features)
        
        # Create peer groups
        groups_created = self._create_peer_groups(
            'system', profiles, profile_ids, labels, cluster_centers, features, scaler
        )
        
        return groups_created
    
    def _extract_user_features(self, profiles: List[UserBehaviorProfile]) -> tuple:
        """
        Convert user profiles to feature vectors for clustering.
        Features are normalized to 0-1 range.
        
        Returns:
            tuple: (feature_matrix, profile_ids)
        """
        feature_list = []
        profile_ids = []
        
        for profile in profiles:
            # Skip profiles carrying no activity. Testing the feature sum could
            # not do this: the auth-type encoding returns a neutral 0.5 when a
            # profile has no authentication at all, so the sum was never zero
            # and empty profiles were clustered alongside real ones, producing
            # groups whose median activity was zero.
            if not self._user_profile_has_activity(profile):
                continue

            features = [
                # Counts are heavy-tailed, so they are compressed before
                # scaling; otherwise one service account flattens everyone else
                # into a single indistinguishable band.
                self._compress_count(profile.avg_daily_logons),
                profile.failure_rate or 0,
                self._compress_count(profile.unique_hosts_accessed),
                profile.off_hours_percentage or 0,
                self._encode_auth_type(profile.auth_types)
            ]
            
            feature_list.append(features)
            profile_ids.append(profile.id)
        
        if not feature_list:
            return None, None
        
        return np.array(feature_list), profile_ids

    @staticmethod
    def _compress_count(value) -> float:
        """Log-compress a count so heavy tails do not dominate the scaler."""
        return float(np.log1p(max(float(value or 0), 0.0)))

    @staticmethod
    def _user_profile_has_activity(profile) -> bool:
        return bool(
            (profile.total_events or 0)
            or (profile.avg_daily_logons or 0)
            or (profile.unique_hosts_accessed or 0)
            or (profile.off_hours_percentage or 0)
            or (profile.failure_rate or 0)
        )
    
    def _extract_system_features(self, profiles: List[SystemBehaviorProfile]) -> tuple:
        """
        Convert system profiles to feature vectors for clustering.
        
        Returns:
            tuple: (feature_matrix, profile_ids)
        """
        feature_list = []
        profile_ids = []
        
        for profile in profiles:
            # Extract auth volume
            auth_vol = profile.auth_destination_volume or {}
            mean_daily_auth = auth_vol.get('mean_daily', 0)

            # As with users, the role encoding returns a neutral 0.5 for an
            # unknown role, so the feature sum could never be zero and could
            # not identify an empty profile.
            if not (profile.total_events or 0) and not mean_daily_auth:
                continue
            
            features = [
                self._compress_count(mean_daily_auth),
                self._compress_count(profile.unique_users),
                self._encode_system_role(profile.system_role),
                self._compress_count(profile.total_events)
            ]
            
            feature_list.append(features)
            profile_ids.append(profile.id)
        
        if not feature_list:
            return None, None
        
        return np.array(feature_list), profile_ids
    
    def _encode_auth_type(self, auth_types: Dict) -> float:
        """
        Encode auth type distribution as a single feature.
        
        Higher value = more Kerberos (typical enterprise)
        Lower value = more NTLM (potentially legacy/suspicious)
        """
        if not auth_types:
            return 0.5  # Neutral
        
        kerberos_pct = auth_types.get('KERBEROS', 0)
        ntlm_pct = auth_types.get('NTLM', 0) + auth_types.get('NTLMSSP', 0)
        
        total = kerberos_pct + ntlm_pct
        if total == 0:
            return 0.5
        
        # Return ratio (0 = all NTLM, 1 = all Kerberos)
        return kerberos_pct / total
    
    def _encode_system_role(self, role: str) -> float:
        """Encode system role as numeric feature"""
        role_map = {
            'domain_controller': 1.0,
            'server': 0.7,
            'workstation': 0.3,
            'unknown': 0.5
        }
        return role_map.get(role, 0.5)
    
    def _cluster(self, features: np.ndarray) -> tuple:
        """
        Perform clustering on feature matrix.
        
        Uses silhouette score to select optimal K (2-10 range).
        Entities > 4 std_dev from all clusters go to 'outlier' group.
        
        Returns:
            tuple: (labels, cluster_centers, scaler)
        """
        # Normalize features
        scaler = MinMaxScaler()
        features_scaled = scaler.fit_transform(features)
        
        n_samples = len(features_scaled)
        
        # Determine K range
        min_k = 2
        max_k = min(10, n_samples // 3, n_samples - 1)
        
        if max_k < min_k:
            # Not enough samples for multiple clusters
            labels = np.zeros(n_samples, dtype=int)
            centers = features_scaled.mean(axis=0).reshape(1, -1)
            return labels, centers, scaler
        
        # Find optimal K using silhouette score
        best_k = min_k
        best_score = -1
        
        for k in range(min_k, max_k + 1):
            try:
                kmeans = KMeans(n_clusters=k, random_state=42, n_init=10)
                labels = kmeans.fit_predict(features_scaled)
                
                # Check if we have more than one cluster in practice
                if len(set(labels)) > 1:
                    score = silhouette_score(features_scaled, labels)
                    if score > best_score:
                        best_score = score
                        best_k = k
            except Exception as e:
                logger.warning(f"Clustering failed for k={k}: {e}")
                continue
        
        # Final clustering with best K
        kmeans = KMeans(n_clusters=best_k, random_state=42, n_init=10)
        labels = kmeans.fit_predict(features_scaled)
        
        # Identify outliers (> 4 std dev from nearest center)
        for i, (point, label) in enumerate(zip(features_scaled, labels)):
            center = kmeans.cluster_centers_[label]
            distance = np.linalg.norm(point - center)
            
            # Calculate threshold based on cluster spread
            cluster_points = features_scaled[labels == label]
            if len(cluster_points) > 1:
                cluster_distances = [np.linalg.norm(p - center) for p in cluster_points]
                threshold = np.mean(cluster_distances) + (self.outlier_threshold * np.std(cluster_distances))
                
                if distance > threshold:
                    labels[i] = -1  # Mark as outlier
        
        return labels, kmeans.cluster_centers_, scaler
    
    def _create_peer_groups(self, group_type: str, profiles: list, profile_ids: list,
                           labels: np.ndarray, centers: np.ndarray,
                           features: np.ndarray, scaler) -> int:
        """Create peer group records and member associations"""

        cluster_members = {
            label: [i for i, cluster_label in enumerate(labels) if cluster_label == label]
            for label in set(labels)
        }
        eligible_labels = {
            label
            for label, member_indices in cluster_members.items()
            if label != -1 and len(member_indices) >= self.min_group_size
        }
        for label, member_indices in cluster_members.items():
            if label == -1 or len(member_indices) >= self.min_group_size:
                continue

            if eligible_labels:
                nearest_label = min(
                    eligible_labels,
                    key=lambda candidate: np.linalg.norm(centers[label] - centers[candidate]),
                )
                for idx in member_indices:
                    labels[idx] = nearest_label
            else:
                for idx in member_indices:
                    labels[idx] = -1

        unique_labels = set(labels)
        groups_created = 0
        
        # Build profile lookup
        profile_lookup = {p.id: p for p in profiles}

        # An outlier has, by definition, no close peers, so comparing it to the
        # other outliers tells us nothing. Outliers are measured against the
        # whole profiled population instead.
        all_profiles = [profile_lookup[profile_id] for profile_id in profile_ids]
        population_values = self._metric_values(all_profiles, group_type)
        
        for label in unique_labels:
            if label == -1:
                group_name = f"{group_type}_outliers"
            else:
                group_name = f"{group_type}_cluster_{label + 1}"
            
            # Get members of this cluster
            member_indices = [i for i, l in enumerate(labels) if l == label]
            
            # Calculate group statistics
            member_profiles = [profile_lookup[profile_ids[i]] for i in member_indices]
            metric_values = self._metric_values(member_profiles, group_type)
            group_stats = self._calculate_peer_statistics(metric_values, group_type)
            
            # Create peer group
            peer_group = PeerGroup(
                case_id=self.case_id,
                group_type=group_type,
                group_name=group_name,
                member_count=len(member_indices),
                **group_stats
            )
            db.session.add(peer_group)
            db.session.flush()  # Get ID
            
            # Create member records and update profiles
            for position, idx in enumerate(member_indices):
                profile_id = profile_ids[idx]
                profile = profile_lookup[profile_id]

                if label == -1:
                    comparison_values = population_values
                    comparison_index = idx
                else:
                    comparison_values = metric_values
                    comparison_index = position

                deviation_scores = self._calculate_deviation_scores(
                    comparison_values, comparison_index
                )
                
                # Calculate similarity to cluster center
                if label != -1:
                    center = centers[label]
                    point = scaler.transform(features[idx:idx+1])[0]
                    similarity = 1 / (1 + np.linalg.norm(point - center))
                else:
                    similarity = 0.0
                
                member = PeerGroupMember(
                    peer_group_id=peer_group.id,
                    entity_type=group_type,
                    entity_id=profile.user_id if group_type == 'user' else profile.system_id,
                    similarity_score=float(similarity),
                    z_scores=deviation_scores
                )
                db.session.add(member)
                
                # Update profile with peer group reference
                profile.peer_group_id = peer_group.id
            
            groups_created += 1
        
        return groups_created

    def _metric_values(self, profiles: list, group_type: str) -> Dict[str, List[Optional[float]]]:
        """Collect each comparison metric across a set of profiles, in order.

        Authentication metrics are left as None for accounts and hosts that
        never authenticated, so they contribute nothing to an authentication
        baseline. Around a third of profiled accounts on a real case have no
        logon or failure events at all, and counting them as zero pulled every
        authentication median to the floor and made ordinary accounts look like
        outliers.
        """
        if group_type == 'user':
            def auth_metric(profile, value):
                return float(value or 0) if self._user_has_authentication(profile) else None

            return {
                'daily_logons': [auth_metric(p, p.avg_daily_logons) for p in profiles],
                'failure_rate': [auth_metric(p, p.failure_rate) for p in profiles],
                'unique_hosts': [auth_metric(p, p.unique_hosts_accessed) for p in profiles],
                # Off-hours activity applies to any profile that saw events.
                'off_hours': [float(p.off_hours_percentage or 0) for p in profiles],
            }

        auth_volumes = [
            float((p.auth_destination_volume or {}).get('mean_daily', 0) or 0)
            for p in profiles
        ]
        return {
            'auth_volume': [value if value else None for value in auth_volumes],
            'unique_users': [
                float(p.unique_users or 0) if (p.unique_users or 0) else None
                for p in profiles
            ],
        }

    @staticmethod
    def _user_has_authentication(profile) -> bool:
        """Whether this account produced any logon or logon-failure events."""
        return bool(
            (profile.total_logons or 0)
            or (getattr(profile, 'avg_daily_failures', 0) or 0)
            or (profile.failure_rate or 0)
            or (profile.unique_hosts_accessed or 0)
        )

    def _calculate_deviation_scores(
        self, metric_values: Dict[str, List[Optional[float]]], entity_index: int
    ) -> Dict[str, float]:
        """Score one member against its peers on every metric, leaving it out.

        The stored shape stays a flat metric-to-number map, but each number is
        now a leave-one-out robust deviation rather than a value measured
        against a baseline the entity was part of.
        """
        deviations = compute_group_deviations(
            metric_values=metric_values,
            entity_index=entity_index,
            configured_threshold=self.anomaly_threshold,
            absolute_floors=DEVIATION_FLOORS,
            log_scaled_metrics=LOG_SCALED_METRICS,
        )
        return {
            metric: round(deviation.score, 2)
            for metric, deviation in deviations.items()
        }
    
    def _calculate_peer_statistics(
        self, metric_values: Dict[str, List[float]], group_type: str
    ) -> Dict[str, Any]:
        """Summarize a peer group's metrics with a median and a robust spread.

        The spread stored alongside each median is the median absolute
        deviation rather than the standard deviation. Pairing a median with a
        standard deviation meant a single high-volume member produced a median
        near zero and a spread in the hundreds, against which nothing else in
        the group could deviate.
        """
        baselines = {
            metric: build_metric_baseline(metric, values)
            for metric, values in metric_values.items()
        }
        profile_data = {
            metric: baseline.as_summary() for metric, baseline in baselines.items()
        }

        def _median(metric: str) -> float:
            baseline = baselines.get(metric)
            return round(baseline.median, 2) if baseline else 0.0

        def _spread(metric: str) -> float:
            baseline = baselines.get(metric)
            return round(baseline.mad, 2) if baseline else 0.0

        if group_type == 'user':
            return {
                'median_daily_logons': _median('daily_logons'),
                'median_failure_rate': _median('failure_rate'),
                'median_unique_hosts': _median('unique_hosts'),
                'median_off_hours_pct': _median('off_hours'),
                'std_daily_logons': _spread('daily_logons'),
                'std_failure_rate': _spread('failure_rate'),
                'profile_data': profile_data,
            }

        return {
            # These two columns are shared with the user groups, so the system
            # equivalents are stored in them.
            'median_daily_logons': _median('auth_volume'),
            'median_unique_hosts': _median('unique_users'),
            'std_daily_logons': _spread('auth_volume'),
            'profile_data': profile_data,
        }
    
    def _clear_existing_groups(self):
        """Clear existing peer groups for this case.

        References are dropped before the rows they point at, so the deletes do
        not depend on every statement landing in one transaction before the
        database checks them.
        """
        UserBehaviorProfile.query.filter_by(case_id=self.case_id).update({'peer_group_id': None})
        SystemBehaviorProfile.query.filter_by(case_id=self.case_id).update({'peer_group_id': None})
        db.session.flush()

        existing_groups = PeerGroup.query.filter_by(case_id=self.case_id).all()
        for group in existing_groups:
            PeerGroupMember.query.filter_by(peer_group_id=group.id).delete()

        PeerGroup.query.filter_by(case_id=self.case_id).delete()
        
        db.session.commit()
