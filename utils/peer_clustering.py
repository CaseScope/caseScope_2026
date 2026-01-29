"""Peer Group Clustering for CaseScope

Clusters users and systems into peer groups based on behavioral similarity.
Uses K-means clustering on behavioral feature vectors.
Peer groups enable "this user is acting differently than similar users" analysis.
"""

import logging
from datetime import datetime
from typing import Dict, List, Optional, Any
import statistics

import numpy as np
from sklearn.cluster import KMeans
from sklearn.metrics import silhouette_score
from sklearn.preprocessing import MinMaxScaler

from models.database import db
from models.behavioral_profiles import (
    UserBehaviorProfile, SystemBehaviorProfile,
    PeerGroup, PeerGroupMember
)
from config import Config

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
            features = [
                profile.avg_daily_logons or 0,
                profile.failure_rate or 0,
                profile.unique_hosts_accessed or 0,
                profile.off_hours_percentage or 0,
                self._encode_auth_type(profile.auth_types)
            ]
            
            # Skip profiles with no meaningful data
            if sum(features) == 0:
                continue
            
            feature_list.append(features)
            profile_ids.append(profile.id)
        
        if not feature_list:
            return None, None
        
        return np.array(feature_list), profile_ids
    
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
            
            features = [
                mean_daily_auth,
                profile.unique_users or 0,
                self._encode_system_role(profile.system_role),
                profile.total_events or 0
            ]
            
            # Skip profiles with no meaningful data
            if sum(features) == 0:
                continue
            
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
        
        unique_labels = set(labels)
        groups_created = 0
        
        # Build profile lookup
        profile_lookup = {p.id: p for p in profiles}
        
        for label in unique_labels:
            if label == -1:
                group_name = f"{group_type}_outliers"
            else:
                group_name = f"{group_type}_cluster_{label + 1}"
            
            # Get members of this cluster
            member_indices = [i for i, l in enumerate(labels) if l == label]
            
            if len(member_indices) < self.min_group_size and label != -1:
                # Merge small clusters with nearest cluster
                continue
            
            # Calculate group statistics
            member_profiles = [profile_lookup[profile_ids[i]] for i in member_indices]
            group_stats = self._calculate_peer_statistics(member_profiles, group_type)
            
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
            for idx in member_indices:
                profile_id = profile_ids[idx]
                profile = profile_lookup[profile_id]
                
                # Calculate z-scores for this member
                z_scores = self._calculate_z_scores(profile, group_stats, group_type)
                
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
                    z_scores=z_scores
                )
                db.session.add(member)
                
                # Update profile with peer group reference
                profile.peer_group_id = peer_group.id
            
            groups_created += 1
        
        return groups_created
    
    def _calculate_peer_statistics(self, profiles: list, group_type: str) -> Dict[str, Any]:
        """Calculate median and std_dev for all metrics in a peer group"""
        
        if group_type == 'user':
            daily_logons = [p.avg_daily_logons or 0 for p in profiles]
            failure_rates = [p.failure_rate or 0 for p in profiles]
            unique_hosts = [p.unique_hosts_accessed or 0 for p in profiles]
            off_hours = [p.off_hours_percentage or 0 for p in profiles]
            
            return {
                'median_daily_logons': self._safe_median(daily_logons),
                'median_failure_rate': self._safe_median(failure_rates),
                'median_unique_hosts': self._safe_median(unique_hosts),
                'median_off_hours_pct': self._safe_median(off_hours),
                'std_daily_logons': self._safe_stdev(daily_logons),
                'std_failure_rate': self._safe_stdev(failure_rates),
                'profile_data': {
                    'daily_logons': {'median': self._safe_median(daily_logons), 'std': self._safe_stdev(daily_logons)},
                    'failure_rate': {'median': self._safe_median(failure_rates), 'std': self._safe_stdev(failure_rates)},
                    'unique_hosts': {'median': self._safe_median(unique_hosts), 'std': self._safe_stdev(unique_hosts)},
                    'off_hours_pct': {'median': self._safe_median(off_hours), 'std': self._safe_stdev(off_hours)}
                }
            }
        else:
            # System profiles
            unique_users = [p.unique_users or 0 for p in profiles]
            auth_volumes = []
            for p in profiles:
                vol = p.auth_destination_volume or {}
                auth_volumes.append(vol.get('mean_daily', 0))
            
            return {
                'median_daily_logons': self._safe_median(auth_volumes),  # Reusing field
                'median_unique_hosts': self._safe_median(unique_users),  # Reusing for unique_users
                'std_daily_logons': self._safe_stdev(auth_volumes),
                'profile_data': {
                    'auth_volume': {'median': self._safe_median(auth_volumes), 'std': self._safe_stdev(auth_volumes)},
                    'unique_users': {'median': self._safe_median(unique_users), 'std': self._safe_stdev(unique_users)}
                }
            }
    
    def _calculate_z_scores(self, profile, peer_stats: Dict, group_type: str) -> Dict[str, float]:
        """
        Calculate z-score for each metric: (value - median) / std_dev
        """
        z_scores = {}
        profile_data = peer_stats.get('profile_data', {})
        
        if group_type == 'user':
            # Daily logons z-score
            logon_stats = profile_data.get('daily_logons', {})
            z_scores['daily_logons'] = self._calc_z_score(
                profile.avg_daily_logons or 0,
                logon_stats.get('median', 0),
                logon_stats.get('std', 1)
            )
            
            # Failure rate z-score
            failure_stats = profile_data.get('failure_rate', {})
            z_scores['failure_rate'] = self._calc_z_score(
                profile.failure_rate or 0,
                failure_stats.get('median', 0),
                failure_stats.get('std', 1)
            )
            
            # Unique hosts z-score
            hosts_stats = profile_data.get('unique_hosts', {})
            z_scores['unique_hosts'] = self._calc_z_score(
                profile.unique_hosts_accessed or 0,
                hosts_stats.get('median', 0),
                hosts_stats.get('std', 1)
            )
            
            # Off-hours z-score
            off_hours_stats = profile_data.get('off_hours_pct', {})
            z_scores['off_hours'] = self._calc_z_score(
                profile.off_hours_percentage or 0,
                off_hours_stats.get('median', 0),
                off_hours_stats.get('std', 1)
            )
        else:
            # System z-scores
            auth_stats = profile_data.get('auth_volume', {})
            vol = profile.auth_destination_volume or {}
            z_scores['auth_volume'] = self._calc_z_score(
                vol.get('mean_daily', 0),
                auth_stats.get('median', 0),
                auth_stats.get('std', 1)
            )
            
            users_stats = profile_data.get('unique_users', {})
            z_scores['unique_users'] = self._calc_z_score(
                profile.unique_users or 0,
                users_stats.get('median', 0),
                users_stats.get('std', 1)
            )
        
        return z_scores
    
    def _calc_z_score(self, value: float, median: float, std: float) -> float:
        """Calculate z-score with protection against division by zero"""
        if std == 0 or std is None:
            return 0.0
        return round((value - median) / std, 2)
    
    def _safe_median(self, values: list) -> float:
        """Calculate median with empty list protection"""
        if not values:
            return 0.0
        return round(statistics.median(values), 2)
    
    def _safe_stdev(self, values: list) -> float:
        """Calculate standard deviation with protection"""
        if len(values) < 2:
            return 0.0
        return round(statistics.stdev(values), 2)
    
    def _clear_existing_groups(self):
        """Clear existing peer groups for this case"""
        # Delete members first (cascade should handle this but being explicit)
        existing_groups = PeerGroup.query.filter_by(case_id=self.case_id).all()
        for group in existing_groups:
            PeerGroupMember.query.filter_by(peer_group_id=group.id).delete()
        
        PeerGroup.query.filter_by(case_id=self.case_id).delete()
        
        # Reset profile peer_group_id references
        UserBehaviorProfile.query.filter_by(case_id=self.case_id).update({'peer_group_id': None})
        SystemBehaviorProfile.query.filter_by(case_id=self.case_id).update({'peer_group_id': None})
        
        db.session.commit()
