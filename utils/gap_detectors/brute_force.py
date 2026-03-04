"""Brute Force Detector for CaseScope

Detects brute force attacks against individual accounts.

Brute force = many password attempts against single username.
Also detects distributed brute force (multiple sources → single target).
"""

import logging
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
import statistics

from models.behavioral_profiles import (
    GapDetectionFinding, GapFindingType, UserBehaviorProfile
)
from utils.gap_detectors import BaseGapDetector
from config import Config

logger = logging.getLogger(__name__)


class BruteForceDetector(BaseGapDetector):
    """
    Detects brute force attacks against individual accounts.
    
    Brute force = many password attempts against single username.
    Also detects distributed brute force (multiple sources → single target).
    """
    
    DEFAULT_THRESHOLDS = {
        'min_attempts': 20,               # Minimum attempts against single user
        'min_failure_rate': 0.95,         # 95% failure rate
        'time_window_hours': 1,           # Time window for grouping
        'distributed_source_threshold': 3  # 3+ sources = distributed attack
    }
    
    def __init__(self, case_id: int, analysis_id: str, thresholds: Dict = None):
        super().__init__(case_id, analysis_id)
        
        # Load thresholds from config or use defaults
        self.thresholds = {
            'min_attempts': getattr(Config, 'BRUTE_MIN_ATTEMPTS', 
                                   self.DEFAULT_THRESHOLDS['min_attempts']),
            'min_failure_rate': getattr(Config, 'BRUTE_MIN_FAILURE_RATE', 
                                        self.DEFAULT_THRESHOLDS['min_failure_rate']),
            'time_window_hours': getattr(Config, 'BRUTE_TIME_WINDOW_HOURS', 
                                         self.DEFAULT_THRESHOLDS['time_window_hours']),
            'distributed_source_threshold': getattr(Config, 'BRUTE_DISTRIBUTED_THRESHOLD', 
                                                    self.DEFAULT_THRESHOLDS['distributed_source_threshold'])
        }
        
        # Override with provided thresholds
        if thresholds:
            self.thresholds.update(thresholds)
    
    def detect(self) -> List[GapDetectionFinding]:
        """
        Main entry point.
        
        Returns:
            list[GapDetectionFinding]: Brute force findings
        """
        findings = []
        
        # Find brute force candidates
        candidates = self._find_brute_candidates()
        
        for candidate in candidates:
            finding = self._analyze_candidate(candidate)
            if finding:
                findings.append(finding)
        
        logger.info(f"Brute force detection complete: {len(findings)} findings from {len(candidates)} candidates")
        return findings
    
    def _find_brute_candidates(self) -> List[Dict]:
        """
        Query ClickHouse for users with high failure counts.
        """
        client = self._get_clickhouse_client()
        
        min_attempts = self.thresholds['min_attempts']
        min_failure_rate = self.thresholds['min_failure_rate']
        
        query = f"""
            SELECT 
                username,
                count(DISTINCT src_ip) as source_count,
                count() as total_attempts,
                countIf(event_id IN ('4625', '18456')) as failures,
                countIf(event_id = '4624') as successes,
                min(timestamp) as first_attempt,
                max(timestamp) as last_attempt,
                dateDiff('second', min(timestamp), max(timestamp)) as duration_seconds,
                groupArray(50)(src_ip) as source_ips_sampled,
                groupArray(50)(timestamp) as timestamps_sampled
            FROM events
            WHERE case_id = {self.case_id}
              AND event_id IN ('4624', '4625', '18456')
              AND username != ''
              AND username NOT LIKE '%$'
              AND username NOT LIKE '##%%'
            GROUP BY username
            HAVING failures >= {min_attempts}
               AND failures / (failures + successes + 0.001) >= {min_failure_rate}
            ORDER BY failures DESC
            LIMIT 100
        """
        
        try:
            result = client.query(query)
            candidates = []
            
            for row in result.result_rows:
                candidates.append({
                    'username': row[0],
                    'source_count': row[1],
                    'total_attempts': row[2],
                    'failures': row[3],
                    'successes': row[4],
                    'first_attempt': row[5],
                    'last_attempt': row[6],
                    'duration_seconds': row[7],
                    'source_ips_sampled': [str(ip) for ip in row[8]] if len(row) > 8 else [],
                    'timestamps_sampled': row[9] if len(row) > 9 else []
                })
            
            return candidates
            
        except Exception as e:
            logger.error(f"Failed to find brute force candidates: {e}")
            return []
    
    def _analyze_candidate(self, candidate: Dict) -> Optional[GapDetectionFinding]:
        """
        Deep analysis of brute force candidate.
        """
        username = candidate['username']
        source_count = candidate['source_count']
        total_attempts = candidate['total_attempts']
        failures = candidate['failures']
        successes = candidate['successes']
        
        # Calculate failure rate
        failure_rate = failures / (failures + successes) if (failures + successes) > 0 else 0
        
        # Check if distributed attack
        is_distributed = self._detect_distributed_attack(candidate)
        
        # Check user baseline
        baseline = self._check_user_baseline(username)
        
        # Analyze timing
        timing_analysis = self._analyze_timing(candidate.get('timestamps_sampled', []))
        
        # Calculate confidence
        confidence_metrics = {
            'failures': failures,
            'failure_rate': failure_rate,
            'is_distributed': is_distributed,
            'source_count': source_count,
            'timing_std': timing_analysis.get('std_interval', 999),
            'is_scripted': timing_analysis.get('is_scripted', False),
            'baseline_deviation': baseline.get('deviation_factor', 1),
            'successes': successes
        }
        
        confidence = self._calculate_confidence(confidence_metrics)
        
        if confidence < 30:
            return None
        
        # Determine finding type and severity
        if is_distributed:
            finding_type = GapFindingType.DISTRIBUTED_BRUTE_FORCE
            severity = 'critical' if successes > 0 else 'high'
        else:
            finding_type = GapFindingType.BRUTE_FORCE
            if confidence >= 75:
                severity = 'critical' if successes > 0 else 'high'
            elif confidence >= 50:
                severity = 'high'
            else:
                severity = 'medium'
        
        # Build summary
        if is_distributed:
            summary = f"Distributed brute force against {username}: {failures} failures from {source_count} sources"
        else:
            summary = f"Brute force against {username}: {failures} failures"
        
        if successes > 0:
            summary += f" - ACCOUNT COMPROMISED ({successes} successful logins)"
        
        # Build details
        details = {
            'username': username,
            'source_count': source_count,
            'total_attempts': total_attempts,
            'failures': failures,
            'successes': successes,
            'failure_rate': round(failure_rate * 100, 1),
            'duration_seconds': candidate.get('duration_seconds', 0),
            'is_distributed': is_distributed,
            'timing_analysis': timing_analysis
        }
        
        # Build evidence
        unique_sources = list(set(candidate.get('source_ips_sampled', [])))
        evidence = {
            'source_ips': unique_sources[:10],
            'first_attempt': candidate.get('first_attempt').isoformat() if candidate.get('first_attempt') else None,
            'last_attempt': candidate.get('last_attempt').isoformat() if candidate.get('last_attempt') else None
        }
        
        # Behavioral context
        behavioral_context = None
        if baseline.get('has_baseline'):
            behavioral_context = {
                'baseline_daily_failures': baseline.get('baseline_daily_failures', 0),
                'current_failures': failures,
                'deviation_factor': baseline.get('deviation_factor', 1)
            }
        
        # Suggested IOCs
        suggested_iocs = [
            {'type': 'user_account', 'value': username, 'reason': 'Account targeted in brute force attack'}
        ]
        
        # Add source IPs as IOCs for distributed attacks
        if is_distributed:
            for ip in unique_sources[:5]:
                if ip and ip not in ['0.0.0.0', '::']:
                    suggested_iocs.append({
                        'type': 'ip_address',
                        'value': ip,
                        'reason': f'Source of distributed brute force against {username}'
                    })
        
        # Get user entity ID if exists
        user_entity_id = None
        from models.known_user import KnownUser
        known_user = KnownUser.query.filter_by(
            case_id=self.case_id
        ).filter(
            KnownUser.username.ilike(username)
        ).first()
        if known_user:
            user_entity_id = known_user.id
        
        return self._create_finding(
            finding_type=finding_type,
            severity=severity,
            confidence=confidence,
            entity_type='user',
            entity_value=username,
            entity_id=user_entity_id,
            summary=summary,
            details=details,
            evidence=evidence,
            behavioral_context=behavioral_context,
            affected_entities={'source_ips': unique_sources},
            time_window_start=candidate.get('first_attempt'),
            time_window_end=candidate.get('last_attempt'),
            event_count=total_attempts,
            suggested_iocs=suggested_iocs
        )
    
    def _detect_distributed_attack(self, candidate: Dict) -> bool:
        """
        Check if multiple source IPs are targeting same user.
        
        Returns:
            bool: True if distributed attack pattern detected
        """
        source_count = candidate.get('source_count', 0)
        threshold = self.thresholds['distributed_source_threshold']
        
        if source_count < threshold:
            return False
        
        # Check if sources are actually different (not just variations)
        source_ips = candidate.get('source_ips_sampled', [])
        unique_sources = set()
        
        for ip in source_ips:
            ip_str = str(ip).strip()
            if ip_str and ip_str not in ['0.0.0.0', '::', '', 'None']:
                unique_sources.add(ip_str)
        
        return len(unique_sources) >= threshold
    
    def _check_user_baseline(self, username: str) -> Dict[str, Any]:
        """
        Compare to user's normal failure rate from behavioral profile.
        """
        # Look up user's behavioral profile
        from models.known_user import KnownUser
        
        known_user = KnownUser.query.filter_by(
            case_id=self.case_id
        ).filter(
            KnownUser.username.ilike(username)
        ).first()
        
        if not known_user:
            return {'has_baseline': False}
        
        profile = UserBehaviorProfile.query.filter_by(
            case_id=self.case_id,
            user_id=known_user.id
        ).first()
        
        if not profile or not profile.avg_daily_failures:
            return {'has_baseline': False}
        
        baseline_daily_failures = profile.avg_daily_failures
        
        return {
            'has_baseline': True,
            'baseline_daily_failures': baseline_daily_failures,
            'deviation_factor': 1  # Would need current count vs baseline calculation
        }
    
    def _analyze_timing(self, timestamps: List) -> Dict[str, Any]:
        """Analyze timing patterns for scripted behavior"""
        if not timestamps or len(timestamps) < 3:
            return {'mean_interval': 0, 'std_interval': 999, 'is_scripted': False}
        
        try:
            sorted_ts = sorted(timestamps)
            intervals = []
            
            for i in range(1, len(sorted_ts)):
                if sorted_ts[i] and sorted_ts[i-1]:
                    diff = (sorted_ts[i] - sorted_ts[i-1]).total_seconds()
                    if 0 < diff < 3600:
                        intervals.append(diff)
            
            if len(intervals) < 2:
                return {'mean_interval': 0, 'std_interval': 999, 'is_scripted': False}
            
            mean_interval = statistics.mean(intervals)
            std_interval = statistics.stdev(intervals)
            
            # Low standard deviation suggests scripted/automated attack
            is_scripted = std_interval < 5.0  # Less than 5 seconds std
            
            return {
                'mean_interval': round(mean_interval, 2),
                'std_interval': round(std_interval, 2),
                'is_scripted': is_scripted
            }
        except Exception as e:
            logger.warning(f"Timing analysis failed: {e}")
            return {'mean_interval': 0, 'std_interval': 999, 'is_scripted': False}
    
    def _calculate_confidence(self, metrics: Dict) -> float:
        """
        Confidence scoring for brute force.
        """
        score = 0
        
        # High failure count: +20
        failures = metrics.get('failures', 0)
        if failures > 100:
            score += 20
        elif failures > 50:
            score += 15
        elif failures >= 20:
            score += 10
        
        # Very high failure rate: +15
        failure_rate = metrics.get('failure_rate', 0)
        if failure_rate > 0.99:
            score += 15
        elif failure_rate > 0.95:
            score += 10
        
        # Distributed attack: +15
        if metrics.get('is_distributed'):
            score += 15
            # Additional for many sources
            if metrics.get('source_count', 0) > 5:
                score += 5
        
        # Scripted timing: +10
        if metrics.get('is_scripted'):
            score += 10
        
        # Successful compromise: +20 (very concerning)
        if metrics.get('successes', 0) > 0:
            score += 20
        
        # Baseline deviation: +5-10
        deviation = metrics.get('baseline_deviation', 1)
        if deviation > 10:
            score += 10
        elif deviation > 5:
            score += 5
        
        return min(100, score)
