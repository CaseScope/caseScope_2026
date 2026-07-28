"""Stateful Brute Force Detector for CaseScope

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
from utils.stateful_detectors import BaseGapDetector
from utils.stateful_detectors.auth_events import (
    build_target_slot_query,
    resolve_thresholds,
    slot_query_parameters,
)
from utils.stateful_detectors.sliding_window import (
    collapse_to_strongest,
    find_window_candidates,
    group_slots_by_key,
    ordered_intervals,
)
from config import Config

logger = logging.getLogger(__name__)


class BruteForceDetector(BaseGapDetector):
    """
    Detects brute force attacks against individual accounts.
    
    Brute force = many password attempts against single username.
    Also detects distributed brute force (multiple sources → single target).
    """
    
    # Each threshold names the configuration attribute that carries it and the
    # documented default. These were previously duplicated in a dictionary the
    # configuration silently overrode: the code documented 8 attempts at a 90
    # percent failure rate while configuration supplied 20 at 95 percent, and
    # configuration always won because its attribute was always present, so no
    # brute-force candidate was ever found on any case in the corpus.
    THRESHOLD_SPEC = {
        'min_attempts': ('BRUTE_MIN_ATTEMPTS', 8),
        'min_failure_rate': ('BRUTE_MIN_FAILURE_RATE', 0.90),
        'time_window_hours': ('BRUTE_TIME_WINDOW_HOURS', 1),
        'distributed_source_threshold': ('BRUTE_DISTRIBUTED_THRESHOLD', 3),
        'timing_std_threshold': ('BRUTE_TIMING_STD_THRESHOLD', 5.0),
    }

    SLOT_MINUTES = 15
    
    def __init__(self, case_id: int, analysis_id: str, thresholds: Dict = None):
        super().__init__(case_id, analysis_id)

        self.thresholds = resolve_thresholds(Config, self.THRESHOLD_SPEC, thresholds)
    
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
        Find accounts that accumulated many failures in a short span.

        Activity is read per account per short slot and a detection window is
        slid across those slots, so an attack straddling the boundary of a
        fixed bucket is no longer split into two halves that each fall under
        the thresholds.
        """
        client = self._get_clickhouse_client()

        min_attempts = self.thresholds['min_attempts']
        min_failure_rate = self.thresholds['min_failure_rate']
        window = timedelta(hours=max(float(self.thresholds['time_window_hours']), 0.25))

        query = build_target_slot_query(self.SLOT_MINUTES)
        result = client.query(query, parameters=slot_query_parameters(self.case_id))

        candidates = []
        for username, slots in group_slots_by_key(result.result_rows).items():
            strongest = collapse_to_strongest(find_window_candidates(
                key=username,
                slots=slots,
                window=window,
                min_failures=int(min_attempts),
                min_failure_rate=float(min_failure_rate),
            ))
            if not strongest:
                continue

            sources = sorted(
                source for source in strongest.peers if source != 'unknown'
            )
            candidates.append({
                'username': username,
                'source_count': len(sources),
                'total_attempts': strongest.attempts,
                'failures': strongest.failures,
                'successes': strongest.successes,
                'first_attempt': strongest.first_event,
                'last_attempt': strongest.last_event,
                'duration_seconds': strongest.duration_seconds,
                'source_ips_sampled': sources,
                'attempt_sample': strongest.sample,
                'burst_count': strongest.burst_count,
                'failures_all_bursts': strongest.failures_all_bursts,
            })

        candidates.sort(key=lambda c: c['failures'], reverse=True)
        return candidates[:100]
    
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
        timing_analysis = self._analyze_timing(candidate.get('attempt_sample', []))
        
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
        
        burst_count = candidate.get('burst_count', 1)
        if burst_count > 1:
            summary += f" in the heaviest of {burst_count} bursts"
        
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
            'timing_analysis': timing_analysis,
            'burst_count': candidate.get('burst_count', 1),
            'failures_all_bursts': candidate.get('failures_all_bursts', failures),
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
        threshold = self.thresholds['distributed_source_threshold']

        # Placeholder and loopback sources are already excluded when the source
        # identity is resolved, and attempts whose source could not be recovered
        # are counted separately rather than as a distinct source.
        return candidate.get('source_count', 0) >= threshold
    
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
    
    def _analyze_timing(self, attempt_sample: List) -> Dict[str, Any]:
        """Analyze timing patterns for scripted behavior.

        Takes a sample of (timestamp, source) pairs, ordered here. The
        timestamps and sources used to be collected as two separate aggregates
        with no common ordering, so the intervals were differences between
        arbitrarily permuted times.
        """
        intervals = ordered_intervals(attempt_sample or [])

        if len(intervals) < 2:
            return {'mean_interval': 0, 'std_interval': 999, 'is_scripted': False}

        mean_interval = statistics.mean(intervals)
        std_interval = statistics.stdev(intervals)

        # Low standard deviation suggests a scripted attack
        is_scripted = std_interval < float(self.thresholds.get('timing_std_threshold', 5.0))

        return {
            'mean_interval': round(mean_interval, 2),
            'std_interval': round(std_interval, 2),
            'is_scripted': is_scripted,
            'sampled_attempts': len(intervals) + 1,
        }
    
    def _calculate_confidence(self, metrics: Dict) -> float:
        """
        Confidence scoring for brute force.
        """
        # Clearing both detection thresholds inside one window is itself
        # evidence, so it carries a base score. Without it the bands below
        # could not reach the reporting floor of 30 for a candidate that only
        # just qualified, which meant lowering the thresholds to the documented
        # values would have admitted candidates that were then all discarded.
        score = 20

        min_attempts = float(self.thresholds.get('min_attempts', 8)) or 8
        min_failure_rate = float(self.thresholds.get('min_failure_rate', 0.90))
        
        # Failure count, measured against the threshold rather than fixed counts
        failures = metrics.get('failures', 0)
        if failures >= min_attempts * 10:
            score += 20
        elif failures >= min_attempts * 5:
            score += 15
        elif failures >= min_attempts * 2:
            score += 12
        else:
            score += 8
        
        # Failure rate, measured against the threshold
        failure_rate = metrics.get('failure_rate', 0)
        midpoint = min_failure_rate + (1.0 - min_failure_rate) / 2
        if failure_rate > 0.99:
            score += 15
        elif failure_rate >= midpoint:
            score += 10
        else:
            score += 6
        
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
