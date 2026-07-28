"""Stateful Password Spraying Detector for CaseScope

Detects password spraying attacks through statistical analysis.

Password spraying = single source attempting many usernames with few passwords.
Hayabusa may miss this if individual events don't meet single-event rule thresholds.

Detection is based on aggregate behavior:
- High unique username count from single source
- High failure rate
- Scripted timing patterns
- Targeting patterns (admin accounts, dictionary usernames)
"""

import logging
import re
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
import statistics

from models.behavioral_profiles import GapDetectionFinding, GapFindingType
from utils.stateful_detectors import BaseGapDetector
from utils.stateful_detectors.auth_events import (
    build_source_slot_query,
    build_successful_accounts_query,
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


class PasswordSprayingDetector(BaseGapDetector):
    """
    Detects password spraying attacks through statistical analysis.
    
    Password spraying = single source attempting many usernames with few passwords.
    Hayabusa may miss this if individual events don't meet single-event rule thresholds.
    """
    
    # Each threshold names the configuration attribute that carries it and the
    # documented default. A contract test asserts the defaults here match the
    # defaults in Config, because when they diverged the configuration silently
    # won and the documented values became fiction.
    THRESHOLD_SPEC = {
        'min_unique_users': ('SPRAY_MIN_UNIQUE_USERS', 10),
        'min_failure_rate': ('SPRAY_MIN_FAILURE_RATE', 0.9),
        'time_window_hours': ('SPRAY_TIME_WINDOW_HOURS', 2),
        'timing_std_threshold': ('SPRAY_TIMING_STD_THRESHOLD', 5.0),
    }

    # Activity is aggregated into slots this short, then a detection window is
    # slid across them, so an attack is measured over its own span rather than
    # over whichever fixed bucket it happened to land in.
    SLOT_MINUTES = 15
    
    # Admin account patterns
    ADMIN_PATTERNS = [
        'admin', 'administrator', 'svc_', 'service_', 'root', 'domain', 
        'enterprise', 'backup', 'system', 'sqlsvc', 'iis', 'exchange'
    ]
    
    def __init__(self, case_id: int, analysis_id: str, thresholds: Dict = None):
        super().__init__(case_id, analysis_id)

        self.thresholds = resolve_thresholds(Config, self.THRESHOLD_SPEC, thresholds)
    
    def detect(self) -> List[GapDetectionFinding]:
        """
        Main entry point.
        
        Returns:
            list[GapDetectionFinding]: List of spray findings
        """
        findings = []
        
        # Find spray candidates
        candidates = self._find_spray_candidates()
        
        for candidate in candidates:
            finding = self._analyze_candidate(candidate)
            if finding:
                findings.append(finding)
        
        logger.info(f"Password spraying detection complete: {len(findings)} findings from {len(candidates)} candidates")
        return findings
    
    def _find_spray_candidates(self) -> List[Dict]:
        """
        Find sources that targeted many accounts with a high failure rate.

        Activity is read per source per short slot and a detection window is
        slid across those slots, rather than grouping directly into fixed
        detection-sized buckets.
        """
        client = self._get_clickhouse_client()

        min_unique_users = self.thresholds['min_unique_users']
        min_failure_rate = self.thresholds['min_failure_rate']
        window = timedelta(hours=max(float(self.thresholds['time_window_hours']), 0.25))

        query = build_source_slot_query(self.SLOT_MINUTES)
        result = client.query(query, parameters=slot_query_parameters(self.case_id))

        candidates = []
        for source_identity, slots in group_slots_by_key(result.result_rows).items():
            strongest = collapse_to_strongest(find_window_candidates(
                key=source_identity,
                slots=slots,
                window=window,
                min_peers=int(min_unique_users),
                min_failure_rate=float(min_failure_rate),
            ))
            if not strongest:
                continue

            candidates.append({
                'source_identity': source_identity,
                'unique_users': len(strongest.peers),
                'total_attempts': strongest.attempts,
                'failures': strongest.failures,
                'successes': strongest.successes,
                'first_attempt': strongest.first_event,
                'last_attempt': strongest.last_event,
                'duration_seconds': strongest.duration_seconds,
                'usernames_sampled': sorted(strongest.peers),
                'attempt_sample': strongest.sample,
                'burst_count': strongest.burst_count,
                'failures_all_bursts': strongest.failures_all_bursts,
            })

        candidates.sort(key=lambda c: c['unique_users'], reverse=True)
        return candidates[:100]
    
    def _analyze_candidate(self, candidate: Dict) -> Optional[GapDetectionFinding]:
        """
        Deep analysis of a spray candidate.
        
        Analyzes:
        - Timing regularity (scripted vs manual)
        - Username patterns (dictionary, sequential, admin-targeting)
        - Success analysis (which accounts succeeded?)
        - Baseline comparison (is this source normally active?)
        """
        source_identity = candidate['source_identity']
        unique_users = candidate['unique_users']
        total_attempts = candidate['total_attempts']
        failures = candidate['failures']
        successes = candidate['successes']
        
        # Calculate failure rate
        failure_rate = failures / (failures + successes) if (failures + successes) > 0 else 0
        
        # Analyze timing patterns
        timing_analysis = self._analyze_timing_pattern(candidate.get('attempt_sample', []))
        
        # Analyze username patterns
        username_analysis = self._analyze_username_patterns(candidate.get('usernames_sampled', []))
        
        # Calculate confidence score
        confidence_metrics = {
            'unique_users': unique_users,
            'failure_rate': failure_rate,
            'is_scripted': timing_analysis.get('is_scripted', False),
            'timing_std': timing_analysis.get('std_interval', 999),
            'targets_admin_accounts': username_analysis.get('targets_admin_accounts', False),
            'has_dictionary_pattern': username_analysis.get('has_dictionary_pattern', False),
            'total_attempts': total_attempts,
            'successes': successes
        }
        
        confidence = self._calculate_confidence(confidence_metrics)
        
        # Only create finding if confidence is meaningful
        if confidence < 30:
            return None
        
        # Determine severity
        if confidence >= 75:
            severity = 'critical' if successes > 0 else 'high'
        elif confidence >= 50:
            severity = 'high'
        else:
            severity = 'medium'
        
        # Build summary
        summary = f"Password spraying from {source_identity}: {unique_users} unique users targeted, {failures} failures"
        if successes > 0:
            summary += f", {successes} SUCCESSFUL LOGINS"
        
        # Build details
        details = {
            'unique_users': unique_users,
            'total_attempts': total_attempts,
            'failures': failures,
            'successes': successes,
            'failure_rate': round(failure_rate * 100, 1),
            'duration_seconds': candidate.get('duration_seconds', 0),
            'timing_analysis': timing_analysis,
            'username_analysis': username_analysis,
            'burst_count': candidate.get('burst_count', 1),
            'failures_all_bursts': candidate.get('failures_all_bursts', failures),
        }
        
        # Build evidence
        evidence = {
            'sample_usernames': candidate.get('usernames_sampled', [])[:20],
            'first_attempt': candidate.get('first_attempt').isoformat() if candidate.get('first_attempt') else None,
            'last_attempt': candidate.get('last_attempt').isoformat() if candidate.get('last_attempt') else None
        }
        
        # Suggested IOCs. The source is an address only when the parser could
        # fill one; on Kerberos and NTLM failures it is usually a workstation
        # name recovered from the event payload.
        suggested_iocs = [
            {
                'type': 'ip_address' if self._looks_like_ip(source_identity) else 'hostname',
                'value': source_identity,
                'reason': 'Source of password spraying attack',
            }
        ]
        
        # Add any successful accounts as IOCs
        if successes > 0:
            # Query for which accounts succeeded
            success_accounts = self._get_successful_accounts(
                source_identity,
                candidate.get('first_attempt'),
                candidate.get('last_attempt'),
            )
            for account in success_accounts[:5]:  # Limit to 5
                suggested_iocs.append({
                    'type': 'user_account',
                    'value': account,
                    'reason': 'Account compromised via password spraying'
                })
        
        return self._create_finding(
            finding_type=GapFindingType.PASSWORD_SPRAYING,
            severity=severity,
            confidence=confidence,
            entity_type='source_ip' if self._looks_like_ip(source_identity) else 'source_host',
            entity_value=source_identity,
            summary=summary,
            details=details,
            evidence=evidence,
            affected_entities={'usernames_targeted': unique_users},
            time_window_start=candidate.get('first_attempt'),
            time_window_end=candidate.get('last_attempt'),
            event_count=total_attempts,
            suggested_iocs=suggested_iocs
        )
    
    def _analyze_timing_pattern(self, attempt_sample: List) -> Dict[str, Any]:
        """
        Calculate inter-attempt timing statistics.

        Takes a sample of (timestamp, username) pairs. The timestamps and
        usernames used to be collected as two separate aggregates with no
        common ordering, so the intervals were differences between arbitrarily
        permuted times and the scripted-timing signal was meaningless.
        
        Returns:
            dict: {
                'mean_interval': float (seconds),
                'std_interval': float (seconds),
                'is_scripted': bool (std < threshold)
            }
        """
        intervals = ordered_intervals(attempt_sample or [])

        if len(intervals) < 2:
            return {'mean_interval': 0, 'std_interval': 999, 'is_scripted': False}

        mean_interval = statistics.mean(intervals)
        std_interval = statistics.stdev(intervals)

        is_scripted = std_interval < self.thresholds['timing_std_threshold']

        return {
            'mean_interval': round(mean_interval, 2),
            'std_interval': round(std_interval, 2),
            'is_scripted': is_scripted,
            'sampled_attempts': len(intervals) + 1,
        }

    @staticmethod
    def _looks_like_ip(value: str) -> bool:
        """Whether a resolved source identity is an address rather than a name."""
        return bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', str(value or '')))
    
    def _analyze_username_patterns(self, usernames: List[str]) -> Dict[str, Any]:
        """
        Analyze attempted usernames for attack patterns.
        
        Checks:
        - Admin account targeting (admin, administrator, svc_*)
        - Sequential patterns (admin1, admin2, admin3)
        - Dictionary-like patterns
        """
        if not usernames:
            return {
                'targets_admin_accounts': False,
                'has_sequential_pattern': False,
                'has_dictionary_pattern': False,
                'admin_count': 0
            }
        
        # Clean usernames
        clean_usernames = [u.lower() if u else '' for u in usernames if u]
        
        # Check for admin targeting
        admin_count = 0
        for username in clean_usernames:
            for pattern in self.ADMIN_PATTERNS:
                if pattern in username:
                    admin_count += 1
                    break
        
        targets_admin = admin_count >= 3 or (admin_count / len(clean_usernames) > 0.2 if clean_usernames else False)
        
        # Check for sequential patterns (e.g., user1, user2, user3)
        has_sequential = self._check_sequential_pattern(clean_usernames)
        
        # Check for dictionary-like patterns (common names, short usernames)
        common_names = ['john', 'jane', 'mike', 'david', 'sarah', 'test', 'user', 'guest']
        dictionary_count = sum(1 for u in clean_usernames if any(name in u for name in common_names))
        has_dictionary = dictionary_count >= 5 or (dictionary_count / len(clean_usernames) > 0.3 if clean_usernames else False)
        
        return {
            'targets_admin_accounts': targets_admin,
            'has_sequential_pattern': has_sequential,
            'has_dictionary_pattern': has_dictionary,
            'admin_count': admin_count,
            'unique_usernames': len(set(clean_usernames))
        }
    
    def _check_sequential_pattern(self, usernames: List[str]) -> bool:
        """Check if usernames have sequential numbering (e.g., user1, user2, user3)"""
        import re
        
        # Extract base names with numbers
        pattern = re.compile(r'^(.+?)(\d+)$')
        base_counts = {}
        
        for username in usernames:
            match = pattern.match(username)
            if match:
                base = match.group(1)
                if base not in base_counts:
                    base_counts[base] = []
                base_counts[base].append(int(match.group(2)))
        
        # Check if any base has 3+ sequential numbers
        for base, numbers in base_counts.items():
            if len(numbers) >= 3:
                sorted_nums = sorted(numbers)
                sequential_count = 1
                for i in range(1, len(sorted_nums)):
                    if sorted_nums[i] == sorted_nums[i-1] + 1:
                        sequential_count += 1
                        if sequential_count >= 3:
                            return True
                    else:
                        sequential_count = 1
        
        return False
    
    def _calculate_confidence(self, metrics: Dict) -> float:
        """
        Weighted confidence scoring.
        
        Returns confidence score 0-100.
        """
        # Clearing both detection thresholds inside one window is itself
        # evidence, so it carries a base score; the bands below otherwise could
        # not reach the reporting floor of 30 for a candidate that only just
        # qualified.
        score = 15
        
        # High unique username count: +20
        if metrics['unique_users'] > 50:
            score += 20
        elif metrics['unique_users'] > 25:
            score += 15
        elif metrics['unique_users'] >= 10:
            score += 10
        
        # Very high failure rate: +15
        if metrics['failure_rate'] > 0.95:
            score += 15
        elif metrics['failure_rate'] > 0.90:
            score += 10
        
        # Scripted timing: +15
        if metrics.get('is_scripted'):
            score += 15
        elif metrics.get('timing_std', 999) < 10:
            score += 10
        
        # Admin account targeting: +10
        if metrics.get('targets_admin_accounts'):
            score += 10
        
        # Dictionary pattern: +5
        if metrics.get('has_dictionary_pattern'):
            score += 5
        
        # High volume: +10
        if metrics['total_attempts'] > 100:
            score += 10
        elif metrics['total_attempts'] > 50:
            score += 5
        
        # Partial success (some accounts compromised): +15 concern
        if metrics.get('successes', 0) > 0:
            score += 15
        
        # Cap at 100
        return min(100, score)
    
    def _get_successful_accounts(
        self,
        source_identity: str,
        window_start: Optional[datetime] = None,
        window_end: Optional[datetime] = None,
    ) -> List[str]:
        """Query for accounts that successfully authenticated from spray source.

        Success now includes Kerberos and NTLM outcomes, not only 4624, so an
        account compromised over Kerberos is reported rather than missed.
        """
        if not window_start or not window_end:
            return []

        client = self._get_clickhouse_client()
        parameters = slot_query_parameters(
            self.case_id,
            source_identity=str(source_identity),
            window_start=self._format_sql_datetime(window_start),
            window_end=self._format_sql_datetime(window_end),
        )

        try:
            result = client.query(build_successful_accounts_query(), parameters=parameters)
            return [row[0] for row in result.result_rows if row[0]]
        except Exception as e:
            # Enriching a finding with the compromised accounts is best effort;
            # the finding itself stands without it.
            logger.warning(f"Failed to get successful accounts: {e}")
            return []
