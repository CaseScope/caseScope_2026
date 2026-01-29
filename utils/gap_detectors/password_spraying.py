"""Password Spraying Detector for CaseScope

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
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
import statistics

from models.behavioral_profiles import GapDetectionFinding, GapFindingType
from utils.gap_detectors import BaseGapDetector
from config import Config

logger = logging.getLogger(__name__)


class PasswordSprayingDetector(BaseGapDetector):
    """
    Detects password spraying attacks through statistical analysis.
    
    Password spraying = single source attempting many usernames with few passwords.
    Hayabusa may miss this if individual events don't meet single-event rule thresholds.
    """
    
    # Default thresholds (configurable via Config)
    DEFAULT_THRESHOLDS = {
        'min_unique_users': 10,       # Minimum unique usernames from single source
        'min_failure_rate': 0.9,      # 90% failure rate
        'time_window_hours': 2,       # Group attempts within this window
        'timing_std_threshold': 5.0   # Seconds - low std = scripted
    }
    
    # Admin account patterns
    ADMIN_PATTERNS = [
        'admin', 'administrator', 'svc_', 'service_', 'root', 'domain', 
        'enterprise', 'backup', 'system', 'sqlsvc', 'iis', 'exchange'
    ]
    
    def __init__(self, case_id: int, analysis_id: str, thresholds: Dict = None):
        super().__init__(case_id, analysis_id)
        
        # Load thresholds from config or use defaults
        self.thresholds = {
            'min_unique_users': getattr(Config, 'SPRAY_MIN_UNIQUE_USERS', 
                                        self.DEFAULT_THRESHOLDS['min_unique_users']),
            'min_failure_rate': getattr(Config, 'SPRAY_MIN_FAILURE_RATE', 
                                        self.DEFAULT_THRESHOLDS['min_failure_rate']),
            'time_window_hours': getattr(Config, 'SPRAY_TIME_WINDOW_HOURS', 
                                         self.DEFAULT_THRESHOLDS['time_window_hours']),
            'timing_std_threshold': getattr(Config, 'SPRAY_TIMING_STD_THRESHOLD', 
                                            self.DEFAULT_THRESHOLDS['timing_std_threshold'])
        }
        
        # Override with provided thresholds
        if thresholds:
            self.thresholds.update(thresholds)
    
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
        Query ClickHouse for sources with high unique user counts.
        
        Returns sources that exceed thresholds for further analysis.
        """
        client = self._get_clickhouse_client()
        
        min_unique_users = self.thresholds['min_unique_users']
        min_failure_rate = self.thresholds['min_failure_rate']
        
        query = f"""
            SELECT 
                src_ip,
                count(DISTINCT username) as unique_users,
                count() as total_attempts,
                countIf(event_id = '4625') as failures,
                countIf(event_id = '4624') as successes,
                min(timestamp) as first_attempt,
                max(timestamp) as last_attempt,
                dateDiff('second', min(timestamp), max(timestamp)) as duration_seconds,
                groupArray(100)(username) as usernames_sampled,
                groupArray(100)(timestamp) as timestamps_sampled
            FROM events
            WHERE case_id = {self.case_id}
              AND event_id IN ('4624', '4625')
              AND src_ip IS NOT NULL
              AND src_ip != ''
              AND toString(src_ip) != '0.0.0.0'
              AND toString(src_ip) != '::'
            GROUP BY src_ip
            HAVING unique_users >= {min_unique_users}
               AND failures / (failures + successes + 0.001) >= {min_failure_rate}
            ORDER BY unique_users DESC
            LIMIT 100
        """
        
        try:
            result = client.query(query)
            candidates = []
            
            for row in result.result_rows:
                candidates.append({
                    'src_ip': str(row[0]),
                    'unique_users': row[1],
                    'total_attempts': row[2],
                    'failures': row[3],
                    'successes': row[4],
                    'first_attempt': row[5],
                    'last_attempt': row[6],
                    'duration_seconds': row[7],
                    'usernames_sampled': row[8] if len(row) > 8 else [],
                    'timestamps_sampled': row[9] if len(row) > 9 else []
                })
            
            return candidates
            
        except Exception as e:
            logger.error(f"Failed to find spray candidates: {e}")
            return []
    
    def _analyze_candidate(self, candidate: Dict) -> Optional[GapDetectionFinding]:
        """
        Deep analysis of a spray candidate.
        
        Analyzes:
        - Timing regularity (scripted vs manual)
        - Username patterns (dictionary, sequential, admin-targeting)
        - Success analysis (which accounts succeeded?)
        - Baseline comparison (is this source normally active?)
        """
        src_ip = candidate['src_ip']
        unique_users = candidate['unique_users']
        total_attempts = candidate['total_attempts']
        failures = candidate['failures']
        successes = candidate['successes']
        
        # Calculate failure rate
        failure_rate = failures / (failures + successes) if (failures + successes) > 0 else 0
        
        # Analyze timing patterns
        timing_analysis = self._analyze_timing_pattern(candidate.get('timestamps_sampled', []))
        
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
        summary = f"Password spraying from {src_ip}: {unique_users} unique users targeted, {failures} failures"
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
            'username_analysis': username_analysis
        }
        
        # Build evidence
        evidence = {
            'sample_usernames': candidate.get('usernames_sampled', [])[:20],
            'first_attempt': candidate.get('first_attempt').isoformat() if candidate.get('first_attempt') else None,
            'last_attempt': candidate.get('last_attempt').isoformat() if candidate.get('last_attempt') else None
        }
        
        # Suggested IOCs
        suggested_iocs = [
            {'type': 'ip_address', 'value': src_ip, 'reason': 'Source of password spraying attack'}
        ]
        
        # Add any successful accounts as IOCs
        if successes > 0:
            # Query for which accounts succeeded
            success_accounts = self._get_successful_accounts(src_ip)
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
            entity_type='source_ip',
            entity_value=src_ip,
            summary=summary,
            details=details,
            evidence=evidence,
            affected_entities={'usernames_targeted': unique_users},
            time_window_start=candidate.get('first_attempt'),
            time_window_end=candidate.get('last_attempt'),
            event_count=total_attempts,
            suggested_iocs=suggested_iocs
        )
    
    def _analyze_timing_pattern(self, timestamps: List) -> Dict[str, Any]:
        """
        Calculate inter-attempt timing statistics.
        
        Returns:
            dict: {
                'mean_interval': float (seconds),
                'std_interval': float (seconds),
                'is_scripted': bool (std < threshold)
            }
        """
        if not timestamps or len(timestamps) < 3:
            return {'mean_interval': 0, 'std_interval': 999, 'is_scripted': False}
        
        # Sort timestamps and calculate intervals
        try:
            sorted_ts = sorted(timestamps)
            intervals = []
            
            for i in range(1, len(sorted_ts)):
                if sorted_ts[i] and sorted_ts[i-1]:
                    diff = (sorted_ts[i] - sorted_ts[i-1]).total_seconds()
                    if 0 < diff < 3600:  # Only consider intervals less than 1 hour
                        intervals.append(diff)
            
            if len(intervals) < 2:
                return {'mean_interval': 0, 'std_interval': 999, 'is_scripted': False}
            
            mean_interval = statistics.mean(intervals)
            std_interval = statistics.stdev(intervals)
            
            is_scripted = std_interval < self.thresholds['timing_std_threshold']
            
            return {
                'mean_interval': round(mean_interval, 2),
                'std_interval': round(std_interval, 2),
                'is_scripted': is_scripted
            }
        except Exception as e:
            logger.warning(f"Timing analysis failed: {e}")
            return {'mean_interval': 0, 'std_interval': 999, 'is_scripted': False}
    
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
        score = 0
        
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
    
    def _get_successful_accounts(self, src_ip: str) -> List[str]:
        """Query for accounts that successfully authenticated from spray source"""
        client = self._get_clickhouse_client()
        
        query = f"""
            SELECT DISTINCT username
            FROM events
            WHERE case_id = {self.case_id}
              AND event_id = '4624'
              AND toString(src_ip) = '{self._escape_sql(src_ip)}'
              AND username != ''
              AND username NOT LIKE '%$'
            LIMIT 10
        """
        
        try:
            result = client.query(query)
            return [row[0] for row in result.result_rows if row[0]]
        except Exception as e:
            logger.warning(f"Failed to get successful accounts: {e}")
            return []
