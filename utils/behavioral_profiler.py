"""Behavioral Profiler for CaseScope

Calculates behavioral profiles for users and systems in a case.
Profiles are built from ClickHouse event data and stored in PostgreSQL
for use in anomaly detection and peer comparison.
"""

import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Callable, Any
from collections import defaultdict
import statistics

from models.database import db
from models.known_user import KnownUser
from models.known_system import KnownSystem
from models.behavioral_profiles import (
    UserBehaviorProfile, SystemBehaviorProfile, SystemRole
)
from utils.clickhouse import get_fresh_client
from config import Config

logger = logging.getLogger(__name__)


# Business hours definition (7am-7pm)
BUSINESS_HOURS_START = 7
BUSINESS_HOURS_END = 19


class BehavioralProfiler:
    """
    Calculates behavioral profiles for users and systems in a case.
    
    Profiles are built from ClickHouse event data and stored in PostgreSQL
    for use in anomaly detection and peer comparison.
    """
    
    def __init__(self, case_id: int, analysis_id: str, progress_callback: Callable = None):
        """
        Args:
            case_id: The case to profile
            analysis_id: UUID for this analysis run
            progress_callback: Optional callable(phase, percent, message) for progress updates
        """
        self.case_id = case_id
        self.analysis_id = analysis_id
        self.progress_callback = progress_callback
        self.ch_client = None
        
        # Configuration
        self.min_events_for_profile = getattr(Config, 'ANALYSIS_MIN_EVENTS_FOR_PROFILE', 10)
    
    def _get_clickhouse_client(self):
        """Get or create ClickHouse client"""
        if self.ch_client is None:
            self.ch_client = get_fresh_client()
        return self.ch_client
    
    def _update_progress(self, phase: str, percent: int, message: str):
        """Update progress if callback is set"""
        if self.progress_callback:
            self.progress_callback(phase, percent, message)
    
    def profile_all(self) -> Dict[str, Any]:
        """
        Main entry point. Profiles all users and systems.
        
        Returns:
            dict: {
                'users_profiled': int,
                'systems_profiled': int,
                'duration_seconds': float
            }
        """
        start_time = datetime.utcnow()
        
        self._update_progress('profiling', 0, 'Starting behavioral profiling...')
        
        # Profile users
        self._update_progress('profiling', 2, 'Profiling users...')
        users_profiled = self.profile_users()
        
        # Profile systems
        self._update_progress('profiling', 12, 'Profiling systems...')
        systems_profiled = self.profile_systems()
        
        duration = (datetime.utcnow() - start_time).total_seconds()
        
        self._update_progress('profiling', 15, f'Profiling complete: {users_profiled} users, {systems_profiled} systems')
        
        return {
            'users_profiled': users_profiled,
            'systems_profiled': systems_profiled,
            'duration_seconds': duration
        }
    
    def profile_users(self) -> int:
        """
        Profile all users in known_users for this case.
        
        Returns:
            int: Count of users profiled
        """
        users = KnownUser.query.filter_by(case_id=self.case_id).all()
        total_users = len(users)
        profiled_count = 0
        
        for i, user in enumerate(users):
            try:
                profile = self._calculate_user_profile(user.id, user.username, user.sid)
                if profile:
                    profiled_count += 1
                
                # Update progress within user profiling (0-10%)
                progress = int(2 + (i / max(total_users, 1)) * 10)
                self._update_progress('profiling', progress, f'Profiling user {i+1}/{total_users}')
                
            except Exception as e:
                logger.error(f"Error profiling user {user.id}: {e}")
                continue
        
        db.session.commit()
        return profiled_count
    
    def profile_systems(self) -> int:
        """
        Profile all systems in known_systems for this case.
        
        Returns:
            int: Count of systems profiled
        """
        systems = KnownSystem.query.filter_by(case_id=self.case_id).all()
        total_systems = len(systems)
        profiled_count = 0
        
        for i, system in enumerate(systems):
            try:
                profile = self._calculate_system_profile(system.id, system.hostname)
                if profile:
                    profiled_count += 1
                
                # Update progress within system profiling (12-15%)
                progress = int(12 + (i / max(total_systems, 1)) * 3)
                self._update_progress('profiling', progress, f'Profiling system {i+1}/{total_systems}')
                
            except Exception as e:
                logger.error(f"Error profiling system {system.id}: {e}")
                continue
        
        db.session.commit()
        return profiled_count
    
    def _calculate_user_profile(self, user_id: int, username: str, sid: str) -> Optional[UserBehaviorProfile]:
        """
        Calculate profile for a single user.
        
        Queries ClickHouse for:
        - Activity patterns by hour/day
        - Authentication patterns (types, success/failure rates)
        - Hosts accessed (source and target)
        
        Calculates anomaly thresholds based on observed behavior.
        """
        client = self._get_clickhouse_client()
        
        # Build user filter - match by username OR sid
        user_filters = []
        if username:
            user_filters.append(f"lower(username) = lower('{self._escape_sql(username)}')")
        if sid:
            user_filters.append(f"sid = '{self._escape_sql(sid)}'")
        
        if not user_filters:
            return None
        
        user_filter = f"({' OR '.join(user_filters)})"
        
        # Query for user activity summary
        query = f"""
            SELECT 
                toHour(timestamp) as hour,
                toDayOfWeek(timestamp) as day_of_week,
                toDate(timestamp) as date,
                event_id,
                source_host,
                remote_host,
                auth_package,
                logon_type,
                count() as event_count
            FROM events
            WHERE case_id = {self.case_id}
              AND {user_filter}
            GROUP BY hour, day_of_week, date, event_id, source_host, remote_host, auth_package, logon_type
        """
        
        result = client.query(query)
        rows = result.result_rows
        
        if not rows or len(rows) < self.min_events_for_profile:
            return None
        
        # Process results
        activity_hours = defaultdict(int)
        activity_days = defaultdict(int)
        daily_logons = defaultdict(int)
        daily_failures = defaultdict(int)
        source_hosts = defaultdict(int)
        target_hosts = defaultdict(int)
        auth_types = defaultdict(int)
        total_events = 0
        total_logons = 0
        total_failures = 0
        dates_seen = set()
        min_date = None
        max_date = None
        
        for row in rows:
            hour, day, date, event_id, source_host, remote_host, auth_package, logon_type, count = row
            
            total_events += count
            activity_hours[hour] += count
            activity_days[day] += count
            dates_seen.add(date)
            
            if min_date is None or date < min_date:
                min_date = date
            if max_date is None or date > max_date:
                max_date = date
            
            # Track authentication events
            if event_id in ('4624', '4625', '4648'):
                if event_id == '4624':
                    total_logons += count
                    daily_logons[date] += count
                elif event_id == '4625':
                    total_failures += count
                    daily_failures[date] += count
                
                if source_host:
                    source_hosts[source_host.upper()] += count
                if remote_host:
                    target_hosts[remote_host.upper()] += count
                if auth_package:
                    auth_types[auth_package.upper()] += count
        
        # Calculate metrics
        total_auth = total_logons + total_failures
        logon_success_rate = (total_logons / total_auth * 100) if total_auth > 0 else 0
        failure_rate = (total_failures / total_auth * 100) if total_auth > 0 else 0
        
        # Off-hours calculation
        off_hours_events = sum(count for hour, count in activity_hours.items() 
                              if hour < BUSINESS_HOURS_START or hour >= BUSINESS_HOURS_END)
        off_hours_percentage = (off_hours_events / total_events * 100) if total_events > 0 else 0
        
        # Peak hours (top 3 hours by activity)
        peak_hours = sorted(activity_hours.keys(), key=lambda h: activity_hours[h], reverse=True)[:3]
        
        # Daily statistics
        daily_logon_values = list(daily_logons.values()) or [0]
        avg_daily_logons = statistics.mean(daily_logon_values) if daily_logon_values else 0
        std_daily_logons = statistics.stdev(daily_logon_values) if len(daily_logon_values) > 1 else 0
        max_daily_logons = max(daily_logon_values) if daily_logon_values else 0
        
        daily_failure_values = list(daily_failures.values()) or [0]
        avg_daily_failures = statistics.mean(daily_failure_values) if daily_failure_values else 0
        
        # Top hosts
        typical_source = self._get_top_n(source_hosts, 10)
        typical_target = self._get_top_n(target_hosts, 10)
        
        # Auth type distribution
        auth_distribution = {}
        total_auth_typed = sum(auth_types.values())
        if total_auth_typed > 0:
            for auth_type, count in auth_types.items():
                auth_distribution[auth_type] = round(count / total_auth_typed * 100, 1)
        
        # Calculate anomaly thresholds
        anomaly_thresholds = self._calculate_anomaly_thresholds({
            'avg_daily_logons': avg_daily_logons,
            'std_daily_logons': std_daily_logons,
            'failure_rate': failure_rate,
            'off_hours_percentage': off_hours_percentage,
            'unique_hosts': len(target_hosts)
        })
        
        # Create or update profile
        profile = UserBehaviorProfile.query.filter_by(
            case_id=self.case_id,
            user_id=user_id
        ).first()
        
        if not profile:
            profile = UserBehaviorProfile(
                case_id=self.case_id,
                user_id=user_id,
                username=username
            )
            db.session.add(profile)
        
        # Update profile
        profile.profile_period_start = min_date
        profile.profile_period_end = max_date
        profile.total_events = total_events
        profile.activity_hours = dict(activity_hours)
        profile.activity_days = dict(activity_days)
        profile.peak_hours = peak_hours
        profile.off_hours_percentage = off_hours_percentage
        profile.total_logons = total_logons
        profile.logon_success_rate = logon_success_rate
        profile.auth_types = auth_distribution
        profile.typical_source_hosts = typical_source
        profile.typical_target_hosts = typical_target
        profile.unique_hosts_accessed = len(target_hosts)
        profile.avg_daily_logons = avg_daily_logons
        profile.std_daily_logons = std_daily_logons
        profile.max_daily_logons = max_daily_logons
        profile.failure_rate = failure_rate
        profile.avg_daily_failures = avg_daily_failures
        profile.anomaly_thresholds = anomaly_thresholds
        
        return profile
    
    def _calculate_system_profile(self, system_id: int, hostname: str) -> Optional[SystemBehaviorProfile]:
        """
        Calculate profile for a single system.
        
        Queries ClickHouse for:
        - Activity patterns
        - Users who authenticate to this system
        - Source IPs that connect
        - Inferred system role (DC, server, workstation)
        """
        client = self._get_clickhouse_client()
        hostname_upper = hostname.upper()
        
        # Query for system activity summary
        query = f"""
            SELECT 
                toHour(timestamp) as hour,
                toDate(timestamp) as date,
                username,
                src_ip,
                event_id,
                process_name,
                count() as event_count
            FROM events
            WHERE case_id = {self.case_id}
              AND (upper(source_host) = '{self._escape_sql(hostname_upper)}' 
                   OR upper(workstation_name) = '{self._escape_sql(hostname_upper)}'
                   OR upper(remote_host) = '{self._escape_sql(hostname_upper)}')
            GROUP BY hour, date, username, src_ip, event_id, process_name
        """
        
        result = client.query(query)
        rows = result.result_rows
        
        if not rows or len(rows) < self.min_events_for_profile:
            return None
        
        # Process results
        activity_hours = defaultdict(int)
        daily_auth = defaultdict(int)
        users = defaultdict(int)
        source_ips = defaultdict(int)
        processes = defaultdict(int)
        total_events = 0
        dates_seen = set()
        min_date = None
        max_date = None
        
        # Track events for role inference
        event_counts = defaultdict(int)
        
        for row in rows:
            hour, date, username, src_ip, event_id, process_name, count = row
            
            total_events += count
            activity_hours[hour] += count
            dates_seen.add(date)
            event_counts[event_id] += count
            
            if min_date is None or date < min_date:
                min_date = date
            if max_date is None or date > max_date:
                max_date = date
            
            if event_id in ('4624', '4625'):
                daily_auth[date] += count
            
            if username:
                users[username.upper()] += count
            if src_ip:
                source_ips[str(src_ip)] += count
            if process_name:
                processes[process_name.upper()] += count
        
        # Calculate metrics
        daily_auth_values = list(daily_auth.values()) or [0]
        auth_stats = {
            'mean_daily': statistics.mean(daily_auth_values) if daily_auth_values else 0,
            'std_daily': statistics.stdev(daily_auth_values) if len(daily_auth_values) > 1 else 0,
            'max_daily': max(daily_auth_values) if daily_auth_values else 0
        }
        
        # Infer system role
        system_role = self._infer_system_role(hostname, {
            'event_counts': dict(event_counts),
            'unique_users': len(users),
            'processes': list(processes.keys())
        })
        
        # Top users and IPs
        typical_users = self._get_top_n(users, 10)
        typical_source_ips = self._get_top_n(source_ips, 10)
        typical_processes = self._get_top_n(processes, 10)
        
        # Calculate anomaly thresholds
        anomaly_thresholds = self._calculate_anomaly_thresholds({
            'mean_daily_auth': auth_stats['mean_daily'],
            'std_daily_auth': auth_stats['std_daily'],
            'unique_users': len(users)
        })
        
        # Create or update profile
        profile = SystemBehaviorProfile.query.filter_by(
            case_id=self.case_id,
            system_id=system_id
        ).first()
        
        if not profile:
            profile = SystemBehaviorProfile(
                case_id=self.case_id,
                system_id=system_id,
                hostname=hostname
            )
            db.session.add(profile)
        
        # Update profile
        profile.profile_period_start = min_date
        profile.profile_period_end = max_date
        profile.total_events = total_events
        profile.system_role = system_role
        profile.activity_hours = dict(activity_hours)
        profile.typical_users = typical_users
        profile.unique_users = len(users)
        profile.typical_source_ips = typical_source_ips
        profile.typical_processes = typical_processes
        profile.auth_destination_volume = auth_stats
        profile.anomaly_thresholds = anomaly_thresholds
        
        return profile
    
    def _infer_system_role(self, hostname: str, events_summary: Dict) -> str:
        """
        Heuristics to determine system role.
        
        Rules:
        - Hostname contains 'DC', 'PDC', 'BDC' → domain_controller
        - Has replication or krbtgt activity → domain_controller
        - High volume of inbound auth from many users → server
        - Primarily single user source → workstation
        """
        hostname_upper = hostname.upper()
        
        # Check hostname patterns
        dc_patterns = ['DC', 'PDC', 'BDC', 'DOMAIN', '-DC-', 'DC0', 'DC1', 'DC2']
        if any(pattern in hostname_upper for pattern in dc_patterns):
            return SystemRole.DOMAIN_CONTROLLER
        
        # Check for server patterns
        server_patterns = ['SRV', 'SERVER', 'SQL', 'WEB', 'APP', 'FILE', 'MAIL', 'EXCH']
        if any(pattern in hostname_upper for pattern in server_patterns):
            return SystemRole.SERVER
        
        # Infer from user count
        unique_users = events_summary.get('unique_users', 0)
        if unique_users > 50:
            return SystemRole.SERVER
        elif unique_users <= 3:
            return SystemRole.WORKSTATION
        
        # Check for DC-specific event IDs (replication, etc.)
        event_counts = events_summary.get('event_counts', {})
        dc_events = ['4662', '4933', '4935', '4936']  # AD replication events
        if any(event_counts.get(eid, 0) > 0 for eid in dc_events):
            return SystemRole.DOMAIN_CONTROLLER
        
        return SystemRole.UNKNOWN
    
    def _calculate_anomaly_thresholds(self, profile_data: Dict) -> Dict[str, Any]:
        """
        Calculate thresholds for anomaly detection.
        
        For most metrics: threshold = mean + (3 * std_dev)
        Minimum thresholds applied to avoid false positives on low-activity entities.
        """
        thresholds = {}
        
        # Logon threshold
        avg_logons = profile_data.get('avg_daily_logons', 0)
        std_logons = profile_data.get('std_daily_logons', 0)
        logon_threshold = avg_logons + (3 * std_logons)
        thresholds['logon_threshold'] = max(logon_threshold, 50)  # Minimum 50
        
        # Failure threshold
        failure_rate = profile_data.get('failure_rate', 0)
        thresholds['failure_threshold'] = min(failure_rate + 20, 50)  # At most 50%
        
        # Off-hours threshold
        off_hours = profile_data.get('off_hours_percentage', 0)
        thresholds['off_hours_threshold'] = min(off_hours + 30, 80)  # At most 80%
        
        # New host access (flag if not in typical hosts)
        thresholds['new_host_is_anomaly'] = profile_data.get('unique_hosts', 0) < 10
        
        return thresholds
    
    def _get_top_n(self, counts: Dict, n: int) -> List[Dict]:
        """Get top N items from a count dictionary"""
        sorted_items = sorted(counts.items(), key=lambda x: x[1], reverse=True)[:n]
        total = sum(counts.values())
        
        return [
            {
                'value': item,
                'count': count,
                'percentage': round(count / total * 100, 1) if total > 0 else 0
            }
            for item, count in sorted_items
        ]
    
    def _escape_sql(self, value: str) -> str:
        """Escape single quotes for SQL"""
        if value is None:
            return ''
        return value.replace("'", "''")
