# CaseScope Enhanced Analysis System - Developer Work List

## Overview

This document describes enhancements to CaseScope's analysis capabilities. The goal is to add behavioral profiling, attack chain correlation, and gap detection that complements the existing Hayabusa/Sigma detection layer. The system operates in four modes depending on whether AI and OpenCTI are enabled.

### Operating Modes

| Mode | OpenCTI | AI | Capabilities |
|------|---------|-----|--------------|
| A | Off | Off | Rule-based correlation + behavioral profiling + gap detection |
| B | Off | On | Mode A + AI reasoning and explanations |
| C | On | Off | Mode A + threat intel enrichment |
| D | On | On | Full stack - all capabilities |

### Key Principle

The system should do maximum work automatically. The analyst verifies and expands upon findings rather than running manual searches. Every feature degrades gracefully when dependencies (AI/OpenCTI) are unavailable.

### Existing System Context

**Current Pipeline:**
1. User uploads file
2. If EVTX → run Hayabusa
3. Index with python evtx module
4. Events stored in ClickHouse, augmented with Hayabusa info (tagging, MITRE, rules)
5. After ingestion, systems and users extracted to PostgreSQL
6. Result: known_users, known_systems, events with Sigma tagging, optional IOCs

**Key Insight:** Hayabusa already provides Sigma detection. This system adds correlation, behavioral analysis, and gap detection on top.

---

## Phase 1: Database Schema Extensions

### Task 1.1: Create Behavioral Profile Tables

**File:** `/opt/casescope/models/behavioral_profiles.py`

**Purpose:** Store computed behavioral profiles for users and systems.

#### Table: `user_behavior_profiles`

| Column | Type | Purpose |
|--------|------|---------|
| id | Integer | PK |
| case_id | Integer | FK to cases |
| user_id | Integer | FK to known_users |
| username | String | Denormalized for query convenience |
| profile_period_start | DateTime | Start of analyzed period |
| profile_period_end | DateTime | End of analyzed period |
| total_events | Integer | Total events for this user |
| activity_hours | JSONB | Histogram of activity by hour (0-23) |
| activity_days | JSONB | Histogram of activity by day of week |
| peak_hours | JSONB | List of most active hours |
| off_hours_percentage | Float | Percentage of activity outside business hours (7am-7pm) |
| total_logons | Integer | Total authentication events |
| logon_success_rate | Float | Percentage of successful logons |
| auth_types | JSONB | Distribution: `{kerberos: %, ntlm: %, other: %}` |
| typical_source_hosts | JSONB | Hosts user normally logs in FROM: `[{host, count, percentage}]` |
| typical_target_hosts | JSONB | Hosts user normally logs in TO: `[{host, count, percentage}]` |
| avg_daily_logons | Float | Mean logons per day |
| std_daily_logons | Float | Standard deviation of daily logons |
| max_daily_logons | Integer | Maximum logons in single day |
| failure_rate | Float | Authentication failure percentage |
| avg_daily_failures | Float | Mean failures per day |
| processes_executed | JSONB | Common processes run (if Sysmon data): `[{process, count}]` |
| network_connections | JSONB | Common destinations (if network data): `[{dst_ip, count}]` |
| peer_group_id | Integer | FK to peer_groups (nullable) |
| anomaly_thresholds | JSONB | Computed thresholds: `{logon_threshold, failure_threshold, etc.}` |
| created_at | DateTime | When profile was computed |

#### Table: `system_behavior_profiles`

| Column | Type | Purpose |
|--------|------|---------|
| id | Integer | PK |
| case_id | Integer | FK to cases |
| system_id | Integer | FK to known_systems |
| hostname | String | Denormalized for query convenience |
| profile_period_start | DateTime | Start of analyzed period |
| profile_period_end | DateTime | End of analyzed period |
| total_events | Integer | Total events for this system |
| system_role | String | Inferred: workstation, server, domain_controller, etc. |
| activity_hours | JSONB | Histogram of activity by hour |
| typical_users | JSONB | Users who normally authenticate TO this system: `[{user, count}]` |
| typical_source_ips | JSONB | IPs that normally connect: `[{ip, count}]` |
| typical_processes | JSONB | Normal processes on this system: `[{process, count}]` |
| auth_destination_volume | JSONB | `{mean_daily, std_daily, max_daily}` auth events as destination |
| auth_source_volume | JSONB | `{mean_daily, std_daily, max_daily}` auth events as source |
| service_accounts | JSONB | Service accounts associated with this system |
| network_listeners | JSONB | Ports/services this system normally exposes |
| outbound_connections | JSONB | Normal outbound destinations |
| anomaly_thresholds | JSONB | Computed thresholds for this system |
| created_at | DateTime | When profile was computed |

#### Table: `peer_groups`

| Column | Type | Purpose |
|--------|------|---------|
| id | Integer | PK |
| case_id | Integer | FK to cases |
| group_type | String | 'user' or 'system' |
| group_name | String | Auto-generated or labeled: "standard_users_cluster_1" |
| member_count | Integer | Number of entities in group |
| median_daily_logons | Float | Peer group median |
| median_failure_rate | Float | Peer group median |
| median_unique_hosts | Float | Peer group median hosts accessed |
| median_off_hours_pct | Float | Peer group median |
| std_daily_logons | Float | Peer group standard deviation |
| std_failure_rate | Float | Peer group standard deviation |
| profile_data | JSONB | Full statistical profile of the group |
| created_at | DateTime | When computed |

#### Table: `peer_group_members`

| Column | Type | Purpose |
|--------|------|---------|
| id | Integer | PK |
| peer_group_id | Integer | FK to peer_groups |
| entity_type | String | 'user' or 'system' |
| entity_id | Integer | FK to known_users or known_systems |
| similarity_score | Float | How closely this entity matches the group |
| z_scores | JSONB | This entity's z-scores vs group for each metric |

---

### Task 1.2: Create Analysis Run Tracking Table

**Purpose:** Track overall analysis runs and their status.

#### Table: `case_analysis_runs`

| Column | Type | Purpose |
|--------|------|---------|
| id | Integer | PK |
| case_id | Integer | FK to cases |
| analysis_id | String | UUID for this run |
| status | String | pending, profiling, correlating, analyzing, complete, failed |
| mode | String | A, B, C, D (based on enabled features) |
| ai_enabled | Boolean | Was AI available for this run |
| opencti_enabled | Boolean | Was OpenCTI available for this run |
| started_at | DateTime | When analysis began |
| completed_at | DateTime | When analysis finished (nullable) |
| profiling_started_at | DateTime | Phase timestamp |
| profiling_completed_at | DateTime | Phase timestamp |
| correlation_started_at | DateTime | Phase timestamp |
| correlation_completed_at | DateTime | Phase timestamp |
| ai_analysis_started_at | DateTime | Phase timestamp (nullable if no AI) |
| ai_analysis_completed_at | DateTime | Phase timestamp |
| total_events_analyzed | Integer | Events in scope |
| users_profiled | Integer | Count |
| systems_profiled | Integer | Count |
| peer_groups_created | Integer | Count |
| patterns_evaluated | Integer | Count |
| findings_generated | Integer | Count |
| high_confidence_findings | Integer | Findings with confidence >= 75 |
| error_message | Text | If failed, why |
| progress_percent | Integer | 0-100 for UI progress bar |
| current_phase | String | Human-readable current activity |

---

### Task 1.3: Create Gap Detection Findings Table

**Purpose:** Store findings from gap detection (password spraying, brute force, etc.) that aren't covered by existing pattern system.

#### Table: `gap_detection_findings`

| Column | Type | Purpose |
|--------|------|---------|
| id | Integer | PK |
| case_id | Integer | FK to cases |
| analysis_id | String | FK to case_analysis_runs.analysis_id |
| finding_type | String | password_spraying, brute_force, anomalous_user, anomalous_system |
| severity | String | critical, high, medium, low |
| confidence | Float | 0-100 |
| entity_type | String | source_ip, user, system |
| entity_value | String | The IP, username, or hostname |
| entity_id | Integer | FK to known_users or known_systems (nullable) |
| summary | Text | One-line description |
| details | JSONB | Full finding details |
| evidence | JSONB | Supporting data points |
| behavioral_context | JSONB | Baseline vs observed comparison |
| peer_comparison | JSONB | How this entity compares to peers |
| affected_entities | JSONB | List of targets (for spraying) or sources (for brute force) |
| time_window_start | DateTime | When activity began |
| time_window_end | DateTime | When activity ended |
| event_count | Integer | Number of events involved |
| ai_reasoning | Text | AI explanation (nullable, Mode B/D only) |
| opencti_context | JSONB | Threat intel context (nullable, Mode C/D only) |
| suggested_iocs | JSONB | IOCs discovered by this finding |
| analyst_reviewed | Boolean | Default false |
| analyst_verdict | String | Nullable: confirmed, false_positive, needs_investigation |
| analyst_notes | Text | Analyst comments |
| created_at | DateTime | When finding was created |

---

### Task 1.4: Create Suggested Actions Table

**Purpose:** Store suggested analyst actions (like marking user compromised).

#### Table: `suggested_actions`

| Column | Type | Purpose |
|--------|------|---------|
| id | Integer | PK |
| case_id | Integer | FK to cases |
| analysis_id | String | FK to case_analysis_runs.analysis_id |
| source_type | String | pattern_finding, gap_finding |
| source_id | Integer | FK to ai_analysis_results or gap_detection_findings |
| action_type | String | mark_user_compromised, mark_system_compromised, add_ioc, investigate |
| target_type | String | user, system, ioc |
| target_id | Integer | FK to relevant table (nullable) |
| target_value | String | Human-readable target |
| reason | Text | Why this action is suggested |
| confidence | Float | How confident the system is in this suggestion |
| status | String | pending, accepted, rejected, deferred |
| accepted_by | Integer | FK to users (nullable) |
| accepted_at | DateTime | When action was taken (nullable) |
| created_at | DateTime | When suggestion was created |

---

## Phase 2: Behavioral Profiling Engine

### Task 2.1: Create Profiling Module

**File:** `/opt/casescope/utils/behavioral_profiler.py`

**Purpose:** Calculate behavioral profiles for all users and systems in a case.

#### Class: `BehavioralProfiler`

```python
class BehavioralProfiler:
    """
    Calculates behavioral profiles for users and systems in a case.
    
    Profiles are built from ClickHouse event data and stored in PostgreSQL
    for use in anomaly detection and peer comparison.
    """
    
    def __init__(self, case_id: int, analysis_id: str, progress_callback=None):
        """
        Args:
            case_id: The case to profile
            analysis_id: UUID for this analysis run
            progress_callback: Optional callable(phase, percent, message) for progress updates
        """
        pass
    
    def profile_all(self) -> dict:
        """
        Main entry point. Profiles all users and systems.
        
        Returns:
            dict: {
                'users_profiled': int,
                'systems_profiled': int,
                'duration_seconds': float
            }
        """
        pass
    
    def profile_users(self) -> int:
        """
        Profile all users in known_users for this case.
        
        Returns:
            int: Count of users profiled
        """
        pass
    
    def profile_systems(self) -> int:
        """
        Profile all systems in known_systems for this case.
        
        Returns:
            int: Count of systems profiled
        """
        pass
    
    def _calculate_user_profile(self, user_id: int, username: str, sid: str):
        """
        Calculate profile for a single user.
        
        Queries ClickHouse for:
        - Activity patterns by hour/day
        - Authentication patterns (types, success/failure rates)
        - Hosts accessed (source and target)
        - Process execution (if Sysmon data available)
        
        Calculates anomaly thresholds based on observed behavior.
        """
        pass
    
    def _calculate_system_profile(self, system_id: int, hostname: str):
        """
        Calculate profile for a single system.
        
        Queries ClickHouse for:
        - Activity patterns
        - Users who authenticate to this system
        - Source IPs that connect
        - Processes running (if Sysmon data available)
        - Inferred system role (DC, server, workstation)
        """
        pass
    
    def _infer_system_role(self, hostname: str, events_summary: dict) -> str:
        """
        Heuristics to determine system role.
        
        Rules:
        - Has replication events or krbtgt activity → domain_controller
        - Hostname contains 'DC', 'PDC', 'BDC' → domain_controller
        - High volume of inbound auth from many users → server
        - Primarily single user source → workstation
        - Has database/web service processes → server
        """
        pass
    
    def _calculate_anomaly_thresholds(self, profile_data: dict) -> dict:
        """
        Calculate thresholds for anomaly detection.
        
        For most metrics: threshold = mean + (3 * std_dev)
        Minimum thresholds applied to avoid false positives on low-activity entities.
        
        Returns:
            dict: {
                'logon_threshold': float,
                'failure_threshold': float,
                'new_host_is_anomaly': bool,
                'off_hours_threshold': float
            }
        """
        pass
```

#### ClickHouse Queries:

**User Activity Profile Query:**
```sql
SELECT 
    toHour(timestamp_utc) as hour,
    toDayOfWeek(timestamp_utc) as day_of_week,
    toDate(timestamp_utc) as date,
    event_id,
    source_host,
    countIf(event_id IN ('4624', '4625', '4648')) as auth_events,
    countIf(event_id = '4624') as successful_logons,
    countIf(event_id = '4625') as failed_logons,
    auth_package,
    logon_type
FROM casescope.events
WHERE case_id = {case_id:UInt32}
  AND (username = {username:String} OR sid = {sid:String})
GROUP BY hour, day_of_week, date, event_id, source_host, auth_package, logon_type
```

**System Activity Profile Query:**
```sql
SELECT 
    toHour(timestamp_utc) as hour,
    toDate(timestamp_utc) as date,
    username,
    src_ip,
    event_id,
    process_name,
    count() as event_count
FROM casescope.events
WHERE case_id = {case_id:UInt32}
  AND (source_host = {hostname:String} 
       OR workstation_name = {hostname:String} 
       OR remote_host = {hostname:String})
GROUP BY hour, date, username, src_ip, event_id, process_name
```

---

### Task 2.2: Create Peer Group Clustering

**File:** `/opt/casescope/utils/peer_clustering.py`

**Purpose:** Cluster users and systems into peer groups for comparison.

#### Class: `PeerGroupBuilder`

```python
class PeerGroupBuilder:
    """
    Clusters users and systems into peer groups based on behavioral similarity.
    
    Uses K-means clustering on behavioral feature vectors.
    Peer groups enable "this user is acting differently than similar users" analysis.
    """
    
    def __init__(self, case_id: int, analysis_id: str):
        pass
    
    def build_user_peer_groups(self, min_group_size: int = 3) -> int:
        """
        Cluster users based on behavioral similarity.
        
        Features used:
        - avg_daily_logons
        - failure_rate
        - unique_hosts_accessed
        - off_hours_percentage
        - auth_type_distribution
        
        Returns:
            int: Number of peer groups created
        """
        pass
    
    def build_system_peer_groups(self, min_group_size: int = 3) -> int:
        """
        Cluster systems based on behavioral similarity.
        
        Features used:
        - auth_volume
        - unique_users
        - system_role (encoded)
        - service_account_count
        
        Returns:
            int: Number of peer groups created
        """
        pass
    
    def _extract_user_features(self, profiles: list) -> np.ndarray:
        """
        Convert user profiles to feature vectors for clustering.
        Features are normalized to 0-1 range.
        """
        pass
    
    def _extract_system_features(self, profiles: list) -> np.ndarray:
        """
        Convert system profiles to feature vectors for clustering.
        """
        pass
    
    def _cluster(self, features: np.ndarray, method: str = 'kmeans') -> list:
        """
        Perform clustering on feature matrix.
        
        Uses silhouette score to select optimal K (2-10 range).
        Entities > 4 std_dev from all clusters go to 'outlier' group.
        
        Returns:
            list: Cluster assignment for each entity
        """
        pass
    
    def _calculate_peer_statistics(self, group_members: list) -> dict:
        """
        Calculate median and std_dev for all metrics in a peer group.
        """
        pass
    
    def _calculate_z_scores(self, entity_profile: dict, peer_stats: dict) -> dict:
        """
        Calculate z-score for each metric: (value - median) / std_dev
        
        Returns:
            dict: {metric_name: z_score} for each metric
        """
        pass
```

#### Clustering Logic Details:

1. **Feature Normalization:** Scale all features to 0-1 range using min-max scaling
2. **Optimal K Selection:** 
   - Try k=2 through k=min(10, n_entities/3)
   - Select k with highest silhouette score
3. **Outlier Handling:** 
   - Entities more than 4 std_dev from all cluster centroids → 'outlier' group
4. **Minimum Group Size:** 
   - Clusters with fewer than `min_group_size` members merge with nearest cluster
5. **Dependencies:** 
   - Use `scikit-learn` for KMeans and silhouette_score

---

## Phase 3: Gap Detection Engine

### Task 3.1: Password Spraying Detector

**File:** `/opt/casescope/utils/gap_detectors/password_spraying.py`

**Purpose:** Detect password spraying attacks that Hayabusa per-event rules may miss.

#### Class: `PasswordSprayingDetector`

```python
class PasswordSprayingDetector:
    """
    Detects password spraying attacks through statistical analysis.
    
    Password spraying = single source attempting many usernames with few passwords.
    Hayabusa may miss this if individual events don't meet single-event rule thresholds.
    
    Detection is based on aggregate behavior:
    - High unique username count from single source
    - High failure rate
    - Scripted timing patterns
    - Targeting patterns (admin accounts, dictionary usernames)
    """
    
    # Default thresholds (configurable via config.py)
    DEFAULT_THRESHOLDS = {
        'min_unique_users': 10,      # Minimum unique usernames from single source
        'min_failure_rate': 0.9,      # 90% failure rate
        'time_window_hours': 2,       # Group attempts within this window
        'timing_std_threshold': 5.0   # Seconds - low std = scripted
    }
    
    def __init__(self, case_id: int, analysis_id: str, thresholds: dict = None):
        pass
    
    def detect(self) -> list:
        """
        Main entry point.
        
        Returns:
            list[GapDetectionFinding]: List of spray findings
        """
        pass
    
    def _find_spray_candidates(self) -> list:
        """
        Query ClickHouse for sources with high unique user counts.
        
        Returns sources that exceed thresholds for further analysis.
        """
        pass
    
    def _analyze_candidate(self, source_ip: str, events: list) -> dict:
        """
        Deep analysis of a spray candidate.
        
        Analyzes:
        - Timing regularity (scripted vs manual)
        - Username patterns (dictionary, sequential, admin-targeting)
        - Success analysis (which accounts succeeded?)
        - Baseline comparison (is this source normally active?)
        
        Returns:
            GapDetectionFinding or None if below confidence threshold
        """
        pass
    
    def _calculate_confidence(self, metrics: dict) -> float:
        """
        Weighted confidence scoring.
        
        See confidence formula below.
        """
        pass
    
    def _analyze_timing_pattern(self, timestamps: list) -> dict:
        """
        Calculate inter-attempt timing statistics.
        
        Returns:
            dict: {
                'mean_interval': float (seconds),
                'std_interval': float (seconds),
                'is_scripted': bool (std < threshold)
            }
        """
        pass
    
    def _analyze_username_patterns(self, usernames: list) -> dict:
        """
        Analyze attempted usernames for attack patterns.
        
        Checks:
        - Dictionary words
        - Sequential patterns (admin1, admin2, admin3)
        - Admin account targeting (admin, administrator, svc_*)
        - Percentage of non-existent usernames
        
        Returns:
            dict: {
                'has_dictionary_pattern': bool,
                'has_sequential_pattern': bool,
                'targets_admin_accounts': bool,
                'unknown_username_pct': float
            }
        """
        pass
    
    def _check_baseline(self, source_ip: str) -> dict:
        """
        Compare current behavior to source IP's historical baseline.
        
        Returns:
            dict: {
                'has_baseline': bool,
                'baseline_daily_auth': float,
                'current_auth_count': int,
                'deviation_factor': float
            }
        """
        pass
```

#### ClickHouse Query - Find Spray Candidates:

```sql
SELECT 
    src_ip,
    count(DISTINCT username) as unique_users,
    count() as total_attempts,
    countIf(event_id = '4625') as failures,
    countIf(event_id = '4624') as successes,
    min(timestamp_utc) as first_attempt,
    max(timestamp_utc) as last_attempt,
    dateDiff('second', min(timestamp_utc), max(timestamp_utc)) as duration_seconds,
    groupArray(username) as usernames_attempted,
    groupArray(timestamp_utc) as attempt_times
FROM casescope.events
WHERE case_id = {case_id:UInt32}
  AND event_id IN ('4624', '4625')
  AND src_ip IS NOT NULL
  AND src_ip != toIPv4('0.0.0.0')
GROUP BY src_ip
HAVING unique_users >= {min_unique_users:UInt32}
   AND failures / (failures + successes + 0.001) >= {min_failure_rate:Float32}
ORDER BY unique_users DESC
```

#### Confidence Scoring Formula:

| Indicator | Points | Condition |
|-----------|--------|-----------|
| High unique username count | +20 | unique_users > 50 |
| Very high failure rate | +15 | failure_rate > 95% |
| Scripted timing | +15 | timing_std < 3 seconds |
| Off-hours activity | +10 | Outside 7am-7pm local |
| Unknown usernames targeted | +10 | >20% usernames not in known_users |
| Admin account targeting | +10 | Targets include admin, administrator, svc_* |
| Source not in baseline | +10 | Source IP never seen before this activity |
| Baseline deviation extreme | +10 | Current volume > 10x historical |
| **Deductions:** | | |
| Source is known service | -15 | Source IP is known scanner/service |
| Partial success pattern | -10 | Some successes mixed in (might be user error) |

**Confidence Bands:**
- 75+ = High confidence spraying
- 50-74 = Medium confidence, analyst review needed
- <50 = Low confidence, informational only

---

### Task 3.2: Brute Force Detector

**File:** `/opt/casescope/utils/gap_detectors/brute_force.py`

**Purpose:** Detect brute force attacks against single accounts.

#### Class: `BruteForceDetector`

```python
class BruteForceDetector:
    """
    Detects brute force attacks against individual accounts.
    
    Brute force = many password attempts against single username.
    Also detects distributed brute force (multiple sources → single target).
    """
    
    DEFAULT_THRESHOLDS = {
        'min_attempts': 20,              # Minimum attempts against single user
        'min_failure_rate': 0.95,        # 95% failure rate
        'time_window_hours': 1,          # Time window for grouping
        'distributed_source_threshold': 3 # 3+ sources = distributed attack
    }
    
    def __init__(self, case_id: int, analysis_id: str, thresholds: dict = None):
        pass
    
    def detect(self) -> list:
        """
        Main entry point.
        
        Returns:
            list[GapDetectionFinding]: Brute force findings
        """
        pass
    
    def _find_brute_candidates(self) -> list:
        """
        Query ClickHouse for users with high failure counts.
        """
        pass
    
    def _analyze_candidate(self, username: str, events: list) -> dict:
        """
        Deep analysis of brute force candidate.
        """
        pass
    
    def _detect_distributed_attack(self, username: str, events: list) -> bool:
        """
        Check if multiple source IPs are targeting same user.
        
        Returns:
            bool: True if distributed attack pattern detected
        """
        pass
    
    def _calculate_confidence(self, metrics: dict) -> float:
        """
        Confidence scoring for brute force.
        """
        pass
    
    def _check_user_baseline(self, username: str) -> dict:
        """
        Compare to user's normal failure rate.
        """
        pass
```

#### ClickHouse Query - Find Brute Force Candidates:

```sql
SELECT 
    username,
    count(DISTINCT src_ip) as source_count,
    count() as total_attempts,
    countIf(event_id = '4625') as failures,
    countIf(event_id = '4624') as successes,
    min(timestamp_utc) as first_attempt,
    max(timestamp_utc) as last_attempt,
    groupArray(src_ip) as source_ips,
    groupArray(timestamp_utc) as attempt_times
FROM casescope.events
WHERE case_id = {case_id:UInt32}
  AND event_id IN ('4624', '4625')
  AND username != ''
  AND username NOT LIKE '%$'  -- Exclude computer accounts
GROUP BY username
HAVING failures >= {min_attempts:UInt32}
   AND failures / (failures + successes + 0.001) >= {min_failure_rate:Float32}
ORDER BY failures DESC
```

---

### Task 3.3: Behavioral Anomaly Detector

**File:** `/opt/casescope/utils/gap_detectors/behavioral_anomaly.py`

**Purpose:** Find users and systems behaving outside their baseline and peer group norms.

#### Class: `BehavioralAnomalyDetector`

```python
class BehavioralAnomalyDetector:
    """
    Detects entities behaving anomalously compared to their baseline and peers.
    
    This catches attacks that don't trigger specific Sigma rules but represent
    significant deviations from normal behavior.
    
    Key insight: A compromised user's OWN baseline may be polluted, so we also
    compare to PEER behavior to catch anomalies.
    """
    
    def __init__(self, case_id: int, analysis_id: str, z_score_threshold: float = 3.0):
        """
        Args:
            z_score_threshold: How many standard deviations = anomaly (default 3.0)
        """
        pass
    
    def detect(self) -> list:
        """
        Iterate through all profiled users and systems.
        Flag those with high z-scores vs peers.
        
        Returns:
            list[GapDetectionFinding]: Anomaly findings
        """
        pass
    
    def _analyze_user_anomalies(self, user_profile, peer_stats) -> dict:
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
        pass
    
    def _analyze_system_anomalies(self, system_profile, peer_stats) -> dict:
        """
        Same analysis for systems.
        """
        pass
    
    def _calculate_composite_anomaly_score(self, z_scores: dict) -> float:
        """
        Weighted combination of individual z-scores.
        
        Weights:
        - auth_volume: 0.3
        - failure_rate: 0.25
        - off_hours: 0.15
        - new_targets: 0.2
        - auth_method_change: 0.1
        """
        pass
    
    def _identify_anomaly_type(self, z_scores: dict) -> str:
        """
        Categorize the primary anomaly type for reporting.
        """
        pass
```

#### Anomaly Types:

| Anomaly Type | Detection Logic | Severity |
|--------------|-----------------|----------|
| Volume Spike | Daily auth count z-score > 3 | High if > 5 |
| Failure Spike | Failure count z-score > 3 | High |
| Off-Hours Activity | Off-hours % z-score > 3 | Medium |
| New Target Access | User accessing hosts not in typical_target_hosts | Medium |
| Auth Method Change | Significant shift from Kerberos to NTLM | Medium |
| Privilege Behavior | Non-admin accessing admin resources | High |

---

### Task 3.4: Gap Detector Manager

**File:** `/opt/casescope/utils/gap_detectors/__init__.py`

**Purpose:** Orchestrate all gap detectors.

#### Class: `GapDetectionManager`

```python
class GapDetectionManager:
    """
    Orchestrates all gap detection modules.
    
    Runs enabled detectors and combines/deduplicates results.
    """
    
    def __init__(self, case_id: int, analysis_id: str):
        pass
    
    def run_all_detectors(self) -> list:
        """
        Run all enabled gap detectors.
        
        Order:
        1. Password spraying
        2. Brute force
        3. Behavioral anomalies
        
        Deduplicates overlapping findings.
        
        Returns:
            list[GapDetectionFinding]: Combined findings
        """
        pass
    
    def _deduplicate_findings(self, findings: list) -> list:
        """
        Remove or merge overlapping findings.
        
        Example: If spray and brute force flag same source IP for
        different reasons, merge into single finding with both contexts.
        """
        pass
```

---

## Phase 4: Correlation Engine Enhancement

### Task 4.1: Hayabusa Detection Correlator

**File:** `/opt/casescope/utils/hayabusa_correlator.py`

**Purpose:** Correlate Hayabusa-tagged events into attack chains.

#### Class: `HayabusaCorrelator`

```python
class HayabusaCorrelator:
    """
    Correlates Hayabusa/Sigma detections into attack chains.
    
    Hayabusa tags individual events with rule_title, mitre_tactics, etc.
    This class groups related detections by:
    - Time window
    - Correlation key (user + host, or source IP + target)
    - MITRE tactic progression
    
    Output: Correlated detection groups that represent potential attack sequences.
    """
    
    def __init__(self, case_id: int, analysis_id: str, time_window_minutes: int = 60):
        pass
    
    def correlate(self) -> list:
        """
        Group related Hayabusa detections.
        
        Returns:
            list[CorrelatedDetectionGroup]: Grouped detections
        """
        pass
    
    def _find_detection_clusters(self) -> list:
        """
        Query ClickHouse for events with rule_title set.
        Group by time window and correlation key.
        """
        pass
    
    def _build_correlation_key(self, event: dict) -> str:
        """
        Determine appropriate grouping key for an event.
        
        Options:
        - "{username}|{source_host}" for user-based correlation
        - "{src_ip}|{remote_host}" for network-based correlation
        - "{source_host}|{process_name}" for process-based correlation
        
        Selection based on event type and available fields.
        """
        pass
    
    def _analyze_cluster(self, events: list) -> dict:
        """
        Analyze a cluster of related detections.
        
        Determines:
        - Combined severity (highest among events)
        - Attack chain progression (tactic sequence)
        - Involved entities
        - Time span
        """
        pass
    
    def _identify_attack_chain(self, mitre_tactics: list, mitre_techniques: list) -> str:
        """
        Map tactics to kill chain progression.
        
        Examples:
        - [initial-access, execution] → "Initial compromise"
        - [credential-access, lateral-movement] → "Credential theft with lateral movement"
        - [persistence, defense-evasion] → "Establishing persistence"
        
        Returns human-readable attack chain description.
        """
        pass
    
    def _enrich_with_behavioral_context(self, group: dict, user_profile, system_profile):
        """
        Add behavioral baseline comparison to detection group.
        
        Adds:
        - User baseline vs observed behavior
        - System baseline vs observed behavior
        - Peer comparison z-scores
        - Anomaly flags
        """
        pass
```

#### ClickHouse Query - Get Hayabusa Detections:

```sql
SELECT 
    uuid,
    timestamp_utc,
    username,
    source_host,
    src_ip,
    remote_host,
    event_id,
    rule_title,
    rule_level,
    rule_file,
    mitre_tactics,
    mitre_tags,
    process_name,
    command_line,
    logon_type,
    auth_package
FROM casescope.events
WHERE case_id = {case_id:UInt32}
  AND rule_title IS NOT NULL
  AND rule_title != ''
ORDER BY timestamp_utc
```

---

### Task 4.2: Enhance Existing Pattern Matcher

**File:** Modify `/opt/casescope/utils/candidate_extractor.py`

**Purpose:** Add behavioral context to pattern matching.

#### Changes to `CandidateExtractor`:

```python
# Add these methods to existing CandidateExtractor class

def _attach_behavioral_context(self, candidates: list) -> list:
    """
    For each candidate event group, lookup user and system profiles.
    Attach z-scores and anomaly flags.
    
    Args:
        candidates: List of candidate event groups
        
    Returns:
        list: Candidates with behavioral_context field added
    """
    pass

def _attach_peer_comparison(self, candidates: list) -> list:
    """
    Add peer group comparison data to candidates.
    
    For each involved user/system:
    - Lookup peer group
    - Calculate z-scores vs peer median
    - Flag significant deviations
    """
    pass

def _calculate_behavioral_confidence_modifier(self, candidate: dict) -> float:
    """
    Calculate confidence modifier based on behavioral analysis.
    
    Returns:
        float: Modifier from -20 to +20
        
    Positive (more suspicious):
    - User z-score > 2 vs peers: +5 to +15
    - System z-score > 2 vs peers: +5 to +10
    - Off-hours activity: +5
    - New target access: +5
    
    Negative (less suspicious):
    - Behavior matches baseline: -10 to -20
    - Common pattern for this user/system: -5 to -10
    """
    pass
```

---

### Task 4.3: Enhance AI Correlation Analyzer

**File:** Modify `/opt/casescope/utils/ai_correlation_analyzer.py`

**Purpose:** Update prompts to include behavioral context; handle Mode A (no AI).

#### Changes to `AICorrelationAnalyzer`:

```python
# Add these methods to existing AICorrelationAnalyzer class

def analyze_without_ai(self, candidates: list, pattern_config: dict) -> dict:
    """
    Mode A/C path: Pure rule-based analysis without AI.
    
    Returns structured finding with:
    - Confidence score (calculated from criteria + behavioral factors)
    - Criteria checklist (which indicators matched)
    - Behavioral context summary
    - No AI reasoning (field set to None)
    
    This ensures the system works without AI dependency.
    """
    pass

def _build_behavioral_context_section(self, user_profile, system_profile, peer_comparison) -> str:
    """
    Format behavioral data for AI prompt.
    
    Example output:
    '''
    BEHAVIORAL CONTEXT:
    - User: jsmith
      - Baseline: 12 logons/day, 1.2% failure rate
      - Current: 847 logons in 2 hours, 99% failure rate
      - Z-Score vs Self: +156 (extreme)
      - Z-Score vs Peers: +98 (extreme outlier in peer group)
      - Anomaly Flags: volume_spike, failure_spike, off_hours
    '''
    """
    pass

def _build_opencti_context_section(self, pattern_id: str, mitre_techniques: list) -> str:
    """
    If OpenCTI enabled, fetch and format threat intel context.
    If not enabled, return empty string.
    
    Example output:
    '''
    THREAT INTELLIGENCE CONTEXT:
    - MITRE Technique: T1110.003 - Password Spraying
    - Detection Guidance: "Monitor for many failed auth attempts..."
    - Associated Threat Actors: APT28, APT29, FIN7
    - Recent Campaigns: [list if available]
    '''
    """
    pass
```

#### Updated Prompt Structure:

```
ATTACK PATTERN ANALYSIS: {pattern_name}

DETECTION CRITERIA:
{pattern checklist from pattern_rules.py - numbered list of indicators}

{IF OPENCTI ENABLED}
THREAT INTELLIGENCE CONTEXT:
- MITRE Technique: {technique_id} - {technique_name}
- Detection Guidance: {x_mitre_detection from OpenCTI}
- Associated Threat Actors: {intrusion sets using this technique}
- Related Sigma Rules Not in Hayabusa: {gap rules from OpenCTI}
{END IF}

BEHAVIORAL CONTEXT:
- User: {username}
  - Baseline: {avg_daily_logons} logons/day, {failure_rate}% failure rate
  - Current Activity: {observed_logons} logons, {observed_failure_rate}% failures
  - Z-Score vs Own Baseline: {self_z_score}
  - Z-Score vs Peer Group ({peer_group_name}, {peer_count} members): {peer_z_score}
  - Anomaly Flags: {list of anomalies detected}
  
- System: {hostname}
  - Role: {inferred_role}
  - Baseline: {typical_metrics}
  - Current Activity: {observed_metrics}
  - Z-Score vs Peer Systems: {system_peer_z_score}

{IF case has IOCs}
KNOWN IOCS FOR THIS CASE:
{list of relevant IOCs that match any event data}
{END IF}

HAYABUSA DETECTIONS IN THIS GROUP:
{For each Hayabusa-tagged event in candidate group:}
- {rule_title} (Level: {rule_level}) - {mitre_tactics}

CANDIDATE EVENTS:
{Formatted events with relevant fields}

ANALYSIS INSTRUCTIONS:
Analyze these events for {pattern_name}. Consider:
1. Which detection criteria are met?
2. How does the behavioral context affect your assessment?
3. Do the Hayabusa detections support this pattern?
4. What is the likelihood this is a false positive?

Respond with JSON:
{
  "confidence": <0-100>,
  "reasoning": "<2-4 sentences explaining your analysis, citing specific evidence>",
  "indicators_found": ["<list of matched indicators>"],
  "behavioral_factors": {
    "supports_detection": ["<anomalies that support this being an attack>"],
    "against_detection": ["<factors suggesting normal behavior>"]
  },
  "suggested_iocs": ["<IPs, accounts, hashes discovered>"],
  "false_positive_likelihood": "<low/medium/high>",
  "false_positive_reason": "<if medium/high, explain why>",
  "checklist_results": {
    "<indicator_1>": true/false,
    "<indicator_2>": true/false,
    ...
  }
}
```

---

## Phase 5: OpenCTI Integration Enhancement

### Task 5.1: OpenCTI Context Provider

**File:** `/opt/casescope/utils/opencti_context.py`

**Purpose:** Centralized OpenCTI data fetching for analysis.

#### Class: `OpenCTIContextProvider`

```python
class OpenCTIContextProvider:
    """
    Provides threat intelligence context from OpenCTI.
    
    Caches responses to avoid repeated API calls during analysis.
    Gracefully handles OpenCTI being unavailable.
    """
    
    def __init__(self, case_id: int):
        """
        Args:
            case_id: Used for caching context to case
        """
        pass
    
    def is_available(self) -> bool:
        """
        Check if OpenCTI is enabled and connected.
        
        Returns:
            bool: True if OpenCTI can be used
        """
        pass
    
    def get_attack_pattern_context(self, mitre_technique_id: str) -> dict:
        """
        Get context for a MITRE technique.
        
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
        pass
    
    def get_threat_actor_context(self, technique_ids: list) -> list:
        """
        Get threat actors known to use these techniques.
        
        Returns:
            list[dict]: [{
                'name': str,
                'aliases': list,
                'description': str,
                'techniques_used': list  # From the input list
            }]
        """
        pass
    
    def get_sigma_rules_not_in_hayabusa(self, technique_id: str) -> list:
        """
        Get Sigma rules from OpenCTI that may not be in Hayabusa's ruleset.
        
        Compares by rule name/id to avoid duplicates.
        
        Returns:
            list[dict]: [{
                'name': str,
                'sigma_rule': str,  # YAML content
                'description': str
            }]
        """
        pass
    
    def enrich_ioc(self, ioc_value: str, ioc_type: str) -> dict:
        """
        Check if IOC is known in OpenCTI threat feeds.
        
        Returns:
            dict: {
                'found': bool,
                'threat_actors': list,
                'campaigns': list,
                'confidence': int,
                'labels': list
            }
        """
        pass
    
    def get_campaign_context(self, technique_ids: list, days_back: int = 90) -> list:
        """
        Get recent threat reports/campaigns using these techniques.
        
        Returns:
            list[dict]: [{
                'name': str,
                'published': datetime,
                'description': str,
                'techniques': list
            }]
        """
        pass
```

#### Caching Strategy:

- Cache responses in PostgreSQL table: `opencti_cache`
  - Columns: `case_id`, `query_type`, `query_params_hash`, `response_json`, `cached_at`
- Cache TTL: Duration of analysis run (clear at start of new run)
- On cache miss: Call OpenCTI API, store result
- On cache hit: Return stored result

---

### Task 5.2: Graceful Degradation Handler

**File:** `/opt/casescope/utils/feature_availability.py`

**Purpose:** Centralized feature availability checking.

#### Class: `FeatureAvailability`

```python
class FeatureAvailability:
    """
    Centralized feature availability checking.
    
    Determines what analysis capabilities are available based on:
    - Configuration settings
    - Service connectivity (Ollama, OpenCTI)
    """
    
    @classmethod
    def is_ai_enabled(cls) -> bool:
        """
        Check if AI is available.
        
        Checks:
        1. AI_ANALYSIS_ENABLED in config
        2. analysis.ai_enabled in system_settings
        3. Ollama service connectivity
        
        Returns:
            bool: True if AI can be used
        """
        pass
    
    @classmethod
    def is_opencti_enabled(cls) -> bool:
        """
        Check if OpenCTI is available.
        
        Checks:
        1. OPENCTI_ENABLED in config
        2. analysis.opencti_enabled in system_settings
        3. OpenCTI API connectivity
        
        Returns:
            bool: True if OpenCTI can be used
        """
        pass
    
    @classmethod
    def get_analysis_mode(cls) -> str:
        """
        Determine current analysis mode.
        
        Returns:
            str: 'A', 'B', 'C', or 'D'
            
        Mode determination:
        - A: No OpenCTI, No AI
        - B: No OpenCTI, AI enabled
        - C: OpenCTI enabled, No AI
        - D: OpenCTI enabled, AI enabled
        """
        pass
    
    @classmethod
    def get_available_capabilities(cls) -> dict:
        """
        Get detailed capability breakdown.
        
        Returns:
            dict: {
                'mode': str,  # A, B, C, D
                'ai_reasoning': bool,
                'ai_explanations': bool,
                'threat_intel_enrichment': bool,
                'sigma_gap_rules': bool,
                'threat_actor_context': bool,
                'ioc_enrichment': bool,
                'behavioral_profiling': True,  # Always available
                'peer_comparison': True,  # Always available
                'pattern_detection': True,  # Always available
                'gap_detection': True,  # Always available
            }
        """
        pass
```

---

## Phase 6: Analysis Orchestration

### Task 6.1: Main Analysis Orchestrator

**File:** `/opt/casescope/utils/case_analyzer.py`

**Purpose:** Orchestrates the full analysis pipeline.

#### Class: `CaseAnalyzer`

```python
class CaseAnalyzer:
    """
    Main orchestrator for case analysis.
    
    Coordinates all analysis phases:
    1. Behavioral profiling
    2. Peer group clustering
    3. Gap detection
    4. Hayabusa correlation
    5. Pattern analysis
    6. OpenCTI enrichment (if available)
    7. Suggested action generation
    
    Adapts behavior based on available features (Mode A/B/C/D).
    """
    
    def __init__(self, case_id: int):
        self.case_id = case_id
        self.analysis_id = None  # Set during initialization
        self.mode = None  # Set based on feature availability
        self.progress_callback = None  # Optional callback for progress updates
    
    def run_full_analysis(self) -> str:
        """
        Main entry point.
        
        Returns:
            str: analysis_id for this run
            
        Raises:
            AnalysisError: If analysis fails
        """
        pass
    
    def _initialize_analysis_run(self) -> str:
        """
        Create case_analysis_runs record.
        Determine mode based on feature availability.
        
        Returns:
            str: analysis_id (UUID)
        """
        pass
    
    def _update_progress(self, phase: str, percent: int, message: str):
        """
        Update progress in database and emit socket event.
        
        Args:
            phase: Current phase name
            percent: Progress percentage (0-100)
            message: Human-readable status message
        """
        pass
    
    def _run_behavioral_profiling(self) -> dict:
        """
        Phase 1: Build behavioral profiles.
        
        Progress: 0-20%
        
        Returns:
            dict: {
                'users_profiled': int,
                'systems_profiled': int,
                'duration_seconds': float
            }
        """
        pass
    
    def _run_peer_clustering(self) -> dict:
        """
        Phase 2: Build peer groups.
        
        Progress: 15-20%
        
        Returns:
            dict: {
                'user_groups': int,
                'system_groups': int
            }
        """
        pass
    
    def _run_gap_detection(self) -> list:
        """
        Phase 3: Run gap detectors.
        
        Progress: 20-35%
        
        Returns:
            list[GapDetectionFinding]
        """
        pass
    
    def _run_hayabusa_correlation(self) -> list:
        """
        Phase 4: Correlate Hayabusa detections.
        
        Progress: 35-50%
        
        Returns:
            list[CorrelatedDetectionGroup]
        """
        pass
    
    def _run_pattern_analysis(self, correlated_groups: list) -> list:
        """
        Phase 5: Run pattern analysis.
        
        Progress: 50-85%
        
        Integrates with existing:
        - candidate_extractor.py
        - ai_correlation_analyzer.py
        
        Mode A/C: Uses analyze_without_ai()
        Mode B/D: Uses full AI analysis
        
        Returns:
            list: Pattern analysis results (stored in ai_analysis_results)
        """
        pass
    
    def _enrich_with_opencti(self, all_findings: list):
        """
        Phase 6: Add OpenCTI context (Mode C/D only).
        
        Progress: 85-90%
        
        Updates findings in-place with threat intel.
        """
        pass
    
    def _generate_suggested_actions(self, all_findings: list) -> list:
        """
        Phase 7: Create suggested actions.
        
        Progress: 90-95%
        
        Rules:
        - Confidence >= 75 AND entity identified → suggest mark compromised
        - IOCs discovered → suggest add to case IOCs
        - High severity finding → suggest investigate
        
        Returns:
            list[SuggestedAction]
        """
        pass
    
    def _finalize_analysis(self, all_findings: list):
        """
        Phase 8: Finalize.
        
        Progress: 95-100%
        
        - Update case_analysis_runs with final stats
        - Mark analysis complete
        - Calculate summary metrics
        """
        pass
```

#### Analysis Pipeline Flow:

```
┌────────────────────────────────────────────────────────────────┐
│                    ANALYSIS PIPELINE                           │
├────────────────────────────────────────────────────────────────┤
│                                                                │
│  1. INITIALIZE (0%)                                            │
│     └── Create analysis run record                             │
│     └── Determine mode (A/B/C/D)                               │
│                                                                │
│  2. BEHAVIORAL PROFILING (0-20%)                               │
│     └── Profile all users (0-10%)                              │
│     └── Profile all systems (10-15%)                           │
│     └── Build peer groups (15-20%)                             │
│                                                                │
│  3. GAP DETECTION (20-35%)                                     │
│     └── Password spraying detector (20-25%)                    │
│     └── Brute force detector (25-30%)                          │
│     └── Behavioral anomaly detector (30-35%)                   │
│                                                                │
│  4. HAYABUSA CORRELATION (35-50%)                              │
│     └── Query Hayabusa-tagged events (35-40%)                  │
│     └── Build detection groups (40-45%)                        │
│     └── Identify attack chains (45-50%)                        │
│                                                                │
│  5. PATTERN ANALYSIS (50-85%)                                  │
│     └── For each of 58 patterns:                               │
│         └── Extract candidates with behavioral context         │
│         └── Mode A/C: Rule-based analysis                      │
│         └── Mode B/D: AI-enhanced analysis                     │
│         └── Store results                                      │
│                                                                │
│  6. OPENCTI ENRICHMENT (85-90%) [Mode C/D only]                │
│     └── Enrich findings with threat intel                      │
│                                                                │
│  7. SUGGESTED ACTIONS (90-95%)                                 │
│     └── Generate analyst suggestions                           │
│                                                                │
│  8. FINALIZE (95-100%)                                         │
│     └── Calculate statistics                                   │
│     └── Mark complete                                          │
│                                                                │
└────────────────────────────────────────────────────────────────┘
```

---

### Task 6.2: Celery Task

**File:** Modify `/opt/casescope/tasks/rag_tasks.py`

**Purpose:** Add Celery task for running full analysis.

#### New Task: `run_case_analysis`

```python
@celery.task(bind=True)
def run_case_analysis(self, case_id: int) -> dict:
    """
    Run full case analysis pipeline.
    
    This is a long-running task that:
    1. Builds behavioral profiles for all users/systems
    2. Creates peer groups for comparison
    3. Runs gap detection (spraying, brute force, behavioral anomalies)
    4. Correlates Hayabusa detections into attack chains
    5. Runs pattern analysis (AI-enhanced if available)
    6. Enriches with OpenCTI (if available)
    7. Generates suggested actions for analyst review
    
    Args:
        case_id: The case to analyze
        
    Returns:
        dict: {
            'success': bool,
            'analysis_id': str (if success),
            'error': str (if failure),
            'summary': dict (findings counts, etc.)
        }
    """
    from utils.case_analyzer import CaseAnalyzer
    
    analyzer = CaseAnalyzer(case_id)
    
    # Hook up progress callback to Celery task state
    def progress_callback(phase: str, percent: int, message: str):
        self.update_state(
            state='PROGRESS',
            meta={
                'phase': phase,
                'percent': percent,
                'message': message
            }
        )
    
    analyzer.progress_callback = progress_callback
    
    try:
        analysis_id = analyzer.run_full_analysis()
        
        # Get summary for response
        from utils.analysis_results_formatter import AnalysisResultsFormatter
        formatter = AnalysisResultsFormatter(analysis_id)
        summary = formatter.get_summary()
        
        return {
            'success': True,
            'analysis_id': analysis_id,
            'summary': summary
        }
        
    except Exception as e:
        logger.exception(f"Analysis failed for case {case_id}")
        return {
            'success': False,
            'error': str(e)
        }
```

---

## Phase 7: Results Output Formatting

### Task 7.1: Results Formatter

**File:** `/opt/casescope/utils/analysis_results_formatter.py`

**Purpose:** Format analysis results for different output modes and views.

#### Class: `AnalysisResultsFormatter`

```python
class AnalysisResultsFormatter:
    """
    Formats analysis results for display and export.
    
    Supports multiple views:
    - Timeline (chronological)
    - By Pattern (grouped by attack type)
    - By Entity (grouped by user/system)
    
    Adapts output based on analysis mode (A/B/C/D).
    """
    
    def __init__(self, analysis_id: str):
        self.analysis_id = analysis_id
        self.analysis_run = None  # Loaded from case_analysis_runs
    
    def get_summary(self) -> dict:
        """
        High-level summary of analysis run.
        
        Returns:
            dict: {
                'analysis_id': str,
                'case_id': int,
                'mode': str,
                'mode_description': str,
                'started_at': datetime,
                'completed_at': datetime,
                'duration_seconds': float,
                'capabilities_used': {
                    'behavioral_profiling': True,
                    'peer_comparison': True,
                    'ai_reasoning': bool,
                    'threat_intel': bool
                },
                'statistics': {
                    'total_events_analyzed': int,
                    'users_profiled': int,
                    'systems_profiled': int,
                    'peer_groups_created': int,
                    'patterns_evaluated': int,
                    'total_findings': int,
                    'high_confidence_findings': int,
                    'gap_findings': int,
                    'pattern_findings': int
                },
                'severity_breakdown': {
                    'critical': int,
                    'high': int,
                    'medium': int,
                    'low': int
                },
                'top_findings': [<top 5 by confidence>],
                'suggested_actions_pending': int
            }
        """
        pass
    
    def get_timeline_view(self) -> list:
        """
        All findings sorted chronologically.
        
        Returns:
            list[dict]: [{
                'timestamp': datetime,
                'finding_type': str,  # 'pattern' or 'gap'
                'finding_id': int,
                'name': str,
                'summary': str,
                'severity': str,
                'confidence': float,
                'entities_involved': list,
                'has_ai_reasoning': bool,
                'has_threat_intel': bool
            }]
        """
        pass
    
    def get_pattern_grouped_view(self) -> dict:
        """
        Findings grouped by pattern/finding type.
        
        Returns:
            dict: {
                'credential_access': {
                    'findings': [list of findings],
                    'count': int,
                    'high_confidence_count': int
                },
                'lateral_movement': {...},
                'gap_detection': {
                    'password_spraying': {...},
                    'brute_force': {...},
                    'behavioral_anomaly': {...}
                },
                ...
            }
        """
        pass
    
    def get_entity_grouped_view(self) -> dict:
        """
        Findings grouped by affected entity.
        
        Returns:
            dict: {
                'users': {
                    'jsmith': {
                        'user_id': int,
                        'is_compromised': bool,
                        'findings': [list],
                        'behavioral_summary': dict,
                        'anomaly_flags': list
                    },
                    ...
                },
                'systems': {
                    'DC01': {
                        'system_id': int,
                        'is_compromised': bool,
                        'findings': [list],
                        'behavioral_summary': dict
                    },
                    ...
                },
                'source_ips': {
                    '10.5.5.100': {
                        'findings': [list],
                        'is_internal': bool
                    },
                    ...
                }
            }
        """
        pass
    
    def get_finding_detail(self, finding_id: int, finding_type: str) -> dict:
        """
        Full detail for a single finding.
        
        Args:
            finding_id: ID of the finding
            finding_type: 'pattern' or 'gap'
            
        Returns:
            dict: Complete finding with all context including:
            - Full evidence
            - Behavioral context
            - Peer comparison
            - AI reasoning (if Mode B/D)
            - OpenCTI context (if Mode C/D)
            - Related events (UUIDs for event browser link)
            - Suggested actions for this finding
        """
        pass
    
    def get_suggested_actions(self) -> list:
        """
        All pending suggested actions.
        
        Returns:
            list[dict]: [{
                'id': int,
                'action_type': str,
                'target': str,
                'reason': str,
                'confidence': float,
                'source_finding': {
                    'type': str,
                    'id': int,
                    'name': str
                },
                'status': str
            }]
        """
        pass
    
    def export_report(self, format: str = 'json') -> str:
        """
        Export full results.
        
        Args:
            format: 'json', 'csv', or 'markdown'
            
        Returns:
            str: Formatted report content
        """
        pass
```

---

### Task 7.2: Mode-Specific Output Structure

**Purpose:** Ensure output clearly indicates what analysis was performed.

#### Mode A Output Example (No AI, No OpenCTI):

```json
{
  "analysis_mode": "A",
  "mode_description": "Rule-based analysis with behavioral profiling",
  "capabilities_used": {
    "behavioral_profiling": true,
    "peer_comparison": true,
    "pattern_detection": true,
    "gap_detection": true,
    "ai_reasoning": false,
    "threat_intel": false
  },
  "finding": {
    "id": 123,
    "type": "pattern",
    "pattern": "pass_the_hash",
    "pattern_name": "Pass the Hash",
    "confidence": 73,
    "severity": "high",
    "confidence_breakdown": {
      "criteria_score": 45,
      "behavioral_modifier": 15,
      "peer_deviation_modifier": 8,
      "hayabusa_severity_bonus": 5,
      "total": 73
    },
    "criteria_checklist": {
      "NTLM authentication with KeyLength=0": true,
      "Logon Type 3 or 9": true,
      "No prior Kerberos TGT request": true,
      "Same source to multiple targets": true,
      "Privileged account": true,
      "Suspicious process (psexec/wmic/powershell)": false
    },
    "behavioral_context": {
      "user": {
        "username": "jsmith",
        "baseline_daily_logons": 12,
        "observed_logons": 847,
        "z_score_self": 156.2,
        "z_score_peers": 98.4,
        "anomaly_flags": ["volume_spike", "off_hours"]
      },
      "system": {
        "hostname": "DC01",
        "role": "domain_controller",
        "baseline_auth_volume": 15000,
        "observed_auth_volume": 15234,
        "z_score_peers": 0.8
      }
    },
    "ai_reasoning": null,
    "threat_intel_context": null,
    "events": ["uuid1", "uuid2", "..."],
    "time_window": {
      "start": "2024-01-15T02:00:00Z",
      "end": "2024-01-15T04:15:00Z"
    }
  }
}
```

#### Mode D Output Example (Full Stack):

```json
{
  "analysis_mode": "D",
  "mode_description": "Full analysis with AI reasoning and threat intelligence",
  "capabilities_used": {
    "behavioral_profiling": true,
    "peer_comparison": true,
    "pattern_detection": true,
    "gap_detection": true,
    "ai_reasoning": true,
    "threat_intel": true
  },
  "finding": {
    "id": 123,
    "type": "pattern",
    "pattern": "pass_the_hash",
    "pattern_name": "Pass the Hash",
    "confidence": 89,
    "severity": "critical",
    "confidence_breakdown": {
      "criteria_score": 45,
      "behavioral_modifier": 15,
      "peer_deviation_modifier": 8,
      "hayabusa_severity_bonus": 5,
      "ai_adjustment": 9,
      "threat_intel_bonus": 7,
      "total": 89
    },
    "criteria_checklist": {
      "NTLM authentication with KeyLength=0": true,
      "Logon Type 3 or 9": true,
      "No prior Kerberos TGT request": true,
      "Same source to multiple targets": true,
      "Privileged account": true,
      "Suspicious process (psexec/wmic/powershell)": false
    },
    "behavioral_context": {
      "user": {
        "username": "jsmith",
        "baseline_daily_logons": 12,
        "observed_logons": 847,
        "z_score_self": 156.2,
        "z_score_peers": 98.4,
        "anomaly_flags": ["volume_spike", "off_hours"]
      },
      "system": {
        "hostname": "DC01",
        "role": "domain_controller",
        "baseline_auth_volume": 15000,
        "observed_auth_volume": 15234,
        "z_score_peers": 0.8
      }
    },
    "ai_reasoning": "This is a high-confidence Pass-the-Hash attack. The user jsmith authenticated via NTLM with KeyLength=0 to 4 different systems (DC01, FILESVR, SQLSVR, HR01) within a 2-hour window. This is extremely anomalous - jsmith typically has 12 logons per day but generated 847 in this window, a 70x increase. Compared to peer users in the 'standard_users' group, this represents a z-score of 98.4, making jsmith an extreme outlier. The lack of Kerberos TGT requests before these NTLM authentications strongly suggests credential material was obtained and replayed rather than the user interactively authenticating. The targeting of a domain controller and file servers suggests the attacker is seeking to expand access.",
    "threat_intel_context": {
      "mitre_technique": {
        "id": "T1550.002",
        "name": "Use Alternate Authentication Material: Pass the Hash",
        "detection_guidance": "Monitor for NTLM LogonType 3 authentications that are not associated with a domain login and are not anonymous."
      },
      "associated_threat_actors": [
        {
          "name": "APT28",
          "aliases": ["Fancy Bear", "Sofacy"]
        },
        {
          "name": "APT29",
          "aliases": ["Cozy Bear", "The Dukes"]
        }
      ],
      "ioc_matches": [],
      "campaign_context": "Pass-the-Hash is commonly used in targeted intrusions after initial credential theft. Recent campaigns have used this technique following Kerberoasting or LSASS dumps."
    },
    "suggested_iocs": [
      {
        "type": "user_account",
        "value": "jsmith",
        "reason": "Account used in PTH attack"
      },
      {
        "type": "ip_address",
        "value": "10.0.0.55",
        "reason": "Source of PTH authentications"
      }
    ],
    "events": ["uuid1", "uuid2", "..."],
    "time_window": {
      "start": "2024-01-15T02:00:00Z",
      "end": "2024-01-15T04:15:00Z"
    }
  }
}
```

---

## Phase 8: Frontend Integration

### Task 8.1: API Endpoints

**File:** Add to appropriate routes blueprint (e.g., `/opt/casescope/routes/api.py` or create `/opt/casescope/routes/analysis.py`)

#### Endpoints:

```python
# Start analysis
@bp.route('/api/case/<int:case_id>/analysis/run', methods=['POST'])
def start_analysis(case_id):
    """
    Start case analysis Celery task.
    
    Returns:
        {
            'success': bool,
            'task_id': str,
            'analysis_id': str
        }
    """
    pass

# Get analysis status
@bp.route('/api/case/<int:case_id>/analysis/status/<analysis_id>', methods=['GET'])
def get_analysis_status(case_id, analysis_id):
    """
    Get current progress and status.
    
    Returns:
        {
            'status': str,  # pending, profiling, correlating, analyzing, complete, failed
            'progress_percent': int,
            'current_phase': str,
            'mode': str,
            'findings_count': int (if complete)
        }
    """
    pass

# Get analysis results
@bp.route('/api/case/<int:case_id>/analysis/results/<analysis_id>', methods=['GET'])
def get_analysis_results(case_id, analysis_id):
    """
    Get analysis results.
    
    Query params:
        view: 'timeline' | 'pattern' | 'entity' (default: 'timeline')
        format: 'json' | 'csv' (default: 'json')
        
    Returns:
        Formatted results based on view parameter
    """
    pass

# Get finding detail
@bp.route('/api/case/<int:case_id>/analysis/findings/<finding_type>/<int:finding_id>', methods=['GET'])
def get_finding_detail(case_id, finding_type, finding_id):
    """
    Get full detail for a single finding.
    
    Args:
        finding_type: 'pattern' or 'gap'
        finding_id: ID of the finding
        
    Returns:
        Complete finding with all context
    """
    pass

# Get suggested actions
@bp.route('/api/case/<int:case_id>/analysis/suggested-actions', methods=['GET'])
def get_suggested_actions(case_id):
    """
    Get pending suggested actions.
    
    Returns:
        List of pending suggestions
    """
    pass

# Handle suggested action
@bp.route('/api/case/<int:case_id>/analysis/suggested-actions/<int:action_id>', methods=['POST'])
def handle_suggested_action(case_id, action_id):
    """
    Accept or reject a suggested action.
    
    Body:
        {
            'status': 'accepted' | 'rejected',
            'notes': str (optional)
        }
        
    If accepted:
        - mark_user_compromised: Updates known_users.compromised = True
        - mark_system_compromised: Updates known_systems.compromised = True
        - add_ioc: Creates IOC record
        
    Returns:
        Updated action record
    """
    pass

# Get analysis history
@bp.route('/api/case/<int:case_id>/analysis/history', methods=['GET'])
def get_analysis_history(case_id):
    """
    Get list of past analysis runs for this case.
    
    Returns:
        List of case_analysis_runs records with summary stats
    """
    pass
```

---

### Task 8.2: UI Components

#### Component: Analysis Run Button

**Location:** Case dashboard, left of "AI Report" button

**HTML:**
```html
<button id="run-case-analysis-btn" 
        class="btn btn-primary" 
        data-case-id="{{ case.id }}"
        title="Run comprehensive case analysis">
    <i class="fas fa-microscope"></i> Run Case Analysis
</button>
```

**JavaScript Behavior:**
```javascript
$('#run-case-analysis-btn').click(function() {
    const caseId = $(this).data('case-id');
    
    // Disable button
    $(this).prop('disabled', true).html('<i class="fas fa-spinner fa-spin"></i> Starting...');
    
    // Start analysis
    $.post(`/api/case/${caseId}/analysis/run`)
        .done(function(response) {
            if (response.success) {
                // Open progress modal
                showAnalysisProgressModal(caseId, response.analysis_id, response.task_id);
            } else {
                showError(response.error);
            }
        })
        .fail(function() {
            showError('Failed to start analysis');
        })
        .always(function() {
            $('#run-case-analysis-btn').prop('disabled', false)
                .html('<i class="fas fa-microscope"></i> Run Case Analysis');
        });
});
```

---

#### Component: Progress Modal

**HTML Structure:**
```html
<div class="modal fade" id="analysis-progress-modal" tabindex="-1">
    <div class="modal-dialog">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title">
                    <i class="fas fa-microscope"></i> Case Analysis Running
                </h5>
            </div>
            <div class="modal-body">
                <!-- Mode indicator -->
                <div class="mode-indicator mb-3">
                    <span class="badge badge-info" id="analysis-mode-badge">Mode D</span>
                    <span class="badge" id="ai-status-badge">AI: Checking...</span>
                    <span class="badge" id="opencti-status-badge">OpenCTI: Checking...</span>
                </div>
                
                <!-- Progress bar -->
                <div class="progress mb-2" style="height: 25px;">
                    <div class="progress-bar progress-bar-striped progress-bar-animated" 
                         role="progressbar" 
                         id="analysis-progress-bar"
                         style="width: 0%">
                        0%
                    </div>
                </div>
                
                <!-- Current phase -->
                <p class="text-muted text-center" id="analysis-current-phase">
                    Initializing...
                </p>
                
                <!-- Stats (shown during analysis) -->
                <div class="analysis-stats mt-3" id="analysis-stats" style="display: none;">
                    <small class="text-muted">
                        Users profiled: <span id="stat-users">0</span> |
                        Systems profiled: <span id="stat-systems">0</span> |
                        Findings: <span id="stat-findings">0</span>
                    </small>
                </div>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-secondary" data-dismiss="modal" disabled id="analysis-close-btn">
                    Close
                </button>
            </div>
        </div>
    </div>
</div>
```

**JavaScript Polling:**
```javascript
function showAnalysisProgressModal(caseId, analysisId, taskId) {
    $('#analysis-progress-modal').modal({backdrop: 'static', keyboard: false});
    
    // Start polling
    const pollInterval = setInterval(function() {
        $.get(`/api/case/${caseId}/analysis/status/${analysisId}`)
            .done(function(status) {
                // Update progress bar
                $('#analysis-progress-bar')
                    .css('width', status.progress_percent + '%')
                    .text(status.progress_percent + '%');
                
                // Update phase text
                $('#analysis-current-phase').text(status.current_phase);
                
                // Update mode badges
                updateModeBadges(status.mode, status.ai_enabled, status.opencti_enabled);
                
                // Update stats if available
                if (status.statistics) {
                    $('#analysis-stats').show();
                    $('#stat-users').text(status.statistics.users_profiled || 0);
                    $('#stat-systems').text(status.statistics.systems_profiled || 0);
                    $('#stat-findings').text(status.statistics.findings_count || 0);
                }
                
                // Check if complete
                if (status.status === 'complete') {
                    clearInterval(pollInterval);
                    $('#analysis-progress-bar')
                        .removeClass('progress-bar-animated')
                        .addClass('bg-success');
                    $('#analysis-current-phase').html(
                        '<i class="fas fa-check text-success"></i> Analysis complete! ' +
                        `Found ${status.findings_count} findings.`
                    );
                    $('#analysis-close-btn').prop('disabled', false);
                    
                    // Optionally redirect to results
                    setTimeout(function() {
                        window.location.href = `/case/${caseId}/analysis/${analysisId}`;
                    }, 2000);
                    
                } else if (status.status === 'failed') {
                    clearInterval(pollInterval);
                    $('#analysis-progress-bar')
                        .removeClass('progress-bar-animated')
                        .addClass('bg-danger');
                    $('#analysis-current-phase').html(
                        '<i class="fas fa-exclamation-triangle text-danger"></i> ' +
                        'Analysis failed: ' + status.error_message
                    );
                    $('#analysis-close-btn').prop('disabled', false);
                }
            });
    }, 2000);  // Poll every 2 seconds
}

function updateModeBadges(mode, aiEnabled, openctiEnabled) {
    const modeDescriptions = {
        'A': 'Rule-based',
        'B': 'AI-enhanced',
        'C': 'Intel-enriched',
        'D': 'Full Stack'
    };
    
    $('#analysis-mode-badge').text(`Mode ${mode}: ${modeDescriptions[mode]}`);
    
    $('#ai-status-badge')
        .removeClass('badge-success badge-secondary')
        .addClass(aiEnabled ? 'badge-success' : 'badge-secondary')
        .text(aiEnabled ? 'AI: Connected' : 'AI: Disabled');
    
    $('#opencti-status-badge')
        .removeClass('badge-success badge-secondary')
        .addClass(openctiEnabled ? 'badge-success' : 'badge-secondary')
        .text(openctiEnabled ? 'OpenCTI: Connected' : 'OpenCTI: Disabled');
}
```

---

#### Component: Analysis Results View

**Option:** Create new template `templates/case/analysis_results.html`

**Layout:**
```html
{% extends "layouts/base.html" %}

{% block content %}
<div class="container-fluid">
    <!-- Header -->
    <div class="d-flex justify-content-between align-items-center mb-4">
        <h4>
            <i class="fas fa-microscope"></i> 
            Analysis Results - {{ analysis.created_at.strftime('%Y-%m-%d %H:%M') }}
        </h4>
        <div>
            <span class="badge badge-{{ mode_badge_class }}">Mode {{ analysis.mode }}</span>
            {% if analysis.ai_enabled %}
            <span class="badge badge-success">AI Enabled</span>
            {% endif %}
            {% if analysis.opencti_enabled %}
            <span class="badge badge-success">OpenCTI Enabled</span>
            {% endif %}
        </div>
    </div>
    
    <!-- Summary Cards -->
    <div class="row mb-4">
        <div class="col-md-3">
            <div class="card text-white bg-primary">
                <div class="card-body">
                    <h5 class="card-title">Total Findings</h5>
                    <h2>{{ summary.total_findings }}</h2>
                </div>
            </div>
        </div>
        <div class="col-md-3">
            <div class="card text-white bg-danger">
                <div class="card-body">
                    <h5 class="card-title">High Confidence</h5>
                    <h2>{{ summary.high_confidence_findings }}</h2>
                </div>
            </div>
        </div>
        <div class="col-md-3">
            <div class="card text-white bg-warning">
                <div class="card-body">
                    <h5 class="card-title">Pending Actions</h5>
                    <h2>{{ summary.suggested_actions_pending }}</h2>
                </div>
            </div>
        </div>
        <div class="col-md-3">
            <div class="card text-white bg-info">
                <div class="card-body">
                    <h5 class="card-title">Duration</h5>
                    <h2>{{ summary.duration_formatted }}</h2>
                </div>
            </div>
        </div>
    </div>
    
    <!-- View Toggle -->
    <ul class="nav nav-tabs mb-3" id="results-view-tabs">
        <li class="nav-item">
            <a class="nav-link active" data-view="timeline" href="#">
                <i class="fas fa-stream"></i> Timeline
            </a>
        </li>
        <li class="nav-item">
            <a class="nav-link" data-view="pattern" href="#">
                <i class="fas fa-puzzle-piece"></i> By Pattern
            </a>
        </li>
        <li class="nav-item">
            <a class="nav-link" data-view="entity" href="#">
                <i class="fas fa-user"></i> By Entity
            </a>
        </li>
    </ul>
    
    <!-- Filter -->
    <div class="mb-3">
        <select class="form-control" id="severity-filter" style="width: 200px; display: inline-block;">
            <option value="all">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
        </select>
        <select class="form-control" id="confidence-filter" style="width: 200px; display: inline-block;">
            <option value="all">All Confidence</option>
            <option value="high">High (75+)</option>
            <option value="medium">Medium (50-74)</option>
            <option value="low">Low (<50)</option>
        </select>
    </div>
    
    <!-- Results Container -->
    <div id="results-container">
        <!-- Populated by JavaScript based on selected view -->
    </div>
    
    <!-- Suggested Actions Panel -->
    {% if suggested_actions %}
    <div class="card mt-4">
        <div class="card-header bg-warning text-dark">
            <i class="fas fa-tasks"></i> Suggested Actions ({{ suggested_actions|length }})
        </div>
        <div class="card-body">
            {% for action in suggested_actions %}
            <div class="suggested-action mb-3 p-3 border rounded">
                <div class="d-flex justify-content-between">
                    <div>
                        <strong>{{ action.action_type_display }}</strong>: {{ action.target_value }}
                        <br>
                        <small class="text-muted">{{ action.reason }}</small>
                    </div>
                    <div>
                        <button class="btn btn-success btn-sm accept-action" data-action-id="{{ action.id }}">
                            <i class="fas fa-check"></i> Accept
                        </button>
                        <button class="btn btn-secondary btn-sm reject-action" data-action-id="{{ action.id }}">
                            <i class="fas fa-times"></i> Reject
                        </button>
                    </div>
                </div>
            </div>
            {% endfor %}
        </div>
    </div>
    {% endif %}
</div>
{% endblock %}
```

---

#### Component: Finding Detail Modal

**Template for finding detail popup:**

```html
<div class="modal fade" id="finding-detail-modal" tabindex="-1">
    <div class="modal-dialog modal-xl">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title" id="finding-title">Finding Detail</h5>
                <button type="button" class="close" data-dismiss="modal">
                    <span>&times;</span>
                </button>
            </div>
            <div class="modal-body" id="finding-detail-content">
                <!-- Populated dynamically -->
            </div>
            <div class="modal-footer">
                <div class="mr-auto">
                    <select class="form-control" id="analyst-verdict" style="width: 200px; display: inline-block;">
                        <option value="">-- Set Verdict --</option>
                        <option value="confirmed">Confirmed</option>
                        <option value="false_positive">False Positive</option>
                        <option value="needs_investigation">Needs Investigation</option>
                    </select>
                    <button class="btn btn-primary" id="save-verdict-btn">Save Review</button>
                </div>
                <a href="#" class="btn btn-info" id="view-events-btn" target="_blank">
                    <i class="fas fa-list"></i> View Events
                </a>
                <button type="button" class="btn btn-secondary" data-dismiss="modal">Close</button>
            </div>
        </div>
    </div>
</div>
```

---

## Phase 9: Configuration

### Task 9.1: Configuration Options

**File:** Modify `/opt/casescope/config.py`

**Add Configuration:**

```python
# =============================================================================
# CASE ANALYSIS SETTINGS
# =============================================================================

class Config:
    # ... existing config ...
    
    # --- Behavioral Profiling ---
    ANALYSIS_MIN_EVENTS_FOR_PROFILE = int(os.environ.get('ANALYSIS_MIN_EVENTS_FOR_PROFILE', 10))
    ANALYSIS_PEER_GROUP_MIN_SIZE = int(os.environ.get('ANALYSIS_PEER_GROUP_MIN_SIZE', 3))
    ANALYSIS_ANOMALY_Z_THRESHOLD = float(os.environ.get('ANALYSIS_ANOMALY_Z_THRESHOLD', 3.0))
    
    # --- Gap Detection: Password Spraying ---
    SPRAY_MIN_UNIQUE_USERS = int(os.environ.get('SPRAY_MIN_UNIQUE_USERS', 10))
    SPRAY_MIN_FAILURE_RATE = float(os.environ.get('SPRAY_MIN_FAILURE_RATE', 0.9))
    SPRAY_TIME_WINDOW_HOURS = int(os.environ.get('SPRAY_TIME_WINDOW_HOURS', 2))
    SPRAY_TIMING_STD_THRESHOLD = float(os.environ.get('SPRAY_TIMING_STD_THRESHOLD', 5.0))
    
    # --- Gap Detection: Brute Force ---
    BRUTE_MIN_ATTEMPTS = int(os.environ.get('BRUTE_MIN_ATTEMPTS', 20))
    BRUTE_MIN_FAILURE_RATE = float(os.environ.get('BRUTE_MIN_FAILURE_RATE', 0.95))
    BRUTE_TIME_WINDOW_HOURS = int(os.environ.get('BRUTE_TIME_WINDOW_HOURS', 1))
    BRUTE_DISTRIBUTED_THRESHOLD = int(os.environ.get('BRUTE_DISTRIBUTED_THRESHOLD', 3))
    
    # --- Pattern Analysis ---
    ANALYSIS_MAX_EVENTS_PER_PATTERN = int(os.environ.get('ANALYSIS_MAX_EVENTS_PER_PATTERN', 5000))
    ANALYSIS_HIGH_CONFIDENCE_THRESHOLD = int(os.environ.get('ANALYSIS_HIGH_CONFIDENCE_THRESHOLD', 75))
    ANALYSIS_HAYABUSA_CORRELATION_WINDOW = int(os.environ.get('ANALYSIS_HAYABUSA_CORRELATION_WINDOW', 60))
    
    # --- AI Settings (ensure these exist) ---
    AI_ANALYSIS_ENABLED = os.environ.get('AI_ANALYSIS_ENABLED', 'true').lower() == 'true'
    AI_MODEL_PRIMARY = os.environ.get('AI_MODEL_PRIMARY', 'deepseek-r1:14b')
    AI_MODEL_FALLBACK = os.environ.get('AI_MODEL_FALLBACK', 'qwen2.5:14b-instruct')
    AI_TEMPERATURE = float(os.environ.get('AI_TEMPERATURE', 0.6))
    AI_MAX_TOKENS = int(os.environ.get('AI_MAX_TOKENS', 4000))
    
    # --- OpenCTI Settings (ensure these exist) ---
    OPENCTI_ENABLED = os.environ.get('OPENCTI_ENABLED', 'true').lower() == 'true'
    OPENCTI_URL = os.environ.get('OPENCTI_URL', '')
    OPENCTI_API_KEY = os.environ.get('OPENCTI_API_KEY', '')
    OPENCTI_CACHE_TTL_HOURS = int(os.environ.get('OPENCTI_CACHE_TTL_HOURS', 24))
```

---

### Task 9.2: Database Settings Integration

**Purpose:** Allow runtime toggling via system_settings table.

**Settings Keys to Support:**

| Key | Type | Default | Purpose |
|-----|------|---------|---------|
| `analysis.enabled` | bool | true | Master toggle for analysis |
| `analysis.ai_enabled` | bool | true | Use AI when available |
| `analysis.opencti_enabled` | bool | true | Use OpenCTI when available |
| `analysis.auto_suggest_compromised` | bool | true | Generate compromised suggestions |
| `analysis.spray_detection_enabled` | bool | true | Run spray detection |
| `analysis.brute_force_detection_enabled` | bool | true | Run brute force detection |
| `analysis.behavioral_anomaly_enabled` | bool | true | Run behavioral anomaly detection |

**Implementation in FeatureAvailability class:**
```python
@classmethod
def _get_setting(cls, key: str, default: bool) -> bool:
    """Get setting from database or fall back to config."""
    from models.system_settings import SystemSettings
    return SystemSettings.get(key, default)
```

---

## Phase 10: Testing Requirements

### Task 10.1: Unit Tests

**Directory:** `/opt/casescope/tests/test_analysis/`

**Test Modules:**

#### `test_behavioral_profiler.py`
```python
class TestBehavioralProfiler:
    def test_user_profile_calculation(self):
        """Test that user profiles are calculated correctly from events."""
        pass
    
    def test_system_profile_calculation(self):
        """Test that system profiles are calculated correctly."""
        pass
    
    def test_anomaly_threshold_calculation(self):
        """Test that anomaly thresholds are set appropriately."""
        pass
    
    def test_empty_event_handling(self):
        """Test handling of users/systems with no events."""
        pass
    
    def test_system_role_inference(self):
        """Test that system roles are correctly inferred."""
        pass
```

#### `test_peer_clustering.py`
```python
class TestPeerClustering:
    def test_cluster_formation(self):
        """Test that users are clustered into meaningful groups."""
        pass
    
    def test_z_score_calculation(self):
        """Test z-score calculation against peer medians."""
        pass
    
    def test_small_dataset_handling(self):
        """Test handling of cases with few users."""
        pass
    
    def test_single_user_case(self):
        """Test handling when only one user exists."""
        pass
    
    def test_outlier_detection(self):
        """Test that extreme outliers are identified."""
        pass
```

#### `test_gap_detectors.py`
```python
class TestPasswordSprayingDetector:
    def test_high_confidence_spray(self):
        """Test detection of clear spray attack."""
        pass
    
    def test_low_confidence_spray(self):
        """Test that borderline cases get lower confidence."""
        pass
    
    def test_timing_analysis(self):
        """Test scripted timing detection."""
        pass
    
    def test_baseline_comparison(self):
        """Test comparison against source baseline."""
        pass

class TestBruteForceDetector:
    def test_single_source_brute_force(self):
        """Test detection of single-source brute force."""
        pass
    
    def test_distributed_brute_force(self):
        """Test detection of distributed attack."""
        pass
    
    def test_false_positive_handling(self):
        """Test that legitimate failures don't trigger."""
        pass

class TestBehavioralAnomalyDetector:
    def test_volume_spike_detection(self):
        """Test detection of volume anomalies."""
        pass
    
    def test_peer_comparison_anomaly(self):
        """Test anomaly detection via peer comparison."""
        pass
    
    def test_composite_score_calculation(self):
        """Test weighted anomaly scoring."""
        pass
```

#### `test_hayabusa_correlator.py`
```python
class TestHayabusaCorrelator:
    def test_event_clustering(self):
        """Test that related events are grouped correctly."""
        pass
    
    def test_attack_chain_identification(self):
        """Test MITRE tactic progression detection."""
        pass
    
    def test_correlation_key_generation(self):
        """Test appropriate correlation keys are chosen."""
        pass
    
    def test_behavioral_enrichment(self):
        """Test that behavioral context is attached."""
        pass
```

#### `test_case_analyzer.py`
```python
class TestCaseAnalyzer:
    def test_mode_a_analysis(self):
        """Test analysis without AI or OpenCTI."""
        pass
    
    def test_mode_b_analysis(self):
        """Test analysis with AI only."""
        pass
    
    def test_mode_c_analysis(self):
        """Test analysis with OpenCTI only."""
        pass
    
    def test_mode_d_analysis(self):
        """Test full analysis with both."""
        pass
    
    def test_graceful_degradation(self):
        """Test fallback when services become unavailable."""
        pass
    
    def test_progress_reporting(self):
        """Test that progress is reported correctly."""
        pass
    
    def test_suggested_actions_generation(self):
        """Test that appropriate actions are suggested."""
        pass
```

---

### Task 10.2: Integration Tests

**File:** `/opt/casescope/tests/test_analysis/test_integration.py`

```python
class TestFullAnalysisPipeline:
    def test_analysis_with_sample_evtx(self):
        """
        End-to-end test with real EVTX data.
        
        1. Create test case
        2. Import sample EVTX (with known attack patterns)
        3. Run full analysis
        4. Verify expected findings are generated
        """
        pass
    
    def test_analysis_no_findings(self):
        """Test analysis on clean logs produces no high-confidence findings."""
        pass
    
    def test_analysis_multiple_patterns(self):
        """Test detection of multiple attack patterns in same case."""
        pass
    
    def test_celery_task_integration(self):
        """Test that Celery task runs and reports progress correctly."""
        pass
    
    def test_api_endpoints(self):
        """Test all API endpoints return expected responses."""
        pass
```

---

## Implementation Order

**Recommended development sequence:**

### Sprint 1: Foundation (Phases 1-2) - ~2 weeks
1. Database schema extensions (Task 1.1-1.4)
   - Create all new tables
   - Run migrations
2. Behavioral profiling engine (Task 2.1-2.2)
   - User profiling
   - System profiling
   - Peer clustering
3. Unit tests for profiling

### Sprint 2: Gap Detection (Phase 3) - ~1.5 weeks
1. Password spraying detector (Task 3.1)
2. Brute force detector (Task 3.2)
3. Behavioral anomaly detector (Task 3.3)
4. Gap detector manager (Task 3.4)
5. Unit tests for gap detection

### Sprint 3: Correlation & Integration (Phases 4-5) - ~2 weeks
1. Hayabusa correlator (Task 4.1)
2. Enhance existing pattern matcher (Task 4.2-4.3)
3. OpenCTI context provider (Task 5.1)
4. Feature availability handler (Task 5.2)
5. Unit tests

### Sprint 4: Orchestration (Phase 6) - ~1 week
1. Case analyzer orchestrator (Task 6.1)
2. Celery task integration (Task 6.2)
3. End-to-end testing

### Sprint 5: Output & UI (Phases 7-8) - ~2 weeks
1. Results formatter (Task 7.1-7.2)
2. API endpoints (Task 8.1)
3. UI components (Task 8.2)
   - Analysis button
   - Progress modal
   - Results view
   - Finding detail modal

### Sprint 6: Polish (Phases 9-10) - ~1 week
1. Configuration options (Task 9.1-9.2)
2. Full test suite completion (Task 10.1-10.2)
3. Documentation
4. Bug fixes and optimization

---

## File Summary

### New Files to Create

| File | Purpose |
|------|---------|
| `models/behavioral_profiles.py` | Database models for profiles, peer groups, gap findings, suggested actions |
| `utils/behavioral_profiler.py` | User and system profile calculation |
| `utils/peer_clustering.py` | Peer group building and z-score calculation |
| `utils/gap_detectors/__init__.py` | Gap detector manager |
| `utils/gap_detectors/password_spraying.py` | Password spray detection |
| `utils/gap_detectors/brute_force.py` | Brute force detection |
| `utils/gap_detectors/behavioral_anomaly.py` | Behavioral anomaly detection |
| `utils/hayabusa_correlator.py` | Correlate Hayabusa detections |
| `utils/opencti_context.py` | OpenCTI data provider with caching |
| `utils/feature_availability.py` | Feature availability checker |
| `utils/case_analyzer.py` | Main analysis orchestrator |
| `utils/analysis_results_formatter.py` | Results formatting for display/export |
| `routes/analysis.py` (or add to existing) | API endpoints |
| `templates/case/analysis_results.html` | Results view template |
| `tests/test_analysis/*.py` | Test modules |

### Files to Modify

| File | Changes |
|------|---------|
| `utils/candidate_extractor.py` | Add behavioral context attachment methods |
| `utils/ai_correlation_analyzer.py` | Update prompts for behavioral context; add `analyze_without_ai()` method |
| `tasks/rag_tasks.py` | Add `run_case_analysis` Celery task |
| `config.py` | Add analysis configuration options |
| `models/__init__.py` | Import new models |
| Case dashboard template | Add "Run Case Analysis" button |
| Static JS files | Add analysis progress and results handling |

---

## Dependencies

### Python Packages (ensure installed)

```
scikit-learn>=1.0.0  # For clustering
numpy>=1.20.0        # For statistical calculations
```

### Existing Dependencies (confirm available)

- SQLAlchemy (database ORM)
- Celery (background tasks)
- Flask (web framework)
- clickhouse-driver (ClickHouse queries)
- pycti (OpenCTI client) - already present

---

## Questions for Developer

If anything is unclear during implementation:

1. **ClickHouse Query Performance:** 
   - If profiling queries are slow on 30M+ events, consider materialized views
   - May need to batch user/system profiling

2. **Progress Updates Mechanism:**
   - Confirm existing real-time update mechanism (Socket.IO? Polling?)
   - Adapt progress modal accordingly

3. **UI Framework:**
   - Document assumes Bootstrap - adapt components to actual framework
   - May need to adjust CSS classes and JavaScript

4. **Test Data:**
   - Need sample EVTX files with known attack patterns for integration tests
   - Can use existing test fixtures if available

---

## Glossary

| Term | Definition |
|------|------------|
| **Gap Detection** | Finding attacks that Hayabusa/Sigma rules miss (volume-based, behavioral) |
| **Peer Group** | Cluster of similar users/systems for comparison |
| **Z-Score** | Number of standard deviations from peer group median |
| **Correlation Key** | Field(s) used to group related events (e.g., username+host) |
| **Mode A/B/C/D** | Operating modes based on AI and OpenCTI availability |
| **Suggested Action** | System-generated recommendation for analyst to accept/reject |

---

*Document Version: 1.0*
*Last Updated: January 2025*
