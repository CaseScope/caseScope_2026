"""Pattern Check Definitions for Deterministic Evidence Engine

Defines structured verification checks for each attack pattern.
Each check specifies a ClickHouse query, weight, pass condition,
and optional graduated scoring tiers.

Dataclasses:
- CheckDefinition: What to verify and how to score it
- CheckResult: Outcome of a single check
- CoverageAssessment: Log coverage for a host/time window
- BurstResult: Temporal clustering detection result
- SequenceResult: Ordered event chain verification result
- EvidencePackage: Full evidence assembly for one correlation key
"""

from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Tuple, Any
from datetime import datetime


@dataclass
class CheckDefinition:
    """Defines a single verification check for a pattern."""
    id: str
    name: str
    weight: int
    check_type: str
    query_template: str = ''
    pass_condition: str = ''
    tiers: Optional[List[Tuple[int, float]]] = None
    required_sources: Optional[Dict[str, str]] = None
    deduplicate: bool = True


@dataclass
class CheckResult:
    """Outcome of evaluating a single CheckDefinition."""
    check_id: str
    status: str
    weight: int
    contribution: float
    detail: str
    source: str
    name: str = ''


@dataclass
class CoverageAssessment:
    """Log coverage assessment for a host within a time window."""
    host: str
    window_start: Optional[str] = None
    window_end: Optional[str] = None
    coverage_status: str = 'unknown'
    event_count: int = 0
    earliest_event: Optional[str] = None
    latest_event: Optional[str] = None
    present_sources: List[str] = field(default_factory=list)
    missing_sources: List[str] = field(default_factory=list)
    coverage_score: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class BurstResult:
    """Temporal clustering detection result."""
    username: str
    source_host: str
    src_ip: str
    events_in_bucket: int
    distinct_event_types: int
    span_seconds: int
    bucket_start: str
    bucket_end: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class SequenceResult:
    """Ordered event chain verification result."""
    chain: str
    status: str
    steps: List[Dict[str, Any]] = field(default_factory=list)
    missing_steps: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class EvidencePackage:
    """Full evidence assembly for one anchor/correlation key."""
    anchor: Dict[str, Any]
    pattern_id: str
    pattern_name: str
    correlation_key: str
    checks: List[CheckResult] = field(default_factory=list)
    coverage: Optional[CoverageAssessment] = None
    bursts: List[BurstResult] = field(default_factory=list)
    sequences: List[SequenceResult] = field(default_factory=list)
    gap_inputs: List[Dict[str, Any]] = field(default_factory=list)
    deterministic_score: float = 0.0
    max_possible_score: float = 100.0
    ai_judgment: Optional[Dict[str, Any]] = None
    ai_escalated: bool = False

    def final_score(self) -> float:
        adjustment = 0.0
        if self.ai_judgment:
            raw = self.ai_judgment.get('adjustment', 0)
            adjustment = max(-20, min(10, raw))
        return max(0, min(100, self.deterministic_score + adjustment))

    def to_dict(self) -> Dict[str, Any]:
        inconclusive_checks = [c for c in self.checks if c.status == 'INCONCLUSIVE']
        inconclusive_weight = sum(c.weight for c in inconclusive_checks)
        return {
            'anchor': self.anchor,
            'pattern_id': self.pattern_id,
            'pattern_name': self.pattern_name,
            'correlation_key': self.correlation_key,
            'checks': [asdict(c) for c in self.checks],
            'coverage': self.coverage.to_dict() if self.coverage else None,
            'bursts': [b.to_dict() for b in self.bursts],
            'sequences': [s.to_dict() for s in self.sequences],
            'gap_detector_inputs': self.gap_inputs,
            'scoring_context': {
                'deterministic_score': self.deterministic_score,
                'max_possible_score': self.max_possible_score,
                'inconclusive_count': len(inconclusive_checks),
                'inconclusive_weight_lost': round(inconclusive_weight * 0.7, 1),
            },
            'ai_judgment': self.ai_judgment,
            'ai_escalated': self.ai_escalated,
        }


BURST_THRESHOLDS = {
    'pass_the_ticket': {'window_seconds': 30, 'min_events': 5, 'event_ids': ['4624']},
    'password_spraying': {'window_seconds': 300, 'min_events': 10, 'event_ids': ['4625']},
    'brute_force': {'window_seconds': 120, 'min_events': 5, 'event_ids': ['4625']},
    'kerberoasting': {'window_seconds': 300, 'min_events': 3, 'event_ids': ['4769']},
    'network_scanning': {'window_seconds': 60, 'min_events': 20, 'event_ids': ['3']},
}

SEQUENCE_DEFINITIONS = {
    'psexec_execution': {
        'chain': 'logon -> share_access -> service_install',
        'steps': [
            {'event_id': '4624', 'label': 'logon', 'conditions': {'logon_type': [3]},
             'max_offset_seconds': 300, 'direction': 'before_anchor'},
            {'event_id': ['5140', '5145'], 'label': 'share_access',
             'max_offset_seconds': 300, 'direction': 'before_anchor'},
        ],
    },
    'dcsync': {
        'chain': 'logon -> replication_request',
        'steps': [
            {'event_id': '4624', 'label': 'logon', 'conditions': {},
             'max_offset_seconds': 300, 'direction': 'before_anchor'},
        ],
    },
}


PATTERN_CHECKS: Dict[str, List[CheckDefinition]] = {

    'pass_the_hash': [
        CheckDefinition(
            id='pth_ntlm_keylength', name='NTLM auth with KeyLength=0',
            weight=30, check_type='anchor_match',
        ),
        CheckDefinition(
            id='pth_no_kerberos_tgt', name='No preceding Kerberos TGT',
            weight=20, check_type='absence_with_coverage',
            query_template=(
                "SELECT count() FROM events "
                "WHERE case_id = {case_id:UInt32} AND event_id = '4768' "
                "AND username = {username:String} "
                "AND timestamp BETWEEN {anchor_ts:DateTime64} - INTERVAL 60 MINUTE AND {anchor_ts:DateTime64} "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            pass_condition='result == 0',
            required_sources={'Security': 'critical'},
        ),
        CheckDefinition(
            id='pth_multi_target', name='Multiple targets from same source',
            weight=15, check_type='graduated',
            query_template=(
                "SELECT uniqExact(target_host) FROM events "
                "WHERE case_id = {case_id:UInt32} AND event_id = '4624' "
                "AND src_ip = {src_ip:String} "
                "AND timestamp BETWEEN {window_start:DateTime64} AND {window_end:DateTime64} "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            tiers=[(2, 0.3), (5, 0.6), (10, 1.0)],
        ),
        CheckDefinition(
            id='pth_privilege_escalation', name='Privilege escalation (4672)',
            weight=15, check_type='threshold',
            query_template=(
                "SELECT count() FROM events "
                "WHERE case_id = {case_id:UInt32} AND event_id = '4672' "
                "AND username = {username:String} "
                "AND timestamp BETWEEN {anchor_ts:DateTime64} - INTERVAL 5 SECOND "
                "AND {anchor_ts:DateTime64} + INTERVAL 5 SECOND "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            pass_condition='result >= 1',
        ),
        CheckDefinition(
            id='pth_process_context', name='Suspicious process context',
            weight=10, check_type='threshold',
            query_template=(
                "SELECT count() FROM events "
                "WHERE case_id = {case_id:UInt32} AND event_id IN ('1', '4688') "
                "AND source_host = {source_host:String} AND username = {username:String} "
                "AND timestamp BETWEEN {anchor_ts:DateTime64} AND {anchor_ts:DateTime64} + INTERVAL 10 MINUTE "
                "AND lower(process_name) IN ('psexec.exe','wmic.exe','powershell.exe','cmd.exe',"
                "'paexec.exe','csexec.exe','wmiprvse.exe') "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            pass_condition='result >= 1',
        ),
        CheckDefinition(
            id='pth_off_hours', name='Off-hours activity',
            weight=10, check_type='field_match',
        ),
    ],

    'pass_the_ticket': [
        CheckDefinition(
            id='ptt_kerberos_logon', name='Kerberos logon anchor',
            weight=20, check_type='anchor_match',
        ),
        CheckDefinition(
            id='ptt_no_tgt', name='No preceding TGT (4768)',
            weight=25, check_type='absence_with_coverage',
            query_template=(
                "SELECT count() FROM events "
                "WHERE case_id = {case_id:UInt32} AND event_id = '4768' "
                "AND username = {username:String} "
                "AND timestamp BETWEEN {anchor_ts:DateTime64} - INTERVAL 60 MINUTE AND {anchor_ts:DateTime64} "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            pass_condition='result == 0',
            required_sources={'Security': 'critical'},
        ),
        CheckDefinition(
            id='ptt_no_tgs', name='No preceding TGS (4769)',
            weight=25, check_type='absence_with_coverage',
            query_template=(
                "SELECT count() FROM events "
                "WHERE case_id = {case_id:UInt32} AND event_id = '4769' "
                "AND username = {username:String} "
                "AND timestamp BETWEEN {anchor_ts:DateTime64} - INTERVAL 60 MINUTE AND {anchor_ts:DateTime64} "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            pass_condition='result == 0',
            required_sources={'Security': 'critical'},
        ),
        CheckDefinition(
            id='ptt_burst', name='Burst of Kerberos logons',
            weight=15, check_type='burst',
        ),
        CheckDefinition(
            id='ptt_sensitive_service', name='Sensitive service target',
            weight=15, check_type='field_match',
        ),
    ],

    'dcsync': [
        CheckDefinition(
            id='dcs_replication_rights', name='Replication rights anchor',
            weight=30, check_type='anchor_match',
        ),
        CheckDefinition(
            id='dcs_not_dc_account', name='Account is NOT a DC computer account',
            weight=25, check_type='field_match',
        ),
        CheckDefinition(
            id='dcs_not_dc_host', name='Source host is NOT a domain controller',
            weight=20, check_type='field_match',
        ),
        CheckDefinition(
            id='dcs_multi_replication', name='Multiple replication requests in 5min',
            weight=15, check_type='graduated',
            query_template=(
                "SELECT count() FROM events "
                "WHERE case_id = {case_id:UInt32} AND event_id = '4662' "
                "AND username = {username:String} "
                "AND timestamp BETWEEN {anchor_ts:DateTime64} - INTERVAL 5 MINUTE "
                "AND {anchor_ts:DateTime64} + INTERVAL 5 MINUTE "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            tiers=[(2, 0.4), (5, 0.7), (10, 1.0)],
        ),
        CheckDefinition(
            id='dcs_off_hours', name='Off-hours activity',
            weight=10, check_type='field_match',
        ),
    ],

    'kerberoasting': [
        CheckDefinition(
            id='kerb_rc4_anchor', name='RC4 encryption TGS request',
            weight=20, check_type='anchor_match',
        ),
        CheckDefinition(
            id='kerb_multi_spn', name='Multiple distinct SPNs requested',
            weight=25, check_type='graduated',
            query_template=(
                "SELECT uniqExact(payload_data1) FROM events "
                "WHERE case_id = {case_id:UInt32} AND event_id = '4769' "
                "AND username = {username:String} "
                "AND timestamp BETWEEN {window_start:DateTime64} AND {window_end:DateTime64} "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            tiers=[(3, 0.4), (5, 0.7), (10, 1.0)],
        ),
        CheckDefinition(
            id='kerb_not_service_account', name='Requesting account is not a service account',
            weight=20, check_type='field_match',
        ),
        CheckDefinition(
            id='kerb_from_workstation', name='Request originates from workstation',
            weight=20, check_type='field_match',
        ),
        CheckDefinition(
            id='kerb_burst', name='Burst of TGS requests',
            weight=15, check_type='burst',
        ),
    ],

    'password_spraying': [
        CheckDefinition(
            id='spray_distinct_users', name='10+ distinct usernames failed from same source',
            weight=25, check_type='graduated',
            query_template=(
                "SELECT uniqExact(username) FROM events "
                "WHERE case_id = {case_id:UInt32} AND event_id = '4625' "
                "AND src_ip = {src_ip:String} "
                "AND timestamp BETWEEN {window_start:DateTime64} AND {window_end:DateTime64} "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            tiers=[(5, 0.3), (10, 0.6), (25, 0.8), (50, 1.0)],
        ),
        CheckDefinition(
            id='spray_low_per_account', name='Low attempts per account (1-3 each)',
            weight=20, check_type='threshold',
            query_template=(
                "SELECT max(cnt) FROM ("
                "  SELECT username, count() as cnt FROM events "
                "  WHERE case_id = {case_id:UInt32} AND event_id = '4625' "
                "  AND src_ip = {src_ip:String} "
                "  AND timestamp BETWEEN {window_start:DateTime64} AND {window_end:DateTime64} "
                "  AND (noise_matched = false OR noise_matched IS NULL) "
                "  GROUP BY username"
                ")"
            ),
            pass_condition='result <= 3',
        ),
        CheckDefinition(
            id='spray_bad_password', name='SubStatus 0xC000006A (bad password)',
            weight=15, check_type='threshold',
            query_template=(
                "SELECT count() FROM events "
                "WHERE case_id = {case_id:UInt32} AND event_id = '4625' "
                "AND src_ip = {src_ip:String} "
                "AND lower(payload_data1) LIKE '%%c000006a%%' "
                "AND timestamp BETWEEN {window_start:DateTime64} AND {window_end:DateTime64} "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            pass_condition='result >= 1',
        ),
        CheckDefinition(
            id='spray_followed_by_success', name='Followed by successful logon from same source',
            weight=15, check_type='threshold',
            query_template=(
                "SELECT count() FROM events "
                "WHERE case_id = {case_id:UInt32} AND event_id = '4624' "
                "AND src_ip = {src_ip:String} "
                "AND timestamp BETWEEN {window_start:DateTime64} AND {window_end:DateTime64} + INTERVAL 30 MINUTE "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            pass_condition='result >= 1',
        ),
        CheckDefinition(
            id='spray_spread_pattern', name='Spread pattern (not all at once)',
            weight=15, check_type='threshold',
            query_template=(
                "SELECT dateDiff('second', min(timestamp), max(timestamp)) FROM events "
                "WHERE case_id = {case_id:UInt32} AND event_id = '4625' "
                "AND src_ip = {src_ip:String} "
                "AND timestamp BETWEEN {window_start:DateTime64} AND {window_end:DateTime64} "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            pass_condition='result >= 60',
        ),
        CheckDefinition(
            id='spray_off_hours', name='Off-hours activity',
            weight=10, check_type='field_match',
        ),
    ],

    'brute_force': [
        CheckDefinition(
            id='brute_high_failures', name='Multiple failed logons for same account',
            weight=25, check_type='graduated',
            query_template=(
                "SELECT count() FROM events "
                "WHERE case_id = {case_id:UInt32} AND event_id = '4625' "
                "AND username = {username:String} AND src_ip = {src_ip:String} "
                "AND timestamp BETWEEN {window_start:DateTime64} AND {window_end:DateTime64} "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            tiers=[(5, 0.3), (10, 0.6), (25, 0.8), (50, 1.0)],
        ),
        CheckDefinition(
            id='brute_bad_password', name='SubStatus 0xC000006A (bad password)',
            weight=20, check_type='threshold',
            query_template=(
                "SELECT count() FROM events "
                "WHERE case_id = {case_id:UInt32} AND event_id = '4625' "
                "AND username = {username:String} AND src_ip = {src_ip:String} "
                "AND lower(payload_data1) LIKE '%%c000006a%%' "
                "AND timestamp BETWEEN {window_start:DateTime64} AND {window_end:DateTime64} "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            pass_condition='result >= 1',
        ),
        CheckDefinition(
            id='brute_followed_by_success', name='Followed by successful logon',
            weight=20, check_type='threshold',
            query_template=(
                "SELECT count() FROM events "
                "WHERE case_id = {case_id:UInt32} AND event_id = '4624' "
                "AND username = {username:String} "
                "AND timestamp BETWEEN {window_start:DateTime64} AND {window_end:DateTime64} + INTERVAL 30 MINUTE "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            pass_condition='result >= 1',
        ),
        CheckDefinition(
            id='brute_account_lockout', name='Account lockout triggered (4740)',
            weight=15, check_type='threshold',
            query_template=(
                "SELECT count() FROM events "
                "WHERE case_id = {case_id:UInt32} AND event_id = '4740' "
                "AND username = {username:String} "
                "AND timestamp BETWEEN {window_start:DateTime64} AND {window_end:DateTime64} + INTERVAL 10 MINUTE "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            pass_condition='result >= 1',
        ),
        CheckDefinition(
            id='brute_off_hours', name='Off-hours activity',
            weight=20, check_type='field_match',
        ),
    ],

    'psexec_execution': [
        CheckDefinition(
            id='psexec_service_install', name='Remote service installation anchor',
            weight=30, check_type='anchor_match',
        ),
        CheckDefinition(
            id='psexec_network_logon', name='Network logon preceding service install',
            weight=25, check_type='threshold',
            query_template=(
                "SELECT count() FROM events "
                "WHERE case_id = {case_id:UInt32} AND event_id = '4624' "
                "AND logon_type IN (3) "
                "AND source_host = {source_host:String} "
                "AND timestamp BETWEEN {anchor_ts:DateTime64} - INTERVAL 5 MINUTE AND {anchor_ts:DateTime64} "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            pass_condition='result >= 1',
        ),
        CheckDefinition(
            id='psexec_share_access', name='ADMIN$ or C$ share access',
            weight=25, check_type='threshold',
            query_template=(
                "SELECT count() FROM events "
                "WHERE case_id = {case_id:UInt32} AND event_id IN ('5140', '5145') "
                "AND source_host = {source_host:String} "
                "AND timestamp BETWEEN {anchor_ts:DateTime64} - INTERVAL 5 MINUTE AND {anchor_ts:DateTime64} "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            pass_condition='result >= 1',
            required_sources={'Security': 'critical'},
        ),
        CheckDefinition(
            id='psexec_suspicious_service', name='Suspicious service name pattern',
            weight=20, check_type='field_match',
        ),
    ],

    'rdp_lateral': [
        CheckDefinition(
            id='rdp_type10_anchor', name='RemoteInteractive logon (type 10)',
            weight=20, check_type='anchor_match',
        ),
        CheckDefinition(
            id='rdp_multi_host', name='RDP to multiple hosts from same user',
            weight=25, check_type='graduated',
            query_template=(
                "SELECT uniqExact(target_host) FROM events "
                "WHERE case_id = {case_id:UInt32} AND event_id = '4624' "
                "AND logon_type IN (10, 7) AND username = {username:String} "
                "AND timestamp BETWEEN {window_start:DateTime64} AND {window_end:DateTime64} "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            tiers=[(2, 0.3), (3, 0.6), (5, 1.0)],
        ),
        CheckDefinition(
            id='rdp_off_hours', name='Off-hours RDP activity',
            weight=20, check_type='field_match',
        ),
        CheckDefinition(
            id='rdp_unusual_source', name='RDP from unusual source',
            weight=15, check_type='field_match',
        ),
        CheckDefinition(
            id='rdp_session_pattern', name='Session reconnect/disconnect patterns',
            weight=20, check_type='threshold',
            query_template=(
                "SELECT count() FROM events "
                "WHERE case_id = {case_id:UInt32} AND event_id IN ('4778', '4779') "
                "AND username = {username:String} "
                "AND timestamp BETWEEN {window_start:DateTime64} AND {window_end:DateTime64} "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            pass_condition='result >= 1',
        ),
    ],

    'log_clearing': [
        CheckDefinition(
            id='logclr_anchor', name='Log cleared event (1102/104)',
            weight=40, check_type='anchor_match',
        ),
        CheckDefinition(
            id='logclr_non_admin', name='Log cleared by non-admin user',
            weight=30, check_type='field_match',
        ),
        CheckDefinition(
            id='logclr_multi_log', name='Multiple logs cleared in sequence',
            weight=30, check_type='graduated',
            query_template=(
                "SELECT count() FROM events "
                "WHERE case_id = {case_id:UInt32} AND event_id IN ('1102', '104') "
                "AND source_host = {source_host:String} "
                "AND timestamp BETWEEN {anchor_ts:DateTime64} - INTERVAL 5 MINUTE "
                "AND {anchor_ts:DateTime64} + INTERVAL 5 MINUTE "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            tiers=[(2, 0.5), (3, 1.0)],
        ),
    ],

    'lsass_memory_dump': [
        CheckDefinition(
            id='lsass_access_anchor', name='Process accessing lsass.exe',
            weight=30, check_type='anchor_match',
        ),
        CheckDefinition(
            id='lsass_vm_read', name='PROCESS_VM_READ access rights',
            weight=25, check_type='field_match',
        ),
        CheckDefinition(
            id='lsass_dump_file', name='DMP file creation after access',
            weight=20, check_type='threshold',
            query_template=(
                "SELECT count() FROM events "
                "WHERE case_id = {case_id:UInt32} AND event_id = '11' "
                "AND source_host = {source_host:String} "
                "AND lower(process_name) LIKE '%.dmp%' "
                "AND timestamp BETWEEN {anchor_ts:DateTime64} AND {anchor_ts:DateTime64} + INTERVAL 5 MINUTE "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            pass_condition='result >= 1',
        ),
        CheckDefinition(
            id='lsass_suspicious_process', name='Suspicious accessing process',
            weight=15, check_type='field_match',
        ),
        CheckDefinition(
            id='lsass_off_hours', name='Off-hours activity',
            weight=10, check_type='field_match',
        ),
    ],

    'wmi_lateral': [
        CheckDefinition(
            id='wmi_anchor', name='WMI process creation anchor',
            weight=25, check_type='anchor_match',
        ),
        CheckDefinition(
            id='wmi_wmiprvse_child', name='WmiPrvSE spawning child processes',
            weight=25, check_type='threshold',
            query_template=(
                "SELECT count() FROM events "
                "WHERE case_id = {case_id:UInt32} AND event_id IN ('1', '4688') "
                "AND source_host = {source_host:String} "
                "AND lower(process_name) = 'wmiprvse.exe' "
                "AND timestamp BETWEEN {anchor_ts:DateTime64} - INTERVAL 5 MINUTE AND {anchor_ts:DateTime64} + INTERVAL 5 MINUTE "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            pass_condition='result >= 1',
        ),
        CheckDefinition(
            id='wmi_network_logon', name='Network logon preceding WMI',
            weight=25, check_type='threshold',
            query_template=(
                "SELECT count() FROM events "
                "WHERE case_id = {case_id:UInt32} AND event_id = '4624' "
                "AND logon_type IN (3) AND source_host = {source_host:String} "
                "AND timestamp BETWEEN {anchor_ts:DateTime64} - INTERVAL 5 MINUTE AND {anchor_ts:DateTime64} "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            pass_condition='result >= 1',
        ),
        CheckDefinition(
            id='wmi_off_hours', name='Off-hours activity',
            weight=15, check_type='field_match',
        ),
        CheckDefinition(
            id='wmi_unusual_source', name='Unusual source host',
            weight=10, check_type='field_match',
        ),
    ],

    'registry_run_keys': [
        CheckDefinition(
            id='regrun_anchor', name='Registry Run key modification',
            weight=30, check_type='anchor_match',
        ),
        CheckDefinition(
            id='regrun_unusual_path', name='Binary in unusual location',
            weight=25, check_type='field_match',
        ),
        CheckDefinition(
            id='regrun_recent_binary', name='Recently created binary referenced',
            weight=20, check_type='threshold',
            query_template=(
                "SELECT count() FROM events "
                "WHERE case_id = {case_id:UInt32} AND event_id = '11' "
                "AND source_host = {source_host:String} "
                "AND timestamp BETWEEN {anchor_ts:DateTime64} - INTERVAL 30 MINUTE AND {anchor_ts:DateTime64} "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            pass_condition='result >= 1',
        ),
        CheckDefinition(
            id='regrun_non_admin', name='Non-admin process modifying Run key',
            weight=15, check_type='field_match',
        ),
        CheckDefinition(
            id='regrun_off_hours', name='Off-hours activity',
            weight=10, check_type='field_match',
        ),
    ],

    'scheduled_task_persistence': [
        CheckDefinition(
            id='schtask_anchor', name='Scheduled task created (4698)',
            weight=30, check_type='anchor_match',
        ),
        CheckDefinition(
            id='schtask_system_priv', name='Task runs as SYSTEM',
            weight=25, check_type='field_match',
        ),
        CheckDefinition(
            id='schtask_script_action', name='Task action runs script/suspicious binary',
            weight=20, check_type='field_match',
        ),
        CheckDefinition(
            id='schtask_non_admin', name='Created by non-admin user',
            weight=15, check_type='field_match',
        ),
        CheckDefinition(
            id='schtask_off_hours', name='Off-hours activity',
            weight=10, check_type='field_match',
        ),
    ],

    'service_persistence': [
        CheckDefinition(
            id='svcpers_anchor', name='Service installed (7045/4697)',
            weight=30, check_type='anchor_match',
        ),
        CheckDefinition(
            id='svcpers_unusual_path', name='Service binary in unusual location',
            weight=25, check_type='field_match',
        ),
        CheckDefinition(
            id='svcpers_localsystem', name='Service runs as LocalSystem',
            weight=20, check_type='field_match',
        ),
        CheckDefinition(
            id='svcpers_auto_start', name='Service auto-start enabled',
            weight=15, check_type='field_match',
        ),
        CheckDefinition(
            id='svcpers_off_hours', name='Off-hours activity',
            weight=10, check_type='field_match',
        ),
    ],

    'process_injection': [
        CheckDefinition(
            id='inject_anchor', name='Process injection indicator (Sysmon 8/10)',
            weight=30, check_type='anchor_match',
        ),
        CheckDefinition(
            id='inject_suspicious_parent', name='Suspicious parent process',
            weight=25, check_type='field_match',
        ),
        CheckDefinition(
            id='inject_unusual_dll', name='DLL loaded from unusual path',
            weight=20, check_type='threshold',
            query_template=(
                "SELECT count() FROM events "
                "WHERE case_id = {case_id:UInt32} AND event_id = '7' "
                "AND source_host = {source_host:String} "
                "AND timestamp BETWEEN {anchor_ts:DateTime64} - INTERVAL 1 MINUTE AND {anchor_ts:DateTime64} + INTERVAL 1 MINUTE "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            pass_condition='result >= 1',
        ),
        CheckDefinition(
            id='inject_target_process', name='Target is sensitive process',
            weight=15, check_type='field_match',
        ),
        CheckDefinition(
            id='inject_off_hours', name='Off-hours activity',
            weight=10, check_type='field_match',
        ),
    ],

    'bloodhound_sharphound': [
        CheckDefinition(
            id='bh_anchor', name='Mass AD enumeration anchor',
            weight=25, check_type='anchor_match',
        ),
        CheckDefinition(
            id='bh_mass_ldap', name='Mass LDAP queries from single host',
            weight=25, check_type='graduated',
            query_template=(
                "SELECT count() FROM events "
                "WHERE case_id = {case_id:UInt32} AND event_id = '4662' "
                "AND source_host = {source_host:String} "
                "AND timestamp BETWEEN {window_start:DateTime64} AND {window_end:DateTime64} "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            tiers=[(50, 0.3), (200, 0.6), (500, 1.0)],
        ),
        CheckDefinition(
            id='bh_session_enum', name='Session enumeration (NetSessionEnum)',
            weight=20, check_type='threshold',
            query_template=(
                "SELECT count() FROM events "
                "WHERE case_id = {case_id:UInt32} AND event_id = '5145' "
                "AND source_host = {source_host:String} "
                "AND timestamp BETWEEN {window_start:DateTime64} AND {window_end:DateTime64} "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            pass_condition='result >= 5',
        ),
        CheckDefinition(
            id='bh_from_workstation', name='Enumeration from workstation',
            weight=15, check_type='field_match',
        ),
        CheckDefinition(
            id='bh_off_hours', name='Off-hours activity',
            weight=15, check_type='field_match',
        ),
    ],

    'network_scanning': [
        CheckDefinition(
            id='netscan_anchor', name='Network connection anchor (Sysmon 3)',
            weight=20, check_type='anchor_match',
        ),
        CheckDefinition(
            id='netscan_multi_dest', name='Connections to many IPs',
            weight=30, check_type='graduated',
            query_template=(
                "SELECT uniqExact(dst_ip) FROM events "
                "WHERE case_id = {case_id:UInt32} AND event_id = '3' "
                "AND source_host = {source_host:String} "
                "AND timestamp BETWEEN {window_start:DateTime64} AND {window_end:DateTime64} "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            tiers=[(10, 0.3), (50, 0.6), (200, 1.0)],
        ),
        CheckDefinition(
            id='netscan_sequential_ports', name='Sequential port connections',
            weight=20, check_type='threshold',
            query_template=(
                "SELECT uniqExact(JSONExtractUInt(raw_json, 'EventData', 'DestinationPort')) FROM events "
                "WHERE case_id = {case_id:UInt32} AND event_id = '3' "
                "AND source_host = {source_host:String} "
                "AND timestamp BETWEEN {window_start:DateTime64} AND {window_end:DateTime64} "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            pass_condition='result >= 10',
        ),
        CheckDefinition(
            id='netscan_burst', name='Burst of connections',
            weight=15, check_type='burst',
        ),
        CheckDefinition(
            id='netscan_off_hours', name='Off-hours activity',
            weight=15, check_type='field_match',
        ),
    ],
}


def get_checks_for_pattern(pattern_id: str) -> List[CheckDefinition]:
    """Get check definitions for a pattern, returning empty list if undefined."""
    return PATTERN_CHECKS.get(pattern_id, [])


def get_burst_config(pattern_id: str) -> Optional[Dict[str, Any]]:
    """Get burst detection config for a pattern."""
    return BURST_THRESHOLDS.get(pattern_id)


def get_sequence_config(pattern_id: str) -> Optional[Dict[str, Any]]:
    """Get sequence validation config for a pattern."""
    return SEQUENCE_DEFINITIONS.get(pattern_id)
