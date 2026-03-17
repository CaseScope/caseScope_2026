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
    sysmon_fp_warning: str = ''

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
class SpreadAssessment:
    """Cross-key spread assessment for campaign-style attacks.
    Measures how many distinct targets/users a single pivot value
    (source IP, username) touched across correlation keys."""
    pivot_field: str
    pivot_value: str
    total_targets: int = 0
    total_users: int = 0
    span_minutes: int = 0
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    sibling_keys: List[str] = field(default_factory=list)
    contribution: float = 0.0

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
    spread: Optional[SpreadAssessment] = None
    deterministic_score: float = 0.0
    max_possible_score: float = 100.0
    ai_judgment: Optional[Dict[str, Any]] = None
    ai_escalated: bool = False
    mitre_techniques: List[str] = field(default_factory=list)

    def _has_explicit_benign_ai_rationale(self) -> bool:
        """Require concrete benign context before downgrading very strong detections."""
        if not self.ai_judgment:
            return False

        text = ' '.join(
            str(self.ai_judgment.get(key, '') or '')
            for key in ('reasoning', 'false_positive_assessment')
        ).lower()
        benign_markers = (
            'machine account',
            'computer account',
            'loopback',
            '127.0.0.1',
            'localhost',
            'domain controller',
            'dc replication',
            'directory replication',
            'administrative workflow',
            'admin workflow',
            'legitimate administrative',
            'known administrative workflow',
            'expected system behavior',
        )
        return any(marker in text for marker in benign_markers)

    def _has_strong_user_account_signal(self) -> bool:
        """Check if a user account (not machine) passed a privileged-operation check."""
        pass_names = [c.name.lower() for c in self.checks if c.status == 'PASS']
        return any(
            'not a dc computer account' in n or 'not dc account' in n or
            'user account' in n
            for n in pass_names
        )

    def _bounded_ai_adjustment(self, raw_adjustment: float) -> float:
        adjustment = max(-20, min(10, raw_adjustment))
        remote_exec_patterns = {
            'psexec_execution', 'wmi_lateral', 'winrm_lateral', 'rdp_lateral'
        }

        if (
            self.deterministic_score >= 85
            and adjustment < 0
            and not self._has_explicit_benign_ai_rationale()
        ):
            adjustment = 0

        if self.deterministic_score >= 80 and adjustment < -2:
            adjustment = -2
        elif self.deterministic_score >= 70 and adjustment < -4:
            adjustment = -4
        elif self.deterministic_score >= 60 and adjustment < -6:
            adjustment = -6
        elif self.deterministic_score >= 50 and adjustment < -8:
            adjustment = -8

        if self.pattern_id in remote_exec_patterns and self.deterministic_score >= 50 and adjustment < -4:
            adjustment = -4

        if self.deterministic_score >= 70 and self._has_strong_user_account_signal() and adjustment < -4:
            adjustment = -4

        return adjustment

    def bounded_ai_adjustment(self) -> float:
        if not self.ai_judgment:
            return 0.0
        raw = self.ai_judgment.get('adjustment', 0)
        return self._bounded_ai_adjustment(raw)

    def final_score(self) -> float:
        adjustment = self.bounded_ai_adjustment()
        score = max(0, min(100, self.deterministic_score + adjustment))
        if self.ai_judgment and self.deterministic_score >= 50 and score < 50:
            score = 50
        return score

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
            'spread': self.spread.to_dict() if self.spread else None,
            'scoring_context': {
                'deterministic_score': self.deterministic_score,
                'max_possible_score': self.max_possible_score,
                'inconclusive_count': len(inconclusive_checks),
                'inconclusive_weight_lost': round(inconclusive_weight * 0.7, 1),
            },
            'ai_judgment': self.ai_judgment,
            'ai_escalated': self.ai_escalated,
            'mitre_techniques': self.mitre_techniques,
        }


BURST_THRESHOLDS = {
    'pass_the_ticket': {'window_seconds': 30, 'min_events': 5, 'event_ids': ['4624']},
    'password_spraying': {'window_seconds': 300, 'min_events': 10, 'event_ids': ['4625', '4771', '4768', '18456']},
    'brute_force': {'window_seconds': 120, 'min_events': 5, 'event_ids': ['4625', '18456']},
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

    'ntds_credential_dump': [
        CheckDefinition(
            id='ntds_esent_anchor', name='ESENT ntds.dit database operation (325/326/327)',
            weight=30, check_type='anchor_match',
        ),
        CheckDefinition(
            id='ntds_suspicious_path', name='NTDS.dit accessed from non-standard path',
            weight=25, check_type='threshold',
            query_template=(
                "SELECT count() FROM events "
                "WHERE case_id = {case_id:UInt32} "
                "AND event_id IN ('325', '326', '327') "
                "AND provider = 'ESENT' "
                "AND lower(search_blob) LIKE '%%ntds.dit%%' "
                "AND lower(search_blob) NOT LIKE '%%\\\\windows\\\\ntds\\\\ntds.dit%%' "
                "AND timestamp BETWEEN {window_start:DateTime64} AND {window_end:DateTime64} "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            pass_condition='result >= 1',
        ),
        CheckDefinition(
            id='ntds_vss_snapshot', name='VSS snapshot path ($SNAP_) in ESENT event',
            weight=15, check_type='threshold',
            query_template=(
                "SELECT count() FROM events "
                "WHERE case_id = {case_id:UInt32} "
                "AND event_id IN ('325', '326', '327') "
                "AND provider = 'ESENT' "
                "AND lower(search_blob) LIKE '%%$snap_%%' "
                "AND lower(search_blob) LIKE '%%ntds.dit%%' "
                "AND timestamp BETWEEN {window_start:DateTime64} AND {window_end:DateTime64} "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            pass_condition='result >= 1',
        ),
        CheckDefinition(
            id='ntds_ifm_creation', name='IFM creation sequence (325 new database + 327 detach)',
            weight=20, check_type='graduated',
            query_template=(
                "SELECT uniqExact(event_id) FROM events "
                "WHERE case_id = {case_id:UInt32} "
                "AND event_id IN ('325', '326', '327') "
                "AND provider = 'ESENT' "
                "AND lower(search_blob) LIKE '%%ntds.dit%%' "
                "AND timestamp BETWEEN {window_start:DateTime64} AND {window_end:DateTime64} "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            tiers=[(2, 0.5), (3, 1.0)],
        ),
        CheckDefinition(
            id='ntds_hayabusa_tag', name='Hayabusa rule tagged Ntdsutil Abuse or Dump Ntds.dit',
            weight=10, check_type='threshold',
            query_template=(
                "SELECT count() FROM events "
                "WHERE case_id = {case_id:UInt32} "
                "AND (lower(rule_title) LIKE '%%ntdsutil%%' "
                "  OR lower(rule_title) LIKE '%%ntds.dit%%') "
                "AND timestamp BETWEEN {window_start:DateTime64} AND {window_end:DateTime64} "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            pass_condition='result >= 1',
        ),
    ],

    'remote_registry_sam_access': [
        CheckDefinition(
            id='rr_winreg_anchor', name='Remote registry access via IPC$/winreg named pipe',
            weight=25, check_type='anchor_match',
        ),
        CheckDefinition(
            id='rr_sam_hive_access', name='SAM/SYSTEM/SECURITY hive access via C$ share',
            weight=25, check_type='threshold',
            query_template=(
                "SELECT count() FROM events "
                "WHERE case_id = {case_id:UInt32} AND event_id = '5145' "
                "AND endsWith(username, {username:String}) "
                "AND lower(search_blob) LIKE '%%c$%%' "
                "AND (lower(search_blob) LIKE '%%sam%%' "
                "  OR lower(search_blob) LIKE '%%system%%' "
                "  OR lower(search_blob) LIKE '%%security%%') "
                "AND timestamp BETWEEN {window_start:DateTime64} AND {window_end:DateTime64} "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            pass_condition='result >= 1',
        ),
        CheckDefinition(
            id='rr_backup_privilege', name='User has SeBackupPrivilege (Backup Operator)',
            weight=20, check_type='threshold',
            query_template=(
                "SELECT count() FROM events "
                "WHERE case_id = {case_id:UInt32} AND event_id = '4672' "
                "AND endsWith(username, {username:String}) "
                "AND lower(search_blob) LIKE '%%sebackupprivilege%%' "
                "AND timestamp BETWEEN {window_start:DateTime64} AND {window_end:DateTime64} "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            pass_condition='result >= 1',
        ),
        CheckDefinition(
            id='rr_not_machine_account', name='Account is not a machine account ($)',
            weight=15, check_type='field_match',
        ),
        CheckDefinition(
            id='rr_multi_hive', name='Multiple hives accessed (SAM + SYSTEM + SECURITY)',
            weight=15, check_type='graduated',
            query_template=(
                "SELECT uniqExact(multiIf("
                "  position(lower(search_blob), 'sam') > 0 AND position(lower(search_blob), 'system') = 0 AND position(lower(search_blob), 'security') = 0, 'SAM', "
                "  position(lower(search_blob), 'system') > 0 AND position(lower(search_blob), 'sam') = 0, 'SYSTEM', "
                "  position(lower(search_blob), 'security') > 0, 'SECURITY', "
                "  '')) FROM events "
                "WHERE case_id = {case_id:UInt32} AND event_id = '5145' "
                "AND endsWith(username, {username:String}) "
                "AND lower(search_blob) LIKE '%%c$%%' "
                "AND timestamp BETWEEN {window_start:DateTime64} AND {window_end:DateTime64} "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            tiers=[(2, 0.5), (3, 1.0)],
        ),
    ],

    'backup_operator_abuse': [
        CheckDefinition(
            id='bkop_privilege_anchor', name='SeBackupPrivilege assigned to user',
            weight=20, check_type='anchor_match',
        ),
        CheckDefinition(
            id='bkop_not_machine_account', name='Account is not a machine account ($)',
            weight=25, check_type='field_match',
        ),
        CheckDefinition(
            id='bkop_limited_privs', name='Limited privilege set (Backup Operator, not full admin)',
            weight=20, check_type='threshold',
            query_template=(
                "SELECT count() FROM events "
                "WHERE case_id = {case_id:UInt32} AND event_id = '4672' "
                "AND endsWith(username, {username:String}) "
                "AND lower(search_blob) LIKE '%%sebackupprivilege%%' "
                "AND lower(search_blob) NOT LIKE '%%sedebugprivilege%%' "
                "AND timestamp BETWEEN {window_start:DateTime64} AND {window_end:DateTime64} "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            pass_condition='result >= 1',
        ),
        CheckDefinition(
            id='bkop_remote_logon', name='Network logon (type 3) from remote source',
            weight=15, check_type='threshold',
            query_template=(
                "SELECT count() FROM events "
                "WHERE case_id = {case_id:UInt32} AND event_id = '4624' "
                "AND logon_type = 3 "
                "AND endsWith(username, {username:String}) "
                "AND src_ip IS NOT NULL "
                "AND src_ip != toIPv4('127.0.0.1') "
                "AND src_ip != toIPv4('0.0.0.0') "
                "AND timestamp BETWEEN {window_start:DateTime64} AND {window_end:DateTime64} "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            pass_condition='result >= 1',
        ),
        CheckDefinition(
            id='bkop_share_access', name='IPC$/winreg or C$ admin share access in same session',
            weight=20, check_type='threshold',
            query_template=(
                "SELECT count() FROM events "
                "WHERE case_id = {case_id:UInt32} AND event_id = '5145' "
                "AND endsWith(username, {username:String}) "
                "AND (lower(search_blob) LIKE '%%winreg%%' "
                "  OR lower(search_blob) LIKE '%%c$%%') "
                "AND timestamp BETWEEN {window_start:DateTime64} AND {window_end:DateTime64} "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            pass_condition='result >= 1',
        ),
    ],

    'sam_database_dump': [
        CheckDefinition(
            id='samdump_anchor', name='SAM database access or dump command anchor',
            weight=25, check_type='anchor_match',
        ),
        CheckDefinition(
            id='samdump_reg_save', name='reg save command for SAM/SYSTEM/SECURITY',
            weight=25, check_type='threshold',
            query_template=(
                "SELECT count() FROM events "
                "WHERE case_id = {case_id:UInt32} AND event_id IN ('1', '4688') "
                "AND source_host = {source_host:String} "
                "AND (lower(search_blob) LIKE '%%reg%%save%%hklm%%sam%%' "
                "  OR lower(search_blob) LIKE '%%reg%%save%%hklm%%system%%' "
                "  OR lower(search_blob) LIKE '%%reg%%save%%hklm%%security%%') "
                "AND timestamp BETWEEN {window_start:DateTime64} AND {window_end:DateTime64} "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            pass_condition='result >= 1',
        ),
        CheckDefinition(
            id='samdump_esentutl', name='esentutl or raw shadow-copy export',
            weight=20, check_type='threshold',
            query_template=(
                "SELECT count() FROM events "
                "WHERE case_id = {case_id:UInt32} AND event_id IN ('1', '4688') "
                "AND source_host = {source_host:String} "
                "AND (lower(search_blob) LIKE '%%esentutl%%' "
                "  OR lower(search_blob) LIKE '%%globalroot\\\\device\\\\harddiskvolumeshadowcopy%%') "
                "AND timestamp BETWEEN {window_start:DateTime64} AND {window_end:DateTime64} "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            pass_condition='result >= 1',
        ),
        CheckDefinition(
            id='samdump_vss', name='Volume Shadow Copy abuse for SAM extraction',
            weight=20, check_type='threshold',
            query_template=(
                "SELECT count() FROM events "
                "WHERE case_id = {case_id:UInt32} AND event_id IN ('1', '4688') "
                "AND source_host = {source_host:String} "
                "AND lower(search_blob) LIKE '%%vssadmin%%' "
                "AND lower(search_blob) LIKE '%%create%%shadow%%' "
                "AND timestamp BETWEEN {window_start:DateTime64} AND {window_end:DateTime64} "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            pass_condition='result >= 1',
        ),
        CheckDefinition(
            id='samdump_file_creation', name='SAM/SYSTEM/SECURITY .sav file creation',
            weight=15, check_type='threshold',
            query_template=(
                "SELECT count() FROM events "
                "WHERE case_id = {case_id:UInt32} AND event_id = '11' "
                "AND source_host = {source_host:String} "
                "AND (lower(search_blob) LIKE '%%sam.sav%%' "
                "  OR lower(search_blob) LIKE '%%system.sav%%' "
                "  OR lower(search_blob) LIKE '%%security.sav%%' "
                "  OR lower(search_blob) LIKE '%%sam.save%%' "
                "  OR lower(search_blob) LIKE '%%system.save%%' "
                "  OR lower(search_blob) LIKE '%%security.save%%') "
                "AND timestamp BETWEEN {window_start:DateTime64} AND {window_end:DateTime64} "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            pass_condition='result >= 1',
        ),
        CheckDefinition(
            id='samdump_hayabusa', name='Hayabusa rule tagged credential dump or reg export',
            weight=10, check_type='threshold',
            query_template=(
                "SELECT count() FROM events "
                "WHERE case_id = {case_id:UInt32} "
                "AND source_host = {source_host:String} "
                "AND (lower(rule_title) LIKE '%%sam%%dump%%' "
                "  OR lower(rule_title) LIKE '%%credential%%dump%%' "
                "  OR lower(rule_title) LIKE '%%reg%%export%%sensitive%%' "
                "  OR lower(rule_title) LIKE '%%dumping%%sensitive%%hive%%') "
                "AND timestamp BETWEEN {window_start:DateTime64} AND {window_end:DateTime64} "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            pass_condition='result >= 1',
        ),
    ],

    'pass_the_hash': [
        CheckDefinition(
            id='pth_ntlm_keylength', name='NTLM auth with KeyLength=0',
            weight=20, check_type='anchor_match',
        ),
        CheckDefinition(
            id='pth_local_loopback', name='Local PTH via loopback (classic Mimikatz)',
            weight=15, check_type='threshold',
            query_template=(
                "SELECT count() FROM events "
                "WHERE case_id = {case_id:UInt32} AND event_id = '4624' "
                "AND src_ip = '127.0.0.1' "
                "AND logon_type = 3 AND auth_package = 'NTLM' "
                "AND username = {username:String} "
                "AND timestamp BETWEEN {window_start:DateTime64} AND {window_end:DateTime64} "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            pass_condition='result >= 1',
        ),
        CheckDefinition(
            id='pth_type9_seclogo', name='Source-side type 9 logon — newer Mimikatz',
            weight=10, check_type='threshold',
            query_template=(
                "SELECT count() FROM events "
                "WHERE case_id = {case_id:UInt32} AND event_id = '4624' "
                "AND logon_type = 9 "
                "AND lower(search_blob) LIKE '%%seclogo%%' "
                "AND timestamp BETWEEN {window_start:DateTime64} AND {window_end:DateTime64} "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            pass_condition='result >= 1',
        ),
        CheckDefinition(
            id='pth_ipc_share', name='IPC$ share access post-logon (old+new Mimikatz)',
            weight=10, check_type='threshold',
            query_template=(
                "SELECT count() FROM events "
                "WHERE case_id = {case_id:UInt32} AND event_id = '5145' "
                "AND lower(search_blob) LIKE '%%ipc%%' "
                "AND endsWith(username, {username:String}) "
                "AND timestamp BETWEEN {anchor_ts:DateTime64} - INTERVAL 5 SECOND "
                "AND {anchor_ts:DateTime64} + INTERVAL 5 MINUTE "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            pass_condition='result >= 1',
        ),
        CheckDefinition(
            id='pth_no_kerberos_tgt', name='No preceding Kerberos TGT',
            weight=10, check_type='absence_with_coverage',
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
                "SELECT uniqExact(source_host) FROM events "
                "WHERE case_id = {case_id:UInt32} AND event_id = '4624' "
                "AND src_ip = {src_ip:String} "
                "AND timestamp BETWEEN {window_start:DateTime64} AND {window_end:DateTime64} "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            tiers=[(2, 0.3), (5, 0.6), (10, 1.0)],
        ),
        CheckDefinition(
            id='pth_privilege_escalation', name='Privilege escalation (4672)',
            weight=10, check_type='threshold',
            query_template=(
                "SELECT count() FROM events "
                "WHERE case_id = {case_id:UInt32} AND event_id = '4672' "
                "AND endsWith(username, {username:String}) "
                "AND timestamp BETWEEN {anchor_ts:DateTime64} - INTERVAL 5 SECOND "
                "AND {anchor_ts:DateTime64} + INTERVAL 5 SECOND "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            pass_condition='result >= 1',
        ),
        CheckDefinition(
            id='pth_process_context', name='Suspicious process after PTH logon',
            weight=10, check_type='threshold',
            query_template=(
                "SELECT count() FROM events "
                "WHERE case_id = {case_id:UInt32} AND event_id IN ('1', '4688') "
                "AND endsWith(username, {username:String}) "
                "AND timestamp BETWEEN {anchor_ts:DateTime64} - INTERVAL 30 SECOND "
                "AND {anchor_ts:DateTime64} + INTERVAL 10 MINUTE "
                "AND (lower(search_blob) LIKE '%%powershell.exe%%' "
                "     OR lower(search_blob) LIKE '%%cmd.exe%%' "
                "     OR lower(search_blob) LIKE '%%psexec.exe%%' "
                "     OR lower(search_blob) LIKE '%%wmic.exe%%' "
                "     OR lower(search_blob) LIKE '%%paexec.exe%%' "
                "     OR lower(search_blob) LIKE '%%csexec.exe%%' "
                "     OR lower(search_blob) LIKE '%%wmiprvse.exe%%') "
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
            weight=15, check_type='anchor_match',
        ),
        CheckDefinition(
            id='ptt_not_machine_account', name='Account is not a machine account ($)',
            weight=25, check_type='field_match',
        ),
        CheckDefinition(
            id='ptt_not_local_ip', name='Source is not loopback/local',
            weight=20, check_type='field_match',
        ),
        CheckDefinition(
            id='ptt_no_tgt', name='No preceding TGT (4768) within 10h',
            weight=15, check_type='absence_with_coverage',
            query_template=(
                "SELECT count() FROM events "
                "WHERE case_id = {case_id:UInt32} AND event_id = '4768' "
                "AND username = {username:String} "
                "AND timestamp BETWEEN {anchor_ts:DateTime64} - INTERVAL 600 MINUTE AND {anchor_ts:DateTime64} "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            pass_condition='result == 0',
            required_sources={'Security': 'critical'},
        ),
        CheckDefinition(
            id='ptt_no_tgs', name='No preceding TGS (4769) within 10h',
            weight=15, check_type='absence_with_coverage',
            query_template=(
                "SELECT count() FROM events "
                "WHERE case_id = {case_id:UInt32} AND event_id = '4769' "
                "AND username = {username:String} "
                "AND timestamp BETWEEN {anchor_ts:DateTime64} - INTERVAL 600 MINUTE AND {anchor_ts:DateTime64} "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            pass_condition='result == 0',
            required_sources={'Security': 'critical'},
        ),
        CheckDefinition(
            id='ptt_no_tgt_ever', name='User has no TGT request anywhere in case',
            weight=20, check_type='threshold',
            query_template=(
                "SELECT count() FROM events "
                "WHERE case_id = {case_id:UInt32} AND event_id = '4768' "
                "AND username = {username:String} "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            pass_condition='result == 0',
        ),
        CheckDefinition(
            id='ptt_burst', name='Burst of Kerberos logons',
            weight=20, check_type='burst',
        ),
        CheckDefinition(
            id='ptt_sensitive_service', name='Sensitive service target',
            weight=15, check_type='field_match',
        ),
    ],

    'dcsync': [
        CheckDefinition(
            id='dcs_replication_rights', name='Replication rights anchor',
            weight=25, check_type='anchor_match',
        ),
        CheckDefinition(
            id='dcs_dual_guid', name='Both Get-Changes AND Get-Changes-All GUIDs present',
            weight=20, check_type='threshold',
            query_template=(
                "SELECT uniqExact(multiIf("
                "  position(lower(search_blob), '1131f6aa') > 0, 'get-changes', "
                "  position(lower(search_blob), '1131f6ad') > 0, 'get-changes-all', "
                "  '')) as guid_count "
                "FROM events "
                "WHERE case_id = {case_id:UInt32} AND event_id = '4662' "
                "AND username = {username:String} "
                "AND timestamp BETWEEN {anchor_ts:DateTime64} - INTERVAL 5 MINUTE "
                "AND {anchor_ts:DateTime64} + INTERVAL 5 MINUTE "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            pass_condition='result >= 2',
        ),
        CheckDefinition(
            id='dcs_not_dc_account', name='Account is NOT a DC computer account',
            weight=20, check_type='field_match',
        ),
        CheckDefinition(
            id='dcs_not_dc_host', name='Source host is NOT a domain controller',
            weight=15, check_type='field_match',
        ),
        CheckDefinition(
            id='dcs_multi_replication', name='Multiple replication requests in 5min',
            weight=10, check_type='graduated',
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
            id='kerb_rc4_anchor', name='RC4/DES encryption TGS request (0x17/0x18)',
            weight=15, check_type='anchor_match',
        ),
        CheckDefinition(
            id='kerb_aes_requests', name='AES encryption TGS requests (0x11/0x12)',
            weight=10, check_type='threshold',
            query_template=(
                "SELECT count() FROM events "
                "WHERE case_id = {case_id:UInt32} AND event_id = '4769' "
                "AND username = {username:String} "
                "AND (lower(search_blob) LIKE '%%0x11%%' OR lower(search_blob) LIKE '%%0x12%%') "
                "AND timestamp BETWEEN {window_start:DateTime64} AND {window_end:DateTime64} "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            pass_condition='result >= 1',
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
            id='kerb_volume', name='High volume TGS requests (any encryption)',
            weight=15, check_type='graduated',
            query_template=(
                "SELECT count() FROM events "
                "WHERE case_id = {case_id:UInt32} AND event_id = '4769' "
                "AND username = {username:String} "
                "AND timestamp BETWEEN {window_start:DateTime64} AND {window_end:DateTime64} "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            tiers=[(5, 0.3), (10, 0.6), (20, 0.85), (50, 1.0)],
        ),
        CheckDefinition(
            id='kerb_not_service_account', name='Requesting account is not a service account',
            weight=20, check_type='field_match',
        ),
        CheckDefinition(
            id='kerb_burst', name='Burst of TGS requests',
            weight=15, check_type='burst',
        ),
    ],

    'password_spraying': [
        CheckDefinition(
            id='spray_distinct_users', name='10+ distinct usernames failed',
            weight=30, check_type='graduated',
            query_template=(
                "SELECT uniqExact(username) FROM events "
                "WHERE case_id = {case_id:UInt32} "
                "AND (event_id IN ('4625', '4771', '18456') OR (event_id = '4768' AND (payload_data5 IS NULL OR payload_data5 NOT LIKE '%%KDC_ERR_NONE%%'))) "
                "AND username NOT LIKE '##%%' "
                "AND ((source_host = {source_host:String}) "
                "  OR ({source_host:String} = '' AND src_ip = {src_ip:String})) "
                "AND timestamp BETWEEN {window_start:DateTime64} AND {window_end:DateTime64} "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            tiers=[(4, 0.3), (8, 0.6), (12, 0.85), (20, 1.0)],
        ),
        CheckDefinition(
            id='spray_low_per_account', name='Low attempts per account (1-3 each)',
            weight=15, check_type='threshold',
            query_template=(
                "SELECT max(cnt) FROM ("
                "  SELECT username, count() as cnt FROM events "
                "  WHERE case_id = {case_id:UInt32} "
                "  AND (event_id IN ('4625', '4771', '18456') OR (event_id = '4768' AND (payload_data5 IS NULL OR payload_data5 NOT LIKE '%%KDC_ERR_NONE%%'))) "
                "  AND username NOT LIKE '##%%' "
                "  AND ((source_host = {source_host:String}) "
                "    OR ({source_host:String} = '' AND src_ip = {src_ip:String})) "
                "  AND timestamp BETWEEN {window_start:DateTime64} AND {window_end:DateTime64} "
                "  AND (noise_matched = false OR noise_matched IS NULL) "
                "  GROUP BY username"
                ")"
            ),
            pass_condition='result <= 3',
        ),
        CheckDefinition(
            id='spray_total_failures', name='High total failed-auth volume',
            weight=20, check_type='graduated',
            query_template=(
                "SELECT count() FROM events "
                "WHERE case_id = {case_id:UInt32} "
                "AND (event_id IN ('4625', '4771', '18456') OR (event_id = '4768' AND (payload_data5 IS NULL OR payload_data5 NOT LIKE '%%KDC_ERR_NONE%%'))) "
                "AND ((source_host = {source_host:String}) "
                "  OR ({source_host:String} = '' AND src_ip = {src_ip:String})) "
                "AND timestamp BETWEEN {window_start:DateTime64} AND {window_end:DateTime64} "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            tiers=[(6, 0.3), (10, 0.6), (15, 0.85), (25, 1.0)],
        ),
        CheckDefinition(
            id='spray_bad_password', name='Auth failure indicator (bad password / pre-auth failed / principal unknown / MSSQL mismatch)',
            weight=15, check_type='threshold',
            query_template=(
                "SELECT count() FROM events "
                "WHERE case_id = {case_id:UInt32} "
                "AND ((source_host = {source_host:String}) "
                "  OR ({source_host:String} = '' AND src_ip = {src_ip:String})) "
                "AND ("
                "  (event_id = '4625' AND lower(payload_data1) LIKE '%%c000006a%%') "
                "  OR (event_id = '4771' AND payload_data3 LIKE '%%KDC_ERR_PREAUTH_FAILED%%') "
                "  OR (event_id = '4768' AND payload_data5 LIKE '%%KDC_ERR_C_PRINCIPAL_UNKNOWN%%') "
                "  OR (event_id = '18456' AND lower(payload_data2) LIKE '%%password did not match%%') "
                ") "
                "AND timestamp BETWEEN {window_start:DateTime64} AND {window_end:DateTime64} "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            pass_condition='result >= 1',
        ),
        CheckDefinition(
            id='spray_distinct_sources', name='Multiple source IPs attempting',
            weight=10, check_type='graduated',
            query_template=(
                "SELECT uniqExact(src_ip) FROM events "
                "WHERE case_id = {case_id:UInt32} "
                "AND (event_id IN ('4625', '4771', '18456') OR (event_id = '4768' AND (payload_data5 IS NULL OR payload_data5 NOT LIKE '%%KDC_ERR_NONE%%'))) "
                "AND ((source_host = {source_host:String}) "
                "  OR ({source_host:String} = '' AND src_ip = {src_ip:String})) "
                "AND timestamp BETWEEN {window_start:DateTime64} AND {window_end:DateTime64} "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            tiers=[(2, 0.3), (5, 0.6), (10, 1.0)],
        ),
        CheckDefinition(
            id='spray_spread_pattern', name='Spread pattern (not all at once)',
            weight=10, check_type='threshold',
            query_template=(
                "SELECT dateDiff('second', min(timestamp), max(timestamp)) FROM events "
                "WHERE case_id = {case_id:UInt32} "
                "AND (event_id IN ('4625', '4771', '18456') OR (event_id = '4768' AND (payload_data5 IS NULL OR payload_data5 NOT LIKE '%%KDC_ERR_NONE%%'))) "
                "AND ((source_host = {source_host:String}) "
                "  OR ({source_host:String} = '' AND src_ip = {src_ip:String})) "
                "AND timestamp BETWEEN {window_start:DateTime64} AND {window_end:DateTime64} "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            pass_condition='result >= 30',
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
                "WHERE case_id = {case_id:UInt32} AND event_id IN ('4625', '18456') "
                "AND username = {username:String} "
                "AND ((source_host = {source_host:String}) "
                "  OR ({source_host:String} = '' AND src_ip = {src_ip:String})) "
                "AND timestamp BETWEEN {window_start:DateTime64} AND {window_end:DateTime64} "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            tiers=[(5, 0.3), (10, 0.6), (25, 0.8), (50, 1.0)],
        ),
        CheckDefinition(
            id='brute_bad_password', name='Bad password indicator (SubStatus 0xC000006A or MSSQL password mismatch)',
            weight=20, check_type='threshold',
            query_template=(
                "SELECT count() FROM events "
                "WHERE case_id = {case_id:UInt32} "
                "AND username = {username:String} "
                "AND ((source_host = {source_host:String}) "
                "  OR ({source_host:String} = '' AND src_ip = {src_ip:String})) "
                "AND ("
                "  (event_id = '4625' AND lower(payload_data1) LIKE '%%c000006a%%') "
                "  OR (event_id = '18456' AND lower(payload_data2) LIKE '%%password did not match%%') "
                ") "
                "AND timestamp BETWEEN {window_start:DateTime64} AND {window_end:DateTime64} "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            pass_condition='result >= 1',
        ),
        CheckDefinition(
            id='brute_mssql_failures', name='MSSQL failed login concentration',
            weight=15, check_type='threshold',
            query_template=(
                "SELECT count() FROM events "
                "WHERE case_id = {case_id:UInt32} AND event_id = '18456' "
                "AND username = {username:String} "
                "AND ((source_host = {source_host:String}) "
                "  OR ({source_host:String} = '' AND src_ip = {src_ip:String})) "
                "AND timestamp BETWEEN {window_start:DateTime64} AND {window_end:DateTime64} "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            pass_condition='result >= 3',
        ),
        CheckDefinition(
            id='brute_followed_by_success', name='Followed by successful logon',
            weight=15, check_type='threshold',
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
            weight=10, check_type='field_match',
        ),
    ],

    'psexec_execution': [
        CheckDefinition(
            id='psexec_service_install', name='Remote service installation anchor',
            weight=25, check_type='anchor_match',
        ),
        CheckDefinition(
            id='psexec_network_logon', name='Network logon preceding service install',
            weight=15, check_type='threshold',
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
                "AND (lower(search_blob) LIKE '%%admin$%%' OR lower(search_blob) LIKE '%%c$%%') "
                "AND timestamp BETWEEN {anchor_ts:DateTime64} - INTERVAL 5 MINUTE AND {anchor_ts:DateTime64} "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            pass_condition='result >= 1',
            required_sources={'Security': 'critical'},
        ),
        CheckDefinition(
            id='psexec_remote_tooling', name='PsExec/PAExec/RemCom or remote sc.exe tooling',
            weight=15, check_type='threshold',
            query_template=(
                "SELECT count() FROM events "
                "WHERE case_id = {case_id:UInt32} AND event_id IN ('1', '4688') "
                "AND source_host = {source_host:String} "
                "AND (lower(search_blob) LIKE '%%psexec%%' "
                "  OR lower(search_blob) LIKE '%%paexec%%' "
                "  OR lower(search_blob) LIKE '%%csexec%%' "
                "  OR lower(search_blob) LIKE '%%remcom%%' "
                "  OR lower(search_blob) LIKE '%%sc.exe \\\\\\\\%%' "
                "  OR lower(search_blob) LIKE '%%sc \\\\\\\\%%') "
                "AND timestamp BETWEEN {window_start:DateTime64} AND {window_end:DateTime64} "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            pass_condition='result >= 1',
        ),
        CheckDefinition(
            id='psexec_suspicious_service', name='Suspicious service name pattern',
            weight=10, check_type='field_match',
        ),
        CheckDefinition(
            id='psexec_cmd_svc_binary', name='Service binary runs cmd.exe or powershell',
            weight=10, check_type='threshold',
            query_template=(
                "SELECT count() FROM events "
                "WHERE case_id = {case_id:UInt32} AND event_id IN ('7045', '4697') "
                "AND source_host = {source_host:String} "
                "AND (lower(search_blob) LIKE '%%cmd.exe%%' "
                "  OR lower(search_blob) LIKE '%%powershell%%' "
                "  OR lower(search_blob) LIKE '%%/c %%' "
                "  OR lower(search_blob) LIKE '%%\\\\admin$%%') "
                "AND timestamp BETWEEN {anchor_ts:DateTime64} - INTERVAL 1 MINUTE "
                "AND {anchor_ts:DateTime64} + INTERVAL 1 MINUTE "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            pass_condition='result >= 1',
        ),
        CheckDefinition(
            id='psexec_file_drop', name='Remote binary copy to ADMIN$ or C$ share',
            weight=10, check_type='threshold',
            query_template=(
                "SELECT count() FROM events "
                "WHERE case_id = {case_id:UInt32} AND event_id = '5145' "
                "AND source_host = {source_host:String} "
                "AND (lower(search_blob) LIKE '%%admin$%%' OR lower(search_blob) LIKE '%%c$%%') "
                "AND (lower(search_blob) LIKE '%%psexesvc%%' "
                "  OR lower(search_blob) LIKE '%%remcom%%' "
                "  OR lower(search_blob) LIKE '%%paexec%%' "
                "  OR lower(search_blob) LIKE '%%svc%%.exe%%') "
                "AND timestamp BETWEEN {window_start:DateTime64} AND {window_end:DateTime64} "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            pass_condition='result >= 1',
        ),
        CheckDefinition(
            id='psexec_short_lived', name='Service installed and quickly removed',
            weight=10, check_type='threshold',
            query_template=(
                "SELECT count() FROM events "
                "WHERE case_id = {case_id:UInt32} "
                "AND event_id IN ('7045', '4697', '7036') "
                "AND source_host = {source_host:String} "
                "AND timestamp BETWEEN {anchor_ts:DateTime64} AND {anchor_ts:DateTime64} + INTERVAL 10 MINUTE "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            pass_condition='result >= 2',
        ),
        CheckDefinition(
            id='psexec_off_hours', name='Off-hours activity',
            weight=5, check_type='field_match',
        ),
    ],

    'rdp_lateral': [
        CheckDefinition(
            id='rdp_type10_anchor', name='RemoteInteractive logon (type 10)',
            weight=25, check_type='anchor_match',
        ),
        CheckDefinition(
            id='rdp_multi_host', name='RDP to multiple hosts from same user',
            weight=20, check_type='graduated',
            query_template=(
                "SELECT uniqExact(source_host) FROM events "
                "WHERE case_id = {case_id:UInt32} AND event_id = '4624' "
                "AND logon_type IN (10, 7) AND username = {username:String} "
                "AND timestamp BETWEEN {window_start:DateTime64} AND {window_end:DateTime64} "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            tiers=[(2, 0.3), (3, 0.6), (5, 1.0)],
        ),
        CheckDefinition(
            id='rdp_off_hours', name='Off-hours RDP activity',
            weight=10, check_type='field_match',
        ),
        CheckDefinition(
            id='rdp_unusual_source', name='RDP from unusual source',
            weight=10, check_type='field_match',
        ),
        CheckDefinition(
            id='rdp_1149', name='Terminal Services authentication success (1149)',
            weight=20, check_type='threshold',
            query_template=(
                "SELECT count() FROM events "
                "WHERE case_id = {case_id:UInt32} AND event_id = '1149' "
                "AND endsWith(username, {username:String}) "
                "AND timestamp BETWEEN {window_start:DateTime64} AND {window_end:DateTime64} "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            pass_condition='result >= 1',
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

    'winrm_lateral': [
        CheckDefinition(
            id='winrm_logon_anchor', name='WinRM-specific process or service anchor',
            weight=25, check_type='anchor_match',
        ),
        CheckDefinition(
            id='winrm_wsmprovhost', name='wsmprovhost.exe or winrshost.exe process',
            weight=25, check_type='threshold',
            query_template=(
                "SELECT count() FROM events "
                "WHERE case_id = {case_id:UInt32} AND event_id IN ('1', '4688') "
                "AND source_host = {source_host:String} "
                "AND (lower(process_name) IN ('wsmprovhost.exe', 'winrshost.exe') "
                "  OR lower(search_blob) LIKE '%%wsmprovhost%%' "
                "  OR lower(search_blob) LIKE '%%winrshost%%') "
                "AND timestamp BETWEEN {anchor_ts:DateTime64} - INTERVAL 2 MINUTE "
                "AND {anchor_ts:DateTime64} + INTERVAL 5 MINUTE "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            pass_condition='result >= 1',
        ),
        CheckDefinition(
            id='winrm_service_event', name='WinRM or WSMan service event',
            weight=10, check_type='threshold',
            query_template=(
                "SELECT count() FROM events "
                "WHERE case_id = {case_id:UInt32} AND event_id IN ('91', '6') "
                "AND source_host = {source_host:String} "
                "AND (lower(search_blob) LIKE '%%winrm%%' "
                "  OR lower(search_blob) LIKE '%%wsman%%' "
                "  OR lower(search_blob) LIKE '%%shell%%') "
                "AND timestamp BETWEEN {window_start:DateTime64} AND {window_end:DateTime64} "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            pass_condition='result >= 1',
        ),
        CheckDefinition(
            id='winrm_ps_remoting', name='PowerShell remoting indicators',
            weight=20, check_type='threshold',
            query_template=(
                "SELECT count() FROM events "
                "WHERE case_id = {case_id:UInt32} AND event_id IN ('1', '4688', '4104') "
                "AND source_host = {source_host:String} "
                "AND (lower(search_blob) LIKE '%%enter-pssession%%' "
                "  OR lower(search_blob) LIKE '%%invoke-command%%' "
                "  OR lower(search_blob) LIKE '%%new-pssession%%' "
                "  OR lower(search_blob) LIKE '%%winrm%%') "
                "AND timestamp BETWEEN {anchor_ts:DateTime64} - INTERVAL 5 MINUTE "
                "AND {anchor_ts:DateTime64} + INTERVAL 5 MINUTE "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            pass_condition='result >= 1',
        ),
        CheckDefinition(
            id='winrm_multi_target', name='WinRM to multiple targets',
            weight=10, check_type='graduated',
            query_template=(
                "SELECT uniqExact(source_host) FROM events "
                "WHERE case_id = {case_id:UInt32} AND event_id = '4624' "
                "AND logon_type = 3 AND username = {username:String} "
                "AND timestamp BETWEEN {window_start:DateTime64} AND {window_end:DateTime64} "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            tiers=[(2, 0.3), (4, 0.6), (6, 0.85), (10, 1.0)],
        ),
        CheckDefinition(
            id='winrm_off_hours', name='Off-hours activity',
            weight=10, check_type='field_match',
        ),
    ],

    'log_clearing': [
        CheckDefinition(
            id='logclr_anchor', name='Log cleared event (1102/104)',
            weight=45, check_type='anchor_match',
        ),
        CheckDefinition(
            id='logclr_non_admin', name='Log cleared by non-admin user',
            weight=10, check_type='field_match',
        ),
        CheckDefinition(
            id='logclr_multi_log', name='Multiple logs cleared in sequence',
            weight=15, check_type='graduated',
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
        CheckDefinition(
            id='logclr_command', name='Explicit log-clearing command execution',
            weight=15, check_type='threshold',
            query_template=(
                "SELECT count() FROM events "
                "WHERE case_id = {case_id:UInt32} AND event_id IN ('1', '4688', '4104') "
                "AND source_host = {source_host:String} "
                "AND (lower(search_blob) LIKE '%%wevtutil%% cl %%' "
                "  OR lower(search_blob) LIKE '%%clear-eventlog%%' "
                "  OR lower(search_blob) LIKE '%%remove-eventlog%%') "
                "AND timestamp BETWEEN {anchor_ts:DateTime64} - INTERVAL 5 MINUTE "
                "AND {anchor_ts:DateTime64} + INTERVAL 2 MINUTE "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            pass_condition='result >= 1',
        ),
        CheckDefinition(
            id='logclr_off_hours', name='Off-hours activity',
            weight=15, check_type='field_match',
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
            id='lsass_silent_process_exit', name='Silent Process Exit cross-process termination',
            weight=25, check_type='field_match',
        ),
        CheckDefinition(
            id='lsass_dump_file', name='DMP file creation after access',
            weight=12, check_type='threshold',
            query_template=(
                "SELECT count() FROM events "
                "WHERE case_id = {case_id:UInt32} AND event_id = '11' "
                "AND source_host = {source_host:String} "
                "AND (lower(search_blob) LIKE '%%.dmp%%' OR lower(search_blob) LIKE '%%.mdmp%%') "
                "AND timestamp BETWEEN {anchor_ts:DateTime64} - INTERVAL 1 MINUTE "
                "AND {anchor_ts:DateTime64} + INTERVAL 5 MINUTE "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            pass_condition='result >= 1',
        ),
        CheckDefinition(
            id='lsass_reflection_dump', name='Process reflection / different-PID LSASS access',
            weight=8, check_type='threshold',
            query_template=(
                "SELECT uniqExact(JSONExtractString(raw_json, 'EventData', 'TargetProcessId')) "
                "FROM events "
                "WHERE case_id = {case_id:UInt32} AND event_id = '10' "
                "AND lower(JSONExtractString(raw_json, 'EventData', 'TargetImage')) LIKE '%%lsass.exe' "
                "AND timestamp BETWEEN {anchor_ts:DateTime64} - INTERVAL 2 MINUTE "
                "AND {anchor_ts:DateTime64} + INTERVAL 2 MINUTE "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            pass_condition='result >= 2',
        ),
        CheckDefinition(
            id='lsass_suspicious_process', name='Suspicious accessing process',
            weight=15, check_type='field_match',
        ),
        CheckDefinition(
            id='lsass_sysmon_technique_tag', name='Sysmon RuleName T1003 credential dumping tag',
            weight=10, check_type='threshold',
            query_template=(
                "SELECT count() FROM events "
                "WHERE case_id = {case_id:UInt32} "
                "AND source_host = {source_host:String} "
                "AND lower(search_blob) LIKE '%%technique_id=t1003%%' "
                "AND timestamp BETWEEN {anchor_ts:DateTime64} - INTERVAL 5 MINUTE "
                "AND {anchor_ts:DateTime64} + INTERVAL 5 MINUTE "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            pass_condition='result >= 1',
        ),
        CheckDefinition(
            id='lsass_calltrace_short', name='Short CallTrace indicative of direct API tool',
            weight=8, check_type='field_match',
        ),
        CheckDefinition(
            id='lsass_off_hours', name='Off-hours activity',
            weight=10, check_type='field_match',
        ),
    ],

    'powershell_credential_dump': [
        CheckDefinition(
            id='posh_lsass_anchor', name='PowerShell credential dump anchor (4104, Sysmon 7 DLL load, or Sysmon 10 lsass access)',
            weight=25, check_type='anchor_match',
        ),
        CheckDefinition(
            id='posh_minidump_api', name='MiniDumpWriteDump API in script block',
            weight=20, check_type='threshold',
            query_template=(
                "SELECT count() FROM events "
                "WHERE case_id = {case_id:UInt32} AND event_id = '4104' "
                "AND source_host = {source_host:String} "
                "AND lower(search_blob) LIKE '%%minidumpwritedump%%' "
                "AND timestamp BETWEEN {anchor_ts:DateTime64} - INTERVAL 5 MINUTE "
                "AND {anchor_ts:DateTime64} + INTERVAL 5 MINUTE "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            pass_condition='result >= 1',
        ),
        CheckDefinition(
            id='posh_getprocess_lsass', name='Get-Process lsass in script block',
            weight=15, check_type='threshold',
            query_template=(
                "SELECT count() FROM events "
                "WHERE case_id = {case_id:UInt32} AND event_id = '4104' "
                "AND source_host = {source_host:String} "
                "AND lower(search_blob) LIKE '%%get-process%%lsass%%' "
                "AND timestamp BETWEEN {anchor_ts:DateTime64} - INTERVAL 5 MINUTE "
                "AND {anchor_ts:DateTime64} + INTERVAL 5 MINUTE "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            pass_condition='result >= 1',
        ),
        CheckDefinition(
            id='posh_cred_dlls', name='Credential-dumping DLLs loaded by PowerShell (Sysmon 7)',
            weight=25, check_type='graduated',
            query_template=(
                "SELECT uniqExact(JSONExtractString(raw_json, 'EventData', 'ImageLoaded')) "
                "FROM events "
                "WHERE case_id = {case_id:UInt32} AND event_id = '7' "
                "AND source_host = {source_host:String} "
                "AND lower(JSONExtractString(raw_json, 'EventData', 'Image')) LIKE '%%powershell%%' "
                "AND (lower(JSONExtractString(raw_json, 'EventData', 'ImageLoaded')) LIKE '%%cryptdll.dll' "
                "  OR lower(JSONExtractString(raw_json, 'EventData', 'ImageLoaded')) LIKE '%%samlib.dll' "
                "  OR lower(JSONExtractString(raw_json, 'EventData', 'ImageLoaded')) LIKE '%%vaultcli.dll' "
                "  OR lower(JSONExtractString(raw_json, 'EventData', 'ImageLoaded')) LIKE '%%winscard.dll' "
                "  OR lower(JSONExtractString(raw_json, 'EventData', 'ImageLoaded')) LIKE '%%hid.dll') "
                "AND timestamp BETWEEN {anchor_ts:DateTime64} - INTERVAL 5 MINUTE "
                "AND {anchor_ts:DateTime64} + INTERVAL 5 MINUTE "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            tiers=[(2, 0.4), (3, 0.7), (4, 1.0)],
        ),
        CheckDefinition(
            id='posh_lsass_access', name='PowerShell accessing lsass.exe (Sysmon 10)',
            weight=15, check_type='threshold',
            query_template=(
                "SELECT count() FROM events "
                "WHERE case_id = {case_id:UInt32} AND event_id = '10' "
                "AND source_host = {source_host:String} "
                "AND lower(JSONExtractString(raw_json, 'EventData', 'SourceImage')) LIKE '%%powershell%%' "
                "AND lower(JSONExtractString(raw_json, 'EventData', 'TargetImage')) LIKE '%%lsass.exe' "
                "AND timestamp BETWEEN {anchor_ts:DateTime64} - INTERVAL 10 MINUTE "
                "AND {anchor_ts:DateTime64} + INTERVAL 10 MINUTE "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            pass_condition='result >= 1',
        ),
        CheckDefinition(
            id='posh_wer_reflection', name='WER / reflection abuse pattern',
            weight=10, check_type='threshold',
            query_template=(
                "SELECT count() FROM events "
                "WHERE case_id = {case_id:UInt32} AND event_id = '4104' "
                "AND source_host = {source_host:String} "
                "AND (lower(search_blob) LIKE '%%windowserrorreporting%%' "
                "  OR lower(search_blob) LIKE '%%nativemethods%%' "
                "  OR lower(search_blob) LIKE '%%reflection.bindingflags%%') "
                "AND timestamp BETWEEN {anchor_ts:DateTime64} - INTERVAL 5 MINUTE "
                "AND {anchor_ts:DateTime64} + INTERVAL 5 MINUTE "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            pass_condition='result >= 1',
        ),
        CheckDefinition(
            id='posh_network_download', name='PowerShell outbound network connection before lsass access',
            weight=10, check_type='threshold',
            query_template=(
                "SELECT count() FROM events "
                "WHERE case_id = {case_id:UInt32} AND event_id = '3' "
                "AND source_host = {source_host:String} "
                "AND lower(search_blob) LIKE '%%powershell%%' "
                "AND timestamp BETWEEN {anchor_ts:DateTime64} - INTERVAL 10 MINUTE "
                "AND {anchor_ts:DateTime64} "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            pass_condition='result >= 1',
        ),
        CheckDefinition(
            id='posh_off_hours', name='Off-hours activity',
            weight=10, check_type='field_match',
        ),
    ],

    'comsvcs_minidump': [
        CheckDefinition(
            id='comsvcs_anchor', name='rundll32 comsvcs.dll MiniDump command',
            weight=35, check_type='anchor_match',
        ),
        CheckDefinition(
            id='comsvcs_process_access', name='Process access after MiniDump (Sysmon 10)',
            weight=25, check_type='threshold',
            query_template=(
                "SELECT count() FROM events "
                "WHERE case_id = {case_id:UInt32} AND event_id = '10' "
                "AND source_host = {source_host:String} "
                "AND lower(search_blob) LIKE '%%comsvcs%%' "
                "AND timestamp BETWEEN {anchor_ts:DateTime64} - INTERVAL 1 MINUTE "
                "AND {anchor_ts:DateTime64} + INTERVAL 2 MINUTE "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            pass_condition='result >= 1',
        ),
        CheckDefinition(
            id='comsvcs_dump_file', name='Dump file created (Sysmon 11)',
            weight=15, check_type='threshold',
            query_template=(
                "SELECT count() FROM events "
                "WHERE case_id = {case_id:UInt32} AND event_id = '11' "
                "AND source_host = {source_host:String} "
                "AND timestamp BETWEEN {anchor_ts:DateTime64} - INTERVAL 1 MINUTE "
                "AND {anchor_ts:DateTime64} + INTERVAL 2 MINUTE "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            pass_condition='result >= 1',
        ),
        CheckDefinition(
            id='comsvcs_high_access', name='PROCESS_ALL_ACCESS rights (0x1FFFFF)',
            weight=15, check_type='threshold',
            query_template=(
                "SELECT count() FROM events "
                "WHERE case_id = {case_id:UInt32} AND event_id = '10' "
                "AND source_host = {source_host:String} "
                "AND (search_blob LIKE '%%0x1FFFFF%%' OR search_blob LIKE '%%0x1010%%' "
                "  OR search_blob LIKE '%%0x1038%%' OR search_blob LIKE '%%0x143A%%') "
                "AND timestamp BETWEEN {anchor_ts:DateTime64} - INTERVAL 1 MINUTE "
                "AND {anchor_ts:DateTime64} + INTERVAL 2 MINUTE "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            pass_condition='result >= 1',
        ),
        CheckDefinition(
            id='comsvcs_off_hours', name='Off-hours activity',
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
                "AND (lower(search_blob) LIKE '%%parentimage%%wmiprvse%%' "
                "  OR lower(JSONExtractString(raw_json, 'EventData', 'ParentImage')) LIKE '%%wmiprvse%%') "
                "AND timestamp BETWEEN {anchor_ts:DateTime64} - INTERVAL 5 MINUTE AND {anchor_ts:DateTime64} + INTERVAL 5 MINUTE "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            pass_condition='result >= 1',
        ),
        CheckDefinition(
            id='wmi_tooling', name='WMIC or PowerShell WMI remote execution tooling',
            weight=20, check_type='threshold',
            query_template=(
                "SELECT count() FROM events "
                "WHERE case_id = {case_id:UInt32} AND event_id IN ('1', '4688', '4104') "
                "AND source_host = {source_host:String} "
                "AND (lower(search_blob) LIKE '%%wmic%%/node%%' "
                "  OR lower(search_blob) LIKE '%%invoke-wmimethod%%' "
                "  OR lower(search_blob) LIKE '%%invoke-cimmethod%%' "
                "  OR lower(search_blob) LIKE '%%win32_process%%create%%') "
                "AND timestamp BETWEEN {window_start:DateTime64} AND {window_end:DateTime64} "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            pass_condition='result >= 1',
        ),
        CheckDefinition(
            id='wmi_operational', name='WMI operational telemetry present',
            weight=10, check_type='threshold',
            query_template=(
                "SELECT count() FROM events "
                "WHERE case_id = {case_id:UInt32} AND event_id IN ('5857', '5858', '5861') "
                "AND source_host = {source_host:String} "
                "AND timestamp BETWEEN {window_start:DateTime64} AND {window_end:DateTime64} "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            pass_condition='result >= 1',
        ),
        CheckDefinition(
            id='wmi_network_logon', name='Network logon preceding WMI (required for lateral)',
            weight=10, check_type='threshold',
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
            weight=5, check_type='field_match',
        ),
        CheckDefinition(
            id='wmi_unusual_source', name='Unusual source host',
            weight=5, check_type='field_match',
        ),
    ],

    'dcom_lateral_movement': [
        CheckDefinition(
            id='dcom_anchor', name='DCOM execution anchor',
            weight=25, check_type='anchor_match',
        ),
        CheckDefinition(
            id='dcom_tooling', name='MMC, ShellWindows, or mshta DCOM tooling',
            weight=25, check_type='threshold',
            query_template=(
                "SELECT count() FROM events "
                "WHERE case_id = {case_id:UInt32} AND event_id IN ('1', '4688') "
                "AND source_host = {source_host:String} "
                "AND (lower(search_blob) LIKE '%%shellbrowserwindow%%' "
                "  OR lower(search_blob) LIKE '%%shellwindows%%' "
                "  OR lower(search_blob) LIKE '%%mmc20%%' "
                "  OR lower(search_blob) LIKE '%%mmc%%' "
                "  OR lower(search_blob) LIKE '%%mshta%%' "
                "  OR lower(search_blob) LIKE '%%docmexec%%') "
                "AND timestamp BETWEEN {window_start:DateTime64} AND {window_end:DateTime64} "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            pass_condition='result >= 1',
        ),
        CheckDefinition(
            id='dcom_system_event', name='DCOM activation or error event observed',
            weight=20, check_type='threshold',
            query_template=(
                "SELECT count() FROM events "
                "WHERE case_id = {case_id:UInt32} AND event_id = '10016' "
                "AND source_host = {source_host:String} "
                "AND lower(search_blob) LIKE '%%dcom%%' "
                "AND timestamp BETWEEN {anchor_ts:DateTime64} - INTERVAL 5 MINUTE "
                "AND {anchor_ts:DateTime64} + INTERVAL 5 MINUTE "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            pass_condition='result >= 1',
        ),
        CheckDefinition(
            id='dcom_rpc_activity', name='RPC/DCOM network activity near execution',
            weight=20, check_type='threshold',
            query_template=(
                "SELECT count() FROM events "
                "WHERE case_id = {case_id:UInt32} AND event_id = '3' "
                "AND source_host = {source_host:String} "
                "AND (lower(search_blob) LIKE '%%rpcss%%' "
                "  OR lower(search_blob) LIKE '%%135%%' "
                "  OR lower(search_blob) LIKE '%%dcom%%') "
                "AND timestamp BETWEEN {window_start:DateTime64} AND {window_end:DateTime64} "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            pass_condition='result >= 1',
        ),
        CheckDefinition(
            id='dcom_network_logon', name='Network logon around DCOM execution',
            weight=10, check_type='threshold',
            query_template=(
                "SELECT count() FROM events "
                "WHERE case_id = {case_id:UInt32} AND event_id = '4624' "
                "AND logon_type IN (3) "
                "AND source_host = {source_host:String} "
                "AND timestamp BETWEEN {anchor_ts:DateTime64} - INTERVAL 5 MINUTE "
                "AND {anchor_ts:DateTime64} + INTERVAL 2 MINUTE "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            pass_condition='result >= 1',
        ),
    ],

    'smb_admin_shares': [
        CheckDefinition(
            id='smbshare_anchor', name='Administrative share access anchor',
            weight=25, check_type='anchor_match',
        ),
        CheckDefinition(
            id='smbshare_multi_access', name='Repeated ADMIN$/C$/IPC$ access',
            weight=30, check_type='graduated',
            query_template=(
                "SELECT count() FROM events "
                "WHERE case_id = {case_id:UInt32} AND event_id IN ('5140', '5145') "
                "AND ((source_host = {source_host:String}) "
                "  OR ({source_host:String} = '' AND src_ip = {src_ip:String})) "
                "AND (lower(search_blob) LIKE '%%admin$%%' "
                "  OR lower(search_blob) LIKE '%%c$%%' "
                "  OR lower(search_blob) LIKE '%%ipc$%%') "
                "AND timestamp BETWEEN {window_start:DateTime64} AND {window_end:DateTime64} "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            tiers=[(1, 0.3), (3, 0.6), (5, 1.0)],
        ),
        CheckDefinition(
            id='smbshare_network_logon', name='Network logon tied to admin-share access',
            weight=20, check_type='threshold',
            query_template=(
                "SELECT count() FROM events "
                "WHERE case_id = {case_id:UInt32} AND event_id = '4624' "
                "AND logon_type = 3 "
                "AND ((source_host = {source_host:String}) "
                "  OR ({source_host:String} = '' AND src_ip = {src_ip:String})) "
                "AND timestamp BETWEEN {window_start:DateTime64} AND {window_end:DateTime64} "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            pass_condition='result >= 1',
        ),
        CheckDefinition(
            id='smbshare_not_local_ip', name='Remote IP associated with admin-share access',
            weight=15, check_type='field_match',
        ),
        CheckDefinition(
            id='smbshare_off_hours', name='Off-hours activity',
            weight=10, check_type='field_match',
        ),
    ],

    'lateral_tool_transfer': [
        CheckDefinition(
            id='toolxfer_anchor', name='Remote tool transfer anchor',
            weight=25, check_type='anchor_match',
        ),
        CheckDefinition(
            id='toolxfer_suspicious_ext', name='Executable or script transferred over admin share',
            weight=30, check_type='threshold',
            query_template=(
                "SELECT count() FROM events "
                "WHERE case_id = {case_id:UInt32} AND event_id = '5145' "
                "AND ((source_host = {source_host:String}) "
                "  OR ({source_host:String} = '' AND src_ip = {src_ip:String})) "
                "AND (lower(search_blob) LIKE '%%admin$%%' OR lower(search_blob) LIKE '%%c$%%') "
                "AND (lower(search_blob) LIKE '%%.exe%%' "
                "  OR lower(search_blob) LIKE '%%.dll%%' "
                "  OR lower(search_blob) LIKE '%%.ps1%%' "
                "  OR lower(search_blob) LIKE '%%.bat%%' "
                "  OR lower(search_blob) LIKE '%%.hta%%' "
                "  OR lower(search_blob) LIKE '%%.vbs%%') "
                "AND timestamp BETWEEN {window_start:DateTime64} AND {window_end:DateTime64} "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            pass_condition='result >= 1',
        ),
        CheckDefinition(
            id='toolxfer_remote_logon', name='Remote logon tied to tool transfer',
            weight=15, check_type='threshold',
            query_template=(
                "SELECT count() FROM events "
                "WHERE case_id = {case_id:UInt32} AND event_id = '4624' "
                "AND logon_type = 3 "
                "AND ((source_host = {source_host:String}) "
                "  OR ({source_host:String} = '' AND src_ip = {src_ip:String})) "
                "AND timestamp BETWEEN {window_start:DateTime64} AND {window_end:DateTime64} "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            pass_condition='result >= 1',
        ),
        CheckDefinition(
            id='toolxfer_filecreate', name='Transferred payload written locally',
            weight=20, check_type='threshold',
            query_template=(
                "SELECT count() FROM events "
                "WHERE case_id = {case_id:UInt32} AND event_id = '11' "
                "AND source_host = {source_host:String} "
                "AND (lower(search_blob) LIKE '%%.exe%%' "
                "  OR lower(search_blob) LIKE '%%.dll%%' "
                "  OR lower(search_blob) LIKE '%%.ps1%%' "
                "  OR lower(search_blob) LIKE '%%.bat%%') "
                "AND timestamp BETWEEN {window_start:DateTime64} AND {window_end:DateTime64} "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            pass_condition='result >= 1',
        ),
        CheckDefinition(
            id='toolxfer_off_hours', name='Off-hours activity',
            weight=10, check_type='field_match',
        ),
    ],

    'registry_run_keys': [
        CheckDefinition(
            id='regrun_anchor', name='Registry Run key modification',
            weight=20, check_type='anchor_match',
        ),
        CheckDefinition(
            id='regrun_unusual_path', name='Binary in unusual location',
            weight=20, check_type='field_match',
        ),
        CheckDefinition(
            id='regrun_recent_binary', name='Recently created binary referenced',
            weight=15, check_type='threshold',
            query_template=(
                "SELECT count() FROM events "
                "WHERE case_id = {case_id:UInt32} AND event_id = '11' "
                "AND source_host = {source_host:String} "
                "AND (lower(search_blob) LIKE '%%\\\\temp\\\\%%' "
                "  OR lower(search_blob) LIKE '%%\\\\tmp\\\\%%' "
                "  OR lower(search_blob) LIKE '%%\\\\appdata\\\\%%' "
                "  OR lower(search_blob) LIKE '%%\\\\users\\\\public\\\\%%' "
                "  OR lower(search_blob) LIKE '%%\\\\programdata\\\\%%') "
                "AND timestamp BETWEEN {anchor_ts:DateTime64} - INTERVAL 30 MINUTE AND {anchor_ts:DateTime64} "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            pass_condition='result >= 1',
        ),
        CheckDefinition(
            id='regrun_non_admin', name='Non-admin process modifying Run key',
            weight=10, check_type='field_match',
        ),
        CheckDefinition(
            id='regrun_off_hours', name='Off-hours activity',
            weight=5, check_type='field_match',
        ),
    ],

    'winlogon_helper_dll': [
        CheckDefinition(
            id='winlogon_anchor', name='Winlogon shell/userinit registry anchor',
            weight=35, check_type='anchor_match',
        ),
        CheckDefinition(
            id='winlogon_key_scope', name='Winlogon Shell/Userinit/Notify key modified',
            weight=20, check_type='threshold',
            query_template=(
                "SELECT count() FROM events "
                "WHERE case_id = {case_id:UInt32} AND event_id IN ('12', '13', '4657') "
                "AND source_host = {source_host:String} "
                "AND (lower(search_blob) LIKE '%%\\\\winlogon\\\\shell%%' "
                "  OR lower(search_blob) LIKE '%%\\\\winlogon\\\\userinit%%' "
                "  OR lower(search_blob) LIKE '%%\\\\winlogon\\\\notify%%' "
                "  OR lower(search_blob) LIKE '%%\\\\winlogon\\\\taskman%%') "
                "AND timestamp BETWEEN {anchor_ts:DateTime64} - INTERVAL 2 MINUTE "
                "AND {anchor_ts:DateTime64} + INTERVAL 2 MINUTE "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            pass_condition='result >= 1',
        ),
        CheckDefinition(
            id='winlogon_suspicious_path', name='Winlogon value points to unusual path',
            weight=25, check_type='threshold',
            query_template=(
                "SELECT count() FROM events "
                "WHERE case_id = {case_id:UInt32} AND event_id IN ('12', '13', '4657') "
                "AND source_host = {source_host:String} "
                "AND (lower(search_blob) LIKE '%%\\\\temp\\\\%%' "
                "  OR lower(search_blob) LIKE '%%\\\\tmp\\\\%%' "
                "  OR lower(search_blob) LIKE '%%\\\\appdata\\\\%%' "
                "  OR lower(search_blob) LIKE '%%\\\\users\\\\public\\\\%%' "
                "  OR lower(search_blob) LIKE '%%\\\\programdata\\\\%%') "
                "AND timestamp BETWEEN {window_start:DateTime64} AND {window_end:DateTime64} "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            pass_condition='result >= 1',
        ),
        CheckDefinition(
            id='winlogon_followon_exec', name='Follow-on execution after Winlogon modification',
            weight=10, check_type='threshold',
            query_template=(
                "SELECT count() FROM events "
                "WHERE case_id = {case_id:UInt32} AND event_id IN ('1', '4688') "
                "AND source_host = {source_host:String} "
                "AND timestamp BETWEEN {anchor_ts:DateTime64} AND {anchor_ts:DateTime64} + INTERVAL 10 MINUTE "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            pass_condition='result >= 1',
        ),
        CheckDefinition(
            id='winlogon_off_hours', name='Off-hours activity',
            weight=10, check_type='field_match',
        ),
    ],

    'scheduled_task_persistence': [
        CheckDefinition(
            id='schtask_anchor', name='Scheduled task created (4698)',
            weight=25, check_type='anchor_match',
        ),
        CheckDefinition(
            id='schtask_system_priv', name='Task runs as SYSTEM',
            weight=25, check_type='field_match',
        ),
        CheckDefinition(
            id='schtask_script_action', name='Task action runs script/suspicious binary',
            weight=15, check_type='field_match',
        ),
        CheckDefinition(
            id='schtask_non_admin', name='Created by non-admin user',
            weight=10, check_type='field_match',
        ),
        CheckDefinition(
            id='schtask_off_hours', name='Off-hours activity',
            weight=10, check_type='field_match',
        ),
        CheckDefinition(
            id='schtask_bits_tooling', name='BITS or schtasks persistence tooling observed',
            weight=15, check_type='threshold',
            query_template=(
                "SELECT count() FROM events "
                "WHERE case_id = {case_id:UInt32} AND event_id IN ('1', '4688', '59', '60') "
                "AND source_host = {source_host:String} "
                "AND (lower(search_blob) LIKE '%%bitsadmin%%' "
                "  OR lower(search_blob) LIKE '%%setnotifycmdline%%' "
                "  OR lower(search_blob) LIKE '%%schtasks%%') "
                "AND timestamp BETWEEN {window_start:DateTime64} AND {window_end:DateTime64} "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            pass_condition='result >= 1',
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

    'wmi_persistence': [
        CheckDefinition(
            id='wmipers_anchor', name='Permanent WMI subscription anchor',
            weight=30, check_type='anchor_match',
        ),
        CheckDefinition(
            id='wmipers_object_chain', name='Multiple WMI subscription object types present',
            weight=25, check_type='threshold',
            query_template=(
                "SELECT uniqExact(event_id) FROM events "
                "WHERE case_id = {case_id:UInt32} AND event_id IN ('19', '20', '21', '5861') "
                "AND source_host = {source_host:String} "
                "AND timestamp BETWEEN {window_start:DateTime64} AND {window_end:DateTime64} "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            pass_condition='result >= 2',
        ),
        CheckDefinition(
            id='wmipers_consumer_type', name='CommandLine or ActiveScript consumer observed',
            weight=25, check_type='threshold',
            query_template=(
                "SELECT count() FROM events "
                "WHERE case_id = {case_id:UInt32} AND event_id IN ('20', '21', '5861') "
                "AND source_host = {source_host:String} "
                "AND (lower(search_blob) LIKE '%%commandlineeventconsumer%%' "
                "  OR lower(search_blob) LIKE '%%activescripteventconsumer%%' "
                "  OR lower(search_blob) LIKE '%%filtertoconsumerbinding%%') "
                "AND timestamp BETWEEN {window_start:DateTime64} AND {window_end:DateTime64} "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            pass_condition='result >= 1',
        ),
        CheckDefinition(
            id='wmipers_tooling', name='WMI persistence tooling or commands',
            weight=10, check_type='threshold',
            query_template=(
                "SELECT count() FROM events "
                "WHERE case_id = {case_id:UInt32} AND event_id IN ('1', '4688', '4104') "
                "AND source_host = {source_host:String} "
                "AND (lower(search_blob) LIKE '%%__eventfilter%%' "
                "  OR lower(search_blob) LIKE '%%filtertoconsumerbinding%%' "
                "  OR lower(search_blob) LIKE '%%set-wmiinstance%%' "
                "  OR lower(search_blob) LIKE '%%wmic%%') "
                "AND timestamp BETWEEN {window_start:DateTime64} AND {window_end:DateTime64} "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            pass_condition='result >= 1',
        ),
        CheckDefinition(
            id='wmipers_off_hours', name='Off-hours activity',
            weight=10, check_type='field_match',
        ),
    ],

    'dll_hijacking': [
        CheckDefinition(
            id='dllhijack_anchor', name='DLL/COM hijack anchor',
            weight=25, check_type='anchor_match',
        ),
        CheckDefinition(
            id='dllhijack_registry', name='COM/InprocServer32 registry modification',
            weight=25, check_type='threshold',
            query_template=(
                "SELECT count() FROM events "
                "WHERE case_id = {case_id:UInt32} AND event_id IN ('12', '13') "
                "AND source_host = {source_host:String} "
                "AND (lower(search_blob) LIKE '%%inprocserver32%%' "
                "  OR lower(search_blob) LIKE '%%treatas%%' "
                "  OR lower(search_blob) LIKE '%%clsid%%') "
                "AND timestamp BETWEEN {window_start:DateTime64} AND {window_end:DateTime64} "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            pass_condition='result >= 1',
        ),
        CheckDefinition(
            id='dllhijack_suspicious_path', name='Malicious DLL in user-writable path',
            weight=25, check_type='threshold',
            query_template=(
                "SELECT count() FROM events "
                "WHERE case_id = {case_id:UInt32} AND event_id IN ('7', '11') "
                "AND source_host = {source_host:String} "
                "AND lower(search_blob) LIKE '%%.dll%%' "
                "AND (lower(search_blob) LIKE '%%\\\\temp\\\\%%' "
                "  OR lower(search_blob) LIKE '%%\\\\tmp\\\\%%' "
                "  OR lower(search_blob) LIKE '%%\\\\appdata\\\\%%' "
                "  OR lower(search_blob) LIKE '%%\\\\users\\\\public\\\\%%') "
                "AND timestamp BETWEEN {window_start:DateTime64} AND {window_end:DateTime64} "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            pass_condition='result >= 1',
        ),
        CheckDefinition(
            id='dllhijack_target_app', name='Trusted application loads or references hijacked DLL',
            weight=15, check_type='threshold',
            query_template=(
                "SELECT count() FROM events "
                "WHERE case_id = {case_id:UInt32} AND event_id IN ('7', '1', '4688') "
                "AND source_host = {source_host:String} "
                "AND (lower(search_blob) LIKE '%%firefox%%' "
                "  OR lower(search_blob) LIKE '%%outlook%%' "
                "  OR lower(search_blob) LIKE '%%iexplore%%') "
                "AND timestamp BETWEEN {window_start:DateTime64} AND {window_end:DateTime64} "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            pass_condition='result >= 1',
        ),
        CheckDefinition(
            id='dllhijack_off_hours', name='Off-hours activity',
            weight=10, check_type='field_match',
        ),
    ],

    'uac_bypass': [
        CheckDefinition(
            id='uac_anchor', name='UAC bypass binary or registry hijack anchor',
            weight=35, check_type='anchor_match',
        ),
        CheckDefinition(
            id='uac_non_explorer_parent', name='Auto-elevated binary not launched by explorer.exe',
            weight=25, check_type='field_match',
        ),
        CheckDefinition(
            id='uac_child_process', name='Child process spawned by auto-elevated binary',
            weight=20, check_type='threshold',
            query_template=(
                "SELECT count() FROM events "
                "WHERE case_id = {case_id:UInt32} AND event_id IN ('1', '4688') "
                "AND source_host = {source_host:String} "
                "AND (lower(search_blob) LIKE '%%parentimage%%eventvwr%%' "
                "  OR lower(search_blob) LIKE '%%parentimage%%fodhelper%%' "
                "  OR lower(search_blob) LIKE '%%parentimage%%sdclt%%' "
                "  OR lower(search_blob) LIKE '%%parentimage%%computerdefaults%%') "
                "AND timestamp BETWEEN {anchor_ts:DateTime64} AND {anchor_ts:DateTime64} + INTERVAL 5 MINUTE "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            pass_condition='result >= 1',
        ),
        CheckDefinition(
            id='uac_registry_hijack', name='Registry modification for ms-settings/mscfile',
            weight=10, check_type='threshold',
            query_template=(
                "SELECT count() FROM events "
                "WHERE case_id = {case_id:UInt32} AND event_id IN ('12', '13') "
                "AND source_host = {source_host:String} "
                "AND (lower(search_blob) LIKE '%%ms-settings%%' OR lower(search_blob) LIKE '%%mscfile%%') "
                "AND timestamp BETWEEN {anchor_ts:DateTime64} - INTERVAL 2 MINUTE "
                "AND {anchor_ts:DateTime64} + INTERVAL 2 MINUTE "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            pass_condition='result >= 1',
        ),
        CheckDefinition(
            id='uac_off_hours', name='Off-hours activity',
            weight=10, check_type='field_match',
        ),
        CheckDefinition(
            id='uac_cmstp_or_uacme', name='CMSTP or UACME-style tooling observed',
            weight=10, check_type='threshold',
            query_template=(
                "SELECT count() FROM events "
                "WHERE case_id = {case_id:UInt32} AND event_id IN ('1', '4688') "
                "AND source_host = {source_host:String} "
                "AND (lower(search_blob) LIKE '%%cmstp%%' "
                "  OR lower(search_blob) LIKE '%%uacme%%' "
                "  OR lower(search_blob) LIKE '%%akagi%%') "
                "AND timestamp BETWEEN {window_start:DateTime64} AND {window_end:DateTime64} "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            pass_condition='result >= 1',
        ),
    ],

    'security_tool_tampering': [
        CheckDefinition(
            id='sectamper_anchor', name='Security or logging tamper anchor',
            weight=25, check_type='anchor_match',
        ),
        CheckDefinition(
            id='sectamper_eventlog_service', name='Event Log service crash/stop observed',
            weight=25, check_type='threshold',
            query_template=(
                "SELECT count() FROM events "
                "WHERE case_id = {case_id:UInt32} AND event_id IN ('7031', '7034', '7036') "
                "AND source_host = {source_host:String} "
                "AND lower(search_blob) LIKE '%%event log%%' "
                "AND timestamp BETWEEN {window_start:DateTime64} AND {window_end:DateTime64} "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            pass_condition='result >= 1',
        ),
        CheckDefinition(
            id='sectamper_logging_change', name='PowerShell or security logging setting changed',
            weight=25, check_type='threshold',
            query_template=(
                "SELECT count() FROM events "
                "WHERE case_id = {case_id:UInt32} AND event_id IN ('12', '13') "
                "AND source_host = {source_host:String} "
                "AND (lower(search_blob) LIKE '%%scriptblocklogging%%' "
                "  OR lower(search_blob) LIKE '%%executionpolicy%%' "
                "  OR lower(search_blob) LIKE '%%enablelua%%' "
                "  OR lower(search_blob) LIKE '%%eventlog%%') "
                "AND timestamp BETWEEN {window_start:DateTime64} AND {window_end:DateTime64} "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            pass_condition='result >= 1',
        ),
        CheckDefinition(
            id='sectamper_tooling', name='Tamper tooling or commands observed',
            weight=15, check_type='threshold',
            query_template=(
                "SELECT count() FROM events "
                "WHERE case_id = {case_id:UInt32} AND event_id IN ('1', '4688', '4104') "
                "AND source_host = {source_host:String} "
                "AND (lower(search_blob) LIKE '%%set-executionpolicy%%' "
                "  OR lower(search_blob) LIKE '%%wevtutil%%' "
                "  OR lower(search_blob) LIKE '%%eventlog%%' "
                "  OR lower(search_blob) LIKE '%%powershell -ep%%') "
                "AND timestamp BETWEEN {window_start:DateTime64} AND {window_end:DateTime64} "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            pass_condition='result >= 1',
        ),
        CheckDefinition(
            id='sectamper_off_hours', name='Off-hours activity',
            weight=10, check_type='field_match',
        ),
    ],

    'token_manipulation': [
        CheckDefinition(
            id='token_anchor', name='Token privilege or duplication anchor',
            weight=25, check_type='anchor_match',
        ),
        CheckDefinition(
            id='token_sedebug', name='SeDebugPrivilege or special privilege enablement',
            weight=25, check_type='threshold',
            query_template=(
                "SELECT count() FROM events "
                "WHERE case_id = {case_id:UInt32} AND event_id IN ('4703', '4672') "
                "AND source_host = {source_host:String} "
                "AND (lower(search_blob) LIKE '%%sedebugprivilege%%' "
                "  OR lower(search_blob) LIKE '%%setcbprivilege%%' "
                "  OR lower(search_blob) LIKE '%%seassignprimarytoken%%') "
                "AND timestamp BETWEEN {window_start:DateTime64} AND {window_end:DateTime64} "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            pass_condition='result >= 1',
        ),
        CheckDefinition(
            id='token_tooling', name='Token manipulation tooling observed',
            weight=25, check_type='threshold',
            query_template=(
                "SELECT count() FROM events "
                "WHERE case_id = {case_id:UInt32} AND event_id IN ('1', '4688', '4104') "
                "AND source_host = {source_host:String} "
                "AND (lower(search_blob) LIKE '%%tokenduplication%%' "
                "  OR lower(search_blob) LIKE '%%incognito%%' "
                "  OR lower(search_blob) LIKE '%%getsystem%%' "
                "  OR lower(search_blob) LIKE '%%impersonate%%token%%') "
                "AND timestamp BETWEEN {window_start:DateTime64} AND {window_end:DateTime64} "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            pass_condition='result >= 1',
        ),
        CheckDefinition(
            id='token_not_machine_account', name='User account performing privileged token operation',
            weight=15, check_type='field_match',
        ),
        CheckDefinition(
            id='token_off_hours', name='Off-hours activity',
            weight=10, check_type='field_match',
        ),
    ],

    'named_pipe_impersonation': [
        CheckDefinition(
            id='pipe_anchor', name='Named pipe impersonation anchor',
            weight=25, check_type='anchor_match',
        ),
        CheckDefinition(
            id='pipe_multi_events', name='Multiple pipe telemetry events present',
            weight=25, check_type='threshold',
            query_template=(
                "SELECT uniqExact(event_id) FROM events "
                "WHERE case_id = {case_id:UInt32} AND event_id IN ('17', '18', '13', '7045') "
                "AND source_host = {source_host:String} "
                "AND timestamp BETWEEN {window_start:DateTime64} AND {window_end:DateTime64} "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            pass_condition='result >= 2',
        ),
        CheckDefinition(
            id='pipe_tooling', name='Potato or named-pipe privesc tooling observed',
            weight=25, check_type='threshold',
            query_template=(
                "SELECT count() FROM events "
                "WHERE case_id = {case_id:UInt32} AND event_id IN ('1', '4688', '4104') "
                "AND source_host = {source_host:String} "
                "AND (lower(search_blob) LIKE '%%roguepotato%%' "
                "  OR lower(search_blob) LIKE '%%printspoofer%%' "
                "  OR lower(search_blob) LIKE '%%juicypotato%%' "
                "  OR lower(search_blob) LIKE '%%godpotato%%' "
                "  OR lower(search_blob) LIKE '%%namedpipe%%' "
                "  OR lower(search_blob) LIKE '%%getsystem%%') "
                "AND timestamp BETWEEN {window_start:DateTime64} AND {window_end:DateTime64} "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            pass_condition='result >= 1',
        ),
        CheckDefinition(
            id='pipe_service_trigger', name='Service creation used to trigger impersonation',
            weight=15, check_type='threshold',
            query_template=(
                "SELECT count() FROM events "
                "WHERE case_id = {case_id:UInt32} AND event_id = '7045' "
                "AND source_host = {source_host:String} "
                "AND timestamp BETWEEN {window_start:DateTime64} AND {window_end:DateTime64} "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            pass_condition='result >= 1',
        ),
        CheckDefinition(
            id='pipe_off_hours', name='Off-hours activity',
            weight=10, check_type='field_match',
        ),
    ],

    'certificate_installation': [
        CheckDefinition(
            id='cert_anchor', name='Root certificate store modification anchor',
            weight=30, check_type='anchor_match',
        ),
        CheckDefinition(
            id='cert_multiple_stores', name='Multiple certificate stores modified',
            weight=25, check_type='graduated',
            query_template=(
                "SELECT uniqExact(target_path) FROM events "
                "WHERE case_id = {case_id:UInt32} AND event_id IN ('12', '13') "
                "AND source_host = {source_host:String} "
                "AND lower(search_blob) LIKE '%%systemcertificates%%' "
                "AND lower(search_blob) LIKE '%%root%%' "
                "AND timestamp BETWEEN {anchor_ts:DateTime64} - INTERVAL 5 MINUTE "
                "AND {anchor_ts:DateTime64} + INTERVAL 5 MINUTE "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            tiers=[(2, 0.4), (3, 0.7), (4, 1.0)],
        ),
        CheckDefinition(
            id='cert_non_standard_process', name='Non-standard process modifying cert store',
            weight=20, check_type='field_match',
        ),
        CheckDefinition(
            id='cert_certutil_usage', name='certutil.exe used for certificate operations',
            weight=15, check_type='threshold',
            query_template=(
                "SELECT count() FROM events "
                "WHERE case_id = {case_id:UInt32} AND event_id IN ('1', '4688') "
                "AND source_host = {source_host:String} "
                "AND lower(search_blob) LIKE '%%certutil%%' "
                "AND timestamp BETWEEN {anchor_ts:DateTime64} - INTERVAL 5 MINUTE "
                "AND {anchor_ts:DateTime64} + INTERVAL 5 MINUTE "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            pass_condition='result >= 1',
        ),
        CheckDefinition(
            id='cert_off_hours', name='Off-hours activity',
            weight=10, check_type='field_match',
        ),
    ],

    'system_owner_discovery': [
        CheckDefinition(
            id='discovery_anchor', name='Discovery command execution anchor',
            weight=25, check_type='anchor_match',
        ),
        CheckDefinition(
            id='discovery_multi_commands', name='Multiple discovery commands in sequence',
            weight=30, check_type='graduated',
            query_template=(
                "SELECT count() FROM events "
                "WHERE case_id = {case_id:UInt32} AND event_id IN ('1', '4688') "
                "AND source_host = {source_host:String} "
                "AND (lower(command_line) LIKE '%%whoami%%' "
                "  OR lower(command_line) LIKE '%%hostname%%' "
                "  OR lower(command_line) LIKE '%%ipconfig%%' "
                "  OR lower(command_line) LIKE '%%net user%%' "
                "  OR lower(command_line) LIKE '%%net group%%' "
                "  OR lower(command_line) LIKE '%%quser%%' "
                "  OR lower(command_line) LIKE '%%systeminfo%%' "
                "  OR lower(command_line) LIKE '%%nltest%%') "
                "AND timestamp BETWEEN {anchor_ts:DateTime64} - INTERVAL 10 MINUTE "
                "AND {anchor_ts:DateTime64} + INTERVAL 10 MINUTE "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            tiers=[(2, 0.3), (3, 0.6), (5, 1.0)],
        ),
        CheckDefinition(
            id='discovery_suspicious_parent', name='Discovery from suspicious parent process',
            weight=20, check_type='field_match',
        ),
        CheckDefinition(
            id='discovery_priv_enum', name='Privilege or group enumeration flags',
            weight=15, check_type='field_match',
        ),
        CheckDefinition(
            id='discovery_off_hours', name='Off-hours activity',
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
            weight=20, check_type='field_match',
        ),
        CheckDefinition(
            id='inject_dual_events', name='Multiple injection telemetry types in same window',
            weight=10, check_type='threshold',
            query_template=(
                "SELECT uniqExact(event_id) FROM events "
                "WHERE case_id = {case_id:UInt32} AND event_id IN ('8', '10') "
                "AND source_host = {source_host:String} "
                "AND timestamp BETWEEN {anchor_ts:DateTime64} - INTERVAL 2 MINUTE "
                "AND {anchor_ts:DateTime64} + INTERVAL 2 MINUTE "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            pass_condition='result >= 2',
        ),
        CheckDefinition(
            id='inject_unusual_dll', name='DLL loaded from unusual path',
            weight=15, check_type='threshold',
            query_template=(
                "SELECT count() FROM events "
                "WHERE case_id = {case_id:UInt32} AND event_id = '7' "
                "AND source_host = {source_host:String} "
                "AND (lower(search_blob) LIKE '%%\\\\temp\\\\%%' "
                "  OR lower(search_blob) LIKE '%%\\\\tmp\\\\%%' "
                "  OR lower(search_blob) LIKE '%%\\\\appdata\\\\%%' "
                "  OR lower(search_blob) LIKE '%%\\\\users\\\\public\\\\%%' "
                "  OR lower(search_blob) LIKE '%%\\\\programdata\\\\%%') "
                "AND timestamp BETWEEN {anchor_ts:DateTime64} - INTERVAL 1 MINUTE AND {anchor_ts:DateTime64} + INTERVAL 1 MINUTE "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            pass_condition='result >= 1',
        ),
        CheckDefinition(
            id='inject_target_process', name='Target is sensitive process',
            weight=20, check_type='field_match',
        ),
        CheckDefinition(
            id='inject_off_hours', name='Off-hours activity',
            weight=5, check_type='field_match',
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
            tiers=[(5, 0.3), (10, 0.6), (25, 0.85), (50, 1.0)],
        ),
        CheckDefinition(
            id='bh_session_enum', name='Session enumeration (NetSessionEnum)',
            weight=25, check_type='threshold',
            query_template=(
                "SELECT count() FROM events "
                "WHERE case_id = {case_id:UInt32} AND event_id = '5145' "
                "AND source_host = {source_host:String} "
                "AND lower(search_blob) LIKE '%%ipc$%%' "
                "AND lower(search_blob) NOT LIKE '%%winreg%%' "
                "AND lower(search_blob) NOT LIKE '%%samr%%' "
                "AND timestamp BETWEEN {window_start:DateTime64} AND {window_end:DateTime64} "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            pass_condition='result >= 5',
        ),
        CheckDefinition(
            id='bh_tooling', name='BloodHound or SharpHound tooling observed',
            weight=15, check_type='threshold',
            query_template=(
                "SELECT count() FROM events "
                "WHERE case_id = {case_id:UInt32} AND event_id IN ('1', '4688', '4104') "
                "AND source_host = {source_host:String} "
                "AND (lower(search_blob) LIKE '%%sharphound%%' "
                "  OR lower(search_blob) LIKE '%%bloodhound%%' "
                "  OR lower(search_blob) LIKE '%%invoke-bloodhound%%' "
                "  OR lower(search_blob) LIKE '%%collectionmethod%%') "
                "AND timestamp BETWEEN {window_start:DateTime64} AND {window_end:DateTime64} "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            pass_condition='result >= 1',
        ),
        CheckDefinition(
            id='bh_from_workstation', name='Enumeration from workstation',
            weight=10, check_type='field_match',
        ),
        CheckDefinition(
            id='bh_off_hours', name='Off-hours activity',
            weight=10, check_type='field_match',
        ),
        CheckDefinition(
            id='bh_admin_focus', name='Sensitive admin group or object focus',
            weight=15, check_type='threshold',
            query_template=(
                "SELECT count() FROM events "
                "WHERE case_id = {case_id:UInt32} "
                "AND source_host = {source_host:String} "
                "AND (lower(search_blob) LIKE '%%domain admins%%' "
                "  OR lower(search_blob) LIKE '%%enterprise admins%%' "
                "  OR lower(search_blob) LIKE '%%adminsdholder%%') "
                "AND timestamp BETWEEN {window_start:DateTime64} AND {window_end:DateTime64} "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            pass_condition='result >= 1',
        ),
    ],

    'network_scanning': [
        CheckDefinition(
            id='netscan_anchor', name='Network connection anchor (Sysmon 3)',
            weight=25, check_type='anchor_match',
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
            tiers=[(2, 0.3), (5, 0.6), (10, 0.85), (25, 1.0)],
        ),
        CheckDefinition(
            id='netscan_sequential_ports', name='Sequential port connections',
            weight=15, check_type='threshold',
            query_template=(
                "SELECT uniqExact(JSONExtractUInt(raw_json, 'EventData', 'DestinationPort')) FROM events "
                "WHERE case_id = {case_id:UInt32} AND event_id = '3' "
                "AND source_host = {source_host:String} "
                "AND timestamp BETWEEN {window_start:DateTime64} AND {window_end:DateTime64} "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            pass_condition='result >= 2',
        ),
        CheckDefinition(
            id='netscan_burst', name='Burst of connections',
            weight=15, check_type='burst',
        ),
        CheckDefinition(
            id='netscan_off_hours', name='Off-hours activity',
            weight=15, check_type='field_match',
        ),
        CheckDefinition(
            id='netscan_smb_rdp_focus', name='Scan focused on common lateral-movement ports',
            weight=15, check_type='threshold',
            query_template=(
                "SELECT count() FROM events "
                "WHERE case_id = {case_id:UInt32} AND event_id = '3' "
                "AND source_host = {source_host:String} "
                "AND (lower(search_blob) LIKE '%%445%%' "
                "  OR lower(search_blob) LIKE '%%3389%%' "
                "  OR lower(search_blob) LIKE '%%5985%%' "
                "  OR lower(search_blob) LIKE '%%135%%') "
                "AND timestamp BETWEEN {window_start:DateTime64} AND {window_end:DateTime64} "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            pass_condition='result >= 1',
        ),
    ],

    'security_tool_tampering': [
        CheckDefinition(
            id='sectamper_anchor', name='Security or logging tamper anchor',
            weight=25, check_type='anchor_match',
        ),
        CheckDefinition(
            id='sectamper_eventlog_service', name='Event Log service crash/stop observed',
            weight=25, check_type='threshold',
            query_template=(
                "SELECT count() FROM events "
                "WHERE case_id = {case_id:UInt32} AND event_id IN ('7031', '7034', '7036') "
                "AND source_host = {source_host:String} "
                "AND lower(search_blob) LIKE '%%event log%%' "
                "AND timestamp BETWEEN {window_start:DateTime64} AND {window_end:DateTime64} "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            pass_condition='result >= 1',
        ),
        CheckDefinition(
            id='sectamper_logging_change', name='PowerShell or security logging setting changed',
            weight=25, check_type='threshold',
            query_template=(
                "SELECT count() FROM events "
                "WHERE case_id = {case_id:UInt32} AND event_id IN ('12', '13') "
                "AND source_host = {source_host:String} "
                "AND (lower(search_blob) LIKE '%%scriptblocklogging%%' "
                "  OR lower(search_blob) LIKE '%%executionpolicy%%' "
                "  OR lower(search_blob) LIKE '%%enablelua%%' "
                "  OR lower(search_blob) LIKE '%%eventlog%%') "
                "AND timestamp BETWEEN {window_start:DateTime64} AND {window_end:DateTime64} "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            pass_condition='result >= 1',
        ),
        CheckDefinition(
            id='sectamper_tooling', name='Tamper tooling or commands observed',
            weight=15, check_type='threshold',
            query_template=(
                "SELECT count() FROM events "
                "WHERE case_id = {case_id:UInt32} AND event_id IN ('1', '4688', '4104') "
                "AND source_host = {source_host:String} "
                "AND (lower(search_blob) LIKE '%%set-executionpolicy%%' "
                "  OR lower(search_blob) LIKE '%%wevtutil%%' "
                "  OR lower(search_blob) LIKE '%%eventlog%%' "
                "  OR lower(search_blob) LIKE '%%powershell -ep%%') "
                "AND timestamp BETWEEN {window_start:DateTime64} AND {window_end:DateTime64} "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            pass_condition='result >= 1',
        ),
        CheckDefinition(
            id='sectamper_off_hours', name='Off-hours activity',
            weight=10, check_type='field_match',
        ),
    ],

    'timestomping': [
        CheckDefinition(
            id='timestomp_anchor', name='File timestamp manipulation anchor',
            weight=35, check_type='anchor_match',
        ),
        CheckDefinition(
            id='timestomp_suspicious_path', name='Timestamp change on suspicious path',
            weight=25, check_type='threshold',
            query_template=(
                "SELECT count() FROM events "
                "WHERE case_id = {case_id:UInt32} AND event_id = '2' "
                "AND source_host = {source_host:String} "
                "AND (lower(search_blob) LIKE '%%\\\\temp\\\\%%' "
                "  OR lower(search_blob) LIKE '%%\\\\tmp\\\\%%' "
                "  OR lower(search_blob) LIKE '%%\\\\appdata\\\\%%' "
                "  OR lower(search_blob) LIKE '%%\\\\users\\\\public\\\\%%' "
                "  OR lower(search_blob) LIKE '%%\\\\programdata\\\\%%') "
                "AND timestamp BETWEEN {window_start:DateTime64} AND {window_end:DateTime64} "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            pass_condition='result >= 1',
        ),
        CheckDefinition(
            id='timestomp_tooling', name='Timestomp tooling observed near change',
            weight=20, check_type='threshold',
            query_template=(
                "SELECT count() FROM events "
                "WHERE case_id = {case_id:UInt32} AND event_id IN ('1', '4688', '4104') "
                "AND source_host = {source_host:String} "
                "AND (lower(search_blob) LIKE '%%timestomp%%' "
                "  OR lower(search_blob) LIKE '%%setmace%%' "
                "  OR lower(search_blob) LIKE '%%setfiletime%%') "
                "AND timestamp BETWEEN {window_start:DateTime64} AND {window_end:DateTime64} "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            pass_condition='result >= 1',
        ),
        CheckDefinition(
            id='timestomp_off_hours', name='Off-hours activity',
            weight=10, check_type='field_match',
        ),
    ],

    'amsi_bypass': [
        CheckDefinition(
            id='amsi_anchor', name='AMSI or PowerShell logging bypass anchor',
            weight=25, check_type='anchor_match',
        ),
        CheckDefinition(
            id='amsi_registry_change', name='Logging or CLM registry setting changed',
            weight=25, check_type='threshold',
            query_template=(
                "SELECT count() FROM events "
                "WHERE case_id = {case_id:UInt32} AND event_id IN ('12', '13') "
                "AND source_host = {source_host:String} "
                "AND (lower(search_blob) LIKE '%%scriptblocklogging%%' "
                "  OR lower(search_blob) LIKE '%%constrainedlanguage%%' "
                "  OR lower(search_blob) LIKE '%%powershell%%') "
                "AND timestamp BETWEEN {window_start:DateTime64} AND {window_end:DateTime64} "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            pass_condition='result >= 1',
        ),
        CheckDefinition(
            id='amsi_bypass_strings', name='AMSI bypass strings or patching logic present',
            weight=25, check_type='threshold',
            query_template=(
                "SELECT count() FROM events "
                "WHERE case_id = {case_id:UInt32} AND event_id IN ('1', '4688', '4104') "
                "AND source_host = {source_host:String} "
                "AND (lower(search_blob) LIKE '%%amsi%%' "
                "  OR lower(search_blob) LIKE '%%amsiutils%%' "
                "  OR lower(search_blob) LIKE '%%amsiinitfailed%%' "
                "  OR lower(search_blob) LIKE '%%bypass%%') "
                "AND timestamp BETWEEN {window_start:DateTime64} AND {window_end:DateTime64} "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            pass_condition='result >= 1',
        ),
        CheckDefinition(
            id='amsi_offensive_ps', name='Offensive PowerShell context around bypass',
            weight=15, check_type='threshold',
            query_template=(
                "SELECT count() FROM events "
                "WHERE case_id = {case_id:UInt32} AND event_id IN ('4104', '1', '4688') "
                "AND source_host = {source_host:String} "
                "AND (lower(search_blob) LIKE '%%invoke-mimikatz%%' "
                "  OR lower(search_blob) LIKE '%%downloadstring%%' "
                "  OR lower(search_blob) LIKE '%%frombase64string%%') "
                "AND timestamp BETWEEN {window_start:DateTime64} AND {window_end:DateTime64} "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            pass_condition='result >= 1',
        ),
        CheckDefinition(
            id='amsi_off_hours', name='Off-hours activity',
            weight=10, check_type='field_match',
        ),
    ],

    'firewall_tampering': [
        CheckDefinition(
            id='fw_anchor', name='Firewall or remote-access tamper anchor',
            weight=25, check_type='anchor_match',
        ),
        CheckDefinition(
            id='fw_rdp_enable', name='RDP enablement registry change',
            weight=25, check_type='threshold',
            query_template=(
                "SELECT count() FROM events "
                "WHERE case_id = {case_id:UInt32} AND event_id IN ('12', '13') "
                "AND source_host = {source_host:String} "
                "AND lower(search_blob) LIKE '%%fdenytsconnections%%' "
                "AND timestamp BETWEEN {window_start:DateTime64} AND {window_end:DateTime64} "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            pass_condition='result >= 1',
        ),
        CheckDefinition(
            id='fw_portproxy', name='Port proxy or firewall command observed',
            weight=25, check_type='threshold',
            query_template=(
                "SELECT count() FROM events "
                "WHERE case_id = {case_id:UInt32} AND event_id IN ('1', '4688', '13') "
                "AND source_host = {source_host:String} "
                "AND (lower(search_blob) LIKE '%%portproxy%%' "
                "  OR lower(search_blob) LIKE '%%advfirewall%%' "
                "  OR lower(search_blob) LIKE '%%netsh%%') "
                "AND timestamp BETWEEN {window_start:DateTime64} AND {window_end:DateTime64} "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            pass_condition='result >= 1',
        ),
        CheckDefinition(
            id='fw_off_hours', name='Off-hours activity',
            weight=10, check_type='field_match',
        ),
    ],

    'evidence_deletion': [
        CheckDefinition(
            id='evdel_anchor', name='Evidence cleanup registry anchor',
            weight=30, check_type='anchor_match',
        ),
        CheckDefinition(
            id='evdel_multiple_keys', name='Multiple MRU or recent-item keys affected',
            weight=25, check_type='graduated',
            query_template=(
                "SELECT uniqExact(target_path) FROM events "
                "WHERE case_id = {case_id:UInt32} AND event_id IN ('12', '13') "
                "AND source_host = {source_host:String} "
                "AND (lower(search_blob) LIKE '%%mru%%' "
                "  OR lower(search_blob) LIKE '%%recentdocs%%' "
                "  OR lower(search_blob) LIKE '%%typedpaths%%' "
                "  OR lower(search_blob) LIKE '%%opensavepidlmru%%') "
                "AND timestamp BETWEEN {window_start:DateTime64} AND {window_end:DateTime64} "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            tiers=[(1, 0.3), (2, 0.6), (3, 1.0)],
        ),
        CheckDefinition(
            id='evdel_cleanup_tool', name='Cleanup tooling or registry deletion commands',
            weight=20, check_type='threshold',
            query_template=(
                "SELECT count() FROM events "
                "WHERE case_id = {case_id:UInt32} AND event_id IN ('1', '4688', '4104') "
                "AND source_host = {source_host:String} "
                "AND (lower(search_blob) LIKE '%%reg delete%%' "
                "  OR lower(search_blob) LIKE '%%remove-itemproperty%%' "
                "  OR lower(search_blob) LIKE '%%mru%%') "
                "AND timestamp BETWEEN {window_start:DateTime64} AND {window_end:DateTime64} "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            pass_condition='result >= 1',
        ),
        CheckDefinition(
            id='evdel_off_hours', name='Off-hours activity',
            weight=10, check_type='field_match',
        ),
    ],

    'local_group_discovery': [
        CheckDefinition(
            id='lgdisc_anchor', name='Local group or user discovery anchor',
            weight=25, check_type='anchor_match',
        ),
        CheckDefinition(
            id='lgdisc_multi_events', name='Multiple local group discovery events',
            weight=30, check_type='graduated',
            query_template=(
                "SELECT count() FROM events "
                "WHERE case_id = {case_id:UInt32} AND event_id IN ('4798', '4799') "
                "AND source_host = {source_host:String} "
                "AND timestamp BETWEEN {window_start:DateTime64} AND {window_end:DateTime64} "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            tiers=[(1, 0.3), (2, 0.6), (4, 1.0)],
        ),
        CheckDefinition(
            id='lgdisc_tooling', name='Local group discovery tooling observed',
            weight=20, check_type='threshold',
            query_template=(
                "SELECT count() FROM events "
                "WHERE case_id = {case_id:UInt32} AND event_id IN ('1', '4688') "
                "AND source_host = {source_host:String} "
                "AND (lower(search_blob) LIKE '%%net localgroup%%' "
                "  OR lower(search_blob) LIKE '%%whoami /groups%%' "
                "  OR lower(search_blob) LIKE '%%net user%%') "
                "AND timestamp BETWEEN {window_start:DateTime64} AND {window_end:DateTime64} "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            pass_condition='result >= 1',
        ),
        CheckDefinition(
            id='lgdisc_from_workstation', name='Enumeration from workstation',
            weight=15, check_type='field_match',
        ),
        CheckDefinition(
            id='lgdisc_off_hours', name='Off-hours activity',
            weight=10, check_type='field_match',
        ),
    ],

    'domain_group_discovery': [
        CheckDefinition(
            id='dgdisc_anchor', name='Domain group discovery anchor',
            weight=25, check_type='anchor_match',
        ),
        CheckDefinition(
            id='dgdisc_domain_admins', name='Sensitive domain group queried',
            weight=30, check_type='threshold',
            query_template=(
                "SELECT count() FROM events "
                "WHERE case_id = {case_id:UInt32} "
                "AND source_host = {source_host:String} "
                "AND (event_id = '4661' OR event_id IN ('1', '4688')) "
                "AND (lower(search_blob) LIKE '%%domain admins%%' "
                "  OR lower(search_blob) LIKE '%%enterprise admins%%' "
                "  OR lower(search_blob) LIKE '%%domain users%%') "
                "AND timestamp BETWEEN {window_start:DateTime64} AND {window_end:DateTime64} "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            pass_condition='result >= 1',
        ),
        CheckDefinition(
            id='dgdisc_tooling', name='Domain group discovery tooling observed',
            weight=20, check_type='threshold',
            query_template=(
                "SELECT count() FROM events "
                "WHERE case_id = {case_id:UInt32} AND event_id IN ('1', '4688') "
                "AND source_host = {source_host:String} "
                "AND (lower(search_blob) LIKE '%%net group%%' "
                "  OR lower(search_blob) LIKE '%%dsquery%%' "
                "  OR lower(search_blob) LIKE '%%adfind%%') "
                "AND timestamp BETWEEN {window_start:DateTime64} AND {window_end:DateTime64} "
                "AND (noise_matched = false OR noise_matched IS NULL)"
            ),
            pass_condition='result >= 1',
        ),
        CheckDefinition(
            id='dgdisc_not_machine_account', name='User account performing group discovery',
            weight=15, check_type='field_match',
        ),
        CheckDefinition(
            id='dgdisc_off_hours', name='Off-hours activity',
            weight=10, check_type='field_match',
        ),
    ],
}


SPREAD_CHECKS: Dict[str, Dict[str, Any]] = {
    'pass_the_hash': {
        'pivot_field': 'src_ip',
        'weight': 15,
        'event_filter': "event_id = '4624'",
        'target_field': 'source_host',
        'tiers': [(2, 0.3), (5, 0.6), (10, 0.85), (20, 1.0)],
    },
    'pass_the_ticket': {
        'pivot_field': 'username',
        'weight': 15,
        'event_filter': "event_id = '4624'",
        'target_field': 'source_host',
        'tiers': [(2, 0.3), (5, 0.6), (10, 0.85), (20, 1.0)],
    },
    'psexec_execution': {
        'pivot_field': 'src_ip',
        'weight': 15,
        'event_filter': "event_id IN ('7045', '4697')",
        'target_field': 'source_host',
        'tiers': [(2, 0.3), (5, 0.6), (8, 0.85), (15, 1.0)],
    },
    'kerberoasting': {
        'pivot_field': 'username',
        'weight': 12,
        'event_filter': "event_id = '4769'",
        'target_field': 'payload_data1',
        'tiers': [(3, 0.3), (5, 0.6), (10, 0.85), (20, 1.0)],
    },
    'password_spraying': {
        'pivot_field': 'src_ip',
        'weight': 12,
        'event_filter': "(event_id IN ('4625', '4771') OR (event_id = '4768' AND (payload_data5 IS NULL OR payload_data5 NOT LIKE '%KDC_ERR_NONE%')))",
        'target_field': 'username',
        'tiers': [(5, 0.3), (10, 0.5), (25, 0.75), (50, 1.0)],
    },
    'rdp_lateral': {
        'pivot_field': 'username',
        'weight': 15,
        'event_filter': "event_id = '4624'",
        'target_field': 'source_host',
        'tiers': [(2, 0.3), (4, 0.6), (6, 0.85), (10, 1.0)],
    },
    'wmi_lateral': {
        'pivot_field': 'src_ip',
        'weight': 12,
        'event_filter': "event_id IN ('4624', '4688')",
        'target_field': 'source_host',
        'tiers': [(2, 0.3), (5, 0.6), (8, 0.85), (15, 1.0)],
    },
    'winrm_lateral': {
        'pivot_field': 'username',
        'weight': 15,
        'event_filter': "event_id = '4624'",
        'target_field': 'source_host',
        'tiers': [(2, 0.3), (4, 0.6), (6, 0.85), (10, 1.0)],
    },
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


def get_spread_config(pattern_id: str) -> Optional[Dict[str, Any]]:
    """Get cross-key spread config for a pattern."""
    return SPREAD_CHECKS.get(pattern_id)
