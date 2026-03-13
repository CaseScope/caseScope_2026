"""Deterministic Evidence Engine for CaseScope

Computes verifiable evidence for each attack pattern match using
ClickHouse queries instead of LLM inference. Produces structured
evidence packages that can optionally be refined by an AI judgment layer.

Architecture:
  CandidateExtractor (anchors) -> DeterministicEvidenceEngine -> EvidencePackage
  EvidencePackage -> (optional) AI Judgment Layer -> AIAnalysisResult
"""

import logging
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any

from utils.pattern_check_definitions import (
    CheckDefinition, CheckResult, CoverageAssessment, BurstResult,
    SequenceResult, EvidencePackage, SpreadAssessment,
    get_checks_for_pattern, get_burst_config, get_sequence_config,
    get_spread_config,
    BURST_THRESHOLDS,
)
from utils.gap_detector_bridge import map_gap_finding_to_check_results, get_gap_pattern_id

logger = logging.getLogger(__name__)

INCONCLUSIVE_WEIGHT_FRACTION = 0.3


class DeterministicEvidenceEngine:
    """Computes verifiable evidence for each pattern match."""

    def __init__(self, case_id: int, analysis_id: str,
                 census: Dict[str, int] = None,
                 gap_findings: List = None):
        self.case_id = case_id
        self.analysis_id = analysis_id
        self.census = census or {}
        self.gap_findings = gap_findings or []
        self._ch_client = None

    def _get_ch(self):
        if self._ch_client is None:
            from utils.clickhouse import get_fresh_client
            self._ch_client = get_fresh_client()
        return self._ch_client

    def evaluate_pattern(
        self, pattern_id: str, pattern_config: Dict,
        anchor_events: List[Dict], time_window_minutes: int = 60
    ) -> List[EvidencePackage]:
        """Evaluate all anchors for a pattern, returning one EvidencePackage
        per correlation key."""
        start_time = time.time()
        checks_defs = get_checks_for_pattern(pattern_id)
        if not checks_defs:
            logger.warning(f"[DetEngine] No check definitions for {pattern_id}")
            return []

        correlation_fields = pattern_config.get('correlation_fields', ['source_host', 'username'])
        required_sources = pattern_config.get('required_sources', {})

        groups = self._group_anchors_by_key(anchor_events, correlation_fields)

        min_anchors = pattern_config.get('min_anchors_per_key', 1)
        if min_anchors > 1:
            before = len(groups)
            groups = {k: v for k, v in groups.items() if len(v) >= min_anchors}
            if before > len(groups):
                logger.info(
                    f"[DetEngine] {pattern_id}: pre-filtered {before} -> {len(groups)} "
                    f"keys (min_anchors={min_anchors})"
                )

        packages = []

        all_gap_results = self._consume_gap_findings(pattern_id)

        for corr_key, anchors in groups.items():
            if not anchors:
                continue

            representative = anchors[0]
            host = representative.get('source_host', '')

            all_ts = [a.get('timestamp') or a.get('timestamp_utc') for a in anchors]
            parsed = [self._parse_ts(t) for t in all_ts if t]
            parsed = [p for p in parsed if p is not None]
            if parsed:
                earliest = min(parsed)
                latest = max(parsed)
                half = timedelta(minutes=time_window_minutes / 2)
                window_start = earliest - half
                window_end = latest + half
            else:
                ts = representative.get('timestamp') or representative.get('timestamp_utc')
                window_start, window_end = self._compute_window(ts, time_window_minutes)

            coverage = self._check_coverage(host, window_start, window_end, required_sources)

            params = self._build_query_params(
                representative, window_start, window_end,
                all_anchors=anchors
            )

            scoped_gap = self._scope_gap_results(all_gap_results, params)

            check_results = self._run_checks(
                checks_defs, params, coverage, scoped_gap
            )

            bursts = self._detect_bursts(pattern_id, params)
            sequences = self._validate_sequences(pattern_id, params)

            det_score, max_score = self._compute_score(check_results, bursts, sequences)

            pkg = EvidencePackage(
                anchor=self._sanitize_anchor(representative),
                pattern_id=pattern_id,
                pattern_name=pattern_config.get('name', pattern_id),
                correlation_key=corr_key,
                checks=check_results,
                coverage=coverage,
                bursts=bursts,
                sequences=sequences,
                gap_inputs=[],
                deterministic_score=det_score,
                max_possible_score=max_score,
                mitre_techniques=pattern_config.get('mitre_techniques', []),
            )

            if scoped_gap:
                pkg.gap_inputs = [
                    {'finding_type': cr.detail.split('(')[1].rstrip('):') if '(' in cr.detail else '',
                     'mapped_check': cr.check_id, 'status': cr.status}
                    for cr in check_results if cr.source == 'gap_detector'
                ]

            packages.append(pkg)

        spread_config = get_spread_config(pattern_id)
        if spread_config and len(packages) >= 2:
            self._evaluate_spread(packages, spread_config)

        elapsed = int((time.time() - start_time) * 1000)
        logger.info(
            f"[DetEngine] {pattern_id}: {len(packages)} evidence packages "
            f"in {elapsed}ms"
        )
        return packages

    # -----------------------------------------------------------------
    # Anchor grouping
    # -----------------------------------------------------------------

    def _group_anchors_by_key(
        self, anchors: List[Dict], correlation_fields: List[str]
    ) -> Dict[str, List[Dict]]:
        groups: Dict[str, List[Dict]] = {}
        for anchor in anchors:
            parts = [str(anchor.get(f, '')) for f in correlation_fields]
            key = '|'.join(parts)
            groups.setdefault(key, []).append(anchor)
        return groups

    def _compute_window(self, ts, window_minutes: int):
        parsed = self._parse_ts(ts)
        if parsed is None:
            parsed = datetime.utcnow()
        half = timedelta(minutes=window_minutes / 2)
        return parsed - half, parsed + half

    @staticmethod
    def _parse_ts(ts) -> Optional[datetime]:
        """Parse a timestamp value into a datetime, returning None on failure."""
        if isinstance(ts, datetime):
            return ts
        if isinstance(ts, str):
            for fmt in ('%Y-%m-%d %H:%M:%S.%f', '%Y-%m-%d %H:%M:%S',
                        '%Y-%m-%dT%H:%M:%S.%f', '%Y-%m-%dT%H:%M:%S'):
                try:
                    return datetime.strptime(ts, fmt)
                except ValueError:
                    continue
        return None

    # -----------------------------------------------------------------
    # Coverage assessment
    # -----------------------------------------------------------------

    def _check_coverage(
        self, host: str, window_start: datetime, window_end: datetime,
        required_sources: Dict[str, str]
    ) -> CoverageAssessment:
        assessment = CoverageAssessment(
            host=host,
            window_start=window_start.isoformat() if window_start else None,
            window_end=window_end.isoformat() if window_end else None,
        )
        if not host:
            assessment.coverage_status = 'unknown'
            return assessment

        try:
            client = self._get_ch()
            result = client.query(
                "SELECT channel, count() as cnt, "
                "  min(timestamp) as earliest, max(timestamp) as latest "
                "FROM events "
                "WHERE case_id = {case_id:UInt32} "
                "AND source_host = {host:String} "
                "AND timestamp BETWEEN {ws:DateTime64} AND {we:DateTime64} "
                "AND (noise_matched = false OR noise_matched IS NULL) "
                "GROUP BY channel",
                parameters={
                    'case_id': self.case_id,
                    'host': host,
                    'ws': window_start,
                    'we': window_end,
                }
            )
            rows = result.result_rows
            total_events = 0
            present = []
            earliest_global = None
            latest_global = None

            for channel, cnt, earliest, latest in rows:
                ch_name = str(channel).strip()
                if ch_name:
                    present.append(ch_name)
                total_events += cnt
                if earliest_global is None or earliest < earliest_global:
                    earliest_global = earliest
                if latest_global is None or latest > latest_global:
                    latest_global = latest

            assessment.event_count = total_events
            assessment.present_sources = present
            if earliest_global:
                assessment.earliest_event = str(earliest_global)
            if latest_global:
                assessment.latest_event = str(latest_global)

            missing = []
            for src, criticality in required_sources.items():
                matched = any(src.lower() in p.lower() for p in present)
                if not matched:
                    missing.append(src)
            assessment.missing_sources = missing

            if 'Sysmon' in required_sources and 'Sysmon' in missing:
                sysmon_crit = required_sources['Sysmon']
                if sysmon_crit == 'critical':
                    assessment.sysmon_fp_warning = (
                        'Sysmon data not available. This pattern relies on process-level '
                        'telemetry for accurate detection. Without it, Security log events '
                        'alone may produce false positives. Findings should be validated '
                        'with endpoint evidence.'
                    )
                elif sysmon_crit in ('high', 'supplementary'):
                    assessment.sysmon_fp_warning = (
                        'Sysmon data not available. Some checks lack process-level context '
                        'which increases false positive risk. Corroborate with other '
                        'artifact sources before confirming.'
                    )

            if total_events == 0:
                assessment.coverage_status = 'none'
                assessment.coverage_score = 0.0
            elif total_events < 10:
                assessment.coverage_status = 'sparse'
                assessment.coverage_score = 20.0
            elif missing and any(required_sources.get(m) == 'critical' for m in missing):
                assessment.coverage_status = 'partial'
                assessment.coverage_score = 40.0
            elif missing:
                assessment.coverage_status = 'partial'
                assessment.coverage_score = 70.0
            else:
                assessment.coverage_status = 'full'
                assessment.coverage_score = min(100.0, 50.0 + (total_events / 20.0))

        except Exception as e:
            logger.warning(f"[DetEngine] Coverage check failed for {host}: {e}")
            assessment.coverage_status = 'unknown'
            assessment.coverage_score = 50.0

        return assessment

    # -----------------------------------------------------------------
    # Check execution
    # -----------------------------------------------------------------

    def _build_query_params(self, anchor: Dict, window_start: datetime,
                            window_end: datetime,
                            all_anchors: List[Dict] = None) -> Dict[str, Any]:
        ts = anchor.get('timestamp') or anchor.get('timestamp_utc')
        if isinstance(ts, str):
            for fmt in ('%Y-%m-%d %H:%M:%S.%f', '%Y-%m-%d %H:%M:%S',
                        '%Y-%m-%dT%H:%M:%S.%f', '%Y-%m-%dT%H:%M:%S'):
                try:
                    ts = datetime.strptime(ts, fmt)
                    break
                except ValueError:
                    continue
        combined_search = anchor.get('search_summary', '') or ''
        if all_anchors and len(all_anchors) > 1:
            parts = []
            budget = 8000
            for a in all_anchors:
                p = a.get('search_summary', '') or ''
                if not p:
                    continue
                if len(p) > budget:
                    break
                parts.append(p)
                budget -= len(p)
            combined_search = ' ||| '.join(parts) if parts else combined_search
        elif len(combined_search) > 8000:
            combined_search = combined_search[:8000]
        return {
            'case_id': self.case_id,
            'anchor_ts': ts,
            'window_start': window_start,
            'window_end': window_end,
            'event_id': anchor.get('event_id', ''),
            'username': anchor.get('username', ''),
            'source_host': anchor.get('source_host', ''),
            'target_host': anchor.get('target_host', ''),
            'src_ip': anchor.get('src_ip', ''),
            'dst_ip': anchor.get('dst_ip', ''),
            'process_name': anchor.get('process_name', ''),
            'command_line': anchor.get('command_line', ''),
            'search_summary': combined_search,
            'source_image': anchor.get('source_image', ''),
            'target_image': anchor.get('target_image', ''),
            'parent_image': anchor.get('parent_image', ''),
        }

    def _run_checks(
        self, check_defs: List[CheckDefinition],
        params: Dict[str, Any],
        coverage: CoverageAssessment,
        gap_results: List[CheckResult],
    ) -> List[CheckResult]:
        results = []
        gap_by_id = {cr.check_id: cr for cr in gap_results}

        for cdef in check_defs:
            if cdef.id in gap_by_id:
                gr = gap_by_id[cdef.id]
                gr.weight = cdef.weight
                if gr.status == 'PASS':
                    gr.contribution = float(cdef.weight)
                elif gr.status == 'INCONCLUSIVE':
                    gr.contribution = float(cdef.weight) * INCONCLUSIVE_WEIGHT_FRACTION
                else:
                    gr.contribution = 0.0
                results.append(gr)
                continue

            if cdef.check_type == 'anchor_match':
                results.append(CheckResult(
                    check_id=cdef.id, status='PASS', weight=cdef.weight,
                    contribution=float(cdef.weight),
                    detail=self._format_anchor_detail(params),
                    source='anchor_match',
                ))
                continue

            if cdef.check_type == 'field_match':
                result = self._evaluate_field_match(cdef, params)
                results.append(result)
                continue

            if cdef.check_type in ('absence_with_coverage',):
                result = self._evaluate_absence(cdef, params, coverage)
                results.append(result)
                continue

            if cdef.check_type in ('threshold', 'graduated'):
                result = self._evaluate_query_check(cdef, params, coverage)
                results.append(result)
                continue

            if cdef.check_type == 'burst':
                results.append(CheckResult(
                    check_id=cdef.id, status='FAIL', weight=cdef.weight,
                    contribution=0.0, detail='Evaluated via burst engine',
                    source='burst_engine',
                ))
                continue

            results.append(CheckResult(
                check_id=cdef.id, status='FAIL', weight=cdef.weight,
                contribution=0.0, detail=f'Unhandled check_type: {cdef.check_type}',
                source='unknown',
            ))

        cdef_by_id = {cd.id: cd for cd in check_defs}
        for r in results:
            if not r.name and r.check_id in cdef_by_id:
                r.name = cdef_by_id[r.check_id].name

        return results

    def _evaluate_absence(
        self, cdef: CheckDefinition, params: Dict, coverage: CoverageAssessment
    ) -> CheckResult:
        if coverage.coverage_status in ('none', 'sparse'):
            return CheckResult(
                check_id=cdef.id, status='INCONCLUSIVE', weight=cdef.weight,
                contribution=float(cdef.weight) * INCONCLUSIVE_WEIGHT_FRACTION,
                detail=f"Insufficient log coverage ({coverage.coverage_status}, "
                       f"{coverage.event_count} events in window)",
                source='coverage',
            )

        if cdef.required_sources:
            for src, crit in cdef.required_sources.items():
                if crit == 'critical' and src in coverage.missing_sources:
                    return CheckResult(
                        check_id=cdef.id, status='INCONCLUSIVE', weight=cdef.weight,
                        contribution=float(cdef.weight) * INCONCLUSIVE_WEIGHT_FRACTION,
                        detail=f"Missing critical source: {src}",
                        source='coverage',
                    )

        try:
            client = self._get_ch()
            filtered = self._filter_params(cdef.query_template, params)
            result = client.query(cdef.query_template, parameters=filtered)
            value = result.result_rows[0][0] if result.result_rows else None

            if value is None:
                value = 0

            passed = self._eval_condition(cdef.pass_condition, value)
            return CheckResult(
                check_id=cdef.id,
                status='PASS' if passed else 'FAIL',
                weight=cdef.weight,
                contribution=float(cdef.weight) if passed else 0.0,
                detail=f"Query returned {value} (condition: {cdef.pass_condition})",
                source='clickhouse',
            )
        except Exception as e:
            logger.warning(f"[DetEngine] Absence check {cdef.id} failed: {e}")
            return CheckResult(
                check_id=cdef.id, status='INCONCLUSIVE', weight=cdef.weight,
                contribution=float(cdef.weight) * INCONCLUSIVE_WEIGHT_FRACTION,
                detail=f"Query error: {str(e)[:100]}",
                source='error',
            )

    def _evaluate_query_check(self, cdef: CheckDefinition, params: Dict,
                              coverage: CoverageAssessment = None) -> CheckResult:
        if cdef.required_sources and coverage:
            for src, crit in cdef.required_sources.items():
                if crit == 'critical' and src in (coverage.missing_sources or []):
                    return CheckResult(
                        check_id=cdef.id, status='INCONCLUSIVE', weight=cdef.weight,
                        contribution=float(cdef.weight) * INCONCLUSIVE_WEIGHT_FRACTION,
                        detail=f"Missing critical source: {src}",
                        source='coverage',
                    )
        try:
            tmpl = cdef.query_template
            ip_fields = {'src_ip', 'dst_ip'}
            for ip_field in ip_fields:
                if f'{{{ip_field}:' in tmpl and not params.get(ip_field):
                    return CheckResult(
                        check_id=cdef.id, status='INCONCLUSIVE',
                        weight=cdef.weight,
                        contribution=float(cdef.weight) * INCONCLUSIVE_WEIGHT_FRACTION,
                        detail=f"No {ip_field} available on anchor event",
                        source='skip',
                    )
            client = self._get_ch()
            filtered = self._filter_params(tmpl, params)
            result = client.query(tmpl, parameters=filtered)
            value = result.result_rows[0][0] if result.result_rows else 0
            if value is None:
                value = 0

            if cdef.check_type == 'graduated' and cdef.tiers:
                contribution = self._graduated_score(cdef.weight, value, cdef.tiers)
                passed = contribution > 0
                return CheckResult(
                    check_id=cdef.id,
                    status='PASS' if passed else 'FAIL',
                    weight=cdef.weight,
                    contribution=contribution,
                    detail=f"Value={value}, graduated contribution={contribution:.1f}",
                    source='clickhouse',
                )

            passed = self._eval_condition(cdef.pass_condition, value)
            return CheckResult(
                check_id=cdef.id,
                status='PASS' if passed else 'FAIL',
                weight=cdef.weight,
                contribution=float(cdef.weight) if passed else 0.0,
                detail=f"Query returned {value} (condition: {cdef.pass_condition})",
                source='clickhouse',
            )
        except Exception as e:
            logger.warning(f"[DetEngine] Query check {cdef.id} failed: {e}")
            return CheckResult(
                check_id=cdef.id, status='FAIL', weight=cdef.weight,
                contribution=0.0,
                detail=f"Query error: {str(e)[:100]}",
                source='error',
            )

    def _evaluate_field_match(self, cdef: CheckDefinition, params: Dict) -> CheckResult:
        check_id = cdef.id

        if 'off_hours' in check_id:
            ts = params.get('anchor_ts')
            if isinstance(ts, datetime):
                hour = ts.hour
                is_off_hours = hour < 7 or hour >= 19
                return CheckResult(
                    check_id=cdef.id,
                    status='PASS' if is_off_hours else 'FAIL',
                    weight=cdef.weight,
                    contribution=float(cdef.weight) if is_off_hours else 0.0,
                    detail=f"Hour={hour} ({'off-hours' if is_off_hours else 'business hours'})",
                    source='field_match',
                )

        if 'not_machine_account' in check_id or 'not_dc_account' in check_id or 'not_service_account' in check_id:
            username = params.get('username', '')
            upper = username.upper()
            is_machine = (username.endswith('$')
                          or upper.startswith('NT AUTHORITY\\')
                          or upper in ('SYSTEM', 'LOCAL SERVICE', 'NETWORK SERVICE'))
            passed = not is_machine
            return CheckResult(
                check_id=cdef.id,
                status='PASS' if passed else 'FAIL',
                weight=cdef.weight,
                contribution=float(cdef.weight) if passed else 0.0,
                detail=f"username={username} ({'machine/system account' if is_machine else 'user account'})",
                source='field_match',
            )

        if 'not_local_ip' in check_id:
            src = params.get('src_ip', '')
            if not src or src in ('-', 'None', ''):
                return CheckResult(
                    check_id=cdef.id,
                    status='INCONCLUSIVE', weight=cdef.weight,
                    contribution=float(cdef.weight) * INCONCLUSIVE_WEIGHT_FRACTION,
                    detail=f"src_ip={src!r} (no IP recorded)",
                    source='field_match',
                )
            is_local = (src in ('::1', '127.0.0.1')
                        or src.startswith('::ffff:127.')
                        or src.startswith('fe80:'))
            passed = not is_local
            return CheckResult(
                check_id=cdef.id,
                status='PASS' if passed else 'FAIL',
                weight=cdef.weight,
                contribution=float(cdef.weight) if passed else 0.0,
                detail=f"src_ip={src} ({'local/loopback' if is_local else 'remote'})",
                source='field_match',
            )

        if 'not_dc_host' in check_id:
            host = params.get('source_host', '').lower()
            likely_dc = any(x in host for x in ['dc', 'domain', 'ad-'])
            passed = not likely_dc
            return CheckResult(
                check_id=cdef.id,
                status='PASS' if passed else 'FAIL',
                weight=cdef.weight,
                contribution=float(cdef.weight) if passed else 0.0,
                detail=f"host={host} ({'likely DC' if likely_dc else 'not a DC'})",
                source='field_match',
            )

        if 'from_workstation' in check_id or 'unusual_source' in check_id:
            host = params.get('source_host', '').lower()
            is_server = any(x in host for x in ['srv', 'server', 'dc', 'sql', 'web', 'app'])
            passed = not is_server
            return CheckResult(
                check_id=cdef.id,
                status='PASS' if passed else 'FAIL',
                weight=cdef.weight,
                contribution=float(cdef.weight) if passed else 0.0,
                detail=f"host={host} ({'server' if is_server else 'workstation'})",
                source='field_match',
            )

        if 'non_admin' in check_id:
            username = params.get('username', '').lower()
            is_admin = any(x in username for x in ['admin', 'administrator', 'system'])
            passed = not is_admin
            return CheckResult(
                check_id=cdef.id,
                status='PASS' if passed else 'FAIL',
                weight=cdef.weight,
                contribution=float(cdef.weight) if passed else 0.0,
                detail=f"username={username} ({'admin' if is_admin else 'non-admin'})",
                source='field_match',
            )

        if check_id == 'psexec_suspicious_service':
            search_text = (params.get('search_summary', '') or '').lower()
            known_tools = ['psexesvc', 'csexec', 'paexec', 'remcom', 'xcmd']
            found = [t for t in known_tools if t in search_text]
            if found:
                return CheckResult(
                    check_id=cdef.id, status='PASS', weight=cdef.weight,
                    contribution=float(cdef.weight),
                    detail=f"Known remote execution service: {', '.join(found)}",
                    source='field_match',
                )
            import re as _re
            svc_match = _re.search(r'(?:service\s*name|servicename)[:\s]+(\S+)', search_text, _re.IGNORECASE)
            if svc_match:
                svc_name = svc_match.group(1).strip().rstrip(',')
                is_suspicious = (
                    len(svc_name) <= 8
                    and not any(w in svc_name for w in [
                        'windows', 'update', 'defender', 'print', 'spool',
                        'network', 'audio', 'wmi', 'bits', 'theme',
                    ])
                    and any(c.isdigit() for c in svc_name)
                )
                if is_suspicious:
                    return CheckResult(
                        check_id=cdef.id, status='PASS', weight=cdef.weight,
                        contribution=float(cdef.weight),
                        detail=f"Suspicious service name pattern: {svc_name}",
                        source='field_match',
                    )
            return CheckResult(
                check_id=cdef.id, status='INCONCLUSIVE', weight=cdef.weight,
                contribution=float(cdef.weight) * INCONCLUSIVE_WEIGHT_FRACTION,
                detail="Service name could not be determined or appears benign",
                source='field_match',
            )

        if 'suspicious_service' in check_id or 'sensitive_service' in check_id:
            search_text = (params.get('search_summary', '') or '').lower()
            sensitive_services = [
                'krbtgt', 'cifs/', 'http/', 'ldap/', 'mssql/', 'host/',
                'rpcss', 'dns/', 'wsman/', 'exchange',
            ]
            found = [s for s in sensitive_services if s in search_text]
            if found:
                return CheckResult(
                    check_id=cdef.id, status='PASS', weight=cdef.weight,
                    contribution=float(cdef.weight),
                    detail=f"Sensitive service indicators: {', '.join(found)}",
                    source='field_match',
                )
            return CheckResult(
                check_id=cdef.id, status='INCONCLUSIVE', weight=cdef.weight,
                contribution=float(cdef.weight) * INCONCLUSIVE_WEIGHT_FRACTION,
                detail="Service sensitivity could not be determined from available data",
                source='field_match',
            )

        if check_id == 'lsass_vm_read':
            search_text = (params.get('search_summary', '') or '').lower()
            anchor_event_id = params.get('event_id', '')
            if anchor_event_id == '8' or 'createremotethread' in search_text:
                return CheckResult(
                    check_id=cdef.id,
                    status='PASS',
                    weight=cdef.weight,
                    contribution=float(cdef.weight),
                    detail="CreateRemoteThread into lsass.exe (stronger than VM_READ)",
                    source='field_match',
                )
            aggressive_masks = ['0x143a', '0x1038', '0x1410', '0x1fffff', '0x1f1fff', '0x1f0fff']
            readonly_masks = ['0x1010', '0x0810']
            security_access_codes = ['%%4484', '%%4480', '%%4481', '%%4482', '%%4483',
                                     '%%1537', '%%1538', '%%1539', '%%1540', '%%1541']
            found_aggressive = [m for m in aggressive_masks if m in search_text]
            found_readonly = [m for m in readonly_masks if m in search_text]
            found_security = [c for c in security_access_codes if c in search_text]
            if found_aggressive:
                fraction = 1.0
                detail = f"Aggressive GrantedAccess: {', '.join(found_aggressive)} (VM_WRITE/CREATE_THREAD/ALL_ACCESS)"
            elif found_security:
                fraction = 0.8
                detail = f"Security AccessList codes: {', '.join(found_security)}"
            elif found_readonly:
                fraction = 0.6
                detail = f"Read-only GrantedAccess: {', '.join(found_readonly)} (PROCESS_VM_READ only)"
            else:
                fraction = 0.0
                detail = "No PROCESS_VM_READ access mask found"
            passed = fraction > 0
            return CheckResult(
                check_id=cdef.id,
                status='PASS' if passed else 'FAIL',
                weight=cdef.weight,
                contribution=cdef.weight * fraction,
                detail=detail,
                source='field_match',
            )

        if check_id == 'lsass_silent_process_exit':
            anchor_event_id = params.get('event_id', '')
            search_text = (params.get('search_summary', '') or '').lower()
            is_spe = (anchor_event_id == '3001'
                      and 'lsass' in search_text
                      and 'crossprocess' in search_text.replace('_', '').replace(' ', ''))
            if is_spe:
                tool_hint = ''
                for token in search_text.split():
                    if 'silentprocessexit' in token.lower() or 'lsasssilent' in token.lower():
                        tool_hint = token
                        break
                detail = "Event 3001 cross-process termination of lsass.exe (Silent Process Exit dump)"
                if tool_hint:
                    detail += f" via {tool_hint}"
            else:
                detail = "Not a Silent Process Exit event"
            return CheckResult(
                check_id=cdef.id,
                status='PASS' if is_spe else 'FAIL',
                weight=cdef.weight,
                contribution=float(cdef.weight) if is_spe else 0.0,
                detail=detail,
                source='field_match',
            )

        if check_id == 'lsass_calltrace_short':
            search_text = (params.get('search_summary', '') or '')
            import re
            ct_match = re.search(r'calltrace:\s*(\S+)', search_text, re.IGNORECASE)
            if ct_match:
                calltrace = ct_match.group(1)
                frames = [f for f in calltrace.split('|') if f.strip()]
                is_short = len(frames) <= 3
                return CheckResult(
                    check_id=cdef.id,
                    status='PASS' if is_short else 'FAIL',
                    weight=cdef.weight,
                    contribution=float(cdef.weight) if is_short else 0.0,
                    detail=f"CallTrace has {len(frames)} frame(s) — direct API call pattern" if is_short
                           else f"CallTrace has {len(frames)} frames — normal call depth",
                    source='field_match',
                )
            return CheckResult(
                check_id=cdef.id,
                status='INCONCLUSIVE',
                weight=cdef.weight,
                contribution=cdef.weight * 0.3,
                detail="No CallTrace data available (non-Sysmon event or data truncated)",
                source='field_match',
            )

        if check_id == 'lsass_suspicious_process':
            search_text = (params.get('search_summary', '') or '').lower()
            process_name = (params.get('process_name', '') or '').lower()
            combined = f"{search_text} {process_name}"
            suspicious_tools = ['mimikatz', 'procdump', 'comsvcs', 'lsassy', 'pypykatz',
                                'crackmapexec', 'secretsdump', 'lazagne', 'handlekatz',
                                'dumpert', 'outflank', 'andrewspecial', 'nanodump',
                                'sharpkatz', 'safetykatz', 'memdump', 'taskmanager',
                                'cscript', 'wscript', 'rdrleakdiag', 'sqldumper',
                                'tttracer', 'createdump', 'werfault',
                                'ppldump', 'pplkiller', 'pplblade', 'pplfault', 'pplmedic',
                                'physmem2profit', 'dcomexec', 'wmiexec', 'atexec',
                                'silentprocessexit', 'lsasssilentprocessexit',
                                'powershell', 'pwsh']
            found = [t for t in suspicious_tools if t in combined]
            passed = len(found) > 0
            return CheckResult(
                check_id=cdef.id,
                status='PASS' if passed else 'FAIL',
                weight=cdef.weight,
                contribution=float(cdef.weight) if passed else 0.0,
                detail=f"Suspicious tool(s): {', '.join(found)}" if passed else "No known credential dump tools detected",
                source='field_match',
            )

        if check_id == 'inject_suspicious_parent':
            source_image = (params.get('source_image', '') or '').lower()
            parent_image = (params.get('parent_image', '') or '').lower()
            search_text = (params.get('search_summary', '') or '').lower()
            combined = f"{source_image} {parent_image} {search_text}"
            suspicious_injectors = [
                'powershell', 'pwsh', 'cscript', 'wscript', 'mshta', 'rundll32',
                'regsvr32', 'msbuild', 'installutil', 'regasm', 'regsvcs',
                'python', 'ruby', 'perl', 'java', 'cmd.exe',
                'mimikatz', 'cobalt', 'meterpreter', 'inject', 'hollow',
                'dumpert', 'outflank', 'andrewspecial', 'nanodump',
                'frida', 'sharphound', 'rubeus',
                'procdump', 'rdrleakdiag', 'sqldumper', 'tttracer', 'createdump',
                'ppldump', 'pplkiller', 'pplblade', 'pplfault', 'pplmedic',
            ]
            benign_sources = ['csrss.exe', 'services.exe', 'svchost.exe', 'smss.exe', 'wininit.exe']
            source_proc = source_image or search_text
            is_benign = any(source_proc.endswith(b) for b in benign_sources)
            found = [t for t in suspicious_injectors if t in combined]
            passed = len(found) > 0 and not is_benign
            detail_proc = source_image.rsplit('\\', 1)[-1] if source_image else 'unknown'
            return CheckResult(
                check_id=cdef.id,
                status='PASS' if passed else 'FAIL',
                weight=cdef.weight,
                contribution=float(cdef.weight) if passed else 0.0,
                detail=f"Suspicious injector: {', '.join(found)} (source={detail_proc})" if passed
                       else (f"Benign system process ({detail_proc})" if is_benign
                             else f"No suspicious source process detected ({detail_proc})"),
                source='field_match',
            )

        if check_id == 'inject_target_process':
            target_image = (params.get('target_image', '') or '').lower()
            search_text = (params.get('search_summary', '') or '').lower()
            sensitive_targets = [
                'lsass.exe', 'csrss.exe', 'winlogon.exe', 'svchost.exe',
                'explorer.exe', 'spoolsv.exe', 'wininit.exe', 'services.exe',
                'smss.exe', 'taskhost', 'dwm.exe', 'conhost.exe',
                # RMM tools — credential-storing targets (noise rules filter these when enabled)
                'teamviewer.exe', 'anydesk.exe', 'mstsc.exe',
                'logmein.exe', 'screenconnect.windowsclient.exe',
                # Browsers — credential/session targets
                'chrome.exe', 'firefox.exe', 'msedge.exe', 'iexplore.exe',
            ]
            found = [t for t in sensitive_targets if t in target_image]
            if not found:
                found = [t for t in sensitive_targets if t in search_text]
            passed = len(found) > 0
            detail_proc = target_image.rsplit('\\', 1)[-1] if target_image else 'unknown'
            return CheckResult(
                check_id=cdef.id,
                status='PASS' if passed else 'FAIL',
                weight=cdef.weight,
                contribution=float(cdef.weight) if passed else 0.0,
                detail=f"Sensitive target: {', '.join(found)} (target={detail_proc})" if passed
                       else f"Target is not a known sensitive process ({detail_proc})",
                source='field_match',
            )

        if check_id == 'uac_non_explorer_parent':
            parent_image = (params.get('parent_image', '') or '').lower()
            search_text = (params.get('search_summary', '') or '').lower()
            combined = f"{parent_image} {search_text}"
            is_explorer = 'explorer.exe' in combined
            passed = not is_explorer and len(combined.strip()) > 0
            return CheckResult(
                check_id=cdef.id,
                status='PASS' if passed else 'FAIL',
                weight=cdef.weight,
                contribution=float(cdef.weight) if passed else 0.0,
                detail="Auto-elevated binary not launched by explorer.exe" if passed
                       else "Launched by explorer.exe (normal UAC flow)",
                source='field_match',
            )

        if check_id == 'cert_non_standard_process':
            process_name = (params.get('process_name', '') or '').lower()
            search_text = (params.get('search_summary', '') or '').lower()
            combined = f"{process_name} {search_text}"
            standard_cert_procs = ['svchost.exe', 'certutil.exe', 'certmgr.exe',
                                   'mmc.exe', 'gpupdate.exe', 'dsregcmd.exe']
            is_standard = any(p in combined for p in standard_cert_procs)
            passed = not is_standard and len(combined.strip()) > 0
            return CheckResult(
                check_id=cdef.id,
                status='PASS' if passed else 'FAIL',
                weight=cdef.weight,
                contribution=float(cdef.weight) if passed else 0.0,
                detail="Non-standard process modifying certificate store" if passed
                       else "Standard certificate management process",
                source='field_match',
            )

        if check_id == 'discovery_suspicious_parent':
            parent_image = (params.get('parent_image', '') or '').lower()
            search_text = (params.get('search_summary', '') or '').lower()
            combined = f"{parent_image} {search_text}"
            suspicious_parents = ['powershell', 'pwsh', 'wmiprvse', 'mshta', 'wscript',
                                  'cscript', 'cmd.exe', 'python', 'ruby', 'perl']
            found = [p for p in suspicious_parents if p in combined]
            passed = len(found) > 0
            return CheckResult(
                check_id=cdef.id,
                status='PASS' if passed else 'FAIL',
                weight=cdef.weight,
                contribution=float(cdef.weight) if passed else 0.0,
                detail=f"Suspicious parent: {', '.join(found)}" if passed
                       else "No suspicious parent process",
                source='field_match',
            )

        if check_id == 'discovery_priv_enum':
            command_line = (params.get('command_line', '') or '').lower()
            search_text = (params.get('search_summary', '') or '').lower()
            combined = f"{command_line} {search_text}"
            priv_flags = ['/all', '/priv', '/groups', '/user', '/domain']
            found = [f for f in priv_flags if f in combined]
            passed = len(found) > 0
            return CheckResult(
                check_id=cdef.id,
                status='PASS' if passed else 'FAIL',
                weight=cdef.weight,
                contribution=float(cdef.weight) if passed else 0.0,
                detail=f"Privilege/group enumeration flags: {', '.join(found)}" if passed
                       else "No privilege enumeration flags detected",
                source='field_match',
            )

        if check_id in ('regrun_unusual_path', 'svcpers_unusual_path'):
            return self._evaluate_path_suspicion(cdef, params)

        if check_id in ('schtask_system_priv', 'svcpers_localsystem'):
            search_text = (params.get('search_summary', '') or '').lower()
            system_indicators = [
                'localsystem', 'local system', 'nt authority\\system',
                'nt authority\\\\system', 's-1-5-18',
            ]
            found = [s for s in system_indicators if s in search_text]
            passed = len(found) > 0
            return CheckResult(
                check_id=cdef.id,
                status='PASS' if passed else 'FAIL',
                weight=cdef.weight,
                contribution=float(cdef.weight) if passed else 0.0,
                detail=f"Runs as SYSTEM ({', '.join(found)})" if passed
                       else "Does not run as SYSTEM",
                source='field_match',
            )

        if check_id == 'schtask_script_action':
            search_text = (params.get('search_summary', '') or '').lower()
            command_line = (params.get('command_line', '') or '').lower()
            combined = f"{search_text} {command_line}"
            script_indicators = [
                'powershell', 'pwsh', 'cmd.exe', 'cmd /c', 'wscript', 'cscript',
                'mshta', 'python', 'perl', 'ruby',
                '.ps1', '.bat', '.cmd', '.vbs', '.vbe', '.js', '.jse', '.wsf', '.wsh',
            ]
            found = [s for s in script_indicators if s in combined]
            passed = len(found) > 0
            return CheckResult(
                check_id=cdef.id,
                status='PASS' if passed else 'FAIL',
                weight=cdef.weight,
                contribution=float(cdef.weight) if passed else 0.0,
                detail=f"Script/suspicious action: {', '.join(found)}" if passed
                       else "Task action does not appear to be a script",
                source='field_match',
            )

        if check_id == 'svcpers_auto_start':
            search_text = (params.get('search_summary', '') or '').lower()
            auto_indicators = [
                'auto start', 'service_auto_start', 'start = 2',
                'start type: auto', 'starttype: automatic', 'delayed auto',
            ]
            demand_indicators = [
                'demand start', 'service_demand_start', 'start = 3',
                'manual', 'disabled',
            ]
            found_auto = [s for s in auto_indicators if s in search_text]
            found_demand = [s for s in demand_indicators if s in search_text]
            if found_auto:
                return CheckResult(
                    check_id=cdef.id, status='PASS', weight=cdef.weight,
                    contribution=float(cdef.weight),
                    detail=f"Service auto-start: {', '.join(found_auto)}",
                    source='field_match',
                )
            if found_demand:
                return CheckResult(
                    check_id=cdef.id, status='FAIL', weight=cdef.weight,
                    contribution=0.0,
                    detail=f"Service not auto-start: {', '.join(found_demand)}",
                    source='field_match',
                )
            return CheckResult(
                check_id=cdef.id, status='INCONCLUSIVE', weight=cdef.weight,
                contribution=float(cdef.weight) * INCONCLUSIVE_WEIGHT_FRACTION,
                detail="Service start type could not be determined",
                source='field_match',
            )

        return CheckResult(
            check_id=cdef.id, status='FAIL', weight=cdef.weight,
            contribution=0.0,
            detail=f"Unhandled field_match: {check_id}",
            source='field_match',
        )

    def _evaluate_path_suspicion(self, cdef: CheckDefinition, params: Dict) -> CheckResult:
        """Shared path-analysis logic for regrun_unusual_path and svcpers_unusual_path."""
        search_text = (params.get('search_summary', '') or '').lower()
        command_line = (params.get('command_line', '') or '').lower()
        combined = f"{search_text} {command_line}"
        normal_dirs = [
            '\\program files\\', '\\program files (x86)\\',
            '\\windows\\system32\\', '\\windows\\syswow64\\',
            '\\windows\\', '\\microsoft\\',
        ]
        suspicious_dirs = [
            '\\temp\\', '\\tmp\\', '\\appdata\\local\\temp\\',
            '\\users\\public\\', '\\programdata\\',
            '\\appdata\\roaming\\', '\\downloads\\',
            '\\recycle', '\\perflogs\\',
        ]
        in_suspicious = any(d in combined for d in suspicious_dirs)
        in_normal = any(d in combined for d in normal_dirs)
        if in_suspicious:
            passed = True
            detail = "Binary path in suspicious location"
        elif in_normal:
            passed = False
            detail = "Binary path in standard location"
        elif combined.strip():
            passed = True
            detail = "Binary path not in standard OS directories"
        else:
            return CheckResult(
                check_id=cdef.id, status='INCONCLUSIVE', weight=cdef.weight,
                contribution=float(cdef.weight) * INCONCLUSIVE_WEIGHT_FRACTION,
                detail="No path data available for evaluation",
                source='field_match',
            )
        return CheckResult(
            check_id=cdef.id,
            status='PASS' if passed else 'FAIL',
            weight=cdef.weight,
            contribution=float(cdef.weight) if passed else 0.0,
            detail=detail,
            source='field_match',
        )

    # -----------------------------------------------------------------
    # Burst detection
    # -----------------------------------------------------------------

    def _detect_bursts(self, pattern_id: str, params: Dict) -> List[BurstResult]:
        config = get_burst_config(pattern_id)
        if not config:
            return []

        window_sec = config['window_seconds']
        min_events = config['min_events']
        event_ids = config['event_ids']

        event_id_list = ', '.join(f"'{eid}'" for eid in event_ids)

        try:
            client = self._get_ch()
            result = client.query(
                f"SELECT "
                f"  username, source_host, src_ip, "
                f"  toStartOfInterval(timestamp, INTERVAL {window_sec} SECOND) as time_bucket, "
                f"  count() as events_in_bucket, "
                f"  uniqExact(event_id) as distinct_types, "
                f"  min(timestamp) as bucket_start, "
                f"  max(timestamp) as bucket_end, "
                f"  dateDiff('second', min(timestamp), max(timestamp)) as span "
                f"FROM events "
                f"WHERE case_id = {{case_id:UInt32}} "
                f"AND event_id IN ({event_id_list}) "
                f"AND (noise_matched = false OR noise_matched IS NULL) "
                f"AND timestamp BETWEEN {{window_start:DateTime64}} AND {{window_end:DateTime64}} "
                f"GROUP BY username, source_host, src_ip, time_bucket "
                f"HAVING events_in_bucket >= {min_events} "
                f"ORDER BY events_in_bucket DESC "
                f"LIMIT 20",
                parameters={
                    'case_id': params['case_id'],
                    'window_start': params['window_start'],
                    'window_end': params['window_end'],
                }
            )

            bursts = []
            for row in result.result_rows:
                bursts.append(BurstResult(
                    username=str(row[0]),
                    source_host=str(row[1]),
                    src_ip=str(row[2]),
                    events_in_bucket=int(row[4]),
                    distinct_event_types=int(row[5]),
                    span_seconds=int(row[8]) if len(row) > 8 and row[8] is not None else 0,
                    bucket_start=str(row[6]),
                    bucket_end=str(row[7]) if len(row) > 7 else str(row[6]),
                ))
            return bursts

        except Exception as e:
            logger.warning(f"[DetEngine] Burst detection failed for {pattern_id}: {e}")
            return []

    # -----------------------------------------------------------------
    # Sequence validation
    # -----------------------------------------------------------------

    def _validate_sequences(self, pattern_id: str, params: Dict) -> List[SequenceResult]:
        config = get_sequence_config(pattern_id)
        if not config:
            return []

        chain_name = config['chain']
        steps = config['steps']
        found_steps = []
        missing = []

        for step_def in steps:
            event_ids = step_def['event_id']
            if isinstance(event_ids, str):
                event_ids = [event_ids]
            label = step_def['label']
            max_offset = step_def.get('max_offset_seconds', 300)
            direction = step_def.get('direction', 'before_anchor')

            eid_list = ', '.join(f"'{e}'" for e in event_ids)

            if direction == 'before_anchor':
                time_clause = (
                    "AND timestamp BETWEEN {anchor_ts:DateTime64} - "
                    f"INTERVAL {max_offset} SECOND AND {{anchor_ts:DateTime64}}"
                )
            else:
                time_clause = (
                    "AND timestamp BETWEEN {anchor_ts:DateTime64} AND "
                    f"{{anchor_ts:DateTime64}} + INTERVAL {max_offset} SECOND"
                )

            cond_clauses = ''
            conditions = step_def.get('conditions', {})
            if 'logon_type' in conditions:
                types = conditions['logon_type']
                if isinstance(types, list):
                    cond_clauses += f"AND logon_type IN ({', '.join(str(t) for t in types)}) "
                else:
                    cond_clauses += f"AND logon_type = {types} "

            try:
                client = self._get_ch()
                seq_query = (
                    f"SELECT timestamp, event_id, username, source_host "
                    f"FROM events "
                    f"WHERE case_id = {{case_id:UInt32}} "
                    f"AND event_id IN ({eid_list}) "
                    f"AND source_host = {{source_host:String}} "
                    f"{time_clause} "
                    f"{cond_clauses}"
                    f"AND (noise_matched = false OR noise_matched IS NULL) "
                    f"ORDER BY timestamp DESC LIMIT 1"
                )
                result = client.query(
                    seq_query,
                    parameters=self._filter_params(seq_query, params)
                )
                if result.result_rows:
                    row = result.result_rows[0]
                    found_steps.append({
                        'label': label,
                        'timestamp': str(row[0]),
                        'event_id': str(row[1]),
                        'found': True,
                    })
                else:
                    missing.append(label)
                    found_steps.append({'label': label, 'found': False})
            except Exception as e:
                logger.warning(f"[DetEngine] Sequence step {label} failed: {e}")
                missing.append(label)
                found_steps.append({'label': label, 'found': False, 'error': str(e)[:80]})

        if not missing:
            status = 'complete'
        elif len(missing) < len(steps):
            status = 'partial'
        else:
            status = 'missing'

        return [SequenceResult(
            chain=chain_name,
            status=status,
            steps=found_steps,
            missing_steps=missing,
        )]

    # -----------------------------------------------------------------
    # Scoring
    # -----------------------------------------------------------------

    def _compute_score(
        self, checks: List[CheckResult],
        bursts: List[BurstResult],
        sequences: List[SequenceResult],
    ) -> Tuple[float, float]:
        score = sum(c.contribution for c in checks)

        max_possible = 0.0
        for c in checks:
            if c.status == 'INCONCLUSIVE':
                max_possible += c.weight * INCONCLUSIVE_WEIGHT_FRACTION
            else:
                max_possible += c.weight

        if bursts:
            score += min(10, len(bursts) * 3)
            max_possible += 10

        for seq in sequences:
            if seq.status == 'complete':
                score += 5
            elif seq.status == 'partial':
                score += 2
            max_possible += 5

        score = min(100, score)
        max_possible = min(100, max_possible)

        return round(score, 1), round(max_possible, 1)

    def _graduated_score(self, weight: int, value, tiers: List[Tuple[int, float]]) -> float:
        if value is None:
            return 0.0
        best_fraction = 0.0
        for threshold, fraction in sorted(tiers, key=lambda t: t[0]):
            if value >= threshold:
                best_fraction = fraction
        return round(weight * best_fraction, 1)

    def _eval_condition(self, condition: str, value) -> bool:
        if not condition:
            return value is not None and value > 0
        try:
            return eval(condition, {'result': value, '__builtins__': {}})
        except Exception:
            return False

    # -----------------------------------------------------------------
    # Gap detector consumption
    # -----------------------------------------------------------------

    def _consume_gap_findings(self, pattern_id: str) -> List[Tuple[Any, CheckResult]]:
        """Collect gap findings paired with their source finding for scoping."""
        all_results = []
        for finding in self.gap_findings:
            mapped_pid = get_gap_pattern_id(finding)
            if mapped_pid == pattern_id:
                for cr in map_gap_finding_to_check_results(finding):
                    all_results.append((finding, cr))
        return all_results

    def _scope_gap_results(
        self, all_gap: List[Tuple[Any, CheckResult]], params: Dict[str, Any]
    ) -> List[CheckResult]:
        """Filter gap results to only those relevant to the current correlation key.
        Matches on source_host from the gap finding's evidence/details against the
        current key's source_host. Falls back to include the result if no scoping
        metadata is available on the finding (fail-open)."""
        if not all_gap:
            return []

        key_host = (params.get('source_host', '') or '').lower()
        key_user = (params.get('username', '') or '').lower()
        scoped = []

        for finding, cr in all_gap:
            evidence = getattr(finding, 'evidence', None) or {}
            details = getattr(finding, 'details', None) or {}

            finding_host = str(
                evidence.get('source_host') or details.get('source_host')
                or evidence.get('target_host') or details.get('target_host')
                or ''
            ).lower()
            finding_user = str(
                evidence.get('username') or details.get('username') or ''
            ).lower()

            has_metadata = bool(finding_host or finding_user)
            if not has_metadata:
                scoped.append(cr)
                continue

            host_match = (not finding_host) or (not key_host) or (finding_host in key_host or key_host in finding_host)
            user_match = (not finding_user) or (not key_user) or (finding_user in key_user or key_user in finding_user)

            if host_match and user_match:
                scoped.append(cr)

        return scoped

    # -----------------------------------------------------------------
    # Cross-key spread assessment
    # -----------------------------------------------------------------

    def _evaluate_spread(
        self, packages: List[EvidencePackage], spread_config: Dict[str, Any]
    ) -> None:
        """Post-process packages to add cross-key spread scores.
        Groups packages by pivot_field and awards bonus points
        based on how many distinct targets the pivot value touched."""
        pivot_field = spread_config['pivot_field']
        weight = spread_config['weight']
        tiers = spread_config.get('tiers', [])
        target_field = spread_config.get('target_field', 'target_host')
        event_filter = spread_config.get('event_filter', '')

        pivot_groups: Dict[str, List[EvidencePackage]] = {}
        for pkg in packages:
            pivot_val = pkg.anchor.get(pivot_field, '')
            if not pivot_val:
                continue
            pivot_groups.setdefault(pivot_val, []).append(pkg)

        ch = self._get_ch()

        for pivot_val, group in pivot_groups.items():
            if len(group) < 2:
                continue

            timestamps = []
            for pkg in group:
                ts = pkg.anchor.get('timestamp') or pkg.anchor.get('timestamp_utc', '')
                if ts:
                    timestamps.append(str(ts))

            all_windows = []
            for pkg in group:
                if pkg.coverage:
                    if pkg.coverage.window_start:
                        all_windows.append(pkg.coverage.window_start)
                    if pkg.coverage.window_end:
                        all_windows.append(pkg.coverage.window_end)

            time_clause = ''
            spread_params = {
                'case_id': self.case_id,
                pivot_field: pivot_val,
            }
            if all_windows:
                spread_params['spread_ws'] = min(all_windows)
                spread_params['spread_we'] = max(all_windows)
                time_clause = "AND timestamp BETWEEN {spread_ws:DateTime64} AND {spread_we:DateTime64} "

            try:
                query = (
                    f"SELECT uniqExact({target_field}) AS target_count, "
                    f"uniqExact(username) AS user_count, "
                    f"min(timestamp) AS first_seen, "
                    f"max(timestamp) AS last_seen, "
                    f"dateDiff('minute', min(timestamp), max(timestamp)) AS span_minutes "
                    f"FROM events "
                    f"WHERE case_id = {{case_id:UInt32}} "
                    f"AND {pivot_field} = {{{pivot_field}:String}} "
                    f"AND {event_filter} "
                    f"{time_clause}"
                    f"AND (noise_matched = false OR noise_matched IS NULL)"
                )

                result = ch.query(query, parameters=spread_params)

                if not result.result_rows:
                    continue

                row = result.result_rows[0]
                target_count = int(row[0])
                user_count = int(row[1])
                first_seen = str(row[2])
                last_seen = str(row[3])
                span_minutes = int(row[4])

                contribution = self._graduated_score(weight, target_count, tiers)

                sibling_keys = [p.correlation_key for p in group]

                spread = SpreadAssessment(
                    pivot_field=pivot_field,
                    pivot_value=pivot_val,
                    total_targets=target_count,
                    total_users=user_count,
                    span_minutes=span_minutes,
                    first_seen=first_seen,
                    last_seen=last_seen,
                    sibling_keys=sibling_keys,
                    contribution=contribution,
                )

                for pkg in group:
                    pkg.spread = spread
                    pkg.deterministic_score = min(100, pkg.deterministic_score + contribution)
                    pkg.max_possible_score = min(100, pkg.max_possible_score + weight)

            except Exception as e:
                logger.warning(f"[DetEngine] Spread query failed for {pivot_field}={pivot_val}: {e}")

    # -----------------------------------------------------------------
    # Helpers
    # -----------------------------------------------------------------

    @staticmethod
    def _filter_params(template: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Return only the params actually referenced in the query template.
        Prevents sending oversized unused fields (like search_summary) to ClickHouse."""
        import re
        referenced = set(re.findall(r'\{(\w+):', template))
        return {k: v for k, v in params.items() if k in referenced}

    def _format_anchor_detail(self, params: Dict) -> str:
        parts = []
        for key in ('username', 'source_host', 'src_ip', 'target_host'):
            val = params.get(key)
            if val:
                parts.append(f"{key}={val}")
        return ', '.join(parts) if parts else 'anchor matched'

    def _sanitize_anchor(self, anchor: Dict) -> Dict[str, Any]:
        safe = {}
        for key in ('timestamp', 'timestamp_utc', 'event_id', 'username',
                     'source_host', 'target_host', 'src_ip', 'dst_ip',
                     'logon_type', 'auth_package', 'key_length',
                     'process_name', 'channel'):
            if key in anchor:
                val = anchor[key]
                if isinstance(val, datetime):
                    safe[key] = val.isoformat()
                else:
                    safe[key] = val
        return safe
