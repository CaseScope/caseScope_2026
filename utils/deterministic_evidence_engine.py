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
    SequenceResult, EvidencePackage,
    get_checks_for_pattern, get_burst_config, get_sequence_config,
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
        packages = []

        gap_check_results = self._consume_gap_findings(pattern_id)

        for corr_key, anchors in groups.items():
            if not anchors:
                continue

            representative = anchors[0]
            ts = representative.get('timestamp') or representative.get('timestamp_utc')
            host = representative.get('source_host', '')

            window_start, window_end = self._compute_window(ts, time_window_minutes)

            coverage = self._check_coverage(host, window_start, window_end, required_sources)

            params = self._build_query_params(
                representative, window_start, window_end
            )

            check_results = self._run_checks(
                checks_defs, params, coverage, gap_check_results
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
            )

            if gap_check_results:
                pkg.gap_inputs = [
                    {'finding_type': cr.detail.split('(')[1].rstrip('):') if '(' in cr.detail else '',
                     'mapped_check': cr.check_id, 'status': cr.status}
                    for cr in check_results if cr.source == 'gap_detector'
                ]

            packages.append(pkg)

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
        if isinstance(ts, str):
            for fmt in ('%Y-%m-%d %H:%M:%S.%f', '%Y-%m-%d %H:%M:%S', '%Y-%m-%dT%H:%M:%S.%f', '%Y-%m-%dT%H:%M:%S'):
                try:
                    ts = datetime.strptime(ts, fmt)
                    break
                except ValueError:
                    continue
        if not isinstance(ts, datetime):
            ts = datetime.utcnow()
        half = timedelta(minutes=window_minutes / 2)
        return ts - half, ts + half

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
                            window_end: datetime) -> Dict[str, Any]:
        ts = anchor.get('timestamp') or anchor.get('timestamp_utc')
        if isinstance(ts, str):
            for fmt in ('%Y-%m-%d %H:%M:%S.%f', '%Y-%m-%d %H:%M:%S',
                        '%Y-%m-%dT%H:%M:%S.%f', '%Y-%m-%dT%H:%M:%S'):
                try:
                    ts = datetime.strptime(ts, fmt)
                    break
                except ValueError:
                    continue
        return {
            'case_id': self.case_id,
            'anchor_ts': ts,
            'window_start': window_start,
            'window_end': window_end,
            'username': anchor.get('username', ''),
            'source_host': anchor.get('source_host', ''),
            'target_host': anchor.get('target_host', ''),
            'src_ip': anchor.get('src_ip', ''),
            'dst_ip': anchor.get('dst_ip', ''),
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
                result = self._evaluate_query_check(cdef, params)
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
            result = client.query(cdef.query_template, parameters=params)
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

    def _evaluate_query_check(self, cdef: CheckDefinition, params: Dict) -> CheckResult:
        try:
            client = self._get_ch()
            result = client.query(cdef.query_template, parameters=params)
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
                is_off_hours = hour < 6 or hour >= 22
                return CheckResult(
                    check_id=cdef.id,
                    status='PASS' if is_off_hours else 'FAIL',
                    weight=cdef.weight,
                    contribution=float(cdef.weight) if is_off_hours else 0.0,
                    detail=f"Hour={hour} ({'off-hours' if is_off_hours else 'business hours'})",
                    source='field_match',
                )

        if 'not_dc_account' in check_id or 'not_service_account' in check_id:
            username = params.get('username', '')
            is_machine = username.endswith('$')
            passed = not is_machine
            return CheckResult(
                check_id=cdef.id,
                status='PASS' if passed else 'FAIL',
                weight=cdef.weight,
                contribution=float(cdef.weight) if passed else 0.0,
                detail=f"username={username} ({'machine account' if is_machine else 'user account'})",
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

        if 'suspicious_service' in check_id or 'sensitive_service' in check_id:
            return CheckResult(
                check_id=cdef.id, status='FAIL', weight=cdef.weight,
                contribution=0.0,
                detail="Field match not evaluated (requires event-level data)",
                source='field_match',
            )

        return CheckResult(
            check_id=cdef.id, status='FAIL', weight=cdef.weight,
            contribution=0.0,
            detail=f"Unhandled field_match: {check_id}",
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
                    span_seconds=int(row[7]) if row[7] else 0,
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

            try:
                client = self._get_ch()
                result = client.query(
                    f"SELECT timestamp, event_id, username, source_host "
                    f"FROM events "
                    f"WHERE case_id = {{case_id:UInt32}} "
                    f"AND event_id IN ({eid_list}) "
                    f"AND source_host = {{source_host:String}} "
                    f"{time_clause} "
                    f"AND (noise_matched = false OR noise_matched IS NULL) "
                    f"ORDER BY timestamp DESC LIMIT 1",
                    parameters=params
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

    def _consume_gap_findings(self, pattern_id: str) -> List[CheckResult]:
        all_results = []
        for finding in self.gap_findings:
            mapped_pid = get_gap_pattern_id(finding)
            if mapped_pid == pattern_id:
                all_results.extend(map_gap_finding_to_check_results(finding))
        return all_results

    # -----------------------------------------------------------------
    # Helpers
    # -----------------------------------------------------------------

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
