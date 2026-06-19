"""Deterministic Evidence Engine for CaseScope

Computes verifiable evidence for each attack pattern match using
ClickHouse queries instead of LLM inference. Produces structured
evidence packages that can optionally be refined by an AI judgment layer.

Architecture:
  CandidateExtractor (anchors) -> DeterministicEvidenceEngine -> EvidencePackage
  EvidencePackage -> (optional) AI Judgment Layer -> AIAnalysisResult
"""

import copy
import logging
import operator
import re
import time
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Tuple, Any

from utils.pattern_check_definitions import (
    CheckDefinition, CheckResult, CoverageAssessment, BurstResult,
    SequenceResult, EvidencePackage, SpreadAssessment,
    get_pattern_id_for_gap_finding,
)
from utils.finding_contract import (
    build_burst_engine_producer_input,
    build_gap_detector_producer_input,
    build_sequence_engine_producer_input,
    get_burst_engine_contribution,
    get_burst_engine_max_possible,
    get_sequence_engine_contribution,
    get_sequence_engine_max_possible,
    sort_producer_inputs,
)
from utils.event_noise_state import (
    build_effective_not_noise_clause,
    ensure_event_noise_state_tables,
    replace_legacy_noise_filter,
)
from utils.gap_detector_bridge import map_gap_finding_to_check_results
from utils.rules.loader import RuleCatalog, RuleLoader
from utils.scoring_telemetry import resolve_effective_scoring_version
from utils.timezone import from_utc

logger = logging.getLogger(__name__)

INCONCLUSIVE_WEIGHT_FRACTION = 0.3
UTC_QUERY_TIMESTAMP = "COALESCE(timestamp_utc, timestamp)"
PASS_CONDITION_RE = re.compile(
    r"^\s*result\s*(==|!=|>=|<=|>|<)\s*(-?(?:\d+(?:\.\d*)?|\.\d+))\s*$"
)
SEQUENCE_EVENT_ID_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")
MAX_SEQUENCE_OFFSET_SECONDS = 86400
PASS_CONDITION_OPERATORS = {
    "==": operator.eq,
    "!=": operator.ne,
    ">": operator.gt,
    ">=": operator.ge,
    "<": operator.lt,
    "<=": operator.le,
}


class DeterministicEvidenceEngine:
    """Computes verifiable evidence for each pattern match."""

    def __init__(self, case_id: int, analysis_id: str,
                 census: Dict[str, int] = None,
                 gap_findings: List = None,
                 case_tz: str = 'UTC',
                 exclude_noise: bool = False):
        self.case_id = case_id
        self.analysis_id = analysis_id
        self.census = census or {}
        self.gap_findings = gap_findings or []
        self.case_tz = case_tz or 'UTC'
        self.exclude_noise = bool(exclude_noise)
        self._ch_client = None
        self.rule_catalog = RuleLoader(self).register_with_engine()

    def register_rule_catalog(self, catalog: RuleCatalog) -> None:
        """Attach the active rule catalog loaded by RuleLoader."""
        self.rule_catalog = catalog

    def _get_ch(self):
        if self._ch_client is None:
            from utils.clickhouse import get_fresh_client
            self._ch_client = get_fresh_client()
            ensure_event_noise_state_tables(self._ch_client)
        return self._ch_client

    def evaluate_pattern(
        self, pattern_id: str, pattern_config: Dict,
        anchor_events: List[Dict], time_window_minutes: int = 60
    ) -> List[EvidencePackage]:
        """Evaluate all anchors for a pattern, returning one EvidencePackage
        per correlation key."""
        start_time = time.time()
        checks_defs = self.rule_catalog.get_checks_for_pattern(pattern_id)
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

        # Phase 1: resolve each correlation key's window so coverage can be
        # assessed with one batched query instead of one round-trip per key.
        prepared_keys = []
        for corr_key, anchors in groups.items():
            sorted_anchors = self._sort_anchors_by_rarity(anchors)
            if not sorted_anchors:
                continue

            representative = sorted_anchors[0]
            host = representative.get('source_host', '')

            all_ts = [self._anchor_query_timestamp(a) for a in sorted_anchors]
            parsed = [self._parse_ts(t) for t in all_ts if t]
            parsed = [p for p in parsed if p is not None]
            if parsed:
                earliest = min(parsed)
                latest = max(parsed)
                half = timedelta(minutes=time_window_minutes / 2)
                window_start = earliest - half
                window_end = latest + half
            else:
                ts = self._anchor_query_timestamp(representative)
                window_start, window_end = self._compute_window(ts, time_window_minutes)

            prepared_keys.append(
                (corr_key, sorted_anchors, representative, host, window_start, window_end)
            )

        coverages = self._check_coverage_batch(
            [(host, window_start, window_end) for _, _, _, host, window_start, window_end in prepared_keys],
            required_sources,
        )

        # Phase 2: evaluate checks, bursts, sequences, and scoring per key.
        for (corr_key, sorted_anchors, representative, host, window_start, window_end), coverage in zip(
            prepared_keys, coverages
        ):
            params = self._build_query_params(
                representative, window_start, window_end,
                all_anchors=sorted_anchors
            )

            scoped_gap = self._scope_gap_results(all_gap_results, params)

            check_results = self._run_checks(
                checks_defs, params, coverage, [cr for _, cr in scoped_gap]
            )

            bursts = self._detect_bursts(
                pattern_id,
                params,
                correlation_fields=correlation_fields,
            )
            sequences = self._validate_sequences(
                pattern_id,
                params,
                coverage=coverage,
                correlation_fields=correlation_fields,
            )

            requested_scoring_version = str(pattern_config.get('scoring_version') or '1.0')
            effective_scoring_version = resolve_effective_scoring_version(pattern_config)
            scoring_meta = self._compute_scoring(
                pattern_id=pattern_id,
                pattern_name=pattern_config.get('name', pattern_id),
                pattern_config=pattern_config,
                scoring_version=effective_scoring_version,
                check_defs=checks_defs,
                checks=check_results,
                bursts=bursts,
                sequences=sequences,
                coverage=coverage,
            )
            scoring_changes = list(scoring_meta.get('scoring_changes', []))
            if requested_scoring_version != effective_scoring_version and 'forced_legacy_scoring' not in scoring_changes:
                scoring_changes.append('forced_legacy_scoring')

            pkg = EvidencePackage(
                anchor=self._sanitize_anchor(representative),
                pattern_id=pattern_id,
                pattern_name=pattern_config.get('name', pattern_id),
                correlation_key=corr_key,
                checks=check_results,
                coverage=coverage,
                bursts=bursts,
                sequences=sequences,
                producer_inputs=[],
                deterministic_score=scoring_meta['score'],
                max_possible_score=scoring_meta['max_possible'],
                eligible_to_emit=scoring_meta['eligible_to_emit'],
                emit_block_reasons=scoring_meta['emit_block_reasons'],
                anchor_class=pattern_config.get('anchor_class'),
                scoring_version=effective_scoring_version,
                scoring_changes=scoring_changes,
                evaluable_weight=scoring_meta['evaluable_weight'],
                excluded_weight=scoring_meta['excluded_weight'],
                raw_total_weight=scoring_meta['raw_total_weight'],
                coverage_gap_present=scoring_meta['coverage_gap_present'],
                mitre_techniques=pattern_config.get('mitre_techniques', []),
                score_components=scoring_meta.get('score_components', {}),
                score_reasons=scoring_meta.get('score_reasons', []),
            )
            if pkg.anchor.get('noise_matched') or pkg.anchor.get('noise_rules'):
                noise_reduction = 10.0 if pkg.deterministic_score >= 70 else 15.0
                pkg.deterministic_score = round(max(0.0, pkg.deterministic_score - noise_reduction), 1)
                pkg.score_components['noise_reduction'] = round(
                    pkg.score_components.get('noise_reduction', 0.0) - noise_reduction,
                    1,
                )
                pkg.score_components['final_score'] = pkg.deterministic_score
                pkg.score_reasons.append({
                    'id': 'noise_context',
                    'name': 'Noise or known-good context',
                    'role': 'noise',
                    'delta': -noise_reduction,
                    'source': 'noise_context',
                    'detail': 'Noise context reduces score but preserves evidence for abuse correlation',
                })

            pkg.producer_inputs = self._build_deterministic_producer_inputs(
                pattern_id=pattern_id,
                scoped_gap=scoped_gap,
                bursts=bursts,
                sequences=sequences,
            )
            behavioral_inputs = self._build_unmapped_gap_producer_inputs(
                pattern_id=pattern_id,
                params=params,
            )
            if behavioral_inputs:
                pkg.producer_inputs = sort_producer_inputs(
                    [*pkg.producer_inputs, *behavioral_inputs]
                )

            packages.append(pkg)

        spread_config = self.rule_catalog.get_spread_config(pattern_id)
        if spread_config and len(packages) >= 2:
            self._evaluate_spread(packages, spread_config, pattern_config)

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
            parts = []
            for field in correlation_fields:
                if field == 'username':
                    val = anchor.get('username_canonical') or self._canonicalize_username(anchor.get('username'))
                else:
                    val = anchor.get(field, '')
                parts.append(str(val or '').strip())
            if not any(parts):
                logger.warning("[DetEngine] Skipping anchor with empty correlation key")
                continue
            key = '|'.join(parts)
            groups.setdefault(key, []).append(anchor)
        return groups

    def _sort_anchors_by_rarity(self, anchors: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Prefer the rarest anchor event for deterministic package pivoting."""
        def _sort_key(anchor: Dict[str, Any]) -> tuple[Any, Any, str]:
            event_id = str(anchor.get('event_id', '') or '')
            count = self.census.get(event_id)
            if count is None:
                count = float('inf')
            parsed_ts = self._parse_ts(self._anchor_query_timestamp(anchor))
            ts_key = parsed_ts.isoformat() if parsed_ts is not None else ''
            return (count, ts_key, event_id)

        return sorted(anchors or [], key=_sort_key)

    def _compute_window(self, ts, window_minutes: int):
        parsed = self._parse_ts(ts)
        if parsed is None:
            return None, None
        half = timedelta(minutes=window_minutes / 2)
        return parsed - half, parsed + half

    @staticmethod
    def _window_available(params: Dict[str, Any]) -> bool:
        """Return True when a deterministic query window is available."""
        return bool(params.get('window_start') and params.get('window_end'))

    @staticmethod
    def _parse_ts(ts) -> Optional[datetime]:
        """Parse a timestamp value into a datetime, returning None on failure."""
        if isinstance(ts, datetime):
            if ts.tzinfo is not None:
                return ts.astimezone(timezone.utc).replace(tzinfo=None)
            return ts
        if isinstance(ts, str):
            cleaned = ts.strip()
            if cleaned.endswith('Z'):
                cleaned = cleaned[:-1] + '+00:00'
            try:
                parsed = datetime.fromisoformat(cleaned)
                if parsed.tzinfo is not None:
                    return parsed.astimezone(timezone.utc).replace(tzinfo=None)
                return parsed
            except ValueError:
                pass
            for fmt in ('%Y-%m-%d %H:%M:%S.%f', '%Y-%m-%d %H:%M:%S',
                        '%Y-%m-%dT%H:%M:%S.%f', '%Y-%m-%dT%H:%M:%S'):
                try:
                    return datetime.strptime(ts, fmt)
                except ValueError:
                    continue
        return None

    @staticmethod
    def _anchor_query_timestamp(anchor: Dict[str, Any]) -> Any:
        """Prefer the normalized UTC timestamp when both shapes are present."""
        return anchor.get('timestamp_utc') or anchor.get('timestamp')

    @staticmethod
    def _canonicalize_username(username: Any) -> str:
        value = str(username or '').strip()
        if not value:
            return ''
        if '\\' in value:
            value = value.rsplit('\\', 1)[-1]
        if '@' in value:
            value = value.split('@', 1)[0]
        return value.strip().lower()

    def _normalize_query_time_template(self, query_template: str) -> str:
        """Rewrite deterministic event-time SQL onto the UTC-normalized column."""
        normalized = query_template
        replacements = (
            (r"\btoStartOfInterval\(timestamp,", f"toStartOfInterval({UTC_QUERY_TIMESTAMP},"),
            (r"\bmin\(timestamp\)", f"min({UTC_QUERY_TIMESTAMP})"),
            (r"\bmax\(timestamp\)", f"max({UTC_QUERY_TIMESTAMP})"),
            (r"\bSELECT\s+timestamp\b", f"SELECT {UTC_QUERY_TIMESTAMP} AS timestamp"),
            (r"\bORDER BY\s+timestamp\b", f"ORDER BY {UTC_QUERY_TIMESTAMP}"),
            (r"\btimestamp\s+BETWEEN\b", f"{UTC_QUERY_TIMESTAMP} BETWEEN"),
        )
        for pattern, replacement in replacements:
            normalized = re.sub(pattern, replacement, normalized)
        if not getattr(self, "exclude_noise", False):
            return self._remove_legacy_noise_filter(normalized)
        return replace_legacy_noise_filter(normalized, alias="", case_id_sql="{case_id:UInt32}")

    @staticmethod
    def _remove_legacy_noise_filter(query: str) -> str:
        legacy = "(noise_matched = false OR noise_matched IS NULL)"
        updated = query
        for variant in (
            f"AND {legacy}\n",
            f"AND {legacy} ",
            f"AND {legacy}",
            f" {legacy} ",
        ):
            updated = updated.replace(variant, " ")
        return updated.replace(legacy, "1")

    def _not_noise_clause(self, *, alias: str = "", case_id_sql: str = "{case_id:UInt32}") -> str:
        if not getattr(self, "exclude_noise", False):
            return "1"
        return build_effective_not_noise_clause(alias=alias, case_id_sql=case_id_sql)

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
        if not window_start or not window_end:
            assessment.coverage_status = 'unknown'
            return assessment
        if not host:
            assessment.coverage_status = 'unknown'
            return assessment

        try:
            client = self._get_ch()
            time_column = UTC_QUERY_TIMESTAMP
            result = client.query(
                "SELECT channel, count() as cnt, "
                f"  min({time_column}) as earliest, max({time_column}) as latest "
                "FROM events "
                "WHERE case_id = {case_id:UInt32} "
                "AND source_host = {host:String} "
                f"AND {time_column} BETWEEN {{ws:DateTime64}} AND {{we:DateTime64}} "
                f"AND {self._not_noise_clause(alias='', case_id_sql='{case_id:UInt32}')} "
                "GROUP BY channel",
                parameters={
                    'case_id': self.case_id,
                    'host': host,
                    'ws': window_start,
                    'we': window_end,
                }
            )
            self._finalize_coverage_assessment(
                assessment, result.result_rows, required_sources
            )
        except Exception as e:
            logger.warning(f"[DetEngine] Coverage check failed for {host}: {e}")
            assessment.coverage_status = 'unknown'
            assessment.coverage_score = 50.0

        return assessment

    @staticmethod
    def _finalize_coverage_assessment(
        assessment: CoverageAssessment,
        rows: List[Tuple],
        required_sources: Dict[str, str],
    ) -> CoverageAssessment:
        """Apply per-channel (channel, cnt, earliest, latest) rows to an assessment."""
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

        return assessment

    def _check_coverage_batch(
        self,
        specs: List[Tuple[str, Optional[datetime], Optional[datetime]]],
        required_sources: Dict[str, str],
    ) -> List[CoverageAssessment]:
        """Assess coverage for many (host, window_start, window_end) tuples.

        Issues one grouped ClickHouse query for all distinct windows instead
        of one round-trip per correlation key. Falls back to per-key queries
        if the batched query fails.
        """
        assessments: List[Optional[CoverageAssessment]] = [None] * len(specs)

        unique: Dict[Tuple[str, datetime, datetime], List[int]] = {}
        for idx, (host, window_start, window_end) in enumerate(specs):
            if not window_start or not window_end or not host:
                unknown = CoverageAssessment(
                    host=host,
                    window_start=window_start.isoformat() if window_start else None,
                    window_end=window_end.isoformat() if window_end else None,
                )
                unknown.coverage_status = 'unknown'
                assessments[idx] = unknown
                continue
            unique.setdefault((host, window_start, window_end), []).append(idx)

        if not unique:
            return assessments

        unique_keys = list(unique.keys())
        if len(unique_keys) == 1:
            host, window_start, window_end = unique_keys[0]
            base = self._check_coverage(host, window_start, window_end, required_sources)
            for position, idx in enumerate(unique[unique_keys[0]]):
                assessments[idx] = base if position == 0 else copy.deepcopy(base)
            return assessments

        try:
            client = self._get_ch()
            time_column = UTC_QUERY_TIMESTAMP
            hosts = [key[0] for key in unique_keys]
            starts = [key[1] for key in unique_keys]
            ends = [key[2] for key in unique_keys]
            result = client.query(
                "SELECT w_idx, channel, count() as cnt, "
                f"  min({time_column}) as earliest, max({time_column}) as latest "
                "FROM events "
                "ARRAY JOIN arrayFilter("
                "    i -> source_host = {hosts:Array(String)}[i] "
                f"      AND {time_column} >= {{starts:Array(DateTime64(3))}}[i] "
                f"      AND {time_column} <= {{ends:Array(DateTime64(3))}}[i], "
                "    arrayEnumerate({hosts:Array(String)})"
                ") AS w_idx "
                "WHERE case_id = {case_id:UInt32} "
                "AND source_host IN {hosts:Array(String)} "
                f"AND {time_column} BETWEEN {{gmin:DateTime64}} AND {{gmax:DateTime64}} "
                f"AND {self._not_noise_clause(alias='', case_id_sql='{case_id:UInt32}')} "
                "GROUP BY w_idx, channel",
                parameters={
                    'case_id': self.case_id,
                    'hosts': hosts,
                    'starts': starts,
                    'ends': ends,
                    'gmin': min(starts),
                    'gmax': max(ends),
                },
            )
            rows_by_window: Dict[int, List[Tuple]] = {}
            for w_idx, channel, cnt, earliest, latest in result.result_rows:
                rows_by_window.setdefault(int(w_idx), []).append(
                    (channel, cnt, earliest, latest)
                )

            for window_number, key in enumerate(unique_keys, start=1):
                host, window_start, window_end = key
                base = CoverageAssessment(
                    host=host,
                    window_start=window_start.isoformat(),
                    window_end=window_end.isoformat(),
                )
                self._finalize_coverage_assessment(
                    base, rows_by_window.get(window_number, []), required_sources
                )
                for position, idx in enumerate(unique[key]):
                    assessments[idx] = base if position == 0 else copy.deepcopy(base)
        except Exception as e:
            logger.warning(
                f"[DetEngine] Batched coverage check failed for {len(unique_keys)} "
                f"windows, falling back to per-key queries: {e}"
            )
            for key in unique_keys:
                host, window_start, window_end = key
                base = self._check_coverage(host, window_start, window_end, required_sources)
                for position, idx in enumerate(unique[key]):
                    assessments[idx] = base if position == 0 else copy.deepcopy(base)

        return assessments

    # -----------------------------------------------------------------
    # Check execution
    # -----------------------------------------------------------------

    def _build_query_params(self, anchor: Dict, window_start: datetime,
                            window_end: datetime,
                            all_anchors: List[Dict] = None) -> Dict[str, Any]:
        ts = self._parse_ts(self._anchor_query_timestamp(anchor))
        normalized_start = self._parse_ts(window_start) or window_start
        normalized_end = self._parse_ts(window_end) or window_end
        if ts is None:
            ts = normalized_start
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
            'window_start': normalized_start,
            'window_end': normalized_end,
            'event_id': anchor.get('event_id', ''),
            'channel': anchor.get('channel', ''),
            'provider': anchor.get('provider', ''),
            'username': anchor.get('username', ''),
            'username_canonical': (
                anchor.get('username_canonical')
                or self._canonicalize_username(anchor.get('username', ''))
            ),
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

    def _validate_anchor_detail_for_scoring_v2(
        self,
        pattern_id: str,
        check_defs: List[CheckDefinition],
        results: List[CheckResult],
    ) -> None:
        """Require non-generic anchor detail text for Scoring 2.0 anchor checks."""
        defs_by_id = {cdef.id: cdef for cdef in check_defs}
        for result in results:
            cdef = defs_by_id.get(result.check_id)
            if cdef is None or cdef.check_type != 'anchor_match':
                continue
            detail = (result.detail or '').strip().lower()
            if detail == 'anchor matched':
                raise RuntimeError(
                    f"Scoring 2.0 pattern {pattern_id} requires explicit anchor detail for {result.check_id}"
                )

    def _validate_anchor_class_for_scoring_v2(
        self,
        pattern_id: str,
        pattern_name: str,
        pattern_config: Dict[str, Any],
    ) -> str:
        """Require explicit anchor-class semantics for Scoring 2.0 patterns."""
        anchor_class = str(pattern_config.get('anchor_class') or '').strip().lower()
        if anchor_class not in {'definitive', 'gateway', 'seed'}:
            raise RuntimeError(
                f"Scoring 2.0 pattern {pattern_id} requires anchor_class "
                "to be one of definitive, gateway, or seed"
            )

        required_check_ids = set(pattern_config.get('required_check_ids', []) or [])
        required_pass_count = int(pattern_config.get('required_pass_count', 0) or 0)
        allow_anchor_only_emit = bool(
            pattern_config.get('allow_anchor_only_emit', anchor_class == 'definitive')
        )

        if anchor_class in {'gateway', 'seed'} and allow_anchor_only_emit:
            raise RuntimeError(
                f"Scoring 2.0 pattern {pattern_id} ({pattern_name}) cannot allow "
                f"anchor-only emit for anchor_class={anchor_class}"
            )
        if anchor_class == 'gateway' and required_pass_count < 1 and not required_check_ids:
            raise RuntimeError(
                f"Scoring 2.0 pattern {pattern_id} ({pattern_name}) requires corroboration "
                "for gateway anchor_class"
            )
        if anchor_class == 'seed' and required_pass_count < 2:
            raise RuntimeError(
                f"Scoring 2.0 pattern {pattern_id} ({pattern_name}) requires "
                "required_pass_count >= 2 for seed anchor_class"
            )
        return anchor_class

    def _evaluate_absence(
        self, cdef: CheckDefinition, params: Dict, coverage: CoverageAssessment
    ) -> CheckResult:
        if not self._window_available(params):
            return CheckResult(
                check_id=cdef.id, status='INCONCLUSIVE', weight=cdef.weight,
                contribution=float(cdef.weight) * INCONCLUSIVE_WEIGHT_FRACTION,
                detail='Anchor timestamp unavailable; deterministic window could not be computed',
                source='coverage',
            )
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
            query_template = self._normalize_query_time_template(cdef.query_template)
            filtered = self._filter_params(query_template, params)
            result = client.query(query_template, parameters=filtered)
            value = result.result_rows[0][0] if result.result_rows else None

            if value is None:
                value = 0

            passed = self._eval_condition(cdef.pass_condition, value)
            if passed is None:
                return CheckResult(
                    check_id=cdef.id, status='INCONCLUSIVE', weight=cdef.weight,
                    contribution=float(cdef.weight) * INCONCLUSIVE_WEIGHT_FRACTION,
                    detail=f"Malformed pass_condition: {cdef.pass_condition}",
                    source='condition',
                )
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
        if (
            ('{window_start:' in cdef.query_template or '{window_end:' in cdef.query_template)
            and not self._window_available(params)
        ):
            return CheckResult(
                check_id=cdef.id, status='INCONCLUSIVE', weight=cdef.weight,
                contribution=float(cdef.weight) * INCONCLUSIVE_WEIGHT_FRACTION,
                detail='Anchor timestamp unavailable; deterministic window could not be computed',
                source='coverage',
            )
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
            tmpl = self._normalize_query_time_template(cdef.query_template)
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
            if passed is None:
                return CheckResult(
                    check_id=cdef.id, status='INCONCLUSIVE',
                    weight=cdef.weight,
                    contribution=float(cdef.weight) * INCONCLUSIVE_WEIGHT_FRACTION,
                    detail=f"Malformed pass_condition: {cdef.pass_condition}",
                    source='condition',
                )
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
                check_id=cdef.id, status='INCONCLUSIVE', weight=cdef.weight,
                contribution=float(cdef.weight) * INCONCLUSIVE_WEIGHT_FRACTION,
                detail=f"Query error: {str(e)[:100]}",
                source='error',
            )

    def _evaluate_field_match(self, cdef: CheckDefinition, params: Dict) -> CheckResult:
        check_id = cdef.id

        if 'off_hours' in check_id:
            ts = params.get('anchor_ts')
            if isinstance(ts, datetime):
                local_ts = from_utc(ts, self.case_tz) if self.case_tz else ts
                hour = local_ts.hour
                is_off_hours = hour < 7 or hour >= 19
                return CheckResult(
                    check_id=cdef.id,
                    status='PASS' if is_off_hours else 'FAIL',
                    weight=cdef.weight,
                    contribution=float(cdef.weight) if is_off_hours else 0.0,
                    detail=(
                        f"Local hour={hour} ({self.case_tz}; "
                        f"{'off-hours' if is_off_hours else 'business hours'})"
                    ),
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

        if 'machine_account' in check_id:
            username = params.get('username', '')
            upper = username.upper()
            is_machine = (username.endswith('$')
                          or upper.startswith('NT AUTHORITY\\')
                          or upper in ('SYSTEM', 'LOCAL SERVICE', 'NETWORK SERVICE'))
            return CheckResult(
                check_id=cdef.id,
                status='PASS' if is_machine else 'FAIL',
                weight=cdef.weight,
                contribution=float(cdef.weight) if is_machine else 0.0,
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
            raw_username = str(params.get('username') or '').strip()
            if not raw_username:
                return CheckResult(
                    check_id=cdef.id,
                    status='INCONCLUSIVE',
                    weight=cdef.weight,
                    contribution=float(cdef.weight) * INCONCLUSIVE_WEIGHT_FRACTION,
                    detail='username unavailable; cannot determine admin status',
                    source='field_match',
                )
            username = raw_username.lower()
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
                benign_words = [
                    'windows', 'update', 'defender', 'print', 'spool',
                    'network', 'audio', 'wmi', 'bits', 'theme',
                ]
                looks_benign = any(w in svc_name for w in benign_words)

                if len(svc_name) == 1 and not looks_benign:
                    return CheckResult(
                        check_id=cdef.id, status='PASS', weight=cdef.weight,
                        contribution=float(cdef.weight),
                        detail=f"Single-character service name: {svc_name}",
                        source='field_match',
                    )

                has_digit = any(c.isdigit() for c in svc_name)
                vowels = sum(1 for c in svc_name if c in 'aeiou')
                consonants = sum(1 for c in svc_name if c.isalpha() and c not in 'aeiou')
                high_consonant_ratio = consonants > 0 and vowels > 0 and (consonants / vowels) > 3
                all_consonants = len(svc_name) >= 4 and consonants == sum(1 for c in svc_name if c.isalpha()) and vowels == 0

                is_suspicious = (
                    len(svc_name) <= 8
                    and not looks_benign
                    and (has_digit or high_consonant_ratio or all_consonants)
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
            username = (params.get('username', '') or '').upper().strip()
            username_bare = username.rsplit('\\', 1)[-1] if '\\' in username else username

            system_indicators = [
                'localsystem', 'local system', 'nt authority\\system',
                'nt authority\\\\system', 's-1-5-18',
            ]
            found = [s for s in system_indicators if s in search_text]

            if not found and username_bare in ('SYSTEM', 'LOCAL SYSTEM'):
                found = [f'username={username}']

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
        strict_mode = cdef.id == 'regrun_unusual_path'
        if in_suspicious:
            passed = True
            detail = "Binary path in suspicious location"
        elif in_normal:
            passed = False
            detail = "Binary path in standard location"
        elif combined.strip():
            if strict_mode:
                return CheckResult(
                    check_id=cdef.id, status='INCONCLUSIVE', weight=cdef.weight,
                    contribution=float(cdef.weight) * INCONCLUSIVE_WEIGHT_FRACTION,
                    detail="Path present but not clearly suspicious",
                    source='field_match',
                )
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

    def _detect_bursts(
        self,
        pattern_id: str,
        params: Dict,
        *,
        correlation_fields: Optional[List[str]] = None,
    ) -> List[BurstResult]:
        config = self.rule_catalog.get_burst_config(pattern_id)
        if not config:
            return []

        window_sec = config['window_seconds']
        min_events = config['min_events']
        event_ids = config['event_ids']

        event_id_list = ', '.join(f"'{eid}'" for eid in event_ids)
        if not self._window_available(params):
            return []

        supported_scope_fields = {"username", "source_host", "src_ip"}
        scoped_fields = [
            field
            for field in (correlation_fields or [])
            if field in supported_scope_fields and params.get(field)
        ]
        scope_clause = ""
        if scoped_fields:
            scope_clause = "".join(
                f"AND {field} = {{{field}:String}} " for field in scoped_fields
            )

        try:
            client = self._get_ch()
            time_column = UTC_QUERY_TIMESTAMP
            burst_query = (
                f"SELECT "
                f"  username, source_host, src_ip, "
                f"  toStartOfInterval({time_column}, INTERVAL {window_sec} SECOND) as time_bucket, "
                f"  count() as events_in_bucket, "
                f"  uniqExact(event_id) as distinct_types, "
                f"  min({time_column}) as bucket_start, "
                f"  max({time_column}) as bucket_end, "
                f"  dateDiff('second', min({time_column}), max({time_column})) as span "
                f"FROM events "
                f"WHERE case_id = {{case_id:UInt32}} "
                f"AND event_id IN ({event_id_list}) "
                f"{scope_clause}"
                f"AND {self._not_noise_clause(alias='', case_id_sql='{case_id:UInt32}')} "
                f"AND {time_column} BETWEEN {{window_start:DateTime64}} AND {{window_end:DateTime64}} "
                f"GROUP BY username, source_host, src_ip, time_bucket "
                f"HAVING events_in_bucket >= {min_events} "
                f"ORDER BY events_in_bucket DESC "
            )
            result = client.query(
                burst_query,
                parameters=self._filter_params(burst_query, params),
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

    @staticmethod
    def _sequence_scope_fields(
        correlation_fields: Optional[List[str]],
        params: Dict[str, Any],
    ) -> List[str]:
        supported_scope_fields = {
            "username",
            "source_host",
            "src_ip",
            "target_host",
            "dst_ip",
        }
        return [
            field
            for field in (correlation_fields or [])
            if field in supported_scope_fields and params.get(field)
        ]

    @staticmethod
    def _validate_sequence_event_ids(event_ids: Any) -> List[str]:
        if isinstance(event_ids, str):
            values = [event_ids]
        elif isinstance(event_ids, (list, tuple)):
            values = list(event_ids)
        else:
            raise ValueError("sequence event_id must be a string or list")

        cleaned = [str(value).strip() for value in values if str(value).strip()]
        if not cleaned:
            raise ValueError("sequence event_id list cannot be empty")
        for event_id in cleaned:
            if not SEQUENCE_EVENT_ID_RE.fullmatch(event_id):
                raise ValueError(f"unsafe sequence event_id: {event_id!r}")
        return cleaned

    @staticmethod
    def _validate_sequence_uint16(value: Any, *, field_name: str) -> int:
        if isinstance(value, bool):
            raise ValueError(f"{field_name} must be an integer")
        try:
            parsed = int(value)
        except (TypeError, ValueError):
            raise ValueError(f"{field_name} must be an integer") from None
        if parsed < 0 or parsed > 65535:
            raise ValueError(f"{field_name} out of UInt16 range")
        return parsed

    @classmethod
    def _validate_sequence_offset(cls, value: Any) -> int:
        if isinstance(value, bool):
            raise ValueError("max_offset_seconds must be an integer")
        try:
            parsed = int(value)
        except (TypeError, ValueError):
            raise ValueError("max_offset_seconds must be an integer") from None
        if parsed < 1 or parsed > MAX_SEQUENCE_OFFSET_SECONDS:
            raise ValueError("max_offset_seconds out of allowed range")
        return parsed

    def _query_sequence_step(
        self,
        step_def: Dict[str, Any],
        params: Dict[str, Any],
        *,
        reference_ts: Any,
        scope_fields: List[str],
    ) -> Optional[Dict[str, Any]]:
        event_ids = self._validate_sequence_event_ids(step_def['event_id'])
        max_offset = self._validate_sequence_offset(step_def.get('max_offset_seconds', 300))
        direction = step_def.get('direction', 'before_anchor')
        if direction not in ('before_anchor', 'after_anchor'):
            raise ValueError(f"unsupported sequence direction: {direction!r}")
        time_column = UTC_QUERY_TIMESTAMP

        if direction == 'before_anchor':
            time_clause = (
                f"AND {time_column} BETWEEN {{sequence_ref_ts:DateTime64}} - "
                f"INTERVAL {max_offset} SECOND AND {{sequence_ref_ts:DateTime64}}"
            )
            order_direction = "DESC"
        else:
            time_clause = (
                f"AND {time_column} BETWEEN {{sequence_ref_ts:DateTime64}} AND "
                f"{{sequence_ref_ts:DateTime64}} + INTERVAL {max_offset} SECOND"
            )
            order_direction = "ASC"

        order_clause = (
            f"ORDER BY {time_column} {order_direction}, "
            f"ifNull(record_id, 0) {order_direction}, "
            f"source_file {order_direction}, "
            f"selector_key {order_direction}"
        )

        cond_clauses = ''
        sequence_params = dict(params)
        sequence_params['sequence_ref_ts'] = reference_ts
        sequence_params['sequence_event_ids'] = event_ids
        conditions = step_def.get('conditions', {})
        if 'logon_type' in conditions:
            types = conditions['logon_type']
            if isinstance(types, list):
                sequence_params['sequence_logon_types'] = [
                    self._validate_sequence_uint16(t, field_name='logon_type')
                    for t in types
                ]
                if not sequence_params['sequence_logon_types']:
                    raise ValueError("logon_type list cannot be empty")
                cond_clauses += "AND logon_type IN {sequence_logon_types:Array(UInt16)} "
            else:
                sequence_params['sequence_logon_type'] = self._validate_sequence_uint16(
                    types,
                    field_name='logon_type',
                )
                cond_clauses += "AND logon_type = {sequence_logon_type:UInt16} "

        scope_clause = ''.join(
            f"AND {field} = {{{field}:String}} " for field in scope_fields
        )

        client = self._get_ch()
        seq_query = (
            f"SELECT {time_column} AS timestamp, event_id, username, source_host "
            f"FROM events "
            f"WHERE case_id = {{case_id:UInt32}} "
            f"AND event_id IN {{sequence_event_ids:Array(String)}} "
            f"{scope_clause}"
            f"{time_clause} "
            f"{cond_clauses}"
            f"AND {self._not_noise_clause(alias='', case_id_sql='{case_id:UInt32}')} "
            f"{order_clause} LIMIT 1"
        )
        result = client.query(
            seq_query,
            parameters=self._filter_params(seq_query, sequence_params)
        )
        if not result.result_rows:
            return None

        row = result.result_rows[0]
        return {
            'timestamp': str(row[0]),
            'event_id': str(row[1]),
            'username': str(row[2]) if len(row) > 2 else '',
            'source_host': str(row[3]) if len(row) > 3 else '',
        }

    def _walk_sequence_steps(
        self,
        steps_with_indices: List[Tuple[int, Dict[str, Any]]],
        *,
        params: Dict[str, Any],
        anchor_ts: Any,
        scope_fields: List[str],
        found_steps: Dict[int, Dict[str, Any]],
        missing: List[str],
        query_errors: Optional[List[str]] = None,
    ) -> None:
        reference_ts = anchor_ts
        branch_broken = False

        for index, step_def in steps_with_indices:
            label = step_def['label']
            if branch_broken:
                missing.append(label)
                found_steps[index] = {
                    'label': label,
                    'found': False,
                    'skipped': True,
                    'reason': 'prior_step_missing',
                }
                continue

            try:
                matched = self._query_sequence_step(
                    step_def,
                    params,
                    reference_ts=reference_ts,
                    scope_fields=scope_fields,
                )
                if matched:
                    found_steps[index] = {
                        'label': label,
                        'timestamp': matched['timestamp'],
                        'event_id': matched['event_id'],
                        'found': True,
                    }
                    parsed_ts = self._parse_ts(matched['timestamp'])
                    reference_ts = parsed_ts if parsed_ts is not None else matched['timestamp']
                else:
                    missing.append(label)
                    found_steps[index] = {'label': label, 'found': False}
                    branch_broken = True
            except Exception as e:
                logger.warning(f"[DetEngine] Sequence step {label} failed: {e}")
                if query_errors is not None:
                    query_errors.append(label)
                missing.append(label)
                found_steps[index] = {
                    'label': label,
                    'found': False,
                    'error': str(e)[:80],
                    'reason': 'query_error',
                }
                branch_broken = True

    def _validate_sequences(
        self,
        pattern_id: str,
        params: Dict,
        coverage: Optional[CoverageAssessment] = None,
        *,
        correlation_fields: Optional[List[str]] = None,
    ) -> List[SequenceResult]:
        config = self.rule_catalog.get_sequence_config(pattern_id)
        if not config:
            return []

        chain_name = config['chain']
        steps = config['steps']
        found_steps: Dict[int, Dict[str, Any]] = {}
        missing = []
        query_errors = []
        telemetry_gap_sources = list(getattr(coverage, 'missing_sources', []) or [])
        sequence_required_sources = list((config.get('required_sources') or {}).keys())
        relevant_gap_sources = [
            src for src in telemetry_gap_sources
            if src in sequence_required_sources
        ]
        sequence_gap_sources = relevant_gap_sources if sequence_required_sources else telemetry_gap_sources
        anchor_ts = self._parse_ts(params.get('anchor_ts'))
        if anchor_ts is None:
            return [SequenceResult(
                chain=chain_name,
                status='inconclusive',
                steps=[
                    {
                        'label': step_def['label'],
                        'found': False,
                        'reason': 'anchor_window_unavailable',
                    }
                    for step_def in steps
                ],
                missing_steps=[step_def['label'] for step_def in steps],
                evaluability='anchor_window_unavailable',
                telemetry_gap_sources=sequence_gap_sources,
            )]
        scope_fields = self._sequence_scope_fields(correlation_fields, params)
        indexed_steps = list(enumerate(steps))
        before_steps = [
            (index, step_def)
            for index, step_def in indexed_steps
            if step_def.get('direction', 'before_anchor') == 'before_anchor'
        ]
        after_steps = [
            (index, step_def)
            for index, step_def in indexed_steps
            if step_def.get('direction', 'before_anchor') != 'before_anchor'
        ]

        if before_steps:
            self._walk_sequence_steps(
                list(reversed(before_steps)),
                params=params,
                anchor_ts=anchor_ts,
                scope_fields=scope_fields,
                found_steps=found_steps,
                missing=missing,
                query_errors=query_errors,
            )

        if after_steps:
            self._walk_sequence_steps(
                after_steps,
                params=params,
                anchor_ts=anchor_ts,
                scope_fields=scope_fields,
                found_steps=found_steps,
                missing=missing,
                query_errors=query_errors,
            )

        ordered_steps = [
            found_steps.get(index, {'label': step_def['label'], 'found': False})
            for index, step_def in indexed_steps
        ]

        if query_errors:
            status = 'inconclusive'
        elif not missing:
            status = 'complete'
        elif len(missing) < len(steps):
            status = 'partial'
        else:
            status = 'missing'

        if query_errors:
            evaluability = 'query_error'
        elif status == 'complete':
            evaluability = 'evaluable'
        elif relevant_gap_sources:
            evaluability = 'missing_telemetry'
        elif (
            not sequence_required_sources
            and telemetry_gap_sources
            and getattr(coverage, 'coverage_status', '') in ('none', 'sparse', 'unknown')
        ):
            evaluability = 'missing_telemetry'
        else:
            evaluability = 'evaluable'

        return [SequenceResult(
            chain=chain_name,
            status=status,
            steps=ordered_steps,
            missing_steps=missing,
            evaluability=evaluability,
            telemetry_gap_sources=sequence_gap_sources,
        )]

    # -----------------------------------------------------------------
    # Scoring
    # -----------------------------------------------------------------

    def _compute_legacy_score(
        self,
        checks: List[CheckResult],
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
            score += get_burst_engine_contribution(bursts)
            max_possible += get_burst_engine_max_possible()

        for seq in sequences:
            score += get_sequence_engine_contribution(getattr(seq, 'status', ''))
            if getattr(seq, 'status', '') == 'inconclusive':
                max_possible += get_sequence_engine_max_possible() * INCONCLUSIVE_WEIGHT_FRACTION
            else:
                max_possible += get_sequence_engine_max_possible()

        score = min(100, score)
        max_possible = min(100, max_possible)

        return round(score, 1), round(max_possible, 1)

    def _compute_scoring(
        self,
        *,
        pattern_id: str,
        pattern_name: str,
        pattern_config: Dict[str, Any],
        scoring_version: str,
        check_defs: List[CheckDefinition],
        checks: List[CheckResult],
        bursts: List[BurstResult],
        sequences: List[SequenceResult],
        coverage: CoverageAssessment,
    ) -> Dict[str, Any]:
        if scoring_version == '2.0':
            return self._compute_score_v2(
                pattern_id=pattern_id,
                pattern_name=pattern_name,
                pattern_config=pattern_config,
                check_defs=check_defs,
                checks=checks,
                bursts=bursts,
                sequences=sequences,
                coverage=coverage,
            )

        score, max_possible = self._compute_legacy_score(checks, bursts, sequences)
        eligible_to_emit = score >= 50
        return {
            'score': score,
            'max_possible': max_possible,
            'eligible_to_emit': eligible_to_emit,
            'emit_block_reasons': [] if eligible_to_emit else ['score_below_emit_threshold'],
            'evaluable_weight': max_possible,
            'excluded_weight': 0.0,
            'raw_total_weight': max_possible,
            'coverage_gap_present': bool(coverage and coverage.missing_sources),
            'scoring_changes': [],
        }

    def _resolve_coverage_policy(self, cdef: CheckDefinition) -> str:
        """Resolve the effective coverage policy for a check."""
        if cdef.coverage_policy != 'inherit':
            return cdef.coverage_policy

        default_policies = {
            'anchor_match': 'zero',
            'field_match': 'zero',
            'threshold': 'zero',
            'graduated': 'zero',
            'absence_with_coverage': 'zero',
            'burst': 'exclude',
        }
        return default_policies.get(cdef.check_type, 'zero')

    def _effective_check_role(self, cdef: CheckDefinition) -> str:
        """Apply compatibility role defaults for checks that predate role tagging."""
        if cdef.role != 'evidence':
            return cdef.role
        if cdef.check_type == 'anchor_match':
            return 'anchor'
        return cdef.role

    def _compute_score_v2(
        self,
        *,
        pattern_id: str,
        pattern_name: str,
        pattern_config: Dict[str, Any],
        check_defs: List[CheckDefinition],
        checks: List[CheckResult],
        bursts: List[BurstResult],
        sequences: List[SequenceResult],
        coverage: CoverageAssessment,
    ) -> Dict[str, Any]:
        self._validate_anchor_detail_for_scoring_v2(pattern_id, check_defs, checks)
        self._validate_anchor_class_for_scoring_v2(pattern_id, pattern_name, pattern_config)

        checks_by_id = {check.check_id: check for check in checks}
        sequence_catalog = getattr(self, 'rule_catalog', None)
        get_sequence_config = getattr(sequence_catalog, 'get_sequence_config', None)
        sequence_config = get_sequence_config(pattern_id) if callable(get_sequence_config) else {}
        sequence_config = sequence_config or {}
        sequence_required_sources = set((sequence_config.get('required_sources') or {}).keys())
        required_ids = set(pattern_config.get('required_check_ids', []) or [])
        required_pass_count = int(pattern_config.get('required_pass_count', 0) or 0)
        emit_threshold_mode = str(pattern_config.get('emit_threshold_mode', 'score_only') or 'score_only')
        allow_anchor_only_emit = bool(
            pattern_config.get(
                'allow_anchor_only_emit',
                str(pattern_config.get('anchor_class') or '').strip().lower() == 'definitive',
            )
        )
        emit_score_threshold = float(pattern_config.get('emit_score_threshold', 50) or 50)
        # Explicit config flag drives lateral-movement scoring semantics;
        # never derive them from the pattern id/name (renames must not
        # silently change scoring).
        is_lateral_pattern = bool(pattern_config.get('lateral_movement'))

        score = 0.0
        score_components = {
            'anchor_score': 0.0,
            'corroboration_score': 0.0,
            'field_bonus_score': 0.0,
            'sysmon_enrichment_score': 0.0,
            'known_good_reduction': 0.0,
            'noise_reduction': 0.0,
            'coverage_penalty': 0.0,
            'abuse_of_known_good_score': 0.0,
            'ai_adjustment': 0.0,
            'final_score': 0.0,
        }
        score_reasons: List[Dict[str, Any]] = []
        evaluable_weight = 0.0
        excluded_weight = 0.0
        raw_total_weight = 0.0
        coverage_gap_present = False
        required_hits = 0
        passed_non_anchor_signal = False
        passed_lateral_signal = False
        disqualifier_hits: List[str] = []

        def add_score_reason(
            *,
            check_id: str,
            name: str,
            role: str,
            delta: float,
            source: str,
            detail: str = '',
        ) -> None:
            if delta <= 0:
                return
            component_key = {
                'anchor': 'anchor_score',
                'corroboration': 'corroboration_score',
                'field_bonus': 'field_bonus_score',
                'sysmon_enrichment': 'sysmon_enrichment_score',
                'known_good': 'known_good_reduction',
                'noise': 'noise_reduction',
                'coverage': 'coverage_penalty',
                'abuse_of_known_good': 'abuse_of_known_good_score',
            }.get(role, 'corroboration_score')
            score_components[component_key] = round(
                score_components.get(component_key, 0.0) + float(delta),
                1,
            )
            score_reasons.append({
                'id': check_id,
                'name': name,
                'role': role,
                'delta': round(float(delta), 1),
                'source': source,
                'detail': detail,
            })

        for cdef in check_defs:
            raw_total_weight += float(cdef.weight)
            role = self._effective_check_role(cdef)
            policy = self._resolve_coverage_policy(cdef)

            if cdef.check_type == 'burst':
                if bursts:
                    contribution = min(float(cdef.weight), float(get_burst_engine_contribution(bursts)))
                    evaluable_weight += float(cdef.weight)
                    score += contribution
                    passed = contribution > 0
                elif coverage and coverage.coverage_status in ('none', 'sparse', 'unknown'):
                    coverage_gap_present = True
                    excluded_weight += float(cdef.weight) if policy == 'exclude' else 0.0
                    evaluable_weight += 0.0 if policy == 'exclude' else float(cdef.weight)
                    passed = False
                else:
                    evaluable_weight += float(cdef.weight)
                    passed = False

                if passed and (cdef.required_pass or cdef.id in required_ids):
                    required_hits += 1
                if passed and role not in ('anchor', 'context'):
                    passed_non_anchor_signal = True
                if passed and is_lateral_pattern:
                    passed_lateral_signal = True
                if passed and cdef.disqualifier:
                    disqualifier_hits.append(cdef.id)
                if passed:
                    add_score_reason(
                        check_id=cdef.id,
                        name=cdef.name,
                        role=role,
                        delta=contribution,
                        source='burst_engine',
                        detail='Burst threshold crossed',
                    )
                continue

            result = checks_by_id.get(cdef.id)
            if result is None:
                evaluable_weight += float(cdef.weight)
                continue

            if result.status == 'PASS':
                evaluable_weight += float(cdef.weight)
                contribution = float(result.contribution or 0.0)
                score += contribution
                if cdef.required_pass or cdef.id in required_ids:
                    required_hits += 1
                if role not in ('anchor', 'context'):
                    passed_non_anchor_signal = True
                # Deliberate compatibility heuristic: in addition to the
                # explicit lateral_movement config flag, a passed check whose
                # id/name/detail mentions lateral-style markers still counts
                # as a lateral signal. This means a non-lateral pattern with a
                # check named e.g. "remote registry access" can set the
                # signal; it is harmless there because missing_lateral_signal
                # only gates emit for flagged lateral patterns. Remove the
                # text heuristic only after per-check lateral tagging exists.
                lateral_text = ' '.join(
                    part for part in (cdef.id, cdef.name, result.detail) if part
                ).lower()
                if is_lateral_pattern or 'lateral' in lateral_text or any(
                    marker in lateral_text for marker in ('rdp', 'wmi', 'dcom', 'psexec', 'winrm', 'remote')
                ):
                    passed_lateral_signal = True
                if cdef.disqualifier:
                    disqualifier_hits.append(cdef.id)
                add_score_reason(
                    check_id=cdef.id,
                    name=cdef.name,
                    role=role,
                    delta=contribution,
                    source=result.source,
                    detail=result.detail,
                )
                continue

            if result.status == 'FAIL':
                evaluable_weight += float(cdef.weight)
                continue

            if result.status == 'INCONCLUSIVE':
                coverage_gap_present = True
                if policy == 'exclude':
                    excluded_weight += float(cdef.weight)
                else:
                    evaluable_weight += float(cdef.weight)
                continue

            evaluable_weight += float(cdef.weight)

        for sequence in sequences:
            raw_total_weight += float(get_sequence_engine_max_possible())
            sequence_status = getattr(sequence, 'status', '')
            sequence_evaluability = getattr(sequence, 'evaluability', 'evaluable')
            sequence_gap_sources = set(getattr(sequence, 'telemetry_gap_sources', []) or [])
            missing_sequence_telemetry = (
                sequence_evaluability == 'missing_telemetry'
                and bool(sequence_required_sources & sequence_gap_sources)
            )
            if sequence_status == 'inconclusive' or sequence_evaluability == 'anchor_window_unavailable':
                coverage_gap_present = True
                excluded_weight += float(get_sequence_engine_max_possible())
                continue
            if missing_sequence_telemetry:
                coverage_gap_present = True
                excluded_weight += float(get_sequence_engine_max_possible())
                continue
            evaluable_weight += float(get_sequence_engine_max_possible())
            sequence_contribution = float(get_sequence_engine_contribution(sequence_status))
            score += sequence_contribution
            add_score_reason(
                check_id='sequence',
                name=getattr(sequence, 'chain', '') or 'Sequence validation',
                role='corroboration',
                delta=sequence_contribution,
                source='sequence_engine',
                detail=f"Sequence status: {sequence_status}",
            )
            if sequence_status in ('partial', 'complete'):
                passed_non_anchor_signal = True
                if is_lateral_pattern:
                    passed_lateral_signal = True

        score = round(min(100.0, score), 1)
        score_components['final_score'] = score
        evaluable_weight = round(min(100.0, evaluable_weight), 1)
        excluded_weight = round(min(100.0, excluded_weight), 1)
        raw_total_weight = round(min(100.0, raw_total_weight), 1)

        emit_block_reasons: List[str] = []
        score_meets_threshold = score >= emit_score_threshold
        requireds_met = required_hits >= required_pass_count

        if disqualifier_hits:
            emit_block_reasons.extend(
                f"disqualifier:{check_id}" for check_id in sorted(disqualifier_hits)
            )
        if emit_threshold_mode in ('score_only', 'score_and_required') and not score_meets_threshold:
            emit_block_reasons.append('score_below_emit_threshold')
        if emit_threshold_mode in ('score_and_required', 'required_only') and not requireds_met:
            emit_block_reasons.append('required_checks_not_met')
        if not allow_anchor_only_emit and not passed_non_anchor_signal:
            emit_block_reasons.append('anchor_only_not_allowed')
        if is_lateral_pattern and not passed_lateral_signal:
            emit_block_reasons.append('missing_lateral_signal')

        return {
            'score': score,
            'max_possible': evaluable_weight,
            'eligible_to_emit': not emit_block_reasons,
            'emit_block_reasons': emit_block_reasons,
            'evaluable_weight': evaluable_weight,
            'excluded_weight': excluded_weight,
            'raw_total_weight': raw_total_weight,
            'coverage_gap_present': coverage_gap_present or excluded_weight > 0,
            'scoring_changes': ['scoring_2_0_dual_path'],
            'score_components': score_components,
            'score_reasons': score_reasons,
        }

    def _graduated_score(self, weight: int, value, tiers: List[Tuple[int, float]]) -> float:
        if value is None:
            return 0.0
        best_fraction = 0.0
        for threshold, fraction in sorted(tiers, key=lambda t: t[0]):
            if value >= threshold:
                best_fraction = fraction
        return round(weight * best_fraction, 1)

    def _eval_condition(self, condition: str, value) -> Optional[bool]:
        if not condition:
            try:
                return value is not None and float(value) > 0
            except (TypeError, ValueError):
                logger.warning("[DetEngine] pass_condition default could not evaluate result=%r", value)
                return None

        match = PASS_CONDITION_RE.match(str(condition))
        if not match:
            logger.warning("[DetEngine] Malformed pass_condition ignored: %r", condition)
            return None

        try:
            left = float(value)
            right = float(match.group(2))
        except (TypeError, ValueError):
            logger.warning(
                "[DetEngine] pass_condition %r could not evaluate non-numeric result=%r",
                condition,
                value,
            )
            return None

        return bool(PASS_CONDITION_OPERATORS[match.group(1)](left, right))

    # -----------------------------------------------------------------
    # Gap detector consumption
    # -----------------------------------------------------------------

    def _consume_gap_findings(self, pattern_id: str) -> List[Tuple[Any, CheckResult]]:
        """Collect gap findings paired with their source finding for scoping."""
        all_results = []
        for finding in self.gap_findings:
            mapped_pid = get_pattern_id_for_gap_finding(
                getattr(finding, 'finding_type', '') or ''
            )
            if mapped_pid == pattern_id:
                for cr in map_gap_finding_to_check_results(finding):
                    all_results.append((finding, cr))
        return all_results

    def build_gap_only_anchor_events(self, pattern_id: str) -> List[Dict[str, Any]]:
        """Materialize synthetic anchors for gap-only deterministic patterns."""
        anchors: List[Dict[str, Any]] = []
        for finding in self.gap_findings:
            finding_type = getattr(finding, 'finding_type', '') or ''
            if get_pattern_id_for_gap_finding(finding_type) != pattern_id:
                continue
            anchors.append(self._build_gap_only_anchor(finding))
        return anchors

    def _build_gap_only_anchor(self, finding: Any) -> Dict[str, Any]:
        """Build a minimal anchor-like dict from a mapped gap finding."""
        evidence = getattr(finding, 'evidence', None) or {}
        details = getattr(finding, 'details', None) or {}
        source_ips = list(evidence.get('source_ips') or [])
        entity_type = str(getattr(finding, 'entity_type', '') or '')
        entity_value = str(getattr(finding, 'entity_value', '') or '')
        anchor_ts = (
            getattr(finding, 'time_window_end', None)
            or getattr(finding, 'time_window_start', None)
            or getattr(finding, 'created_at', None)
        )

        anchor = {
            'gap_finding_id': getattr(finding, 'id', None) or f"{entity_type}:{entity_value}",
            'gap_finding_type': getattr(finding, 'finding_type', '') or '',
            'timestamp': anchor_ts,
            'timestamp_utc': anchor_ts,
            'event_id': getattr(finding, 'finding_type', '') or '',
            'entity_type': entity_type,
            'entity_value': entity_value,
            'username': '',
            'source_host': '',
            'src_ip': '',
            'search_summary': getattr(finding, 'summary', '') or '',
        }

        if entity_type == 'user':
            anchor['username'] = entity_value
        elif entity_type == 'system':
            anchor['source_host'] = entity_value
        elif entity_type == 'source_ip':
            anchor['src_ip'] = entity_value

        if not anchor['username']:
            anchor['username'] = str(details.get('username') or '')
        if not anchor['source_host']:
            anchor['source_host'] = str(details.get('hostname') or '')
        if not anchor['src_ip'] and source_ips:
            anchor['src_ip'] = str(source_ips[0] or '')

        return anchor

    def _scope_gap_results(
        self, all_gap: List[Tuple[Any, CheckResult]], params: Dict[str, Any]
    ) -> List[Tuple[Any, CheckResult]]:
        """Filter gap results to only those relevant to the current correlation key.
        Uses the finding's entity_type/entity_value for scoping and, when
        available, narrows user findings by the sampled source IPs captured in
        the finding evidence."""
        if not all_gap:
            return []

        scoped: List[Tuple[Any, CheckResult]] = []

        for finding, cr in all_gap:
            if self._finding_matches_scope(finding, params):
                scoped.append((finding, cr))

        return scoped

    def _finding_matches_scope(self, finding: Any, params: Dict[str, Any]) -> bool:
        key_host = self._normalize_entity(params.get('source_host', ''))
        key_user = self._normalize_entity(params.get('username', ''))
        key_src_ip = self._normalize_entity(params.get('src_ip', ''))
        entity_type = getattr(finding, 'entity_type', None) or ''
        entity_value = self._normalize_entity(getattr(finding, 'entity_value', None) or '')
        evidence = getattr(finding, 'evidence', None) or {}
        evidence_source_ips = {
            self._normalize_entity(ip)
            for ip in (evidence.get('source_ips') or [])
            if self._normalize_entity(ip)
        }

        if not entity_value:
            return True

        if entity_type == 'source_ip':
            return bool(key_src_ip and entity_value == key_src_ip)

        if entity_type == 'user':
            if entity_value != key_user:
                return False
            if evidence_source_ips:
                if not key_src_ip:
                    return True
                return key_src_ip in evidence_source_ips
            return not key_src_ip

        if entity_type == 'system':
            return bool(key_host and entity_value == key_host)

        return True

    def _build_deterministic_producer_inputs(
        self,
        pattern_id: str,
        scoped_gap: List[Tuple[Any, CheckResult]],
        bursts: List[BurstResult],
        sequences: List[SequenceResult],
    ) -> List[Dict[str, Any]]:
        """Build canonical producer metadata across deterministic producers."""
        producer_inputs: List[Dict[str, Any]] = []

        if scoped_gap:
            producer_inputs.extend(self._build_gap_producer_inputs(scoped_gap))
        if bursts:
            producer_inputs.extend(self._build_burst_producer_inputs(pattern_id, bursts))
        if sequences:
            producer_inputs.extend(self._build_sequence_producer_inputs(pattern_id, sequences))

        return sort_producer_inputs(producer_inputs)

    def _build_gap_producer_inputs(
        self, scoped_gap: List[Tuple[Any, CheckResult]]
    ) -> List[Dict[str, Any]]:
        """Build canonical producer metadata for scoped gap-detector findings."""
        producer_inputs: Dict[int, Dict[str, Any]] = {}

        for finding, check_result in scoped_gap:
            finding_key = id(finding)
            if finding_key not in producer_inputs:
                evidence = getattr(finding, 'evidence', None) or {}
                details = getattr(finding, 'details', None) or {}
                producer_inputs[finding_key] = build_gap_detector_producer_input(
                    finding_type=getattr(finding, 'finding_type', '') or '',
                    pattern_id=get_pattern_id_for_gap_finding(
                        getattr(finding, 'finding_type', '') or ''
                    ) or '',
                    confidence=getattr(finding, 'confidence', 0) or 0,
                    entity_type=getattr(finding, 'entity_type', '') or '',
                    entity_value=getattr(finding, 'entity_value', '') or '',
                    event_count=getattr(finding, 'event_count', 0) or 0,
                    source_ips=evidence.get('source_ips') or [],
                    evidence_keys=evidence.keys(),
                    detail_keys=details.keys(),
                )

            producer_inputs[finding_key]['mapped_checks'].append(
                {
                    'check_id': check_result.check_id,
                    'status': check_result.status,
                    'detail': check_result.detail,
                }
            )

        normalized_inputs = list(producer_inputs.values())
        for producer_input in normalized_inputs:
            producer_input['mapped_checks'].sort(key=lambda item: item['check_id'])
        return normalized_inputs

    def _build_unmapped_gap_producer_inputs(
        self,
        *,
        pattern_id: str,
        params: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        """Attach scoped behavioral/unmapped gap findings as producer inputs."""
        producer_inputs: List[Dict[str, Any]] = []
        for finding in self.gap_findings:
            finding_type = getattr(finding, 'finding_type', '') or ''
            if get_pattern_id_for_gap_finding(finding_type):
                continue
            if not self._finding_matches_scope(finding, params):
                continue

            evidence = getattr(finding, 'evidence', None) or {}
            details = getattr(finding, 'details', None) or {}
            producer_inputs.append(
                build_gap_detector_producer_input(
                    finding_type=finding_type,
                    pattern_id=pattern_id,
                    confidence=getattr(finding, 'confidence', 0) or 0,
                    entity_type=getattr(finding, 'entity_type', '') or '',
                    entity_value=getattr(finding, 'entity_value', '') or '',
                    event_count=getattr(finding, 'event_count', 0) or 0,
                    source_ips=evidence.get('source_ips') or [],
                    evidence_keys=evidence.keys(),
                    detail_keys=details.keys(),
                )
            )
        return producer_inputs

    def _build_burst_producer_inputs(
        self, pattern_id: str, bursts: List[BurstResult]
    ) -> List[Dict[str, Any]]:
        """Build canonical producer metadata for burst-engine outputs."""
        if not bursts:
            return []

        return [
            build_burst_engine_producer_input(
                pattern_id=pattern_id,
                bursts=bursts,
            )
        ]

    def _build_sequence_producer_inputs(
        self, pattern_id: str, sequences: List[SequenceResult]
    ) -> List[Dict[str, Any]]:
        """Build canonical producer metadata for sequence-validation outputs."""
        producer_inputs: List[Dict[str, Any]] = []

        for sequence in sequences:
            producer_inputs.append(
                build_sequence_engine_producer_input(
                    pattern_id=pattern_id,
                    sequence=sequence,
                )
            )

        return producer_inputs

    @staticmethod
    def _normalize_entity(value: str) -> str:
        """Normalize a host/user/IP for comparison: lowercase, strip domain prefix and trailing $."""
        if not value:
            return ''
        val = str(value).lower().strip()
        if '\\' in val:
            val = val.rsplit('\\', 1)[-1]
        return val.rstrip('$')

    # -----------------------------------------------------------------
    # Cross-key spread assessment
    # -----------------------------------------------------------------

    def _reconcile_spread_scoring_v2(
        self,
        package: EvidencePackage,
        *,
        pattern_config: Dict[str, Any],
        weight: float,
    ) -> None:
        """Keep Scoring 2.0 package metadata consistent after spread bonuses."""
        if getattr(package, 'scoring_version', '1.0') != '2.0':
            return

        package.evaluable_weight = round(min(100.0, float(package.evaluable_weight) + float(weight)), 1)
        package.raw_total_weight = round(min(100.0, float(package.raw_total_weight) + float(weight)), 1)
        package.max_possible_score = package.evaluable_weight

        emit_threshold_mode = str(pattern_config.get('emit_threshold_mode', 'score_only') or 'score_only')
        emit_score_threshold = float(pattern_config.get('emit_score_threshold', 50) or 50)
        if (
            emit_threshold_mode in ('score_only', 'score_and_required')
            and package.deterministic_score >= emit_score_threshold
            and package.emit_block_reasons
        ):
            package.emit_block_reasons = [
                reason for reason in package.emit_block_reasons
                if reason != 'score_below_emit_threshold'
            ]
            package.eligible_to_emit = not package.emit_block_reasons

    def _evaluate_spread(
        self,
        packages: List[EvidencePackage],
        spread_config: Dict[str, Any],
        pattern_config: Dict[str, Any],
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

            anchor_times = []
            for pkg in group:
                ts = self._anchor_query_timestamp(pkg.anchor)
                if ts:
                    parsed_ts = self._parse_ts(ts)
                    if parsed_ts:
                        anchor_times.append(parsed_ts)

            all_windows = []
            for pkg in group:
                if pkg.coverage:
                    if pkg.coverage.window_start:
                        parsed_start = self._parse_ts(pkg.coverage.window_start)
                        if parsed_start:
                            all_windows.append(parsed_start)
                    if pkg.coverage.window_end:
                        parsed_end = self._parse_ts(pkg.coverage.window_end)
                        if parsed_end:
                            all_windows.append(parsed_end)

            time_clause = ''
            spread_params = {
                'case_id': self.case_id,
                pivot_field: pivot_val,
            }
            if all_windows:
                spread_params['spread_ws'] = min(all_windows)
                spread_params['spread_we'] = max(all_windows)
                time_clause = (
                    f"AND {UTC_QUERY_TIMESTAMP} BETWEEN "
                    "{spread_ws:DateTime64} AND {spread_we:DateTime64} "
                )
            elif anchor_times:
                spread_params['spread_ws'] = min(anchor_times)
                spread_params['spread_we'] = max(anchor_times)
                time_clause = (
                    f"AND {UTC_QUERY_TIMESTAMP} BETWEEN "
                    "{spread_ws:DateTime64} AND {spread_we:DateTime64} "
                )

            try:
                query = (
                    f"SELECT uniqExact({target_field}) AS target_count, "
                    f"uniqExact(username) AS user_count, "
                    f"min({UTC_QUERY_TIMESTAMP}) AS first_seen, "
                    f"max({UTC_QUERY_TIMESTAMP}) AS last_seen, "
                    f"dateDiff('minute', min({UTC_QUERY_TIMESTAMP}), max({UTC_QUERY_TIMESTAMP})) "
                    f"AS span_minutes "
                    f"FROM events "
                    f"WHERE case_id = {{case_id:UInt32}} "
                    f"AND {pivot_field} = {{{pivot_field}:String}} "
                    f"AND {event_filter} "
                    f"{time_clause}"
                    f"AND {self._not_noise_clause(alias='', case_id_sql='{case_id:UInt32}')}"
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
                    self._reconcile_spread_scoring_v2(
                        pkg,
                        pattern_config=pattern_config,
                        weight=weight,
                    )

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
        referenced_types = dict(re.findall(r'\{(\w+):([^}]+)\}', template))
        filtered = {}
        for key, value in params.items():
            if key not in referenced_types:
                continue
            type_name = referenced_types[key]
            if 'DateTime' in type_name:
                normalized = DeterministicEvidenceEngine._parse_ts(value)
                filtered[key] = normalized if normalized is not None else value
            else:
                filtered[key] = value
        return filtered

    def _format_anchor_detail(self, params: Dict) -> str:
        parts = []
        for key in ('event_id', 'username', 'source_host', 'src_ip', 'target_host', 'process_name'):
            val = params.get(key)
            if val:
                parts.append(f"{key}={val}")
        command_line = self._compact_anchor_value(params.get('command_line'))
        if command_line:
            parts.append(f"command_line={command_line}")
        else:
            search_summary = self._compact_anchor_value(params.get('search_summary'))
            if search_summary:
                parts.append(f"summary={search_summary}")
        return ', '.join(parts) if parts else 'anchor matched'

    def _sanitize_anchor(self, anchor: Dict) -> Dict[str, Any]:
        safe = {}
        for key in ('timestamp', 'timestamp_utc', 'event_id', 'username',
                     'username_canonical',
                     'source_host', 'target_host', 'src_ip', 'dst_ip',
                     'logon_type', 'auth_package', 'key_length',
                     'process_name', 'channel', 'command_line',
                     'search_summary', 'workstation', 'logon_process',
                     'source_image', 'target_image', 'parent_image',
                     'event_uuid', 'noise_matched', 'noise_rules'):
            if key in anchor:
                val = anchor[key]
                safe[key] = self._json_safe_anchor_value(val)
        safe['anchor_summary'] = self._build_anchor_summary(safe)
        return safe

    @staticmethod
    def _compact_anchor_value(value: Any, limit: int = 160) -> str:
        cleaned = ' '.join(str(value or '').split())
        if not cleaned:
            return ''
        return cleaned[: limit - 3] + '...' if len(cleaned) > limit else cleaned

    @staticmethod
    def _json_safe_anchor_value(value: Any) -> Any:
        """Normalize anchor fields so EvidencePackage JSON persistence stays safe."""
        if isinstance(value, datetime):
            return value.isoformat()
        if isinstance(value, (str, int, float, bool)) or value is None:
            return value
        if isinstance(value, (list, tuple)):
            return [
                item
                if isinstance(item, (str, int, float, bool)) or item is None
                else str(item)
                for item in value
            ]
        return str(value)

    def _build_anchor_summary(self, anchor: Dict[str, Any]) -> str:
        """Keep a short, event-led anchor summary for analyst/UI explainability."""
        parts = []
        event_id = anchor.get('event_id')
        if event_id:
            parts.append(f"event_id={event_id}")
        process_name = self._compact_anchor_value(anchor.get('process_name'), limit=80)
        if process_name:
            parts.append(f"process={process_name}")
        command_line = self._compact_anchor_value(anchor.get('command_line'))
        if command_line:
            parts.append(f"command={command_line}")
        else:
            search_summary = self._compact_anchor_value(anchor.get('search_summary'))
            if search_summary:
                parts.append(f"summary={search_summary}")
        return ', '.join(parts) if parts else 'anchor matched'
