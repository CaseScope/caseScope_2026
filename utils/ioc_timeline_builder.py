"""IOC-Anchored Timeline Builder

Builds causal event chains starting from IOCs. For each IOC in a case:
1. Query ClickHouse for ALL events containing the IOC value
2. Fetch surrounding context (same host ±15 min, same user ±30 min)
3. Tag events with IOC associations
4. Build temporal chains grouped by host
5. Identify cross-host links (IOC appears on host A, then host B)

This is the missing pipeline between IOC extraction and timeline
narrative generation. Deterministic (no AI) — runs in all modes.

Usage:
    builder = IOCTimelineBuilder(case_id=123, analysis_id='uuid')
    timeline = builder.build()
    # timeline.entries: list of IOCTimelineEntry dicts
    # timeline.cross_host_links: list of cross-host IOC movement
    # timeline.summary: stats about the timeline
"""

import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Set, Tuple
from collections import defaultdict

from utils.clickhouse import get_fresh_client
from models.database import db

logger = logging.getLogger(__name__)

# Context window sizes
HOST_CONTEXT_MINUTES = 15   # ±15 min on same host around IOC hit
USER_CONTEXT_MINUTES = 30   # ±30 min for same user
MAX_CONTEXT_EVENTS = 200    # Cap context events per IOC per host
MAX_IOC_MATCHES = 500       # Cap direct IOC matches per IOC value
MAX_IOCS_TO_PROCESS = 50    # Cap total IOCs to process per case


class IOCTimelineBuilder:
    """Builds IOC-anchored timelines from ClickHouse event data.
    
    Deterministic pipeline (no AI required). Reuses the existing
    IOC matching infrastructure from ioc_artifact_tagger.py.
    """
    
    def __init__(self, case_id: int, analysis_id: str = None, 
                 progress_callback=None):
        """Initialize builder.
        
        Args:
            case_id: PostgreSQL case ID
            analysis_id: UUID for this analysis run
            progress_callback: Optional callback(phase, percent, message)
        """
        self.case_id = case_id
        self.analysis_id = analysis_id
        self.progress_callback = progress_callback
        self.client = get_fresh_client()
        
        self._stats = {
            'iocs_processed': 0,
            'iocs_with_matches': 0,
            'total_ioc_hits': 0,
            'total_context_events': 0,
            'hosts_involved': 0,
            'cross_host_links': 0,
            'duration_seconds': 0.0
        }
    
    def build(self) -> Dict[str, Any]:
        """Build the full IOC-anchored timeline.
        
        Returns:
            {
                'entries': list of timeline entry dicts,
                'cross_host_links': list of cross-host IOC movements,
                'ioc_summaries': per-IOC summary dicts,
                'summary': overall stats,
                'analysis_id': str
            }
        """
        start_time = datetime.utcnow()
        
        # Step 1: Load IOCs for this case
        self._update_progress('ioc_timeline', 0, 'Loading case IOCs...')
        iocs = self._load_case_iocs()
        
        if not iocs:
            logger.info(f"[IOCTimeline] No IOCs found for case {self.case_id}")
            return self._empty_result()
        
        logger.info(f"[IOCTimeline] Processing {len(iocs)} IOCs for case {self.case_id}")
        
        # Step 2: For each IOC, find matching events
        all_entries = []
        ioc_summaries = []
        ioc_host_times = defaultdict(list)  # {ioc_value: [(host, timestamp), ...]}
        
        for idx, ioc in enumerate(iocs):
            progress = int((idx / len(iocs)) * 70)  # 0-70%
            ioc_value = ioc['value']
            ioc_type = ioc['ioc_type']
            
            self._update_progress('ioc_timeline', progress, 
                                 f'Searching for IOC: {ioc_value[:40]}...')
            
            # Find all events containing this IOC
            ioc_events = self._find_ioc_events(ioc_value, ioc_type, ioc.get('aliases', []))
            
            self._stats['iocs_processed'] += 1
            
            if not ioc_events:
                continue
            
            self._stats['iocs_with_matches'] += 1
            self._stats['total_ioc_hits'] += len(ioc_events)
            
            # Track host appearances for cross-host detection
            for evt in ioc_events:
                host = evt.get('source_host', 'Unknown')
                ts = evt.get('timestamp')
                if host and ts:
                    ioc_host_times[ioc_value].append((host, ts))
            
            # Get surrounding context for each host where IOC appeared
            hosts_with_ioc = set(evt.get('source_host', '') for evt in ioc_events if evt.get('source_host'))
            context_events = {}
            
            for host in hosts_with_ioc:
                # Get the time range of IOC appearances on this host
                host_ioc_events = [e for e in ioc_events if e.get('source_host') == host]
                if not host_ioc_events:
                    continue
                    
                earliest = min(e['timestamp'] for e in host_ioc_events)
                latest = max(e['timestamp'] for e in host_ioc_events)
                
                ctx = self._get_host_context(host, earliest, latest)
                if ctx:
                    context_events[host] = ctx
                    self._stats['total_context_events'] += len(ctx)
            
            # Build timeline entries for this IOC
            entries = self._build_ioc_entries(
                ioc=ioc,
                ioc_events=ioc_events,
                context_events=context_events
            )
            all_entries.extend(entries)
            
            # Build per-IOC summary
            ioc_summaries.append({
                'ioc_id': ioc.get('id'),
                'ioc_value': ioc_value,
                'ioc_type': ioc_type,
                'match_count': len(ioc_events),
                'hosts_affected': list(hosts_with_ioc),
                'host_count': len(hosts_with_ioc),
                'first_seen': min(e['timestamp'] for e in ioc_events).isoformat() if ioc_events else None,
                'last_seen': max(e['timestamp'] for e in ioc_events).isoformat() if ioc_events else None,
                'timeline_entries': len(entries)
            })
        
        # Step 3: Sort all entries chronologically
        self._update_progress('ioc_timeline', 75, 'Building temporal chains...')
        all_entries.sort(key=lambda e: e['timestamp'])
        
        # Step 4: Detect cross-host IOC movement
        self._update_progress('ioc_timeline', 80, 'Detecting cross-host movement...')
        cross_host_links = self._detect_cross_host_movement(ioc_host_times)
        self._stats['cross_host_links'] = len(cross_host_links)
        
        # Step 5: Link sequential entries (preceding/following)
        self._update_progress('ioc_timeline', 85, 'Linking timeline entries...')
        self._link_entries(all_entries)
        
        # Step 6: Compute stats
        all_hosts = set()
        for entry in all_entries:
            if entry.get('source_host'):
                all_hosts.add(entry['source_host'])
        self._stats['hosts_involved'] = len(all_hosts)
        self._stats['duration_seconds'] = (datetime.utcnow() - start_time).total_seconds()
        
        self._update_progress('ioc_timeline', 90, 
                             f'Timeline built: {len(all_entries)} entries, '
                             f'{len(cross_host_links)} cross-host links')
        
        # Step 7: Store results
        self._update_progress('ioc_timeline', 95, 'Storing timeline...')
        result = {
            'entries': all_entries,
            'cross_host_links': cross_host_links,
            'ioc_summaries': ioc_summaries,
            'summary': self._stats.copy(),
            'analysis_id': self.analysis_id
        }
        
        self._store_timeline(result)
        
        self._update_progress('ioc_timeline', 100, 'IOC timeline complete')
        
        logger.info(f"[IOCTimeline] Complete: {len(all_entries)} entries, "
                    f"{self._stats['iocs_with_matches']}/{self._stats['iocs_processed']} IOCs matched, "
                    f"{len(cross_host_links)} cross-host links, "
                    f"{self._stats['duration_seconds']:.1f}s")
        
        return result
    
    def _load_case_iocs(self) -> List[Dict]:
        """Load IOCs for this case from PostgreSQL.
        
        Returns:
            List of IOC dicts with id, value, ioc_type, aliases, match_type
        """
        from models.ioc import IOC
        
        iocs = IOC.query.filter_by(case_id=self.case_id).order_by(
            IOC.created_at.asc()
        ).limit(MAX_IOCS_TO_PROCESS).all()
        
        return [
            {
                'id': ioc.id,
                'value': ioc.value,
                'value_normalized': ioc.value_normalized,
                'ioc_type': ioc.ioc_type,
                'aliases': ioc.aliases or [],
                'match_type': ioc.get_effective_match_type(),
                'category': ioc.category
            }
            for ioc in iocs
        ]
    
    def _find_ioc_events(self, ioc_value: str, ioc_type: str, 
                          aliases: List[str] = None) -> List[Dict]:
        """Find all events in the case containing this IOC value.
        
        Uses the existing match clause builder for consistent matching,
        plus direct column queries for IPs and hashes for speed.
        
        Args:
            ioc_value: The IOC value
            ioc_type: Type of IOC
            aliases: Optional aliases
            
        Returns:
            List of event dicts
        """
        from utils.ioc_artifact_tagger import build_ioc_match_clause
        from models.ioc import detect_match_type
        
        match_type = detect_match_type(ioc_value, ioc_type)
        
        # Build clauses — combine direct column matches with search_blob
        where_parts = [
            f"case_id = {self.case_id}",
            "(noise_matched = false OR noise_matched IS NULL)"
        ]
        
        # Build IOC-specific match conditions
        match_conditions = []
        
        # Direct column matches (faster than search_blob scanning)
        if ioc_type in ('IP Address (IPv4)',):
            match_conditions.append(
                f"(src_ip = toIPv4OrNull('{self._escape(ioc_value)}') "
                f"OR dst_ip = toIPv4OrNull('{self._escape(ioc_value)}'))"
            )
        
        if ioc_type == 'MD5 Hash':
            match_conditions.append(
                f"lower(file_hash_md5) = '{self._escape(ioc_value.lower())}'"
            )
        elif ioc_type == 'SHA1 Hash':
            match_conditions.append(
                f"lower(file_hash_sha1) = '{self._escape(ioc_value.lower())}'"
            )
        elif ioc_type == 'SHA256 Hash':
            match_conditions.append(
                f"lower(file_hash_sha256) = '{self._escape(ioc_value.lower())}'"
            )
        
        if ioc_type == 'Hostname':
            match_conditions.append(
                f"lower(source_host) = '{self._escape(ioc_value.lower())}'"
            )
        
        # Always add search_blob/raw_json match as fallback
        blob_clause = build_ioc_match_clause(ioc_value, ioc_type, match_type, aliases)
        match_conditions.append(blob_clause)
        
        where_parts.append(f"({' OR '.join(match_conditions)})")
        
        query = f"""
            SELECT 
                timestamp,
                timestamp_utc,
                event_id,
                source_host,
                username,
                channel,
                artifact_type,
                rule_title,
                rule_level,
                process_name,
                command_line,
                src_ip,
                dst_ip,
                src_port,
                dst_port,
                record_id,
                logon_type,
                mitre_tactics,
                mitre_tags,
                substring(search_blob, 1, 300) as search_summary
            FROM events
            WHERE {' AND '.join(where_parts)}
            ORDER BY timestamp ASC
            LIMIT {MAX_IOC_MATCHES}
        """
        
        try:
            result = self.client.query(query)
        except Exception as e:
            logger.error(f"[IOCTimeline] Query failed for IOC '{ioc_value}': {e}")
            return []
        
        events = []
        for row in result.result_rows:
            events.append({
                'timestamp': row[0],
                'timestamp_utc': row[1],
                'event_id': str(row[2]) if row[2] else '',
                'source_host': row[3] or '',
                'username': row[4] or '',
                'channel': row[5] or '',
                'artifact_type': row[6] or '',
                'rule_title': row[7] or '',
                'rule_level': row[8] or '',
                'process_name': row[9] or '',
                'command_line': row[10] or '',
                'src_ip': str(row[11]) if row[11] else '',
                'dst_ip': str(row[12]) if row[12] else '',
                'src_port': row[13],
                'dst_port': row[14],
                'record_id': row[15],
                'logon_type': row[16],
                'mitre_tactics': row[17] or [],
                'mitre_tags': row[18] or [],
                'search_summary': row[19] or '',
                'is_ioc_match': True,
                'is_context': False
            })
        
        return events
    
    def _get_host_context(self, host: str, earliest: datetime, 
                           latest: datetime) -> List[Dict]:
        """Get surrounding events on the same host within ± context window.
        
        Args:
            host: Hostname to get context for
            earliest: Earliest IOC event timestamp on this host
            latest: Latest IOC event timestamp on this host
            
        Returns:
            List of context event dicts
        """
        context_start = earliest - timedelta(minutes=HOST_CONTEXT_MINUTES)
        context_end = latest + timedelta(minutes=HOST_CONTEXT_MINUTES)
        
        query = f"""
            SELECT 
                timestamp,
                timestamp_utc,
                event_id,
                source_host,
                username,
                channel,
                artifact_type,
                rule_title,
                rule_level,
                process_name,
                command_line,
                src_ip,
                dst_ip,
                src_port,
                dst_port,
                record_id,
                logon_type,
                mitre_tactics,
                mitre_tags,
                substring(search_blob, 1, 300) as search_summary
            FROM events
            WHERE case_id = {self.case_id}
              AND lower(source_host) = '{self._escape(host.lower())}'
              AND timestamp BETWEEN '{context_start.strftime('%Y-%m-%d %H:%M:%S')}' 
                  AND '{context_end.strftime('%Y-%m-%d %H:%M:%S')}'
              AND (noise_matched = false OR noise_matched IS NULL)
            ORDER BY timestamp ASC
            LIMIT {MAX_CONTEXT_EVENTS}
        """
        
        try:
            result = self.client.query(query)
        except Exception as e:
            logger.warning(f"[IOCTimeline] Context query failed for host '{host}': {e}")
            return []
        
        events = []
        for row in result.result_rows:
            events.append({
                'timestamp': row[0],
                'timestamp_utc': row[1],
                'event_id': str(row[2]) if row[2] else '',
                'source_host': row[3] or '',
                'username': row[4] or '',
                'channel': row[5] or '',
                'artifact_type': row[6] or '',
                'rule_title': row[7] or '',
                'rule_level': row[8] or '',
                'process_name': row[9] or '',
                'command_line': row[10] or '',
                'src_ip': str(row[11]) if row[11] else '',
                'dst_ip': str(row[12]) if row[12] else '',
                'src_port': row[13],
                'dst_port': row[14],
                'record_id': row[15],
                'logon_type': row[16],
                'mitre_tactics': row[17] or [],
                'mitre_tags': row[18] or [],
                'search_summary': row[19] or '',
                'is_ioc_match': False,
                'is_context': True
            })
        
        return events
    
    def _build_ioc_entries(self, ioc: Dict, ioc_events: List[Dict],
                            context_events: Dict[str, List[Dict]]) -> List[Dict]:
        """Build timeline entries combining IOC hits and context.
        
        Deduplicates context events that are also IOC hits.
        Tags each entry with the IOC(s) it relates to.
        
        Args:
            ioc: IOC dict
            ioc_events: Direct IOC match events
            context_events: {host: [context_events]} 
            
        Returns:
            List of timeline entry dicts
        """
        entries = []
        seen_record_ids = set()
        
        # Add IOC match events first
        for evt in ioc_events:
            rid = evt.get('record_id')
            key = (evt.get('source_host', ''), rid, str(evt.get('timestamp', '')))
            if key in seen_record_ids:
                continue
            seen_record_ids.add(key)
            
            entry = {
                **evt,
                'entry_type': 'ioc_match',
                'ioc_id': ioc['id'],
                'ioc_value': ioc['value'],
                'ioc_type': ioc['ioc_type'],
                'iocs_involved': [ioc['value']],
                'relevance': 'direct'  # Direct IOC match
            }
            entries.append(entry)
        
        # Add context events (deduplicating against IOC hits)
        for host, ctx_events in context_events.items():
            for evt in ctx_events:
                rid = evt.get('record_id')
                key = (evt.get('source_host', ''), rid, str(evt.get('timestamp', '')))
                if key in seen_record_ids:
                    continue
                seen_record_ids.add(key)
                
                # Determine relevance based on rule_level
                level = evt.get('rule_level', '').lower()
                if level in ('critical', 'high'):
                    relevance = 'high_severity_context'
                elif evt.get('rule_title'):
                    relevance = 'detection_context'
                else:
                    relevance = 'temporal_context'
                
                entry = {
                    **evt,
                    'entry_type': 'context',
                    'ioc_id': ioc['id'],
                    'ioc_value': ioc['value'],
                    'ioc_type': ioc['ioc_type'],
                    'iocs_involved': [ioc['value']],
                    'relevance': relevance
                }
                entries.append(entry)
        
        return entries
    
    def _detect_cross_host_movement(
        self, ioc_host_times: Dict[str, List[Tuple[str, datetime]]]
    ) -> List[Dict]:
        """Detect IOC values appearing on multiple hosts over time.
        
        Identifies potential lateral movement by finding IOCs that appear
        on host A at time T1, then on host B at time T2 > T1.
        
        Args:
            ioc_host_times: {ioc_value: [(host, timestamp), ...]}
            
        Returns:
            List of cross-host link dicts
        """
        links = []
        
        for ioc_value, appearances in ioc_host_times.items():
            # Need appearances on at least 2 different hosts
            hosts = set(h for h, _ in appearances)
            if len(hosts) < 2:
                continue
            
            # Sort by timestamp
            sorted_appearances = sorted(appearances, key=lambda x: x[1])
            
            # Track first appearance per host
            first_per_host = {}
            for host, ts in sorted_appearances:
                if host not in first_per_host:
                    first_per_host[host] = ts
            
            # Build links from first host to subsequent hosts
            host_order = sorted(first_per_host.items(), key=lambda x: x[1])
            
            for i in range(len(host_order) - 1):
                src_host, src_time = host_order[i]
                dst_host, dst_time = host_order[i + 1]
                
                time_delta = (dst_time - src_time).total_seconds()
                
                links.append({
                    'ioc_value': ioc_value,
                    'source_host': src_host,
                    'source_first_seen': src_time.isoformat(),
                    'destination_host': dst_host,
                    'destination_first_seen': dst_time.isoformat(),
                    'time_delta_seconds': time_delta,
                    'potential_lateral_movement': time_delta < 3600  # Within 1 hour
                })
        
        # Sort by time
        links.sort(key=lambda x: x['source_first_seen'])
        
        return links
    
    def _link_entries(self, entries: List[Dict]):
        """Link sequential entries with preceding/following references.
        
        Groups entries by host, then links them in chronological order.
        Modifies entries in-place.
        
        Args:
            entries: Sorted list of timeline entries
        """
        # Group by host
        by_host = defaultdict(list)
        for i, entry in enumerate(entries):
            entry['_global_idx'] = i
            host = entry.get('source_host', 'Unknown')
            by_host[host].append(entry)
        
        # Link within each host
        for host, host_entries in by_host.items():
            for j, entry in enumerate(host_entries):
                if j > 0:
                    entry['preceding_idx'] = host_entries[j - 1]['_global_idx']
                if j < len(host_entries) - 1:
                    entry['following_idx'] = host_entries[j + 1]['_global_idx']
        
        # Clean up internal indices
        for entry in entries:
            entry.pop('_global_idx', None)
    
    def _store_timeline(self, result: Dict):
        """Store timeline results in the CaseAnalysisRun summary.
        
        Also stores as a standalone IOCTimeline record if the model exists.
        
        Args:
            result: Full timeline result dict
        """
        if not self.analysis_id:
            return
            
        try:
            from models.behavioral_profiles import CaseAnalysisRun
            
            run = CaseAnalysisRun.query.filter_by(
                analysis_id=self.analysis_id
            ).first()
            
            if run and run.summary:
                import json
                # Merge into existing summary
                if isinstance(run.summary, str):
                    try:
                        summary = json.loads(run.summary)
                    except (json.JSONDecodeError, TypeError):
                        summary = {}
                elif isinstance(run.summary, dict):
                    summary = run.summary
                else:
                    summary = {}
                
                summary['ioc_timeline'] = {
                    'entries_count': len(result.get('entries', [])),
                    'cross_host_links': len(result.get('cross_host_links', [])),
                    'iocs_matched': result['summary'].get('iocs_with_matches', 0),
                    'iocs_processed': result['summary'].get('iocs_processed', 0),
                    'hosts_involved': result['summary'].get('hosts_involved', 0),
                    'duration_seconds': result['summary'].get('duration_seconds', 0)
                }
                
                run.summary = summary if isinstance(run.summary, dict) else json.dumps(summary)
                db.session.commit()
                
        except Exception as e:
            logger.warning(f"[IOCTimeline] Failed to store timeline in analysis run: {e}")
    
    def _empty_result(self) -> Dict[str, Any]:
        """Return an empty timeline result."""
        return {
            'entries': [],
            'cross_host_links': [],
            'ioc_summaries': [],
            'summary': self._stats.copy(),
            'analysis_id': self.analysis_id
        }
    
    def _update_progress(self, phase: str, percent: int, message: str):
        """Update progress via callback."""
        if self.progress_callback:
            try:
                self.progress_callback(phase, percent, message)
            except Exception:
                pass
        logger.info(f"[IOCTimeline] [{percent}%] {message}")
    
    @staticmethod
    def _escape(value: str) -> str:
        """Escape a value for safe inclusion in ClickHouse SQL."""
        return value.replace("'", "\\'").replace("\\", "\\\\")
