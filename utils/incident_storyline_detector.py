"""Build generic download, execution, and containment storylines."""

import logging
from datetime import datetime, timedelta
from typing import Any, Callable, Dict, List, Optional, Tuple

from utils.clickhouse import get_fresh_client

logger = logging.getLogger(__name__)

EVENT_TS = "COALESCE(timestamp_utc, timestamp)"


class IncidentStorylineDetector:
    """Derive higher-level incident storylines from raw case telemetry."""

    def __init__(
        self,
        case_id: int,
        target_downloads_per_window: int = 2000,
        max_window_seconds: int = 21600,
        max_merged_window_seconds: int = 604800,
        min_window_seconds: int = 60,
        progress_callback: Optional[Callable[[str, int, str], None]] = None,
        max_source_rows: Optional[int] = None,
    ):
        self.case_id = case_id
        self.target_downloads_per_window = max_source_rows or target_downloads_per_window
        self.max_window_seconds = max_window_seconds
        self.max_merged_window_seconds = max_merged_window_seconds
        self.min_window_seconds = min_window_seconds
        self.progress_callback = progress_callback
        self.client = get_fresh_client()

    def build(self) -> Dict[str, Any]:
        windows = self._build_download_windows()
        if not windows:
            return {
                'downloads': [],
                'containments': [],
                'storylines': [],
                'download_count': 0,
                'containment_count': 0,
                'storyline_count': 0,
                'windows_processed': 0,
            }

        storylines: List[Dict[str, Any]] = []
        download_count = 0
        containment_keys = set()

        for idx, (window_start, window_end, expected_downloads) in enumerate(windows, start=1):
            window_label = (
                f'{expected_downloads:,} downloads'
                if expected_downloads is not None
                else f'{window_start} to {window_end}'
            )
            self._emit_progress(
                idx,
                len(windows),
                f'Correlating storyline window {idx}/{len(windows)} '
                f'({window_label})',
            )
            downloads = self._query_download_execution_pairs(window_start, window_end)
            containments = self._query_containment_events(window_start, window_end)
            download_count += len(downloads)
            for event in containments:
                containment_keys.add((
                    event.get('source_host'),
                    event.get('timestamp'),
                    event.get('artifact_type'),
                    event.get('event_id'),
                    event.get('snippet'),
                ))
            storylines.extend(self._stitch_storylines(downloads, containments))

        self._emit_progress(
            len(windows),
            len(windows),
            f'Correlated {len(storylines):,} storylines across {len(windows):,} windows',
        )
        return {
            # Detailed downloads/containments are intentionally not accumulated here:
            # the finalized analysis stores storylines and counts, and avoiding
            # raw-row retention keeps huge cases from exhausting worker memory.
            'downloads': [],
            'containments': [],
            'storylines': storylines,
            'download_count': download_count,
            'containment_count': len(containment_keys),
            'storyline_count': len(storylines),
            'windows_processed': len(windows),
        }

    def _emit_progress(self, window_index: int, total_windows: int, message: str) -> None:
        if not self.progress_callback or total_windows <= 0:
            return
        percent = 80 + int((window_index / total_windows) * 4)
        self.progress_callback('incident_storylines', min(percent, 84), message)

    def _query_case_time_buckets(self) -> List[Tuple[Any, Any, int]]:
        bucket_seconds = max(int(self.max_window_seconds), int(self.min_window_seconds))
        query = f"""
            SELECT
                toStartOfInterval({EVENT_TS}, INTERVAL {bucket_seconds} SECOND) AS bucket_start,
                max({EVENT_TS}) AS bucket_last_event,
                count() AS event_count
            FROM events
            WHERE case_id = {{case_id:UInt32}}
              AND {EVENT_TS} >= {{sane_min:DateTime64}}
              AND {EVENT_TS} < {{sane_max:DateTime64}}
              AND artifact_type = 'browser_download'
              AND target_path != ''
              AND source_host != ''
            GROUP BY bucket_start
            ORDER BY bucket_start ASC
        """
        result = self.client.query(
            query,
            parameters={
                'case_id': self.case_id,
                'sane_min': datetime(2000, 1, 1),
                'sane_max': datetime.utcnow() + timedelta(days=30),
            },
        )
        windows: List[Tuple[Any, Any, int]] = []
        for bucket_start, _bucket_last_event, event_count in result.result_rows:
            if not bucket_start or not event_count:
                continue
            windows.append((
                bucket_start,
                bucket_start + timedelta(seconds=bucket_seconds),
                int(event_count),
            ))
        return windows

    def _build_download_windows(self) -> List[Tuple[Any, Any, Optional[int]]]:
        return self._merge_download_buckets(self._query_case_time_buckets())

    def _merge_download_buckets(
        self,
        buckets: List[Tuple[Any, Any, int]],
    ) -> List[Tuple[Any, Any, Optional[int]]]:
        """Merge sparse populated buckets to reduce query count without row caps."""
        if not buckets:
            return []

        merged: List[Tuple[Any, Any, Optional[int]]] = []
        current_start, current_end, current_count = buckets[0]
        max_span = timedelta(seconds=self.max_merged_window_seconds)

        for bucket_start, bucket_end, bucket_count in buckets[1:]:
            merged_count = current_count + bucket_count
            merged_span = bucket_end - current_start
            if (
                merged_count <= self.target_downloads_per_window
                and merged_span <= max_span
            ):
                current_end = bucket_end
                current_count = merged_count
                continue

            merged.append((current_start, current_end, current_count))
            current_start, current_end, current_count = bucket_start, bucket_end, bucket_count

        merged.append((current_start, current_end, current_count))
        return merged

    def _query_download_execution_pairs(self, window_start: Any, window_end: Any) -> List[Dict[str, Any]]:
        query = """
            WITH downloads AS (
                SELECT
                    source_host,
                    username,
                    COALESCE(timestamp_utc, timestamp) AS download_time,
                    target_path AS download_path,
                    lower(replaceRegexpOne(target_path, '^.*[\\\\/]', '')) AS download_name,
                    raw_json
                FROM events
                WHERE case_id = {case_id:UInt32}
                  AND artifact_type = 'browser_download'
                  AND target_path != ''
                  AND source_host != ''
                  AND COALESCE(timestamp_utc, timestamp) >= {window_start:DateTime64}
                  AND COALESCE(timestamp_utc, timestamp) < {window_end:DateTime64}
            ),
            download_bounds AS (
                SELECT
                    min(download_time) AS first_download,
                    max(download_time) AS last_download
                FROM downloads
            ),
            executions AS (
                SELECT
                    source_host,
                    username,
                    COALESCE(timestamp_utc, timestamp) AS execution_time,
                    process_name,
                    process_path,
                    command_line,
                    event_id
                FROM events
                WHERE case_id = {case_id:UInt32}
                  AND source_host IN (SELECT DISTINCT source_host FROM downloads)
                  AND COALESCE(timestamp_utc, timestamp) BETWEEN
                        (SELECT first_download FROM download_bounds)
                        AND (SELECT last_download FROM download_bounds) + INTERVAL 60 MINUTE
                  AND (
                    event_id IN ('1', '4688')
                    OR process_name != ''
                    OR process_path != ''
                    OR command_line != ''
                  )
            )
            SELECT
                d.source_host,
                d.username,
                d.download_time,
                d.download_path,
                d.download_name,
                e.execution_time,
                e.process_name,
                e.process_path,
                e.command_line,
                e.event_id
            FROM downloads d
            LEFT JOIN executions e
                ON e.source_host = d.source_host
               AND e.execution_time BETWEEN d.download_time AND d.download_time + INTERVAL 60 MINUTE
               AND (
                    positionCaseInsensitive(ifNull(e.command_line, ''), d.download_name) > 0
                    OR positionCaseInsensitive(ifNull(e.process_path, ''), d.download_name) > 0
                    OR positionCaseInsensitive(ifNull(e.process_name, ''), d.download_name) > 0
               )
            ORDER BY d.download_time ASC
        """
        result = self.client.query(
            query,
            parameters={
                'case_id': self.case_id,
                'window_start': window_start,
                'window_end': window_end,
            },
        )
        rows: List[Dict[str, Any]] = []
        for row in result.result_rows:
            rows.append({
                'source_host': row[0],
                'username': row[1],
                'download_time': row[2],
                'download_path': row[3],
                'download_name': row[4],
                'execution_time': row[5],
                'process_name': row[6],
                'process_path': row[7],
                'command_line': row[8],
                'event_id': row[9],
            })
        return rows

    def _query_containment_events(self, window_start: Any, window_end: Any) -> List[Dict[str, Any]]:
        query = """
            WITH download_hosts AS (
                SELECT DISTINCT source_host
                FROM events
                WHERE case_id = {case_id:UInt32}
                  AND artifact_type = 'browser_download'
                  AND target_path != ''
                  AND source_host != ''
                  AND COALESCE(timestamp_utc, timestamp) >= {window_start:DateTime64}
                  AND COALESCE(timestamp_utc, timestamp) < {window_end:DateTime64}
            )
            SELECT
                source_host,
                username,
                COALESCE(timestamp_utc, timestamp) AS event_time,
                artifact_type,
                provider,
                event_id,
                left(search_blob, 500) AS snippet
            FROM events
            WHERE case_id = {case_id:UInt32}
              AND source_host IN (SELECT source_host FROM download_hosts)
              AND COALESCE(timestamp_utc, timestamp) >= {window_start:DateTime64}
              AND COALESCE(timestamp_utc, timestamp) < {window_end:DateTime64} + INTERVAL 30 MINUTE
              AND (
                    positionCaseInsensitive(search_blob, 'isolat') > 0
                 OR positionCaseInsensitive(search_blob, 'quarantin') > 0
                 OR positionCaseInsensitive(search_blob, 'contained') > 0
                 OR positionCaseInsensitive(search_blob, 'containment') > 0
                 OR (
                        positionCaseInsensitive(search_blob, 'blocked') > 0
                    AND (
                           positionCaseInsensitive(search_blob, 'defender') > 0
                        OR positionCaseInsensitive(search_blob, 'huntress') > 0
                        OR positionCaseInsensitive(provider, 'defender') > 0
                        OR positionCaseInsensitive(provider, 'huntress') > 0
                        OR artifact_type IN ('defender_av', 'mde_xdr')
                    )
                 )
              )
            ORDER BY event_time ASC
        """
        result = self.client.query(
            query,
            parameters={
                'case_id': self.case_id,
                'window_start': window_start,
                'window_end': window_end,
            },
        )
        rows: List[Dict[str, Any]] = []
        for row in result.result_rows:
            rows.append({
                'source_host': row[0],
                'username': row[1],
                'timestamp': row[2],
                'artifact_type': row[3],
                'provider': row[4],
                'event_id': row[5],
                'snippet': row[6],
            })
        return rows

    def _stitch_storylines(self, downloads: List[Dict[str, Any]],
                           containments: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        storylines: List[Dict[str, Any]] = []
        for download in downloads:
            host = download.get('source_host')
            download_time = download.get('download_time')
            if not host or not download_time:
                continue

            containment = next(
                (
                    event for event in containments
                    if event.get('source_host') == host
                    and event.get('timestamp')
                    and event['timestamp'] >= download_time
                    and (event['timestamp'] - download_time).total_seconds() <= 1800
                ),
                None,
            )
            if not download.get('execution_time') and not containment:
                continue

            confidence = 65
            severity = 'medium'
            mitre = ['T1204.001']
            summary_parts = [f"Downloaded `{download.get('download_name') or download.get('download_path')}`"]

            if download.get('execution_time'):
                confidence += 15
                severity = 'high'
                mitre.append('T1059')
                summary_parts.append('was followed by execution on the same host')

            if containment:
                confidence += 15
                severity = 'critical'
                mitre.extend(['T1562.001', 'T1486'])
                summary_parts.append('and containment or blocking telemetry appeared within 30 minutes')

            storylines.append({
                'type': 'storyline',
                'storyline_type': 'download_execution_containment',
                'storyline_title': 'Download to execution storyline',
                'name': 'Download to execution storyline',
                'summary': ' '.join(summary_parts),
                'severity': severity,
                'confidence': min(confidence, 95),
                'entity_type': 'system',
                'entity_value': host,
                'source_host': host,
                'username': download.get('username'),
                'first_seen': download_time,
                'last_seen': containment.get('timestamp') if containment else (
                    download.get('execution_time') or download_time
                ),
                'mitre_techniques': sorted(set(mitre)),
                'download_path': download.get('download_path'),
                'process_name': download.get('process_name'),
                'command_line': download.get('command_line'),
                'containment': containment,
                'suggested_iocs': [
                    {
                        'type': 'file_path',
                        'value': download.get('download_path'),
                        'reason': 'Downloaded file associated with suspicious storyline',
                    }
                ] if download.get('download_path') else [],
            })
        return storylines
