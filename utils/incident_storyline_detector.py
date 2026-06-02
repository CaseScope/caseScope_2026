"""Build generic download, execution, and containment storylines."""

import logging
from typing import Any, Dict, List

from utils.clickhouse import get_fresh_client

logger = logging.getLogger(__name__)


class IncidentStorylineDetector:
    """Derive higher-level incident storylines from raw case telemetry."""

    def __init__(self, case_id: int, max_source_rows: int = 2000):
        self.case_id = case_id
        self.max_source_rows = max_source_rows
        self.client = get_fresh_client()

    def build(self) -> Dict[str, Any]:
        downloads = self._query_download_execution_pairs()
        containments = self._query_containment_events()
        storylines = self._stitch_storylines(downloads, containments)
        return {
            'downloads': downloads,
            'containments': containments,
            'storylines': storylines,
            'download_count': len(downloads),
            'containment_count': len(containments),
            'storyline_count': len(storylines),
        }

    def _query_download_execution_pairs(self) -> List[Dict[str, Any]]:
        query = """
            WITH downloads AS (
                SELECT
                    source_host,
                    username,
                    timestamp AS download_time,
                    target_path AS download_path,
                    lower(replaceRegexpOne(target_path, '^.*[\\\\/]', '')) AS download_name,
                    raw_json
                FROM events
                WHERE case_id = {case_id:UInt32}
                  AND artifact_type = 'browser_download'
                  AND target_path != ''
                  AND source_host != ''
                ORDER BY timestamp ASC
                LIMIT {max_source_rows:UInt32}
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
                    timestamp AS execution_time,
                    process_name,
                    process_path,
                    command_line,
                    event_id
                FROM events
                WHERE case_id = {case_id:UInt32}
                  AND source_host IN (SELECT DISTINCT source_host FROM downloads)
                  AND timestamp BETWEEN
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
            LIMIT {max_source_rows:UInt32}
        """
        result = self.client.query(
            query,
            parameters={
                'case_id': self.case_id,
                'max_source_rows': self.max_source_rows,
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

    def _query_containment_events(self) -> List[Dict[str, Any]]:
        query = """
            SELECT
                source_host,
                username,
                timestamp,
                artifact_type,
                provider,
                event_id,
                left(search_blob, 500) AS snippet
            FROM events
            WHERE case_id = {case_id:UInt32}
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
            ORDER BY timestamp ASC
            LIMIT {max_source_rows:UInt32}
        """
        result = self.client.query(
            query,
            parameters={
                'case_id': self.case_id,
                'max_source_rows': self.max_source_rows,
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
