"""
ClickHouse Client for CaseScope
Handles event storage, indexing, and Google-style search queries
"""

import re
import json
import shlex
import logging
from typing import Dict, List, Tuple, Any, Iterator, Optional
from datetime import datetime, timezone
from clickhouse_driver import Client
from clickhouse_driver.errors import Error as ClickHouseError

logger = logging.getLogger(__name__)


# =============================================================================
# TIME RANGE PATTERNS - For Google-style time filters
# =============================================================================

TIME_PATTERNS = [
    # Relative: last:Xh, last:Xd, last:Xw, last:Xm (months)
    (r'last:(\d+)h\b', lambda m: f"timestamp >= now() - INTERVAL {m.group(1)} HOUR"),
    (r'last:(\d+)d\b', lambda m: f"timestamp >= now() - INTERVAL {m.group(1)} DAY"),
    (r'last:(\d+)w\b', lambda m: f"timestamp >= now() - INTERVAL {m.group(1)} WEEK"),
    (r'last:(\d+)m\b', lambda m: f"timestamp >= now() - INTERVAL {m.group(1)} MONTH"),
    
    # Absolute dates: after:YYYY-MM-DD, before:YYYY-MM-DD
    (r'after:(\d{4}-\d{2}-\d{2})\b', lambda m: f"timestamp >= toDateTime('{m.group(1)} 00:00:00')"),
    (r'before:(\d{4}-\d{2}-\d{2})\b', lambda m: f"timestamp <= toDateTime('{m.group(1)} 23:59:59')"),
    
    # Absolute datetime: after:"YYYY-MM-DD HH:MM:SS"
    (r'after:"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})"', 
     lambda m: f"timestamp >= toDateTime('{m.group(1)}')"),
    (r'before:"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})"', 
     lambda m: f"timestamp <= toDateTime('{m.group(1)}')"),
    
    # Named periods: today, yesterday, thisweek
    (r'\btoday\b', lambda m: "toDate(timestamp) = today()"),
    (r'\byesterday\b', lambda m: "toDate(timestamp) = yesterday()"),
    (r'\bthisweek\b', lambda m: "toStartOfWeek(timestamp) = toStartOfWeek(now())"),
    (r'\blastweek\b', lambda m: "toStartOfWeek(timestamp) = toStartOfWeek(now()) - INTERVAL 1 WEEK"),
]

# Valid field names for field:value searches (prevents SQL injection)
VALID_SEARCH_FIELDS = {
    'computer', 'username', 'event_id', 'channel', 'provider_name',
    'source_file', 'source_system', 'file_type', 'log_source_type'
}


class ClickHouseIndexer:
    """
    Handles bulk indexing of events into ClickHouse
    Replaces OpenSearchIndexer for event storage
    """
    
    def __init__(self, host: str = 'localhost', port: int = 9000, 
                 database: str = 'casescope', user: str = 'default', 
                 password: str = ''):
        """
        Initialize ClickHouse connection
        
        Args:
            host: ClickHouse host
            port: ClickHouse native port (9000)
            database: Database name
            user: ClickHouse user
            password: ClickHouse password
        """
        self.host = host
        self.port = port
        self.database = database
        self.user = user
        self.password = password
        
        self.client = Client(
            host=host,
            port=port,
            database=database,
            user=user,
            password=password,
            settings={'max_block_size': 100000}
        )
        
        # Ensure database and tables exist
        self._init_schema()
        
    def _init_schema(self):
        """Create database and events table if they don't exist"""
        # Create database
        self.client.execute(f"CREATE DATABASE IF NOT EXISTS {self.database}")
        
        # Create main events table with proper indexing
        self.client.execute(f"""
            CREATE TABLE IF NOT EXISTS {self.database}.events (
                -- Core identifiers
                case_id UInt32,
                doc_id String DEFAULT generateUUIDv4(),
                
                -- Event identification
                event_record_id UInt64 DEFAULT 0,
                event_id String,
                
                -- Timestamps
                timestamp DateTime64(3) DEFAULT now64(3),
                system_time DateTime64(3) DEFAULT now64(3),
                indexed_at DateTime64(3) DEFAULT now64(3),
                
                -- Source identification
                computer LowCardinality(String) DEFAULT '',
                channel LowCardinality(String) DEFAULT '',
                provider_name LowCardinality(String) DEFAULT '',
                level LowCardinality(String) DEFAULT '',
                task LowCardinality(String) DEFAULT '',
                opcode LowCardinality(String) DEFAULT '',
                keywords String DEFAULT '',
                
                -- User information
                username String DEFAULT '',
                domain String DEFAULT '',
                sid String DEFAULT '',
                
                -- Network fields
                src_ip String DEFAULT '',
                dst_ip String DEFAULT '',
                src_port UInt16 DEFAULT 0,
                dst_port UInt16 DEFAULT 0,
                ip_protocol LowCardinality(String) DEFAULT '',
                
                -- Event data as JSON
                event_data String DEFAULT '{{}}',
                
                -- Searchable text blob (all fields concatenated)
                search_blob String DEFAULT '',
                
                -- Metadata
                source_file String DEFAULT '',
                source_system LowCardinality(String) DEFAULT '',
                file_type LowCardinality(String) DEFAULT '',
                log_source_type LowCardinality(String) DEFAULT '',
                
                -- Analyst tagging
                analyst_tagged UInt8 DEFAULT 0,
                analyst_tagged_by String DEFAULT '',
                analyst_tagged_at DateTime64(3) DEFAULT toDateTime64(0, 3),
                noise_category String DEFAULT '',
                
                -- Bloom filter index for fast token lookups
                INDEX search_tokens search_blob TYPE tokenbf_v1(32768, 3, 0) GRANULARITY 4,
                
                -- N-gram index for substring matching (LIKE '%term%')
                INDEX search_ngram search_blob TYPE ngrambf_v1(3, 256, 2, 0) GRANULARITY 4,
                
                -- Index for event_id lookups
                INDEX event_id_idx event_id TYPE bloom_filter(0.01) GRANULARITY 4
            )
            ENGINE = MergeTree()
            PARTITION BY (case_id, toYYYYMM(timestamp))
            ORDER BY (case_id, timestamp, event_id, event_record_id)
            SETTINGS index_granularity = 8192
        """)
        
        logger.info(f"ClickHouse schema initialized: {self.database}.events")
    
    def bulk_index(self, case_id: int, events: Iterator[Dict[str, Any]], 
                   chunk_size: int = 10000, source_file: str = None, 
                   file_type: str = None, source_system: str = None) -> Dict[str, Any]:
        """
        Bulk index events into ClickHouse
        
        Args:
            case_id: Case ID to associate with events
            events: Iterator of event dictionaries
            chunk_size: Number of events per batch insert
            source_file: Source file name
            file_type: File type (EVTX, NDJSON, CSV, IIS)
            source_system: Source hostname where artifact was collected
        
        Returns:
            dict: Indexing statistics
        """
        stats = {
            'indexed': 0,
            'failed': 0,
            'errors': []
        }
        
        batch = []
        now = datetime.now(timezone.utc)
        
        for event in events:
            try:
                # Build search blob from all string fields
                search_parts = []
                for key, value in event.items():
                    if isinstance(value, str) and value:
                        search_parts.append(f"{key}={value}")
                    elif isinstance(value, dict):
                        search_parts.append(json.dumps(value))
                
                # Prepare row for insertion
                row = {
                    'case_id': case_id,
                    'event_record_id': event.get('event_record_id', 0) or 0,
                    'event_id': str(event.get('event_id', '')),
                    'timestamp': self._parse_timestamp(event.get('timestamp') or event.get('system_time') or event.get('@timestamp')),
                    'system_time': self._parse_timestamp(event.get('system_time')),
                    'indexed_at': now,
                    'computer': event.get('computer', '') or '',
                    'channel': event.get('channel', '') or '',
                    'provider_name': event.get('provider_name', '') or '',
                    'level': event.get('level', '') or '',
                    'task': str(event.get('task', '')) or '',
                    'opcode': str(event.get('opcode', '')) or '',
                    'keywords': event.get('keywords', '') or '',
                    'username': event.get('username', '') or event.get('TargetUserName', '') or '',
                    'domain': event.get('domain', '') or event.get('TargetDomainName', '') or '',
                    'sid': event.get('sid', '') or event.get('TargetUserSid', '') or '',
                    'src_ip': event.get('src_ip', '') or event.get('IpAddress', '') or '',
                    'dst_ip': event.get('dst_ip', '') or '',
                    'src_port': int(event.get('src_port', 0) or 0),
                    'dst_port': int(event.get('dst_port', 0) or 0),
                    'ip_protocol': event.get('ip_protocol', '') or '',
                    'event_data': json.dumps(event.get('event_data', {}) or {}),
                    'search_blob': ' | '.join(search_parts),
                    'source_file': source_file or event.get('source_file', '') or '',
                    'source_system': source_system or event.get('source_system', '') or '',
                    'file_type': file_type or event.get('file_type', '') or '',
                    'log_source_type': event.get('log_source_type', '') or '',
                    'analyst_tagged': 1 if event.get('analyst_tagged') else 0,
                    'analyst_tagged_by': event.get('analyst_tagged_by', '') or '',
                    'noise_category': event.get('noise_category', '') or '',
                }
                
                batch.append(row)
                
                # Insert batch when full
                if len(batch) >= chunk_size:
                    self._insert_batch(batch)
                    stats['indexed'] += len(batch)
                    batch = []
                    
            except Exception as e:
                stats['failed'] += 1
                stats['errors'].append(str(e))
                logger.warning(f"Failed to process event: {e}")
        
        # Insert remaining events
        if batch:
            self._insert_batch(batch)
            stats['indexed'] += len(batch)
        
        logger.info(f"Indexed {stats['indexed']} events into case_{case_id}")
        return stats
    
    def _insert_batch(self, batch: List[Dict]):
        """Insert a batch of events"""
        if not batch:
            return
            
        columns = list(batch[0].keys())
        values = [[row[col] for col in columns] for row in batch]
        
        self.client.execute(
            f"INSERT INTO {self.database}.events ({', '.join(columns)}) VALUES",
            values
        )
    
    def _parse_timestamp(self, ts) -> datetime:
        """Parse various timestamp formats to datetime"""
        if ts is None:
            return datetime.now(timezone.utc)
        if isinstance(ts, datetime):
            return ts
        if isinstance(ts, (int, float)):
            return datetime.fromtimestamp(ts, tz=timezone.utc)
        if isinstance(ts, str):
            # Try various formats
            for fmt in [
                '%Y-%m-%dT%H:%M:%S.%fZ',
                '%Y-%m-%dT%H:%M:%SZ',
                '%Y-%m-%dT%H:%M:%S.%f',
                '%Y-%m-%dT%H:%M:%S',
                '%Y-%m-%d %H:%M:%S.%f',
                '%Y-%m-%d %H:%M:%S',
            ]:
                try:
                    return datetime.strptime(ts.replace('+00:00', 'Z').replace('Z', ''), fmt.replace('Z', ''))
                except ValueError:
                    continue
        return datetime.now(timezone.utc)
    
    def get_event_count(self, case_id: int) -> int:
        """Get total event count for a case"""
        try:
            result = self.client.execute(
                f"SELECT count() FROM {self.database}.events WHERE case_id = %(case_id)s",
                {'case_id': case_id}
            )
            return result[0][0] if result else 0
        except Exception as e:
            logger.error(f"Error getting event count: {e}")
            return 0
    
    def delete_case_events(self, case_id: int):
        """Delete all events for a case"""
        try:
            self.client.execute(
                f"ALTER TABLE {self.database}.events DELETE WHERE case_id = %(case_id)s",
                {'case_id': case_id}
            )
            logger.info(f"Deleted events for case {case_id}")
        except Exception as e:
            logger.error(f"Error deleting events: {e}")
            raise


class ClickHouseSearcher:
    """
    Handles Google-style search queries against ClickHouse
    Provides analyst-friendly search interface
    """
    
    def __init__(self, host: str = 'localhost', port: int = 9000,
                 database: str = 'casescope', user: str = 'default',
                 password: str = ''):
        """Initialize ClickHouse search client"""
        self.database = database
        self.client = Client(
            host=host,
            port=port,
            database=database,
            user=user,
            password=password
        )
    
    def search(self, case_id: int, query: str, limit: int = 100,
               offset: int = 0, sort_field: str = 'timestamp',
               sort_order: str = 'DESC') -> Dict[str, Any]:
        """
        Execute Google-style search query
        
        Args:
            case_id: Case ID to search in
            query: User's search query (Google-style)
            limit: Maximum results to return
            offset: Pagination offset
            sort_field: Field to sort by
            sort_order: ASC or DESC
        
        Returns:
            dict: {total: int, hits: list, query_time_ms: float}
        """
        import time
        start_time = time.time()
        
        # Parse the query
        where_clause, params = self.parse_search_query(query)
        params['case_id'] = case_id
        params['limit'] = limit
        params['offset'] = offset
        
        # Validate sort field
        valid_sort_fields = {'timestamp', 'event_id', 'computer', 'username', 'event_record_id'}
        if sort_field not in valid_sort_fields:
            sort_field = 'timestamp'
        if sort_order.upper() not in ('ASC', 'DESC'):
            sort_order = 'DESC'
        
        # Count total
        count_sql = f"""
            SELECT count()
            FROM {self.database}.events
            WHERE case_id = %(case_id)s AND {where_clause}
        """
        total = self.client.execute(count_sql, params)[0][0]
        
        # Get results
        search_sql = f"""
            SELECT 
                doc_id,
                event_record_id,
                event_id,
                timestamp,
                computer,
                channel,
                provider_name,
                username,
                src_ip,
                dst_ip,
                search_blob,
                source_file,
                source_system,
                event_data,
                analyst_tagged,
                noise_category
            FROM {self.database}.events
            WHERE case_id = %(case_id)s AND {where_clause}
            ORDER BY {sort_field} {sort_order}
            LIMIT %(limit)s OFFSET %(offset)s
        """
        
        rows = self.client.execute(search_sql, params)
        
        # Format results
        hits = []
        columns = ['doc_id', 'event_record_id', 'event_id', 'timestamp', 'computer',
                   'channel', 'provider_name', 'username', 'src_ip', 'dst_ip',
                   'search_blob', 'source_file', 'source_system', 'event_data',
                   'analyst_tagged', 'noise_category']
        
        # Extract search terms for highlighting
        search_terms = self._extract_search_terms(query)
        
        for row in rows:
            hit = dict(zip(columns, row))
            hit['_id'] = hit['doc_id']
            hit['timestamp'] = hit['timestamp'].isoformat() if hit['timestamp'] else None
            hit['event_data'] = json.loads(hit['event_data']) if hit['event_data'] else {}
            hit['analyst_tagged'] = bool(hit['analyst_tagged'])
            
            # Add highlighted snippet
            hit['_highlight'] = self._highlight_matches(hit['search_blob'], search_terms)
            
            hits.append(hit)
        
        query_time_ms = (time.time() - start_time) * 1000
        
        return {
            'total': total,
            'hits': hits,
            'query_time_ms': round(query_time_ms, 2)
        }
    
    def parse_search_query(self, query: str) -> Tuple[str, Dict]:
        """
        Parse Google-style search into ClickHouse SQL WHERE clause.
        
        Supports:
            word           → substring match (case-insensitive)
            "exact phrase" → exact substring match
            -exclude       → must NOT contain
            field:value    → exact field match
            field:value*   → field prefix match
            192.168.*      → wildcard in value
            word1 OR word2 → OR logic
            last:24h       → time filters
        
        Returns:
            (where_clause, params) - parameterized query for safety
        """
        if not query or not query.strip():
            return "1=1", {}
        
        # Handle OR at top level first
        if ' OR ' in query.upper():
            return self._parse_or_query(query)
        
        # Extract time filters first (removes them from query)
        query, time_conditions = self._extract_time_filters(query)
        
        conditions = list(time_conditions)
        params = {}
        param_idx = 0
        
        # Extract quoted phrases first
        phrases = re.findall(r'"([^"]+)"', query)
        query = re.sub(r'"[^"]+"', '', query)
        
        # Extract field:value pairs
        field_pairs = re.findall(r'(\w+):(\S+)', query)
        query = re.sub(r'\w+:\S+', '', query)
        
        # Extract exclusions (-term)
        exclusions = re.findall(r'-(\S+)', query)
        query = re.sub(r'-\S+', '', query)
        
        # Detect bare event IDs (4-5 digit numbers)
        event_ids = re.findall(r'\b([0-9]{4,5})\b(?!\.\d)', query)
        query = re.sub(r'\b[0-9]{4,5}\b(?!\.\d)', '', query)
        
        # Remaining are search terms
        terms = query.split()
        
        # Build conditions for phrases
        for phrase in phrases:
            param_name = f"p{param_idx}"
            conditions.append(f"positionCaseInsensitive(search_blob, %({param_name})s) > 0")
            params[param_name] = phrase
            param_idx += 1
        
        # Build conditions for regular terms
        for term in terms:
            if not term.strip():
                continue
            param_name = f"p{param_idx}"
            if '*' in term:
                # Wildcard → LIKE
                conditions.append(f"search_blob ILIKE %({param_name})s")
                params[param_name] = term.replace('*', '%')
            else:
                # Substring match
                conditions.append(f"positionCaseInsensitive(search_blob, %({param_name})s) > 0")
                params[param_name] = term
            param_idx += 1
        
        # Build conditions for field:value pairs
        for field, value in field_pairs:
            # Validate field name (prevents SQL injection)
            if field.lower() not in VALID_SEARCH_FIELDS:
                # Treat as search term instead
                param_name = f"p{param_idx}"
                conditions.append(f"positionCaseInsensitive(search_blob, %({param_name})s) > 0")
                params[param_name] = f"{field}:{value}"
                param_idx += 1
                continue
            
            param_name = f"p{param_idx}"
            if '*' in value:
                conditions.append(f"{field} ILIKE %({param_name})s")
                params[param_name] = value.replace('*', '%')
            else:
                conditions.append(f"{field} = %({param_name})s")
                params[param_name] = value
            param_idx += 1
        
        # Build conditions for event IDs
        for eid in event_ids:
            param_name = f"p{param_idx}"
            conditions.append(f"event_id = %({param_name})s")
            params[param_name] = eid
            param_idx += 1
        
        # Build conditions for exclusions
        for excl in exclusions:
            param_name = f"p{param_idx}"
            conditions.append(f"positionCaseInsensitive(search_blob, %({param_name})s) = 0")
            params[param_name] = excl
            param_idx += 1
        
        where_clause = " AND ".join(conditions) if conditions else "1=1"
        return where_clause, params
    
    def _parse_or_query(self, query: str) -> Tuple[str, Dict]:
        """Handle OR queries by splitting and combining"""
        or_parts = re.split(r'\s+OR\s+', query, flags=re.IGNORECASE)
        or_conditions = []
        all_params = {}
        offset = 0
        
        for part in or_parts:
            part = part.strip()
            if not part:
                continue
            
            # Parse each part, offsetting param names to avoid collision
            sub_where, sub_params = self._parse_single_query(part, offset)
            or_conditions.append(f"({sub_where})")
            all_params.update(sub_params)
            offset += len(sub_params)
        
        if not or_conditions:
            return "1=1", {}
        
        return " OR ".join(or_conditions), all_params
    
    def _parse_single_query(self, query: str, param_offset: int = 0) -> Tuple[str, Dict]:
        """Parse a single query part (no OR)"""
        # Extract time filters first
        query, time_conditions = self._extract_time_filters(query)
        
        conditions = list(time_conditions)
        params = {}
        param_idx = param_offset
        
        # Extract quoted phrases
        phrases = re.findall(r'"([^"]+)"', query)
        query = re.sub(r'"[^"]+"', '', query)
        
        # Extract field:value pairs
        field_pairs = re.findall(r'(\w+):(\S+)', query)
        query = re.sub(r'\w+:\S+', '', query)
        
        # Extract exclusions
        exclusions = re.findall(r'-(\S+)', query)
        query = re.sub(r'-\S+', '', query)
        
        # Detect event IDs
        event_ids = re.findall(r'\b([0-9]{4,5})\b(?!\.\d)', query)
        query = re.sub(r'\b[0-9]{4,5}\b(?!\.\d)', '', query)
        
        # Remaining terms
        terms = query.split()
        
        # Build conditions
        for phrase in phrases:
            param_name = f"p{param_idx}"
            conditions.append(f"positionCaseInsensitive(search_blob, %({param_name})s) > 0")
            params[param_name] = phrase
            param_idx += 1
        
        for term in terms:
            if not term.strip():
                continue
            param_name = f"p{param_idx}"
            if '*' in term:
                conditions.append(f"search_blob ILIKE %({param_name})s")
                params[param_name] = term.replace('*', '%')
            else:
                conditions.append(f"positionCaseInsensitive(search_blob, %({param_name})s) > 0")
                params[param_name] = term
            param_idx += 1
        
        for field, value in field_pairs:
            if field.lower() not in VALID_SEARCH_FIELDS:
                param_name = f"p{param_idx}"
                conditions.append(f"positionCaseInsensitive(search_blob, %({param_name})s) > 0")
                params[param_name] = f"{field}:{value}"
                param_idx += 1
                continue
            
            param_name = f"p{param_idx}"
            if '*' in value:
                conditions.append(f"{field} ILIKE %({param_name})s")
                params[param_name] = value.replace('*', '%')
            else:
                conditions.append(f"{field} = %({param_name})s")
                params[param_name] = value
            param_idx += 1
        
        for eid in event_ids:
            param_name = f"p{param_idx}"
            conditions.append(f"event_id = %({param_name})s")
            params[param_name] = eid
            param_idx += 1
        
        for excl in exclusions:
            param_name = f"p{param_idx}"
            conditions.append(f"positionCaseInsensitive(search_blob, %({param_name})s) = 0")
            params[param_name] = excl
            param_idx += 1
        
        where_clause = " AND ".join(conditions) if conditions else "1=1"
        return where_clause, params
    
    def _extract_time_filters(self, query: str) -> Tuple[str, List[str]]:
        """Extract and remove time filters from query"""
        time_conditions = []
        
        for pattern, formatter in TIME_PATTERNS:
            for match in re.finditer(pattern, query, re.IGNORECASE):
                time_conditions.append(formatter(match))
            query = re.sub(pattern, '', query, flags=re.IGNORECASE)
        
        return query.strip(), time_conditions
    
    def _extract_search_terms(self, query: str) -> List[str]:
        """Extract search terms for highlighting"""
        # Remove operators and extract meaningful terms
        query = re.sub(r'\b(OR|AND|NOT)\b', ' ', query, flags=re.IGNORECASE)
        query = re.sub(r'(last|after|before|today|yesterday|thisweek|lastweek):\S*', '', query, flags=re.IGNORECASE)
        query = re.sub(r'\w+:', '', query)  # Remove field: prefixes
        query = re.sub(r'-\S+', '', query)  # Remove exclusions
        
        # Get phrases and terms
        phrases = re.findall(r'"([^"]+)"', query)
        query = re.sub(r'"[^"]+"', '', query)
        terms = [t.strip() for t in query.split() if t.strip() and len(t.strip()) > 1]
        
        return phrases + terms
    
    def _highlight_matches(self, text: str, search_terms: List[str], max_length: int = 300) -> str:
        """Return snippet with highlighted matches"""
        if not text or not search_terms:
            return text[:max_length] + ('...' if len(text) > max_length else '')
        
        # Find first match position
        first_pos = len(text)
        for term in search_terms:
            pos = text.lower().find(term.lower())
            if pos != -1 and pos < first_pos:
                first_pos = pos
        
        # Extract context around match
        start = max(0, first_pos - 75)
        end = min(len(text), first_pos + 225)
        snippet = text[start:end]
        
        # Highlight terms with <mark> tags
        for term in search_terms:
            if not term:
                continue
            pattern = re.compile(re.escape(term), re.IGNORECASE)
            snippet = pattern.sub(f'<mark>{term}</mark>', snippet)
        
        prefix = '...' if start > 0 else ''
        suffix = '...' if end < len(text) else ''
        
        return f"{prefix}{snippet}{suffix}"
    
    def aggregate(self, case_id: int, group_by: str, 
                  query: str = None, limit: int = 50) -> List[Dict]:
        """
        Run aggregation query (counts by field)
        
        Args:
            case_id: Case ID
            group_by: Field to group by
            query: Optional filter query
            limit: Max buckets to return
        """
        # Validate group_by field
        valid_fields = {'event_id', 'computer', 'username', 'channel', 
                        'provider_name', 'source_file', 'file_type', 'src_ip', 'dst_ip'}
        if group_by not in valid_fields:
            group_by = 'event_id'
        
        params = {'case_id': case_id, 'limit': limit}
        
        where_clause = "1=1"
        if query:
            where_clause, query_params = self.parse_search_query(query)
            params.update(query_params)
        
        sql = f"""
            SELECT 
                {group_by} as field_value,
                count() as doc_count
            FROM {self.database}.events
            WHERE case_id = %(case_id)s AND {where_clause}
            GROUP BY {group_by}
            ORDER BY doc_count DESC
            LIMIT %(limit)s
        """
        
        rows = self.client.execute(sql, params)
        
        return [{'key': row[0], 'doc_count': row[1]} for row in rows]
    
    def timeline(self, case_id: int, interval: str = '1 HOUR',
                 query: str = None, start: datetime = None,
                 end: datetime = None) -> List[Dict]:
        """
        Generate timeline histogram
        
        Args:
            case_id: Case ID
            interval: Time interval (1 HOUR, 1 DAY, etc.)
            query: Optional filter query
            start: Start time
            end: End time
        """
        params = {'case_id': case_id}
        
        where_conditions = ["case_id = %(case_id)s"]
        
        if query:
            filter_clause, query_params = self.parse_search_query(query)
            if filter_clause != "1=1":
                where_conditions.append(filter_clause)
                params.update(query_params)
        
        if start:
            where_conditions.append("timestamp >= %(start)s")
            params['start'] = start
        if end:
            where_conditions.append("timestamp <= %(end)s")
            params['end'] = end
        
        where_clause = " AND ".join(where_conditions)
        
        # Validate interval
        valid_intervals = {'1 MINUTE', '5 MINUTE', '15 MINUTE', '1 HOUR', '1 DAY', '1 WEEK'}
        if interval.upper() not in valid_intervals:
            interval = '1 HOUR'
        
        sql = f"""
            SELECT 
                toStartOfInterval(timestamp, INTERVAL {interval}) as time_bucket,
                count() as doc_count
            FROM {self.database}.events
            WHERE {where_clause}
            GROUP BY time_bucket
            ORDER BY time_bucket ASC
        """
        
        rows = self.client.execute(sql, params)
        
        return [{'timestamp': row[0].isoformat(), 'count': row[1]} for row in rows]


def get_clickhouse_client() -> ClickHouseIndexer:
    """Get configured ClickHouse indexer instance"""
    from app.config import (
        CLICKHOUSE_HOST, CLICKHOUSE_PORT, CLICKHOUSE_DATABASE,
        CLICKHOUSE_USER, CLICKHOUSE_PASSWORD
    )
    return ClickHouseIndexer(
        host=CLICKHOUSE_HOST,
        port=CLICKHOUSE_PORT,
        database=CLICKHOUSE_DATABASE,
        user=CLICKHOUSE_USER,
        password=CLICKHOUSE_PASSWORD
    )


def get_clickhouse_searcher() -> ClickHouseSearcher:
    """Get configured ClickHouse searcher instance"""
    from app.config import (
        CLICKHOUSE_HOST, CLICKHOUSE_PORT, CLICKHOUSE_DATABASE,
        CLICKHOUSE_USER, CLICKHOUSE_PASSWORD
    )
    return ClickHouseSearcher(
        host=CLICKHOUSE_HOST,
        port=CLICKHOUSE_PORT,
        database=CLICKHOUSE_DATABASE,
        user=CLICKHOUSE_USER,
        password=CLICKHOUSE_PASSWORD
    )
