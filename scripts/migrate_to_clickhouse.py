#!/usr/bin/env python3
"""
Migrate Events from OpenSearch to ClickHouse

This script migrates all event data from OpenSearch indices to ClickHouse.
It preserves all data and creates the optimized ClickHouse schema.

Usage:
    python scripts/migrate_to_clickhouse.py [--case CASE_ID] [--dry-run]

Options:
    --case CASE_ID    Migrate only a specific case (default: all cases)
    --dry-run         Show what would be migrated without actually migrating
    --batch-size N    Events per batch (default: 10000)
    --verify          Verify counts after migration
"""

import os
import sys
import json
import argparse
import logging
from datetime import datetime, timezone
from typing import List, Dict, Any, Iterator

# Add app to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from opensearchpy import OpenSearch
from opensearchpy.helpers import scan
from clickhouse_driver import Client

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class OpenSearchToClickHouseMigrator:
    """Migrates event data from OpenSearch to ClickHouse"""
    
    def __init__(self, dry_run: bool = False, batch_size: int = 10000):
        self.dry_run = dry_run
        self.batch_size = batch_size
        
        # Load config
        from app.config import (
            OPENSEARCH_HOST, OPENSEARCH_PORT, OPENSEARCH_USE_SSL,
            CLICKHOUSE_HOST, CLICKHOUSE_PORT, CLICKHOUSE_DATABASE,
            CLICKHOUSE_USER, CLICKHOUSE_PASSWORD
        )
        
        # Initialize OpenSearch client
        self.os_client = OpenSearch(
            hosts=[{'host': OPENSEARCH_HOST, 'port': OPENSEARCH_PORT}],
            use_ssl=OPENSEARCH_USE_SSL,
            verify_certs=False,
            ssl_show_warn=False,
            timeout=60
        )
        
        # Initialize ClickHouse client
        self.ch_client = Client(
            host=CLICKHOUSE_HOST,
            port=CLICKHOUSE_PORT,
            database=CLICKHOUSE_DATABASE,
            user=CLICKHOUSE_USER,
            password=CLICKHOUSE_PASSWORD or '',
            settings={'max_block_size': 100000}
        )
        
        self.stats = {
            'indices_processed': 0,
            'events_migrated': 0,
            'events_failed': 0,
            'errors': []
        }
    
    def init_clickhouse_schema(self):
        """Create ClickHouse database and tables"""
        from app.config import CLICKHOUSE_DATABASE
        
        logger.info("Initializing ClickHouse schema...")
        
        if self.dry_run:
            logger.info("[DRY RUN] Would create ClickHouse schema")
            return
        
        # Create database
        self.ch_client.execute(f"CREATE DATABASE IF NOT EXISTS {CLICKHOUSE_DATABASE}")
        
        # Drop existing table to ensure clean schema
        self.ch_client.execute(f"DROP TABLE IF EXISTS {CLICKHOUSE_DATABASE}.events")
        
        # Create main events table
        self.ch_client.execute(f"""
            CREATE TABLE IF NOT EXISTS {CLICKHOUSE_DATABASE}.events (
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
        
        logger.info("ClickHouse schema created successfully")
    
    def get_opensearch_indices(self, case_id: int = None) -> List[str]:
        """Get list of OpenSearch indices to migrate"""
        try:
            indices = list(self.os_client.indices.get_alias(index="case_*").keys())
            
            if case_id:
                # Filter to specific case
                indices = [idx for idx in indices if idx.startswith(f"case_{case_id}")]
            
            # Sort for consistent processing
            indices.sort()
            
            logger.info(f"Found {len(indices)} indices to migrate: {indices}")
            return indices
            
        except Exception as e:
            logger.error(f"Error getting indices: {e}")
            return []
    
    def extract_case_id(self, index_name: str) -> int:
        """Extract case_id from index name like 'case_5' or 'case_5_browser'"""
        import re
        match = re.match(r'case_(\d+)', index_name)
        if match:
            return int(match.group(1))
        return 0
    
    def stream_opensearch_events(self, index_name: str) -> Iterator[Dict[str, Any]]:
        """Stream events from an OpenSearch index using scroll API"""
        try:
            # Use scan helper for efficient scrolling
            for hit in scan(
                self.os_client,
                index=index_name,
                query={"query": {"match_all": {}}},
                scroll='5m',
                size=1000,
                preserve_order=False
            ):
                yield hit
                
        except Exception as e:
            logger.error(f"Error streaming from {index_name}: {e}")
            self.stats['errors'].append(f"{index_name}: {str(e)}")
    
    def transform_event(self, hit: Dict, case_id: int) -> Dict[str, Any]:
        """Transform OpenSearch hit to ClickHouse row format"""
        source = hit.get('_source', {})
        
        # Build search blob from all string fields
        search_parts = []
        for key, value in source.items():
            if isinstance(value, str) and value:
                search_parts.append(f"{key}={value}")
            elif isinstance(value, dict):
                search_parts.append(json.dumps(value))
        
        # Parse timestamps
        timestamp = self._parse_timestamp(
            source.get('timestamp') or 
            source.get('system_time') or 
            source.get('@timestamp') or
            source.get('normalized_timestamp')
        )
        
        system_time = self._parse_timestamp(source.get('system_time'))
        indexed_at = self._parse_timestamp(source.get('indexed_at'))
        
        # Extract event data
        event_data = source.get('event_data', {})
        if isinstance(event_data, str):
            try:
                event_data = json.loads(event_data)
            except:
                event_data = {}
        
        return {
            'case_id': case_id,
            'doc_id': hit.get('_id', ''),
            'event_record_id': int(source.get('event_record_id', 0) or 0),
            'event_id': str(source.get('event_id', '') or ''),
            'timestamp': timestamp,
            'system_time': system_time,
            'indexed_at': indexed_at,
            'computer': source.get('computer', '') or source.get('normalized_computer', '') or '',
            'channel': source.get('channel', '') or '',
            'provider_name': source.get('provider_name', '') or '',
            'level': source.get('level', '') or '',
            'task': str(source.get('task', '') or ''),
            'opcode': str(source.get('opcode', '') or ''),
            'keywords': source.get('keywords', '') or '',
            'username': source.get('username', '') or source.get('TargetUserName', '') or '',
            'domain': source.get('domain', '') or source.get('TargetDomainName', '') or '',
            'sid': source.get('sid', '') or source.get('TargetUserSid', '') or '',
            'src_ip': source.get('src_ip', '') or source.get('IpAddress', '') or source.get('normalized_source_ip', '') or '',
            'dst_ip': source.get('dst_ip', '') or source.get('normalized_dest_ip', '') or '',
            'src_port': int(source.get('src_port', 0) or 0),
            'dst_port': int(source.get('dst_port', 0) or 0),
            'ip_protocol': source.get('ip_protocol', '') or '',
            'event_data': json.dumps(event_data),
            'search_blob': source.get('search_blob', '') or ' | '.join(search_parts),
            'source_file': source.get('source_file', '') or '',
            'source_system': source.get('source_system', '') or '',
            'file_type': source.get('file_type', '') or '',
            'log_source_type': source.get('log_source_type', '') or '',
            'analyst_tagged': 1 if source.get('analyst_tagged') else 0,
            'analyst_tagged_by': source.get('analyst_tagged_by', '') or '',
            'noise_category': source.get('noise_category', '') or '',
        }
    
    def _parse_timestamp(self, ts) -> datetime:
        """Parse various timestamp formats to datetime"""
        if ts is None:
            return datetime.now(timezone.utc)
        if isinstance(ts, datetime):
            return ts
        if isinstance(ts, (int, float)):
            try:
                return datetime.fromtimestamp(ts / 1000 if ts > 1e12 else ts, tz=timezone.utc)
            except:
                return datetime.now(timezone.utc)
        if isinstance(ts, str):
            # Try various formats
            for fmt in [
                '%Y-%m-%dT%H:%M:%S.%fZ',
                '%Y-%m-%dT%H:%M:%SZ',
                '%Y-%m-%dT%H:%M:%S.%f',
                '%Y-%m-%dT%H:%M:%S',
                '%Y-%m-%d %H:%M:%S.%f',
                '%Y-%m-%d %H:%M:%S',
                '%Y-%m-%dT%H:%M:%S.%f%z',
            ]:
                try:
                    ts_clean = ts.replace('+00:00', '').replace('Z', '')
                    fmt_clean = fmt.replace('Z', '').replace('%z', '')
                    return datetime.strptime(ts_clean, fmt_clean).replace(tzinfo=timezone.utc)
                except ValueError:
                    continue
        return datetime.now(timezone.utc)
    
    def insert_batch(self, batch: List[Dict]):
        """Insert a batch of events into ClickHouse"""
        if not batch or self.dry_run:
            return
        
        from app.config import CLICKHOUSE_DATABASE
        
        columns = list(batch[0].keys())
        values = [[row[col] for col in columns] for row in batch]
        
        self.ch_client.execute(
            f"INSERT INTO {CLICKHOUSE_DATABASE}.events ({', '.join(columns)}) VALUES",
            values
        )
    
    def migrate_index(self, index_name: str) -> int:
        """Migrate a single OpenSearch index to ClickHouse"""
        case_id = self.extract_case_id(index_name)
        
        if case_id == 0:
            logger.warning(f"Could not extract case_id from {index_name}, skipping")
            return 0
        
        logger.info(f"Migrating {index_name} (case_id={case_id})...")
        
        # Get document count
        try:
            count = self.os_client.count(index=index_name)['count']
            logger.info(f"  Source documents: {count:,}")
        except Exception as e:
            logger.error(f"  Error getting count: {e}")
            count = 0
        
        if self.dry_run:
            logger.info(f"  [DRY RUN] Would migrate {count:,} events")
            return count
        
        migrated = 0
        batch = []
        
        for hit in self.stream_opensearch_events(index_name):
            try:
                row = self.transform_event(hit, case_id)
                batch.append(row)
                
                if len(batch) >= self.batch_size:
                    self.insert_batch(batch)
                    migrated += len(batch)
                    logger.info(f"  Progress: {migrated:,}/{count:,} ({100*migrated/max(count,1):.1f}%)")
                    batch = []
                    
            except Exception as e:
                self.stats['events_failed'] += 1
                if len(self.stats['errors']) < 10:
                    self.stats['errors'].append(f"Event error: {str(e)[:100]}")
        
        # Insert remaining
        if batch:
            self.insert_batch(batch)
            migrated += len(batch)
        
        logger.info(f"  Completed: {migrated:,} events migrated")
        return migrated
    
    def verify_migration(self, case_id: int = None):
        """Verify event counts match between OpenSearch and ClickHouse"""
        from app.config import CLICKHOUSE_DATABASE
        
        logger.info("Verifying migration...")
        
        indices = self.get_opensearch_indices(case_id)
        
        for index_name in indices:
            case_id = self.extract_case_id(index_name)
            
            # OpenSearch count
            try:
                os_count = self.os_client.count(index=index_name)['count']
            except:
                os_count = 0
            
            # ClickHouse count for this case
            ch_result = self.ch_client.execute(
                f"SELECT count() FROM {CLICKHOUSE_DATABASE}.events WHERE case_id = %(case_id)s",
                {'case_id': case_id}
            )
            ch_count = ch_result[0][0] if ch_result else 0
            
            match = "✓" if os_count == ch_count else "✗"
            logger.info(f"  {index_name}: OpenSearch={os_count:,} ClickHouse={ch_count:,} {match}")
    
    def run(self, case_id: int = None, verify: bool = False):
        """Run the migration"""
        start_time = datetime.now()
        
        logger.info("=" * 60)
        logger.info("OpenSearch to ClickHouse Migration")
        logger.info("=" * 60)
        
        if self.dry_run:
            logger.info("MODE: Dry Run (no changes will be made)")
        
        # Initialize schema
        self.init_clickhouse_schema()
        
        # Get indices to migrate
        indices = self.get_opensearch_indices(case_id)
        
        if not indices:
            logger.warning("No indices found to migrate")
            return
        
        # Migrate each index
        for index_name in indices:
            count = self.migrate_index(index_name)
            self.stats['events_migrated'] += count
            self.stats['indices_processed'] += 1
        
        # Verify if requested
        if verify and not self.dry_run:
            self.verify_migration(case_id)
        
        # Summary
        duration = (datetime.now() - start_time).total_seconds()
        
        logger.info("=" * 60)
        logger.info("Migration Complete")
        logger.info("=" * 60)
        logger.info(f"  Indices processed: {self.stats['indices_processed']}")
        logger.info(f"  Events migrated: {self.stats['events_migrated']:,}")
        logger.info(f"  Events failed: {self.stats['events_failed']}")
        logger.info(f"  Duration: {duration:.1f} seconds")
        logger.info(f"  Rate: {self.stats['events_migrated']/max(duration,1):,.0f} events/sec")
        
        if self.stats['errors']:
            logger.warning("Errors encountered:")
            for error in self.stats['errors'][:10]:
                logger.warning(f"  - {error}")


def main():
    parser = argparse.ArgumentParser(description='Migrate OpenSearch events to ClickHouse')
    parser.add_argument('--case', type=int, help='Migrate only a specific case ID')
    parser.add_argument('--dry-run', action='store_true', help='Show what would be migrated')
    parser.add_argument('--batch-size', type=int, default=10000, help='Events per batch')
    parser.add_argument('--verify', action='store_true', help='Verify counts after migration')
    
    args = parser.parse_args()
    
    migrator = OpenSearchToClickHouseMigrator(
        dry_run=args.dry_run,
        batch_size=args.batch_size
    )
    
    migrator.run(case_id=args.case, verify=args.verify)


if __name__ == '__main__':
    main()
