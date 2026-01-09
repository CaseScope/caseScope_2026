"""
Event Store Abstraction Layer

Provides a unified interface for event storage and search,
supporting both ClickHouse and OpenSearch backends.

Usage:
    from app.utils.event_store import get_event_store
    
    store = get_event_store()
    results = store.search(case_id=5, query="mimikatz last:24h")
"""

import logging
from typing import Dict, List, Any, Iterator, Optional
from datetime import datetime
from abc import ABC, abstractmethod

logger = logging.getLogger(__name__)


class EventStore(ABC):
    """Abstract base class for event storage backends"""
    
    @abstractmethod
    def search(self, case_id: int, query: str, limit: int = 100,
               offset: int = 0, sort_field: str = 'timestamp',
               sort_order: str = 'DESC') -> Dict[str, Any]:
        """
        Execute search query
        
        Returns:
            {total: int, hits: list, query_time_ms: float}
        """
        pass
    
    @abstractmethod
    def get_event_count(self, case_id: int) -> int:
        """Get total event count for a case"""
        pass
    
    @abstractmethod
    def aggregate(self, case_id: int, group_by: str,
                  query: str = None, limit: int = 50) -> List[Dict]:
        """Run aggregation query"""
        pass
    
    @abstractmethod
    def timeline(self, case_id: int, interval: str = '1 HOUR',
                 query: str = None, start: datetime = None,
                 end: datetime = None) -> List[Dict]:
        """Generate timeline histogram"""
        pass
    
    @abstractmethod
    def bulk_index(self, case_id: int, events: Iterator[Dict[str, Any]],
                   chunk_size: int = 1000, source_file: str = None,
                   file_type: str = None, source_system: str = None) -> Dict[str, Any]:
        """Bulk index events"""
        pass
    
    @abstractmethod
    def delete_case_events(self, case_id: int):
        """Delete all events for a case"""
        pass
    
    @abstractmethod
    def get_event_by_id(self, case_id: int, doc_id: str) -> Optional[Dict]:
        """Get a single event by document ID"""
        pass


class ClickHouseEventStore(EventStore):
    """ClickHouse implementation of EventStore"""
    
    def __init__(self):
        from config import (
            CLICKHOUSE_HOST, CLICKHOUSE_PORT, CLICKHOUSE_DATABASE,
            CLICKHOUSE_USER, CLICKHOUSE_PASSWORD
        )
        from clickhouse_client import ClickHouseSearcher, ClickHouseIndexer
        
        self.searcher = ClickHouseSearcher(
            host=CLICKHOUSE_HOST,
            port=CLICKHOUSE_PORT,
            database=CLICKHOUSE_DATABASE,
            user=CLICKHOUSE_USER,
            password=CLICKHOUSE_PASSWORD or ''
        )
        self.indexer = ClickHouseIndexer(
            host=CLICKHOUSE_HOST,
            port=CLICKHOUSE_PORT,
            database=CLICKHOUSE_DATABASE,
            user=CLICKHOUSE_USER,
            password=CLICKHOUSE_PASSWORD or ''
        )
        self.database = CLICKHOUSE_DATABASE
    
    def search(self, case_id: int, query: str, limit: int = 100,
               offset: int = 0, sort_field: str = 'timestamp',
               sort_order: str = 'DESC') -> Dict[str, Any]:
        return self.searcher.search(
            case_id=case_id,
            query=query,
            limit=limit,
            offset=offset,
            sort_field=sort_field,
            sort_order=sort_order
        )
    
    def get_event_count(self, case_id: int) -> int:
        return self.indexer.get_event_count(case_id)
    
    def aggregate(self, case_id: int, group_by: str,
                  query: str = None, limit: int = 50) -> List[Dict]:
        return self.searcher.aggregate(
            case_id=case_id,
            group_by=group_by,
            query=query,
            limit=limit
        )
    
    def timeline(self, case_id: int, interval: str = '1 HOUR',
                 query: str = None, start: datetime = None,
                 end: datetime = None) -> List[Dict]:
        return self.searcher.timeline(
            case_id=case_id,
            interval=interval,
            query=query,
            start=start,
            end=end
        )
    
    def bulk_index(self, case_id: int, events: Iterator[Dict[str, Any]],
                   chunk_size: int = 10000, source_file: str = None,
                   file_type: str = None, source_system: str = None) -> Dict[str, Any]:
        return self.indexer.bulk_index(
            case_id=case_id,
            events=events,
            chunk_size=chunk_size,
            source_file=source_file,
            file_type=file_type,
            source_system=source_system
        )
    
    def delete_case_events(self, case_id: int):
        self.indexer.delete_case_events(case_id)
    
    def get_event_by_id(self, case_id: int, doc_id: str) -> Optional[Dict]:
        result = self.indexer.client.execute(
            f"""
            SELECT *
            FROM {self.database}.events
            WHERE case_id = %(case_id)s AND doc_id = %(doc_id)s
            LIMIT 1
            """,
            {'case_id': case_id, 'doc_id': doc_id}
        )
        if result:
            # Get column names from description
            columns = [
                'case_id', 'doc_id', 'event_record_id', 'event_id', 'timestamp',
                'system_time', 'indexed_at', 'computer', 'channel', 'provider_name',
                'level', 'task', 'opcode', 'keywords', 'username', 'domain', 'sid',
                'src_ip', 'dst_ip', 'src_port', 'dst_port', 'ip_protocol',
                'event_data', 'search_blob', 'source_file', 'source_system',
                'file_type', 'log_source_type', 'analyst_tagged', 'analyst_tagged_by',
                'analyst_tagged_at', 'noise_category'
            ]
            row = result[0]
            event = {}
            for i, col in enumerate(columns):
                if i < len(row):
                    event[col] = row[i]
            return event
        return None


class OpenSearchEventStore(EventStore):
    """OpenSearch implementation of EventStore (legacy)"""
    
    def __init__(self):
        from config import OPENSEARCH_HOST, OPENSEARCH_PORT, OPENSEARCH_USE_SSL
        from opensearchpy import OpenSearch
        
        self.client = OpenSearch(
            hosts=[{'host': OPENSEARCH_HOST, 'port': OPENSEARCH_PORT}],
            use_ssl=OPENSEARCH_USE_SSL,
            verify_certs=False,
            ssl_show_warn=False,
            timeout=30
        )
    
    def _get_index_name(self, case_id: int) -> str:
        return f"case_{case_id}"
    
    def search(self, case_id: int, query: str, limit: int = 100,
               offset: int = 0, sort_field: str = 'timestamp',
               sort_order: str = 'DESC') -> Dict[str, Any]:
        import time
        start_time = time.time()
        
        index_name = self._get_index_name(case_id)
        
        # Build OpenSearch query
        if query and query.strip():
            os_query = {
                "query_string": {
                    "query": query,
                    "default_field": "search_blob",
                    "analyze_wildcard": True
                }
            }
        else:
            os_query = {"match_all": {}}
        
        body = {
            "query": os_query,
            "from": offset,
            "size": limit,
            "sort": [{sort_field: {"order": sort_order.lower()}}]
        }
        
        try:
            response = self.client.search(index=index_name, body=body)
            
            hits = []
            for hit in response['hits']['hits']:
                event = hit['_source']
                event['_id'] = hit['_id']
                event['doc_id'] = hit['_id']
                hits.append(event)
            
            query_time_ms = (time.time() - start_time) * 1000
            
            return {
                'total': response['hits']['total']['value'],
                'hits': hits,
                'query_time_ms': round(query_time_ms, 2)
            }
        except Exception as e:
            logger.error(f"OpenSearch search error: {e}")
            return {'total': 0, 'hits': [], 'query_time_ms': 0}
    
    def get_event_count(self, case_id: int) -> int:
        try:
            index_name = self._get_index_name(case_id)
            result = self.client.count(index=index_name)
            return result['count']
        except Exception as e:
            logger.error(f"Error getting event count: {e}")
            return 0
    
    def aggregate(self, case_id: int, group_by: str,
                  query: str = None, limit: int = 50) -> List[Dict]:
        index_name = self._get_index_name(case_id)
        
        body = {
            "size": 0,
            "aggs": {
                "by_field": {
                    "terms": {
                        "field": f"{group_by}.keyword" if group_by not in ['event_id'] else group_by,
                        "size": limit
                    }
                }
            }
        }
        
        if query:
            body["query"] = {"query_string": {"query": query, "default_field": "search_blob"}}
        
        try:
            response = self.client.search(index=index_name, body=body)
            buckets = response.get('aggregations', {}).get('by_field', {}).get('buckets', [])
            return [{'key': b['key'], 'doc_count': b['doc_count']} for b in buckets]
        except Exception as e:
            logger.error(f"OpenSearch aggregation error: {e}")
            return []
    
    def timeline(self, case_id: int, interval: str = '1 HOUR',
                 query: str = None, start: datetime = None,
                 end: datetime = None) -> List[Dict]:
        index_name = self._get_index_name(case_id)
        
        # Convert interval format
        interval_map = {
            '1 MINUTE': '1m', '5 MINUTE': '5m', '15 MINUTE': '15m',
            '1 HOUR': '1h', '1 DAY': '1d', '1 WEEK': '1w'
        }
        os_interval = interval_map.get(interval.upper(), '1h')
        
        body = {
            "size": 0,
            "aggs": {
                "timeline": {
                    "date_histogram": {
                        "field": "timestamp",
                        "fixed_interval": os_interval
                    }
                }
            }
        }
        
        filters = []
        if start:
            filters.append({"range": {"timestamp": {"gte": start.isoformat()}}})
        if end:
            filters.append({"range": {"timestamp": {"lte": end.isoformat()}}})
        if query:
            filters.append({"query_string": {"query": query, "default_field": "search_blob"}})
        
        if filters:
            body["query"] = {"bool": {"must": filters}}
        
        try:
            response = self.client.search(index=index_name, body=body)
            buckets = response.get('aggregations', {}).get('timeline', {}).get('buckets', [])
            return [{'timestamp': b['key_as_string'], 'count': b['doc_count']} for b in buckets]
        except Exception as e:
            logger.error(f"OpenSearch timeline error: {e}")
            return []
    
    def bulk_index(self, case_id: int, events: Iterator[Dict[str, Any]],
                   chunk_size: int = 500, source_file: str = None,
                   file_type: str = None, source_system: str = None) -> Dict[str, Any]:
        from opensearch_indexer import OpenSearchIndexer
        from config import OPENSEARCH_HOST, OPENSEARCH_PORT, OPENSEARCH_USE_SSL
        
        indexer = OpenSearchIndexer(
            host=OPENSEARCH_HOST,
            port=OPENSEARCH_PORT,
            use_ssl=OPENSEARCH_USE_SSL
        )
        
        index_name = self._get_index_name(case_id)
        return indexer.bulk_index(
            index_name=index_name,
            events=events,
            chunk_size=chunk_size,
            case_id=case_id,
            source_file=source_file,
            file_type=file_type,
            source_system=source_system
        )
    
    def delete_case_events(self, case_id: int):
        index_name = self._get_index_name(case_id)
        try:
            if self.client.indices.exists(index=index_name):
                self.client.indices.delete(index=index_name)
                logger.info(f"Deleted index: {index_name}")
        except Exception as e:
            logger.error(f"Error deleting index: {e}")
    
    def get_event_by_id(self, case_id: int, doc_id: str) -> Optional[Dict]:
        index_name = self._get_index_name(case_id)
        try:
            result = self.client.get(index=index_name, id=doc_id)
            event = result['_source']
            event['_id'] = result['_id']
            event['doc_id'] = result['_id']
            return event
        except Exception as e:
            logger.error(f"Error getting event: {e}")
            return None


# Singleton instance
_event_store = None


def get_event_store() -> EventStore:
    """
    Get the configured event store instance.
    
    Returns ClickHouseEventStore or OpenSearchEventStore based on
    EVENT_STORAGE_BACKEND config setting.
    """
    global _event_store
    
    if _event_store is None:
        from config import EVENT_STORAGE_BACKEND
        
        if EVENT_STORAGE_BACKEND == 'clickhouse':
            logger.info("Using ClickHouse event store")
            _event_store = ClickHouseEventStore()
        else:
            logger.info("Using OpenSearch event store")
            _event_store = OpenSearchEventStore()
    
    return _event_store


def reset_event_store():
    """Reset the event store singleton (for testing)"""
    global _event_store
    _event_store = None
