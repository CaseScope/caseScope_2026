"""
OpenSearch Indexer
Handles bulk indexing of events into OpenSearch
"""

import logging
from typing import List, Dict, Any, Iterator
from datetime import datetime
from opensearchpy import OpenSearch, helpers
from opensearchpy.exceptions import OpenSearchException

logger = logging.getLogger(__name__)


class OpenSearchIndexer:
    """
    Handles bulk indexing of events into OpenSearch
    """
    
    def __init__(self, host='localhost', port=9200, use_ssl=False):
        """
        Initialize OpenSearch connection
        
        Args:
            host: OpenSearch host
            port: OpenSearch port
            use_ssl: Whether to use SSL
        """
        self.client = OpenSearch(
            hosts=[{'host': host, 'port': port}],
            use_ssl=use_ssl,
            verify_certs=False,
            ssl_show_warn=False,
            timeout=30,
            max_retries=3,
            retry_on_timeout=True
        )
        
    def create_index_if_not_exists(self, index_name: str):
        """
        Create index if it doesn't exist
        
        Args:
            index_name: Name of index to create
        """
        if not self.client.indices.exists(index=index_name):
            # Index mapping for Windows events and NDJSON data
            from app.config import OPENSEARCH_TOTAL_FIELDS_LIMIT, OPENSEARCH_NESTED_FIELDS_LIMIT
            
            mapping = {
                'settings': {
                    'number_of_shards': 1,
                    'number_of_replicas': 0,
                    'refresh_interval': '5s',
                    'index': {
                        'mapping.total_fields.limit': OPENSEARCH_TOTAL_FIELDS_LIMIT,
                        'mapping.nested_fields.limit': OPENSEARCH_NESTED_FIELDS_LIMIT
                    }
                },
                'mappings': {
                    'properties': {
                        # EVTX fields
                        'event_record_id': {'type': 'long'},
                        'event_id': {'type': 'keyword'},
                        'timestamp': {'type': 'date'},
                        'system_time': {'type': 'date'},
                        'computer': {'type': 'keyword'},
                        'channel': {'type': 'keyword'},
                        'provider_name': {'type': 'keyword'},
                        'level': {'type': 'keyword'},
                        'task': {'type': 'keyword'},
                        'opcode': {'type': 'keyword'},
                        'keywords': {'type': 'keyword'},
                        'event_data': {'type': 'object', 'enabled': True},
                        'event_data_fields': {'type': 'object', 'enabled': True},
                        
                        # Normalized fields (works for all event types)
                        'normalized_timestamp': {'type': 'date'},
                        'normalized_computer': {'type': 'keyword'},
                        'normalized_event_id': {'type': 'keyword'},
                        'normalized_source_ip': {'type': 'ip'},
                        'normalized_dest_ip': {'type': 'ip'},
                        
                        # Search blob - flattened searchable text from all fields
                        'search_blob': {
                            'type': 'text',
                            'analyzer': 'standard'
                        },
                        
                        # Firewall/CSV-specific fields
                        'log_source_type': {'type': 'keyword'},
                        'row_number': {'type': 'long'},
                        'src_ip': {'type': 'ip'},
                        'dst_ip': {'type': 'ip'},
                        'src_port': {'type': 'integer'},
                        'dst_port': {'type': 'integer'},
                        'src_mac': {'type': 'keyword'},
                        'dst_mac': {'type': 'keyword'},
                        'src_zone': {'type': 'keyword'},
                        'dst_zone': {'type': 'keyword'},
                        'ip_protocol': {'type': 'keyword'},
                        'fw_action': {'type': 'keyword'},
                        'application': {'type': 'keyword'},
                        'priority': {'type': 'keyword'},
                        'access_rule': {'type': 'keyword'},
                        'rx_bytes': {'type': 'long'},
                        'tx_bytes': {'type': 'long'},
                        'extracted_ips': {'type': 'ip'},
                        'geo_blocked_country': {'type': 'keyword'},
                        'geo_blocked_ip': {'type': 'ip'},
                        'geo_block_direction': {'type': 'keyword'},
                        
                        # Metadata fields
                        'source_file': {'type': 'keyword'},
                        'file_type': {'type': 'keyword'},
                        'case_id': {'type': 'keyword'},
                        'indexed_at': {'type': 'date'},
                        
                        # Analyst tagging fields
                        'analyst_tagged': {'type': 'boolean'},
                        'analyst_tagged_by': {'type': 'keyword'},
                        'analyst_tagged_at': {'type': 'date'}
                    }
                }
            }
            
            self.client.indices.create(index=index_name, body=mapping)
            logger.info(f"Created index: {index_name}")
        else:
            logger.debug(f"Index already exists: {index_name}")
    
    def bulk_index(self, index_name: str, events: Iterator[Dict[str, Any]], 
                   chunk_size: int = 500, case_id: int = None, 
                   source_file: str = None, file_type: str = None) -> Dict[str, Any]:
        """
        Bulk index events into OpenSearch
        
        Args:
            index_name: Target index name
            events: Iterator of event dictionaries
            chunk_size: Number of events per bulk request
            case_id: Case ID to associate with events
            source_file: Source file name
            file_type: File type (EVTX, NDJSON, CSV, IIS)
        
        Returns:
            dict: Indexing statistics
        """
        # Ensure index exists
        self.create_index_if_not_exists(index_name)
        
        stats = {
            'indexed': 0,
            'failed': 0,
            'errors': []
        }
        
        def generate_actions():
            """Generate actions for bulk indexing"""
            for event in events:
                # Add metadata
                from datetime import datetime, timezone
                event['indexed_at'] = datetime.now(timezone.utc).isoformat()
                if case_id:
                    event['case_id'] = str(case_id)
                if source_file:
                    event['source_file'] = source_file
                if file_type:
                    event['file_type'] = file_type
                
                # Generate action
                yield {
                    '_index': index_name,
                    '_source': event
                }
        
        try:
            # Bulk index with helpers
            for success, info in helpers.parallel_bulk(
                self.client,
                generate_actions(),
                chunk_size=chunk_size,
                raise_on_error=False,
                raise_on_exception=False,
                max_chunk_bytes=10485760  # 10MB
            ):
                if success:
                    stats['indexed'] += 1
                else:
                    stats['failed'] += 1
                    stats['errors'].append(info)
                    logger.error(f"Failed to index event: {info}")
            
            # Refresh index to make documents searchable
            self.client.indices.refresh(index=index_name)
            
            logger.info(f"Indexed {stats['indexed']} events into {index_name}")
            
        except OpenSearchException as e:
            logger.error(f"OpenSearch bulk indexing error: {e}")
            stats['error'] = str(e)
        except Exception as e:
            logger.error(f"Unexpected error during bulk indexing: {e}")
            stats['error'] = str(e)
        
        return stats
    
    def get_event_count(self, index_name: str) -> int:
        """
        Get total event count in index
        
        Args:
            index_name: Index name
        
        Returns:
            int: Event count
        """
        try:
            result = self.client.count(index=index_name)
            return result['count']
        except Exception as e:
            logger.error(f"Error getting event count: {e}")
            return 0
    
    def delete_index(self, index_name: str):
        """
        Delete an index
        
        Args:
            index_name: Index to delete
        """
        try:
            if self.client.indices.exists(index=index_name):
                self.client.indices.delete(index=index_name)
                logger.info(f"Deleted index: {index_name}")
        except Exception as e:
            logger.error(f"Error deleting index: {e}")
