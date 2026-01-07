"""
Pattern Detection Engine
Executes detection patterns and extracts findings from aggregation results
"""

import logging
from opensearchpy import OpenSearch

logger = logging.getLogger(__name__)


class PatternDetector:
    """
    Executes detection patterns against case data using OpenSearch aggregations
    """
    
    def __init__(self, opensearch_client: OpenSearch):
        """
        Initialize detector with OpenSearch client
        
        Args:
            opensearch_client: Configured OpenSearch client
        """
        self.client = opensearch_client
    
    def execute_pattern(self, pattern, case_id):
        """
        Execute single detection pattern against case
        
        Args:
            pattern: Pattern dictionary from patterns.py
            case_id: Case ID to analyze
        
        Returns:
            Finding dict if pattern matched, None otherwise
        """
        # Get target index
        index = pattern.get('target_index', 'case_{case_id}').format(case_id=case_id)
        query = pattern['query']
        
        try:
            # Add case_id filter if not already present
            if 'query' in query and 'bool' in query['query']:
                if 'must' not in query['query']['bool']:
                    query['query']['bool']['must'] = []
                
                # Check if case_id filter already exists
                has_case_filter = any(
                    'term' in clause and 'case_id' in clause.get('term', {})
                    for clause in query['query']['bool']['must']
                )
                
                if not has_case_filter:
                    query['query']['bool']['must'].append({'term': {'case_id': str(case_id)}})
            
            # Execute aggregation query
            result = self.client.search(
                index=index,
                body=query,
                request_timeout=60
            )
            
            # Check if pattern matched
            if self.has_findings(result, pattern):
                return self.extract_findings(pattern, result, case_id)
            
            return None
            
        except Exception as e:
            logger.error(f"Pattern {pattern['id']} ({pattern['name']}) failed: {e}")
            return {
                'pattern_id': pattern['id'],
                'pattern_name': pattern['name'],
                'error': str(e),
                'status': 'error'
            }
    
    def has_findings(self, result, pattern):
        """
        Check if aggregation result shows suspicious activity
        
        Args:
            result: OpenSearch aggregation result
            pattern: Pattern definition
        
        Returns:
            True if findings exist, False otherwise
        """
        # Check for direct hits (patterns with size > 0)
        if result['hits']['total']['value'] > 0 and pattern['query'].get('size', 0) > 0:
            return True
        
        # Check aggregations
        if 'aggregations' not in result:
            return False
        
        # If any aggregation has buckets, we have findings
        for agg_name, agg_data in result['aggregations'].items():
            if 'buckets' in agg_data and len(agg_data['buckets']) > 0:
                return True
        
        return False
    
    def extract_findings(self, pattern, result, case_id):
        """
        Extract actionable findings from aggregation result
        
        Args:
            pattern: Pattern definition
            result: OpenSearch result
            case_id: Case ID
        
        Returns:
            Finding dictionary with entities and statistics
        """
        finding = {
            'pattern_id': pattern['id'],
            'pattern_name': pattern['name'],
            'description': pattern['description'],
            'mitre_technique': pattern['mitre_technique'],
            'mitre_tactic': pattern['mitre_tactic'],
            'severity': pattern['severity'],
            'data_source': pattern['data_source'],
            'total_events': result['hits']['total']['value'],
            'entities': [],
            'statistics': {}
        }
        
        # Extract entities from aggregations
        if 'aggregations' in result:
            finding['entities'] = self._extract_entities(result['aggregations'])
            finding['statistics'] = self._extract_statistics(result['aggregations'])
        
        # Get sample events if query returned documents
        if result['hits']['total']['value'] > 0 and len(result['hits']['hits']) > 0:
            finding['sample_events'] = [
                self._simplify_event(hit['_source'])
                for hit in result['hits']['hits'][:5]
            ]
        else:
            finding['sample_events'] = []
        
        return finding
    
    def _extract_entities(self, aggregations):
        """
        Extract entities (IPs, users, hosts) from aggregation buckets
        
        Args:
            aggregations: Aggregation results
        
        Returns:
            List of entity dictionaries
        """
        entities = []
        
        for agg_name, agg_data in aggregations.items():
            if 'buckets' in agg_data:
                entity_type = agg_name.replace('by_', '').replace('_', ' ')
                
                for bucket in agg_data['buckets'][:20]:  # Top 20 entities
                    entity = {
                        'type': entity_type,
                        'value': bucket['key'],
                        'count': bucket['doc_count']
                    }
                    
                    # Extract nested aggregations
                    for sub_agg_name, sub_agg_data in bucket.items():
                        if sub_agg_name.startswith('_'):
                            continue
                        
                        if isinstance(sub_agg_data, dict):
                            if 'value' in sub_agg_data:
                                entity[sub_agg_name] = sub_agg_data['value']
                            elif 'buckets' in sub_agg_data:
                                entity[sub_agg_name] = [
                                    {'key': b['key'], 'count': b['doc_count']}
                                    for b in sub_agg_data['buckets'][:5]
                                ]
                    
                    entities.append(entity)
        
        return entities
    
    def _extract_statistics(self, aggregations):
        """Extract statistical summaries from aggregations"""
        stats = {}
        
        for agg_name, agg_data in aggregations.items():
            if 'buckets' in agg_data:
                stats[agg_name] = {
                    'bucket_count': len(agg_data['buckets']),
                    'total_docs': sum(b['doc_count'] for b in agg_data['buckets'])
                }
        
        return stats
    
    def _simplify_event(self, event):
        """
        Simplify event for display (extract key fields only)
        
        Args:
            event: Full event document
        
        Returns:
            Simplified event with key fields
        """
        simplified = {
            'timestamp': event.get('normalized_timestamp') or event.get('@timestamp'),
            'host': event.get('normalized_computer') or event.get('host', {}).get('name'),
            'source_file': event.get('source_file')
        }
        
        # Add process fields if available
        if 'process' in event:
            simplified['process'] = {
                'name': event['process'].get('name'),
                'command_line': event['process'].get('command_line', '')[:200],  # Truncate long commands
                'user': event['process'].get('user', {}).get('name'),
                'parent': event['process'].get('parent', {}).get('name')
            }
        
        # Add network fields if available
        if 'src_ip' in event:
            simplified['network'] = {
                'src_ip': event.get('src_ip'),
                'dst_ip': event.get('dst_ip'),
                'dst_port': event.get('dst_port'),
                'user': event.get('user_name')
            }
        
        # Add event log fields if available
        if 'normalized_event_id' in event:
            simplified['event_id'] = event.get('normalized_event_id')
            simplified['event_data'] = event.get('event_data_fields', {})
        
        return simplified
    
    def get_evidence_events(self, pattern, case_id, entity_value, limit=10):
        """
        Get sample evidence events for a specific entity
        
        Args:
            pattern: Pattern definition
            case_id: Case ID
            entity_value: Specific entity to get events for (e.g., IP, username, hostname)
            limit: Maximum events to return
        
        Returns:
            List of evidence events
        """
        # Build evidence query based on pattern's main query
        index = pattern.get('target_index', 'case_{case_id}').format(case_id=case_id)
        
        # Clone the pattern query but set size and remove aggregations
        evidence_query = {
            'query': pattern['query']['query'],
            'size': limit,
            'sort': [{'normalized_timestamp': 'desc'}]
        }
        
        try:
            result = self.client.search(
                index=index,
                body=evidence_query,
                request_timeout=30
            )
            
            return [self._simplify_event(hit['_source']) for hit in result['hits']['hits']]
            
        except Exception as e:
            logger.error(f"Failed to get evidence events: {e}")
            return []

