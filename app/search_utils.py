"""
Search Utilities Module
Modular functions for OpenSearch event searching with pagination, sorting, filtering
"""

import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple, Set

logger = logging.getLogger(__name__)

# =============================================================================
# v1.43.5: OPTIMIZED SEARCH FIELDS
# =============================================================================
# Performance optimization: Search key fields instead of all 8,759 fields
# 
# PRIMARY: search_blob (contains ALL event data flattened)
#   - v1.43.5: Now created for ALL event types (EVTX, EDR, CSV, JSON, IIS)
#   - Single field = fastest search + 100% coverage
#   - NOTE: Existing data needs reindex to populate search_blob for EDR/CSV
#
# FALLBACK: EDR/forensic fields for backwards compatibility
#   - These fields are searched for events that don't have search_blob yet
#   - After full reindex, these could be removed (search_blob covers all)
#
# Benchmarks on 10.5M event case:
#   - All fields (8,759): 10-15 seconds per search
#   - Targeted fields: 400-600ms per search (20-30x faster)
# =============================================================================
SEARCH_FIELDS = [
    # PRIMARY: Universal search blob (ALL event data flattened)
    # After v1.43.5, this contains EVERYTHING for all event types
    "search_blob",
    
    # FALLBACK: EDR fields (for events without search_blob - pre-v1.43.5 data)
    "process.command_line",
    "process.executable",
    "process.name",
    "process.parent.command_line",
    "process.parent.executable",
    "process.user_logon.ip",
    "user.name",
    "host.hostname",
    "host.ip",
    "source.ip",
    "destination.ip",
    "client.ip",
    "file.path",
    "file.name",
    "url.full",
    "message",
    
    # FALLBACK: Forensic fields (extracted during EVTX processing)
    "forensic_CommandLine",
    "forensic_ParentCommandLine", 
    "forensic_ProcessName",
    "forensic_IpAddress",
    "forensic_TargetUserName",
    "forensic_SubjectUserName",
    "forensic_WorkstationName",
    
    # Normalized fields
    "normalized_computer",
]


def build_search_query(
    search_text: str = "",
    filter_type: str = "all",
    date_range: str = "all",
    custom_date_start: Optional[datetime] = None,
    custom_date_end: Optional[datetime] = None,
    file_types: Optional[List[str]] = None,
    additional_filters: Optional[Dict] = None,
    tagged_event_ids: Optional[List[str]] = None,
    latest_event_timestamp: Optional[datetime] = None,
    hidden_filter: str = "hide",
    status_filter: Optional[List[str]] = None,
    exclude_event_ids: Optional[Set[str]] = None,
    include_only_event_ids: Optional[Set[str]] = None
) -> Dict[str, Any]:
    """
    Build OpenSearch query DSL based on search parameters
    
    Args:
        search_text: Free-text search query
        filter_type: 'all', 'sigma', 'ioc', 'ioc_2plus', 'ioc_3plus', 'sigma_and_ioc', 'ai_evidence'
        date_range: '24h', '7d', '30d', 'custom', 'all'
        custom_date_start: Custom start date
        custom_date_end: Custom end date
        file_types: List of file types to include ['EVTX', 'EDR', 'JSON', 'CSV']
        additional_filters: Additional field filters (e.g., {'EventID': '4624'})
        tagged_event_ids: List of event IDs for 'ai_evidence' filter
        latest_event_timestamp: Latest event timestamp in case (for relative date filters)
        hidden_filter: 'hide' (exclude hidden), 'show' (include all), 'only' (only hidden)
        status_filter: List of statuses to include ['new', 'hunted', 'confirmed', 'noise']. Default: ['new', 'hunted', 'confirmed']
        exclude_event_ids: Set of event IDs to exclude (legacy, prefer status_filter)
        include_only_event_ids: Set of event IDs to include (legacy, prefer status_filter)
    
    Returns:
        OpenSearch query DSL dictionary
    """
    query = {
        "bool": {
            "must": [],
            "filter": [],
            "must_not": []
        }
    }
    
    # Status-based filtering (NEW - v1.46.0)
    # Filter by event_status field directly in OpenSearch (fast, no DB lookup)
    if status_filter is not None:
        # Default to showing new, hunted, confirmed (not noise)
        if not status_filter:
            status_filter = ['new', 'hunted', 'confirmed']
        
        # If all statuses are included, no filter needed
        all_statuses = {'new', 'noise', 'hunted', 'confirmed'}
        if set(status_filter) != all_statuses:
            # 'new' means events WITHOUT a status field (or status='new')
            # Other statuses have explicit field values
            
            if 'new' in status_filter and len(status_filter) == 1:
                # Only show 'new' events (no status field or status='new')
                query["bool"]["must_not"].extend([
                    {"term": {"event_status": "noise"}},
                    {"term": {"event_status": "hunted"}},
                    {"term": {"event_status": "confirmed"}}
                ])
            elif 'new' not in status_filter:
                # Exclude 'new' events, show only specific statuses
                explicit_statuses = [s for s in status_filter if s != 'new']
                if explicit_statuses:
                    query["bool"]["filter"].append({
                        "terms": {"event_status": explicit_statuses}
                    })
            else:
                # 'new' + other statuses: show 'new' OR specific statuses
                # But explicitly exclude statuses that are NOT in the filter
                explicit_statuses = [s for s in status_filter if s != 'new']
                excluded_statuses = [s for s in all_statuses if s not in status_filter and s != 'new']
                
                should_clauses = []
                
                # Include events with no status field or status not set
                should_clauses.append({
                    "bool": {
                        "must_not": [
                            {"exists": {"field": "event_status"}}
                        ]
                    }
                })
                
                # Include events with explicit statuses
                if explicit_statuses:
                    should_clauses.append({
                        "terms": {"event_status": explicit_statuses}
                    })
                
                query["bool"]["filter"].append({
                    "bool": {
                        "should": should_clauses,
                        "minimum_should_match": 1
                    }
                })
                
                # CRITICAL FIX: Explicitly exclude statuses not in filter (e.g., noise)
                if excluded_statuses:
                    for excluded in excluded_statuses:
                        query["bool"]["must_not"].append({
                            "term": {"event_status": excluded}
                        })
    
    # Legacy: Exclude specific event IDs (deprecated - use status_filter instead)
    if exclude_event_ids and len(exclude_event_ids) > 0:
        # Only use if status_filter not provided (backward compatibility)
        if status_filter is None:
            query["bool"]["must_not"].append({
                "ids": {"values": list(exclude_event_ids)}
            })
    
    # Text search - hybrid approach for performance + UX
    # v1.43.7: Optimized search with fields parameter for speed
    # 
    # HISTORY:
    #   - v1.27.13: smart_wildcard() for partial matching (nltest → nltest.exe)
    #   - v1.43.5: simple_query_string broke partial matching
    #   - v1.43.6: query_string without fields - correct but 10s+ searches
    # 
    # PROBLEM: 
    #   - Wildcards need query_string (simple_query_string wildcards weak)
    #   - query_string without 'fields' searches ALL 4,500 fields → 10+ seconds
    #   - query_string with 'fields' + wildcards fails on hyphens (DESKTOP-951CN7O)
    #   - Hyphens tokenize: DESKTOP-951CN7O → ['desktop', '951cn7o']
    #
    # SOLUTION: Route based on term characteristics
    #   1. Hyphenated terms: Use simple_query_string (tokenizes, fast)
    #   2. Simple terms: Wrap in wildcards, use query_string with fields (fast)
    #   3. Advanced queries: Use appropriate query with fields
    #
    # Benchmark: 10s → 0.5s per search
    if search_text:
        import re
        
        # Detect query characteristics
        has_hyphen_term = bool(re.search(r'\b\w+-\w+\b', search_text))  # word-word pattern
        has_operators = any(op in search_text for op in [' AND ', ' OR ', ' NOT ', '(', ')'])
        has_wildcards = '*' in search_text or '?' in search_text
        has_field_query = ':' in search_text
        has_quotes = '"' in search_text
        
        is_simple_term = not (has_operators or has_wildcards or has_field_query or has_quotes)
        
        if is_simple_term and has_hyphen_term:
            # Hyphenated simple term (DESKTOP-951CN7O)
            # Use simple_query_string - tokenizes hyphens correctly
            # Don't wrap in wildcards - tokenization handles partial matching
            query["bool"]["must"].append({
                "simple_query_string": {
                    "query": search_text,
                    "fields": ["search_blob"] + SEARCH_FIELDS[1:],  # search_blob + fallbacks
                    "default_operator": "AND"
                }
            })
        elif is_simple_term:
            # Simple term without hyphens (nltest, powershell)
            # Wrap in wildcards for partial matching (nltest → *nltest*)
            # Use query_string with fields for performance
            query["bool"]["must"].append({
                "query_string": {
                    "query": f"*{search_text.strip()}*",
                    "fields": ["search_blob"],
                    "default_operator": "AND",
                    "analyze_wildcard": True,
                    "lenient": True
                }
            })
        elif has_wildcards or has_operators:
            # Advanced query with wildcards or operators
            # Use query_string with fields
            # For operators, wrap non-wildcard terms in wildcards
            def wrap_terms(text):
                """Wrap plain terms in wildcards, preserve operators/quotes/fields."""
                parts = re.split(r'(\s+AND\s+|\s+OR\s+|\s+NOT\s+|\(|\)|"[^"]*")', text)
                result = []
                for part in parts:
                    p = part.strip()
                    if not p or p in ['AND', 'OR', 'NOT', '(', ')']:
                        result.append(part)
                    elif p.startswith('"') or ':' in p or '*' in p or '?' in p:
                        result.append(part)
                    elif '-' in p:
                        # Hyphenated - don't wrap (tokenization will handle)
                        result.append(part)
                    else:
                        result.append(f"*{p}*")
                return ''.join(result)
            
            search_query = wrap_terms(search_text)
            query["bool"]["must"].append({
                "query_string": {
                    "query": search_query,
                    "fields": ["search_blob"],
                    "default_operator": "AND",
                    "analyze_wildcard": True,
                    "lenient": True
                }
            })
        else:
            # Field query or quoted phrase - use as-is
            query["bool"]["must"].append({
                "query_string": {
                    "query": search_text,
                    "fields": ["search_blob"] + SEARCH_FIELDS[1:],
                    "default_operator": "AND",
                    "analyze_wildcard": True,
                    "lenient": True
                }
            })
    
    # Filter by SIGMA/IOC tags
    if filter_type == "sigma":
        query["bool"]["filter"].append({"term": {"has_sigma": True}})
    elif filter_type == "ioc":
        query["bool"]["filter"].append({"term": {"has_ioc": True}})
    elif filter_type == "ioc_2plus":
        # Events with 2 or more IOC matches
        query["bool"]["filter"].append({"range": {"ioc_count": {"gte": 2}}})
    elif filter_type == "ioc_3plus":
        # Events with 3 or more IOC matches
        query["bool"]["filter"].append({"range": {"ioc_count": {"gte": 3}}})
    elif filter_type == "sigma_and_ioc":
        # Require BOTH SIGMA and IOC (AND logic, not OR)
        query["bool"]["filter"].append({
            "bool": {
                "must": [
                    {"term": {"has_sigma": True}},
                    {"term": {"has_ioc": True}}
                ]
            }
        })
    elif filter_type == "tagged" or filter_type == "ai_evidence" or filter_type == "excluded":
        # Filter to only show events that have timeline tags, AI evidence IDs, or are excluded
        if tagged_event_ids and len(tagged_event_ids) > 0:
            query["bool"]["filter"].append({
                "ids": {
                    "values": tagged_event_ids
                }
            })
        else:
            # No matching events - return empty result set
            query["bool"]["filter"].append({"term": {"_id": "no_matching_events_found"}})
    
    # Filter by file types (with structure-based detection for backward compatibility)
    if file_types and len(file_types) > 0 and len(file_types) < 5:
        # Only filter if not all 5 types are selected (EVTX, EDR, JSON, CSV, IIS)
        should_clauses = []
        
        # Events with source_file_type field matching selected types (use .keyword for exact match)
        should_clauses.append({"terms": {"source_file_type.keyword": file_types}})
        
        # For events without source_file_type, detect by structure
        for file_type in file_types:
            if file_type == 'EVTX':
                # EVTX: has System field or Event.System structure
                should_clauses.append({
                    "bool": {
                        "must": [
                            {"bool": {"must_not": {"exists": {"field": "source_file_type"}}}},
                            {"bool": {
                                "should": [
                                    {"exists": {"field": "System"}},
                                    {"exists": {"field": "Event.System"}}
                                ]
                            }}
                        ]
                    }
                })
            elif file_type == 'EDR':
                # EDR: has @timestamp AND (process OR host OR ecs OR event.kind)
                should_clauses.append({
                    "bool": {
                        "must": [
                            {"bool": {"must_not": {"exists": {"field": "source_file_type"}}}},
                            {"exists": {"field": "@timestamp"}},
                            {"bool": {
                                "should": [
                                    {"exists": {"field": "process"}},
                                    {"exists": {"field": "host"}},
                                    {"exists": {"field": "ecs"}},
                                    {"exists": {"field": "event.kind"}}
                                ]
                            }}
                        ]
                    }
                })
            elif file_type == 'CSV':
                # CSV: has row_number field
                should_clauses.append({
                    "bool": {
                        "must": [
                            {"bool": {"must_not": {"exists": {"field": "source_file_type"}}}},
                            {"exists": {"field": "row_number"}}
                        ]
                    }
                })
            elif file_type == 'IIS':
                # v1.14.0: IIS: has source_file_type='IIS' field
                should_clauses.append({
                    "bool": {
                        "must": [
                            {"term": {"source_file_type.keyword": "IIS"}}
                        ]
                    }
                })
            elif file_type == 'JSON':
                # JSON: no source_file_type AND not EVTX/EDR/CSV structure
                should_clauses.append({
                    "bool": {
                        "must": [
                            {"bool": {"must_not": {"exists": {"field": "source_file_type"}}}},
                            {"bool": {"must_not": {"exists": {"field": "System"}}}},
                            {"bool": {"must_not": {"exists": {"field": "Event.System"}}}},
                            {"bool": {"must_not": {"exists": {"field": "row_number"}}}},
                            {"bool": {
                                "should": [
                                    {"bool": {"must_not": {"exists": {"field": "@timestamp"}}}},
                                    {"bool": {
                                        "must_not": [
                                            {"exists": {"field": "process"}},
                                            {"exists": {"field": "host"}},
                                            {"exists": {"field": "ecs"}},
                                            {"exists": {"field": "event.kind"}}
                                        ]
                                    }}
                                ]
                            }}
                        ]
                    }
                })
        
        query["bool"]["filter"].append({
            "bool": {
                "should": should_clauses,
                "minimum_should_match": 1
            }
        })
    
    # Date range filtering (using normalized_timestamp for compatibility with all file types)
    if date_range != "all":
        date_filter = None
        
        if date_range in ["24h", "7d", "30d"]:
            # Calculate relative date based on latest event timestamp (not current system time)
            reference_time = latest_event_timestamp if latest_event_timestamp else datetime.utcnow()
            
            if date_range == "24h":
                start_date = reference_time - timedelta(hours=24)
            elif date_range == "7d":
                start_date = reference_time - timedelta(days=7)
            elif date_range == "30d":
                start_date = reference_time - timedelta(days=30)
            
            date_filter = {
                "range": {
                    "normalized_timestamp": {
                        "gte": start_date.isoformat(),
                        "lte": reference_time.isoformat()
                    }
                }
            }
            logger.info(f"[SEARCH] Date filter: {date_range} from {start_date} to {reference_time}")
        
        elif date_range == "custom" and custom_date_start and custom_date_end:
            date_filter = {
                "range": {
                    "normalized_timestamp": {
                        "gte": custom_date_start.isoformat(),
                        "lte": custom_date_end.isoformat()
                    }
                }
            }
            logger.info(f"[SEARCH] Custom date filter: {custom_date_start} to {custom_date_end}")
        
        if date_filter:
            query["bool"]["filter"].append(date_filter)
    
    # Additional field filters
    if additional_filters:
        for field, value in additional_filters.items():
            query["bool"]["filter"].append({
                "term": {field: value}
            })
    
    # Hidden events filter
    # Include only specific event IDs (status-based filtering)
    if include_only_event_ids is not None and len(include_only_event_ids) > 0:
        query["bool"]["filter"].append({
            "ids": {"values": list(include_only_event_ids)}
        })
        logger.debug(f"[SEARCH] Including only {len(include_only_event_ids)} events by status")
    
    # Hidden filter (legacy - still used for is_hidden field in OpenSearch)
    if hidden_filter == "hide":
        # Exclude hidden events - only show events where is_hidden doesn't exist OR is_hidden is false
        query["bool"]["filter"].append({
            "bool": {
                "should": [
                    {"bool": {"must_not": [{"exists": {"field": "is_hidden"}}]}},  # Field doesn't exist
                    {"term": {"is_hidden": False}}  # Or explicitly false
                ],
                "minimum_should_match": 1
            }
        })
        logger.debug("[SEARCH] Excluding hidden events from results")
    elif hidden_filter == "only":
        # Show ONLY hidden events
        query["bool"]["filter"].append({
            "term": {"is_hidden": True}
        })
        logger.debug("[SEARCH] Showing only hidden events")
    # If hidden_filter == "show", no filter is applied (show all events)
    
    return {"query": query}


def execute_search(
    opensearch_client,
    index_name: str,
    query_dsl: Dict[str, Any],
    page: int = 1,
    per_page: int = 50,
    sort_field: Optional[str] = None,
    sort_order: str = "desc"
) -> Tuple[List[Dict], int, Dict]:
    """
    Execute OpenSearch query with pagination and sorting
    
    Args:
        opensearch_client: OpenSearch client instance
        index_name: Index or index pattern to search
        query_dsl: Query DSL dictionary from build_search_query()
        page: Page number (1-based)
        per_page: Results per page
        sort_field: Field to sort by
        sort_order: 'asc' or 'desc'
    
    Returns:
        Tuple of (results_list, total_count, aggregations_dict)
    """
    from_offset = (page - 1) * per_page
    
    search_body = {
        **query_dsl,
        "from": from_offset,
        "size": per_page,
        "track_total_hits": True  # Track ALL hits, not just first 10k
    }
    
    # Add sorting
    if sort_field:
        # Handle nested fields
        sort_config = {
            sort_field: {
                "order": sort_order,
                "unmapped_type": "long"  # Handle missing fields gracefully
            }
        }
        
        # Add .keyword for text fields to enable sorting
        # Exclude fields that are already indexed as sortable types (dates, numbers, keywords)
        sortable_fields = [
            "System.TimeCreated.@attributes.SystemTime",
            "System.EventID",
            "System.EventRecordID",
            "normalized_timestamp",  # ISO 8601 string, sortable as-is
            "normalized_event_id",   # String, sortable as-is
            "normalized_computer"    # String, sortable as-is
        ]
        
        if not sort_field.endswith(".keyword") and sort_field not in sortable_fields:
            sort_field_keyword = f"{sort_field}.keyword"
            sort_config = {
                sort_field_keyword: {
                    "order": sort_order,
                    "unmapped_type": "keyword"
                }
            }
        
        search_body["sort"] = [sort_config]
    else:
        # Default sort by timestamp (with fallback for missing field)
        search_body["sort"] = [
            {
                "System.TimeCreated.@attributes.SystemTime": {
                    "order": "desc",
                    "unmapped_type": "date"
                }
            }
        ]
    
    try:
        response = opensearch_client.search(
            index=index_name,
            body=search_body
        )
        
        results = []
        for hit in response['hits']['hits']:
            results.append({
                '_id': hit['_id'],
                '_index': hit['_index'],
                '_source': hit['_source']
            })
        
        # Get total count - handle both exact and approximate counts
        total_info = response['hits']['total']
        if isinstance(total_info, dict):
            total_count = total_info['value']
            relation = total_info.get('relation', 'eq')
            if relation == 'gte':
                # Approximate count (hit track_total_hits limit)
                logger.warning(f"[SEARCH] Total count is approximate (>= {total_count})")
        else:
            total_count = int(total_info)
        
        aggregations = response.get('aggregations', {})
        
        total_pages = (total_count + per_page - 1) // per_page
        logger.info(f"[SEARCH] Found {total_count} results, page {page}/{total_pages}, from={from_offset}")
        
        return results, total_count, aggregations
        
    except Exception as e:
        logger.error(f"[SEARCH] Error executing search: {e}")
        return [], 0, {}


def execute_search_scroll(
    opensearch_client,
    index_name: str,
    query_dsl: Dict[str, Any],
    batch_size: int = 1000,
    sort_field: Optional[str] = None,
    sort_order: str = "desc",
    max_results: Optional[int] = None
) -> Tuple[List[Dict], int]:
    """
    Execute OpenSearch query using Scroll API for unlimited results
    
    This function bypasses the max_result_window limitation (default 10,000) by using
    the Scroll API, which is designed for efficiently retrieving large result sets.
    
    Args:
        opensearch_client: OpenSearch client instance
        index_name: Index or index pattern to search
        query_dsl: Query DSL dictionary from build_search_query()
        batch_size: Number of results per scroll batch (default 1000)
        sort_field: Field to sort by
        sort_order: 'asc' or 'desc'
        max_results: Optional maximum number of results to return (for testing)
    
    Returns:
        Tuple of (results_list, total_count)
    
    Example:
        results, total = execute_search_scroll(
            client, 
            "case_123_*", 
            query_dsl,
            batch_size=2000
        )
        # Returns ALL matching results, not limited to 10k
    """
    scroll_timeout = '5m'  # Keep scroll context alive for 5 minutes
    all_results = []
    scroll_id = None
    
    try:
        # Initial search with scroll parameter
        search_body = {
            **query_dsl,
            "size": batch_size,
            "track_total_hits": True
        }
        
        # Add sorting (same logic as execute_search)
        if sort_field:
            sort_config = {
                sort_field: {
                    "order": sort_order,
                    "unmapped_type": "long"
                }
            }
            
            # Add .keyword for text fields
            sortable_fields = [
                "System.TimeCreated.@attributes.SystemTime",
                "System.EventID",
                "System.EventRecordID",
                "normalized_timestamp",
                "normalized_event_id",
                "normalized_computer"
            ]
            
            if not sort_field.endswith(".keyword") and sort_field not in sortable_fields:
                sort_field_keyword = f"{sort_field}.keyword"
                sort_config = {
                    sort_field_keyword: {
                        "order": sort_order,
                        "unmapped_type": "keyword"
                    }
                }
            
            search_body["sort"] = [sort_config]
        else:
            # Default sort by timestamp
            search_body["sort"] = [
                {
                    "System.TimeCreated.@attributes.SystemTime": {
                        "order": "desc",
                        "unmapped_type": "date"
                    }
                }
            ]
        
        logger.info(f"[SCROLL_EXPORT] Starting scroll export from {index_name}")
        
        # Initial scroll request
        response = opensearch_client.search(
            index=index_name,
            body=search_body,
            scroll=scroll_timeout
        )
        
        # Get total count
        total_info = response['hits']['total']
        if isinstance(total_info, dict):
            total_count = total_info['value']
            relation = total_info.get('relation', 'eq')
            if relation == 'gte':
                logger.warning(f"[SCROLL_EXPORT] Total count is approximate (>= {total_count})")
        else:
            total_count = int(total_info)
        
        logger.info(f"[SCROLL_EXPORT] Total documents to export: {total_count}")
        
        # Get scroll_id for subsequent requests
        scroll_id = response['_scroll_id']
        
        # Collect results from first batch
        hits = response['hits']['hits']
        all_results.extend(hits)
        
        batch_num = 1
        logger.info(f"[SCROLL_EXPORT] Batch {batch_num}: Retrieved {len(hits)} results (total: {len(all_results)})")
        
        # Continue scrolling until no more results
        while len(hits) > 0:
            # Check max_results limit if specified
            if max_results and len(all_results) >= max_results:
                logger.info(f"[SCROLL_EXPORT] Reached max_results limit: {max_results}")
                all_results = all_results[:max_results]
                break
            
            # Scroll to next batch
            response = opensearch_client.scroll(
                scroll_id=scroll_id,
                scroll=scroll_timeout
            )
            
            scroll_id = response['_scroll_id']
            hits = response['hits']['hits']
            
            if len(hits) > 0:
                all_results.extend(hits)
                batch_num += 1
                logger.info(f"[SCROLL_EXPORT] Batch {batch_num}: Retrieved {len(hits)} results (total: {len(all_results)})")
        
        logger.info(f"[SCROLL_EXPORT] Export complete: {len(all_results)} total results in {batch_num} batches")
        
        return all_results, total_count
        
    except Exception as e:
        logger.error(f"[SCROLL_EXPORT] Error during scroll export: {e}")
        raise
        
    finally:
        # Always clear scroll context to free resources
        if scroll_id:
            try:
                opensearch_client.clear_scroll(scroll_id=scroll_id)
                logger.info(f"[SCROLL_EXPORT] Cleared scroll context")
            except Exception as e:
                logger.warning(f"[SCROLL_EXPORT] Failed to clear scroll context: {e}")


def extract_event_fields(event_source: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extract and normalize key fields from event for display
    Uses normalized_* fields added during ingestion for consistency
    
    Args:
        event_source: OpenSearch document _source
    
    Returns:
        Dictionary with normalized fields
    """
    fields = {}
    
    # Use normalized fields from ingestion (added by event_normalization.py)
    # These are consistent regardless of original event structure
    
    # Event ID - use normalized field first
    # Initialize variables for legacy detection
    event_id_raw = None
    is_evtx_structure = False
    
    if 'normalized_event_id' in event_source and event_source['normalized_event_id']:
        fields['event_id'] = event_source['normalized_event_id']
    else:
        # Fallback to legacy detection for older indexed events
        # Check for EVTX structure: System.EventID or Event.System.EventID
        if 'System' in event_source and 'EventID' in event_source.get('System', {}):
            event_id_raw = event_source['System']['EventID']
            is_evtx_structure = True
        elif 'Event' in event_source and isinstance(event_source['Event'], dict):
            if 'System' in event_source['Event'] and 'EventID' in event_source['Event']['System']:
                event_id_raw = event_source['Event']['System']['EventID']
                is_evtx_structure = True
        
        # Extract the actual event ID value
        if event_id_raw:
            if isinstance(event_id_raw, dict):
                fields['event_id'] = str(event_id_raw.get('#text', event_id_raw.get('text', 'EVTX')))
            else:
                fields['event_id'] = str(event_id_raw)
        else:
            # Try alternative event ID fields for non-EVTX files
            for alt in ['event_id', 'eventid', 'EventID', 'id', 'event.id']:
                if alt in event_source:
                    fields['event_id'] = str(event_source[alt])
                    break
    
    # Determine source type based on structure and file type
    if is_evtx_structure:
        # This is EVTX data (either native or EVTX->JSON import)
        fields['source_type'] = 'EVTX'
        if 'event_id' not in fields:
            fields['event_id'] = 'EVTX'
    elif (
        'event_type' in event_source or 
        event_source.get('source', {}).get('type') == 'ndjson' or
        # EDR NDJSON detection: has nested event.kind/category/type structure
        (isinstance(event_source.get('event'), dict) and 
         any(k in event_source['event'] for k in ['kind', 'category', 'type', 'action'])) or
        # Common EDR fields: @timestamp, process, host with ECS structure
        ('@timestamp' in event_source and 
         ('process' in event_source or 'host' in event_source or 'agent' in event_source)) or
        # ECS version indicator
        'ecs' in event_source
    ):
        # EDR/NDJSON file (Elastic Common Schema or similar)
        fields['source_type'] = 'EDR'
        if 'event_id' not in fields:
            fields['event_id'] = 'EDR'
    elif (event_source.get('_csv_source') or 
          event_source.get('source_type') == 'csv' or
          event_source.get('source_file_type') == 'CSV'):
        # CSV file (firewall logs, etc.)
        fields['source_type'] = 'CSV'
        if 'event_id' not in fields:
            fields['event_id'] = 'CSV'
    elif event_source.get('source_file_type') == 'IIS':
        # IIS log file (v1.14.0)
        fields['source_type'] = 'IIS'
        if 'event_id' not in fields:
            fields['event_id'] = 'IIS'
    elif isinstance(event_source, dict) and len(event_source) > 0:
        # Generic JSON file
        fields['source_type'] = 'JSON'
        if 'event_id' not in fields:
            fields['event_id'] = 'JSON'
    else:
        fields['source_type'] = 'UNKNOWN'
        if 'event_id' not in fields:
            fields['event_id'] = 'UNKNOWN'
    
    # Timestamp - use normalized field first (added during ingestion)
    if 'normalized_timestamp' in event_source and event_source['normalized_timestamp']:
        try:
            fields['timestamp'] = datetime.fromisoformat(event_source['normalized_timestamp'])
        except:
            fields['timestamp'] = None
    else:
        # Legacy fallback for older indexed events
        fields['timestamp'] = None
    
    # Computer name - use normalized field first (added during ingestion)
    if 'normalized_computer' in event_source and event_source['normalized_computer']:
        fields['computer_name'] = event_source['normalized_computer']
    else:
        # Legacy fallback for older indexed events
        fields['computer_name'] = 'Unknown'
    
    # Friendly description - multiple fallbacks
    description = event_source.get('event_title') or event_source.get('event_description')
    
    if not description:
        # Try to build description from available fields
        desc_fields = [
            'description', 'Description', 'message', 'Message',
            'event_name', 'EventName', 'event_type', 'EventType',
            'action', 'Action', 'activity', 'Activity'
        ]
        for field in desc_fields:
            if field in event_source and event_source[field]:
                description = str(event_source[field])
                break
    
    # EDR NDJSON specific description building
    if not description and fields.get('source_type') == 'EDR':
        # Priority 1: Use process.command_line (most descriptive)
        if 'process' in event_source and isinstance(event_source['process'], dict):
            proc = event_source['process']
            if 'command_line' in proc:
                description = proc['command_line']
        
        # Priority 2: Build from event metadata if no parent command line
        if not description:
            edr_desc_parts = []
            
            # Extract event category, kind, and type
            if isinstance(event_source.get('event'), dict):
                event_info = event_source['event']
                if 'category' in event_info:
                    edr_desc_parts.append(f"{event_info['category']}")
                if 'action' in event_info:
                    edr_desc_parts.append(f"action: {event_info['action']}")
                elif 'type' in event_info:
                    evt_type = event_info['type']
                    if isinstance(evt_type, list) and evt_type:
                        edr_desc_parts.append(f"type: {evt_type[0]}")
                    elif isinstance(evt_type, str):
                        edr_desc_parts.append(f"type: {evt_type}")
            
            # Add process information if available
            if 'process' in event_source:
                proc = event_source['process']
                if isinstance(proc, dict):
                    if 'name' in proc:
                        edr_desc_parts.append(f"process: {proc['name']}")
                    elif 'executable' in proc:
                        # Extract just the filename from full path
                        exec_path = proc['executable']
                        if isinstance(exec_path, str) and ('\\' in exec_path or '/' in exec_path):
                            exec_name = exec_path.split('\\')[-1].split('/')[-1]
                            edr_desc_parts.append(f"process: {exec_name}")
            
            # Add user information if available
            if 'user' in event_source:
                user = event_source['user']
                if isinstance(user, dict) and 'name' in user:
                    edr_desc_parts.append(f"user: {user['name']}")
            
            if edr_desc_parts:
                description = ' | '.join(edr_desc_parts)
    
    # CSV/Firewall specific description building
    if not description and fields.get('source_type') == 'CSV':
        csv_desc_parts = []
        
        # Priority 1: Use 'Event' field (SonicWall event type)
        if 'Event' in event_source and event_source['Event']:
            csv_desc_parts.append(str(event_source['Event']))
        
        # Add 'Message' or 'Notes' for additional context
        if 'Message' in event_source and event_source['Message']:
            msg = str(event_source['Message'])
            if msg and msg != str(event_source.get('Event', '')):
                csv_desc_parts.append(msg[:100])  # Limit length
        elif 'Notes' in event_source and event_source['Notes']:
            notes = str(event_source['Notes'])
            if notes and notes != str(event_source.get('Event', '')):
                csv_desc_parts.append(notes[:100])
        
        # Add source/dest IPs for firewall logs
        src_ip = event_source.get('Src. IP') or event_source.get('Source IP')
        dst_ip = event_source.get('Dst. IP') or event_source.get('Destination IP')
        if src_ip or dst_ip:
            ip_info = []
            if src_ip:
                ip_info.append(f"src: {src_ip}")
            if dst_ip:
                ip_info.append(f"dst: {dst_ip}")
            csv_desc_parts.append(' → '.join(ip_info))
        
        if csv_desc_parts:
            description = ' | '.join(csv_desc_parts)
    
    # IIS specific description building (v1.14.0)
    if not description and fields.get('source_type') == 'IIS':
        iis_desc_parts = []
        
        # Priority 1: cs-uri-query (query string parameters - most descriptive for web requests)
        if 'cs-uri-query' in event_source and event_source['cs-uri-query']:
            query = str(event_source['cs-uri-query'])
            if query and query != '-':  # IIS uses '-' for empty fields
                iis_desc_parts.append(f"Query: {query[:150]}")  # Limit length
        
        # Priority 2: cs-uri-stem (URL path)
        if not iis_desc_parts and 'cs-uri-stem' in event_source and event_source['cs-uri-stem']:
            uri_stem = str(event_source['cs-uri-stem'])
            if uri_stem and uri_stem != '-':
                iis_desc_parts.append(f"Path: {uri_stem}")
        
        # Add HTTP method and status for context
        method_status = []
        if 'cs-method' in event_source and event_source['cs-method']:
            method = str(event_source['cs-method'])
            if method and method != '-':
                method_status.append(method)
        
        if 'sc-status' in event_source and event_source['sc-status']:
            status = str(event_source['sc-status'])
            if status and status != '-':
                method_status.append(f"Status {status}")
        
        if method_status:
            iis_desc_parts.append(' '.join(method_status))
        
        # Add client IP for additional context
        if 'c-ip' in event_source and event_source['c-ip']:
            client_ip = str(event_source['c-ip'])
            if client_ip and client_ip != '-':
                iis_desc_parts.append(f"Client: {client_ip}")
        
        if iis_desc_parts:
            description = ' | '.join(iis_desc_parts)
    
    # EVTX specific description building (for events without friendly descriptions)
    if not description and fields.get('source_type') == 'EVTX':
        evtx_desc_parts = []
        
        # Try to extract meaningful EVTX fields from Event.System or System structure
        system_data = None
        if 'System' in event_source:
            system_data = event_source['System']
        elif 'Event' in event_source and isinstance(event_source.get('Event'), dict):
            if 'System' in event_source['Event']:
                system_data = event_source['Event']['System']
        
        if system_data:
            # Get channel/provider name
            channel = system_data.get('Channel')
            provider = None
            if 'Provider' in system_data:
                prov_data = system_data['Provider']
                if isinstance(prov_data, dict):
                    provider = prov_data.get('#attributes', {}).get('Name') or prov_data.get('@attributes', {}).get('Name')
                elif isinstance(prov_data, str):
                    provider = prov_data
            
            # Build description from available info
            if channel:
                # Simplify channel name: Microsoft-Windows-Security-Auditing → Security-Auditing
                channel_short = channel.replace('Microsoft-Windows-', '').replace('%4', '/').replace('%2', '-')
                evtx_desc_parts.append(f"Channel: {channel_short}")
            elif provider:
                evtx_desc_parts.append(f"Provider: {provider}")
            
            # Add task/opcode if available
            if 'Task' in system_data and system_data['Task']:
                evtx_desc_parts.append(f"Task: {system_data['Task']}")
            if 'Opcode' in system_data and system_data['Opcode']:
                evtx_desc_parts.append(f"Opcode: {system_data['Opcode']}")
        
        # Try Event.EventData for additional context
        event_data = None
        if 'EventData' in event_source:
            event_data = event_source['EventData']
        elif 'Event' in event_source and isinstance(event_source.get('Event'), dict):
            if 'EventData' in event_source['Event']:
                event_data = event_source['Event']['EventData']
        
        if event_data and isinstance(event_data, dict):
            # Look for common meaningful fields
            for key in ['SubjectUserName', 'TargetUserName', 'ProcessName', 'ImagePath', 'CommandLine']:
                if key in event_data and event_data[key]:
                    value = str(event_data[key])[:50]  # Limit length
                    evtx_desc_parts.append(f"{key}: {value}")
                    break  # Only add one to keep description concise
        
        if evtx_desc_parts:
            description = ' | '.join(evtx_desc_parts)
    
    if not description:
        # Last resort: show first few meaningful fields
        skip_fields = {
            'opensearch_key', '_id', '_index', '_score', 
            'has_sigma', 'has_ioc', 'ioc_count',  # Skip IOC metadata fields
            'is_hidden', 'hidden_by', 'hidden_at',  # Skip hidden metadata fields
            'normalized_timestamp', 'normalized_computer', 'normalized_event_id',  # Skip normalized fields
            'source_file_type',  # Skip this metadata field
            'source_file', 'file_id',  # CRITICAL (v1.13.7): Skip v1.13.1 consolidated index metadata fields
            'row_number', 'System',  # Skip IIS metadata fields (v1.14.0)
            'date', 'time',  # Skip IIS raw date/time fields (v1.14.0) - we use combined normalized_timestamp
            'search_blob'  # Skip search_blob field (v1.16.26) - internal search optimization, not for display
        }
        meaningful = []
        for key, val in event_source.items():
            # v1.19.4: Skip forensic_ fields (extracted from EventData/UserData) - they're for searching, not display
            if key not in skip_fields and not key.startswith('_') and not key.startswith('forensic_'):
                if isinstance(val, (str, int, float)) and str(val).strip():
                    meaningful.append(f"{key}={val}")
                    if len(meaningful) >= 3:
                        break
        description = ', '.join(meaningful) if meaningful else 'No description available'
    
    fields['description'] = description[:200]  # Limit length
    
    # Source filename - extract from opensearch_key
    # Format: "case1_filename" -> extract "filename"
    if 'opensearch_key' in event_source and event_source['opensearch_key']:
        opensearch_key = str(event_source['opensearch_key'])
        # Remove "case<id>_" prefix to get filename
        if '_' in opensearch_key:
            parts = opensearch_key.split('_', 1)
            if len(parts) > 1:
                fields['source_file'] = parts[1]
            else:
                fields['source_file'] = opensearch_key
        else:
            fields['source_file'] = opensearch_key
    else:
        fields['source_file'] = 'Unknown'
    
    # SIGMA and IOC flags
    fields['has_sigma'] = bool(event_source.get('has_sigma'))
    fields['has_ioc'] = bool(event_source.get('has_ioc'))
    
    # IOC details for displaying specific IOC types in UI (v1.16.x)
    fields['ioc_details'] = event_source.get('ioc_details', [])
    fields['matched_iocs'] = event_source.get('matched_iocs', [])
    
    return fields


def get_event_detail(opensearch_client, index_name: str, event_id: str) -> Optional[Dict]:
    """
    Retrieve single event by ID
    
    Args:
        opensearch_client: OpenSearch client instance
        index_name: Index name
        event_id: Document ID
    
    Returns:
        Event document or None
    """
    try:
        response = opensearch_client.get(index=index_name, id=event_id)
        return {
            '_id': response['_id'],
            '_index': response['_index'],
            '_source': response['_source']
        }
    except Exception as e:
        logger.error(f"[SEARCH] Error retrieving event {event_id}: {e}")
        return None


def format_event_for_display(event_source: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Format event data as human-friendly key-value pairs for UI display
    
    Args:
        event_source: OpenSearch document _source
    
    Returns:
        List of {'field': str, 'value': Any, 'path': str} dictionaries
    """
    def flatten_dict(d: Dict, parent_key: str = '', sep: str = '.') -> List[Dict]:
        items = []
        for k, v in d.items():
            new_key = f"{parent_key}{sep}{k}" if parent_key else k
            
            # Skip internal fields
            if k.startswith('_') or k in ['opensearch_key']:
                continue
            
            if isinstance(v, dict):
                items.extend(flatten_dict(v, new_key, sep=sep))
            elif isinstance(v, list):
                # Handle lists
                if v and isinstance(v[0], dict):
                    for i, item in enumerate(v):
                        items.extend(flatten_dict(item, f"{new_key}[{i}]", sep=sep))
                else:
                    items.append({
                        'field': new_key,
                        'value': ', '.join(str(x) for x in v) if v else '',
                        'path': new_key
                    })
            else:
                items.append({
                    'field': new_key,
                    'value': str(v) if v is not None else '',
                    'path': new_key
                })
        return items
    
    return flatten_dict(event_source)


def save_search_to_history(
    db, SearchHistory, user_id: int, case_id: Optional[int],
    search_params: Dict, result_count: int, search_name: Optional[str] = None
) -> int:
    """
    Save search to history
    
    Args:
        db: SQLAlchemy database session
        SearchHistory: SearchHistory model class
        user_id: Current user ID
        case_id: Current case ID (optional)
        search_params: Search parameters dict
        result_count: Number of results
        search_name: Optional name for saved search
    
    Returns:
        Search history ID
    """
    history = SearchHistory(
        user_id=user_id,
        case_id=case_id,
        search_query=json.dumps(search_params),
        search_name=search_name,
        filter_type=search_params.get('filter_type', 'all'),
        date_range=search_params.get('date_range', 'all'),
        custom_date_start=search_params.get('custom_date_start'),
        custom_date_end=search_params.get('custom_date_end'),
        column_config=json.dumps(search_params.get('column_config', [])),
        result_count=result_count
    )
    db.session.add(history)
    db.session.commit()
    
    logger.info(f"[SEARCH] Saved search to history: ID={history.id}, user={user_id}, results={result_count}")
    return history.id

