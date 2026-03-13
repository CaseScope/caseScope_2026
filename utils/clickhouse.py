"""ClickHouse client utilities for CaseScope

Provides connection management and helper functions for interacting
with the ClickHouse events database.

Thread-safe client initialization with double-checked locking.
Connection pool settings optimized for concurrent access.
"""
import threading
import clickhouse_connect
from config import Config


# Module-level client cache with thread-safe initialization
_client = None
_client_lock = threading.Lock()

# Connection pool settings for concurrent access
# These settings help prevent connection exhaustion under load
_POOL_SETTINGS = {
    'pool_size': getattr(Config, 'CLICKHOUSE_POOL_SIZE', 10),
    'pool_timeout': getattr(Config, 'CLICKHOUSE_POOL_TIMEOUT', 30),
}


def get_client():
    """Get a ClickHouse client connection
    
    Returns a cached client instance for connection reuse.
    Thread-safe with double-checked locking pattern.
    
    The client uses connection pooling under the hood via urllib3,
    which is thread-safe and handles concurrent access properly.
    """
    global _client
    if _client is None:
        with _client_lock:
            # Double-check after acquiring lock
            if _client is None:
                _client = clickhouse_connect.get_client(
                    host=Config.CLICKHOUSE_HOST,
                    port=Config.CLICKHOUSE_PORT,
                    database=Config.CLICKHOUSE_DATABASE,
                    username=Config.CLICKHOUSE_USER,
                    password=Config.CLICKHOUSE_PASSWORD,
                    settings={
                        # Query execution settings for better concurrency
                        'max_threads': getattr(Config, 'CLICKHOUSE_MAX_THREADS', 8),
                        # Prevent long-running queries from blocking
                        'max_execution_time': getattr(Config, 'CLICKHOUSE_QUERY_TIMEOUT', 300),
                    },
                    # Connection pool settings
                    connect_timeout=10,
                    send_receive_timeout=300,
                )
    return _client


def get_fresh_client():
    """Get a new ClickHouse client (not cached)
    
    Use for long-running operations or when you need
    an isolated connection (e.g., in Celery workers).
    
    Each fresh client gets its own connection, avoiding
    contention with the shared cached client.
    """
    return clickhouse_connect.get_client(
        host=Config.CLICKHOUSE_HOST,
        port=Config.CLICKHOUSE_PORT,
        database=Config.CLICKHOUSE_DATABASE,
        username=Config.CLICKHOUSE_USER,
        password=Config.CLICKHOUSE_PASSWORD,
        settings={
            'max_threads': getattr(Config, 'CLICKHOUSE_MAX_THREADS', 8),
            'max_execution_time': getattr(Config, 'CLICKHOUSE_QUERY_TIMEOUT', 300),
        },
        connect_timeout=10,
        send_receive_timeout=300,
    )


def insert_events(events, column_names=None):
    """Bulk insert events into the events table
    
    Args:
        events: List of tuples/lists containing event data
        column_names: List of column names matching the data order
                     If None, must match table column order exactly
    
    Returns:
        Number of rows inserted
    """
    client = get_client()
    client.insert('events', events, column_names=column_names)
    return len(events)


def query_events(case_id, where_clause='', params=None, limit=1000):
    """Query events for a specific case
    
    Args:
        case_id: The case ID to query
        where_clause: Additional WHERE conditions (without 'AND' prefix)
        params: Query parameters for parameterized queries
        limit: Maximum rows to return
    
    Returns:
        Query result object
    """
    client = get_client()
    
    query = f"SELECT * FROM events WHERE case_id = {{case_id:UInt32}}"
    if where_clause:
        query += f" AND {where_clause}"
    query += f" ORDER BY timestamp DESC LIMIT {limit}"
    
    parameters = {'case_id': case_id}
    if params:
        parameters.update(params)
    
    return client.query(query, parameters=parameters)


def count_events(case_id):
    """Get event count for a case
    
    Args:
        case_id: The case ID to count
    
    Returns:
        Integer count of events
    """
    client = get_client()
    result = client.query(
        "SELECT count() FROM events WHERE case_id = {case_id:UInt32}",
        parameters={'case_id': case_id}
    )
    return result.result_rows[0][0] if result.result_rows else 0


def delete_case_events(case_id):
    """Delete all events for a case
    
    Uses ALTER TABLE DELETE for MergeTree tables.
    Note: This is an async operation in ClickHouse.
    
    Args:
        case_id: The case ID to delete events for
    
    Returns:
        True if delete command was issued
    """
    client = get_client()
    for table_name in ('events', 'events_buffer'):
        client.command(
            f"ALTER TABLE {table_name} DELETE WHERE case_id = {int(case_id)}"
        )
    return True


def get_event_stats(case_id):
    """Get event statistics for a case
    
    Returns counts by file_type, channel, and date range.
    
    Args:
        case_id: The case ID to get stats for
    
    Returns:
        Dict with stats
    """
    client = get_client()
    
    # Total count
    total = count_events(case_id)
    
    if total == 0:
        return {
            'total': 0,
            'by_artifact_type': {},
            'by_channel': {},
            'earliest': None,
            'latest': None
        }
    
    # By artifact_type
    artifact_type_result = client.query(
        """SELECT artifact_type, count() as cnt 
           FROM events 
           WHERE case_id = {case_id:UInt32} 
           GROUP BY artifact_type 
           ORDER BY cnt DESC""",
        parameters={'case_id': case_id}
    )
    by_artifact_type = {row[0]: row[1] for row in artifact_type_result.result_rows}
    
    # By channel
    channel_result = client.query(
        """SELECT channel, count() as cnt 
           FROM events 
           WHERE case_id = {case_id:UInt32} AND channel != ''
           GROUP BY channel 
           ORDER BY cnt DESC 
           LIMIT 20""",
        parameters={'case_id': case_id}
    )
    by_channel = {row[0]: row[1] for row in channel_result.result_rows}
    
    # Time range
    time_result = client.query(
        """SELECT min(timestamp), max(timestamp) 
           FROM events 
           WHERE case_id = {case_id:UInt32}""",
        parameters={'case_id': case_id}
    )
    earliest = time_result.result_rows[0][0] if time_result.result_rows else None
    latest = time_result.result_rows[0][1] if time_result.result_rows else None
    
    return {
        'total': total,
        'by_artifact_type': by_artifact_type,
        'by_channel': by_channel,
        'earliest': earliest,
        'latest': latest
    }


def search_events(case_id, search_term, limit=500):
    """Full-text search in events for a case
    
    Searches the search_blob field using token matching.
    
    Args:
        case_id: The case ID to search
        search_term: Text to search for
        limit: Maximum results
    
    Returns:
        Query result object
    """
    client = get_client()
    
    # Use hasToken for exact token match or LIKE for partial
    query = """
        SELECT * FROM events 
        WHERE case_id = {case_id:UInt32} 
          AND search_blob LIKE {pattern:String}
        ORDER BY timestamp DESC 
        LIMIT {limit:UInt32}
    """
    
    return client.query(
        query,
        parameters={
            'case_id': case_id,
            'pattern': f'%{search_term}%',
            'limit': limit
        }
    )


def delete_file_events(case_file_id):
    """Delete all events for a specific case file
    
    Uses ALTER TABLE DELETE for MergeTree tables.
    Note: This is an async operation in ClickHouse.
    
    Args:
        case_file_id: The case_file_id to delete events for
    
    Returns:
        True if delete command was issued
    """
    client = get_client()
    for table_name in ('events', 'events_buffer'):
        client.command(
            f"ALTER TABLE {table_name} DELETE WHERE case_file_id = {int(case_file_id)}"
        )
    return True


def count_file_events(case_file_id):
    """Get event count for a specific case file
    
    Args:
        case_file_id: The case_file_id to count
    
    Returns:
        Integer count of events
    """
    client = get_client()
    result = client.query(
        "SELECT count() FROM events WHERE case_file_id = {case_file_id:UInt32}",
        parameters={'case_file_id': case_file_id}
    )
    return result.result_rows[0][0] if result.result_rows else 0


def health_check():
    """Check ClickHouse connectivity
    
    Returns:
        Dict with connection status and version
    """
    try:
        client = get_client()
        result = client.query("SELECT version()")
        version = result.result_rows[0][0] if result.result_rows else 'unknown'
        return {
            'status': 'connected',
            'version': version,
            'host': Config.CLICKHOUSE_HOST,
            'database': Config.CLICKHOUSE_DATABASE
        }
    except Exception as e:
        return {
            'status': 'error',
            'error': str(e),
            'host': Config.CLICKHOUSE_HOST,
            'database': Config.CLICKHOUSE_DATABASE
        }
