"""ClickHouse client utilities for CaseScope

Provides connection management and helper functions for interacting
with the ClickHouse events database.

Thread-safe client initialization with double-checked locking.
Connection pool settings optimized for concurrent access.
"""
import json
import threading
import time
import uuid
from contextlib import contextmanager

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
_DESTRUCTIVE_REWRITE_LOCK_KEY = 'clickhouse:events_destructive_rewrite'
_DESTRUCTIVE_REWRITE_LOCK_TTL_SECONDS = max(
    int(getattr(Config, 'CLICKHOUSE_DESTRUCTIVE_REWRITE_LOCK_TTL_SECONDS', 21600) or 0),
    300,
)


class ClickHouseMutationGuardActive(RuntimeError):
    """Raised when another destructive event rewrite is already active."""

    def __init__(self, holder):
        self.holder = holder or {}
        operation = self.holder.get('operation') or 'another destructive rewrite'
        case_id = self.holder.get('case_id')
        started_at = self.holder.get('started_at')
        details = [operation]
        if case_id is not None:
            details.append(f'case_id={case_id}')
        if started_at:
            details.append(f'started_at={started_at}')
        super().__init__(
            'Another ClickHouse destructive events rewrite is already active '
            f"({' '.join(details)}); wait for it to finish before starting a new one"
        )


def _get_destructive_rewrite_redis_client():
    """Get the Redis client used for destructive rewrite admission control."""
    try:
        from utils.progress import get_redis_client

        return get_redis_client()
    except Exception:
        return None


def _decode_destructive_rewrite_payload(raw_payload):
    if not raw_payload:
        return None
    if isinstance(raw_payload, bytes):
        raw_payload = raw_payload.decode('utf-8', errors='replace')
    try:
        payload = json.loads(raw_payload)
    except Exception:
        return {'raw': str(raw_payload)}
    if isinstance(payload, dict):
        return payload
    return {'raw': payload}


def get_active_destructive_event_rewrite():
    """Return metadata for the active destructive events rewrite, if any."""
    client = _get_destructive_rewrite_redis_client()
    if client is None:
        return None
    try:
        return _decode_destructive_rewrite_payload(client.get(_DESTRUCTIVE_REWRITE_LOCK_KEY))
    except Exception:
        return None


@contextmanager
def destructive_event_rewrite_guard(operation, *, case_id=None, ttl_seconds=None):
    """Serialize explicit destructive rewrites against the `events` table."""
    client = _get_destructive_rewrite_redis_client()
    if client is None:
        yield None
        return

    ttl = max(int(ttl_seconds or _DESTRUCTIVE_REWRITE_LOCK_TTL_SECONDS), 300)
    payload = {
        'token': str(uuid.uuid4()),
        'operation': str(operation),
        'case_id': int(case_id) if case_id is not None else None,
        'started_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
    }
    serialized = json.dumps(payload)

    try:
        acquired = client.set(_DESTRUCTIVE_REWRITE_LOCK_KEY, serialized, nx=True, ex=ttl)
    except Exception:
        acquired = True

    if not acquired:
        raise ClickHouseMutationGuardActive(get_active_destructive_event_rewrite())

    try:
        yield payload
    finally:
        try:
            release_script = """
            local key = KEYS[1]
            local expected = ARGV[1]
            local current = redis.call('GET', key)
            if current == expected then
                return redis.call('DEL', key)
            end
            return 0
            """
            client.eval(release_script, 1, _DESTRUCTIVE_REWRITE_LOCK_KEY, serialized)
        except Exception:
            pass


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
                    autogenerate_session_id=False,
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
        autogenerate_session_id=False,
        settings={
            'max_threads': getattr(Config, 'CLICKHOUSE_MAX_THREADS', 8),
            'max_execution_time': getattr(Config, 'CLICKHOUSE_QUERY_TIMEOUT', 300),
        },
        connect_timeout=10,
        send_receive_timeout=300,
    )



def clickhouse_string_literal(value):
    """Return a safely escaped ClickHouse string literal."""
    escaped = str(value or '').replace('\\', '\\\\').replace("'", "\\'")
    return f"'{escaped}'"


def clickhouse_nullable_string_literal(value):
    """Return a nullable string literal for ClickHouse SQL."""
    if value is None:
        return 'NULL'
    return clickhouse_string_literal(value)


def clickhouse_bool_literal(value):
    """Return a ClickHouse boolean literal."""
    return 'true' if bool(value) else 'false'


def clickhouse_string_array_literal(values):
    """Return a ClickHouse Array(String) literal."""
    return '[' + ', '.join(clickhouse_string_literal(item) for item in (values or [])) + ']'


def run_events_update(assignments_sql, where_sql, *, client=None, wait=True):
    """Run an ALTER TABLE events UPDATE mutation.

    The single-table event state model expects writes to be visible immediately
    to subsequent reads, so default to synchronous mutations.
    """
    client = client or get_client()
    settings_clause = ' SETTINGS mutations_sync = 1' if wait else ''
    client.command(
        f"ALTER TABLE events UPDATE {assignments_sql} WHERE {where_sql}{settings_clause}"
    )
    return True


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


def delete_case_events(case_id, *, wait=False, client=None):
    """Delete all events for a case
    
    Uses ALTER TABLE DELETE for MergeTree tables.
    Note: This is an async operation in ClickHouse unless `wait=True`.
    
    Args:
        case_id: The case ID to delete events for
        wait: Whether to wait for the durable `events` mutation to finish applying
    
    Returns:
        True if delete command was issued
    """
    client = client or get_client()
    command_fragment = f"DELETE WHERE case_id = {int(case_id)}"
    with destructive_event_rewrite_guard('case_event_delete', case_id=case_id):
        for table_name in ('events', 'events_buffer'):
            try:
                client.command(f"ALTER TABLE {table_name} {command_fragment}")
            except Exception as exc:
                if table_name == 'events_buffer' and 'doesn\'t support mutations' in str(exc).lower():
                    continue
                raise
        if wait:
            wait_for_mutation_completion('events', command_fragment, client=client)
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



def wait_for_mutation_completion(
    table_name,
    command_fragment,
    *,
    client=None,
    timeout_seconds=300,
    poll_interval_seconds=1.0,
):
    """Wait until a matching ClickHouse mutation finishes applying."""
    client = client or get_client()
    deadline = time.monotonic() + max(timeout_seconds, 1)
    pattern = f"%{command_fragment}%"

    while True:
        result = client.query(
            """
            SELECT count()
            FROM system.mutations
            WHERE database = currentDatabase()
              AND table = {table_name:String}
              AND is_done = 0
              AND command LIKE {command_pattern:String}
            """,
            parameters={
                'table_name': str(table_name),
                'command_pattern': pattern,
            },
        )
        pending = result.result_rows[0][0] if result.result_rows else 0
        if pending == 0:
            return True
        if time.monotonic() >= deadline:
            raise TimeoutError(
                f"Timed out waiting for ClickHouse mutation on {table_name}: {command_fragment}"
            )
        time.sleep(max(poll_interval_seconds, 0.1))


def delete_file_events(case_file_id, *, wait=False, client=None):
    """Delete all events for a specific case file
    
    Uses ALTER TABLE DELETE for MergeTree tables.
    When `wait=True`, block until the durable `events` mutation completes.
    
    Args:
        case_file_id: The case_file_id to delete events for
        wait: Whether to wait for the `events` mutation to finish applying
    
    Returns:
        True if delete command was issued
    """
    client = client or get_client()
    command_fragment = f"DELETE WHERE case_file_id = {int(case_file_id)}"
    for table_name in ('events', 'events_buffer'):
        try:
            client.command(f"ALTER TABLE {table_name} {command_fragment}")
        except Exception as exc:
            # Buffer engine deployments do not support mutations. Keep the
            # durable events delete and skip the buffer mutation when the
            # server rejects it as unsupported.
            if table_name == 'events_buffer' and 'doesn\'t support mutations' in str(exc).lower():
                continue
            raise
    if wait:
        wait_for_mutation_completion('events', command_fragment, client=client)
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
