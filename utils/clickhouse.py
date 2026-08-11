"""ClickHouse client utilities for CaseScope

Provides connection management and helper functions for interacting
with the ClickHouse events database.

Thread-safe client initialization with double-checked locking.
Connection pool settings optimized for concurrent access.
"""
import json
import logging
import os
import threading
import time
import uuid
from contextlib import contextmanager

import clickhouse_connect

logger = logging.getLogger(__name__)


# Module-level client cache with thread-safe initialization
_client = None
_client_lock = threading.Lock()

_DESTRUCTIVE_REWRITE_LOCK_KEY = 'clickhouse:events_destructive_rewrite'

MIGRATION_MAX_THREADS = int(os.environ.get('CLICKHOUSE_MIGRATION_MAX_THREADS', 1))
MIGRATION_MAX_BLOCK_SIZE = int(os.environ.get('CLICKHOUSE_MIGRATION_MAX_BLOCK_SIZE', 8192))
MIGRATION_MAX_EXECUTION_TIME = int(os.environ.get('CLICKHOUSE_MIGRATION_MAX_EXECUTION_TIME', 0))
MIGRATION_SEND_RECEIVE_TIMEOUT = int(
    os.environ.get('CLICKHOUSE_MIGRATION_SEND_RECEIVE_TIMEOUT', 86400)
)
_MIGRATION_MAX_MEMORY_USAGE = os.environ.get('CLICKHOUSE_MIGRATION_MAX_MEMORY_USAGE')


def _get_app_config():
    from config import Config

    return Config


def _get_config_attr(name, default):
    return getattr(_get_app_config(), name, default)


def _destructive_rewrite_lock_ttl_seconds():
    return max(
        int(os.environ.get('CLICKHOUSE_DESTRUCTIVE_REWRITE_LOCK_TTL_SECONDS', 21600) or 0),
        300,
    )


def _destructive_rewrite_lock_renew_interval(ttl_seconds):
    configured = os.environ.get('CLICKHOUSE_DESTRUCTIVE_REWRITE_LOCK_RENEW_INTERVAL_SECONDS')
    if configured:
        return max(int(configured), 5)
    return max(min(int(ttl_seconds) // 3, 300), 5)


def _clickhouse_connection_config():
    return {
        'host': os.environ.get('CLICKHOUSE_HOST') or 'localhost',
        'port': int(os.environ.get('CLICKHOUSE_PORT', 8123)),
        'database': os.environ.get('CLICKHOUSE_DATABASE') or 'casescope',
        'username': os.environ.get('CLICKHOUSE_USER') or 'default',
        'password': os.environ.get('CLICKHOUSE_PASSWORD') or '',
    }


def migration_source_query_settings():
    settings = {
        'max_threads': MIGRATION_MAX_THREADS,
        'max_block_size': MIGRATION_MAX_BLOCK_SIZE,
        'max_execution_time': MIGRATION_MAX_EXECUTION_TIME,
    }
    if _MIGRATION_MAX_MEMORY_USAGE:
        settings['max_memory_usage'] = int(_MIGRATION_MAX_MEMORY_USAGE)
    return settings


def migration_client_effective_settings():
    config = _clickhouse_connection_config()
    settings = migration_source_query_settings()
    return {
        'CLICKHOUSE_HOST': config['host'],
        'CLICKHOUSE_PORT': config['port'],
        'CLICKHOUSE_DATABASE': config['database'],
        'CLICKHOUSE_USER': config['username'],
        'max_threads': settings['max_threads'],
        'max_block_size': settings['max_block_size'],
        'max_execution_time': settings['max_execution_time'],
        'max_memory_usage': settings.get('max_memory_usage'),
        'send_receive_timeout': MIGRATION_SEND_RECEIVE_TIMEOUT,
    }


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


def _get_destructive_rewrite_redis_client(*, required=False):
    """Get the Redis client used for destructive rewrite admission control."""
    try:
        import redis

        client = redis.Redis(
            host=os.environ.get('REDIS_HOST') or 'localhost',
            port=int(os.environ.get('REDIS_PORT', 6379)),
            db=int(os.environ.get('REDIS_DB', 0)),
            password=os.environ.get('REDIS_PASSWORD') or None,
            socket_connect_timeout=float(
                os.environ.get('REDIS_CONNECT_TIMEOUT_SECONDS', 5)
            ),
            socket_timeout=float(os.environ.get('REDIS_SOCKET_TIMEOUT_SECONDS', 5)),
        )
        client.ping()
        return client
    except Exception as exc:
        if required:
            raise RuntimeError(
                "Unable to acquire Redis-backed destructive rewrite lock; "
                f"refusing to run unlocked ({exc})"
            ) from exc
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
def destructive_event_rewrite_guard(operation, *, case_id=None, ttl_seconds=None, require_lock=False):
    """Serialize explicit destructive rewrites against the `events` table."""
    client = _get_destructive_rewrite_redis_client(required=require_lock)
    if client is None:
        yield None
        return

    ttl = max(int(ttl_seconds or _destructive_rewrite_lock_ttl_seconds()), 300)
    payload = {
        'token': str(uuid.uuid4()),
        'operation': str(operation),
        'case_id': int(case_id) if case_id is not None else None,
        'started_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
    }
    serialized = json.dumps(payload)
    stop_renewal = threading.Event()
    renewal_error = {'message': None}

    try:
        acquired = client.set(_DESTRUCTIVE_REWRITE_LOCK_KEY, serialized, nx=True, ex=ttl)
    except Exception as exc:
        if require_lock:
            raise RuntimeError(
                "Unable to acquire Redis-backed destructive rewrite lock; "
                f"refusing to run unlocked ({exc})"
            ) from exc
        yield None
        return

    if not acquired:
        raise ClickHouseMutationGuardActive(get_active_destructive_event_rewrite())

    def assert_active():
        if renewal_error['message']:
            raise RuntimeError(renewal_error['message'])
        try:
            current = client.get(_DESTRUCTIVE_REWRITE_LOCK_KEY)
            if isinstance(current, bytes):
                current = current.decode('utf-8', errors='replace')
            if current != serialized:
                renewal_error['message'] = (
                    "Lost Redis-backed destructive rewrite lock; refusing to continue"
                )
                raise RuntimeError(renewal_error['message'])
        except RuntimeError:
            raise
        except Exception as exc:
            renewal_error['message'] = (
                "Unable to verify Redis-backed destructive rewrite lock; "
                f"refusing to continue ({exc})"
            )
            raise RuntimeError(renewal_error['message']) from exc

    def renew_loop():
        renew_interval = _destructive_rewrite_lock_renew_interval(ttl)
        renew_script = """
        local key = KEYS[1]
        local expected = ARGV[1]
        local ttl = tonumber(ARGV[2])
        local current = redis.call('GET', key)
        if current == expected then
            return redis.call('EXPIRE', key, ttl)
        end
        return 0
        """
        while not stop_renewal.wait(renew_interval):
            try:
                renewed = client.eval(
                    renew_script,
                    1,
                    _DESTRUCTIVE_REWRITE_LOCK_KEY,
                    serialized,
                    int(ttl),
                )
                if int(renewed or 0) != 1:
                    renewal_error['message'] = (
                        "Lost Redis-backed destructive rewrite lock; refusing to continue"
                    )
                    stop_renewal.set()
                    return
            except Exception as exc:
                renewal_error['message'] = (
                    "Unable to renew Redis-backed destructive rewrite lock; "
                    f"refusing to continue ({exc})"
                )
                stop_renewal.set()
                return

    renewal_thread = threading.Thread(
        target=renew_loop,
        name='clickhouse-destructive-rewrite-lock-renewer',
        daemon=True,
    )
    renewal_thread.start()
    payload['assert_active'] = assert_active

    try:
        assert_active()
        yield payload
        assert_active()
    finally:
        stop_renewal.set()
        renewal_thread.join(timeout=5)
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
                Config = _get_app_config()
                _client = clickhouse_connect.get_client(
                    host=Config.CLICKHOUSE_HOST,
                    port=Config.CLICKHOUSE_PORT,
                    database=Config.CLICKHOUSE_DATABASE,
                    username=Config.CLICKHOUSE_USER,
                    password=Config.CLICKHOUSE_PASSWORD,
                    autogenerate_session_id=False,
                    settings={
                        # Query execution settings for better concurrency
                        'max_threads': _get_config_attr('CLICKHOUSE_MAX_THREADS', 8),
                        # Prevent long-running queries from blocking
                        'max_execution_time': _get_config_attr('CLICKHOUSE_QUERY_TIMEOUT', 300),
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
    Config = _get_app_config()
    return clickhouse_connect.get_client(
        host=Config.CLICKHOUSE_HOST,
        port=Config.CLICKHOUSE_PORT,
        database=Config.CLICKHOUSE_DATABASE,
        username=Config.CLICKHOUSE_USER,
        password=Config.CLICKHOUSE_PASSWORD,
        autogenerate_session_id=False,
        settings={
            'max_threads': _get_config_attr('CLICKHOUSE_MAX_THREADS', 8),
            'max_execution_time': _get_config_attr('CLICKHOUSE_QUERY_TIMEOUT', 300),
        },
        connect_timeout=10,
        send_receive_timeout=300,
    )


def get_migration_client():
    """Get an administrative ClickHouse client for long Evidence migrations."""
    config = _clickhouse_connection_config()
    return clickhouse_connect.get_client(
        host=config['host'],
        port=config['port'],
        database=config['database'],
        username=config['username'],
        password=config['password'],
        autogenerate_session_id=False,
        settings=migration_source_query_settings(),
        connect_timeout=int(os.environ.get('CLICKHOUSE_MIGRATION_CONNECT_TIMEOUT', 10)),
        send_receive_timeout=MIGRATION_SEND_RECEIVE_TIMEOUT,
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


def run_events_update(assignments_sql, where_sql, *, client=None, wait=True, audit=None):
    """Run an ALTER TABLE events UPDATE mutation.

    The single-table event state model expects writes to be visible immediately
    to subsequent reads, so default to synchronous mutations.

    `audit` takes an `utils.evidence_audit.EvidenceChange` describing the
    change for the forensic audit log. It is optional only so that internal
    repair paths can opt out deliberately; callers that modify evidence on
    behalf of a user are expected to supply it, and omitting it is logged.
    """
    client = client or get_client()
    settings_clause = ' SETTINGS mutations_sync = 1' if wait else ''
    client.command(
        f"ALTER TABLE events UPDATE {assignments_sql} WHERE {where_sql}{settings_clause}"
    )

    if audit is not None:
        from utils.evidence_audit import record_bulk_change

        if audit.predicate is None:
            audit.predicate = where_sql
        audit.details.setdefault('assignments', assignments_sql)
        record_bulk_change(audit)
    else:
        logger.debug('Unaudited events mutation: %s WHERE %s', assignments_sql, where_sql)

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


def get_event_by_evidence_record_key(case_id, evidence_record_key, *, client=None):
    """Resolve one normalized event by case-scoped forensic evidence identity."""
    key = str(evidence_record_key or '').strip()
    if not key:
        return None

    client = client or get_client()
    result = client.query(
        f"""
        SELECT *
        FROM events
        WHERE case_id = {{case_id:UInt32}}
          AND evidence_record_key = {{evidence_record_key:String}}
        LIMIT 1
        """,
        parameters={
            'case_id': int(case_id),
            'evidence_record_key': key,
        },
    )
    return result.result_rows[0] if result.result_rows else None


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
    Config = None
    try:
        Config = _get_app_config()
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
            'host': getattr(Config, 'CLICKHOUSE_HOST', 'unknown') if Config else 'unknown',
            'database': getattr(Config, 'CLICKHOUSE_DATABASE', 'unknown') if Config else 'unknown',
        }
