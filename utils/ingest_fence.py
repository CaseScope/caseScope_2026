"""Fail-closed shared/exclusive ingest admission for ClickHouse events.

Implements Phase 1.4a / INGEST_FENCE_CONTRACT. Redis is required whenever
correctness depends on this fence: shared writers must not INSERT uncoordinated,
and exclusive destructive operations must not run unlocked.

This module is the admission implementation. Callers must not bypass it.
"""
from __future__ import annotations

import json
import logging
import os
import socket
import threading
import time
import uuid
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterator, Optional

from utils.ingest_metrics import emit_metric

logger = logging.getLogger(__name__)

FENCE_CONTRACT_VERSION = "ingest-fence:v1"
DEFAULT_KEY_PREFIX = "casescope:ingest_fence:v1"
MODE_SHARED = "shared"
MODE_EXCLUSIVE = "exclusive"

_current_lease: ContextVar[Optional["AdmissionLease"]] = ContextVar(
    "casescope_ingest_fence_lease",
    default=None,
)
_backend_override: Optional["FenceBackend"] = None
_backend_lock = threading.Lock()


class IngestFenceError(RuntimeError):
    """Base error for ingest admission failures."""


class IngestFenceUnavailable(IngestFenceError):
    """Redis/admission backend is unavailable; fail closed."""


class IngestAdmissionDenied(IngestFenceError):
    """Shared writer cannot enter because exclusive is pending or held."""


class IngestExclusiveTimeout(IngestFenceError):
    """Drain/serialize wait elapsed; destructive operation must not run."""


class IngestFenceLost(IngestFenceError):
    """Holder no longer owns its lease; stop before further sensitive work."""


class IngestFenceConflict(IngestFenceError):
    """Incompatible nested acquisition that would deadlock or downgrade."""


def _env_int(name: str, default: int, minimum: int = 1) -> int:
    try:
        return max(int(os.environ.get(name, default) or default), minimum)
    except (TypeError, ValueError):
        return default


def _env_float(name: str, default: float, minimum: float = 0.01) -> float:
    try:
        return max(float(os.environ.get(name, default) or default), minimum)
    except (TypeError, ValueError):
        return default


def shared_lease_ttl_seconds() -> int:
    return _env_int("INGEST_FENCE_SHARED_TTL_SECONDS", 300, 15)


def exclusive_lease_ttl_seconds() -> int:
    return _env_int("INGEST_FENCE_EXCLUSIVE_TTL_SECONDS", 21600, 300)


def exclusive_drain_timeout_seconds() -> float:
    return _env_float("INGEST_FENCE_EXCLUSIVE_DRAIN_TIMEOUT_SECONDS", 3600.0, 0.05)


def drain_poll_interval_seconds() -> float:
    return _env_float("INGEST_FENCE_DRAIN_POLL_SECONDS", 0.05, 0.01)


def renew_interval_seconds(ttl_seconds: int) -> float:
    configured = os.environ.get("INGEST_FENCE_RENEW_INTERVAL_SECONDS")
    if configured:
        return max(float(configured), 0.01)
    return max(min(int(ttl_seconds) / 3.0, 300.0), 0.05)


def fence_key_prefix() -> str:
    return os.environ.get("INGEST_FENCE_KEY_PREFIX") or DEFAULT_KEY_PREFIX


def _owner_id() -> str:
    return (
        f"{socket.gethostname()}:{os.getpid()}:{threading.get_ident()}:"
        f"{uuid.uuid4().hex}"
    )


def _json_dumps(payload: Dict[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def _json_loads(raw: Any) -> Optional[Dict[str, Any]]:
    if not raw:
        return None
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", errors="replace")
    if isinstance(raw, dict):
        return raw
    try:
        payload = json.loads(raw)
    except Exception:
        return {"raw": str(raw)}
    if isinstance(payload, dict):
        return payload
    return {"raw": payload}


class FenceBackend:
    """Storage interface for atomic admission operations."""

    def ping(self) -> None:
        raise NotImplementedError

    def acquire_shared(self, token: str, payload: str, ttl_seconds: int) -> str:
        raise NotImplementedError

    def release_shared(self, token: str, payload: str) -> bool:
        raise NotImplementedError

    def renew_shared(self, token: str, payload: str, ttl_seconds: int) -> bool:
        raise NotImplementedError

    def get_shared(self, token: str) -> Optional[str]:
        raise NotImplementedError

    def count_writers(self) -> int:
        raise NotImplementedError

    def begin_exclusive_pending(self, token: str, payload: str, ttl_seconds: int) -> str:
        raise NotImplementedError

    def acquire_exclusive(self, token: str, payload: str, ttl_seconds: int) -> Any:
        raise NotImplementedError

    def release_exclusive(self, token: str, payload: str) -> bool:
        raise NotImplementedError

    def renew_exclusive(self, token: str, payload: str, ttl_seconds: int) -> bool:
        raise NotImplementedError

    def get_exclusive(self) -> Optional[str]:
        raise NotImplementedError

    def get_exclusive_pending(self) -> Optional[str]:
        raise NotImplementedError

    def release_pending(self, token: str, payload: str) -> bool:
        raise NotImplementedError

    def renew_pending(self, token: str, payload: str, ttl_seconds: int) -> bool:
        raise NotImplementedError


class MemoryFenceBackend(FenceBackend):
    """Deterministic in-process backend with the same atomic semantics as Redis."""

    def __init__(self, clock: Optional[Callable[[], float]] = None):
        self._clock = clock or time.time
        self._lock = threading.RLock()
        self._kv: Dict[str, tuple[str, Optional[float]]] = {}
        self._writers: set[str] = set()
        self._epoch = 0
        self.prefix = fence_key_prefix()

    def _now(self) -> float:
        return float(self._clock())

    def _expired(self, expires_at: Optional[float]) -> bool:
        return expires_at is not None and expires_at <= self._now()

    def _get_live(self, key: str) -> Optional[str]:
        item = self._kv.get(key)
        if item is None:
            return None
        value, expires_at = item
        if self._expired(expires_at):
            self._kv.pop(key, None)
            return None
        return value

    def _set(self, key: str, value: str, ttl_seconds: int, nx: bool = False) -> bool:
        current = self._get_live(key)
        if nx and current is not None:
            return False
        expires_at = self._now() + int(ttl_seconds) if ttl_seconds else None
        self._kv[key] = (value, expires_at)
        return True

    def _expire(self, key: str, ttl_seconds: int) -> bool:
        current = self._get_live(key)
        if current is None:
            return False
        self._kv[key] = (current, self._now() + int(ttl_seconds))
        return True

    def _writer_key(self, token: str) -> str:
        return f"{self.prefix}:writer:{token}"

    def ping(self) -> None:
        return None

    def acquire_shared(self, token: str, payload: str, ttl_seconds: int) -> str:
        with self._lock:
            if self._get_live(f"{self.prefix}:exclusive"):
                return "exclusive_held"
            if self._get_live(f"{self.prefix}:exclusive_pending"):
                return "exclusive_pending"
            if not self._set(self._writer_key(token), payload, ttl_seconds, nx=True):
                return "token_collision"
            self._writers.add(token)
            return "ok"

    def release_shared(self, token: str, payload: str) -> bool:
        with self._lock:
            current = self._get_live(self._writer_key(token))
            if current != payload:
                return False
            self._kv.pop(self._writer_key(token), None)
            self._writers.discard(token)
            return True

    def renew_shared(self, token: str, payload: str, ttl_seconds: int) -> bool:
        with self._lock:
            current = self._get_live(self._writer_key(token))
            if current != payload:
                return False
            return self._expire(self._writer_key(token), ttl_seconds)

    def get_shared(self, token: str) -> Optional[str]:
        with self._lock:
            return self._get_live(self._writer_key(token))

    def count_writers(self) -> int:
        with self._lock:
            live = 0
            stale = []
            for token in list(self._writers):
                if self._get_live(self._writer_key(token)):
                    live += 1
                else:
                    stale.append(token)
            for token in stale:
                self._writers.discard(token)
            return live

    def begin_exclusive_pending(self, token: str, payload: str, ttl_seconds: int) -> str:
        with self._lock:
            exclusive = self._get_live(f"{self.prefix}:exclusive")
            if exclusive:
                held = _json_loads(exclusive) or {}
                if held.get("token") != token:
                    return "exclusive_held"
            pending = self._get_live(f"{self.prefix}:exclusive_pending")
            if pending:
                held = _json_loads(pending) or {}
                if held.get("token") != token:
                    return "pending_held"
                self._expire(f"{self.prefix}:exclusive_pending", ttl_seconds)
                return "ok"
            if not self._set(f"{self.prefix}:exclusive_pending", payload, ttl_seconds, nx=True):
                return "pending_held"
            return "ok"

    def acquire_exclusive(self, token: str, payload: str, ttl_seconds: int) -> Any:
        with self._lock:
            pending = self._get_live(f"{self.prefix}:exclusive_pending")
            pending_obj = _json_loads(pending) or {}
            if not pending or pending_obj.get("token") != token:
                return "pending_lost"
            live = self.count_writers()
            if live != 0:
                return live
            exclusive = self._get_live(f"{self.prefix}:exclusive")
            if exclusive:
                held = _json_loads(exclusive) or {}
                if held.get("token") != token:
                    return "exclusive_held"
                self._expire(f"{self.prefix}:exclusive", ttl_seconds)
                return exclusive
            self._epoch += 1
            body = _json_loads(payload) or {}
            body["epoch"] = self._epoch
            serialized = _json_dumps(body)
            self._set(f"{self.prefix}:exclusive", serialized, ttl_seconds, nx=True)
            return serialized

    def release_exclusive(self, token: str, payload: str) -> bool:
        with self._lock:
            exclusive = self._get_live(f"{self.prefix}:exclusive")
            exclusive_obj = _json_loads(exclusive) or {}
            released = False
            if exclusive and exclusive_obj.get("token") == token:
                self._kv.pop(f"{self.prefix}:exclusive", None)
                released = True
            pending = self._get_live(f"{self.prefix}:exclusive_pending")
            pending_obj = _json_loads(pending) or {}
            if pending and pending_obj.get("token") == token:
                self._kv.pop(f"{self.prefix}:exclusive_pending", None)
                released = True
            return released

    def renew_exclusive(self, token: str, payload: str, ttl_seconds: int) -> bool:
        with self._lock:
            exclusive = self._get_live(f"{self.prefix}:exclusive")
            exclusive_obj = _json_loads(exclusive) or {}
            if not exclusive or exclusive_obj.get("token") != token:
                return False
            pending = self._get_live(f"{self.prefix}:exclusive_pending")
            pending_obj = _json_loads(pending) or {}
            if pending and pending_obj.get("token") == token:
                self._expire(f"{self.prefix}:exclusive_pending", ttl_seconds)
            return self._expire(f"{self.prefix}:exclusive", ttl_seconds)

    def get_exclusive(self) -> Optional[str]:
        with self._lock:
            return self._get_live(f"{self.prefix}:exclusive")

    def get_exclusive_pending(self) -> Optional[str]:
        with self._lock:
            return self._get_live(f"{self.prefix}:exclusive_pending")

    def release_pending(self, token: str, payload: str) -> bool:
        with self._lock:
            pending = self._get_live(f"{self.prefix}:exclusive_pending")
            pending_obj = _json_loads(pending) or {}
            if not pending or pending_obj.get("token") != token:
                return False
            self._kv.pop(f"{self.prefix}:exclusive_pending", None)
            return True

    def renew_pending(self, token: str, payload: str, ttl_seconds: int) -> bool:
        with self._lock:
            pending = self._get_live(f"{self.prefix}:exclusive_pending")
            pending_obj = _json_loads(pending) or {}
            if not pending or pending_obj.get("token") != token:
                return False
            return self._expire(f"{self.prefix}:exclusive_pending", ttl_seconds)


class RedisFenceBackend(FenceBackend):
    """Production Redis backend. Fail closed if Redis cannot be used."""

    _ACQUIRE_SHARED = """
    if redis.call('EXISTS', KEYS[1]) == 1 then return 'exclusive_held' end
    if redis.call('EXISTS', KEYS[2]) == 1 then return 'exclusive_pending' end
    local ok = redis.call('SET', KEYS[3], ARGV[1], 'NX', 'EX', ARGV[2])
    if not ok then return 'token_collision' end
    redis.call('SADD', KEYS[4], ARGV[3])
    return 'ok'
    """
    _RELEASE_IF_TOKEN = """
    local current = redis.call('GET', KEYS[1])
    if not current then return 0 end
    if cjson.decode(current)['token'] ~= ARGV[1] then return 0 end
    redis.call('DEL', KEYS[1])
    if KEYS[2] then redis.call('SREM', KEYS[2], ARGV[1]) end
    return 1
    """
    _RENEW_IF_TOKEN = """
    local current = redis.call('GET', KEYS[1])
    if not current then return 0 end
    if cjson.decode(current)['token'] ~= ARGV[1] then return 0 end
    return redis.call('EXPIRE', KEYS[1], tonumber(ARGV[2]))
    """
    _COUNT_WRITERS = """
    local tokens = redis.call('SMEMBERS', KEYS[1])
    local live = 0
    for i = 1, #tokens do
        local key = ARGV[1] .. tokens[i]
        if redis.call('EXISTS', key) == 1 then
            live = live + 1
        else
            redis.call('SREM', KEYS[1], tokens[i])
        end
    end
    return live
    """
    _BEGIN_PENDING = """
    local exclusive = redis.call('GET', KEYS[1])
    if exclusive then
        if cjson.decode(exclusive)['token'] ~= ARGV[1] then return 'exclusive_held' end
    end
    local pending = redis.call('GET', KEYS[2])
    if pending then
        if cjson.decode(pending)['token'] ~= ARGV[1] then return 'pending_held' end
        redis.call('EXPIRE', KEYS[2], tonumber(ARGV[3]))
        return 'ok'
    end
    local ok = redis.call('SET', KEYS[2], ARGV[2], 'NX', 'EX', ARGV[3])
    if not ok then return 'pending_held' end
    return 'ok'
    """
    _ACQUIRE_EXCLUSIVE = """
    local pending = redis.call('GET', KEYS[2])
    if not pending then return 'pending_lost' end
    if cjson.decode(pending)['token'] ~= ARGV[1] then return 'pending_lost' end
    local tokens = redis.call('SMEMBERS', KEYS[3])
    local live = 0
    for i = 1, #tokens do
        local key = ARGV[4] .. tokens[i]
        if redis.call('EXISTS', key) == 1 then
            live = live + 1
        else
            redis.call('SREM', KEYS[3], tokens[i])
        end
    end
    if live ~= 0 then return live end
    local exclusive = redis.call('GET', KEYS[1])
    if exclusive then
        if cjson.decode(exclusive)['token'] ~= ARGV[1] then return 'exclusive_held' end
        redis.call('EXPIRE', KEYS[1], tonumber(ARGV[3]))
        return exclusive
    end
    local epoch = redis.call('INCR', KEYS[4])
    local body = cjson.decode(ARGV[2])
    body['epoch'] = epoch
    local serialized = cjson.encode(body)
    redis.call('SET', KEYS[1], serialized, 'EX', ARGV[3])
    return serialized
    """
    _RELEASE_EXCLUSIVE = """
    local released = 0
    local exclusive = redis.call('GET', KEYS[1])
    if exclusive and cjson.decode(exclusive)['token'] == ARGV[1] then
        redis.call('DEL', KEYS[1])
        released = 1
    end
    local pending = redis.call('GET', KEYS[2])
    if pending and cjson.decode(pending)['token'] == ARGV[1] then
        redis.call('DEL', KEYS[2])
        released = 1
    end
    return released
    """
    _RENEW_EXCLUSIVE = """
    local exclusive = redis.call('GET', KEYS[1])
    if not exclusive then return 0 end
    if cjson.decode(exclusive)['token'] ~= ARGV[1] then return 0 end
    local pending = redis.call('GET', KEYS[2])
    if pending and cjson.decode(pending)['token'] == ARGV[1] then
        redis.call('EXPIRE', KEYS[2], tonumber(ARGV[2]))
    end
    return redis.call('EXPIRE', KEYS[1], tonumber(ARGV[2]))
    """

    def __init__(self, client=None, prefix: Optional[str] = None):
        self.prefix = prefix or fence_key_prefix()
        self._client = client

    def _redis(self):
        if self._client is not None:
            try:
                self._client.ping()
            except Exception as exc:
                raise IngestFenceUnavailable(
                    f"Ingest fence Redis unavailable; refusing uncoordinated access ({exc})"
                ) from exc
            return self._client
        try:
            import redis
            from config import Config

            client = redis.Redis(
                host=os.environ.get("REDIS_HOST") or getattr(Config, "REDIS_HOST", "localhost"),
                port=int(os.environ.get("REDIS_PORT") or getattr(Config, "REDIS_PORT", 6379)),
                db=int(os.environ.get("INGEST_FENCE_REDIS_DB") or getattr(Config, "REDIS_DB", 0)),
                password=os.environ.get("REDIS_PASSWORD") or None,
                socket_connect_timeout=float(os.environ.get("REDIS_CONNECT_TIMEOUT_SECONDS", 5)),
                socket_timeout=float(os.environ.get("REDIS_SOCKET_TIMEOUT_SECONDS", 5)),
                decode_responses=True,
            )
            client.ping()
            self._client = client
            return client
        except IngestFenceUnavailable:
            raise
        except Exception as exc:
            raise IngestFenceUnavailable(
                f"Ingest fence Redis unavailable; refusing uncoordinated access ({exc})"
            ) from exc

    def _keys(self) -> Dict[str, str]:
        prefix = self.prefix
        return {
            "exclusive": f"{prefix}:exclusive",
            "pending": f"{prefix}:exclusive_pending",
            "writers": f"{prefix}:writers",
            "epoch": f"{prefix}:epoch",
            "writer_prefix": f"{prefix}:writer:",
        }

    def ping(self) -> None:
        self._redis()

    def acquire_shared(self, token: str, payload: str, ttl_seconds: int) -> str:
        keys = self._keys()
        result = self._redis().eval(
            self._ACQUIRE_SHARED,
            4,
            keys["exclusive"],
            keys["pending"],
            keys["writer_prefix"] + token,
            keys["writers"],
            payload,
            int(ttl_seconds),
            token,
        )
        return str(result)

    def release_shared(self, token: str, payload: str) -> bool:
        keys = self._keys()
        result = self._redis().eval(
            self._RELEASE_IF_TOKEN,
            2,
            keys["writer_prefix"] + token,
            keys["writers"],
            token,
        )
        return int(result or 0) == 1

    def renew_shared(self, token: str, payload: str, ttl_seconds: int) -> bool:
        keys = self._keys()
        result = self._redis().eval(
            self._RENEW_IF_TOKEN,
            1,
            keys["writer_prefix"] + token,
            token,
            int(ttl_seconds),
        )
        return int(result or 0) == 1

    def get_shared(self, token: str) -> Optional[str]:
        return self._redis().get(self._keys()["writer_prefix"] + token)

    def count_writers(self) -> int:
        keys = self._keys()
        result = self._redis().eval(
            self._COUNT_WRITERS,
            1,
            keys["writers"],
            keys["writer_prefix"],
        )
        return int(result or 0)

    def begin_exclusive_pending(self, token: str, payload: str, ttl_seconds: int) -> str:
        keys = self._keys()
        result = self._redis().eval(
            self._BEGIN_PENDING,
            2,
            keys["exclusive"],
            keys["pending"],
            token,
            payload,
            int(ttl_seconds),
        )
        return str(result)

    def acquire_exclusive(self, token: str, payload: str, ttl_seconds: int) -> Any:
        keys = self._keys()
        result = self._redis().eval(
            self._ACQUIRE_EXCLUSIVE,
            4,
            keys["exclusive"],
            keys["pending"],
            keys["writers"],
            keys["epoch"],
            token,
            payload,
            int(ttl_seconds),
            keys["writer_prefix"],
        )
        return result

    def release_exclusive(self, token: str, payload: str) -> bool:
        keys = self._keys()
        result = self._redis().eval(
            self._RELEASE_EXCLUSIVE,
            2,
            keys["exclusive"],
            keys["pending"],
            token,
        )
        return int(result or 0) >= 1

    def renew_exclusive(self, token: str, payload: str, ttl_seconds: int) -> bool:
        keys = self._keys()
        result = self._redis().eval(
            self._RENEW_EXCLUSIVE,
            2,
            keys["exclusive"],
            keys["pending"],
            token,
            int(ttl_seconds),
        )
        return int(result or 0) == 1

    def get_exclusive(self) -> Optional[str]:
        return self._redis().get(self._keys()["exclusive"])

    def get_exclusive_pending(self) -> Optional[str]:
        return self._redis().get(self._keys()["pending"])

    def release_pending(self, token: str, payload: str) -> bool:
        keys = self._keys()
        result = self._redis().eval(
            self._RELEASE_IF_TOKEN,
            1,
            keys["pending"],
            token,
        )
        return int(result or 0) == 1

    def renew_pending(self, token: str, payload: str, ttl_seconds: int) -> bool:
        keys = self._keys()
        result = self._redis().eval(
            self._RENEW_IF_TOKEN,
            1,
            keys["pending"],
            token,
            int(ttl_seconds),
        )
        return int(result or 0) == 1


class FailingFenceBackend(FenceBackend):
    """Test double: Redis/admission storage is unavailable."""

    def ping(self) -> None:
        raise IngestFenceUnavailable("Ingest fence Redis unavailable; refusing uncoordinated access")

    def acquire_shared(self, token: str, payload: str, ttl_seconds: int) -> str:
        self.ping()
        return "ok"

    def release_shared(self, token: str, payload: str) -> bool:
        self.ping()
        return False

    def renew_shared(self, token: str, payload: str, ttl_seconds: int) -> bool:
        self.ping()
        return False

    def get_shared(self, token: str) -> Optional[str]:
        self.ping()
        return None

    def count_writers(self) -> int:
        self.ping()
        return 0

    def begin_exclusive_pending(self, token: str, payload: str, ttl_seconds: int) -> str:
        self.ping()
        return "ok"

    def acquire_exclusive(self, token: str, payload: str, ttl_seconds: int) -> Any:
        self.ping()
        return "pending_lost"

    def release_exclusive(self, token: str, payload: str) -> bool:
        self.ping()
        return False

    def renew_exclusive(self, token: str, payload: str, ttl_seconds: int) -> bool:
        self.ping()
        return False

    def get_exclusive(self) -> Optional[str]:
        self.ping()
        return None

    def get_exclusive_pending(self) -> Optional[str]:
        self.ping()
        return None

    def release_pending(self, token: str, payload: str) -> bool:
        self.ping()
        return False

    def renew_pending(self, token: str, payload: str, ttl_seconds: int) -> bool:
        self.ping()
        return False


def install_fence_backend(backend: Optional[FenceBackend]) -> Optional[FenceBackend]:
    """Install a process-local backend. Tests use this to isolate Redis."""
    global _backend_override
    with _backend_lock:
        previous = _backend_override
        _backend_override = backend
        return previous


def install_memory_backend(clock: Optional[Callable[[], float]] = None) -> MemoryFenceBackend:
    backend = MemoryFenceBackend(clock=clock)
    install_fence_backend(backend)
    return backend


def reset_fence_backend() -> None:
    install_fence_backend(None)


def get_fence_backend() -> FenceBackend:
    with _backend_lock:
        if _backend_override is not None:
            return _backend_override
    return RedisFenceBackend()


@dataclass
class AdmissionLease:
    mode: str
    token: str
    operation: str
    owner_id: str
    case_id: Optional[int]
    source_ref: Optional[str]
    payload: str
    nested: bool
    epoch: Optional[int] = None
    stage: str = MODE_EXCLUSIVE
    backend: Optional[FenceBackend] = None
    _lost: Optional[str] = None
    _stop_renewal: Optional[threading.Event] = None
    _renew_thread: Optional[threading.Thread] = None

    def assert_active(self) -> None:
        if self._lost:
            raise IngestFenceLost(self._lost)
        if self.nested:
            parent = _current_lease.get()
            if parent is not None and parent is not self:
                parent.assert_active()
                return
        backend = self.backend or get_fence_backend()
        try:
            if self.mode == MODE_EXCLUSIVE and self.stage == "pending":
                current = backend.get_exclusive_pending()
            elif self.mode == MODE_EXCLUSIVE:
                current = backend.get_exclusive()
            else:
                current = backend.get_shared(self.token)
        except IngestFenceUnavailable:
            self._lost = "Ingest fence Redis unavailable; refusing to continue"
            raise IngestFenceLost(self._lost)
        except IngestFenceError:
            raise
        except Exception as exc:
            self._lost = f"Unable to verify ingest fence ownership; refusing to continue ({exc})"
            raise IngestFenceLost(self._lost) from exc
        current_obj = _json_loads(current) or {}
        if not current or current_obj.get("token") != self.token:
            self._lost = "Lost ingest fence ownership; refusing to continue"
            raise IngestFenceLost(self._lost)
        if (
            self.stage != "pending"
            and self.epoch is not None
            and current_obj.get("epoch") not in (None, self.epoch)
        ):
            self._lost = "Ingest fence epoch changed; refusing to continue"
            raise IngestFenceLost(self._lost)

    def mark_lost(self, message: str) -> None:
        self._lost = message
        if self._stop_renewal is not None:
            self._stop_renewal.set()


def _scope_covers(held: AdmissionLease, mode: str, case_id: Optional[int], source_ref: Optional[str]) -> bool:
    if held.mode == MODE_SHARED and mode == MODE_EXCLUSIVE:
        return False
    if held.case_id is not None and case_id is None:
        return False
    if held.case_id is not None and case_id is not None and int(held.case_id) != int(case_id):
        return False
    if held.source_ref and not source_ref:
        return False
    if held.source_ref and source_ref and held.source_ref != source_ref:
        return False
    return True


def _start_renewal(lease: AdmissionLease, ttl_seconds: int, renewer: Callable[[], bool]) -> None:
    stop = threading.Event()
    lease._stop_renewal = stop

    def loop():
        interval = renew_interval_seconds(ttl_seconds)
        while not stop.wait(interval):
            try:
                if not renewer():
                    lease.mark_lost("Lost ingest fence ownership; refusing to continue")
                    return
            except IngestFenceUnavailable as exc:
                lease.mark_lost(str(exc))
                return
            except Exception as exc:
                lease.mark_lost(
                    f"Unable to renew ingest fence; refusing to continue ({exc})"
                )
                return

    thread = threading.Thread(
        target=loop,
        name=f"ingest-fence-{lease.mode}-renewer",
        daemon=True,
    )
    lease._renew_thread = thread
    thread.start()


def _stop_renewal(lease: AdmissionLease) -> None:
    if lease._stop_renewal is not None:
        lease._stop_renewal.set()
    if lease._renew_thread is not None:
        lease._renew_thread.join(timeout=5)


def active_shared_writer_count(backend: Optional[FenceBackend] = None) -> int:
    backend = backend or get_fence_backend()
    try:
        backend.ping()
        return int(backend.count_writers())
    except IngestFenceUnavailable:
        raise
    except Exception as exc:
        raise IngestFenceUnavailable(
            f"Ingest fence Redis unavailable; refusing uncoordinated access ({exc})"
        ) from exc


def get_active_exclusive_fence(backend: Optional[FenceBackend] = None) -> Optional[Dict[str, Any]]:
    backend = backend or get_fence_backend()
    try:
        backend.ping()
        payload = _json_loads(backend.get_exclusive())
        if payload:
            return payload
        return _json_loads(backend.get_exclusive_pending())
    except IngestFenceUnavailable:
        return None
    except Exception:
        return None


@contextmanager
def shared_ingest_admission(
    operation: str = "events_insert",
    *,
    case_id: Optional[int] = None,
    source_ref: Optional[str] = None,
    ttl_seconds: Optional[int] = None,
) -> Iterator[AdmissionLease]:
    """Acquire a shared writer lease around a normal bounded events write."""
    held = _current_lease.get()
    if held is not None:
        if not _scope_covers(held, MODE_SHARED, case_id, source_ref):
            raise IngestFenceConflict(
                "Nested shared ingest admission is wider than the held lease; refusing"
            )
        held.assert_active()
        nested = AdmissionLease(
            mode=held.mode,
            token=held.token,
            operation=operation,
            owner_id=held.owner_id,
            case_id=case_id if case_id is not None else held.case_id,
            source_ref=source_ref if source_ref is not None else held.source_ref,
            payload=held.payload,
            nested=True,
            epoch=held.epoch,
            backend=held.backend,
        )
        token = _current_lease.set(nested)
        try:
            yield nested
        finally:
            _current_lease.reset(token)
        return

    backend = get_fence_backend()
    try:
        backend.ping()
    except IngestFenceUnavailable:
        raise
    except Exception as exc:
        raise IngestFenceUnavailable(
            f"Ingest fence Redis unavailable; refusing uncoordinated INSERT ({exc})"
        ) from exc

    ttl = int(ttl_seconds or shared_lease_ttl_seconds())
    token = uuid.uuid4().hex
    owner_id = _owner_id()
    body = {
        "token": token,
        "mode": MODE_SHARED,
        "operation": str(operation),
        "case_id": int(case_id) if case_id is not None else None,
        "source_ref": source_ref,
        "owner_id": owner_id,
        "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "contract_version": FENCE_CONTRACT_VERSION,
    }
    payload = _json_dumps(body)
    acquire_started = time.perf_counter()
    try:
        result = backend.acquire_shared(token, payload, ttl)
    except IngestFenceUnavailable:
        raise
    except Exception as exc:
        raise IngestFenceUnavailable(
            f"Ingest fence Redis unavailable; refusing uncoordinated INSERT ({exc})"
        ) from exc

    if result != "ok":
        raise IngestAdmissionDenied(
            f"Shared ingest admission denied ({result}); fail/retry, do not bypass fence"
        )

    lease = AdmissionLease(
        mode=MODE_SHARED,
        token=token,
        operation=str(operation),
        owner_id=owner_id,
        case_id=int(case_id) if case_id is not None else None,
        source_ref=source_ref,
        payload=payload,
        nested=False,
        backend=backend,
    )

    def renew() -> bool:
        return backend.renew_shared(token, payload, ttl)

    _start_renewal(lease, ttl, renew)
    context_token = _current_lease.set(lease)
    acquire_ms = (time.perf_counter() - acquire_started) * 1000.0
    emit_metric(
        "ingest_fence_shared_acquire",
        duration_ms=acquire_ms,
        operation=str(operation),
        nested=False,
    )
    try:
        lease.assert_active()
        yield lease
        lease.assert_active()
    finally:
        _stop_renewal(lease)
        _current_lease.reset(context_token)
        try:
            backend.release_shared(token, payload)
        except Exception:
            logger.debug("Shared ingest lease release failed; TTL expiry will reclaim", exc_info=True)


@contextmanager
def exclusive_ingest_fence(
    operation: str,
    *,
    case_id: Optional[int] = None,
    source_ref: Optional[str] = None,
    ttl_seconds: Optional[int] = None,
    timeout_seconds: Optional[float] = None,
    poll_interval_seconds: Optional[float] = None,
) -> Iterator[AdmissionLease]:
    """Acquire the exclusive events fence after draining shared writers.

    Timeout waiting for drain or for another administrator releases any pending
    ownership this caller still holds and does not run the destructive operation.
    """
    held = _current_lease.get()
    if held is not None:
        if held.mode != MODE_EXCLUSIVE:
            raise IngestFenceConflict(
                "Cannot acquire exclusive ingest fence while holding a shared writer lease"
            )
        if not _scope_covers(held, MODE_EXCLUSIVE, case_id, source_ref):
            raise IngestFenceConflict(
                "Nested exclusive ingest fence is wider than the held fence; refusing"
            )
        held.assert_active()
        nested = AdmissionLease(
            mode=MODE_EXCLUSIVE,
            token=held.token,
            operation=operation,
            owner_id=held.owner_id,
            case_id=case_id if case_id is not None else held.case_id,
            source_ref=source_ref if source_ref is not None else held.source_ref,
            payload=held.payload,
            nested=True,
            epoch=held.epoch,
            backend=held.backend,
        )
        token = _current_lease.set(nested)
        try:
            yield nested
        finally:
            _current_lease.reset(token)
        return

    backend = get_fence_backend()
    try:
        backend.ping()
    except IngestFenceUnavailable:
        raise
    except Exception as exc:
        raise IngestFenceUnavailable(
            f"Ingest fence Redis unavailable; refusing exclusive operation ({exc})"
        ) from exc

    ttl = int(ttl_seconds or exclusive_lease_ttl_seconds())
    timeout = float(
        timeout_seconds if timeout_seconds is not None else exclusive_drain_timeout_seconds()
    )
    poll = float(
        poll_interval_seconds if poll_interval_seconds is not None else drain_poll_interval_seconds()
    )
    token = uuid.uuid4().hex
    owner_id = _owner_id()
    body = {
        "token": token,
        "mode": MODE_EXCLUSIVE,
        "operation": str(operation),
        "case_id": int(case_id) if case_id is not None else None,
        "source_ref": source_ref,
        "owner_id": owner_id,
        "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "contract_version": FENCE_CONTRACT_VERSION,
    }
    payload = _json_dumps(body)
    pending_acquired = False
    exclusive_acquired = False
    acquire_started = time.perf_counter()
    lease = AdmissionLease(
        mode=MODE_EXCLUSIVE,
        token=token,
        operation=str(operation),
        owner_id=owner_id,
        case_id=int(case_id) if case_id is not None else None,
        source_ref=source_ref,
        payload=payload,
        nested=False,
        stage="pending",
        backend=backend,
    )

    def renew_pending() -> bool:
        return backend.renew_pending(token, payload, ttl)

    def renew_exclusive() -> bool:
        return backend.renew_exclusive(token, payload, ttl)

    deadline = time.monotonic() + timeout
    try:
        while True:
            if time.monotonic() >= deadline:
                raise IngestExclusiveTimeout(
                    f"Timed out waiting to serialize exclusive ingest fence for {operation}; "
                    "refusing to run unlocked"
                )
            try:
                pending_result = backend.begin_exclusive_pending(token, payload, ttl)
            except IngestFenceUnavailable:
                raise
            except Exception as exc:
                raise IngestFenceUnavailable(
                    f"Ingest fence Redis unavailable; refusing exclusive operation ({exc})"
                ) from exc
            if pending_result == "ok":
                pending_acquired = True
                break
            time.sleep(poll)

        _start_renewal(lease, ttl, renew_pending)

        while True:
            lease.assert_active()
            try:
                writers = backend.count_writers()
            except IngestFenceUnavailable:
                raise
            except Exception as exc:
                raise IngestFenceUnavailable(
                    f"Unable to count shared ingest writers; refusing exclusive operation ({exc})"
                ) from exc
            if writers == 0:
                acquired = backend.acquire_exclusive(token, payload, ttl)
                if acquired == "pending_lost":
                    raise IngestFenceLost(
                        "Lost exclusive pending ownership during drain; refusing to continue"
                    )
                if acquired == "exclusive_held":
                    raise IngestFenceConflict(
                        "Another administrator holds the exclusive ingest fence"
                    )
                if isinstance(acquired, (int, float)) and not isinstance(acquired, bool):
                    writers = int(acquired)
                else:
                    exclusive_payload = acquired if isinstance(acquired, str) else payload
                    exclusive_obj = _json_loads(exclusive_payload) or body
                    lease.payload = (
                        exclusive_payload if isinstance(exclusive_payload, str) else payload
                    )
                    lease.epoch = exclusive_obj.get("epoch")
                    lease.stage = MODE_EXCLUSIVE
                    exclusive_acquired = True
                    break
            if time.monotonic() >= deadline:
                raise IngestExclusiveTimeout(
                    f"Timed out waiting for {writers} shared ingest writer(s) to drain "
                    f"before {operation}; refusing to run unlocked"
                )
            time.sleep(poll)

        _stop_renewal(lease)
        _start_renewal(lease, ttl, renew_exclusive)
        emit_metric(
            "ingest_fence_exclusive_acquire",
            duration_ms=(time.perf_counter() - acquire_started) * 1000.0,
            operation=str(operation),
            nested=False,
        )
        context_token = _current_lease.set(lease)
        try:
            lease.assert_active()
            yield lease
            lease.assert_active()
        finally:
            _current_lease.reset(context_token)
    finally:
        _stop_renewal(lease)
        try:
            if exclusive_acquired or pending_acquired:
                backend.release_exclusive(token, lease.payload)
        except Exception:
            logger.debug(
                "Exclusive ingest fence release failed; TTL expiry will reclaim",
                exc_info=True,
            )


def current_ingest_lease() -> Optional[AdmissionLease]:
    return _current_lease.get()
