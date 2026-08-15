"""Phase 1.4a ingest fence tests.

Run with:

    /opt/casescope/venv/bin/python -m unittest tests.test_ingest_fence

Uses an in-process admission backend that exercises the real fence
implementation. Does not stop or mutate production Redis.
"""
from __future__ import annotations

import inspect
import os
import threading
import time
import unittest

os.environ.setdefault("SECRET_KEY", "phase1-step2-fence-test-secret")
os.environ.setdefault("INGEST_FENCE_RENEW_INTERVAL_SECONDS", "0.02")

from parsers.registry import BatchProcessor
from utils import clickhouse as clickhouse_utils
from utils.ingest_fence import (
    FailingFenceBackend,
    IngestAdmissionDenied,
    IngestExclusiveTimeout,
    IngestFenceConflict,
    IngestFenceLost,
    IngestFenceUnavailable,
    MemoryFenceBackend,
    active_shared_writer_count,
    exclusive_ingest_fence,
    get_active_exclusive_fence,
    install_fence_backend,
    install_memory_backend,
    reset_fence_backend,
    shared_ingest_admission,
)


class FakeClock:
    def __init__(self, start: float = 1_000.0):
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


class _FakeInsertClient:
    def __init__(self):
        self.inserts = []

    def insert(self, table, batch, column_names=None):
        self.inserts.append((table, list(batch), column_names))


class _FakeEvent:
    def __init__(self, payload):
        self.payload = payload

    def to_clickhouse_row(self):
        return self.payload


class IngestFenceTestCase(unittest.TestCase):
    def setUp(self):
        self.backend = install_memory_backend()

    def tearDown(self):
        reset_fence_backend()

    def test_01_shared_writer_acquires_and_inserts(self):
        client = _FakeInsertClient()
        processor = BatchProcessor(client, batch_size=10)
        processor.add_event(_FakeEvent((1, "row")))
        processor.flush()
        self.assertEqual(len(client.inserts), 1)
        self.assertEqual(client.inserts[0][0], "events")
        self.assertEqual(active_shared_writer_count(), 0)

    def test_02_multiple_shared_writers_coexist(self):
        started = threading.Barrier(2)
        holding = threading.Event()
        release = threading.Event()
        errors = []

        def writer():
            try:
                with shared_ingest_admission("events_insert", case_id=1):
                    started.wait(timeout=2)
                    holding.set()
                    self.assertGreaterEqual(active_shared_writer_count(), 1)
                    release.wait(timeout=2)
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=writer) for _ in range(2)]
        for thread in threads:
            thread.start()
        self.assertTrue(holding.wait(timeout=2))
        self.assertEqual(active_shared_writer_count(), 2)
        release.set()
        for thread in threads:
            thread.join(timeout=2)
        self.assertEqual(errors, [])
        self.assertEqual(active_shared_writer_count(), 0)

    def test_03_exclusive_prevents_new_writers(self):
        entered = threading.Event()
        hold = threading.Event()

        def admin():
            with exclusive_ingest_fence("case_event_delete", timeout_seconds=2):
                entered.set()
                hold.wait(timeout=2)

        thread = threading.Thread(target=admin)
        thread.start()
        self.assertTrue(entered.wait(timeout=2))
        with self.assertRaises(IngestAdmissionDenied):
            with shared_ingest_admission("events_insert"):
                pass
        hold.set()
        thread.join(timeout=2)

    def test_04_exclusive_waits_for_existing_writers_to_drain(self):
        writer_holding = threading.Event()
        writer_release = threading.Event()
        exclusive_started = threading.Event()
        saw_writer = []

        def writer():
            with shared_ingest_admission("events_insert", case_id=9):
                writer_holding.set()
                writer_release.wait(timeout=3)

        def admin():
            self.assertTrue(writer_holding.wait(timeout=2))
            exclusive_started.set()
            with exclusive_ingest_fence(
                "case_event_delete",
                timeout_seconds=3,
                poll_interval_seconds=0.02,
            ):
                saw_writer.append(active_shared_writer_count())

        writer_thread = threading.Thread(target=writer)
        admin_thread = threading.Thread(target=admin)
        writer_thread.start()
        admin_thread.start()
        self.assertTrue(exclusive_started.wait(timeout=2))
        time.sleep(0.1)
        self.assertTrue(admin_thread.is_alive())
        writer_release.set()
        writer_thread.join(timeout=2)
        admin_thread.join(timeout=2)
        self.assertEqual(saw_writer, [0])

    def test_05_exclusive_starts_only_after_writer_count_zero(self):
        with shared_ingest_admission("events_insert"):
            self.assertEqual(active_shared_writer_count(), 1)
        with exclusive_ingest_fence("file_event_delete", timeout_seconds=1):
            self.assertEqual(active_shared_writer_count(), 0)

    def test_06_writer_after_exclusive_begins_is_denied(self):
        denied = []

        def late_writer():
            try:
                with shared_ingest_admission("events_insert"):
                    denied.append("entered")
            except IngestAdmissionDenied:
                denied.append("denied")

        with exclusive_ingest_fence("case_event_deduplication", timeout_seconds=1):
            thread = threading.Thread(target=late_writer)
            thread.start()
            thread.join(timeout=2)
        self.assertEqual(denied, ["denied"])

    def test_07_redis_unavailable_shared_writer_fails(self):
        install_fence_backend(FailingFenceBackend())
        client = _FakeInsertClient()
        processor = BatchProcessor(client, batch_size=1, use_buffer=True)
        with self.assertRaises(IngestFenceUnavailable):
            processor.add_event(_FakeEvent((1, "row")))
            processor.flush()
        self.assertEqual(client.inserts, [])

    def test_08_redis_unavailable_destructive_operation_refused(self):
        install_fence_backend(FailingFenceBackend())
        with self.assertRaises(IngestFenceUnavailable):
            with exclusive_ingest_fence("case_event_delete"):
                pass
        with self.assertRaisesRegex(RuntimeError, "refusing to run unlocked"):
            with clickhouse_utils.destructive_event_rewrite_guard("case_event_delete"):
                pass

    def test_09_writer_crash_expires_safely(self):
        clock = FakeClock()
        backend = MemoryFenceBackend(clock=clock)
        install_fence_backend(backend)
        token = "dead-writer"
        payload = '{"token":"dead-writer","mode":"shared"}'
        self.assertEqual(backend.acquire_shared(token, payload, ttl_seconds=2), "ok")
        self.assertEqual(backend.count_writers(), 1)
        clock.advance(3)
        self.assertEqual(backend.count_writers(), 0)
        with exclusive_ingest_fence("case_event_delete", timeout_seconds=1):
            self.assertEqual(active_shared_writer_count(), 0)

    def test_10_admin_crash_recovers_safely(self):
        clock = FakeClock()
        backend = MemoryFenceBackend(clock=clock)
        install_fence_backend(backend)
        stale = '{"token":"stale-admin","mode":"exclusive","operation":"case_event_delete"}'
        self.assertEqual(
            backend.begin_exclusive_pending("stale-admin", stale, ttl_seconds=2),
            "ok",
        )
        acquired = backend.acquire_exclusive("stale-admin", stale, ttl_seconds=2)
        self.assertIsInstance(acquired, str)
        clock.advance(3)
        self.assertIsNone(backend.get_exclusive())
        with exclusive_ingest_fence("case_event_delete", timeout_seconds=1) as lease:
            self.assertNotEqual(lease.token, "stale-admin")
            lease.assert_active()

    def test_11_stale_owner_cannot_release_new_owner_lease(self):
        first_token = None
        first_payload = None
        with exclusive_ingest_fence("case_event_delete", timeout_seconds=1) as first:
            first_token = first.token
            first_payload = first.payload
        with exclusive_ingest_fence("case_event_deduplication", timeout_seconds=1) as second:
            released = self.backend.release_exclusive(first_token, first_payload)
            self.assertFalse(released)
            second.assert_active()
            self.assertEqual(get_active_exclusive_fence()["token"], second.token)

    def test_12_lease_heartbeat_preserves_long_operation(self):
        previous = os.environ.get("INGEST_FENCE_SHARED_TTL_SECONDS")
        os.environ["INGEST_FENCE_SHARED_TTL_SECONDS"] = "1"
        try:
            with shared_ingest_admission("events_insert") as lease:
                time.sleep(1.2)
                lease.assert_active()
        finally:
            if previous is None:
                os.environ.pop("INGEST_FENCE_SHARED_TTL_SECONDS", None)
            else:
                os.environ["INGEST_FENCE_SHARED_TTL_SECONDS"] = previous

    def test_13_lost_exclusive_ownership_prevents_continuation(self):
        with self.assertRaises(IngestFenceLost):
            with exclusive_ingest_fence("case_event_delete", timeout_seconds=1) as lease:
                self.backend._kv.pop(f"{self.backend.prefix}:exclusive", None)
                lease.assert_active()

    def test_14_two_administrators_serialize(self):
        first_holding = threading.Event()
        first_release = threading.Event()
        second_entered = threading.Event()
        order = []

        def first_admin():
            with exclusive_ingest_fence("case_event_delete", timeout_seconds=3):
                order.append("first")
                first_holding.set()
                first_release.wait(timeout=3)

        def second_admin():
            self.assertTrue(first_holding.wait(timeout=2))
            with exclusive_ingest_fence(
                "case_event_deduplication",
                timeout_seconds=3,
                poll_interval_seconds=0.02,
            ):
                order.append("second")
                second_entered.set()

        threads = [
            threading.Thread(target=first_admin),
            threading.Thread(target=second_admin),
        ]
        for thread in threads:
            thread.start()
        self.assertTrue(first_holding.wait(timeout=2))
        time.sleep(0.1)
        self.assertFalse(second_entered.is_set())
        first_release.set()
        for thread in threads:
            thread.join(timeout=3)
        self.assertEqual(order, ["first", "second"])

    def test_15_timeout_does_not_run_destructive_fallback(self):
        ran = {"value": False}
        writer_holding = threading.Event()
        writer_release = threading.Event()

        def writer():
            with shared_ingest_admission("events_insert"):
                writer_holding.set()
                writer_release.wait(timeout=3)

        thread = threading.Thread(target=writer)
        thread.start()
        self.assertTrue(writer_holding.wait(timeout=2))
        with self.assertRaises(IngestExclusiveTimeout):
            with exclusive_ingest_fence(
                "case_event_delete",
                timeout_seconds=0.15,
                poll_interval_seconds=0.02,
            ):
                ran["value"] = True
        self.assertFalse(ran["value"])
        self.assertIsNone(self.backend.get_exclusive())
        self.assertIsNone(self.backend.get_exclusive_pending())
        writer_release.set()
        thread.join(timeout=2)
        with shared_ingest_admission("events_insert"):
            pass

    def test_16_cancellation_releases_owned_state(self):
        cm = exclusive_ingest_fence("case_event_delete", timeout_seconds=1)
        lease = cm.__enter__()
        self.assertIsNotNone(self.backend.get_exclusive())
        cm.__exit__(RuntimeError, RuntimeError("cancelled"), None)
        self.assertIsNone(self.backend.get_exclusive())
        self.assertIsNone(self.backend.get_exclusive_pending())
        self.assertEqual(lease.token, lease.token)

        shared = shared_ingest_admission("events_insert")
        shared.__enter__()
        self.assertEqual(active_shared_writer_count(), 1)
        shared.__exit__(KeyboardInterrupt, KeyboardInterrupt(), None)
        self.assertEqual(active_shared_writer_count(), 0)

    def test_17_nested_exclusive_helper_does_not_deadlock(self):
        with exclusive_ingest_fence("case_permanent_deletion", timeout_seconds=1) as outer:
            with exclusive_ingest_fence("case_event_delete", timeout_seconds=1) as inner:
                self.assertTrue(inner.nested)
                self.assertEqual(inner.token, outer.token)
                inner.assert_active()
                with shared_ingest_admission("events_insert"):
                    inner.assert_active()
            outer.assert_active()
        with self.assertRaises(IngestFenceConflict):
            with shared_ingest_admission("events_insert"):
                with exclusive_ingest_fence("case_event_delete", timeout_seconds=0.2):
                    pass

    def test_18_no_correctness_sensitive_fail_open_callers(self):
        source = inspect.getsource(clickhouse_utils.destructive_event_rewrite_guard)
        self.assertNotIn("yield None", source)
        self.assertIn("exclusive_ingest_fence", source)
        self.assertIn("require_lock", source)
        self.assertIn("ignored as a", clickhouse_utils.destructive_event_rewrite_guard.__doc__)

        install_fence_backend(FailingFenceBackend())
        ran = {"delete_case": False, "delete_file": False, "update": False, "insert": False}

        class _Client:
            def query(self, sql, parameters=None):
                class _Result:
                    result_rows = [(1,)]

                return _Result()

            def command(self, sql):
                raise AssertionError(f"unfenced command: {sql}")

            def insert(self, *args, **kwargs):
                raise AssertionError("unfenced insert")

        client = _Client()
        with self.assertRaises((IngestFenceUnavailable, RuntimeError)):
            ran["delete_case"] = True
            clickhouse_utils.delete_case_events(1, client=client)
        with self.assertRaises((IngestFenceUnavailable, RuntimeError)):
            ran["delete_file"] = True
            clickhouse_utils.delete_file_events(1, client=client)
        with self.assertRaises((IngestFenceUnavailable, RuntimeError)):
            ran["update"] = True
            clickhouse_utils.run_events_update("x = 1", "case_id = 1", client=client)
        processor = BatchProcessor(client, batch_size=1)
        with self.assertRaises(IngestFenceUnavailable):
            ran["insert"] = True
            processor.add_event(_FakeEvent((1, "row")))
            processor.flush()
        self.assertTrue(all(ran.values()))

    def test_guard_default_is_fail_closed_without_require_lock(self):
        install_fence_backend(FailingFenceBackend())
        with self.assertRaisesRegex(RuntimeError, "refusing to run unlocked"):
            with clickhouse_utils.destructive_event_rewrite_guard("case_event_delete"):
                raise AssertionError("fail-open path executed")

    def test_nested_shared_does_not_double_count_writers(self):
        with shared_ingest_admission("events_insert", case_id=4) as outer:
            self.assertEqual(active_shared_writer_count(), 1)
            with shared_ingest_admission("events_insert", case_id=4) as inner:
                self.assertTrue(inner.nested)
                self.assertEqual(inner.token, outer.token)
                self.assertEqual(active_shared_writer_count(), 1)
        self.assertEqual(active_shared_writer_count(), 0)


class ClickHouseDestructiveLockCompatibilityTestCase(unittest.TestCase):
    def setUp(self):
        install_memory_backend()

    def tearDown(self):
        reset_fence_backend()

    def test_required_lock_renews_and_releases(self):
        with clickhouse_utils.destructive_event_rewrite_guard(
            "test_lock",
            ttl_seconds=300,
            require_lock=True,
        ) as lease:
            self.assertIn("token", lease)
            self.assertTrue(callable(lease["assert_active"]))
            time.sleep(0.05)
            lease["assert_active"]()
        self.assertIsNone(get_active_exclusive_fence())

    def test_required_lock_fails_closed_when_redis_unavailable(self):
        install_fence_backend(FailingFenceBackend())
        with self.assertRaisesRegex(RuntimeError, "refusing to run unlocked"):
            with clickhouse_utils.destructive_event_rewrite_guard("test_lock", require_lock=True):
                pass

    def test_assert_active_detects_stolen_token(self):
        backend = install_memory_backend()
        with self.assertRaises(IngestFenceLost):
            with clickhouse_utils.destructive_event_rewrite_guard(
                "test_lock",
                ttl_seconds=300,
                require_lock=True,
            ) as lease:
                backend._kv.pop(f"{backend.prefix}:exclusive", None)
                lease["assert_active"]()


if __name__ == "__main__":
    unittest.main()
