import os
import sys
import time
import types
import unittest

from utils import clickhouse


class _FakeRedisClient:
    def __init__(self):
        self.value = None
        self.renew_count = 0
        self.release_count = 0

    def ping(self):
        return True

    def set(self, key, value, nx=False, ex=None):
        if nx and self.value is not None:
            return False
        self.value = value
        return True

    def get(self, key):
        return self.value

    def eval(self, script, numkeys, key, expected, *args):
        if self.value != expected:
            return 0
        if "EXPIRE" in script:
            self.renew_count += 1
            return 1
        self.release_count += 1
        self.value = None
        return 1


class ClickHouseDestructiveLockTestCase(unittest.TestCase):
    def test_required_lock_uses_admin_redis_without_secret_and_renews(self):
        fake_client = _FakeRedisClient()
        redis_module = types.ModuleType("redis")
        redis_module.Redis = lambda **_kwargs: fake_client
        original_redis = sys.modules.get("redis")
        original_secret = os.environ.pop("SECRET_KEY", None)
        original_interval = clickhouse._destructive_rewrite_lock_renew_interval
        sys.modules["redis"] = redis_module
        clickhouse._destructive_rewrite_lock_renew_interval = lambda _ttl: 0.01
        try:
            with clickhouse.destructive_event_rewrite_guard(
                "test_lock",
                ttl_seconds=300,
                require_lock=True,
            ) as lease:
                self.assertIn("token", lease)
                self.assertTrue(callable(lease["assert_active"]))
                time.sleep(0.05)
                lease["assert_active"]()
        finally:
            clickhouse._destructive_rewrite_lock_renew_interval = original_interval
            if original_secret is not None:
                os.environ["SECRET_KEY"] = original_secret
            if original_redis is None:
                sys.modules.pop("redis", None)
            else:
                sys.modules["redis"] = original_redis

        self.assertGreaterEqual(fake_client.renew_count, 1)
        self.assertEqual(fake_client.release_count, 1)
        self.assertIsNone(fake_client.value)

    def test_required_lock_fails_closed_when_redis_unavailable(self):
        redis_module = types.ModuleType("redis")

        class FailingRedis:
            def __init__(self, **_kwargs):
                pass

            def ping(self):
                raise RuntimeError("redis down")

        redis_module.Redis = FailingRedis
        original_redis = sys.modules.get("redis")
        sys.modules["redis"] = redis_module
        try:
            with self.assertRaisesRegex(RuntimeError, "refusing to run unlocked"):
                with clickhouse.destructive_event_rewrite_guard("test_lock", require_lock=True):
                    pass
        finally:
            if original_redis is None:
                sys.modules.pop("redis", None)
            else:
                sys.modules["redis"] = original_redis

    def test_assert_active_detects_stolen_token_synchronously(self):
        fake_client = _FakeRedisClient()
        redis_module = types.ModuleType("redis")
        redis_module.Redis = lambda **_kwargs: fake_client
        original_redis = sys.modules.get("redis")
        original_interval = clickhouse._destructive_rewrite_lock_renew_interval
        sys.modules["redis"] = redis_module
        clickhouse._destructive_rewrite_lock_renew_interval = lambda _ttl: 3600
        try:
            with self.assertRaisesRegex(RuntimeError, "Lost Redis-backed destructive rewrite lock"):
                with clickhouse.destructive_event_rewrite_guard(
                    "test_lock",
                    ttl_seconds=300,
                    require_lock=True,
                ) as lease:
                    fake_client.value = "stolen-token"
                    lease["assert_active"]()
        finally:
            clickhouse._destructive_rewrite_lock_renew_interval = original_interval
            if original_redis is None:
                sys.modules.pop("redis", None)
            else:
                sys.modules["redis"] = original_redis


if __name__ == "__main__":
    unittest.main()
