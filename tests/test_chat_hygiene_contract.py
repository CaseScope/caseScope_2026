"""Contract tests for chat registry completeness, approval caching and transcripts.

These cover the invariants that quietly rot: a tool added in one place but not
another, approvals that only one web worker can see, and a transcript that is
rewritten in full on every turn.
"""

import json
import os
import sys
import unittest
from types import SimpleNamespace
from typing import Any, Dict, List, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

os.environ.setdefault("SECRET_KEY", "test-secret")

# Bound at import rather than in setUp: other test modules install fake models
# into sys.modules and never remove them, so a later import of the real route
# module fails on a duplicated table definition.
import routes.chat as chat_routes  # noqa: E402


class ToolRegistryCompletenessTestCase(unittest.TestCase):
    """Every assistant-visible tool must be described everywhere it matters."""

    @classmethod
    def setUpClass(cls):
        from utils.chat_tools import TOOL_DEFINITIONS, TOOL_REGISTRY
        from utils.chat.tool_providers import list_tool_providers
        from utils.chat.policy import (
            REQUIRED_CHAT_TOOL_FEATURES,
            SENSITIVE_CHAT_TOOLS,
        )

        cls.schema_names = {d["function"]["name"] for d in TOOL_DEFINITIONS}
        cls.registry_names = set(TOOL_REGISTRY)
        cls.providers = {p["name"]: p for p in list_tool_providers()}
        cls.sensitive = SENSITIVE_CHAT_TOOLS
        cls.required_features = REQUIRED_CHAT_TOOL_FEATURES

    def test_every_advertised_tool_can_be_executed(self):
        missing = sorted(self.schema_names - self.registry_names)
        self.assertEqual(
            [], missing,
            f"advertised to the model but not executable: {missing}",
        )

    def test_every_executable_tool_is_advertised(self):
        missing = sorted(self.registry_names - self.schema_names)
        self.assertEqual(
            [], missing,
            f"executable but never advertised to the model: {missing}",
        )

    def test_every_tool_has_provider_metadata(self):
        missing = sorted(self.schema_names - set(self.providers))
        self.assertEqual(
            [], missing,
            f"no provider metadata, so the analyst cannot see them: {missing}",
        )

        for name in sorted(self.schema_names):
            provider = self.providers[name]
            self.assertTrue(provider.get("description"), f"{name} has no description")
            self.assertTrue(provider.get("tier"), f"{name} has no policy tier")
            self.assertTrue(provider.get("provenance"), f"{name} has no provenance")

    def test_policy_never_names_a_tool_that_does_not_exist(self):
        self.assertEqual(
            [], sorted(set(self.sensitive) - self.schema_names),
            "a sensitive-tool entry that names no real tool gates nothing",
        )
        self.assertEqual(
            [], sorted(set(self.required_features) - self.schema_names),
            "a feature requirement that names no real tool enforces nothing",
        )

    def test_a_declared_feature_requirement_is_actually_enforced(self):
        from unittest.mock import patch

        from utils.feature_availability import FeatureAvailability

        with patch.object(FeatureAvailability, 'is_ai_enabled', return_value=False), \
                patch.object(FeatureAvailability, 'is_threat_intel_enabled',
                             return_value=False):
            for tool_name in sorted(self.required_features):
                self.assertFalse(
                    FeatureAvailability.is_chat_tool_feature_enabled(tool_name),
                    f"{tool_name} declares a feature requirement but runs unlicensed",
                )

    def test_a_tool_without_a_declared_requirement_is_not_gated(self):
        from utils.feature_availability import FeatureAvailability

        ungated = sorted(self.schema_names - set(self.required_features))
        self.assertTrue(ungated, "expected at least one ungated tool")
        for tool_name in ungated:
            self.assertTrue(
                FeatureAvailability.is_chat_tool_feature_enabled(tool_name),
                f"{tool_name} is gated without declaring a requirement",
            )


class _FakeRedis:
    """Enough of a Redis client to exercise the shared approval cache."""

    def __init__(self):
        self.strings: Dict[str, str] = {}
        self.sets: Dict[str, set] = {}

    def ping(self):
        return True

    def setex(self, key, _ttl, value):
        self.strings[key] = value

    def get(self, key):
        return self.strings.get(key)

    def sadd(self, key, *values):
        self.sets.setdefault(key, set()).update(values)

    def expire(self, _key, _ttl):
        return True

    def smembers(self, key):
        return set(self.sets.get(key, set()))

    def delete(self, *keys):
        for key in keys:
            self.strings.pop(key, None)
            self.sets.pop(key, None)

    def pipeline(self):
        return _FakePipeline(self)


class _FakePipeline:
    def __init__(self, client):
        self._client = client
        self._queued = []

    def setex(self, *args):
        self._queued.append(("setex", args))
        return self

    def sadd(self, *args):
        self._queued.append(("sadd", args))
        return self

    def expire(self, *args):
        self._queued.append(("expire", args))
        return self

    def execute(self):
        for name, args in self._queued:
            getattr(self._client, name)(*args)
        self._queued = []


class ApprovalCacheSharingTestCase(unittest.TestCase):
    """An approval must survive the analyst landing on a different worker."""

    def setUp(self):
        from utils.chat.dispatch import PermissionCache, PermissionResult

        self.PermissionCache = PermissionCache
        self.granted = PermissionResult(
            allowed=True, category="approved", reason="analyst approved",
            cacheable=True,
        )

    def _cache_backed_by(self, client):
        cache = self.PermissionCache()
        cache._redis = client
        cache._redis_checked = True
        return cache

    def test_an_approval_is_visible_to_another_worker(self):
        shared = _FakeRedis()
        worker_a = self._cache_backed_by(shared)
        worker_b = self._cache_backed_by(shared)

        key = worker_a.tool_key("run_detector", 7, "sess-1", {"detector": "spray"})
        worker_a.store(key, "sess-1", self.granted)

        seen_by_b = worker_b.load(
            worker_b.tool_key("run_detector", 7, "sess-1", {"detector": "spray"})
        )
        self.assertIsNotNone(seen_by_b, "the second worker would re-prompt the analyst")
        self.assertTrue(seen_by_b.allowed)
        self.assertEqual("analyst approved", seen_by_b.reason)

    def test_different_arguments_do_not_inherit_an_approval(self):
        cache = self._cache_backed_by(_FakeRedis())
        cache.store(
            cache.tool_key("run_detector", 7, "sess-1", {"detector": "spray"}),
            "sess-1", self.granted,
        )

        other = cache.load(
            cache.tool_key("run_detector", 7, "sess-1", {"detector": "brute_force"})
        )
        self.assertIsNone(other, "approving one call must not approve another")

    def test_another_case_does_not_inherit_an_approval(self):
        cache = self._cache_backed_by(_FakeRedis())
        cache.store(cache.session_key(7, "sess-1"), "sess-1", self.granted)

        self.assertIsNone(cache.load(cache.session_key(8, "sess-1")))

    def test_clearing_a_session_revokes_every_approval_it_held(self):
        shared = _FakeRedis()
        worker_a = self._cache_backed_by(shared)
        worker_b = self._cache_backed_by(shared)

        tool_key = worker_a.tool_key("run_detector", 7, "sess-1", {"detector": "spray"})
        worker_a.store(tool_key, "sess-1", self.granted)
        worker_a.store(worker_a.session_key(7, "sess-1"), "sess-1", self.granted)
        worker_a.store(
            worker_a.tool_key("run_detector", 7, "sess-2", {"detector": "spray"}),
            "sess-2", self.granted,
        )

        worker_a.clear_session("sess-1")

        self.assertIsNone(worker_b.load(tool_key))
        self.assertIsNone(worker_b.load(worker_b.session_key(7, "sess-1")))
        self.assertIsNotNone(
            worker_b.load(
                worker_b.tool_key("run_detector", 7, "sess-2", {"detector": "spray"})
            ),
            "clearing one session must not revoke another",
        )

    def test_approvals_expire_rather_than_living_until_a_restart(self):
        cache = self._cache_backed_by(_FakeRedis())
        self.assertGreater(cache.TTL_SECONDS, 0)
        self.assertLessEqual(
            cache.TTL_SECONDS, 24 * 60 * 60,
            "a sensitive-tool approval should not outlive a working day",
        )

    def test_a_cache_key_stays_bounded_for_a_large_argument_payload(self):
        cache = self._cache_backed_by(_FakeRedis())
        huge = {"search_text": "x" * 100_000}
        self.assertLess(len(cache.tool_key("query_events", 1, "sess-1", huge)), 200)

    def test_redis_being_down_falls_back_to_process_memory(self):
        cache = self.PermissionCache()
        cache._redis = None
        cache._redis_checked = True

        key = cache.tool_key("run_detector", 7, "sess-1", {"detector": "spray"})
        cache.store(key, "sess-1", self.granted)
        self.assertTrue(cache.load(key).allowed)

        cache.clear_session("sess-1")
        self.assertIsNone(cache.load(key))


class _FakeSession:
    """A chat session that records how much of the transcript each save wrote."""

    def __init__(self, messages: Optional[List[Dict[str, Any]]] = None):
        self.conversation_id = "conv-1"
        self.messages = list(messages or [])
        self.message_count = len(self.messages)
        self.appended_writes: List[int] = []
        self.replaced_writes: List[int] = []

    def append_messages(self, new_messages):
        self.appended_writes.append(len(new_messages))
        self.messages = self.messages + list(new_messages)
        self.message_count = len(self.messages)

    def replace_messages(self, messages):
        self.replaced_writes.append(len(messages))
        self.messages = list(messages)
        self.message_count = len(self.messages)


class TranscriptPersistenceTestCase(unittest.TestCase):
    """A turn should cost what the turn added, not what the transcript holds."""

    def setUp(self):
        self.extends = chat_routes._extends_persisted_transcript
        self.persist = chat_routes._persist_chat_session
        self.chat_routes = chat_routes

        class _NoopDbSession:
            def add(self, _obj):
                pass

            def commit(self):
                pass

            def rollback(self):
                pass

        self._real_db = chat_routes.db
        chat_routes.db = type("_Db", (), {"session": _NoopDbSession()})()
        self.addCleanup(lambda: setattr(chat_routes, "db", self._real_db))

    @staticmethod
    def _turn(index):
        return [
            {"role": "user", "content": f"question {index}"},
            {"role": "assistant", "content": f"answer {index}"},
        ]

    def test_a_new_turn_writes_only_the_new_messages(self):
        prior = self._turn(1) + self._turn(2)
        session = _FakeSession(prior)

        self.persist(session, prior + self._turn(3))

        self.assertEqual([2], session.appended_writes)
        self.assertEqual([], session.replaced_writes)
        self.assertEqual(6, len(session.messages))

    def test_write_cost_does_not_grow_with_the_transcript(self):
        session = _FakeSession([])
        history: List[Dict[str, Any]] = []

        for turn in range(25):
            history = history + self._turn(turn)
            self.persist(session, list(history))

        self.assertEqual(
            [2] * 25, session.appended_writes,
            "the twenty-fifth turn wrote more than the first",
        )
        self.assertEqual(50, len(session.messages))

    def test_a_rewritten_history_still_replaces_the_transcript(self):
        session = _FakeSession(self._turn(1) + self._turn(2))

        compacted = [{"role": "assistant", "content": "summary of earlier turns"}]
        self.persist(session, compacted)

        self.assertEqual([], session.appended_writes)
        self.assertEqual([1], session.replaced_writes)
        self.assertEqual(compacted, session.messages)

    def test_an_edited_earlier_message_is_not_treated_as_an_append(self):
        prior = self._turn(1)
        session = _FakeSession(prior)

        edited = [{"role": "user", "content": "different question"}, prior[1]]
        self.persist(session, edited + self._turn(2))

        self.assertEqual([], session.appended_writes)
        self.assertEqual([4], session.replaced_writes)

    def test_an_unchanged_history_writes_nothing_new(self):
        prior = self._turn(1)
        session = _FakeSession(prior)

        self.persist(session, list(prior))

        self.assertEqual([0], session.appended_writes)
        self.assertEqual(prior, session.messages)

    def test_a_shorter_history_never_looks_like_an_extension(self):
        self.assertFalse(self.extends(self._turn(1) + self._turn(2), self._turn(1)))

    def test_the_full_transcript_is_preserved_across_many_turns(self):
        session = _FakeSession([])
        history: List[Dict[str, Any]] = []

        for turn in range(10):
            history = history + self._turn(turn)
            self.persist(session, list(history))

        self.assertEqual(history, session.messages)
        self.assertEqual(len(history), session.message_count)

    def test_a_persistence_failure_does_not_raise_into_the_stream(self):
        class _ExplodingSession(_FakeSession):
            def append_messages(self, new_messages):
                raise RuntimeError("database is down")

        session = _ExplodingSession(self._turn(1))
        self.persist(session, self._turn(1) + self._turn(2))


class TranscriptAppendSqlTestCase(unittest.TestCase):
    """The append must reach the database as a concatenation, not a full write."""

    def test_append_sends_only_the_new_messages_to_the_database(self):
        from models.rag import ChatConversationSession

        captured: Dict[str, Any] = {}

        class _RecordingSession:
            def execute(self, statement, params):
                captured["sql"] = str(statement)
                captured["params"] = params

            def expire(self, _obj, _attrs):
                captured["expired"] = list(_attrs)

        # A bare namespace rather than an ORM instance: the method only needs an
        # id, and instantiating the model would require an app context.
        session = SimpleNamespace(id=42, last_activity_at=None)

        import models.rag as rag_models
        real_db = rag_models.db
        rag_models.db = type("_Db", (), {"session": _RecordingSession()})()
        try:
            ChatConversationSession.append_messages(
                session, [{"role": "user", "content": "new question"}]
            )
        finally:
            rag_models.db = real_db

        self.assertIn("messages || ", captured["sql"])
        self.assertIn("message_count + :added", captured["sql"])
        self.assertEqual(1, captured["params"]["added"])
        self.assertEqual(
            [{"role": "user", "content": "new question"}],
            json.loads(captured["params"]["appended"]),
            "the whole transcript was sent instead of the new messages",
        )
        self.assertIn("messages", captured.get("expired", []))


if __name__ == "__main__":
    unittest.main()
