from __future__ import annotations

import json
import os
import sys
import tempfile
import time
import unittest
from dataclasses import asdict
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import patch

os.environ.setdefault("SECRET_KEY", "phase1b-e2-test-secret")

import clickhouse_connect
from flask import Flask
from sqlalchemy import text

from config import Config
from migrations.add_events_table import EVENTS_COLUMN_DEFINITIONS
from models.case import Case
from models.case_file import CaseFile, IngestProtocolOrigin
from models.client import Client
from models.database import db
from models.database_flow import (
    CapabilityName,
    CaseCapabilityBatchCompletion,
    CaseCapabilitySourceState,
    EvidenceGenerationAudit,
    EvidenceGenerationState,
    EvidenceSourceGeneration,
    IngestAttempt,
    IngestBatch,
    IngestBatchReconciliationAudit,
)
from models.graph_saved_view import GraphSavedView
from models.investigation_thread import InvestigationThread
from models.privacy_alias import PrivacyAlias, PrivacyAliasCounter

_MAPPER_RELATIONSHIP_IMPORTS = (GraphSavedView, InvestigationThread)
from parsers.log_parsers import IISLogParser
from utils.ai.router import (
    REASON_E2_ENFORCEMENT_UNAVAILABLE,
    REASON_PREFLIGHT_INFRASTRUCTURE_FAILURE,
    StrictE2PreflightUnavailable,
    invoke_json,
    invoke_text,
    stream_chat,
)
from utils.ai_privacy_freeze import (
    REASON_CROSS_CASE_OR_MALFORMED,
    REASON_EMPTY_FORENSIC_BYPASS,
    REASON_FOLLOWON_NEW_EVIDENCE,
    REASON_GENERATION_AUTHORITY_CHANGED,
    REASON_GENERATION_FAILED,
    REASON_GENERATION_INVALIDATED,
    REASON_GENERATION_NOT_CURRENT,
    REASON_GENERATION_SUPERSEDED,
    REASON_LEGACY_UNPROVABLE,
    REASON_MISSING_FROZEN_PROOF,
    REASON_NON_EVENT_UNSUPPORTED,
    REASON_PAYLOAD_FINGERPRINT_MISMATCH,
    REASON_PROVIDER_LOCALITY_UNCERTAIN,
    REASON_STAGED_BATCH,
    REASON_UNCOVERED_BATCH,
    REASON_WRONG_DERIVATION_VERSION,
    AIPrivacyPreflightError,
    FrozenAIEvidenceSet,
    VerifiedFrozenEgressProof,
    canonical_fingerprint,
    freeze_selected_clickhouse_rows,
    freeze_selected_observations,
    freeze_verify_enabled,
    inherit_verified_proof_for_followon_payload,
    prepare_verified_case_content,
    select_current_generation_event_rows,
    verify_frozen_privacy_coverage,
)
from utils.capability_watermarks import CAPABILITY_INVENTORY, PRIVACY_ALIASES_V1
from utils.ingest_fence import install_memory_backend, reset_fence_backend
from utils.manifest_protocol import (
    PROTOCOL_CLICKHOUSE_COLUMNS,
    ManifestParserContract,
    activate_initial_generation,
    activate_replacement_generation,
    allocate_case_file_initial_generation,
    allocate_case_file_replacement_generation,
    construct_managed_batch,
    create_ingest_attempt,
    declare_generation_ingest_complete,
    invalidate_source_generation,
    mark_batch_durable,
    reserve_staged_batch,
    verify_ingest_batch,
)
from utils.privacy_aliases import AIPrivacyContext, PrivacyEgressLeakError
from utils.row_local_derivations import derive_privacy_aliases_for_durable_batch
from utils.staged_batch_reconciler import reconcile_staged_batch


PG_URL = os.environ.get("PHASE1B_PG_TEST_DATABASE_URL")
CH_DB = os.environ.get("PHASE1B_CH_TEST_DATABASE")
COVERAGE_PATH = Path("docs/database_flow_phase1b/phase1b_tranche_c3e_parser_coverage.json")

POSTGRES_INDEX_DDL = [
    """
    CREATE UNIQUE INDEX IF NOT EXISTS uq_evidence_source_generation_open_building
    ON evidence_source_generations (case_id, source_ref_type, source_ref_id)
    WHERE visibility_state IN ('BUILDING_INITIAL', 'BUILDING_REPLACEMENT')
    """,
    """
    CREATE UNIQUE INDEX IF NOT EXISTS uq_evidence_source_generation_active
    ON evidence_source_generations (case_id, source_ref_type, source_ref_id)
    WHERE visibility_state = 'ACTIVE'
    """,
]

CLICKHOUSE_CONTROL_TABLE_DDL = [
    """
    CREATE TABLE IF NOT EXISTS visible_evidence_generations (
        case_id UInt32,
        source_ref_type String,
        source_ref_id String,
        source_generation UInt32,
        visibility_state LowCardinality(String),
        state_version UInt64,
        publishable UInt8,
        updated_at DateTime64(3) DEFAULT now64(3)
    )
    ENGINE = ReplacingMergeTree(state_version)
    ORDER BY (case_id, source_ref_type, source_ref_id, source_generation)
    SETTINGS index_granularity = 8192
    """,
    """
    CREATE TABLE IF NOT EXISTS durable_ingest_batches (
        ingest_batch_id String,
        case_id UInt32,
        source_ref_type String,
        source_ref_id String,
        source_generation UInt32,
        batch_ordinal UInt32,
        expected_row_count UInt64,
        batch_content_hash String,
        state LowCardinality(String),
        state_version UInt64,
        durable_at Nullable(DateTime64(3)),
        updated_at DateTime64(3) DEFAULT now64(3)
    )
    ENGINE = ReplacingMergeTree(state_version)
    ORDER BY ingest_batch_id
    SETTINGS index_granularity = 8192
    """,
]


class CapturingRemoteProvider:
    def __init__(self, provider_type="openai"):
        self.calls = []
        self.stream_calls = []
        self._provider_type = provider_type
        self.model = "e2-capturing"

    def provider_type(self):
        return self._provider_type

    def get_provider_display(self):
        return f"{self._provider_type}:e2-capturing"

    def generate(self, **kwargs):
        self.calls.append(("generate", kwargs))
        return {"success": True, "response": "aliased-ok", "usage": {"prompt_tokens": 1}}

    def generate_json(self, **kwargs):
        self.calls.append(("generate_json", kwargs))
        return {"success": True, "data": {"ok": True}, "usage": {"prompt_tokens": 1}}

    def stream_chat(self, **kwargs):
        self.stream_calls.append(kwargs)
        self.calls.append(("stream_chat", kwargs))
        yield {"message": {"content": "chunk"}, "done": True, "usage": {"prompt_tokens": 1}}


class LocalCapturingProvider(CapturingRemoteProvider):
    def provider_type(self):
        return "local"


class UncertainLocalityProvider(CapturingRemoteProvider):
    def provider_type(self):
        return "openai_compatible"


class UnknownTypeProvider(CapturingRemoteProvider):
    def provider_type(self):
        return ""


def _simulate_e2_module_import_failure():
    return patch.dict(sys.modules, {"utils.ai_privacy_freeze": None})


class Phase1BE2ContractUnitTestCase(unittest.TestCase):
    def setUp(self):
        self._old_flag = Config.PHASE1B_AI_PRIVACY_FREEZE_VERIFY_ENABLED
        Config.PHASE1B_AI_PRIVACY_FREEZE_VERIFY_ENABLED = False

    def tearDown(self):
        Config.PHASE1B_AI_PRIVACY_FREEZE_VERIFY_ENABLED = self._old_flag

    def test_feature_flag_defaults_off(self):
        self.assertFalse(Config.PHASE1B_AI_PRIVACY_FREEZE_VERIFY_ENABLED)
        self.assertFalse(freeze_verify_enabled(Config))

    def test_verified_proof_cannot_be_constructed_manually(self):
        with self.assertRaises(TypeError):
            VerifiedFrozenEgressProof(
                frozen=None,
                required_capability="privacy_aliases",
                required_derivation_version=PRIVACY_ALIASES_V1,
                raw_payload_fingerprint="x",
                coverage_reason="nope",
                verified_at=datetime.utcnow(),
                generation_authorities=(),
            )

    def test_case_content_is_not_verified_coverage(self):
        context = AIPrivacyContext.case_content(7)
        self.assertEqual(context.case_id, 7)
        self.assertIsNone(context.verified_egress)

    def test_verified_case_content_rejects_fake_proof(self):
        with self.assertRaises(TypeError):
            AIPrivacyContext.verified_case_content(7, object())

    def test_strict_remote_without_proof_does_not_call_provider(self):
        Config.PHASE1B_AI_PRIVACY_FREEZE_VERIFY_ENABLED = True
        provider = CapturingRemoteProvider()
        with self.assertRaises(AIPrivacyPreflightError) as raised:
            invoke_text(
                function="report",
                prompt="Investigate HOST1",
                provider=provider,
                privacy_context=AIPrivacyContext.case_content(7),
            )
        self.assertEqual(raised.exception.reason, REASON_MISSING_FROZEN_PROOF)
        self.assertEqual(len(provider.calls), 0)

    def test_strict_remote_without_context_does_not_call_provider(self):
        Config.PHASE1B_AI_PRIVACY_FREEZE_VERIFY_ENABLED = True
        provider = CapturingRemoteProvider()
        with self.assertRaises(AIPrivacyPreflightError) as raised:
            invoke_json(function="report", prompt="Investigate HOST1", provider=provider)
        self.assertEqual(raised.exception.reason, REASON_MISSING_FROZEN_PROOF)
        self.assertEqual(len(provider.calls), 0)

    def test_strict_stream_chat_does_not_start_when_preflight_fails(self):
        Config.PHASE1B_AI_PRIVACY_FREEZE_VERIFY_ENABLED = True
        provider = CapturingRemoteProvider()
        with self.assertRaises(AIPrivacyPreflightError):
            list(stream_chat(
                function="chat",
                messages=[{"role": "user", "content": "show events"}],
                provider=provider,
                privacy_context=AIPrivacyContext.case_content(7),
            ))
        self.assertEqual(len(provider.calls), 0)
        self.assertEqual(len(provider.stream_calls), 0)

    def test_local_provider_policy_preserved_without_proof(self):
        Config.PHASE1B_AI_PRIVACY_FREEZE_VERIFY_ENABLED = True
        provider = LocalCapturingProvider()
        result = invoke_text(
            function="report",
            prompt="local case text",
            provider=provider,
            privacy_context=AIPrivacyContext.case_content(7),
        )
        self.assertTrue(result["success"])
        self.assertEqual(len(provider.calls), 1)

    def test_uncertain_openai_compatible_locality_fails_closed(self):
        Config.PHASE1B_AI_PRIVACY_FREEZE_VERIFY_ENABLED = True
        provider = UncertainLocalityProvider()
        with self.assertRaises(AIPrivacyPreflightError) as raised:
            invoke_text(
                function="report",
                prompt="remote-looking compat",
                provider=provider,
                privacy_context=AIPrivacyContext.case_content(7),
            )
        self.assertEqual(raised.exception.reason, REASON_PROVIDER_LOCALITY_UNCERTAIN)
        self.assertEqual(len(provider.calls), 0)

    def test_flag_off_preserves_pre_e2_remote_case_content_path(self):
        provider = CapturingRemoteProvider()

        def passthrough(value, *, context, provider):
            return type("Sanitized", (), {"value": value, "metadata": {"enabled": True, "aliases_applied": 1}})()

        with patch("utils.privacy_aliases.sanitize_for_ai_egress", side_effect=passthrough):
            result = invoke_text(
                function="report",
                prompt="Investigate alice@client.example",
                provider=provider,
                privacy_context=AIPrivacyContext.case_content(7),
            )
        self.assertTrue(result["success"])
        self.assertEqual(len(provider.calls), 1)

    def test_c3_coverage_regression_counts(self):
        entries = json.loads(COVERAGE_PATH.read_text())
        certified = [row for row in entries if row["classification"] == "CERTIFIED_MANAGED"]
        deferred = [row for row in entries if row["classification"] == "DEFERRED_LEGACY_ONLY"]
        other = [row for row in entries if row["classification"] not in {"CERTIFIED_MANAGED", "DEFERRED_LEGACY_ONLY"}]
        self.assertEqual(len(entries), 84)
        self.assertEqual(len(certified), 12)
        self.assertEqual(len(deferred), 72)
        self.assertEqual(len(other), 0)

    def test_deferred_capabilities_remain_unmigrated(self):
        self.assertTrue(CAPABILITY_INVENTORY[CapabilityName.PRIVACY_ALIASES]["e1_migrated"])
        for name in (
            CapabilityName.IOC_MATCHES,
            CapabilityName.MITRE_MATCHES,
            CapabilityName.GRAPH_EXTRACTION,
            CapabilityName.KNOWN_PRINCIPAL_DISCOVERY,
            CapabilityName.BEHAVIORAL_PROFILE_CONTRIBUTION,
            CapabilityName.PATTERN_DETECTION,
            CapabilityName.EVENT_EMBEDDINGS,
        ):
            self.assertFalse(CAPABILITY_INVENTORY[name]["e1_migrated"], name)

    def test_no_events_current_or_readiness_cutover_in_e2_module(self):
        source = Path("utils/ai_privacy_freeze.py").read_text()
        self.assertNotIn("events_current", source)
        self.assertNotIn("completion-tail", source)
        self.assertNotIn("readiness UI", source)

    def test_e2_import_failure_blocks_remote_invoke_text(self):
        Config.PHASE1B_AI_PRIVACY_FREEZE_VERIFY_ENABLED = True
        provider = CapturingRemoteProvider()
        with _simulate_e2_module_import_failure():
            with self.assertRaises(StrictE2PreflightUnavailable) as raised:
                invoke_text(
                    function="report",
                    prompt="Investigate HOST1 user1@client.example",
                    provider=provider,
                    privacy_context=AIPrivacyContext.case_content(7),
                )
        self.assertEqual(raised.exception.reason, REASON_E2_ENFORCEMENT_UNAVAILABLE)
        self.assertEqual(len(provider.calls), 0)

    def test_e2_import_failure_blocks_remote_invoke_json(self):
        Config.PHASE1B_AI_PRIVACY_FREEZE_VERIFY_ENABLED = True
        provider = CapturingRemoteProvider()
        with _simulate_e2_module_import_failure():
            with self.assertRaises(StrictE2PreflightUnavailable) as raised:
                invoke_json(
                    function="report",
                    prompt="Investigate HOST1 user1@client.example",
                    provider=provider,
                    privacy_context=AIPrivacyContext.case_content(7),
                )
        self.assertEqual(raised.exception.reason, REASON_E2_ENFORCEMENT_UNAVAILABLE)
        self.assertEqual(len(provider.calls), 0)
        self.assertEqual(sum(1 for name, _kwargs in provider.calls if name == "generate_json"), 0)

    def test_e2_import_failure_blocks_remote_stream_chat(self):
        Config.PHASE1B_AI_PRIVACY_FREEZE_VERIFY_ENABLED = True
        provider = CapturingRemoteProvider()
        with _simulate_e2_module_import_failure():
            with self.assertRaises(StrictE2PreflightUnavailable) as raised:
                list(stream_chat(
                    function="chat",
                    messages=[{"role": "user", "content": "show HOST1 events"}],
                    provider=provider,
                    privacy_context=AIPrivacyContext.case_content(7),
                ))
        self.assertEqual(raised.exception.reason, REASON_E2_ENFORCEMENT_UNAVAILABLE)
        self.assertEqual(len(provider.calls), 0)
        self.assertEqual(len(provider.stream_calls), 0)

    def test_e2_import_failure_does_not_treat_none_context_as_non_case(self):
        Config.PHASE1B_AI_PRIVACY_FREEZE_VERIFY_ENABLED = True
        provider = CapturingRemoteProvider()
        with _simulate_e2_module_import_failure():
            with self.assertRaises(StrictE2PreflightUnavailable) as raised:
                invoke_text(
                    function="report",
                    prompt="Investigate HOST1",
                    provider=provider,
                    privacy_context=None,
                )
        self.assertEqual(raised.exception.reason, REASON_E2_ENFORCEMENT_UNAVAILABLE)
        self.assertEqual(len(provider.calls), 0)

    def test_preflight_infrastructure_failure_does_not_disable_gate(self):
        Config.PHASE1B_AI_PRIVACY_FREEZE_VERIFY_ENABLED = True
        provider = CapturingRemoteProvider()
        with patch(
            "utils.ai_privacy_freeze.require_remote_case_content_preflight",
            side_effect=RuntimeError("authoritative preflight lookup failed"),
        ):
            with self.assertRaises(Exception) as raised:
                invoke_text(
                    function="report",
                    prompt="Investigate HOST1",
                    provider=provider,
                    privacy_context=AIPrivacyContext.case_content(7),
                )
        self.assertEqual(getattr(raised.exception, "reason", None), REASON_PREFLIGHT_INFRASTRUCTURE_FAILURE)
        self.assertEqual(len(provider.calls), 0)

    def test_get_preflight_session_failure_does_not_disable_gate(self):
        Config.PHASE1B_AI_PRIVACY_FREEZE_VERIFY_ENABLED = True
        provider = CapturingRemoteProvider()
        with patch(
            "utils.ai_privacy_freeze.get_preflight_session",
            side_effect=RuntimeError("authority session lookup failed"),
        ):
            with self.assertRaises(Exception) as raised:
                invoke_text(
                    function="report",
                    prompt="Investigate HOST1",
                    provider=provider,
                    privacy_context=AIPrivacyContext.case_content(7),
                )
        self.assertEqual(getattr(raised.exception, "reason", None), REASON_PREFLIGHT_INFRASTRUCTURE_FAILURE)
        self.assertEqual(len(provider.calls), 0)

    def test_unknown_provider_type_fails_closed(self):
        Config.PHASE1B_AI_PRIVACY_FREEZE_VERIFY_ENABLED = True
        provider = UnknownTypeProvider()
        with self.assertRaises(Exception) as raised:
            invoke_text(
                function="report",
                prompt="Investigate HOST1",
                provider=provider,
                privacy_context=AIPrivacyContext.case_content(7),
            )
        self.assertEqual(getattr(raised.exception, "reason", None), REASON_PROVIDER_LOCALITY_UNCERTAIN)
        self.assertEqual(len(provider.calls), 0)

    def test_e2_import_failure_preserves_local_provider(self):
        Config.PHASE1B_AI_PRIVACY_FREEZE_VERIFY_ENABLED = True
        provider = LocalCapturingProvider()
        with _simulate_e2_module_import_failure():
            result = invoke_text(
                function="report",
                prompt="local case text",
                provider=provider,
                privacy_context=AIPrivacyContext.case_content(7),
            )
        self.assertTrue(result["success"])
        self.assertEqual(len(provider.calls), 1)

    def test_non_content_admin_remote_without_case_payload(self):
        Config.PHASE1B_AI_PRIVACY_FREEZE_VERIFY_ENABLED = True
        provider = CapturingRemoteProvider()
        result = invoke_text(
            function="model_health",
            prompt="list available models",
            provider=provider,
            privacy_context=AIPrivacyContext.non_content_admin(),
        )
        self.assertTrue(result["success"])
        self.assertEqual(len(provider.calls), 1)

    def test_non_content_admin_is_not_a_case_content_bypass(self):
        Config.PHASE1B_AI_PRIVACY_FREEZE_VERIFY_ENABLED = True
        provider = CapturingRemoteProvider()
        with self.assertRaises(Exception) as raised:
            invoke_text(
                function="report",
                prompt="Investigate HOST1 and alice@client.example",
                provider=provider,
                privacy_context=AIPrivacyContext.case_content(7),
            )
        self.assertEqual(getattr(raised.exception, "reason", None), REASON_MISSING_FROZEN_PROOF)
        self.assertEqual(len(provider.calls), 0)

    def test_e2_import_failure_preserves_non_content_admin(self):
        Config.PHASE1B_AI_PRIVACY_FREEZE_VERIFY_ENABLED = True
        provider = CapturingRemoteProvider()
        with _simulate_e2_module_import_failure():
            result = invoke_text(
                function="model_health",
                prompt="list available models",
                provider=provider,
                privacy_context=AIPrivacyContext.non_content_admin(),
            )
        self.assertTrue(result["success"])
        self.assertEqual(len(provider.calls), 1)

    def test_sanitizer_unavailable_still_blocks_remote_under_strict_e2_off(self):
        provider = CapturingRemoteProvider()
        with patch.dict(sys.modules, {"utils.privacy_aliases": None}):
            with self.assertRaises(RuntimeError) as raised:
                invoke_text(
                    function="report",
                    prompt="Investigate HOST1",
                    provider=provider,
                    privacy_context=None,
                )
        self.assertIn("privacy sanitizer unavailable", str(raised.exception))
        self.assertEqual(len(provider.calls), 0)

    def test_inherit_helper_is_not_used_by_chat_or_retrieval_paths(self):
        production_paths = [
            Path("utils/chat_agent.py"),
            Path("routes/rag.py"),
            Path("utils/ai_report_generator.py"),
            Path("utils/ai_timeline_generator.py"),
            Path("utils/ai_correlation_analyzer.py"),
            Path("utils/ai_event_summary.py"),
            Path("utils/ai_subagents.py"),
            Path("utils/ai_checkpoints.py"),
        ]
        for path in production_paths:
            source = path.read_text()
            self.assertNotIn("inherit_verified_proof_for_followon_payload", source, path)
        review_source = Path("utils/ai_review.py").read_text()
        self.assertIn("inherit_verified_proof_for_followon_payload", review_source)
        self.assertIn('followon_kind="second_pass_review"', review_source)


@unittest.skipUnless(PG_URL and CH_DB, "PHASE1B_PG_TEST_DATABASE_URL and PHASE1B_CH_TEST_DATABASE are required")
class Phase1BE2RealPGCHTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        install_memory_backend()
        cls._old_flag = getattr(Config, "PHASE1B_MANIFEST_PROTOCOL_ENABLED", False)
        cls._old_incremental = getattr(Config, "PHASE1B_INCREMENTAL_ROW_LOCAL_DERIVATIONS_ENABLED", False)
        cls._old_e2 = getattr(Config, "PHASE1B_AI_PRIVACY_FREEZE_VERIFY_ENABLED", False)
        cls._old_batch_size = getattr(Config, "PHASE1B_MANIFEST_BATCH_SIZE", None)
        Config.PHASE1B_MANIFEST_PROTOCOL_ENABLED = True
        Config.PHASE1B_INCREMENTAL_ROW_LOCAL_DERIVATIONS_ENABLED = False
        Config.PHASE1B_AI_PRIVACY_FREEZE_VERIFY_ENABLED = True
        Config.PHASE1B_MANIFEST_BATCH_SIZE = 4
        cls.app = Flask(__name__)
        cls.app.config.update(
            SQLALCHEMY_DATABASE_URI=PG_URL,
            SQLALCHEMY_TRACK_MODIFICATIONS=False,
            SECRET_KEY="phase1b-e2-ch",
        )
        db.init_app(cls.app)
        cls.ctx = cls.app.app_context()
        cls.ctx.push()
        with db.engine.begin() as conn:
            conn.execute(text("DROP SCHEMA IF EXISTS public CASCADE"))
            conn.execute(text("CREATE SCHEMA public"))
        for table in (
            Client.__table__,
            Case.__table__,
            CaseFile.__table__,
            EvidenceSourceGeneration.__table__,
            EvidenceGenerationAudit.__table__,
            IngestAttempt.__table__,
            IngestBatch.__table__,
            IngestBatchReconciliationAudit.__table__,
            CaseCapabilitySourceState.__table__,
            CaseCapabilityBatchCompletion.__table__,
            PrivacyAlias.__table__,
            PrivacyAliasCounter.__table__,
        ):
            table.create(db.engine, checkfirst=True)
        with db.engine.begin() as conn:
            for ddl in POSTGRES_INDEX_DDL:
                conn.execute(text(ddl))
        cls.ch = clickhouse_connect.get_client(
            host=os.environ.get("CLICKHOUSE_HOST", "localhost"),
            port=int(os.environ.get("CLICKHOUSE_PORT", 8123)),
            username=os.environ.get("CLICKHOUSE_USER", "default"),
            password=os.environ.get("CLICKHOUSE_PASSWORD", ""),
            database=CH_DB,
            autogenerate_session_id=False,
        )
        columns = ",\n".join(f"    {name} {definition}" for name, definition in EVENTS_COLUMN_DEFINITIONS.items())
        cls.ch.command(f"""
        CREATE TABLE IF NOT EXISTS events (
        {columns}
        )
        ENGINE = MergeTree
        PARTITION BY case_id
        ORDER BY (case_id, timestamp_utc, artifact_type, source_host, source_file, event_id)
        SETTINGS index_granularity = 8192
        """)
        for ddl in CLICKHOUSE_CONTROL_TABLE_DDL:
            cls.ch.command(ddl)

    @classmethod
    def tearDownClass(cls):
        cls.ch.command("DROP TABLE IF EXISTS events")
        cls.ch.command("DROP TABLE IF EXISTS visible_evidence_generations")
        cls.ch.command("DROP TABLE IF EXISTS durable_ingest_batches")
        cls.ch.close()
        with db.engine.begin() as conn:
            conn.execute(text("DROP SCHEMA IF EXISTS public CASCADE"))
            conn.execute(text("CREATE SCHEMA public"))
        cls.ctx.pop()
        Config.PHASE1B_MANIFEST_PROTOCOL_ENABLED = cls._old_flag
        Config.PHASE1B_INCREMENTAL_ROW_LOCAL_DERIVATIONS_ENABLED = cls._old_incremental
        Config.PHASE1B_AI_PRIVACY_FREEZE_VERIFY_ENABLED = cls._old_e2
        if cls._old_batch_size is None:
            try:
                delattr(Config, "PHASE1B_MANIFEST_BATCH_SIZE")
            except AttributeError:
                pass
        else:
            Config.PHASE1B_MANIFEST_BATCH_SIZE = cls._old_batch_size
        reset_fence_backend()

    def setUp(self):
        Config.PHASE1B_AI_PRIVACY_FREEZE_VERIFY_ENABLED = True
        self._audit_patch = patch("utils.ai.router._record_ai_audit", return_value=None)
        self._audit_patch.start()
        self.ch.command("TRUNCATE TABLE events")
        self.ch.command("TRUNCATE TABLE visible_evidence_generations")
        self.ch.command("TRUNCATE TABLE durable_ingest_batches")
        PrivacyAlias.query.delete()
        PrivacyAliasCounter.query.delete()
        CaseCapabilityBatchCompletion.query.delete()
        CaseCapabilitySourceState.query.delete()
        IngestBatchReconciliationAudit.query.delete()
        IngestBatch.query.delete()
        IngestAttempt.query.delete()
        EvidenceGenerationAudit.query.delete()
        EvidenceSourceGeneration.query.delete()
        CaseFile.query.delete()
        Case.query.delete()
        Client.query.delete()
        db.session.commit()
        self.client = Client(name="E2 CH", code=f"E2C{time.time_ns() % 100000}", created_by="tester")
        self.case = Case(uuid=f"e2-ch-{time.time_ns()}", name="E2 CH", company="Example", client=self.client, created_by="tester")
        self.tempdir = tempfile.TemporaryDirectory()
        iis_path = os.path.join(self.tempdir.name, "u_ex260101.log")
        lines = [
            "#Software: Microsoft Internet Information Services",
            "#Version: 1.0",
            "#Fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs(User-Agent) sc-status",
        ]
        for idx in range(12):
            query = f"id={idx}&q=alpha" if idx % 2 else "-"
            username = f"user{idx}" if idx % 3 else "-"
            lines.append(
                f"2026-01-01 00:00:{idx:02d} 10.0.0.10 GET /path/{idx} {query} 443 {username} 192.0.2.{idx + 1} Agent{idx} 200"
            )
        with open(iis_path, "w", encoding="utf-8") as handle:
            handle.write("\n".join(lines) + "\n")
        self.case_file = CaseFile(
            case_uuid=self.case.uuid,
            filename="u_ex260101.log",
            original_filename="u_ex260101.log",
            file_path=iis_path,
            file_size=1,
            sha256_hash="7" * 64,
            uploaded_by="tester",
            ingest_protocol_origin=IngestProtocolOrigin.NOT_STARTED,
        )
        db.session.add_all([self.client, self.case, self.case_file])
        db.session.commit()
        parser = IISLogParser(case_id=self.case.id, case_file_id=self.case_file.id)
        self.events = list(parser.parse(iis_path))
        self.contract = ManifestParserContract(
            parser_version=parser.parser_version,
            normalization_version="normalization:v1",
            configured_batch_size=4,
            ordering_contract=parser.manifest_ordering_contract,
            producer_version=parser.parser_version,
            manifest_eligible=True,
        )

    def tearDown(self):
        self._audit_patch.stop()
        db.session.remove()
        self.tempdir.cleanup()

    def _generation(self):
        generation = allocate_case_file_initial_generation(
            session=db.session,
            case_id=self.case.id,
            case_file_id=self.case_file.id,
            contract=self.contract,
        )
        db.session.commit()
        return generation

    def _ingest_batch(self, generation, events, *, batch_ordinal, durable=True):
        attempt = create_ingest_attempt(session=db.session, generation=generation)
        manifest = construct_managed_batch(
            generation=generation,
            attempt=attempt,
            events=events,
            batch_ordinal=batch_ordinal,
        )
        batch = reserve_staged_batch(session=db.session, manifest=manifest)
        db.session.commit()
        self.ch.insert("events", list(manifest.clickhouse_rows), column_names=list(PROTOCOL_CLICKHOUSE_COLUMNS))
        if durable:
            mark_batch_durable(session=db.session, batch=batch, verification=verify_ingest_batch(self.ch, manifest))
            db.session.commit()
        return batch, manifest

    def _derive(self, batch):
        result = derive_privacy_aliases_for_durable_batch(
            session=db.session,
            ingest_batch_id=batch.ingest_batch_id,
            privacy_level="basic",
            clickhouse_client=self.ch,
        )
        db.session.commit()
        return result

    def _select_freeze(self, *, keys=None):
        rows, ch_queries = select_current_generation_event_rows(
            db.session,
            self.ch,
            case_id=self.case.id,
            source_ref_type="CASE_FILE",
            source_ref_id=str(self.case_file.id),
            evidence_record_keys=keys,
        )
        frozen = freeze_selected_clickhouse_rows(
            db.session,
            case_id=self.case.id,
            rows=rows,
            ch_queries=ch_queries,
        )
        return frozen, rows

    def _payload_for(self, frozen: FrozenAIEvidenceSet, extra: str = "") -> dict:
        prompt = frozen.payload_from_frozen_excerpts()
        if extra:
            prompt = f"{prompt}\n{extra}" if prompt else extra
        return {"prompt": prompt, "system": "Return only the provided evidence."}

    def _invoke_verified(self, frozen, provider, extra=""):
        raw_payload = self._payload_for(frozen, extra)
        context, proof = prepare_verified_case_content(
            db.session,
            frozen,
            raw_payload=raw_payload,
            privacy_level="basic",
        )
        started = time.perf_counter()
        result = invoke_text(
            function="report",
            prompt=raw_payload["prompt"],
            system=raw_payload["system"],
            provider=provider,
            privacy_context=context,
        )
        preflight_ms = (time.perf_counter() - started) * 1000.0
        return result, proof, raw_payload, preflight_ms

    def test_success_sends_only_aliased_frozen_payload(self):
        generation = self._generation()
        batch0, _ = self._ingest_batch(generation, self.events[0:4], batch_ordinal=0)
        batch1, _ = self._ingest_batch(generation, self.events[4:8], batch_ordinal=1)
        self._derive(batch0)
        self._derive(batch1)
        frozen, rows = self._select_freeze()
        self.assertEqual(frozen.forensic_event_count, 8)
        self.assertEqual(len(frozen.managed_batch_ids), 2)
        provider = CapturingRemoteProvider()
        result, _proof, raw_payload, _ms = self._invoke_verified(frozen, provider)
        self.assertTrue(result["success"])
        self.assertEqual(len(provider.calls), 1)
        sent = provider.calls[0][1]["prompt"]
        self.assertEqual(canonical_fingerprint({"prompt": sent, "system": provider.calls[0][1]["system"]}), result["privacy"].get("final_outbound_payload_fingerprint") or canonical_fingerprint({"prompt": sent, "system": raw_payload["system"]}))
        self.assertNotIn("user1", sent)
        self.assertNotIn("user2", sent)
        self.assertTrue(any(token.startswith("USERNAME_") or "HOST_" in sent or "IPV4_" in sent or sent != raw_payload["prompt"] for token in [sent]))
        self.assertNotIn("user8", sent)
        self.assertEqual(result["privacy"]["verification_passed"], True)
        self.assertEqual(result["privacy"]["erk_count"], 8)

    def test_one_uncovered_batch_blocks_entire_request(self):
        generation = self._generation()
        batch0, _ = self._ingest_batch(generation, self.events[0:4], batch_ordinal=0)
        batch1, _ = self._ingest_batch(generation, self.events[4:8], batch_ordinal=1)
        batch2, _ = self._ingest_batch(generation, self.events[8:12], batch_ordinal=2)
        self._derive(batch0)
        self._derive(batch1)
        frozen, _rows = self._select_freeze()
        self.assertIn(batch2.ingest_batch_id, frozen.managed_batch_ids)
        provider = CapturingRemoteProvider()
        raw_payload = self._payload_for(frozen)
        with self.assertRaises(AIPrivacyPreflightError) as raised:
            prepare_verified_case_content(db.session, frozen, raw_payload=raw_payload)
        self.assertEqual(raised.exception.reason, REASON_UNCOVERED_BATCH)
        with self.assertRaises(AIPrivacyPreflightError):
            invoke_text(
                function="report",
                prompt=raw_payload["prompt"],
                system=raw_payload["system"],
                provider=provider,
                privacy_context=AIPrivacyContext.case_content(self.case.id),
            )
        self.assertEqual(len(provider.calls), 0)

    def test_new_ingest_after_freeze_cannot_expand_request(self):
        generation = self._generation()
        batch0, _ = self._ingest_batch(generation, self.events[0:4], batch_ordinal=0)
        batch1, _ = self._ingest_batch(generation, self.events[4:8], batch_ordinal=1)
        self._derive(batch0)
        self._derive(batch1)
        frozen, _rows = self._select_freeze(keys=[event.evidence_record_key for event in self.events[0:8]])
        batch2, _ = self._ingest_batch(generation, self.events[8:12], batch_ordinal=2)
        later_batch_id = batch2.ingest_batch_id
        self._derive(batch2)
        provider = CapturingRemoteProvider()
        result, _proof, raw_payload, _ms = self._invoke_verified(frozen, provider)
        self.assertTrue(result["success"])
        sent = provider.calls[0][1]["prompt"]
        later_keys = [event.evidence_record_key for event in self.events[8:12]]
        for key in later_keys:
            self.assertNotIn(key, sent)
        self.assertEqual(frozen.forensic_event_count, 8)
        self.assertNotIn(later_batch_id, frozen.managed_batch_ids)

    def test_coverage_completed_after_failed_verify_requires_explicit_reverify(self):
        generation = self._generation()
        batch0, _ = self._ingest_batch(generation, self.events[0:4], batch_ordinal=0)
        frozen, _rows = self._select_freeze(keys=[event.evidence_record_key for event in self.events[0:4]])
        raw_payload = self._payload_for(frozen)
        with self.assertRaises(AIPrivacyPreflightError) as raised:
            verify_frozen_privacy_coverage(db.session, frozen, raw_payload=raw_payload)
        self.assertEqual(raised.exception.reason, REASON_UNCOVERED_BATCH)
        self._derive(batch0)
        proof = verify_frozen_privacy_coverage(db.session, frozen, raw_payload=raw_payload)
        self.assertTrue(proof.coverage_reason)
        provider = CapturingRemoteProvider()
        context = AIPrivacyContext.verified_case_content(self.case.id, proof, privacy_level="basic")
        result = invoke_text(
            function="report",
            prompt=raw_payload["prompt"],
            system=raw_payload["system"],
            provider=provider,
            privacy_context=context,
        )
        self.assertTrue(result["success"])
        self.assertEqual(len(provider.calls), 1)

    def test_staged_batch_blocks_remote_egress(self):
        generation = self._generation()
        self._ingest_batch(generation, self.events[0:4], batch_ordinal=0, durable=False)
        frozen, _rows = self._select_freeze(keys=[event.evidence_record_key for event in self.events[0:4]])
        provider = CapturingRemoteProvider()
        with self.assertRaises(AIPrivacyPreflightError) as raised:
            prepare_verified_case_content(db.session, frozen, raw_payload=self._payload_for(frozen))
        self.assertEqual(raised.exception.reason, REASON_STAGED_BATCH)
        self.assertEqual(len(provider.calls), 0)

    def test_wrong_derivation_version_does_not_satisfy_v2(self):
        generation = self._generation()
        batch0, _ = self._ingest_batch(generation, self.events[0:4], batch_ordinal=0)
        self._derive(batch0)
        frozen_v1, _ = self._select_freeze(keys=[event.evidence_record_key for event in self.events[0:4]])
        frozen_v2 = freeze_selected_observations(
            db.session,
            case_id=self.case.id,
            observations=list(frozen_v1.observations),
            required_derivation_version="privacy-aliases:v2",
        )
        provider = CapturingRemoteProvider()
        with self.assertRaises(AIPrivacyPreflightError) as raised:
            prepare_verified_case_content(db.session, frozen_v2, raw_payload=self._payload_for(frozen_v2))
        self.assertEqual(raised.exception.reason, REASON_WRONG_DERIVATION_VERSION)
        self.assertEqual(len(provider.calls), 0)

    def test_mixed_managed_and_legacy_is_blocked(self):
        generation = self._generation()
        batch0, _ = self._ingest_batch(generation, self.events[0:4], batch_ordinal=0)
        self._derive(batch0)
        frozen_managed, _ = self._select_freeze(keys=[event.evidence_record_key for event in self.events[0:4]])
        mixed = list(frozen_managed.observations) + [
            {
                "case_id": self.case.id,
                "evidence_record_key": "legacy-erk-1",
                "ingest_batch_id": None,
                "source_ref_type": "CASE_FILE",
                "source_ref_id": str(self.case_file.id),
                "source_generation": None,
                "managed": False,
                "payload_excerpt": "legacy row",
            }
        ]
        frozen = freeze_selected_observations(db.session, case_id=self.case.id, observations=mixed)
        provider = CapturingRemoteProvider()
        with self.assertRaises(AIPrivacyPreflightError) as raised:
            prepare_verified_case_content(db.session, frozen, raw_payload=self._payload_for(frozen))
        self.assertEqual(raised.exception.reason, REASON_LEGACY_UNPROVABLE)
        self.assertEqual(len(provider.calls), 0)

    def test_cross_case_freeze_fails_closed(self):
        generation = self._generation()
        batch0, _ = self._ingest_batch(generation, self.events[0:4], batch_ordinal=0)
        self._derive(batch0)
        frozen, _ = self._select_freeze(keys=[event.evidence_record_key for event in self.events[0:4]])
        bad = [asdict(frozen.observations[0]) | {"case_id": self.case.id + 99}]
        with self.assertRaises(AIPrivacyPreflightError) as raised:
            freeze_selected_observations(db.session, case_id=self.case.id, observations=bad)
        self.assertEqual(raised.exception.reason, REASON_CROSS_CASE_OR_MALFORMED)

    def test_invalidation_after_verify_blocks_provider(self):
        generation = self._generation()
        batch0, _ = self._ingest_batch(generation, self.events[0:4], batch_ordinal=0)
        self._derive(batch0)
        frozen, _ = self._select_freeze(keys=[event.evidence_record_key for event in self.events[0:4]])
        raw_payload = self._payload_for(frozen)
        context, _proof = prepare_verified_case_content(db.session, frozen, raw_payload=raw_payload, privacy_level="basic")
        invalidate_source_generation(session=db.session, generation=generation, actor="tester", reason="e2")
        db.session.commit()
        provider = CapturingRemoteProvider()
        with self.assertRaises(AIPrivacyPreflightError) as raised:
            invoke_text(
                function="report",
                prompt=raw_payload["prompt"],
                system=raw_payload["system"],
                provider=provider,
                privacy_context=context,
            )
        self.assertIn(raised.exception.reason, {REASON_GENERATION_INVALIDATED, REASON_UNCOVERED_BATCH})
        self.assertEqual(len(provider.calls), 0)

    def test_replacement_progress_does_not_leak_into_default_freeze(self):
        initial = self._generation()
        batch0, _ = self._ingest_batch(initial, self.events[0:4], batch_ordinal=0)
        batch1, _ = self._ingest_batch(initial, self.events[4:8], batch_ordinal=1)
        self._derive(batch0)
        self._derive(batch1)
        declare_generation_ingest_complete(
            session=db.session,
            generation=initial,
            expected_rows=8,
            final_batch_ordinal=1,
        )
        activate_initial_generation(session=db.session, generation=initial, actor="tester", reason="e2")
        db.session.commit()
        replacement = allocate_case_file_replacement_generation(
            session=db.session,
            case_id=self.case.id,
            case_file_id=self.case_file.id,
            contract=self.contract,
        )
        db.session.commit()
        repl_batch, _ = self._ingest_batch(replacement, self.events[8:12], batch_ordinal=0)
        self._derive(repl_batch)
        frozen, rows = self._select_freeze()
        self.assertTrue(rows)
        self.assertTrue(all(int(row["source_generation"]) == 1 for row in rows))
        self.assertNotIn(repl_batch.ingest_batch_id, frozen.managed_batch_ids)
        provider = CapturingRemoteProvider()
        result, _proof, raw_payload, _ms = self._invoke_verified(frozen, provider)
        self.assertTrue(result["success"])
        for key in [event.evidence_record_key for event in self.events[8:12]]:
            self.assertNotIn(key, provider.calls[0][1]["prompt"])

    def test_activation_after_verify_blocks_stale_n_request(self):
        initial = self._generation()
        batch0, _ = self._ingest_batch(initial, self.events[0:4], batch_ordinal=0)
        batch1, _ = self._ingest_batch(initial, self.events[4:8], batch_ordinal=1)
        self._derive(batch0)
        self._derive(batch1)
        declare_generation_ingest_complete(session=db.session, generation=initial, expected_rows=8, final_batch_ordinal=1)
        activate_initial_generation(session=db.session, generation=initial, actor="tester", reason="e2")
        db.session.commit()
        frozen, _ = self._select_freeze(keys=[event.evidence_record_key for event in self.events[0:8]])
        raw_payload = self._payload_for(frozen)
        context, _proof = prepare_verified_case_content(db.session, frozen, raw_payload=raw_payload, privacy_level="basic")
        replacement = allocate_case_file_replacement_generation(
            session=db.session,
            case_id=self.case.id,
            case_file_id=self.case_file.id,
            contract=self.contract,
        )
        db.session.commit()
        repl_batch0, _ = self._ingest_batch(replacement, self.events[8:12], batch_ordinal=0)
        self._derive(repl_batch0)
        declare_generation_ingest_complete(session=db.session, generation=replacement, expected_rows=4, final_batch_ordinal=0)
        activate_replacement_generation(session=db.session, replacement=replacement, actor="tester", reason="e2")
        db.session.commit()
        provider = CapturingRemoteProvider()
        with self.assertRaises(AIPrivacyPreflightError) as raised:
            invoke_text(
                function="report",
                prompt=raw_payload["prompt"],
                system=raw_payload["system"],
                provider=provider,
                privacy_context=context,
            )
        self.assertIn(
            raised.exception.reason,
            {REASON_GENERATION_AUTHORITY_CHANGED, REASON_GENERATION_SUPERSEDED, REASON_GENERATION_NOT_CURRENT},
        )
        self.assertEqual(len(provider.calls), 0)

    def test_after_activation_incomplete_n1_does_not_fall_back_to_n(self):
        initial = self._generation()
        batch0, _ = self._ingest_batch(initial, self.events[0:4], batch_ordinal=0)
        self._derive(batch0)
        declare_generation_ingest_complete(session=db.session, generation=initial, expected_rows=4, final_batch_ordinal=0)
        activate_initial_generation(session=db.session, generation=initial, actor="tester", reason="e2")
        db.session.commit()
        replacement = allocate_case_file_replacement_generation(
            session=db.session,
            case_id=self.case.id,
            case_file_id=self.case_file.id,
            contract=self.contract,
        )
        db.session.commit()
        repl_batch, _ = self._ingest_batch(replacement, self.events[4:8], batch_ordinal=0)
        declare_generation_ingest_complete(session=db.session, generation=replacement, expected_rows=4, final_batch_ordinal=0)
        activate_replacement_generation(session=db.session, replacement=replacement, actor="tester", reason="e2")
        db.session.commit()
        frozen, rows = self._select_freeze()
        self.assertTrue(all(int(row["source_generation"]) == 2 for row in rows))
        provider = CapturingRemoteProvider()
        with self.assertRaises(AIPrivacyPreflightError) as raised:
            prepare_verified_case_content(db.session, frozen, raw_payload=self._payload_for(frozen))
        self.assertEqual(raised.exception.reason, REASON_UNCOVERED_BATCH)
        self.assertEqual(len(provider.calls), 0)
        self._derive(repl_batch)
        result, _proof, _raw, _ms = self._invoke_verified(frozen, provider)
        self.assertTrue(result["success"])
        self.assertEqual(len(provider.calls), 1)

    def test_d2_repair_then_new_freeze_succeeds(self):
        generation = self._generation()
        batch0, _ = self._ingest_batch(generation, self.events[0:4], batch_ordinal=0)
        batch1, manifest1 = self._ingest_batch(generation, self.events[4:8], batch_ordinal=1, durable=False)
        self._derive(batch0)
        frozen_staged, _ = self._select_freeze(keys=[event.evidence_record_key for event in self.events[0:8]])
        with self.assertRaises(AIPrivacyPreflightError) as raised:
            prepare_verified_case_content(db.session, frozen_staged, raw_payload=self._payload_for(frozen_staged))
        self.assertEqual(raised.exception.reason, REASON_STAGED_BATCH)
        finish_attempt = IngestAttempt.query.filter_by(ingest_attempt_id=batch1.ingest_attempt_id).one()
        finish_attempt.status = "FAILED"
        finish_attempt.lease_expires_at = datetime.utcnow() - timedelta(seconds=1)
        db.session.commit()
        result = reconcile_staged_batch(session=db.session, clickhouse_client=self.ch, ingest_batch_id=manifest1.ingest_batch_id)
        self.assertEqual(result.action_taken, "mark_durable")
        self.assertEqual(CaseCapabilityBatchCompletion.query.count(), 1)
        self._derive(batch1)
        frozen, _ = self._select_freeze(keys=[event.evidence_record_key for event in self.events[0:8]])
        provider = CapturingRemoteProvider()
        invoked, _proof, _raw, _ms = self._invoke_verified(frozen, provider)
        self.assertTrue(invoked["success"])
        self.assertEqual(len(provider.calls), 1)

    def test_payload_fingerprint_mismatch_blocks(self):
        generation = self._generation()
        batch0, _ = self._ingest_batch(generation, self.events[0:4], batch_ordinal=0)
        self._derive(batch0)
        frozen, _ = self._select_freeze(keys=[event.evidence_record_key for event in self.events[0:4]])
        raw_payload = self._payload_for(frozen)
        context, _proof = prepare_verified_case_content(db.session, frozen, raw_payload=raw_payload, privacy_level="basic")
        provider = CapturingRemoteProvider()
        with self.assertRaises(AIPrivacyPreflightError) as raised:
            invoke_text(
                function="report",
                prompt=raw_payload["prompt"] + "\nextra reconstructed evidence",
                system=raw_payload["system"],
                provider=provider,
                privacy_context=context,
            )
        self.assertEqual(raised.exception.reason, REASON_PAYLOAD_FINGERPRINT_MISMATCH)
        self.assertEqual(len(provider.calls), 0)

    def test_user_text_only_does_not_claim_batch_coverage(self):
        frozen = freeze_selected_observations(
            db.session,
            case_id=self.case.id,
            observations=[],
            user_text_present=True,
        )
        raw_payload = {"prompt": "Summarize this analyst question only", "system": None}
        context, proof = prepare_verified_case_content(db.session, frozen, raw_payload=raw_payload, privacy_level="basic")
        self.assertEqual(proof.coverage_reason, "user_text_only_no_forensic_batches")
        provider = CapturingRemoteProvider()
        result = invoke_text(
            function="report",
            prompt=raw_payload["prompt"],
            system=raw_payload["system"],
            provider=provider,
            privacy_context=context,
        )
        self.assertTrue(result["success"])
        self.assertEqual(len(provider.calls), 1)

    def test_forensic_evidence_missing_batch_provenance_is_blocked(self):
        frozen = freeze_selected_observations(
            db.session,
            case_id=self.case.id,
            observations=[{
                "case_id": self.case.id,
                "evidence_record_key": "forensic-without-batch",
                "ingest_batch_id": None,
                "managed": False,
                "payload_excerpt": "source_host=HOST1 | username=alice | erk=forensic-without-batch",
            }],
        )
        provider = CapturingRemoteProvider()
        with self.assertRaises(AIPrivacyPreflightError) as raised:
            prepare_verified_case_content(
                db.session,
                frozen,
                raw_payload=self._payload_for(frozen),
            )
        self.assertEqual(raised.exception.reason, REASON_LEGACY_UNPROVABLE)
        self.assertEqual(len(provider.calls), 0)

    def test_user_text_flag_cannot_launder_forensic_evidence_without_batches(self):
        frozen = freeze_selected_observations(
            db.session,
            case_id=self.case.id,
            observations=[{
                "case_id": self.case.id,
                "evidence_record_key": "forensic-launder",
                "ingest_batch_id": None,
                "managed": False,
                "payload_excerpt": "source_host=HOST1 | username=alice | erk=forensic-launder",
            }],
            user_text_present=True,
        )
        with self.assertRaises(AIPrivacyPreflightError) as raised:
            prepare_verified_case_content(
                db.session,
                frozen,
                raw_payload={"prompt": frozen.payload_from_frozen_excerpts(), "system": None},
            )
        self.assertEqual(raised.exception.reason, REASON_LEGACY_UNPROVABLE)

    def test_inherit_cannot_bind_new_forensic_identities_to_old_proof(self):
        generation = self._generation()
        batch0, _ = self._ingest_batch(generation, self.events[0:4], batch_ordinal=0)
        batch1, _ = self._ingest_batch(generation, self.events[4:8], batch_ordinal=1)
        self._derive(batch0)
        self._derive(batch1)
        first, _ = self._select_freeze(keys=[event.evidence_record_key for event in self.events[0:4]])
        second, _ = self._select_freeze(keys=[event.evidence_record_key for event in self.events[4:8]])
        raw_payload = self._payload_for(first)
        _context, proof = prepare_verified_case_content(
            db.session,
            first,
            raw_payload=raw_payload,
            privacy_level="basic",
        )
        poisoned = {
            "prompt": f"{raw_payload['prompt']}\n{second.payload_from_frozen_excerpts()}",
            "system": raw_payload["system"],
        }
        provider = CapturingRemoteProvider()
        with self.assertRaises(AIPrivacyPreflightError) as raised:
            inherit_verified_proof_for_followon_payload(
                db.session,
                proof,
                raw_payload=poisoned,
                followon_kind="second_pass_review",
            )
        self.assertEqual(raised.exception.reason, REASON_FOLLOWON_NEW_EVIDENCE)
        self.assertEqual(len(provider.calls), 0)

    def test_inherit_rejects_tool_retrieval_payloads(self):
        generation = self._generation()
        batch0, _ = self._ingest_batch(generation, self.events[0:4], batch_ordinal=0)
        self._derive(batch0)
        frozen, _ = self._select_freeze(keys=[event.evidence_record_key for event in self.events[0:4]])
        raw_payload = self._payload_for(frozen)
        _context, proof = prepare_verified_case_content(
            db.session,
            frozen,
            raw_payload=raw_payload,
            privacy_level="basic",
        )
        tool_payload = {
            "messages": [
                {"role": "user", "content": frozen.payload_from_frozen_excerpts()},
                {"role": "tool", "content": "new retrieval"},
            ],
            "tools": None,
        }
        with self.assertRaises(AIPrivacyPreflightError) as raised:
            inherit_verified_proof_for_followon_payload(
                db.session,
                proof,
                raw_payload=tool_payload,
                followon_kind="second_pass_review",
            )
        self.assertEqual(raised.exception.reason, REASON_FOLLOWON_NEW_EVIDENCE)

    def test_inherit_rejects_unknown_followon_kind(self):
        generation = self._generation()
        batch0, _ = self._ingest_batch(generation, self.events[0:4], batch_ordinal=0)
        self._derive(batch0)
        frozen, _ = self._select_freeze(keys=[event.evidence_record_key for event in self.events[0:4]])
        raw_payload = self._payload_for(frozen)
        _context, proof = prepare_verified_case_content(
            db.session,
            frozen,
            raw_payload=raw_payload,
            privacy_level="basic",
        )
        with self.assertRaises(AIPrivacyPreflightError) as raised:
            inherit_verified_proof_for_followon_payload(
                db.session,
                proof,
                raw_payload=raw_payload,
                followon_kind="chat_tool_reuse",
            )
        self.assertEqual(raised.exception.reason, REASON_FOLLOWON_NEW_EVIDENCE)

    def test_empty_forensic_without_user_text_is_not_a_bypass(self):
        frozen = freeze_selected_observations(db.session, case_id=self.case.id, observations=[])
        with self.assertRaises(AIPrivacyPreflightError) as raised:
            prepare_verified_case_content(
                db.session,
                frozen,
                raw_payload={"prompt": "static", "system": None},
            )
        self.assertEqual(raised.exception.reason, REASON_EMPTY_FORENSIC_BYPASS)

    def test_non_event_metadata_fails_closed(self):
        frozen = freeze_selected_observations(
            db.session,
            case_id=self.case.id,
            observations=[],
            non_event_case_content=True,
        )
        with self.assertRaises(AIPrivacyPreflightError) as raised:
            prepare_verified_case_content(
                db.session,
                frozen,
                raw_payload={"prompt": "case name and notes", "system": None},
            )
        self.assertEqual(raised.exception.reason, REASON_NON_EVENT_UNSUPPORTED)

    def test_sanitizer_failure_does_not_invoke_provider(self):
        generation = self._generation()
        batch0, _ = self._ingest_batch(generation, self.events[0:4], batch_ordinal=0)
        self._derive(batch0)
        frozen, _ = self._select_freeze(keys=[event.evidence_record_key for event in self.events[0:4]])
        raw_payload = self._payload_for(frozen)
        context, _proof = prepare_verified_case_content(db.session, frozen, raw_payload=raw_payload, privacy_level="basic")
        provider = CapturingRemoteProvider()

        def boom(value, *, context, provider):
            raise PrivacyEgressLeakError({"USERNAME"}, self.case.id)

        with patch("utils.privacy_aliases.sanitize_for_ai_egress", side_effect=boom):
            with self.assertRaises(PrivacyEgressLeakError):
                invoke_text(
                    function="report",
                    prompt=raw_payload["prompt"],
                    system=raw_payload["system"],
                    provider=provider,
                    privacy_context=context,
                )
        self.assertEqual(len(provider.calls), 0)

    def test_review_followon_inherits_same_frozen_identity(self):
        generation = self._generation()
        batch0, _ = self._ingest_batch(generation, self.events[0:4], batch_ordinal=0)
        self._derive(batch0)
        frozen, _ = self._select_freeze(keys=[event.evidence_record_key for event in self.events[0:4]])
        raw_payload = self._payload_for(frozen)
        _context, proof = prepare_verified_case_content(db.session, frozen, raw_payload=raw_payload, privacy_level="basic")
        followon = {"prompt": f"Review this draft:\n{raw_payload['prompt']}", "system": "review"}
        inherited = inherit_verified_proof_for_followon_payload(
            db.session,
            proof,
            raw_payload=followon,
            followon_kind="second_pass_review",
        )
        self.assertEqual(inherited.frozen.identity_fingerprint, proof.frozen.identity_fingerprint)
        self.assertNotEqual(inherited.raw_payload_fingerprint, proof.raw_payload_fingerprint)
        provider = CapturingRemoteProvider()
        result = invoke_text(
            function="report",
            prompt=followon["prompt"],
            system=followon["system"],
            provider=provider,
            privacy_context=AIPrivacyContext.verified_case_content(self.case.id, inherited, privacy_level="basic"),
        )
        self.assertTrue(result["success"])
        self.assertEqual(len(provider.calls), 1)

    def test_second_chat_round_cannot_reuse_first_proof_after_new_evidence(self):
        generation = self._generation()
        batch0, _ = self._ingest_batch(generation, self.events[0:4], batch_ordinal=0)
        batch1, _ = self._ingest_batch(generation, self.events[4:8], batch_ordinal=1)
        self._derive(batch0)
        self._derive(batch1)
        first, _ = self._select_freeze(keys=[event.evidence_record_key for event in self.events[0:4]])
        second_keys = [event.evidence_record_key for event in self.events[4:8]]
        first_messages = {"messages": [{"role": "user", "content": first.payload_from_frozen_excerpts()}], "tools": None}
        context, proof = prepare_verified_case_content(db.session, first, raw_payload=first_messages, privacy_level="basic")
        provider = CapturingRemoteProvider()
        chunks = list(stream_chat(
            function="chat",
            messages=first_messages["messages"],
            tools=None,
            provider=provider,
            privacy_context=context,
        ))
        self.assertTrue(chunks)
        db.session.rollback()
        second, _ = self._select_freeze(keys=second_keys)
        second_messages = {
            "messages": [
                {"role": "user", "content": first.payload_from_frozen_excerpts()},
                {"role": "tool", "content": second.payload_from_frozen_excerpts()},
            ],
            "tools": None,
        }
        with self.assertRaises(AIPrivacyPreflightError) as raised:
            list(stream_chat(
                function="chat",
                messages=second_messages["messages"],
                tools=None,
                provider=provider,
                privacy_context=context,
            ))
        self.assertEqual(raised.exception.reason, REASON_PAYLOAD_FINGERPRINT_MISMATCH)
        self.assertEqual(len(provider.stream_calls), 1)
        with self.assertRaises(AIPrivacyPreflightError) as inherit_raised:
            inherit_verified_proof_for_followon_payload(
                db.session,
                proof,
                raw_payload=second_messages,
                followon_kind="second_pass_review",
            )
        self.assertEqual(inherit_raised.exception.reason, REASON_FOLLOWON_NEW_EVIDENCE)
        new_context, _new_proof = prepare_verified_case_content(
            db.session,
            second,
            raw_payload=second_messages,
            privacy_level="basic",
        )
        list(stream_chat(
            function="chat",
            messages=second_messages["messages"],
            tools=None,
            provider=provider,
            privacy_context=new_context,
        ))
        self.assertEqual(len(provider.stream_calls), 2)

    def test_failed_generation_cannot_satisfy_egress(self):
        generation = self._generation()
        batch0, _ = self._ingest_batch(generation, self.events[0:4], batch_ordinal=0)
        self._derive(batch0)
        frozen, _ = self._select_freeze(keys=[event.evidence_record_key for event in self.events[0:4]])
        generation.visibility_state = EvidenceGenerationState.FAILED
        db.session.commit()
        with self.assertRaises(AIPrivacyPreflightError) as raised:
            freeze_selected_observations(db.session, case_id=self.case.id, observations=list(frozen.observations))
        self.assertIn(raised.exception.reason, {REASON_GENERATION_FAILED, REASON_GENERATION_NOT_CURRENT})

    def test_performance_preflight_is_batched(self):
        generation = self._generation()
        batch0, _ = self._ingest_batch(generation, self.events[0:4], batch_ordinal=0)
        batch1, _ = self._ingest_batch(generation, self.events[4:8], batch_ordinal=1)
        batch2, _ = self._ingest_batch(generation, self.events[8:12], batch_ordinal=2)
        self._derive(batch0)
        self._derive(batch1)
        self._derive(batch2)
        started = time.perf_counter()
        frozen, _ = self._select_freeze()
        freeze_ms = (time.perf_counter() - started) * 1000.0
        raw_payload = self._payload_for(frozen)
        started = time.perf_counter()
        context, proof = prepare_verified_case_content(db.session, frozen, raw_payload=raw_payload, privacy_level="basic")
        verify_ms = (time.perf_counter() - started) * 1000.0
        provider = CapturingRemoteProvider()
        started = time.perf_counter()
        result = invoke_text(
            function="report",
            prompt=raw_payload["prompt"],
            system=raw_payload["system"],
            provider=provider,
            privacy_context=context,
        )
        total_ms = (time.perf_counter() - started) * 1000.0
        self.assertTrue(result["success"])
        self.assertLessEqual(frozen.ch_queries, 1)
        self.assertLess(frozen.pg_queries, 20)
        self.assertLess(proof.pg_queries, 20)
        self.assertLess(freeze_ms, 5000)
        self.assertLess(verify_ms, 5000)
        self.assertLess(total_ms, 8000)
        print(
            "E2_PERF "
            f"events={frozen.forensic_event_count} "
            f"batches={len(frozen.managed_batch_ids)} "
            f"freeze_ms={freeze_ms:.2f} "
            f"verify_ms={verify_ms:.2f} "
            f"alias_preflight_ms={total_ms:.2f} "
            f"pg_freeze={frozen.pg_queries} "
            f"pg_verify={proof.pg_queries} "
            f"ch_freeze={frozen.ch_queries}"
        )


if __name__ == "__main__":
    unittest.main()
