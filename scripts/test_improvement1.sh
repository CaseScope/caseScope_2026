#!/usr/bin/env bash
set -euo pipefail

ROOT="/opt/casescope"
PYTHON="$ROOT/venv/bin/python"

cd "$ROOT"

"$PYTHON" -m pytest \
  tests/test_evidence_identity.py \
  tests/test_evidence_identity_migration.py \
  tests/test_evidence_identity_clickhouse_integration.py \
  tests/test_graph_identity.py \
  tests/test_graph_extractors.py \
  tests/test_graph_materializer.py \
  tests/test_graph_migration.py \
  tests/test_graph_query.py \
  tests/test_graph_routes.py \
  tests/test_graph_support_lifecycle.py \
  tests/test_graph_phase0e_contracts.py \
  tests/test_graph_pivots.py \
  tests/test_graph_saved_views.py \
  tests/test_graph_saved_view_routes.py \
  tests/test_investigation_references.py \
  tests/test_investigation_threads.py \
  tests/test_investigation_thread_routes.py \
  tests/test_investigation_thread_ui_contract.py \
  tests/test_investigation_audit_integration.py \
  tests/test_investigation_thread_migration.py \
  tests/test_investigation_context.py \
  tests/test_investigation_thread_report_snapshots.py \
  tests/test_phase0g_release_gate.py
