#!/usr/bin/env bash
set -euo pipefail

ROOT="/opt/casescope"
PYTHON="$ROOT/venv/bin/python"

cd "$ROOT"

"$PYTHON" -m unittest \
  tests.test_evidence_identity \
  tests.test_evidence_identity_migration \
  tests.test_evidence_identity_clickhouse_integration \
  tests.test_graph_identity \
  tests.test_graph_extractors \
  tests.test_graph_materializer \
  tests.test_graph_migration \
  tests.test_graph_query \
  tests.test_graph_routes \
  tests.test_graph_support_lifecycle \
  tests.test_graph_phase0e_contracts \
  tests.test_graph_pivots \
  tests.test_graph_saved_views \
  tests.test_graph_saved_view_routes \
  tests.test_investigation_references \
  tests.test_investigation_threads \
  tests.test_investigation_thread_routes \
  tests.test_investigation_thread_ui_contract \
  tests.test_investigation_audit_integration \
  tests.test_investigation_thread_migration \
  tests.test_investigation_context \
  tests.test_investigation_thread_report_snapshots \
  tests.test_phase0g_release_gate
