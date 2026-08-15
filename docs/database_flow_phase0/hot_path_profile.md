# Phase 0A Hot-Path Profile

Status: EXECUTED.

Runtime verified: `/opt/casescope/venv/bin/python` with `/etc/casescope/casescope.env`.

Tooling: `py-spy 0.4.2` installed only in `/tmp/casescope-phase0a-tools`; no CaseScope application requirements or venv dependencies were changed.

Profile target: disposable benchmark process running `scripts/phase0a_ingest_benchmark.py`, not production Celery workers.

Profile output: `docs/database_flow_phase0/phase0a_ingest_profile.svg`.

Top-sample extraction: `docs/database_flow_phase0/phase0a_ingest_profile_top_samples.json`.

Machine-readable benchmark/timing source: `docs/database_flow_phase0/baseline_performance_run.json`.

## Corpus And Isolation

The approved manifest at `/opt/casescope-benchmark/phase0a_evtx/MANIFEST.txt` authorizes the corpus as benign lab/test Windows event logs, not retained CaseScope evidence, and allows disposable repeated benchmark processing.

Exact retained-source verification found:

- PostgreSQL `case_files.file_path` exact matches: `0`.
- ClickHouse `events.source_path` / `events.source_file` exact matches: `0`.
- Source EVTX files were read-only and were not modified.

## Profile Command

```bash
RUN_ID="phase0a_ingest_$(date -u +%Y%m%d%H%M%S)"
sudo -u postgres createdb -O casescope "$RUN_ID"
sudo -u casescope bash -lc "cd /opt/casescope && set -a && source /etc/casescope/casescope.env && set +a && export DATABASE_URL=<production-url-with-db-replaced-by-$RUN_ID> && export CLICKHOUSE_DATABASE=$RUN_ID && /tmp/casescope-phase0a-tools/bin/py-spy record --rate 99 --output docs/database_flow_phase0/phase0a_ingest_profile.svg -- /opt/casescope/venv/bin/python scripts/phase0a_ingest_benchmark.py --corpus-dir /opt/casescope-benchmark/phase0a_evtx --output-json docs/database_flow_phase0/baseline_performance_run.json --storage-root /tmp/${RUN_ID}_storage"
sudo -u postgres dropdb --if-exists "$RUN_ID"
sudo -u clickhouse clickhouse-client --query "DROP DATABASE IF EXISTS \`$RUN_ID\`"
sudo rm -rf "/tmp/${RUN_ID}_storage"
```

The last `py-spy` wrapper returned `No child process (os error 10)` after the child process exited, but it wrote the flamegraph successfully: `25893` samples, `6` reported sample errors. The benchmark harness completed and wrote the result JSON.

## Structured Wall-Time Correlation

Measured from Phase 0A structured metrics in the disposable run:

| Component | Observed value |
|---|---:|
| Total wall time | 332.884 s |
| Files | 8 EVTX |
| Source bytes | 77,103,104 |
| Events parsed before dedup | 110,742 |
| Events physically present after dedup | 49,115 |
| EvtxECmd subprocess wall time | 47.408 s |
| Hayabusa subprocess wall time | 49.259 s |
| EVTX JSONL consume wall time | 256.142 s |
| Outer JSON decode | 2.197 s |
| Nested Payload JSON decode | 1.209 s |
| Normalization | 38.961 s |
| search_blob construction | 0.931 s |
| ERK/identity CPU frame | observed in py-spy top samples |
| Alias extraction | 170.863 s |
| PostgreSQL alias writes | 8.136 s across 16 batches |
| ClickHouse insert wait | 2.954 s across 16 batches |
| Cleanup DELETE/mutation wait | 1.130 s |

Subprocess wall time is measured from structured metrics. It should not be inferred from Python CPU samples alone.

## Top Python CPU Samples

The top saved flamegraph samples were:

- `_strptime.compile`: 995 samples, 3.85%.
- `ParsedEvent.to_clickhouse_row`: 925 samples, 3.58%.
- `build_evidence_record_identity`: 760 samples, 2.94%.
- `privacy_aliases._extract_text_entities`: multiple hot frames, including 688 samples, 2.66%.
- `BatchProcessor.add_event`: 662 samples, 2.56%.
- `parsers.base._serialized_extra_fields`: 567 samples, 2.19%.
- `dateutil.parser` parse/split frames: multiple hot frames.
- `BatchProcessor.flush` around alias write: 418 samples, 1.62%.

## Finding

The strongest measured Python-side hot paths are alias extraction, timestamp parsing, ClickHouse row serialization, and ERK identity generation. The largest structured wall-time span is EVTX JSONL consumption, with normalization and alias extraction dominating inside Python work. EvtxECmd and Hayabusa are material subprocess wall-time costs, but not the majority of observed end-to-end wall time on this corpus.

Conclusion: EXECUTED - PHASE 0A MEASUREMENT COMPLETE.
