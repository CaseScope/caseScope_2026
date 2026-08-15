# Phase 0A Controlled Baseline Performance Run

Status: EXECUTED.

Machine-readable result: `docs/database_flow_phase0/baseline_performance_run.json`.

Harness: `scripts/phase0a_ingest_benchmark.py`.

Profile artifact: `docs/database_flow_phase0/phase0a_ingest_profile.svg`.

## Isolation

The benchmark used disposable resources only:

- PostgreSQL database: `phase0a_ingest_20260814110501`, dropped after result capture.
- ClickHouse database: `phase0a_ingest_20260814110501`, dropped after result capture.
- Storage root: `/tmp/phase0a_ingest_20260814110501_storage`, removed after result capture.
- Source corpus: `/opt/casescope-benchmark/phase0a_evtx/`, read-only.

No benchmark rows were written into production PostgreSQL or production ClickHouse. Retained evidence was not reprocessed.

## Dataset

The approved corpus contains 8 benign lab EVTX files, 77,103,104 bytes total.

| File | Size bytes | Events parsed |
|---|---:|---:|
| `Application.evtx` | 11,603,968 | 12,137 |
| `Microsoft-Windows-PowerShell-Operational.evtx` | 15,798,272 | 488 |
| `Microsoft-Windows-TaskScheduler-Operational.evtx` | 69,632 | 0 |
| `Microsoft-Windows-TerminalServices-LocalSessionManager.evtx` | 1,118,208 | 221 |
| `Microsoft-Windows-WMI-Activity-Operational.evtx` | 1,118,208 | 1,158 |
| `Microsoft-Windows-Windows-Defender-Operational.evtx` | 5,312,512 | 5,536 |
| `Security.evtx` | 21,041,152 | 29,575 |
| `System.evtx` | 21,041,152 | 61,627 |

Deviation from locked-plan preferred benchmark: this corpus is EVTX-only, 8 files rather than >=20 files, and contains no memory image or PCAP.

## Throughput

- Wall time: 332.884 s.
- Events parsed before dedup: 110,742.
- Events physically present after current dedup: 49,115.
- Events/sec before dedup: 332.674.
- Source MB/sec: 0.221.
- Peak RSS: 237.36 MB.
- Errors: 0.
- Retries: 0.

## Per-File Timing

| File | Duration seconds | Cleanup DELETE ms |
|---|---:|---:|
| `Application.evtx` | 36.147 | 16.509 |
| `Microsoft-Windows-PowerShell-Operational.evtx` | 20.433 | 13.983 |
| `Microsoft-Windows-TaskScheduler-Operational.evtx` | 5.144 | 15.557 |
| `Microsoft-Windows-TerminalServices-LocalSessionManager.evtx` | 5.941 | 14.042 |
| `Microsoft-Windows-WMI-Activity-Operational.evtx` | 7.417 | 14.606 |
| `Microsoft-Windows-Windows-Defender-Operational.evtx` | 20.050 | 16.245 |
| `Security.evtx` | 98.085 | 18.012 |
| `System.evtx` | 132.196 | 1,024.804 |

## Component Breakdown

| Component | Observed value |
|---|---:|
| EvtxECmd subprocess wall time | 47.408 s |
| Hayabusa subprocess wall time | 49.259 s |
| EVTX JSONL consume wall time | 256.142 s |
| Outer JSON decode | 2.197 s |
| Nested Payload JSON decode | 1.209 s |
| Normalization | 38.961 s |
| search_blob construction | 0.931 s |
| Alias extraction | 170.863 s |
| PostgreSQL alias writes | 8.136 s |
| ClickHouse insert wait | 2.954 s |
| ClickHouse insert batches | 16 |
| Estimated serialized bytes | 371,256,909 |
| Cleanup DELETE/mutation wait | 1.130 s |

## Capability Latency

- File/task start to first physical ClickHouse row: 184.478 s.
- File/task start to first current-searchable event: 184.478 s.

Current product search reads `events`; in this disposable run, first searchable was measured as first observed row in the disposable `events` table. This is a current-architecture measurement, not a future publication definition.

## Completion Stages

- Buffer/current final optimize reproduced as `OPTIMIZE TABLE events FINAL`: 2.196 s.
- Dedup reproduced in disposable ClickHouse: success, 0 duplicates found, 0 deleted, 98.187 ms.
- KnownSystem discovery reproduced: success, 7 systems created, 971.908 ms.
- KnownUser discovery reproduced: success, 2 users created, 1 updated, 47.136 ms.
- MITRE match insertion/scheduling: NOT REPRODUCED - harness used `process_file` and did not run `parse_file_task` post-parse MITRE match insert/queue.
- Embeddings: NOT REPRODUCED - disposable harness did not enqueue embedding workers.
- Graph materialization: NOT REPRODUCED - disposable harness did not enqueue graph workers.

## ClickHouse State

- Before: active parts `0`, active rows `0`, mutation count `0`.
- After dedup/finalization: active parts `1`, active rows `49,115`, mutation count `8`.

## Buffer Visibility Finding (pre-existing; feeds Phase 1.4)

`OPTIMIZE TABLE events FINAL` does **not** flush `events_buffer`. The 49,115 row figure above is a Buffer-visibility artifact (110,742 parsed minus the last file still sitting in Buffer: System.evtx 61,627). It is not a semantic event-loss measurement.

Canonical benchmark procedure from Phase 1 Step 1 acceptance closure onward:

1. `OPTIMIZE TABLE events_buffer` (explicit Buffer drain)
2. Confirm pending Buffer rows are 0 (`count(events_buffer) - count(events) == 0`)
3. Only then take final `events` counts, ERK digests, or semantic comparisons
4. `OPTIMIZE TABLE events FINAL` may still run afterward for part merges; it is not a Buffer flush

Do not change production Buffer behavior on the basis of this finding. Phase 1.4 will address Buffer removal behind the ingest fence.

## Reproducibility Notes

The harness preserves current 4.18.5 behavior: no `orjson`, no Buffer removal, no batch-size change, no alias optimization, no Hayabusa mode change, no schema/settings change, no retained-evidence reprocessing.

`py-spy` returned `No child process (os error 10)` after the child benchmark exited, but the profile artifact was written successfully and the benchmark harness completed with JSON output.
