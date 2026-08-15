# Phase 0A Live ClickHouse Baseline

Status: executed read-only.

## Table

- ClickHouse version: `26.7.3.19`
- Database: `casescope`
- Events engine: `MergeTree`
- PARTITION BY: `case_id`
- ORDER BY: `(case_id, timestamp_utc, artifact_type, source_host, source_file, event_id)`
- Settings: `index_granularity = 8192, min_bytes_for_wide_part = 0, min_rows_for_wide_part = 0`
- Events rows from active parts: `745463991`
- Events bytes from active parts: `107590061428`
- Case/partition count: `25`
- Active part count: `201`

## Part Statistics

- median_rows_per_part: `371928`
- median_bytes_per_part: `54340847`
- p95_rows_per_part: `16275388`
- p95_bytes_per_part: `2439666141`
- median_rows_per_partition: `5124844`
- median_bytes_per_partition: `718377153`
- median_parts_per_partition: `8`
- p95_parts_per_partition: `16`
- max_parts_per_partition: `17`

## Compact vs Wide

- Wide: `201`

## Mutations And Merges

- Active/pending recent mutations: `1`
- Recent mutation failures: `0`
- Merge activity rows: `0`
- Active mutation sample: `mutation_32732.txt`

## events_buffer

- exists: `True`
- engine: `Buffer`
- visible_row_count: `745463991`

## Indexes

| Name | Type | Expression | Granularity |
|---|---|---|---:|
| `idx_event_id` | `bloom_filter` | `event_id` | `4` |
| `idx_evidence_record_key` | `bloom_filter` | `evidence_record_key` | `4` |
| `idx_search_ngram` | `ngrambf_v1` | `search_blob` | `4` |
| `idx_search_token` | `tokenbf_v1` | `search_blob` | `4` |
| `idx_selector_key` | `bloom_filter` | `selector_key` | `4` |

## Representative Large Cases By Physical Rows/Bytes

| Case partition | Rows | Bytes | Parts |
|---:|---:|---:|---:|
| 32 | 174899397 | 28642383944 | 16 |
| 7 | 139579161 | 21403254263 | 17 |
| 6 | 121910204 | 16085408208 | 7 |
| 4 | 96347782 | 11498969670 | 8 |
| 12 | 45969319 | 7296004533 | 11 |
| 21 | 68900003 | 6522479272 | 9 |
| 35 | 27336757 | 4951641409 | 14 |
| 2 | 13935546 | 1575125565 | 9 |
| 1 | 5841552 | 1549347074 | 16 |
| 34 | 5124844 | 1215872854 | 8 |

## SQL Sources

Measurements were produced by `bin/database_flow_baseline.py` using read-only `SELECT`/`SHOW CREATE TABLE` statements against `system.parts`, `system.tables`, `system.mutations`, `system.merges`, `system.data_skipping_indices`, and `events_buffer` count where available.

## ClickHouse Version Implication

OBSERVED: deployed ClickHouse version is `26.7.3.19`, which exceeds the locked plan's Phase 2 Gate A minimum version prerequisite of `>=26.2`.

Status: VERSION PREREQUISITE SATISFIED.

This does not mean Phase 2 is ready. Later phases still require separate verification of text index DDL/capability, tokenizer/preprocessor behavior, current deployed syntax, lightweight UPDATE capability, events table block-number/block-offset settings, required feature/table settings, benchmark behavior, and explicit insert mode.
