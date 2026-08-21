# Phase 2.1B Text Index Rollout

Production completion of `idx_search_blob_text` materialization for every
`case_id` partition, plus operator idle-check fail-closed hardening. Hunt
readers remain `search_blob ILIKE`. Bloom indexes remain. No later Phase 2.x/3+
work.

Measurement artifact: `docs/database_flow_phase2/phase2_1b_text_index_rollout.json`.
Phase 2.1A artifacts are unchanged.

## Starting state

- origin/main and HEAD: `8e691d303774f332b2f0d9962c67b735493ddf91`
- Commit: Deploy the locked search_blob text index and a partition-scoped materializer
- Baseline version: 4.24.0
- This tranche version: 4.24.1
- Python: `/opt/casescope/venv/bin/python`
- Deployed ClickHouse: `26.7.3.19`

## Locked scope

Done:

- operator Celery/fence/systemd idle proof fail-closed
- coverage detector mutation-replacement regression
- production materialization of the remaining 23 partitions
- all 25 `case_id` partitions MATERIALIZED
- read-only `hasAllTokens` / `EXPLAIN indexes = 1` proofs
- reader-consumer classification for the next 2.1 tranche

Not done: Hunt `hasAllTokens`/`hasAnyTokens` cutover, bloom drop, production
`command_line` index, Phase 2.2–2.4, Phase 3+.

## Operator idle-check defect

`scripts/phase2_1_materialize_search_index.py` inspected fence, systemd, and
Celery, but `report["ok"]` used only fence and systemd. `inspect_celery`
treated `None`/empty payloads as zero.

Production idle now requires all three:

1. ingest fence healthy (no exclusive owner, `shared_writer_count == 0`)
2. `casescope-web`, `casescope-workers`, `casescope-beat` inactive
3. Celery proven empty: active/reserved/scheduled = 0 when workers reply;
   when workers are stopped, broker queued and Redis `unacked` must be 0.
   Inspection errors fail closed.

Status reports degraded idle without mutating. Dry-run stays non-mutating and
sets `idle_unsafe` when idle proof fails.

## Coverage before

Authoritative detector remains active part files
(`skp_idx_idx_search_blob_text.idx` sentinel).

- 33 MATERIALIZED
- 10 MATERIALIZED
- 23 UNMATERIALIZED
- 0 PARTIAL
- 0 UNKNOWN
- 745,463,991 rows / 25 partitions / 135 active parts

## Rollout order

Recomputed by rows, case 32 last, 33/10 not rerun:

14, 15, 13, 5, 36, 9, 16, 37, 38, 8, 34, 11, 1, 23, 3, 2, 35, 12, 21, 4, 6, 7, 32

Group 1 (through ~10M rows): 14, 15, 13, 5, 36, 9.
Then one partition per invocation through case 32.

## Pre-flight

Schema unchanged: seven Phase 1B protocol columns,
`visible_evidence_generations`, `durable_ingest_batches`,
`enable_block_number_column = 1`, `enable_block_offset_column = 1`.
Text index expr `search_blob`, type
`text(tokenizer = 'splitByNonAlpha', preprocessor = lower(search_blob))`.
Blooms present. In-progress MITRE UPDATEs on case 3 were drained after
stopping writers. Idle proof then PASS.

Two `acks_late` tasks returned to the broker after the first worker stop:
`map_case_mitre_procedures(3, 'system')` and `materialize_case_graph` with
empty args. Those two messages were removed so idle could be proven. After
restart, MITRE mapping for case 3 was requeued
(`6ce8b447-4dda-4fb7-92f4-6816d014179a`). Graph was not blindly requeued
because `case_id` is required.

## Materialization results

Every partition: coverage MATERIALIZED, row count unchanged, ERK/search_blob
fingerprint unchanged, protocol identity unchanged, other partitions
unchanged. No UPDATE/DELETE/OPTIMIZE FINAL/full-table MATERIALIZE.

Case 12: operator skip found it already MATERIALIZED. ClickHouse
`mutation_34789.txt` (`MATERIALIZE INDEX idx_search_blob_text IN PARTITION 12`,
`is_done=1`, create_time 20:16:29 UTC) wrote the replacement active parts
during the post-35 checkpoint window. Active parts have the text-index
sentinel; skip fingerprints were unchanged.

Largest case 32: `mutation_34794.txt`, 174,899,397 rows, 366.9s (~477k rows/s).

No partition failed. Rollout was not stopped mid-way.

## Final coverage

MATERIALIZED 25 / PARTIAL 0 / UNMATERIALIZED 0 / UNKNOWN 0.

Sum of partition rows 745,463,991 equals production `events` row count.
`idx_search_blob_text` type/expression unchanged.
`idx_search_ngram` PRESENT. `idx_search_token` PRESENT.

## Storage and resources

| Measure | 2.1A estimate | Actual |
|---|---:|---:|
| bytes/event | ~26.8 | 19.59 |
| remaining index | ~20 GB | 14.53 GB this tranche |
| sequential wall | ~40–50 min | 45.7 min (20:03:47–20:49:30 UTC) |
| mutation elapsed sum | — | 28.4 min (excludes case 12 skip) |

Table compressed bytes 108,563,103,471 → 123,153,299,221 (+14.59 GB).
Text index 69,117,249 → 14,603,118,274.
Free disk 83.6 GiB → 69.6 GiB. Load peaked ~4.5 during case 32; MemAvailable
stayed ~27 GB. Deviation vs 26.8 bytes/event: production blobs compressed
better than the 2.45M-row Windows-rich pilot (~27% less per event). Wall
clock matched the 40–50 minute estimate.

## Whole-token / EXPLAIN proof

Read-only `hasAllTokens` + `EXPLAIN indexes = 1` on cases 14, 10, 7, 32.

All samples: Skip `idx_search_blob_text` and
`__text_index_idx_search_blob_text_hasAllTokens_*` direct-read. No
`hasAllTokens(lower(search_blob))` scan.

SHA-256 empty hash counts equal ILIKE vs `hasAllTokens` (true whole token).
ILIKE vs token gaps for `local`, `PowerShell`, `Administrator`, `4688` are
substring / punctuation splits, same class as Phase 2.1A. Not a false-negative
index prune.

## Known substring / punctuation exceptions

Retain LIKE/ILIKE for later reader classification. Do not blindly map:

- true substring (`vchos`): ILIKE hits, `hasAllTokens` 0
- dotted IP (`10.0.0.1`): `hasAllTokens` can far exceed ILIKE (split octets)
- `cmd.exe`: ILIKE > `hasAllTokens` (punctuation split)

Numeric `4688` is not equivalent to structured `event_id =` lookup.

## Reader consumer inventory

Classification only. No reader changes.

| Consumer | Predicate | Class |
|---|---|---|
| `routes/hunting_query_helpers.py` `build_hunting_search_clause` free-text term | `search_blob ilike %term%` | TOKEN_CANDIDATE for whole tokens; SUBSTRING_REQUIRED for quoted/explicit substring |
| same, digit-only term | `event_id =` | STRUCTURED_FIELD_SHOULD_BE_USED |
| same, mapped `field:value` eq/like columns | typed column | STRUCTURED_FIELD_SHOULD_BE_USED |
| same, `blob` mapped fields and unknown `field:value` | `search_blob ilike %field:value%` | SUBSTRING_REQUIRED |
| same, `ip` / `src_ip` / `dst_ip` blob fallback | dotted IP in `search_blob` | SUBSTRING_REQUIRED; do not `hasAllTokens` |
| `routes/hunting.py` `match_search_blob` | `position(e.search_blob, …)` | SUBSTRING_REQUIRED |
| `utils/sigma_converter.py` wildcard selection | `search_blob ILIKE` | SUBSTRING_REQUIRED |
| `models/network_log.py` dotted-IP prefix | `search_blob ILIKE %field:value%` | SUBSTRING_REQUIRED |
| `utils/ioc_artifact_tagger.py` | `lower(search_blob) LIKE` | SUBSTRING_REQUIRED |
| `utils/noise_keywords.py` | `search_blob` LIKE with `raw_json` | SUBSTRING_REQUIRED |
| `models/pattern_rules.py` | many `LIKE '%path%'`, hex, punctuation | SUBSTRING_REQUIRED |
| `utils/chat_tools.py` / `utils/forensic_chat_sources.py` `positionCaseInsensitive` | mixed tokens, `cmd.exe`, paths | TOKEN_CANDIDATE for whole tokens such as `powershell`; SUBSTRING_REQUIRED for `cmd.exe`, paths, dotted names |
| parsers writing `search_blob` | ingest, not a hunt predicate | DEFER |
| `utils/graph_query.py` column projection | display | DEFER |
| Hunt event-detail `search_blob` | display | DEFER |

Hashes: empty SHA-256 matched as a whole token; keep verifying token vs hex
substring before any cutover. Quoted Hunt inputs stay LIKE/ILIKE.

## command_line

DEFER. No production `command_line` text index. No new density evidence.

## Services / smoke

Stopped web, workers, beat before materialization. Restarted web → workers →
beat after coverage/no-rewrite verification.

`GET /login` 200; `/case/files`, `/case/hunting`, `/api/hunting/events/14`
302 to login. Case 14 CH total 1,341; `search_blob ILIKE '%sonicwall%'` = 13.
Event detail ERK sample returned. Hunt helper still emits `search_blob ilike`
and does not emit `hasAllTokens`/`hasAnyTokens`.

## Tests

Requested pytest suite: 149 passed, 7 skipped (F2 live DBs unset).
Operator idle + mutation-part coverage added in
`tests/test_phase2_1a_text_index_materialization.py`.
`py_compile`, `pyflakes`, `git diff --check` on changed Python.

## No later phase

No Hunt token cutover, no bloom drop, no `command_line` index, no Phase 2.2
insert-mode change, no 2.3 UPDATE bridge, no 2.4 dedup, no Phase 3/4, no LEK,
no `events_current` / `event_observations_current`. Phase 1B publication
bridge unchanged.
