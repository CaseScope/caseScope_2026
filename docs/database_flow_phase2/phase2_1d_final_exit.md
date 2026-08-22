# Phase 2.1D Bloom Retirement / Final Phase 2.1 Exit

Measurement artifact: `docs/database_flow_phase2/phase2_1d_final_exit.json`.

**Verdict: PHASE2_1D_NOT_READY**

Both bloom indexes remain. Production `EXPLAIN indexes = 1` shows
`idx_search_ngram` pruning retained `search_blob LIKE` queries from
`models/pattern_rules.py`. The locked prerequisite to drop was not met.
No production DROP INDEX. No EVENTS_SCHEMA change. No version bump.

## Starting state

- origin/main and HEAD: `a9e40b712fb72cf182114980db9cad49f00f4279`
- Working tree clean, HEAD == origin/main
- Version: 4.25.2 (unchanged)
- Python: `/opt/casescope/venv/bin/python`
- Deployed ClickHouse: `26.7.3.19`
- Running `casescope-web`: MainPID 501361 since 2026-08-22 03:11:45 UTC (4.25.2 export-publication closure). Not restarted.

## Phase 2.1C accepted preconditions

PASS, unchanged:

- `idx_search_blob_text` locked type/expression PRESENT
- Coverage MATERIALIZED 25 / PARTIAL 0 / UNMATERIALIZED 0 / UNKNOWN 0
- 135/135 active parts MATERIALIZED
- Hunt TOKEN_SAFE live (`hasAllTokens` / `hasAnyTokens`)
- ASCII-only TOKEN_SAFE; Unicode/punctuation remain ILIKE
- Export-view and export-tagged use the Phase 1B publication bridge (4.25.2)
- Blooms still present at 2.1C exit, as required

## Production index inventory

| Name | Type | Expression | Granularity | Compressed bytes |
|---|---|---|---:|---:|
| idx_search_blob_text | text(tokenizer = 'splitByNonAlpha', preprocessor = lower(search_blob)) | search_blob | 100000000 (server-stored) | 14,603,118,274 |
| idx_search_ngram | ngrambf_v1(3, 512, 2, 0) | search_blob | 4 | 4,049,580 |
| idx_search_token | tokenbf_v1(32768, 3, 0) | search_blob | 4 | 964,699,630 |
| idx_event_id | bloom_filter(0.01) | event_id | 4 | 9,913,034 |
| idx_selector_key | bloom_filter(0.01) | selector_key | 4 | 453,214,994 |
| idx_evidence_record_key | bloom_filter(0.01) | evidence_record_key | 4 | 886,609,005 |

Active parts 135 / 25 partitions / 745,463,991 rows / 123,153,313,168 compressed bytes.
Mutations in progress: 0. `idx_event_id`, `idx_selector_key`, `idx_evidence_record_key` were not touched.

Coverage: MATERIALIZED 25 partitions, 135/135 active parts. No PARTIAL / UNMATERIALIZED / UNKNOWN.

## search_blob consumer inventory

Classification only. No reader was migrated in 2.1D.

| Consumer | Predicate | Token vs substring | Hot | EXPLAIN skip |
|---|---|---|---|---|
| Hunt `build_hunting_search_clause` TOKEN_SAFE | `hasAllTokens` / `hasAnyTokens` | whole-token | yes | `idx_search_blob_text` direct read |
| Hunt SUBSTRING / exclusion | `search_blob ilike` / `NOT ilike` | substring | yes | none |
| Hunt numeric | `event_id =` | structured | yes | `idx_event_id` |
| Hunt `cmd:` / `command_line:` | typed `command_line ILIKE` | structured column | yes | none |
| Hunt event-detail `match_search_blob` | `position(e.search_blob, …)` | substring | yes | none |
| `models/pattern_rules.py` | `search_blob LIKE '%NTLM%'` etc. | case-sensitive substring | background / required | **ngram prunes; token listed** |
| IOC tagger | `hasTokenCaseInsensitive` / `lower(search_blob) LIKE` | mixed | background | none |
| Sigma converter | `search_blob ILIKE` | substring | background | none |
| `models/network_log.py` | `search_blob ILIKE` (network_logs table) | dotted IP substring | yes | events analog: none |
| Chat / forensic sources | `positionCaseInsensitive` | mixed | yes | none |
| noise / candidates / MITRE / RAG / pattern checks | LIKE / lower LIKE | substring | background | same LIKE class as pattern_rules |
| parsers | write `search_blob` | n/a | ingest | n/a |

## Pre-drop EXPLAIN matrix

Verified per-query ignore setting on 26.7.3.19:
`ignore_data_skipping_indices = 'idx_search_ngram,idx_search_token'`.

On `search_blob LIKE '%NTLM%'` case 10:

- current Skip: `idx_search_blob_text` (482/482), `idx_search_ngram` (461/482), `idx_search_token` (461/461)
- ignored: only `idx_search_blob_text` (482/482)
- ngram is the pruner; token is listed after ngram with no additional granule reduction

TOKEN_SAFE Hunt (`sonicwall` / `powershell` / `Administrator` / `powershell|administrator` on 14/10/7/32):
Skip `idx_search_blob_text` and `__text_index_*hasAllTokens*` / `hasAnyTokens*` direct read. Blooms absent.

SUBSTRING_REQUIRED Hunt (`cmd.exe`, `10.0.0.1`, `"Windows PowerShell"`, path, `www.ups.com`, `münchen`) and exclusions:
no search_blob skip index. Prewhere remains `search_blob ILIKE`.

`hasTokenCaseInsensitive`, `position` / `positionCaseInsensitive`, `lower(search_blob) LIKE`, Hunt ILIKE: none.

`event_id = '4688'`: `idx_event_id` only.

## Bloom-off A/B

Disposable mechanism: production queries with
`SETTINGS ignore_data_skipping_indices='idx_search_ngram,idx_search_token'`.
9 samples + 1 warmup. Result count and `sum(cityHash64(evidence_record_key))` identity required equal.

TOKEN_SAFE: exact identity, identical `read_rows`, text index still selected, no bloom dependence.

Hunt ILIKE substring: exact identity, identical `read_rows` (blooms unused).

Blocking LIKE:

| Query | n | p50 current → ignored | read_rows current → ignored |
|---|---:|---|---|
| case 10 `LIKE '%NTLM%'` | 2200 | 110.9 → 105.0 ms | 2,336,555 → 2,447,494 (+110,939) |
| case 7 `LIKE '%NTLM%'` | 73510 | 3578 → 3675 ms | 119,984,806 → 139,579,161 (+19,594,355) |
| case 32 `LIKE '%NTLM%'` | 162596 | 3766 → 4002 ms | 149,647,982 → 174,899,397 (+25,251,415) |
| case 10 `LIKE '%ADMIN$%'` | 0 | 99.6 → 100.6 ms | 2,403,574 → 2,447,494 (+43,920) |

Ngram prune is real (13–16% granules/rows on large NTLM cases). Latency delta is modest, not used as a pass threshold. EXPLAIN plus row-prune of a retained required query is the stop.

## Bloom retirement decision

**BLOOM_DEPENDENCY_BLOCKS_EXIT**

- index: `idx_search_ngram` (actual prune); `idx_search_token` listed on the same plans
- consumer: `models/pattern_rules.py` (`search_blob LIKE '%NTLM%'` / `'%ADMIN$%'`)
- cases: 10, 7, 32
- why: locked rule is drop both blooms only after EXPLAIN shows they are unused by retained required queries. Pattern detection is still a current product query. Readers were not migrated.

Neither bloom was dropped. Partial token-only drop was not authorized.

## Pre-drop storage

- ngram ~4.0 MiB compressed
- token ~920 MiB compressed
- text index ~13.6 GiB compressed
- events ~114.7 GiB compressed
- filesystem free on `/var/lib/clickhouse`: 74,440,380,416 bytes (~69.3 GiB)

No disk reclaim was attempted. Instant reclaim is not claimed.

## Canonical fresh schema / upgrade migration

NOT CHANGED / NOT ADDED.

`EVENTS_SCHEMA` still declares both blooms plus the text index so fresh installs match current production. A drop migration would recreate a split-brain with production.

Fresh-install proof, upgrade proof, drift fail-closed, production quiescence, and production DROP: **NOT EXECUTED**.

## Post-drop correctness / performance / smoke

NOT EXECUTED.

## materialize_skip_indexes_on_insert=0 experiment

Disposable events-shaped tables on ClickHouse 26.7.3.19, 10k-row CaseScope batch, `clickhouse_connect insert()`, only this setting differs. Final 2.1 index set still includes both blooms because retirement did not pass.

| Arm | setting | insert rows/s | text-index bytes after insert | immediate hasAllTokens | immediate path |
|---|---:|---:|---:|---|---|
| A | 1 | 41,977 | 70,148 | 10000 in 7.4 ms, 10,000 bytes | direct `__text_index_*` |
| B | 0 | 82,217 | 0 | 10000 in 10.8 ms, 1,755,390 bytes | scan `hasAllTokens(lower(search_blob), …)` |

No false negatives on the new batch, the rare token (100/100), or a missing token (0). Setting 0 is correct-but-scan immediately after insert.

After `OPTIMIZE FINAL` on the table *without* production merge-exclude, arm B built the index and switched to direct read.

Production-like probe with
`exclude_materialize_skip_indexes_on_merge = 'idx_search_blob_text'`
(the live events setting):

- insert with 0: text-index bytes 0, count 10000, scan fallback
- `OPTIMIZE FINAL`: bytes still 0, still scan
- explicit `MATERIALIZE INDEX`: bytes 43,347, direct read, count 10000

Phase 1B requires a newly DURABLE batch to be Hunt-searchable before file EOF. Setting 0 does that without false negatives, but TOKEN_SAFE on new parts is a full-blob scan, and production merge-exclude means the text index will not appear later unless a new post-insert materializer is invented. That architecture is outside this tranche.

**KEEP_PRODUCTION_MATERIALIZE_SKIP_INDEXES_ON_INSERT_1**

Production setting was not changed.

## command_line evaluation

**COMMAND_LINE_INDEX_DEFER**

Hunt `cmd:` / `commandline:` / `command_line:` still use the typed `command_line` column with existing LIKE/ILIKE. EXPLAIN on case 10 `command_line ILIKE '%powershell%'` used no skip index.

Nonempty density:

| case | rows | nonempty | density | `command_line ILIKE '%powershell%'` |
|---:|---:|---:|---:|---:|
| 14 | 1,341 | 0 | 0 | 0 |
| 10 | 2,447,494 | 5,799 | 0.24% | 302 |
| 7 | 139,579,161 | 2,615,167 | 1.87% | 143,510 |
| 32 | 174,899,397 | 73,295 | 0.042% | 999 |

An index was not created. Density and EXPLAIN do not justify one in this tranche.

## Regression

Required suite plus `tests/test_phase2_1d_final_exit.py`, with disposable F2 env
`phase2_1c_test`: **193 passed, 0 skipped**.

`py_compile`, `pyflakes`, and `git diff --check` on changed Python.

## Publication authority / product smoke

Publication helpers were not modified. 4.25.2 export-view / export-tagged gating remains the accepted bridge.

No production DROP, so no post-drop product smoke and no service restart. Login HTTP 200. Web remains the 4.25.2 process.

## No later phase

No Phase 2.2 insert-mode decision, no `async_insert` production change, no 2.3 UPDATE, no 2.4 dedup, no Phase 3/4, no LEK, no `events_current` / `event_observations_current`, no other `search_blob` reader migration, no pagination redesign, no production OPTIMIZE / MATERIALIZE / DROP INDEX, no evidence or `search_blob` rewrite.

## Remaining work

Independent 2.1D review of this NOT_READY result.

Do not start Phase 2.2.

A later bloom-retirement tranche may proceed only after either:

1. EXPLAIN no longer shows ngram/token prune on retained required queries, or
2. those LIKE consumers are explicitly reclassified / migrated under a new locked plan

until then both blooms stay, including in canonical `EVENTS_SCHEMA`.
