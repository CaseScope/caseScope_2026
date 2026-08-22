# Phase 2.1D2B Token Retirement / Final Phase 2.1 Exit

Measurement artifact: `docs/database_flow_phase2/phase2_1d2b_token_retirement_final_exit.json`.

**Tranche verdict: PHASE2_1D2B_PASS**

Phase 2.1 is closed pending independent review. This tranche recorded
architecture exception `PHASE2_1_EXC_001`, retired only `idx_search_token`,
and left `idx_search_ngram` in place with its approved legacy definition.

## 1. Baseline

- Repository: `/opt/casescope`
- Python: `/opt/casescope/venv/bin/python`
- HEAD / origin/main: `0c89dd36a31d2e885acb9268df7496ff57f4e49c`
- HEAD == origin/main, working tree clean at start
- Starting version: 4.25.2
- Deployed ClickHouse: 26.7.3.19

Authoritative inputs read in full: locked plan v4, Phase 2.1D NOT_READY,
Phase 2.1D2A PASS, and the accepted Phase 2 / 2.1A / 2.1B / 2.1C /
live-activation / export-publication artifacts.

## 2. Architecture review input

Independent architecture review of D1 (`PHASE2_1D_NOT_READY`) and D2A
(`PHASE2_1D2A_PASS`) approved this narrow measurement-driven decision:

- KEEP `idx_search_ngram`
- RETIRE `idx_search_token`

`idx_search_ngram` has independently measured pruning benefit on retained
deterministic substring LIKE predicates. The locked `idx_search_blob_text`
cannot replace all of those predicates. Short-token / punctuation examples
remain dependent on ngram behavior. Attempted text-index prefilters were not
universally effective and some materially regressed large-case performance.
On the 745,463,991-row corpus, ngram costs ~3.86 MiB; token showed no
independent pruning contribution when ngram was unavailable and costs
~920 MiB.

This is not permission to weaken the rest of Phase 2.1.

## 3. PHASE2_1_EXC_001

Stable identifier: `PHASE2_1_EXC_001`.

Meaning: `idx_search_ngram` is retained because deployed ClickHouse
26.7.3.19 `EXPLAIN` and four-way ablation prove that retained deterministic
true-substring LIKE predicates materially use it, while the locked text
index cannot safely replace all such predicates.

Expected retained definition:

- name: `idx_search_ngram`
- expression: `search_blob`
- type: `ngrambf_v1(3, 512, 2, 0)`
- granularity: 4

`idx_search_token` is not part of this exception.

The exception does not authorize keeping `idx_search_token`, adding new
bloom indexes, retaining arbitrary obsolete indexes, changing pattern
semantics, changing the locked text-index definition, or ignoring future
EXPLAIN evidence. Future removal of `idx_search_ngram` requires a new
architecture review with exact detection parity + EXPLAIN + performance
evidence.

## 4. Canonical plan amendment

`casescope_database_flow_plan_v4_locked.md` Phase 2.1 now unambiguously
means:

- deploy/use the locked `search_blob` text index
- term hunts use `hasAllTokens` / `hasAnyTokens`
- LIKE remains available for true substrings
- retire legacy bloom indexes only where EXPLAIN proves them redundant
- `idx_search_token` is retired by Phase 2.1
- `idx_search_ngram` is retained under `PHASE2_1_EXC_001`
- `command_line` remains `COMMAND_LINE_INDEX_DEFER`
- `materialize_skip_indexes_on_insert=0` remains measured rather than
  assumed; production stays
  `KEEP_PRODUCTION_MATERIALIZE_SKIP_INDEXES_ON_INSERT_1`

A dated architecture decision / change history entry was added.
Later phases were not rewritten. Publication ≠ presence, measurement
discipline, forensic integrity, fail-closed behavior, and recall-parity
requirements were not weakened.

## 5. Production index state before

Read-only. Database `casescope`. 745,463,991 rows / 135 active parts /
25 partitions.

| Index | Expression | Type | Granularity | Compressed bytes |
|---|---|---|---:|---:|
| `idx_search_blob_text` | `search_blob` | `text(tokenizer = 'splitByNonAlpha', preprocessor = lower(search_blob))` | 100000000 | 14,603,118,274 |
| `idx_search_ngram` | `search_blob` | `ngrambf_v1(3, 512, 2, 0)` | 4 | 4,049,580 |
| `idx_search_token` | `search_blob` | `tokenbf_v1(32768, 3, 0)` | 4 | 964,699,630 |
| `idx_event_id` | `event_id` | `bloom_filter(0.01)` | 4 | present |
| `idx_selector_key` | `selector_key` | `bloom_filter(0.01)` | 4 | present |
| `idx_evidence_record_key` | `evidence_record_key` | `bloom_filter(0.01)` | 4 | present |

Text-index coverage: MATERIALIZED 25 / PARTIAL 0 / UNMATERIALIZED 0 /
UNKNOWN 0. Active parts 135/135 MATERIALIZED. Mutations in progress: 0.

## 6. Final token-bloom dependency check

Targeted confirmation over `hasToken`, `hasTokenCaseInsensitive`, `LIKE`,
`ILIKE`, `lower(search_blob) LIKE`, `hasAllTokens`, and `hasAnyTokens`.
Repository readers were inspected first, including production-required and
background-derivation paths (`utils/ioc_artifact_tagger.py`,
`utils/noise_keywords.py`, `utils/candidate_extractor.py`,
`utils/mitre_attack_sync.py`, `utils/pattern_check_definitions.py`,
`models/rag.py`, Hunt helpers, `models/pattern_rules.py`).

For representative queries, A = normal indexes, B = ignore
`idx_search_token` only.

Decision: `TOKEN_BLOOM_REDUNDANT`.

All retained current readers (production-required and background-derivation)
kept exact result count/identity, the same meaningful EXPLAIN pruning, and
`read_rows` delta 0 attributable to token removal.

Note, not a keep-token reason: case-sensitive `hasToken(search_blob,
'powershell')` on case 10 changed counts when the token bloom was ignored
because that skip index false-negatives when chained with the text-index
`hasToken` prewhere. The only repository caller is
`bin/database_flow_baseline.py` (`offline-admin`). Isolated `hasAllTokens`
and `hasTokenCaseInsensitive` remain exact without the token bloom.

No retained current reader independently benefits materially from
`idx_search_token`.

## 7. Ngram exception reproof

Representative case-sensitive LIKE predicates were re-explained without
optimization, without ILIKE prefilters, and without changing
`models/pattern_rules.py`:

- `search_blob LIKE '%NTLM%'`
- `search_blob LIKE '%RC4%'`
- `search_blob LIKE '%IPC$%'`
- `search_blob LIKE '%TXT%'`
- `search_blob LIKE '%cmd /c%'`

Where corpus matches exist, `idx_search_ngram` still appears and prunes.
Case 10 `cmd /c` had 0 matches and was skipped as specified. After the
token drop the same ngram prune remains.

## 8. Fresh-install schema

`migrations/add_events_table.py` `EVENTS_SCHEMA` now creates:

- `idx_search_ngram` PRESENT (`ngrambf_v1(3, 512, 2, 0)` GRANULARITY 4)
- `idx_search_blob_text` PRESENT (locked tokenizer / `lower(search_blob)`)
- `idx_search_token` ABSENT
- `idx_event_id`, `idx_selector_key`, `idx_evidence_record_key` PRESENT

Block-number / block-offset settings unchanged. No `search_blob` or column
changes.

## 9. Token retirement migration

Dedicated `migrations/drop_events_search_token_bloom.py`.

- Inspects `system.data_skipping_indices`
- Drops only canonical `idx_search_token`
  (`search_blob` / `tokenbf_v1(32768, 3, 0)` / granularity 4)
- Absent = success / no-op
- Wrong expression, type, or granularity = fail closed, no DROP
- Missing or drifted `idx_search_ngram` = refuse
- SQL:
  `ALTER TABLE events DROP INDEX idx_search_token SETTINGS mutations_sync = 1`
- Production database `casescope` requires `--apply-production`
- Not invoked from application startup
- Contains no DROP / mutation of `idx_search_ngram`, no MATERIALIZE INDEX,
  no OPTIMIZE FINAL, no evidence rewrite

## 10. Migration idempotence / drift proof

Disposable ClickHouse fixture (old schema = ngram + token + text):

- first run drops token; ngram and text remain; row count, `search_blob`,
  ERK fingerprint, and protocol identity unchanged
- second run is a clean no-op
- drifted `idx_search_token` type/expression refuses DROP
- migration source contains no DROP of `idx_search_ngram`

## 11. Production quiescence

Producer-first. Broker messages were not deleted.

1. Stopped `casescope-web`, then `casescope-beat`
2. Celery drain: active = 0, reserved = 0, scheduled = 0, queued = 0,
   unacked = 0
3. Ingest fence healthy: `shared_writer_count = 0`, no exclusive owner
4. Stopped `casescope-workers` after drain
5. Recheck: all three units inactive; queued/unacked still 0; fence idle

## 12. Immediate pre-drop proof

Immediately before DROP: database `casescope`, ClickHouse 26.7.3.19,
canonical token identity, approved ngram exception identity, locked text
index, coverage 25/0/0/0, 135/135 materialized, 745,463,991 rows,
25 partitions, 0 mutations, fence idle, fingerprints taken for cases
14 / 10 / 7 / 32. Token definition had not drifted.

## 13. Production token drop

Ran only the dedicated migration with `allow_production=True`.

- elapsed 5.412 s
- mutation `mutation_34837.txt` `(DROP INDEX idx_search_token)` is_done=1,
  parts_to_do=0, no fail reason
- `idx_search_token` ABSENT
- `idx_search_ngram` PRESENT, exact approved definition
- `idx_search_blob_text` PRESENT, exact locked definition
- `idx_event_id`, `idx_selector_key`, `idx_evidence_record_key` unchanged
- no evidence rewrite, no `search_blob` rewrite, no MATERIALIZE INDEX,
  no OPTIMIZE FINAL, no DROP of `idx_search_ngram`

ERK and `search_blob` fingerprints for cases 14 / 10 / 7 / 32 were
identical before and after.

## 14. Semantic parity

Exact pre/post identities:

| Kind | Case | Predicate | n |
|---|---:|---|---:|
| TOKEN_SAFE | 14 | `hasAllTokens(search_blob, 'sonicwall')` | 13 |
| TOKEN_SAFE | 10 | `hasAllTokens(search_blob, 'powershell')` | 19455 |
| TOKEN_SAFE | 7 | `hasAllTokens(search_blob, 'powershell')` | 705353 |
| TOKEN_SAFE | 32 | `hasAllTokens(search_blob, 'powershell')` | 940117 |
| SUBSTRING | 10 | `search_blob ILIKE '%cmd.exe%'` | 3025 |
| SUBSTRING | 7 | `search_blob ILIKE '%10.0.0.1%'` | 3162 |
| SUBSTRING | 10 | `search_blob ILIKE '%Windows PowerShell%'` | 13370 |
| UNICODE | 10 | `münchen` / `用户` ILIKE | 0 / 0 |
| STRUCTURED | 7 | `event_id = '4688'` | 87 |
| EXCLUSION | 14 | `NOT search_blob ILIKE '%powershell%'` | 1341 |
| PATTERN | 10 | LIKE NTLM / RC4 / IPC$ / TXT | 2200 / 29 / 3014 / 124 |

Case 10 `10.0.0.1` and `4688` remain 0 matches on that corpus. Unicode
stays on ILIKE. Pattern `cmd /c` still 0 on case 10; ngram still prunes
the LIKE plan.

## 15. Post-drop EXPLAIN

TOKEN_SAFE queries still take the `idx_search_blob_text` direct path.
Required substring pattern queries still list `idx_search_ngram` and still
prune. `idx_search_token` is absent from skip lists.

## 16. Post-drop performance

TOKEN_SAFE and PATTERN `read_rows` were unchanged. p50 movement was within
normal sample noise (example: case 14 sonicwall 9.41 ms → 8.20 ms; case 10
NTLM 120.6 ms → 123.1 ms). No query previously attributed as
token-independent showed a meaningful regression caused by token
retirement.

## 17. Storage

| | Before | After |
|---|---:|---:|
| `idx_search_token` compressed bytes | 964,699,630 | metadata absent |
| `idx_search_ngram` compressed bytes | 4,049,580 | 4,049,580 |
| `idx_search_blob_text` compressed bytes | 14,603,118,274 | 14,603,118,274 |
| events compressed bytes | 123,153,313,168 | 122,188,508,065 |
| filesystem free (`/var/lib/clickhouse/`) | 74,527,657,984 | 74,459,926,528 |

Token metadata is absent. Parts accounting already dropped ~965 MiB of
index bytes from `events` compressed size. Immediate filesystem free did
not increase; disk-byte reclamation is asynchronous and is not required
for this exit.

## 18. Hunt product smoke

Services restored in accepted order: `casescope-web`,
`casescope-workers`, `casescope-beat`. All active. Authenticated login
succeeded. Running UI reports `v4.26.0`.

Case 14 `sonicwall`: grid total 13, 13 rows, detail 200, export-view 13
CSV data rows, export-tagged HTTP 200 with 0 tagged rows (no tagged
fixture). Product `query_log` shows
`hasAllTokens(search_blob, 'sonicwall')` plus the publication bridge
(`visible_evidence_generations` / `durable_ingest_batches`). No
`ILIKE '%sonicwall%'`. Journal had no 500 / Traceback / UNKNOWN_INDEX /
UNKNOWN_FUNCTION / ClickHouse exception for this window.

## 19. Publication authority regression

F2 re-run against disposable PostgreSQL + ClickHouse
(`phase2_1c_test`). Required surfaces: grid, count, detail/raw,
export-view, export-tagged. STAGED hidden, DURABLE BUILDING_INITIAL
visible, BUILDING_REPLACEMENT hidden, activation swaps authority,
malformed identity hidden. Result: PASS, 0 skipped.

Required regression suite including dedicated D2B tests: 224 passed,
0 skipped, 18.81 s. `py_compile`, `pyflakes`, and `git diff --check`
were clean.

## 20. Insert-index decision

Exactly: `KEEP_PRODUCTION_MATERIALIZE_SKIP_INDEXES_ON_INSERT_1`

The 2.1D setting=0 experiment was not re-run. Production
`system.settings.materialize_skip_indexes_on_insert` remains `1`.
Setting 0 preserves correctness but leaves freshly inserted parts without
the text index under production merge exclusion until explicit
materialization. No post-insert materializer was introduced.

## 21. command_line decision

Exactly: `COMMAND_LINE_INDEX_DEFER`

No `command_line` index was added.

## No-later-phase audit

No DROP of `idx_search_ngram`. No `pattern_rules` rewrite. No ILIKE
prefilter production migration. No new search index. No `command_line`
index. No production `materialize_skip_indexes_on_insert` change. No
async_insert decision. No Phase 2.2 / 2.3 / 2.4 / 3+. No LEK. No
`events_current`. No `event_observations_current`. No pagination redesign.

## Remaining work

Independent review of D2B only. After that review accepts this tranche,
Phase 2.1 is CLOSED. The next locked tranche is Phase 2.2 — explicit
insertion-mode benchmark/decision. Phase 2.2 was not started here.
