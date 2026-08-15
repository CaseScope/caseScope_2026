# Phase 1 Step 1 Report

Status: STEP1_ACCEPTED. Full Phase 1 is not complete.

## 1. Starting State

- Remote main: `8c4c1dd3b1651df42dc08c39f06250d296864c57`
- Local HEAD: `8c4c1dd3b1651df42dc08c39f06250d296864c57`
- Version: `4.18.5`
- Remote main has not moved since the locked baseline.
- Pre-existing/unowned worktree files were preserved. No commit. No push.

## 2. Accepted Phase 0 Baseline

Approved corpus `/opt/casescope-benchmark/phase0a_evtx/` is still present, SHA256-identical, 8 EVTX, 77,103,104 bytes, non-retained.

Accepted BEFORE:

- parsed events: 110,742
- events after current dedup (harness `events` count): 49,115
- wall time: 332.884 s
- parsed throughput: 332.674 events/sec
- source throughput: 0.221 MB/sec
- peak RSS: 237.36 MB

Phase 0B: 10/10 contracts LOCKED. Decision log DEC-001 through DEC-022. No contract implementation blocker was hit.

## 3. Files Changed

New or modified for this step:

- `parsers/registry.py` — remove per-event alias extraction; file-grained populate after insert
- `utils/privacy_aliases.py` — scoped DISTINCT scanner (`case_id`, `case_file_id=None`, `generation=None`)
- `parsers/evtx_parser.py` — orjson in EVTX JSONL / Payload hot loops
- `utils/clickhouse.py` — existence-probe-then-skip DELETE
- `migrations/add_events_table.py` — stop forcing wide parts on CREATE
- `migrations/reset_events_wide_part_settings.py` — idempotent RESET SETTING helper (not wired to startup)
- `requirements.txt` — `orjson>=3.10.0`
- `tests/test_phase1_step1.py`
- `scripts/phase0a_ingest_benchmark.py` — record new stages / part types
- `docs/database_flow_phase1/*`

## 4. Alias Hot-Path Change

`BatchProcessor.add_event` no longer calls `extract_alias_candidates_from_event_rows`. After a file's batches flush under current Buffer architecture, `process_file` calls `populate_case_privacy_aliases(case_id, case_file_id=..., generation=None, source='ingest_structured')`.

Scanner changes:

- independent per-column GROUP BY value (never tuple DISTINCT)
- `raw_json` remains excluded from free-text scan
- file scope uses `AND case_file_id = ?` and unbounded DISTINCT (no 20k cap)
- `generation` is accepted only as `None`; nonzero raises
- scan table prefers `events_buffer` so just-inserted Buffer rows are visible

## 5. Alias Semantic Parity

On flushed disposable Security.evtx (29,575 rows), after canonical `(entity_type, normalized_value)` comparison at `cmmc_cui` and with `raw_json` excluded from both sides:

- old per-event extractor: 946 protected keys
- new scoped DISTINCT scanner: 946
- missing: 0
- extra: 0

Whole-case CMMC_CUI scan: 1,152 candidates.

Disposable ingest itself used privacy level `off` (no SystemSettings), so the live vault was empty. That is populate-as-authority behavior, not a hot-path extractor. Protected aliases at `cmmc_cui` were proven equal on the same rows.

## 6. orjson Change

`orjson` 3.11.9 is used only in EVTX JSONL outer decode, Hayabusa JSONL decode, and nested Payload decode. `raw_json` / `extra_fields` still use `json.dumps`. Fallback parser `json.loads(record['data'])` is unchanged.

Handled differences: bytes vs str, Unicode, duplicate keys (last wins), NaN/Infinity via stdlib fallback, malformed JSON normalized to `json.JSONDecodeError`.

## 7. JSON / ERK Parity

Unit transform of a 4624 fixture through stdlib JSON vs orjson produced identical ERK and identical normalized columns except known JSON-text formatting of `raw_json`/`extra_fields` object equality after parse.

Post-hoc flushed disposable table: 110,742 rows and 110,742 unique ERKs.

## 8. Forced-Wide Setting Change

Live ClickHouse 26.7.3.19 defaults: `min_bytes_for_wide_part=10485760`, `min_rows_for_wide_part=0`.

Production `casescope.events` still has the historical `= 0` override. This step did not ALTER production.

Supported syntax: `ALTER TABLE events RESET SETTING min_bytes_for_wide_part, min_rows_for_wide_part` (idempotent). New CREATE TABLE omits the override. The standalone migration refuses database `casescope` unless `--apply-production`.

## 9. Part Behavior

Disposable CREATE used defaults (no forced-wide). After inserts, Compact parts appeared (2 Compact / 2 Wide at harness snapshot). After Buffer flush: 2 Compact + 11 Wide. After `OPTIMIZE TABLE events FINAL`: 1 Wide part, 110,742 rows. Historical production Wide parts were not OPTIMIZEd.

## 10. Pre-Parse DELETE Probe

`delete_file_events` now `SELECT 1 ... LIMIT 1` on `events`, then `events_buffer`. Miss skips ALTER DELETE. Hit keeps the current guarded DELETE. Probe exceptions fail-safe and still DELETE.

AFTER benchmark: 8 existence misses, 8 DELETEs skipped, probe wall 50.295 ms, zero mutations issued.

## 11. Retry/Cleanup Semantics

Retry-with-rows still executes ALTER DELETE (unit-tested). Parser-failure cleanup in `process_file` still calls `delete_file_events(wait=True)`. Probe failure does not assume zero rows.

## 12. Tests

`/opt/casescope/venv/bin/python -m unittest tests.test_phase1_step1` plus related retry/metrics/hardening tests: 28 OK.

Covered: alias hot-path absence, scoped DISTINCT SQL, generation=None, semantic parity, orjson/ERK/malformed/NaN, DELETE skip/hit/fail-safe, migration idempotency and production guard.

## 13. BEFORE Benchmark

Same accepted Phase 0A run:

- wall 332.884 s / 332.674 events/sec / 0.221 MB/sec / RSS 237.36 MB
- alias extract 170.863 s / alias PG write 8.136 s
- outer JSON 2.197 s / Payload JSON 1.209 s / JSONL consume 256.142 s
- EvtxECmd 47.408 s / Hayabusa 49.259 s
- CH insert 2.954 s / cleanup DELETE 1.130 s

## 14. AFTER Benchmark

Same corpus SHA256s. Disposable PG/CH `phase0a_ingest_20260814161717`.

- wall 148.408 s / 746.198 events/sec / 0.495 MB/sec / RSS 226.29 MB
- parsed events 110,742
- alias extract 0 / scoped scan 5.620 s / PG write 0.003 s
- outer JSON 0.995 s / Payload JSON 0.592 s / JSONL consume 73.644 s
- EvtxECmd 44.428 s / Hayabusa 49.101 s
- CH insert 2.491 s / existence probe 0.050 s / DELETE skipped 8

## 15. Performance Delta

- wall-time reduction: 184.476 s (55.42%)
- throughput multiplier: 2.243x
- RSS delta: -11.07 MB

Dominant win is removing per-event alias extraction from `add_event` (170.863 s → 5.620 s DISTINCT scan). orjson is a smaller decode win. DELETE skip removes ~1.1 s of zero-row mutations.

## 16. ClickHouse Delta

Harness `events` counts (BEFORE 49,115 / AFTER 14,004) are Buffer-visibility artifacts: `OPTIMIZE TABLE events FINAL` does not flush `events_buffer`. BEFORE 49,115 equals 110,742 − 61,627 (System.evtx). AFTER post-hoc `OPTIMIZE TABLE events_buffer` yielded 110,742 rows / 110,742 ERKs / 0 mutations. Compact parts now occur on insert. Production was not altered.

## 17. Semantic Acceptance

- parsed event count identical: 110,742
- ERK uniqueness after flush: 110,742
- alias protected-key parity on Security.evtx: equal
- `raw_json` still excluded from alias free-text scan
- IOC / MITRE / graph ingest paths were not redesigned; Hayabusa still keyed by record id
- retry cleanup preserved; zero-row DELETE skipped
- legacy dedup still ran; 0 duplicates found (same as BEFORE's "0 deleted")

## 18. Regressions / Existing Defects

- Harness physical `events` count without Buffer flush under-counts. This existed in Phase 0A (49,115) and is not a Step 1 semantic loss.
- Disposable privacy level `off` left the ingest vault empty; CMMC_CUI post-hoc scan is the parity proof.
- Production events table remains forced-wide until the standalone migration is deliberately applied.
- `alias_scoped_scan` had one 3.9 s outlier (PowerShell file) against a ~0.2–0.4 s median.

No Phase 0B contract contradiction.

## 19. Step 1 Verdict

**STEP1_ACCEPTED**

Performance PASS remains valid (2.243x). Full-corpus event semantic parity is exact. Contracted CMMC_CUI protected alias identity parity is exact. This is not a full Phase 1 exit.

## 20. Remaining Phase 1 Work

Not implemented here:

- 1.4 / 1.4a Buffer removal and shared/exclusive ingest fence
- 1.5 IOC query-path changes
- 1.6 behavioral profiler rewrite
- 1.7 Hayabusa/EvtxECmd directory mode
- 1.8 typed-column promotion
- 1B progressive orchestration
- Phase 2+
- LEK, generations, batch manifest, event surfaces, Qdrant/overlay migration

Locked Phase 1 overall exit remains >=2x ingest throughput plus remaining item gates. Step 1 alone already measured >=2x on this corpus; later items remain separately gated.

## 21. Step 1 Acceptance Closure

Machine-readable compare: `docs/database_flow_phase1/phase1_step1_parity_compare.json`.

Runs used isolated PostgreSQL/ClickHouse names `phase1_step1_parity_base_20260814191048` and `phase1_step1_parity_step_20260814191048`. Production evidence was not written. BASELINE was `main 8c4c1dd` in a disposable worktree. STEP1 was the current worktree. Privacy policy was `cmmc_cui` (production setting is `off`; no stricter relevant level is configured). Buffer was drained with `OPTIMIZE TABLE events_buffer` and pending rows were confirmed 0 before dumps.

### 1. Corpus identity proof

Both runs hashed the same 8 approved EVTX files. All 8 SHA256s matched the Phase 0A manifest. Total 77,103,104 bytes.

### 2. Full event row parity

After explicit Buffer flush:

| | BASELINE | STEP1 |
|---|---:|---:|
| rows | 110,742 | 110,742 |
| unique ERKs | 110,742 | 110,742 |
| events visible before Buffer flush | 49,115 | 14,004 |

Deterministic forensic/normalized columns were compared after excluding only `indexed_at`, disposable `case_id`, and independently allocated `case_file_id` (both runs actually allocated `case_id=1` and `case_file_id=1..8` identically). JSON object key ordering was treated as equivalent only when parsed objects matched; in this corpus even the `raw_json` / `extra_fields` strings matched.

- rows with any deterministic field difference: **0**
- fields differing: **none**
- representative mismatches: **none**

### 3. ERK set parity

ERK set SHA256 both sides: `6ad87fe76520d18bde4cfb421bbd4fce0b410c00d60abaf642769aa303515b7c`

- ERK set difference A−B: **0**
- ERK set difference B−A: **0**

### 4. raw_json parity

Zero unexplained `raw_json` differences. Parsed objects equal; original strings also equal on this corpus.

### 5. search_blob parity

Zero `search_blob` differences.

### 6. extra_fields parity

Zero unexplained `extra_fields` differences. Parsed objects equal; original strings also equal on this corpus.

### 7. Full-corpus alias parity

Live vault (privacy `cmmc_cui` on, aliases written during ingest):

| | BASELINE old per-event path | STEP1 scoped `populate_case_privacy_aliases` |
|---|---:|---:|
| candidate / vault rows all types | 2437 | 1152 |
| unique CMMC_CUI protected identities | 2414 | 1152 |
| STEP1 scanned candidate count | n/a | 1152 |
| baseline-only protected identities | 1262 | |
| STEP1-only protected identities | 0 | |
| normalization mismatches | 0 | |

Generated alias strings are sequential and were not required to match (26 / 1152 identical). Canonical `(entity_type, normalized_value)` is the comparison key.

Classification of the 1262 live-vault baseline-only identities, **before any production code change**:

- **1262 / 1262** have `sample_fields == ['raw_json']` only. This is the pre-Step1 per-event extractor scanning `raw_json`. Phase 1.1 keeps `raw_json` excluded. Not an unexplained miss.
- **23** additional all-type vault rows are out-of-level at CMMC_CUI: `URL` 13, `EXTERNAL_IPV4` 7, `EXTERNAL_DOMAIN` 3. The old upsert did not filter by privacy level; the new scanner does. These are not CMMC_CUI protected identities.

After applying the 1.1 contracts (raw_json excluded, CMMC_CUI types only):

- contracted protected identity set BASELINE: **1152**
- contracted protected identity set STEP1: **1152**
- missing: **0**
- extra: **0**

### 8. Per-channel alias parity

Contracted identities by source EVTX / channel (raw_json excluded):

| Source | Channel | BASELINE | STEP1 | parity |
|---|---|---:|---:|---|
| Application.evtx | Application | 46 | 46 | exact |
| Microsoft-Windows-PowerShell-Operational.evtx | Microsoft-Windows-PowerShell/Operational | 12 | 12 | exact |
| Microsoft-Windows-TaskScheduler-Operational.evtx | (0 events) | 0 | 0 | exact |
| Microsoft-Windows-TerminalServices-LocalSessionManager.evtx | .../Operational | 9 | 9 | exact |
| Microsoft-Windows-WMI-Activity-Operational.evtx | Microsoft-Windows-WMI-Activity/Operational | 4 | 4 | exact |
| Microsoft-Windows-Windows-Defender-Operational.evtx | Microsoft-Windows-Windows Defender/Operational | 144 | 144 | exact |
| Security.evtx | Security | 946 | 946 | exact |
| System.evtx | System | 9 | 9 | exact |

No channel hides a miss.

### 9. Buffer visibility finding

Pre-existing architectural finding; **not fixed in this closure pass**; feeds Phase 1.4.

`OPTIMIZE TABLE events FINAL` does **not** flush `events_buffer`.

Reproduced here:

- BASELINE before Buffer drain: `events=49,115`, buffer-visible `110,742`, pending `61,627` (System.evtx)
- STEP1 before Buffer drain: `events=14,004`, buffer-visible `110,742`, pending `96,738`
- After `OPTIMIZE TABLE events_buffer`: both `110,742` / pending `0`

The historical Phase 0A `49,115` and Step 1 AFTER harness `14,004` counts are this visibility artifact, not semantic loss. Canonical benchmark procedure now drains Buffer and refuses final counts while pending rows remain. `scripts/phase0a_ingest_benchmark.py` was updated accordingly. Production Buffer behavior was not changed.

### 10. Tests

Focused suite (not production-bound full discovery):

`tests.test_phase1_step1` (including new parity helpers), `tests.test_parser_hardening`, `tests.test_parser_retry_cleanup`, `tests.test_ingest_metrics`, and privacy alias tests:

**290 tests, 0 failures, 0 errors.**

### 11. Final Step 1 Verdict

**STEP1_ACCEPTED**

Required gates:

- previously measured performance PASS remains valid (332.884 s → 148.408 s, 2.243x)
- zero unexplained full-corpus event semantic differences
- exact ERK set parity
- full-corpus protected alias identity parity under CMMC_CUI after classifying raw_json-only and out-of-level live-vault extras as the 1.1 contract
- no unresolved Step1-caused regression

Not started: Phase 1.4 / Buffer removal / ingest fence.
