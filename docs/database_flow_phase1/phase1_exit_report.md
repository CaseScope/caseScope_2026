# Phase 1 Exit Report

## 1. Starting State

- Remote main SHA after fetch: `8c4c1dd3b1651df42dc08c39f06250d296864c57`
- Local HEAD: `8c4c1dd3b1651df42dc08c39f06250d296864c57`
- Expected locked baseline: `8c4c1dd3b1651df42dc08c39f06250d296864c57`
- Main moved: no
- Version: `4.18.6`
- Branch: `main`
- Git actions: no commit, no push, no PR

The initial unauthenticated fetch failed with GitHub SSH public-key denial. The required deploy-key fetch succeeded. Pre-existing modified/untracked Phase 0/1 worktree files were preserved.

## 2. Phase 0 Baseline

Accepted Phase 0 corpus:

- Files: 8 EVTX
- Bytes: 77,103,104
- Parsed events: 110,742
- Wall: 332.884 s
- Throughput: 332.674 events/sec
- Peak RSS: 237.36 MB

## 3. Phase 1 Implemented Scope

Ratified implemented scope:

- 1.1 alias extraction removed from `BatchProcessor.add_event`; scoped post-file alias population preserves raw-json-excluded CMMC semantics.
- 1.2 `orjson` is used in measured EVTX JSONL hot loops while normalized event semantics remain unchanged.
- 1.3 fresh schema no longer forces Wide parts; reset migration is controlled and not startup-wired.
- 1.4a fail-closed shared/exclusive ingest fence exists; Redis outage refuses unsafe writes/destructive operations.
- 1.4 runtime Buffer dependency removed; inserts go directly to `events`; Buffer removal is operator-run.
- 1.5 IOC raw_json removal was not shipped because zero-false-negative recall failed.
- 1.6 profiler set-based rewrite preserves username/SID and hostname-role semantics with bounded query count.
- 1.7 directory mode is source-aware and progressive via eager-first policy.
- 1.8 only `EventData.KeyLength` was promoted to `key_length Nullable(UInt16)`.

No Phase 1B or Phase 2 implementation was found in this exit pass.

## 4. Integrated Benchmark

Fresh integrated run artifact: `docs/database_flow_phase1/phase1_exit_benchmark_run1.json`.

Configuration: direct `events` inserts, explicit ingest fence, no Buffer runtime dependency, scoped alias post-file population, `orjson`, eager-first directory policy, `key_length`, 10k insert batch size, disposable PostgreSQL/ClickHouse/storage, Redis isolated by fence prefix.

Result:

- File count / bytes: 8 / 77,103,104
- Parsed and inserted events: 110,742
- Detections consumed from Hayabusa JSONL: 7,436
- Wall: 136.869 s
- Throughput: 809.109 events/sec
- Source throughput: 0.537 MB/sec
- First searchable: 18.371 s
- Second/last unit searchable: 44.443 s
- Completion tail: 113.576 s
- Peak RSS: 222.45 MB
- CPU self / children: 96.597 s / 93.539 s
- EvtxECmd total: 31.392 s
- Hayabusa total: 16.802 s
- EVTX JSONL consume: 89.862 s
- Normalization: 38.601 s
- Alias scan / PG write: 5.716 s / 0.003 s
- Fence shared / exclusive acquire: 0.009 s / 0.016 s
- After insert parts: 2 Compact + 4 Wide, 0 mutations
- After final harness optimize: 1 Wide part, 0 mutations
- Errors / retries: 0 / 0

Only one fresh run was performed because the result matched the Step 5 integrated envelope and exceeded the locked gate by a wide margin. It is not a cherry-picked fastest run.

## 5. Performance Exit Gate

Required throughput: 665.348 events/sec.

Actual integrated throughput: 809.109 events/sec.

- Multiplier vs Phase 0: 2.432x
- Wall-time reduction vs Phase 0: 58.887%
- RSS delta vs Phase 0: -14.91 MB
- First-searchable retained near accepted Step 4/5 values: 18.371 s

Performance gate: PASS.

## 6. Full Event Semantic Parity

Accepted Step 5 semantic artifact remains exact:

- Events: 110,742 current = 110,742 legacy
- Missing ERKs: 0
- Extra ERKs: 0
- Deterministic field diffs: 0
- `raw_json`, `search_blob`, `extra_fields`: parity preserved
- Parser errors/warnings: 0

The fresh benchmark ERK digest matched the accepted digest: `6ad87fe76520d18bde4cfb421bbd4fce0b410c00d60abaf642769aa303515b7c`.

## 7. Detection Parity

Accepted Step 4/5 artifacts show:

- Legacy detections: 7,436
- Current detections: 7,436
- Legacy minus current detections: 0
- Current minus legacy detections: 0
- Cross-file detection attachments: 0

Directory correlation remains `(source file identity, RecordID)`. RecordID-only correlation remains forbidden.

## 8. Privacy/CMMC Gate

Accepted contracted CMMC_CUI baseline:

- Contracted protected identities: 1,152
- Missing baseline identities: 0
- Extra contracted identities: 0
- Normalization mismatches: 0
- Per-channel coverage: exact in accepted Step 1 closure

`raw_json` alias extraction was not resurrected. `generation`/freeze/verify Phase 1B privacy behavior has not been implemented early.

Gate: PASS.

## 9. Fence Gate

Focused fence coverage remains green:

- Normal event writers use shared admission.
- Exclusive operations drain shared writers.
- Redis unavailable refuses shared insert/destructive operation.
- Stale owner cannot continue.
- Multiple admins serialize.
- Nested ownership remains correct.
- Fail-open correctness callers: 0.

Gate: PASS.

## 10. Buffer Exit State

Current classifications:

- Runtime production dependency: 0
- Fresh installs do not create `events_buffer`.
- Direct ingest writes to `events`.
- `migrations/remove_events_buffer.py` is operator-run, fence-protected, drains/verifies before `DROP`, idempotent, and production-guarded.
- Production Buffer was not dropped in this pass.

Remaining `events_buffer` references are migration compatibility, historical docs/artifacts, tests, and measurement harnesses. Runtime direct ingest does not require Buffer.

Gate: PASS.

## 11. IOC Gate

Step 3 decision is ratified:

- `raw_json` remains IOC common-path coverage.
- Fixture `no_raw_json` A-B misses: 2, both `RAW_JSON_ONLY_TRUE_MATCH`.
- Retained case 10 `no_raw_json` A-B misses: 3, valid raw-json-only legacy matches.
- ERK provenance, matched field/value semantics, and `IOCEvidenceMatch` lifecycle were not redesigned.

Gate: PASS.

## 12. Profiler Gate

Profiler gate remains green:

- Optimized main path query count: 2.
- Username OR SID semantics preserved.
- User set and SID associations preserved.
- System set and `source_host` / `workstation_name` / `remote_host` roles preserved.
- Counts, first/last seen, and aggregates matched accepted parity cases.

Known deferred defect retained, not fixed: `EXISTING_PROFILER_CORRECTNESS_DEFECT` for `_get_top_n` tie ordering.

Gate: PASS.

## 13. Directory-Mode Gate

Ratified final policy:

- First currently ready EVTX: per-file.
- Remaining ready EVTX: bounded directory groups.
- Preferred target: 8 files / 128 MiB.
- Absolute safety max: 32 files / 512 MiB.
- Fill window: 0 seconds.
- Correlation: source file identity + RecordID.

Accepted focused tests cover duplicate basenames, duplicate RecordID, malformed file/tool fallback, no duplicate processing, no cross-file attachment, and progressive first-searchable behavior.

Gate: PASS.

## 14. Typed-Column Gate

Only `EventData.KeyLength -> key_length Nullable(UInt16)` was promoted.

Why it earned promotion:

- Existing pass-the-hash readers directly filtered `JSONExtractString(raw_json, 'EventData', 'KeyLength')`.
- Field is low-cardinality and safely bounded as `Nullable(UInt16)`.
- Parser can populate it from already-decoded EVTX `EventData`.
- Historical fallback preserves legacy rows.
- Query benefit was measured, not inferred.

Measured query value:

- Non-zero case 33 predicate legacy JSON median: 14.006 ms
- Typed-only median: 5.015 ms
- Conditional historical fallback median: 9.165 ms
- Counts equal: 529
- EXPLAIN indexes=1 shape did not change; benefit is avoiding JSON extraction.
- Storage cost: +291,138 compressed bytes, +0.543%, about 0.529 bytes/event on representative data.

Invalid, missing, malformed, and overflow values become `NULL` in `key_length` while source value remains in `raw_json` and `search_blob`. `extra_fields` invariants are preserved.

Gate: PASS.

## 15. Typed-Column Deployment Compatibility

Disposable compatibility probe:

- Can new application code run against old production `events` schema without `key_length`? NO.
- Can old application code run after nullable `key_length` is added? YES.

Evidence:

- New insert against old schema failed: unrecognized column `key_length`.
- New reader SQL against old schema failed: unknown identifier `key_length`.
- Old insert column list against new schema passed and left `key_length` NULL.

Required deployment order:

1. Pre-deploy: run `migrations/add_event_key_length_column.py` against production ClickHouse.
2. Verify `events.key_length Nullable(UInt16)` exists.
3. Deploy application code.
4. Restart workers first, then web, one exact service command at a time.
5. Verify inserts, readers, and key_length population.

Migration-before-code is a HARD deployment requirement. No production migration was run.

## 16. Schema Migration Integration

Disposable upgrade order exercised:

`4.18.5-style forced-Wide schema with Buffer and no key_length -> reset forced-Wide -> remove Buffer -> add key_length`

Results:

- Forced-Wide reset changed once, rerun no-op.
- Buffer removal drained with pending rows 0, dropped, rerun reported already removed.
- `key_length` add changed once, rerun no-op.
- Final: no Buffer, `key_length Nullable(UInt16)`, no forced-Wide override.
- No mass backfill.
- No production-sized `OPTIMIZE FINAL`.

Gate: PASS.

## 17. Reader/Writer Inventory Drift

Accepted Phase 0A counts:

- Direct-events reader locations: 167
- Write/mutation paths: 47

The original exact inventory scanner was not preserved as a reusable command in the repository; `bin/database_flow_baseline.py` is a ClickHouse diagnostics utility, not the source scanner. A transparent current pattern inventory was still performed.

Observed Phase 1 drift:

- New/changed typed-field readers: `utils/candidate_extractor.py`, `models/pattern_rules.py`, `utils/mitre_attack_sync.py`.
- New writer surface: parser insert column list now includes `key_length`.
- New destructive paths: none identified.
- New direct-events dependency: `key_length` column is a deployment dependency; covered by migration-before-code requirement.

This limitation is documented rather than hidden.

## 18. Integrated Tests

Monolithic focused command:

- Ran: 395
- Failures: 0
- Errors: 20
- Skipped: 1
- Classification: test-process contamination. `utils.clickhouse` was stubbed in earlier tests and leaked into later tests, causing missing attributes such as `delete_file_events`.

Reliable module-scoped focused coverage:

- Ran: 407
- Failures: 0
- Errors: 0
- Skipped: 1
- Classification: PASS, with graph model dependency loaded before graph lifecycle/materialization tests.

Covered Phase 1 step tests, parser hardening/retries, ClickHouse delete/dedup contracts, ingest fence, privacy aliases, IOC, profiler, MITRE, and graph lifecycle/materialization interfaces touched by ingest.

## 19. Static Validation

Validation performed:

- Phase 1 and contract JSON files checked: 49
- Phase 1 JSONL files checked: 8
- Python files compiled: 673
- Python compile errors: 0

Static artifact blockers:

- `docs/database_flow_phase1/phase1_step4_latency_ingest_summary.jsonl` contains migration console output and is not valid JSONL.
- Five Step 4 probe JSON outputs contain a UTF-8 BOM and fail strict `json.loads` without `utf-8-sig`.

No benchmark-specific production batch-size change was found. Runtime hardcoded benchmark paths were not found; benchmark paths are in measurement scripts/artifacts.

Static gate: FAIL.

## 20. Existing Defects / Deferred Work

Deferred/pre-existing:

- `EXISTING_PROFILER_CORRECTNESS_DEFECT`: `_get_top_n` tie ordering.
- `IOCEvidenceMatch.matched_field` remains existing search_blob-default behavior.
- Some Huntress SHA256 evidence can exist only in `raw_json`.
- Monolithic test command has process contamination; module-scoped tests pass.
- Exact Phase 0A inventory scanner is not preserved as a reusable command.

Exit blocker:

- Malformed generated Phase 1 artifacts under `docs/database_flow_phase1/`.

## 21. Production Deployment Requirements

Do not apply in this pass.

PRE-DEPLOY:

- Ensure `orjson` dependency is installed.
- Add `events.key_length Nullable(UInt16)` before code deploy. REQUIRED BEFORE NEW CODE.
- Redis must be available for fail-closed ingest fence.
- EvtxECmd and Hayabusa paths/rules/config must remain available.
- Forced-Wide reset is optional/deferred operator action.
- Buffer removal is optional/deferred operator action unless separately scheduled.

DEPLOY:

- Deploy application code after the key_length migration is verified.
- Restart workers before web in controlled single-service commands.

POST-DEPLOY VERIFY:

- Confirm `events.key_length Nullable(UInt16)`.
- Confirm Redis/fence shared and exclusive paths.
- Confirm direct `events` insert.
- Confirm directory-mode tools and source-aware detection attachment.
- Confirm scoped alias scanner.
- Confirm `key_length` population and fallback query behavior.

DEFERRED OPERATOR ACTION:

- Production Buffer removal: optional/deferred, must be operator-run and fence-protected.
- Forced-Wide reset: optional/deferred, must not be automatic.
- Any production migration/drop: not authorized by this exit pass.

## 22. Phase 1 Exit Verdict

PHASE1_NOT_ACCEPTED

Reasons:

- Integrated performance gate passes.
- Semantic, detection, privacy, fence, Buffer, IOC, profiler, directory-mode, typed-column, compatibility, and migration gates pass.
- Phase 1 static artifact validation fails because malformed generated artifacts remain.
- The monolithic integrated test command fails from test-process contamination, though reliable module-scoped coverage passes.

The gate is not weakened. Phase 1 may not be closed until the static artifact blocker is resolved or explicitly accepted under change control.

## 23. Phase 1B Preconditions

Because the verdict is `PHASE1_NOT_ACCEPTED`, no Phase 1B preconditions are declared satisfied by this exit review.

Phase 1B work still not implemented:

- evidence generations
- ingest_attempt_id
- deterministic ingest_batch_id
- manifest STAGED/DURABLE protocol
- CH row ordinals/hashes
- generation publication projections
- event_observations_current
- events_current
- capability watermarks
- freeze-then-verify AI privacy gating
- completion reconciler
- readiness UI
