# Phase 2.3 Lightweight UPDATE Bridge Result

Implementation record for the locked Phase 2.3 sentence only:

"Lightweight UPDATE bridge (Gate B) for small state paths, batched;
 classic mutations behind the drain-capable fail-closed fence for
 large rewrites; audit hooks carried over. Bridge only."

Does not reopen Gate B. Does not start Phase 2.4 or Phase 3+.

**Tranche verdict: PHASE2_3_PASS**

Phase 2.3 state: `PHASE2_3_CLOSED_PENDING_INDEPENDENT_REVIEW`

## 1. Starting State

- Repository: `/opt/casescope`
- Python: `/opt/casescope/venv/bin/python`
- HEAD / origin/main: `658cd18e9647595d49edfb40e1831972837dbca3`
- HEAD == origin/main, working tree clean at start
- Starting version: 4.26.1
- Deployed ClickHouse: 26.7.3.19

## 2. Locked Phase 2.3 Contract

Bridge only. Small explicit selector-key state patches may use SQL `UPDATE`.
Predicate/broad rewrites remain classic `ALTER TABLE events UPDATE` behind the
exclusive drain-capable fail-closed fence. Forensic event facts/identity are
not rewritten. Publication remains distinct from physical presence. Audit
hooks are carried over. Reversal path is retained: oversized and all
non-bridge callers still use the previous classic helper.

## 3. Gate B Inputs

Accepted, not re-qualified. Conservative CaseScope boundary:

`LIGHTWEIGHT_UPDATE_MAX_SELECTOR_KEYS = 1000`

Gate B measured 1,000-row lightweight UPDATE at ~20.6 ms in the small-state
regime; 10,000 rows was substantially more expensive and showed patch-part
read amplification. This is not a universal ClickHouse threshold and has no
environment-variable override.

Accepted small-bridge candidates remain:

- `upsert_event_analyst_state_rows()`
- `upsert_manual_noise_state_rows()`

Classic/deferred classifications were not reopened.

## 4. Lightweight Helper

`utils.clickhouse.run_events_lightweight_update(assignments_sql, *, case_id, selector_keys, artifact_type=None, client=None)`

- `selector_keys` is mandatory and keyword-only
- empty list is a no-op
- more than 1000 keys raises `LightweightUpdateRefused`
- helper builds its own WHERE: `case_id` plus optional `artifact_type` plus
  `has([...], selector_key)`
- does not accept caller-supplied `where_sql`
- SQL form is `UPDATE events SET ... WHERE ...`
- does not use `ALTER UPDATE`

`run_events_update()` is unchanged: classic `ALTER TABLE events UPDATE` with
`mutations_sync = 1` and no `lightweight=` / `mode=` switch.

## 5. Fence Model

Lightweight helper wraps `client.command(...)` in existing
`shared_ingest_admission("events_lightweight_update", case_id=case_id)`.

Classic helper retains `exclusive_ingest_fence("events_alter_update")`.

Redis/fence unavailable refuses the lightweight UPDATE. Exclusive pending
prevents a new lightweight writer. Exclusive waits for an active lightweight
shared writer to drain. After exclusive release, lightweight writers may
proceed. No new lock system.

`shared_ingest_admission` docstring now says "normal bounded events write".
Locking semantics are unchanged.

## 6. Analyst State Cutover

`upsert_event_analyst_state_rows()` chooses one mode for the whole logical
operation from `len(prepared_rows)`:

- `<= 1000` → lightweight helper for every grouped mutation
- `> 1000` → existing classic `run_events_update` for every grouped mutation

Preparation, grouping, `case_id`, optional `artifact_type`, selector keys,
assignments, matched-count, prior-state capture, `operation_id`, per-event
old/new audit, username, remote_ip, and source_file metadata are unchanged.
No route/API identity change.

## 7. Manual Noise Cutover

`upsert_manual_noise_state_rows()` uses the same `<= 1000` / `> 1000` rule.
Noise representation, audit, and HTTP semantics are unchanged.

## 8. Classic Paths Preserved

These still call `run_events_update()` only:

- noise scan / scan-match (`start_noise_scan`, `insert_noise_scan_matches`)
- IOC refresh / scan-match (`start_ioc_refresh`, `insert_ioc_scan_matches`)
- MITRE map / reset / rebuild (`insert_mitre_rule_matches`,
  `rebuild_mitre_summary_columns`)
- overlay case reset (`purge_case_event_overlay_state`)
- Hayabusa MITRE reenrichment (`utils/hayabusa_mitre_reenrichment.py`,
  still deferred; 5,000-record classic batches)

A small pre-count does not switch those structurally broad predicates.

## 9. Audit Parity

Successful small paths still: read prior state → mutate → `record_event_changes()`.
Same `operation_id`, EventChange old/new, actor, remote IP, and source metadata.

If lightweight UPDATE raises, or shared admission fails: no mutation and no
success audit for that group. AuditLog schema/authority were not redesigned.

`utils/evidence_audit.py` commentary now states that events state changes flow
through either the bounded lightweight helper or classic `run_events_update()`.

## 10. Forensic Identity Invariance

Disposable final `EVENTS_SCHEMA` proof: after lightweight analyst UPDATE,
`evidence_record_key`, `selector_key`, `search_blob`, `raw_json`,
`extra_fields`, source-ref / ingest identity columns, timestamps, source
fields, event facts, and row count were unchanged. Non-target rows stayed
untagged.

## 11. Disposable Lightweight Proof

Deployed ClickHouse 26.7.3.19, disposable database, current final events schema.
No million-row rebenchmark.

- A. 1 selector: lightweight UPDATE succeeded
- B. 100 selectors: succeeded
- C. 1000 selectors: succeeded
- D. 1001 selectors: helper refused (`LightweightUpdateRefused`); no command
- E. 1001-row analyst and manual-noise logical actions used classic
  `ALTER TABLE events UPDATE`

## 12. Immediate Visibility

After the helper returned, same-client SELECT and a fresh-client SELECT both
saw the new analyst value. No `OPTIMIZE FINAL`, `MATERIALIZE`, or
sleep-for-correctness.

## 13. Lightweight / Classic State Parity

Identical 12-row fixtures:

- analyst lightweight (product upsert, 6 selectors) vs classic
  `run_events_update` produced the same `analyst_tagged` / tags / notes
- manual-noise lightweight vs classic produced the same `noise_matched` /
  `noise_rules`
- non-target rows remained unchanged

## 14. Fence Fail-Closed Proof

Existing memory fence backend:

1. lightweight helper acquires shared admission
2. Redis/fence unavailable: no UPDATE command
3. exclusive held in another thread: new lightweight writer denied
4. exclusive waits for active lightweight shared writer to drain
5. after exclusive release, lightweight writer proceeds
6. classic `run_events_update` still takes exclusive and emits ALTER UPDATE

## 15. Production Pre-Activation

Read-only, database `casescope`. No production ALTER SETTINGS.

- ClickHouse 26.7.3.19
- `enable_lightweight_update = 1` (changed=0)
- `apply_patch_parts = 1` (changed=0)
- `events`: `enable_block_number_column = 1`, `enable_block_offset_column = 1`
- `idx_search_blob_text` present
- `idx_search_ngram` present
- `idx_search_token` absent
- mutations in progress: 0
- 745,463,991 rows / 135 active parts / 25 partitions
- Phase 2.2 event insert remains `EVENT_INSERT_MODE = "sync"` with
  `async_insert=0` and `materialize_skip_indexes_on_insert=1` per events INSERT
- server default `async_insert = 1` (changed=0) unchanged

## 16. Safe Activation

Natural safe idle before restart: celery active/reserved/scheduled/queued/
unacked all 0; fence shared writers 0; no exclusive fence.

**NO BROKER MESSAGE DELETION**

Restarted `casescope-web` then `casescope-workers`. Beat not restarted:
beat does not import or execute the lightweight helper; analyst/manual-noise
upserts run in web, and workers pick up classic scan paths via the worker
restart.

## 17. Service State

| unit | before PID | before start (UTC) | after PID | after start (UTC) |
|---|---|---|---|---|
| casescope-web | 1173723 | 2026-08-22 17:23:24 | 1199751 | 2026-08-22 17:54:11 |
| casescope-workers | 1173262 | 2026-08-22 17:22:51 | 1199819 | 2026-08-22 17:54:15 |
| casescope-beat | 1048416 | 2026-08-22 14:51:38 | 1048416 | 2026-08-22 14:51:38 (unchanged) |

After: web/workers/beat active; celery empty; fence idle.

## 18. Live Production Lightweight Observation

`LIVE_PRODUCTION_LIGHTWEIGHT_UPDATE_NOT_OBSERVED`

No natural production `UPDATE events SET` in `system.query_log` after
activation. Not a blocker: the production helper was proven on deployed
ClickHouse 26.7.3.19, routing tests passed, and web/workers were restarted
onto the new code.

## 19. Product / Publication Smoke

Authenticated admin session. Case 14 `sonicwall`. No analyst/noise mutation.

- `GET /login` 200; login succeeded; UI reports **v4.26.2**
- Hunt page 200
- Grid `GET /api/hunting/events/14?search=sonicwall` 200, total 13, 13 rows
- Detail 200 for a grid `selector_key`
- Small export-view 200 `text/csv`
- Phase 1B publication authority unchanged

## 20. Regression Tests

162 passed, 0 failed, 0 skipped (required suite including
`tests/test_phase2_3_lightweight_update_bridge.py`, with
`PHASE1B_PG_TEST_DATABASE_URL` / `PHASE1B_CH_TEST_DATABASE=phase2_2a_test`).

`py_compile` on changed Python, `pyflakes` on new/changed logic (no new
findings; pre-existing unused imports in `utils/clickhouse.py` untouched),
`git diff --check` passed.

The F2 Hunt publication fixture now creates its disposable `events` table
with Gate B block-number/offset settings so the required suite can tag
through the new small-path helper. That ALTER was not applied to production.

## 21. Files Changed

Runtime: `utils/clickhouse.py`, `utils/event_analyst_state.py`,
`utils/event_noise_state.py`, `utils/evidence_audit.py`,
`utils/ingest_fence.py` (docstring only), `version.json`.

Tests: `tests/test_phase2_3_lightweight_update_bridge.py` plus existing
analyst/noise stubs, the 2.2B version-contract adjustment, and the F2
disposable schema settings.

Docs: this file and `phase2_3_lightweight_update_bridge.json`.

## 22. Version

4.26.2 (patch).

## 23. Production Mutation Audit

- NO EVIDENCE MUTATION (row count unchanged at 745,463,991)
- NO INDEX MUTATION
- NO SERVER SETTINGS MUTATION

## 24. No-Later-Phase Audit

No ERK API migration, IOC/MITRE/analyst/noise authority migration, events
immutability cutover, LEK, `events_current`, `event_observations_current`,
Phase 2.4 dedup redesign, search/index/insert-mode/generation/publication
changes, forced `OPTIMIZE FINAL`, or master-plan amendment.

## 25. Git State

Recorded after operator commit/push of this bridge.

## 26. Phase 2.3 Exit Checklist

1. Gate B preconditions remain valid — PASS
2. bounded selector lightweight helper exists — PASS
3. lightweight helper max = 1000 selectors — PASS
4. lightweight helper uses shared fail-closed admission — PASS
5. analyst small path uses lightweight — PASS
6. manual-noise small path uses lightweight — PASS
7. oversized explicit actions fall back classic — PASS
8. predicate/broad paths remain classic — PASS
9. Hayabusa remains deferred/classic — PASS
10. classic path retains exclusive fence — PASS
11. audit semantics preserved — PASS
12. forensic identity/content unchanged — PASS
13. immediate visibility proven — PASS
14. no API identity change — PASS
15. no Phase 2.4/3+ work — PASS

## 27. Phase 2.3 State

`PHASE2_3_CLOSED_PENDING_INDEPENDENT_REVIEW`

## 28. Remaining Work

Independent Phase 2.3 review.

Only after independent acceptance: Phase 2.4 — generation-aware accounting +
deterministic-batch retry exclusion.

Do not start Phase 2.4 here.

## 29. Verdict

PHASE2_3_PASS
