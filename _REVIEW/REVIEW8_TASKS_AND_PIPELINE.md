# Review 8 — Tasks, Pipelines, and Orchestration

Date: 2026-04-20

## Scope
Review the live async/task and orchestration surface in `tasks/*.py`, `pipeline/*.py`, and `utils/case_analyzer.py` for idempotency, retry semantics, dead-letter behavior, pipeline/export contract alignment, long-running progress and cancellation, storage-write boundaries, and whether `utils/case_analyzer.py` is truly orchestration-only.

## Review Outcome
- `pipeline/__init__.py` export names and the live pipeline helper signatures currently used by `utils/case_analyzer.py` do match. Review 8 did not find a concrete stage-interface mismatch between the exported pipeline helpers and the case-analysis call sites.
- Review 8 did find multiple runtime-semantics defects on the async side: the long-running case-analysis Celery task explicitly opts out of late acknowledgment / worker-loss redelivery, many background tasks report operational failure only through returned payloads instead of true Celery failure state, and case-ingest completion can proceed after the retry budget even while files are still pending.
- Review 8 directly re-verified `DRIFT-CASE-ANALYZER-FINALIZE`: `utils/case_analyzer.py` is thinner than before, but it still owns terminal persistence, summary shaping, progress DB writes, and unified-findings mirroring. The orchestration-only claim is therefore still only partially true.
- Review 8 landed two narrow in-scope fixes in `utils/case_analyzer.py`: per-pattern failures now degrade the final case-analysis run instead of only logging warnings, and IOC timeline failures now record an explicit failed phase outcome so the final `PARTIAL`/`degraded_reasons` contract matches the live run behavior.

## Findings
### 1. `RISK` / `HIGH`
- Location: `tasks/rag_tasks.py:184`
- Summary: the 24-hour `run_case_analysis` task explicitly overrides the app-wide safe-delivery defaults with `acks_late=False`, `reject_on_worker_lost=False`, and `max_retries=0`. A worker loss after task start can therefore drop a case-analysis run without redelivery.
- Proposed fix: keep the current `analysis_id`-based orchestration but align the task with at-least-once worker semantics (`acks_late=True`, `reject_on_worker_lost=True`) once the remaining idempotency edges on final persistence are tightened. Rough effort: M.

### 2. `CORRECTNESS` / `HIGH`
- Location: `tasks/celery_tasks.py:1854`, `tasks/celery_tasks.py:2085`, `tasks/memory_tasks.py:336`, `tasks/pcap_tasks.py:468`, `tasks/archive_tasks.py:529`
- Summary: several long-running/background tasks persist local failure state and return `{'success': False, ...}` instead of raising. Celery therefore records a `SUCCESS` result for operationally failed work, which suppresses retry, dead-letter, and failure-monitoring semantics unless every caller inspects the payload body.
- Proposed fix: standardize task-failure behavior so durable status updates happen first, then the task raises (or retries) rather than returning a soft-failure payload as the terminal Celery result. Rough effort: M/L.

### 3. `CORRECTNESS` / `HIGH`
- Location: `tasks/celery_tasks.py:1217`
- Summary: `case_indexing_complete_task` defers while files remain in `new` / `queued` / `ingesting`, but once the retry budget is exhausted it logs a warning and proceeds anyway. Deduplication, discovery, summary generation, and completion bookkeeping can therefore run against an incomplete ingest set.
- Proposed fix: fail closed once the retry budget is exhausted, or persist a durable "completion generation" barrier that proves the ingest set is stable before downstream cleanup/finalization runs. Rough effort: M.

### 4. `CORRECTNESS` / `MEDIUM`
- Location: `tasks/celery_tasks.py:843`
- Summary: `delete_case_events_task` returns `success: true` immediately after issuing `ALTER TABLE ... DELETE`, even though the code itself notes that the ClickHouse mutation is asynchronous. Callers can therefore observe a completed task before the underlying event rows are actually gone.
- Proposed fix: expose the mutation as asynchronous work all the way through the status contract, or wait/poll for mutation completion before returning terminal success. Rough effort: M.

### 5. `CORRECTNESS` / `HIGH`
- Location: `utils/case_analyzer.py:663`
- Summary: before this Review's patch, per-pattern failures from `run_case_pattern_loop(...)` only reached a warning callback. The analysis could still finalize as `COMPLETE` with no degraded reason even when one or more patterns failed mid-loop.
- Proposed fix: landed in this Review by capturing per-pattern warning callbacks, recording an explicit `pattern_analysis` phase outcome, and degrading the final run status when any per-pattern failure occurs. Rough effort: S. Commit: local Review 8 checkpoint.

### 6. `CORRECTNESS` / `MEDIUM`
- Location: `utils/case_analyzer.py:747`
- Summary: before this Review's patch, `_run_ioc_timeline()` swallowed timeline exceptions into `{}` plus a progress message, but did not record a failed phase outcome. The final run summary could therefore omit a real IOC timeline failure from `degraded_reasons`.
- Proposed fix: landed in this Review by recording both successful and failed `ioc_timeline` outcomes so the final `PARTIAL`/`COMPLETE` status tracks the actual stage result. Rough effort: S. Commit: local Review 8 checkpoint.

### 7. `DRIFT` / `MEDIUM`
- Location: `utils/case_analyzer.py:91`, `utils/case_analyzer.py:950`
- Summary: `utils/case_analyzer.py` is not orchestration-only yet. It still owns `CaseAnalysisRun` lifecycle writes, progress DB commits, JSON-safe summary shaping, degraded-status synthesis, and unified-findings mirroring during `_finalize_analysis(...)`.
- Proposed fix: keep the Review 8 bookkeeping fix that landed here, but move terminal persistence / summary / sync responsibilities behind one narrower persistence boundary in a later cross-cutting pass rather than guessing at a larger refactor inside Review 8. Rough effort: M/L.

### 8. `GAP` / `MEDIUM`
- Location: `tasks/rag_tasks.py:184`, `tasks/memory_tasks.py:190`, `tasks/archive_tasks.py:308`, `pipeline/pattern_analysis.py:422`, `utils/case_analyzer.py`
- Summary: the long-running task/pipeline surface exposes progress updates, but there is no cooperative cancellation contract. Review 8 did not find revoke/abort polling inside the long-running loops; cancellation behavior therefore depends on process-level interruption or Celery time limits rather than stage-aware stop points.
- Proposed fix: define one shared cancellation contract for long-running case/memory/archive tasks and thread it into the heavy loops before changing delivery semantics. Rough effort: M/L.

## Code Changes Landed During Review 8
- `utils/case_analyzer.py`
  - records explicit `pattern_analysis` phase outcomes, including per-pattern failure counts, so the final run status degrades when the pattern loop only partially succeeds
  - records explicit `ioc_timeline` phase outcomes on both success and failure so timeline errors participate in the existing degraded-summary contract
- `tests/test_case_analysis_pipeline.py`
  - added coverage for the new `pattern_analysis` / `ioc_timeline` degraded-phase bookkeeping contract
- `tests/test_phase7_pattern_case_tail_stage.py`
  - updated the shared-tail helper contract assertion to allow post-helper bookkeeping before returning the completed result

## Verification Run
- `venv/bin/python -m unittest tests.test_case_analysis_pipeline tests.test_phase7_pattern_case_loop_stage tests.test_phase7_pattern_case_tail_stage`
- Result: `OK` (8 tests)

## Review 8 Hand-off
- Review 8 is complete.
- Remaining issues that survive direct verification but were not fixed here are mostly operational/cross-cutting rather than local helper-boundary drift:
  - task failure-state / retry / dead-letter semantics across the async surface
  - lack of cooperative cancellation for long-running case, memory, archive, and PCAP flows
  - `utils/case_analyzer.py` still owning terminal persistence / summary / unified-findings sync despite the thinner pipeline decomposition
- Review 9 can proceed on its own scope. The unresolved Review 8 items above are better treated as later cross-cutting cleanup/backlog work than as enrichment/TI blockers.
