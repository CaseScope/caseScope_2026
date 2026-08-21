# Phase 1B Tranche F2 — PostgreSQL-Authoritative Readiness UI

Status: **NOT_READY**. F2 did not implement the 1B.5 readiness strip, Hunt Artifacts coverage note, or Case Files completion-banner cutover.

F1 and the F1 fail-closed composition closure remain accepted on live main (`0c1e2173`, version 4.21.1). F2 stopped at the locked product-search publication gate.

This is a Phase 1B exit blocker for independent review. It is not permission to start Phase 2 or Phase 4 in this tranche.

## Actual product publication gate result

Product path exercised:

`GET /api/hunting/events/<case_id>` → `routes.hunting.get_hunting_events`

UI caller:

`static/templates/case_hunting.html` (`fetch('/api/hunting/events/' + caseId + ...)`)

The same raw-table pattern is used by `get_hunting_event_detail`.

The route queries:

```text
FROM events AS e
WHERE e.case_id = {case_id:UInt32}
```

There is no join to `visible_evidence_generations` or `durable_ingest_batches`. Overlay joins are empty strings. Physical presence in `events` is what Hunt Artifacts returns.

Proof used disposable real PostgreSQL `phase1b_f2_test` and real ClickHouse `phase1b_f2_test`, certified managed `IISLogParser` fixture rows, `insert_managed_batch` into `events`, and the Flask hunting blueprint with a logged-in analyst.

Test:

`tests/test_phase1b_tranche_f2_product_search_publication_gate.py`

| Gate | Required | Observed |
|---|---|---|
| A. STAGED physical rows visible on ordinary Hunt Artifacts search | NO | **YES** — 4 STAGED IIS blobs returned; `total=4` |
| B. DURABLE BUILDING_INITIAL searchable before EOF | YES | **YES** — same 4 blobs returned while `completed_at` is null |
| C. BUILDING_REPLACEMENT visible before activation | NO | **YES** — `repl-0`..`repl-7` returned; N still visible; `total=16` |
| D. After N SUPERSEDED / N+1 ACTIVE, search follows current generation only | YES | **NO** — stale N blobs still returned together with N+1; `total=16` |

Control-plane projections were populated (`project_generation_control_state` / `project_generation_authority_swap`). The D1 resolver `resolve_projected_visible_generation` is not the Hunt Artifacts path and was not treated as passing this gate.

F2 did not implement `event_observations_current`, `events_current`, LEK reader cutover, or a product-reader migration to satisfy the gate.

## UI / API state before F2

No readiness strip, no Hunt Artifacts ingest-coverage note, no PostgreSQL readiness endpoint.

Case Files:

- `GET /api/files/stats/<case_uuid>` derives `completion.stalled` / `repair_available` from Redis `get_progress` plus latest ingest / known-user/system counts.
- `GET /api/files/progress/<case_uuid>` is Redis file/phase progress.
- `POST /api/files/repair-completion/<case_uuid>` clears the Redis completion trigger, sets Redis `waiting_for_completion`, and queues `case_indexing_complete_task`.
- `static/templates/case_files.html` banners “Resume Completion” from that Redis/latest-ingest model.

Hunt Artifacts Events tab loads `/api/hunting/events/<case_id>` with no publication coverage note. Search controls are not gated on ingest completion.

F1 already exposes an internal PG readiness fragment (`build_case_reconciliation_readiness` / `build_phase1b_ingest_summary`). It is not consumed by Case Files or Hunt Artifacts UI.

## Readiness DTO / API

Not implemented. The publication gate failed, so no cosmetic 1B.5 DTO was added over incorrect product search semantics.

## PostgreSQL authority

Unchanged from F1. Redis does not determine durable F1 reconciliation. F2 did not add a user-facing readiness API.

Can Redis determine durable readiness in a new F2 API? Not implemented. Existing Case Files completion banner still uses Redis.

## Redis live activity decoration

Not implemented.

## Four readiness dimensions

Not implemented. Locked intended dimensions remain Evidence, Privacy, Reconciliation, Live Activity.

## BUILDING_INITIAL

Protocol (D1/F1) still publishes DURABLE BUILDING_INITIAL batches into ClickHouse `events` and control projections. Ordinary Hunt Artifacts search also returns unpublished STAGED rows in that same table, so a coverage note would be untruthful if it claimed “results cover currently published evidence.”

Unknown-denominator percent UI was not added.

## ACTIVE

ACTIVE remains generation lifecycle authority in PostgreSQL. Hunt Artifacts does not filter to the ACTIVE generation.

## BUILDING_REPLACEMENT

Replacement rows physically coexist and are returned by ordinary Hunt Artifacts search before activation (`total=16` with N and N+1). Hidden-replacement current-search behavior is not true on this product path.

## Replacement activation

PostgreSQL activation works (N `SUPERSEDED`, N+1 `ACTIVE`). The next Hunt Artifacts read still returns both generations. There is no product-path authority cutover.

## Privacy presentation

Not implemented. E2 freeze-then-verify was not changed. No UI readiness DTO exists that could authorize AI egress.

## Legacy / mixed behavior

Not implemented. No new mixed-percentage UI.

## Case Files completion / repair

Unchanged. Managed/mixed still depend on F1 inside `case_indexing_complete_task` after the Redis repair button queues that task. The banner itself remains Redis/latest-ingest. Unknown composition fail-closed behavior is the accepted F1 closure, not an F2 UI change.

## Hunt Artifacts coverage note

Not implemented. Adding a non-blocking “results may expand” note over a path that already shows STAGED and replacement rows would be cosmetic coverage of incorrect publication.

## Redis failure

Not implemented for a new readiness API. F1 Redis-loss proofs remain the accepted completion authority story.

## PostgreSQL failure

Not implemented for a new readiness API. F1 fail-closed composition remains accepted.

## Real PostgreSQL / ClickHouse

Gate proof used disposable real PG and CH (`phase1b_f2_test`). No F2 UI DTO was tested because it was not built.

## Performance

Not measured. No readiness endpoint was added. Hunt Artifacts search still issues ClickHouse `events` queries; that is the existing product path, not an F2 poller.

## Accessibility

No F2 UI was added.

## Final Phase 1B implementation assessment

| Requirement | Implementation status after this F2 attempt |
|---|---|
| 1B.1 manifest + watermarks + control projections | Present from A–E1. Control projections exist. Product Hunt Artifacts does not use them. |
| 1B.2 batch publication; BUILDING_INITIAL progressive; replacement hidden | Protocol/projections present from D1. Product Hunt Artifacts does not hide STAGED or BUILDING_REPLACEMENT. |
| 1B.3 AI freeze-then-verify | Present from E2 + E2 closure. |
| 1B.4 completion = reconciliation | Present from F1 + F1 closure. |
| 1B.5 PG readiness UI; Redis decoration; non-blocking search coverage note | **Not implemented.** Blocked by the product publication gate. |

Satisfying the Hunt Artifacts gate requires a product-reader publication filter over the 1B.1 control projections, or the later named surfaces `event_observations_current` / `events_current`. F2 must not silently pull that Phase 4 reader architecture.

## No-later-phase audit

- Phase 2 ClickHouse modernization: **NO**
- Phase 3 ERK API migration: **NO**
- `event_observations_current`: **NO**
- `events_current`: **NO**
- LEK reader cutover: **NO**
- product-reader migration: **NO**
- Phase 5 overlays: **NO**
- Phase 6 derived-evidence migration: **NO**
- Qdrant lifecycle migration: **NO**
- MEMORY_JOB / PCAP managed generation protocol: **NO**

Parser certification was not altered. Certified managed inventory remains 84 / 12 / 72 / 0.
