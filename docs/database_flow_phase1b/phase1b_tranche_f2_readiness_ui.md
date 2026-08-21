# Phase 1B Tranche F2 — PostgreSQL-Authoritative Readiness UI

Status: **NOT_READY** for F2 UI (readiness strip, Hunt coverage note, Case Files completion-banner cutover). Product-search publication gate: **CLOSED** by an interim Hunt Artifacts bridge (version 4.21.2).

F1 and the F1 fail-closed composition closure remain accepted on live main. The original F2 diagnostic on `4e32237d` recorded the Hunt Artifacts publication failure below. The closure that follows does not implement the remainder of F2 UI and does not start Phase 2, 3, or 4.

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

---

# Publication-gate closure (interim Hunt Artifacts bridge)

This section records the narrow product-publication fix. It is **not** F2 UI completion and **not** Phase 4 reader migration.

## Original failure

`GET /api/hunting/events/<case_id>` (`routes.hunting.get_hunting_events`) queried `FROM events AS e` with no join to `visible_evidence_generations` or `durable_ingest_batches`. Physical presence was treated as publication.

Observed on real PG/CH with certified managed IIS rows:

- STAGED managed rows were returned
- DURABLE BUILDING_INITIAL rows were correctly searchable before EOF
- BUILDING_REPLACEMENT rows were returned before activation
- after N → SUPERSEDED and N+1 → ACTIVE, both generations remained returned

`get_hunting_event_detail` used the same raw pattern, so a known selector could drill into unpublished rows.

## Bridge architecture

A single helper, `build_hunting_publication_bridge` in `routes/hunting_query_helpers.py`, adds LEFT JOINs onto the current ReplacingMergeTree control projections using `FINAL` (the same current-state reduction already proven by D1 `resolve_projected_visible_generation`).

The helper is applied to:

- `get_hunting_events` (Hunt Artifacts list + count)
- `get_hunting_event_detail` (selector drill-down)
- `get_raw_event_data` (Hunt Events raw companion; same selector must not bypass list/detail)

The query still reads the physical `events` table. Overlay joins, search, type/alert/noise/time filters, sort, and pagination are unchanged except that unpublished managed physical rows are excluded.

## Why this is not Phase 4 reader migration

The locked future surface for `get_hunting_events` remains `events_current` in `docs/database_flow_contracts/event_surface_consumers.json` (unchanged). This closure did not create `events_current` or `event_observations_current`, did not implement LEK, did not select canonical representatives, and did not migrate dashboard, reports, detectors, graph, RAG, or Hunt export readers.

## Exact managed visibility predicate

A row is **legacy** only when every Phase 1B protocol identity column is NULL:

`source_ref_type`, `source_ref_id`, `source_generation`, `ingest_batch_id`, `ingest_row_ordinal`, `ingest_row_hash`, `ingest_attempt_id`

A row is **published managed** only when all of the following hold:

- `source_ref_type`, `source_ref_id`, `source_generation`, and `ingest_batch_id` are present
- the current `visible_evidence_generations FINAL` row for that exact `case_id` / source / generation has `publishable = 1` and `visibility_state IN ('BUILDING_INITIAL', 'ACTIVE')`
- the current `durable_ingest_batches FINAL` row for that exact `ingest_batch_id` plus the same case/source/generation identity has `state = 'DURABLE'`

Resulting Hunt visibility:

- BUILDING_INITIAL + DURABLE batch → visible (progressive search before EOF)
- ACTIVE + DURABLE batch → visible
- STAGED → hidden
- BUILDING_REPLACEMENT → hidden
- SUPERSEDED / FAILED / INVALIDATED → hidden

No PostgreSQL visibility query and no Redis publication authority are used on the Hunt path.

## Legacy preservation

Historical and deferred rows with all protocol identity NULL remain searchable exactly as before. This bridge does not restrict Hunt to managed evidence only.

## Malformed managed fail-closed

If any protocol identity exists but the row cannot prove the complete publication relationship, it is not reinterpreted as legacy. UNKNOWN != LEGACY. The row is omitted from list, detail, and raw.

## Stale state-version handling

Control tables are ReplacingMergeTree(`state_version`). The bridge reads `... FINAL` subqueries, matching D1. After activation, inserting a lower `state_version` ACTIVE/publishable projection for old N does not resurrect N.

## ClickHouse control failure

If the control tables or required schema cannot be read, the Hunt query errors and the route returns HTTP 500. It does not fall back to unfiltered raw managed events.

## Real PostgreSQL / ClickHouse results

Proof: disposable PostgreSQL `phase1b_f2_test` and ClickHouse `phase1b_f2_test`, certified managed `IISLogParser` fixture, actual Flask Hunt blueprint.

Test: `tests/test_phase1b_tranche_f2_product_search_publication_gate.py`

| Gate | Required | Result |
|---|---|---|
| A. STAGED physical rows on ordinary Hunt search | hidden | hidden |
| B. DURABLE BUILDING_INITIAL before EOF | visible | visible |
| C. Second DURABLE batch before EOF | visible | visible |
| D. BUILDING_REPLACEMENT before activation | hidden; prior ACTIVE visible | hidden; N visible |
| E. After N SUPERSEDED / N+1 ACTIVE | N hidden; N+1 visible | N hidden; N+1 visible |
| F. Stale lower-version projection for N | N remains hidden | N remains hidden |
| G. Event detail / raw selector | unpublished 404; published 200 | unpublished 404; published 200 |
| H. Legacy-only NULL protocol identity | visible as before | visible |
| I. Mixed legacy + published + STAGED + hidden replacement | legacy + published only | legacy + published only |
| J. Partial protocol identity | fail closed | fail closed |

Hunt search text, artifact type filters, alert filters, noise filter, time filter, sort, pagination, count, event detail, and current Hunt overlays (IOC/noise/analyst columns on `events`) remain intact for the publication-safe visible set.

## Performance

Publication is a single-query filter (JOINs inside the existing count query and the existing data query). No extra Hunt SELECT round trip, no per-request PostgreSQL visibility query, no Redis.

Measured on the representative IIS fixture (8 published managed rows) in `test_publication_bridge_query_shape_and_latency`:

- Query shape before: `FROM events AS e WHERE e.case_id = {case_id:UInt32}`
- Query shape after: same `events` read plus `LEFT JOIN (SELECT ... FROM visible_evidence_generations FINAL)` and `LEFT JOIN (SELECT ... FROM durable_ingest_batches FINAL)` with the legacy-or-published predicate
- Hunt list `events` SELECT queries per request: **2** (count + data). Extra publication round trips: **0**
- Total ClickHouse queries during the Flask request: **4** (2 pre-existing `ensure_event_mitre_state_tables` `system.columns` lookups + the 2 Hunt SELECTs)
- Raw unfiltered count: 4.7 ms; raw unfiltered data: 5.0 ms
- Full product Hunt request (Flask + case lookup + mitre ensure + publication-filtered count and data): 100.5 ms
- No PostgreSQL visibility query; no Redis

## Remaining F2 UI work

The publication gate no longer blocks F2 UI. Remaining F2 work is still only:

- PostgreSQL-authoritative readiness DTO/API
- Case Files readiness strip
- F1-consistent completion/repair presentation
- non-blocking Hunt search coverage note
- final Phase 1B exit acceptance review after F2 itself passes

Hunt export-view/export-tagged, noise stats, MITRE match lists, and other non-Events-list readers were not migrated in this closure. Those remain Phase 4/5 `events_current` assignments.
