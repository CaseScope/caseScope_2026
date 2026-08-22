# Phase 2.1C Live Activation

The reviewed 4.25.1 Hunt reader is now the running production web path.
Stored `search_blob` is unchanged. Bloom indexes remain. No later Phase 2.x / 3+
work.

Measurement artifact: `docs/database_flow_phase2/phase2_1c_live_activation.json`.

## Starting state

- origin/main and HEAD: `c5a1926a2aafa7046c7e4f6753f7fdb57cf53c1f`
- Commit: Narrow Hunt TOKEN_SAFE to ASCII alphanumeric atoms so non-ASCII free-text stays on existing ILIKE rather than the unproven Unicode token path
- Commit time: 2026-08-22 02:34:47 UTC
- Version: 4.25.1 (unchanged; documentation-only activation evidence)
- Python: `/opt/casescope/venv/bin/python`
- Deployed ClickHouse: `26.7.3.19`

Working tree was clean. HEAD == origin/main.

## Locked scope

Done:

- pre-activation active-part coverage detector on production `events`
- controlled `casescope-web` restart only
- live authenticated Hunt grid / count / pagination / detail / small export
- product `query_log` SQL-path proof
- focused F2 publication tests on disposable `phase2_1c_test`
- required regression suite

Not done: bloom drop, production `command_line` text index, other
`search_blob` consumer migrations, pagination redesign, Phase 2.2–2.4,
Phase 3+.

## Pre-activation text-index coverage

PASS. Active-part coverage detector (`scripts/phase2_1_materialize_search_index.py --status`):

- `idx_search_blob_text` PRESENT
- expr: `search_blob`
- type: `text(tokenizer = 'splitByNonAlpha', preprocessor = lower(search_blob))`
- coverage: MATERIALIZED 25 / PARTIAL 0 / UNMATERIALIZED 0 / UNKNOWN 0
- parts: 135/135 MATERIALIZED
- rows: 745,463,991 / 25 partitions / 135 active parts
- blooms: `idx_search_ngram` PRESENT, `idx_search_token` PRESENT
- in-progress mutations: 0
- failed text-index mutations: 0
- `materialize_skip_indexes_on_insert = 1` (unchanged)
- `query_plan_direct_read_from_text_index = 1`

Helper contract reconfirmed before restart: ASCII ordinary →
`hasAllTokens(search_blob,…)`; ASCII compact OR → `hasAnyTokens`; Unicode /
quoted / punctuation / IP → `search_blob ILIKE`; negative →
`NOT search_blob ilike`; numeric bare term → `event_id =`; mapped fields
unchanged; Phase 1B publication bridge unchanged.

## Fresh active-part coverage

No events were ingested after the original full materialization.

- row count still 745,463,991
- active parts still 135
- newest `system.parts.modification_time` 2026-08-21 20:58:00 UTC, inside the
  2.1B materialize window (case 32 mutation 20:43:11 UTC, parts settled
  20:57:54–20:58:00 UTC)

No post-materialization parts existed, so there was no unindexed new-part
stop. Future inserts remain on the accepted setting
`materialize_skip_indexes_on_insert=1`. This tranche did not set that to 0
and did not insert production events solely to prove coverage.

## Web service activation

Recorded before restart:

- unit: `casescope-web`
- MainPID: 279132
- ExecMainStartTimestamp: Fri 2026-08-21 21:29:57 UTC
- that start is before commit `c5a1926` (2026-08-22 02:34:47 UTC)
- login HTTP 200; unauthenticated Hunt API 302 to `/login`

Controlled restart:

`sudo -n /usr/bin/systemctl restart casescope-web`

After:

- ActiveState: active / running
- MainPID: 479860 (new)
- ExecMainStartTimestamp: Sat 2026-08-22 02:42:23 UTC (after `c5a1926`)
- gunicorn listening `https://0.0.0.0:443`
- no startup exception, no migration/schema exception, no ClickHouse index
  exception
- workers not restarted (MainPID 251661 since Fri 2026-08-21 20:52:30 UTC)

## Running version

Authenticated dashboard and Hunt UI render `v4.25.1`.

## Authenticated Hunt smoke

Existing production admin login via the service env account. No new user was
created. Credentials are not recorded here.

- `GET /login` 200 then POST login succeeded
- `GET /case/hunting` 200 after selecting case 14
- Hunt grid API is the product path: `GET /api/hunting/events/<case_id>`

Case 14 `sonicwall`: HTTP 200, total 13, 13 rows rendered, event-detail
navigation HTTP 200 from a grid `selector_key`.

## TOKEN_SAFE live product SQL

`system.query_log` for the product request (2026-08-22 02:44:15 UTC):

- count and grid both contain `hasAllTokens(search_blob, 'sonicwall')`
- do **not** contain `search_blob ILIKE '%sonicwall%'`
- both include the Phase 1B publication bridge
  (`visible_evidence_generations` / `durable_ingest_batches` / legacy NULL
  identity)

`EXPLAIN indexes = 1` still resolves through:

- Skip `Name: idx_search_blob_text`
- Prewhere `__text_index_idx_search_blob_text_hasAllTokens_*`

No `hasAllTokens(lower(search_blob))` scan.

## Large-case bounded search

First page only (`per_page=50`). Product SQL is
`hasAllTokens(search_blob, 'powershell')` plus the publication bridge and the
existing `show_noise=false` filter. No HTTP timeout.

| Case | HTTP total | HTTP ms | CH count ms | CH page ms |
|---|---:|---:|---:|---:|
| 10 | 17311 | 775.8 | 62 | 690 |
| 7 | 518829 | 27166.1 | 525 | 26622 |
| 32 | 940117 | 37088.6 | 819 | 36245 |

Product totals are below the isolated 2.1C token counts on cases 10 and 7
because the live Hunt path keeps `noise_matched = false`. Isolated
`hasAllTokens` on case 10 is still 19455; case 32 live total equals the
isolated token count (940117). This is existing noise filtering, not a
token-vs-ILIKE split.

## Substring live product SQL

Product `query_log`:

- `cmd.exe` → `search_blob ILIKE '%cmd.exe%'`, no `hasAllTokens` (case 10,
  total 993 with noise hidden)
- `10.0.0.1` → `search_blob ILIKE '%10.0.0.1%'`, no `hasAllTokens`
  (case 10 had 0 matches; case 7 first page total 3162, HTTP 200)
- `"Windows PowerShell"` → `search_blob ILIKE '%Windows PowerShell%'`, no
  `hasAllTokens` (case 10 total 11641)

## Unicode live product SQL

Zero matches, compiler-path proof:

- `münchen` → `search_blob ILIKE '%münchen%'`
- `用户` → `search_blob ILIKE '%用户%'`

No `hasAllTokens` / `hasAnyTokens` for those atoms.

## Structured search

- `4688` on case 10: product SQL `event_id = '4688'`, not `hasAllTokens`.
  Zero matches (case 10 has no 4688 rows; top IDs are empty / Sysmon 1,3,4 /
  4799).
- mapped `eventid:4688`: same `event_id = '4688'`.
- mapped fixture with matches: `eventid:1` total 13610; `eventid:4799`
  total 14214; both `event_id = '…'`, no token predicate.

## Exclusion search

Case 14 `-powershell`: product SQL
`NOT (search_blob ILIKE '%powershell%')`. Not `NOT hasAllTokens`. Total 1341
(the whole case; no powershell hits to exclude).

## Grid / count consistency

TOKEN_SAFE count and grid queries in `query_log` share the same semantic
clause, including `hasAllTokens(search_blob, …)`, publication, and noise
filter. Case 14 sonicwall count 13 equals returned grid rows.

## Pagination observation

`PRE_EXISTING_PAGINATION_ORDERING_DEFECT`.

This activation requested case 10 `powershell` pages 1 and 2 (`per_page=50`).
Totals matched (17311). Overlap on this pair was 0. The 2.1C measurement of
5 overlapping keys from timestamp ties under OFFSET remains the accepted
classification. Ordering was not changed. Overlap was not treated as a
token-predicate failure.

## Small export proof

Case 14 `sonicwall` actual export path
`GET /api/hunting/events/export-view/14`:

- HTTP 200, CSV, 13 data rows
- export count == grid count (13)
- product SQL `hasAllTokens(search_blob, 'sonicwall')`
- no token-vs-ILIKE split
- export still omits the publication join (pre-existing `export_view_events`
  shape). On this fixture every row is legacy NULL protocol identity, so
  counts match. Not broadened or fixed here.

Did not export case 7/32 powershell result sets.

## Publication bridge proof

Live Hunt grid/count/detail SQL contains the accepted Phase 1B bridge.
Publication state in production was not altered for this smoke.

Disposable F2 re-run against `phase2_1c_test` with current 4.25.1 code,
TOKEN_SAFE term `alpha`:

`8 passed` in `tests/test_phase1b_tranche_f2_product_search_publication_gate.py`.

STAGED managed rows hidden; first DURABLE BUILDING_INITIAL searchable;
replacement hidden until activation; legacy rows visible; malformed protocol
identity hidden.

## Web / ClickHouse error review

`journalctl -u casescope-web` since the activation restart: no Traceback, no
500, no UNKNOWN_FUNCTION, no ClickHouse index/query exception, no
hasAllTokens/hasAnyTokens compiler failure.

`journalctl -u clickhouse-server` in the same window: no matching Error /
Exception / UNKNOWN_FUNCTION lines.

`query_log` product Hunt queries in the smoke window: type QueryFinish,
empty exception.

Unrelated pre-existing SSL `certificate unknown` client warnings exist in
older journal history; none after this restart in the activation window.

## Regression

Required suite after activation, with disposable F2 env pointed at
`phase2_1c_test` (not production `casescope`):

97 passed, 0 skipped.

Includes `tests/test_phase2_1c_hunt_token_cutover.py` and the F2 product
publication gate.

## Bloom index state

Must remain, and does:

- `idx_search_ngram` PRESENT
- `idx_search_token` PRESENT

No DROP INDEX.

## No later phase

No bloom drop, no command_line index, no other `search_blob` consumer
migration, no Phase 2.2 insert-mode change, no 2.3 UPDATE caller, no 2.4
dedup, no Phase 3 ERK API, no LEK, no `events_current` /
`event_observations_current`. Product code was not changed.

## Remaining work

Independent review of this live activation.

Do not drop bloom indexes automatically.

Then and only then:

Phase 2.1D — bloom-index retirement / final Phase 2.1 exit.

## Export publication closure (4.25.2)

The original live activation above discovered
`publication_join=false` on `GET /api/hunting/events/export-view/<case_id>`.
That historical fact is retained. This closure gates Hunt event CSV export
with the accepted Phase 1B publication bridge. The 4.25.1 TOKEN_SAFE reader
is unchanged.

### Discovered bypass

`export_view_events` and `export_tagged_events` read `events AS e` with
overlay filters and did not apply `build_hunting_publication_bridge(alias="e")`
`join_sql` / `where_sql`. Grid/detail/raw hid unpublished managed rows;
CSV export could still emit them.

### Baseline reproduction (disposable `phase2_1c_test`)

STAGED managed batch physically present. Hunt grid/detail/raw hidden.
Export-view returned the unpublished rows.

- selector_key: `ts:2026-01-01 00:00:01|host:unknown|artifact:iis|event:|file:u_ex260101.log`
- evidence_record_key: `erk:v2:bb82e8840f92753dd0ad7317f1bde1019515e012826e8fedcf55150c57d68d1c`
- search_blob: `GET /path/1?id=1&q=alpha 192.0.2.2 user1 Agent1 200`
- export-view also returned the other three STAGED siblings in that batch

BUILDING_REPLACEMENT was not separately exported on the unmodified baseline
because the lifecycle assertion stopped at the STAGED leak. The same missing
join is the cause for both routes.

### Fix

Both Hunt event CSV export routes now reuse the accepted helper, matching
`get_hunting_events`:

- `publication = build_hunting_publication_bridge(alias="e")`
- inject `publication["join_sql"]` and `publication["where_sql"]`

`export_view_events` still uses `build_hunting_search_clause()`. Classifier
untouched.

### Hunt event CSV export inventory

| route | physical events reader? | publication bridge? | action |
|---|---|---|---|
| `GET /api/hunting/events/export-view/<case_id>` | YES | YES | gated in this closure |
| `GET /api/hunting/events/export-tagged/<case_id>` | YES | YES | gated in this closure |

No other Hunt event CSV export of physical `events` rows exists in
`routes/hunting.py`. Browser downloads, process children, MITRE/noise stats,
graph, chat, Sigma, and IOC internals were not changed.

### F2 lifecycle (export-view)

Matches grid publication:

- A legacy physical: export visible
- B managed STAGED: export hidden
- C first DURABLE BUILDING_INITIAL: export visible before EOF
- D subsequent DURABLE BUILDING_INITIAL: export visible
- E BUILDING_REPLACEMENT physical/DURABLE before activation: export hidden
- F old ACTIVE while replacement builds: old export remains visible
- G atomic activation: replacement export-visible; superseded not authoritative
- H malformed partial protocol identity: export hidden
- I stale control projection cannot resurrect hidden evidence

### F2 lifecycle (export-tagged)

Analyst tags applied through `POST /api/hunting/event/tag/<case_id>`. A tag
does not override publication:

- legacy tagged: visible
- managed STAGED tagged: HIDDEN
- DURABLE + publishable tagged: visible
- hidden BUILDING_REPLACEMENT tagged: HIDDEN
- activated replacement tagged: visible
- malformed partial identity tagged: HIDDEN

### Grid / export parity

On a bounded mixed fixture, export-view selectors/ERKs equal the complete
grid set for identical filters. No export-only unpublished selectors.

`SELECT e.*` omits MATERIALIZED `selector_key`; tests identify CSV rows by
`evidence_record_key` / `search_blob` / reconstructed selector. ERK can
coincide across generations; unpublished identity is the selector/blob/event_id.

### Fail-closed

Dropping `durable_ingest_batches` makes export-view and export-tagged fail
closed (not HTTP 200 CSV of all physical events), same as the Hunt grid.

### Live activation of this fix

- pre-restart text index: `idx_search_blob_text` PRESENT; MATERIALIZED 25 /
  PARTIAL 0 / UNMATERIALIZED 0 / UNKNOWN 0; 135/135 active parts;
  blooms `idx_search_ngram` PRESENT, `idx_search_token` PRESENT; 0 in-progress
  mutations; 0 failed text-index mutations. No rematerialization.
- casescope-web restarted only. Before MainPID 479860 (2026-08-22 02:42:23 UTC).
  After MainPID 501361 (2026-08-22 03:11:45 UTC), active/running,
  listening `https://0.0.0.0:443`, version v4.25.2, no startup exception.
  Workers unchanged (MainPID 251661 since 2026-08-21 20:52:30 UTC).

### Live export-view

Case 14 `sonicwall`: grid 13, export-view 13. Product `query_log`
(2026-08-22 03:12:44 UTC, 13 result rows, QueryFinish):

- `hasAllTokens(search_blob, 'sonicwall')`
- no `search_blob ILIKE '%sonicwall%'`
- `visible_evidence_generations FINAL` / `durable_ingest_batches FINAL`
- accepted publication condition including legacy-NULL identity

### Live tagged-export

Case 10 already had 2 analyst-tagged retained events. Export-tagged HTTP 200,
2 CSV rows. Product `query_log` includes the publication bridge and
`e.analyst_tagged = true`. Tags were not modified to manufacture the fixture.

### Regression

Required suite with disposable F2 env `phase2_1c_test`: 100 passed.
`py_compile`, `pyflakes`, `git diff --check` on changed Python.

### No later phase

No bloom drop, no command_line index, no rematerialization, no search grammar
redesign, no pagination redesign, no Phase 2.2–2.4, no Phase 3/4, no LEK, no
`events_current` / `event_observations_current`.
