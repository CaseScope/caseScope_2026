# Phase 1B Tranche C3D1 SQLite Certification

Date: 2026-08-16
Version: 4.19.0
C3C checkpoint: `bca2c4fa358b3cc00795799ceb39db0c63185308`
Remote baseline verified: `be175072ca716f64cba7f087e5fd1d67a29f7c04`

## Scope

Tranche C3D1 evaluated only:

- `ActivitiesCacheParser`
- `BrowserSQLiteParser`

No SRUM, WebCache, Windows Search, EventTranscript, Registry, RegistryPol,
JumpList, Prefetch, LNK, Firefox JSONLZ4, MFT, PCAP, memory, derivation, graph,
reader, `events_current`, replacement generation, ACTIVE transition, C3D2, C3E,
or Tranche D work was started.

## Contract Verification

C3D1 preserves the locked Phase 1B contracts:

- Global `PHASE1B_MANIFEST_PROTOCOL_ENABLED` remains default false.
- `legacy_or_unknown` CaseFiles stay legacy.
- Only `not_started` CaseFiles may newly enter managed initial ingest.
- Existing `BUILDING_INITIAL` managed sources remain pinned to managed retry.
- Frozen parser, normalization, batching, ordering, and producer signatures are
  compared fail-closed on retry.
- Retry uses a new `ingest_attempt_id` and the same deterministic
  `ingest_batch_id`, row hashes, batch hashes, and locators.
- Existing DURABLE batches are not broad-deleted during retry.
- Generation state remains `BUILDING_INITIAL`.
- No derivations, graph cutover, readers, ACTIVE transition, replacement
  generation, protocol backfill, hash backfill, generation backfill, historical
  event update, giant rewrite, or `OPTIMIZE FINAL` was introduced.

## SQLite Source-Set Model

C3D1 uses Option A, standalone database certification.

For managed `ActivitiesCacheParser` adoption/retry, the frozen source set is the
primary `ActivitiesCache.db` bytes only. If any of these companions exists next
to the primary database, managed parsing fails closed before copying or querying:

- `ActivitiesCache.db-wal`
- `ActivitiesCache.db-shm`
- `ActivitiesCache.db-journal`

Legacy parsing preserves the prior best-effort companion copy behavior.

`-wal` and rollback `-journal` can contain transaction content capable of
changing query results. `-shm` is normally SQLite coordination/index state rather
than forensic row content, but C3D1 still rejects it in managed mode because this
tranche certifies a primary-byte-only source identity. Therefore the same
CaseFile generation cannot silently emit different row hashes because companion
content changed.

## ActivitiesCacheParser

Status: CERTIFIED as `ActivitiesCacheParser-1.2.0`.

Backend/dependency: Python stdlib `sqlite3`; deterministic SQL over a generated
valid ActivitiesCache-like SQLite schema. SQLite runtime version is not included
in the producer signature because C3D1 uses explicit `ORDER BY` over native keys
and no planner-dependent result ordering.

Schema/mode: standalone `ActivitiesCache.db` with `Activity` and optional
`ActivityOperation` query streams. Managed certification requires required query
columns to exist; schema/query errors fail closed in managed mode instead of
emitting partial managed generations.

Query sequence and ordering contract:

1. `Activity` stream:
   `SELECT Id, ... FROM Activity ORDER BY Id ASC`
2. `ActivityOperation` stream:
   `SELECT OperationOrder, ... FROM ActivityOperation ORDER BY OperationOrder ASC`

The fixed stream order is part of the ordering contract:
`activities-cache:activity-id-then-operation-order:v1`.

Native row identity and locator:

- `Activity`: native `Id`; managed mode rejects null or duplicate `Id`.
- `ActivityOperation`: native `OperationOrder`; managed mode rejects null or
  duplicate `OperationOrder`.
- Locators are authoritative parser source identifiers:
  `Activity:<Id>` and `ActivityOperation:<OperationOrder>`.

Canonical output hardening:

- `raw_json` and `extra_fields` serialize with sorted keys.
- `source_path` remains the original forensic path, never the temp copy path.
- Temporary directory changes do not affect rows, locators, row hashes, batch
  IDs, or batch hashes.
- Activity payload JSON, original payload, clipboard payload, app identifiers,
  clipboard text, timestamp conversions, fallback timestamps, search blobs, and
  extra fields were covered by the generated fixture.

Independent processes: PASS with `PYTHONHASHSEED=1`, `7`, and `random`.

Query-order adversarial proof: PASS. Equivalent valid databases with reverse
insertion/physical row layout emitted the same canonical logical sequence:
`Activity:A001..A005`, then `ActivityOperation:1..4`.

Legacy/managed parity: PASS. Legacy parse output and managed parse input rows
matched exactly, excluding manifest metadata.

Multi-batch retry: PASS at batch size 3 over 9 events, producing batch row
counts `[3, 3, 3]`. Retry used a new attempt and reproduced identical batch IDs,
row hashes, batch hashes, and locators.

Partial failure recovery: PASS. The real PG/CH integration injected a failure
after the first DURABLE batch; retry preserved the prior DURABLE batch, reused
the first batch manifest, completed remaining batches, and did not perform
CaseFile-wide cleanup.

Real PostgreSQL/ClickHouse: PASS on disposable databases. Flow exercised parser
-> generation 1 `BUILDING_INITIAL` -> attempts -> STAGED -> real CH insert ->
CH verification -> PG DURABLE -> shadow projection -> retry.

Batch source isolation: PASS. Maximum `countDistinct(case_file_id)` per
`ingest_batch_id` was `1`.

Generation state: PASS. Generation remained `BUILDING_INITIAL`.

Performance/RSS: generated 1,000-source-row fixture was 434,176 bytes, emitted
1,000 events, parsed in 0.244421 seconds, built 100 manifest batches at batch
size 10 in 0.738639 seconds, parser throughput 4,091.30 rows/sec, hash/manifest
throughput 1,353.84 rows/sec, peak RSS 76,316 KB. Final real PG/CH C3D1 test
run completed 7 tests in 12.553 seconds including setup/cleanup.

Producer signature:
`ActivitiesCacheParser-1.2.0;sqlite_companions=absent;query_contract=activities-cache:activity-id-then-operation-order:v1`.

Production activation:

- `ActivitiesCacheParser.supports_manifest_protocol = True`
- `ActivitiesCacheParser.manifest_ordering_contract =
  activities-cache:activity-id-then-operation-order:v1`

## BrowserSQLiteParser Mode Inventory

Status: NOT CERTIFIED. The class remains globally disabled for manifest ingest:

- `BrowserSQLiteParser.supports_manifest_protocol = False`
- `BrowserSQLiteParser.manifest_ordering_contract = None`

Current modes and risks:

| Mode | Detection | Query streams | Current ordering | Native ID candidate | C3D1 result |
|---|---|---|---|---|---|
| `firefox_history` | filename `places.sqlite` or `moz_places` + `moz_historyvisits` | history visits, download annotations | `visit_date DESC`, `dateAdded DESC` | `moz_historyvisits.id`, `moz_annos.id` not selected | NOT CERTIFIED |
| `firefox_cookies` | filename `cookies.sqlite` or `moz_cookies` | `moz_cookies` | none | `moz_cookies.id` likely, not selected/proven | NOT CERTIFIED |
| `firefox_forms` | filename `formhistory.sqlite` or `moz_formhistory` | `moz_formhistory` | none | `moz_formhistory.id` likely, not selected/proven | NOT CERTIFIED |
| `firefox_downloads` | filename `downloads.sqlite`; also `places.sqlite` annotations | `moz_downloads`, `moz_annos` joins | `startTime DESC`, `dateAdded DESC` | `moz_downloads.id`, `moz_annos.id` not fully proven | NOT CERTIFIED |
| `firefox_permissions` | filename `permissions.sqlite` | generic SQLite fallback | table enumeration and `SELECT *` | unresolved | NOT CERTIFIED |
| `firefox_prefs` | filename `content-prefs.sqlite` | generic SQLite fallback | table enumeration and `SELECT *` | unresolved | NOT CERTIFIED |
| `firefox_storage` | filename `webappsstore.sqlite` | generic SQLite fallback | table enumeration and `SELECT *` | unresolved | NOT CERTIFIED |
| `firefox_favicons` | filename `favicons.sqlite` | generic SQLite fallback | table enumeration and `SELECT *` | unresolved | NOT CERTIFIED |
| `firefox_origin_storage` | Firefox storage path + `data.sqlite` | generic SQLite fallback | table enumeration and `SELECT *` | unresolved | NOT CERTIFIED |
| `firefox_cache_storage` | Firefox storage path + `caches.sqlite` | generic SQLite fallback | table enumeration and `SELECT *` | unresolved | NOT CERTIFIED |
| `firefox_indexeddb` | Firefox storage `/idb/` numeric SQLite | generic SQLite fallback | table enumeration and `SELECT *` | unresolved | NOT CERTIFIED |
| `chrome_history` | filename `History` or `urls` + `visits` | history visits, downloads, URL chains | `visit_time DESC`, `start_time DESC`; URL chains ordered by `(id, chain_index)` | `visits.id`, `downloads.id` not fully used as locator | NOT CERTIFIED |
| `chrome_cookies` | filename `Cookies` or cookie columns | `cookies` | none | rowid/unique cookie key unresolved across schema variants | NOT CERTIFIED |
| `chrome_logins` | filename `Login Data` or `logins` | `logins` | none | `logins.id` likely, not selected/proven | NOT CERTIFIED |
| `chrome_webdata` | filename `Web Data` or `autofill` | `autofill` | none | schema variants unresolved | NOT CERTIFIED |
| `chrome_topsites` | filename `Top Sites` | generic SQLite fallback | table enumeration and `SELECT *` | unresolved | NOT CERTIFIED |
| `chrome_shortcuts` | filename `Shortcuts` | generic SQLite fallback | table enumeration and `SELECT *` | unresolved | NOT CERTIFIED |
| `chrome_predictor` | filename `Network Action Predictor` | generic SQLite fallback | table enumeration and `SELECT *` | unresolved | NOT CERTIFIED |
| `chrome_favicons` | filename `Favicons` | generic SQLite fallback | table enumeration and `SELECT *` | unresolved | NOT CERTIFIED |

BrowserSQLite copies `-wal`, `-shm`, and `-journal` companions in legacy mode
today. C3D1 did not add mode-aware managed activation or a frozen source-bundle
architecture. Because the manifest protocol currently checks class-level
capability, enabling the whole class would let uncertified generic and
timestamp-ordered modes enter managed ingest. BrowserSQLite therefore remains
legacy-only for every mode.

Generic SQLite fallback is explicitly not certified. It uses `sqlite_master`
table enumeration and `SELECT * ... LIMIT`, lacks stable native row locators,
and has a row cap (`MAX_GENERIC_ROWS_PER_TABLE`) that changes emitted output.

## Source Ordering Proof

`ActivitiesCacheParser` uses a canonical logical source walk, not physical row
sequence:

```text
Activity table by native Id ASC
then ActivityOperation table by native OperationOrder ASC
```

This is appropriate for relational SQLite because tables do not inherently have
a forensic physical row sequence like USN or Registry.pol. The ordering is a
versioned deterministic query contract over source-native identifiers. It does
not sort by timestamp, row hash, ERK, serialized JSON, or an invented arbitrary
field tuple.

BrowserSQLite receives no ordering contract in C3D1.

## Companion and Snapshot Proof

Managed ActivitiesCache rejects `-wal`, `-shm`, and `-journal` before copying the
database. Since managed mode consumes only the primary database, it cannot create
a mixed snapshot by copying the DB at time A and a mutable WAL/journal at time B.

Legacy ActivitiesCache and BrowserSQLite companion copy behavior is unchanged.
Legacy output may still depend on sidecars and remains outside the managed
manifest certification.

## Frozen Semantic Configuration

Frozen for certified ActivitiesCache managed generations:

- parser version: `ActivitiesCacheParser-1.2.0`
- ordering contract:
  `activities-cache:activity-id-then-operation-order:v1`
- producer version:
  `ActivitiesCacheParser-1.2.0;sqlite_companions=absent;query_contract=activities-cache:activity-id-then-operation-order:v1`
- normalization version from `Config.PHASE1B_NORMALIZATION_VERSION`
- batch size from `Config.PHASE1B_MANIFEST_BATCH_SIZE`
- companion-source policy: absent companions only

Parser version, ordering contract, producer version, normalization version, or
batch size mismatch fails closed for an existing generation.

## Tests

Passed:

- C3D1 local:
  `/opt/casescope/venv/bin/python -m unittest tests.test_phase1b_tranche_c3d1_sqlite`
  returned 7 tests OK, 2 skipped without DB env.
- C3D1 real PG/CH:
  same module against disposable PG/CH returned 7 tests OK.
- C3C checkpoint real PG/CH:
  C3D1 plus C3C modules returned 12 tests OK.
- A/B/C1/C2/C3A/C3B/C3C/C3D1 real PG/CH regression slice:
  88 tests OK.
- Retry/task failure/ingest fence:
  49 tests OK.
- ClickHouse delete/dedup:
  35 tests OK standalone. Combined with unrelated failure tests can still hit
  pre-existing Celery test-stub import interference.
- Graph:
  170 tests OK, 1 skipped.
- Privacy/completion:
  83 tests OK.
- Parser hardening/browser/ActivitiesCache:
  focused slice 7 tests OK.
- `py_compile`, `pyflakes`, and `git diff --check` passed for changed C3D1 files.

Known unrelated failure:

- `test_diagnostic_log_parser_emits_clean_windows_etl_metadata` still expects
  `metadata_only` and observes `parse_error`. This was already documented before
  C3D1 and was not modified here.

## No-Cutover Audit

Expected and preserved:

- global flag OFF
- derivations NO
- graph NO
- readers NO
- ACTIVE NO

## Remaining C3 Work

C3D2: SRUM, WebCache, Windows Search, EventTranscript, and other ESE or
database-backed readers.

C3E: cleanup certification for Prefetch, LNK, Firefox JSONLZ4, MFT, Registry,
JumpList, BrowserSQLite modes, and any other remaining uncertified parser when
suitable fixtures/contracts exist.

## Verdict

At least one production parser in C3D1 certified under the managed manifest
protocol: `ActivitiesCacheParser`.

PHASE1B_TRANCHE_C3D1_PASS
