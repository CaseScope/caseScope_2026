# Phase 1B Tranche C3D2B Windows Search / EventTranscript Certification

Date: 2026-08-16
Version: 4.19.0
C3D1 checkpoint: `8f217d7ebb8f9b2ed6173e58b23debc7c0cb01d5`
C3D2A deferred-doc checkpoint: `8e1abfb52c1bd87ef34662ac105ad81fa559440b`
Remote baseline verified: `be175072ca716f64cba7f087e5fd1d67a29f7c04`

## Scope

Tranche C3D2B evaluated only the registered production implementations for:

- `WindowsSearchDbParser`
- `EventTranscriptDbParser`

No SRUM, WebCache, BrowserSQLite, ActivitiesCache, Registry, JumpList, MFT,
Prefetch, LNK, Firefox JSONLZ4, PCAP, memory, derivation, graph, reader,
`events_current`, replacement generation, ACTIVE transition, C3E, or Tranche D
work was started.

## Contract Verification

C3D2B preserves the locked Phase 1B contracts:

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

## Candidate Inventory

| Parser | Registered artifact type | Version before C3D2B | Backend | Source format | C3D2B status |
|---|---|---:|---|---|---|
| `WindowsSearchDbParser` | `windows_search_db` | `WindowsSearchDbParser-1.0.0` | Python stdlib `sqlite3` summary probe | `.db` file under `Microsoft/Search/Data/Applications/Windows/` | NOT CERTIFIED |
| `EventTranscriptDbParser` | `eventtranscript` | `EventTranscriptDbParser-1.0.0` | Python stdlib `sqlite3` | `EventTranscript.db` SQLite database | CERTIFIED as `EventTranscriptDbParser-1.1.0` |

## WindowsSearchDbParser

Status: NOT CERTIFIED.

Current production behavior:

- Registered as artifact type `windows_search_db`.
- Registered patterns/extensions: extension `.db`, path contains
  `/Microsoft/Search/Data/Applications/Windows/` or the Windows backslash form.
- Opens the primary file with Python stdlib `sqlite3`.
- No external binary, helper tool, or producer process is invoked.
- Executes `SELECT name FROM sqlite_master WHERE type='table'` with no explicit
  `ORDER BY`.
- For each discovered non-`sqlite_` table, executes `SELECT COUNT(*) FROM [table]`.
- Emits one database-summary `ParsedEvent`, not one event per search item or row.
- `raw_json` contains filename, file size, and table summaries; it is not
  serialized with sorted keys.
- `search_blob` is filename/path plus table names in the current discovery order.
- Timestamp uses `fallback_timestamp(file_path=...)`, which can depend on file
  mtime or current time.
- No authoritative native item/document identity is emitted.
- No deterministic source locator is emitted.
- Malformed or unsupported SQLite databases produce a warning and still emit a
  one-event summary with an empty table list.

The live implementation does not parse Windows Search item/document records,
does not prove a Windows Search database version, and does not expose a native
record walk. It cannot satisfy the C3D2B multi-batch certification gate because
the current parser emits one summary event per database. C3D2B therefore leaves:

- `WindowsSearchDbParser.supports_manifest_protocol = False`
- `WindowsSearchDbParser.manifest_ordering_contract = None`

Exact blockers:

- No safe non-production Windows Search source corpus was found in the repository,
  `/opt/casescope-benchmark`, installed package data, `/home/jdube`, `/opt/local`,
  or `/opt/ntfs_parse`.
- Current output order depends on implicit SQLite table enumeration.
- Current output has no source-native item/document locator.
- Current timestamp fallback uses mutable file metadata/runtime state.
- The parser emits only one event, so no truthful multi-batch proof exists.

## EventTranscriptDbParser

Status: CERTIFIED as `EventTranscriptDbParser-1.1.0`.

Backend/dependency: Python stdlib `sqlite3`. No external executable, profile,
configuration file, or producer process is used.

Registered artifact type and filename: `eventtranscript`, extension `.db`, filename
pattern `eventtranscript.db`.

Source-set policy:

- Managed certification is primary `EventTranscript.db` bytes only.
- If `EventTranscript.db-wal`, `EventTranscript.db-shm`, or
  `EventTranscript.db-journal` exists next to the primary database, managed
  parsing fails closed before querying.
- Legacy parsing keeps best-effort primary database behavior.

Schema/mode:

- Generic EventTranscript SQLite row mode.
- Managed mode requires ordinary SQLite rowid tables with positive native
  `sqlite_schema.rootpage` values.
- Virtual tables, internal SQLite tables, rootpage-less tables, duplicate
  rootpages, inaccessible tables, or rowid-less tables fail closed in managed
  mode.

Query/table sequence and ordering contract:

1. Table stream:
   `SELECT name, rootpage FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY rootpage ASC`
2. Row stream per table:
   `SELECT rowid AS __casescope_rowid__, * FROM "<table>" ORDER BY rowid ASC`

The fixed contract is:
`eventtranscript:sqlite-rootpage-rowid-order:v1`.

Native identity and locator:

- Table identity: native SQLite `sqlite_schema.rootpage`.
- Row identity: native SQLite `rowid` within that table.
- Locator: `table:<table>;rootpage:<rootpage>;rowid:<rowid>`.
- Locator is emitted as authoritative parser source identifier type
  `eventtranscript_sqlite_rowid`.

Timestamp policy:

- The parser probes deterministic row fields whose column names contain `time` or
  `date`, in sorted column-name order.
- If no row timestamp can be parsed, it emits deterministic
  `1970-01-01 00:00:00` with `timestamp_source=missing_timestamp_unix_epoch`.
- File mtime, temp-file mtime, `datetime.now()`, and current time are not used for
  EventTranscript managed row identity.

Canonical output hardening:

- `raw_json` and `extra_fields` serialize with sorted keys.
- Byte values are represented as deterministic lowercase hex payloads.
- `search_blob` is built from sorted payload keys.
- `target_path` is populated only from deterministic path/URI/url columns when
  present.

Frozen semantic configuration:

- Parser version: `EventTranscriptDbParser-1.1.0`.
- Ordering contract: `eventtranscript:sqlite-rootpage-rowid-order:v1`.
- Producer signature:
  `EventTranscriptDbParser-1.1.0;sqlite=standalone;contract=eventtranscript:rootpage-rowid:v1;missing_ts=epoch`.
- Companion policy: absent SQLite companions only.
- Normalization version and batch size remain frozen by the generation contract.

Corpus/provenance:

- No safe pre-existing EventTranscript corpus was found in the repository,
  `/opt/casescope-benchmark`, installed package data, `/home/jdube`, `/opt/local`,
  or `/opt/ntfs_parse`.
- Certification used a generated structurally valid SQLite `EventTranscript.db`
  consumed by the production `sqlite3` backend and production parser class.
- The fixture contains two real rowid tables, `ProviderEvents` and
  `AppInteractions`, with nine rows total, enough for three manifest batches at
  batch size 3. One row intentionally lacks a timestamp to prove deterministic
  missing-time behavior.

Independent process proof:

- PASS with `PYTHONHASHSEED=1`, `PYTHONHASHSEED=7`, and `PYTHONHASHSEED=random`.
- Event count, normalized ClickHouse rows, source locator sequence, batch IDs,
  ingest row ordinals, ingest row hashes, and batch content hashes matched exactly.
- Retry with a new attempt UUID reproduced identical generation/batch/evidence
  identity. Only `ingest_attempt_id` changed.

Legacy/managed parity:

- PASS. Legacy parser rows and managed parser input rows matched exactly,
  excluding manifest protocol metadata.
- This is a parser semantic change from inherited generic SQLite summary behavior,
  so `EventTranscriptDbParser` version was bumped from `1.0.0` to `1.1.0`.

Multi-batch retry:

- PASS at batch size 3 over 9 events, producing batch row counts `[3, 3, 3]`.
- Retry used a new attempt and reproduced identical batch IDs, row hashes, batch
  hashes, ordinals, and locators.

Partial failure recovery:

- PASS. An injected failure after the first DURABLE batch left that batch intact.
- Retry reused the first batch manifest, completed the remaining batches, and did
  not perform CaseFile-wide cleanup.
- Broad deletion of prior DURABLE managed batches is not permitted.

Real PostgreSQL/ClickHouse:

- PASS on disposable databases.
- Flow exercised parser -> generation 1 `BUILDING_INITIAL` -> attempt -> STAGED
  -> real ClickHouse insert -> exact ClickHouse verifier -> PostgreSQL DURABLE ->
  control projection -> retry.
- Batch source isolation: maximum `countDistinct(case_file_id)` per
  `ingest_batch_id` was `1`.
- Generation state remained `BUILDING_INITIAL`.
- Disposable PostgreSQL and ClickHouse databases were dropped after the proof.

Performance:

- Generated performance fixture: 90,112 bytes.
- Companion bytes: 0.
- Table/query streams: 2 tables, 2 row streams.
- Source records/events: 1,000 / 1,000.
- Parser time: 0.071803 seconds, about 13,926.98 rows/sec.
- Manifest/hash time: 0.566828 seconds, about 1,764.20 rows/sec at batch size 10.
- Batches at size 10: 100.
- Peak RSS: 74,756 KB.
- C3D2B disposable PG/CH proof: 7 tests in 9.012 seconds including setup,
  insert, verify, durable transition, projection, retry, cleanup, and drop.

## Production Activation Audit

Enabled in C3D2B:

- `EventTranscriptDbParser.supports_manifest_protocol = True`
- `EventTranscriptDbParser.manifest_ordering_contract =
  eventtranscript:sqlite-rootpage-rowid-order:v1`

Still disabled:

- `WindowsSearchDbParser.supports_manifest_protocol = False`
- `WindowsSearchDbParser.manifest_ordering_contract = None`
- `SRUMParser.supports_manifest_protocol = False`
- `SRUMParser.manifest_ordering_contract = None`
- `WebCacheParser.supports_manifest_protocol = False`
- `WebCacheParser.manifest_ordering_contract = None`

No-cutover audit:

- global flag OFF
- derivations NO
- graph NO
- readers NO
- ACTIVE NO

## Tests

Passed:

- C3D2B local:
  `/opt/casescope/venv/bin/python -m unittest tests.test_phase1b_tranche_c3d2b_search_eventtranscript`
  returned 7 tests OK, 2 skipped without DB env.
- C3D2B real PG/CH:
  same module against disposable PG/CH returned 7 tests OK.
- A/B/C1/C2/C3A/C3B/C3C/C3D1/C3D2B local regression:
  95 tests OK, 19 skipped.
- A/B/C1/C2/C3A/C3B/C3C/C3D1/C3D2B real PG/CH regression:
  95 tests OK.
- Broader parser hardening/gap, retry/fence, ClickHouse delete/dedup, graph,
  privacy, and completion slice:
  503 tests run with one known unrelated diagnostic parser failure and one skip.
- `py_compile`, `pyflakes` on changed C3D2B files, and `git diff --check` passed.

Known unrelated failure preserved:

- `test_diagnostic_log_parser_emits_clean_windows_etl_metadata` still expects
  `metadata_only` and observes `parse_error`. This was already documented before
  C3D2B and was not modified here.

## Deferred Certification Inventory

Still deferred and not implemented in C3D2B:

- Prefetch
- LNK
- Firefox JSONLZ4
- MFT
- Registry
- JumpList
- BrowserSQLite
- SRUM
- WebCache
- Windows Search

## Remaining C3 Work

C3E should perform targeted cleanup/deferred parser certification and the final
C3 coverage audit. C3E was not started.

## Verdict

At least one production parser in C3D2B certified under the managed manifest
protocol: `EventTranscriptDbParser`.

PHASE1B_TRANCHE_C3D2B_PASS
