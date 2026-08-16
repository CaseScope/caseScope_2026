# Phase 1B Tranche C3D2A ESE Certification

Date: 2026-08-16
Version: 4.19.0
C3C checkpoint: `bca2c4fa358b3cc00795799ceb39db0c63185308`
C3D1 checkpoint: `8f217d7ebb8f9b2ed6173e58b23debc7c0cb01d5`
Remote baseline verified: `be175072ca716f64cba7f087e5fd1d67a29f7c04`

## Scope

Tranche C3D2A evaluated only:

- `SRUMParser`
- `WebCacheParser`

No Windows Search, EventTranscript, BrowserSQLite, ActivitiesCache, Registry,
JumpList, MFT, Prefetch, LNK, Firefox JSONLZ4, PCAP, memory, derivation, graph,
reader, `events_current`, replacement generation, ACTIVE transition, C3D2B, C3E,
or Tranche D work was started.

## Initial NOT_READY Audit

The following sections through the original `PHASE1B_TRANCHE_C3D2A_NOT_READY`
verdict record the initial C3D2A audit. They remain authoritative starting
evidence for this closure pass and were not discarded.

## Contract Verification

C3D2A preserves the locked Phase 1B contracts:

- Global `PHASE1B_MANIFEST_PROTOCOL_ENABLED` remains default false.
- `legacy_or_unknown` CaseFiles stay legacy.
- Only `not_started` CaseFiles may newly enter managed initial ingest.
- Existing `BUILDING_INITIAL` managed sources remain pinned to managed retry.
- Frozen parser, normalization, batching, ordering, and producer signatures must
  compare fail-closed on retry.
- Retry must use a new `ingest_attempt_id` and reproduce the same deterministic
  `ingest_batch_id`, row hashes, batch hashes, and locators.
- Existing DURABLE batches must not be broad-deleted during retry.
- Generation state remains `BUILDING_INITIAL`.
- No derivations, graph cutover, readers, ACTIVE transition, replacement
  generation, protocol backfill, hash backfill, generation backfill, historical
  event update, giant rewrite, or `OPTIMIZE FINAL` was introduced.

## Candidate Inventory

| Parser | Registered artifact type | Version | Backend | C3D2A status |
|---|---|---:|---|---|
| `SRUMParser` | `srum` | `SRUMParser-1.1.0` | `dissect.esedb` 3.18 | NOT CERTIFIED |
| `WebCacheParser` | `webcache` | `WebCacheParser-1.1.0` | `dissect.esedb` 3.18 | NOT CERTIFIED |

Both production classes remain disabled for manifest ingest:

- `SRUMParser.supports_manifest_protocol = False`
- `SRUMParser.manifest_ordering_contract = None`
- `WebCacheParser.supports_manifest_protocol = False`
- `WebCacheParser.manifest_ordering_contract = None`

## ESE Backend / Source-Set Model

The current production parsers open only the primary ESE file with
`dissect.esedb.EseDB(handle)`. The installed backend is `dissect.esedb` 3.18.
No external ESE helper, transaction log replay helper, checkpoint replay helper,
reserved log directory, or temporary recovery tool is invoked by either parser.

The backend exposes useful source-native metadata:

- database header fields including `dbstate`, `lGenMinRequired`,
  `lGenMaxRequired`, and related recovery generation fields;
- table catalog rows with `ObjidTable`, `Name`, and `ColtypOrPgnoFDP`;
- table root/FDP page via `Table.root_page`;
- index records and primary-index metadata;
- per-record B-tree `Record._node.key`;
- physical node coordinates through `Record._node.tag.page.num` and
  `Record._node.tag.num`.

However, the current parsers do not use those fields for ordering or locators.
They trust `db.tables()` and `table.records()` implicitly. In `dissect.esedb`
3.18, `db.tables()` is catalog-table iteration order and `table.records()` walks
the table root B-tree leaves. That may be source-native, but C3D2A did not prove
that the current parser outputs can be frozen safely without changing semantics,
especially around dynamic table selection, duplicate mapping rows, malformed
records, and absent timestamp fallbacks.

Managed source-set policy if these parsers are revisited should be primary ESE
bytes only unless a later tranche explicitly designs and freezes companion log
and checkpoint replay. Because ESE logs can contain committed changes absent
from the primary file, a managed parser should fail closed when the header or
sidecar set indicates recovery-required state that cannot be replayed under the
frozen contract.

## SRUM Result

Status: NOT CERTIFIED.

Current production behavior:

- Opens `SRUDB.dat` or `SRU.dat` with `dissect.esedb.EseDB`.
- Builds `SruDbIdMapTable` by iterating `db.tables()` until table name
  `SruDbIdMapTable`, then iterating `table.records()`.
- Walks every table whose name starts with `{`.
- Emits known and unknown GUID tables; known descriptions come from
  `SRUM_TABLES`, unknown GUID tables emit with description `Unknown`.
- Resolves `AppId` and `UserId` through the ID map.
- Emits one `srum` event per successfully processed record.

Known SRUM table descriptions in the current parser:

- `{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}` Application Resource Usage
- `{D10CA2FE-6FCF-4F6D-848E-B2E99266FA86}` Application Resource Usage (Push)
- `{973F5D5C-1D90-4944-BE8E-24B94231A174}` Network Connectivity
- `{DD6636C4-8929-4683-974E-22C046A43763}` Network Data Usage
- `{FEE4E14F-02A9-4550-B5CE-5FA2DA202E37}` Energy Usage
- `{DA73FB89-2BEA-4DDC-86B8-6E048C6DA477}` Push Notifications
- `{5C8CF1C7-7257-4F13-B223-970EF5939312}` vfuprov
- `{7ACBBAA3-D029-4BE4-9A7A-0885927F1D8F}` App Timeline
- `{B6D82AF1-F780-4E17-8077-6CB9AD8A6FC4}` SDL Storage Provider

SRUM blockers:

- No valid SRUDB/SRU.dat fixture was found in `tests/`, the repository, or
  `/opt/casescope-benchmark`; existing tests only cover SID helper decoding.
- `SruDbIdMapTable` duplicate `IdIndex` behavior is accidental last Python dict
  write wins under unproven table record order.
- Malformed `IdBlob` rows are silently skipped or decoded by fallback paths
  without a managed fail-closed policy.
- SID vs UTF-16 path decoding is deterministic for a single blob, but duplicate
  or malformed map-row conflict semantics are not source-frozen.
- Unresolved IDs fall back to `str(value)`, which is deterministic but must be
  explicitly part of a future contract.
- The parser emits every `{GUID}` table, including unknown GUID tables, so a
  future managed contract must either prove native ordering for dynamic tables or
  define a safe known-table contract without silently dropping forensic rows.
- `table.columns` comes from catalog interpretation and current `search_blob`
  extends `record_dict.values()`, so column order affects canonical row values.
  That order may be source-defined, but it is not documented or frozen here.
- Timestamp fallback uses `fallback_timestamp(file_path=...)`, which depends on
  file metadata rather than primary ESE bytes. Same bytes copied with a different
  mtime can change managed row identity.
- No authoritative locator is emitted. Viable future candidates include table
  catalog identity plus primary/index key, or table catalog identity plus
  B-tree node key/page/tag, but none is currently part of emitted rows.
- Legacy behavior catches many table/record exceptions and continues with
  warnings; managed behavior would need to fail closed for recovery-required or
  partial-output states.
- Independent process, legacy parity, multi-batch retry, partial failure
  recovery, real PG/CH, and performance proofs were not run because no valid
  parser-backed corpus exists and the ordering/locator contract is unresolved.

Frozen semantic configuration: unresolved. `dissect.esedb` 3.18 should be part of
producer identity if SRUM is later certified because ESE catalog, record, tagged
value, and B-tree interpretation are semantic.

## WebCache Result

Status: NOT CERTIFIED.

Current production behavior:

- Opens `WebCacheV01.dat` or `WebCacheV24.dat` with `dissect.esedb.EseDB`.
- Builds a `Containers` mapping from `ContainerId` to `Name` and `Directory`.
- Walks every ESE table whose name starts with `Container_`.
- Extracts the numeric container ID from the table name.
- Classifies artifact type by fixed substring match order over container name:
  history, downloads, compatibility, cache, cookies, DOM storage, or unknown.
- Emits one event per non-empty container-table record as
  `webcache_<container_type>`.

Current category coverage includes:

- history (`MSHist`, `History`)
- downloads (`BackgroundTransferApi`, `iedownload`)
- compatibility (`iecompat`, `IEToEdgeList`, `EmieSiteList`, `ieflipahead`,
  `ietld`)
- cache (`Content`)
- cookies (`Cookies`)
- DOM storage (`DOMStore`)
- unknown container types

WebCache blockers:

- No valid WebCache ESE fixture was found in `tests/`, the repository, or
  `/opt/casescope-benchmark`; existing tests only cover helper classification and
  byte decoding.
- `Containers` duplicate `ContainerId` behavior is accidental last Python dict
  write wins under unproven `Containers` record order.
- Duplicate names, missing `Containers`, damaged container records, missing
  container tables, unknown container types, and WebCache version differences are
  not governed by a managed contract.
- Global output order is the dynamic `db.tables()` order of `Container_N` tables,
  not a fixed artifact-category sequence or proven source-native container table
  sequence.
- Different `Container_N` tables can reuse record field values such as `EntryId`;
  no emitted locator includes table/container identity plus a native record
  identity.
- No authoritative source locator is emitted. Viable future candidates include
  table catalog identity plus record B-tree key, or table/container identity plus
  a proven container-record key, but C3D2A did not prove this across categories.
- Timestamp fallback uses `fallback_timestamp(file_path=...)`, which depends on
  file metadata rather than primary ESE bytes. Same bytes copied with a different
  mtime can change managed row identity.
- `raw_json` and `extra_fields` are not serialized with sorted keys, and current
  record dictionaries depend on catalog column iteration order.
- Legacy behavior treats corrupt/malformed database errors as warnings for some
  failures and continues per-table/per-record for others. Managed behavior would
  need to fail closed for recovery-required or partial-output states.
- Independent process, legacy parity, multi-batch retry, partial failure
  recovery, real PG/CH, and performance proofs were not run because no valid
  parser-backed corpus exists and the ordering/locator contract is unresolved.

Frozen semantic configuration: unresolved. `dissect.esedb` 3.18 should be part of
producer identity if WebCache is later certified because ESE catalog, record,
tagged value, and B-tree interpretation are semantic.

## Source-Ordering Proof

No C3D2A candidate has an accepted source-ordering proof.

The backend exposes B-tree keys and page/tag coordinates, but the current
production parsers do not declare them as ordering contracts or locators. C3D2A
does not use timestamp order, serialized-row alphabetical order, row hash order,
ERK order, JSON order, or arbitrary content tuples to manufacture repeatability.

## Locator Proof

No C3D2A candidate emits a truthful authoritative locator today.

For future work, a locator should include at minimum table identity plus native
record identity. For ESE that may be table catalog identity (`ObjidTable` or
root/FDP page) plus primary/index key, or table catalog identity plus B-tree
node key and physical page/tag coordinates if that is accepted as source-native.
URL, process name, app name, user SID, timestamps, or arbitrary content tuples
are not acceptable locators by themselves.

## ESE Recovery / Companion Proof

The current backend opens the provided primary ESE file handle only. It does not
discover or replay `.log`, `.jrs`, checkpoint, reserved log, or temp recovery
files. Header fields expose recovery-relevant state, but the current parsers do
not inspect them.

Because output can be incomplete when committed transactions live only in
external logs, managed SRUM/WebCache should remain disabled until a future
contract either freezes a complete source bundle with replay or fails closed for
dirty/recovery-required primary files and relevant nearby companions.

## Dependency / Producer Identity

Observed dependency:

- `dissect.esedb` 3.18

No external ESE tools are used by the current SRUM or WebCache parsers. If either
parser is later certified, the producer identity should include the CaseScope
parser version, the `dissect.esedb` version, the ESE source-set/recovery policy,
and the parser-specific ordering contract.

## Tests

Passed in this environment before C3D2A documentation:

- C3D1 local: `/opt/casescope/venv/bin/python -m unittest tests.test_phase1b_tranche_c3d1_sqlite`
  returned 7 tests OK, 2 skipped without DB env.
- A/B/C1/C2/C3A/C3B/C3C/C3D1 focused regression slice:
  88 tests OK, 17 skipped.
- `py_compile` passed for C3D1 files.
- `pyflakes` passed for C3D1 files.
- `git diff --check` passed before the C3D1 checkpoint commit.

Passed after adding this C3D2A record:

- Focused SRUM/WebCache helper tests:
  `tests.test_parser_hardening.ParserHardeningTestCase.test_srum_id_blob_decodes_binary_sid_instead_of_mojibake`,
  `tests.test_parser_hardening.ParserHardeningTestCase.test_webcache_catalog_lists_all_emitted_artifact_types`,
  `tests.test_parser_hardening.ParserBatchThreeRegressions.test_webcache_weekly_history_containers_are_classified_as_history`,
  and
  `tests.test_parser_hardening.WindowsParserRobustnessTests.test_webcache_column_decoder_falls_back_through_encodings`
  returned 4 tests OK.
- `py_compile` passed for inspected parser/protocol files.
- `git diff --check` passed.

Observed existing lint limitation:

- `pyflakes` over inspected parser/protocol files reported pre-existing issues in
  `parsers/registry.py` (`datetime`, `Path`, and local variable `wrapped`). C3D2A
  did not modify that file and did not fix unrelated lint.

Disposable real PostgreSQL/ClickHouse reruns were not available in this shell:
`PHASE1B_PG_TEST_DATABASE_URL` and `PHASE1B_CH_TEST_DATABASE` were unset,
PostgreSQL did not respond on the default socket, ClickHouse did not respond on
`localhost:8123`, systemd is not available, and Docker is not installed.

## Production Activation Audit

Expected and preserved:

- `SRUMParser.supports_manifest_protocol = False`
- `SRUMParser.manifest_ordering_contract = None`
- `WebCacheParser.supports_manifest_protocol = False`
- `WebCacheParser.manifest_ordering_contract = None`
- global flag OFF
- derivations NO
- graph NO
- readers NO
- ACTIVE NO

## Remaining C3 Work

C3D2B: Windows Search + EventTranscript and their actual current
database-backed production implementations.

C3E: remaining uncertified parser cleanup: Prefetch / LNK / Firefox JSONLZ4 /
MFT / Registry / JumpList / BrowserSQLite / SRUM / WebCache / any failed ESE
candidate, only with truthful contracts and adequate fixtures.

## Verdict

No C3D2A candidate genuinely certified. Both SRUM and WebCache remain disabled
for managed manifest ingest.

PHASE1B_TRANCHE_C3D2A_NOT_READY

## Closure Evidence

Closure pass date: 2026-08-16.

Starting state:

- `origin/main`: `be175072ca716f64cba7f087e5fd1d67a29f7c04`
- C3D1 checkpoint: `8f217d7ebb8f9b2ed6173e58b23debc7c0cb01d5`
- Version: `4.19.0`
- Worktree: `main...origin/main [ahead 8]` with only this C3D2A document
  untracked for closure work.

Corpus discovery revalidated no safe valid C3D2A ESE corpus:

- `/opt/casescope`: no `SRUDB.dat`, `SruDb.dat`, `SRU.dat`,
  `WebCacheV01.dat`, or `WebCacheV24.dat` found. Only source code,
  documentation, helper tests, and Sigma rule names referenced SRUM/WebCache.
- `/opt/casescope-benchmark`: no SRUM or WebCache ESE artifact found.
- `/tmp`: accessible search produced no usable SRUM/WebCache artifact; several
  unrelated private/system temporary directories were not readable.
- `/opt/casescope/tests`: no SRUM or WebCache ESE fixture found.
- `/opt/casescope/venv/lib/python3.12/site-packages`: no SRUM or WebCache ESE
  data file found.
- Installed `dissect.esedb` package assets contain read-only parser/tool code
  for ESE/SRUM and WebCache-related plugins, but no package test database.
- `/opt/local`, `/opt/ntfs_parse`, `/opt/zeek`, and `/home/jdube`: exact-name
  safe sweeps found no SRUM/WebCache ESE artifact; inaccessible Zeek runtime
  paths were not used.

No production/client CaseScope evidence was searched or used to close C3D2A.
No mock records, fake `db.tables()`, CSV/JSON fixture, or Python object
construction was treated as a valid ESE corpus.

Fixture generation remains unavailable on this host for C3D2A certification.
The installed `dissect.esedb` 3.18 API exposes `EseDB(fh)`, catalog, tables,
records, B-tree traversal, and page reads, but no ESE database writer or
structurally valid SRUM/WebCache generator. Fabricating a database by ad hoc byte
writing would not be trustworthy certification evidence.

PostgreSQL / ClickHouse environment:

- Current hostname: `casescope2026`.
- Current Cursor shell user observed as `root`; project services and existing
  DB processes run under service users.
- `PHASE1B_PG_TEST_DATABASE_URL` and `PHASE1B_CH_TEST_DATABASE` are not exported
  in the Cursor shell.
- Accepted prior harness is still the Phase 1B disposable integration pattern in
  the tranche tests, gated by `PHASE1B_PG_TEST_DATABASE_URL` and
  `PHASE1B_CH_TEST_DATABASE`.
- PostgreSQL and ClickHouse processes are running locally.
- ClickHouse `localhost:8123` and `localhost:9000` are reachable; `SELECT 1`
  succeeds through `clickhouse_connect`.
- PostgreSQL requires credentials; documented local credentials
  `postgresql://casescope:casescope@localhost/casescope` and
  `postgresql://casescope:casescope@localhost/postgres` connect successfully.
- Earlier "not responding" readiness checks were unauthenticated/default-role
  probes, not proof that services were absent.
- No service restart, Docker install, second database installation, or
  production configuration mutation was performed.

Candidate decision:

- No SRUM or WebCache candidate was chosen for activation because neither has a
  valid non-production corpus for real `dissect.esedb.EseDB` parsing.
- Without a valid ESE artifact, independent-process proof, legacy/managed
  parity, multi-batch retry, partial failure recovery, and real disposable
  PostgreSQL/ClickHouse proof cannot be executed truthfully.
- The minimum artifact needed to continue is one approved, non-production,
  structurally valid SRUM `SRUDB.dat`/`SruDb.dat`/`SRU.dat` or WebCache
  `WebCacheV01.dat`/`WebCacheV24.dat`, preferably with enough legitimate records
  to create multiple manifest batches at batch size 3, plus provenance proving it
  is lab/package/benchmark data and not production/client evidence.

ESE structural identity status:

- `dissect.esedb` 3.18 exposes table catalog identity, table root pages,
  primary-index metadata, record B-tree keys, and page/tag coordinates.
- These identities remain promising but uncertified for SRUM/WebCache because no
  real candidate artifact was available to inventory the actual `SruDbIdMapTable`
  or `Containers` mappings, duplicate semantics, table sequences, record keys, or
  dirty/recovery state.
- The current production parsers still do not emit authoritative ESE locators,
  still use dynamic table walks, still have unresolved duplicate mapping
  behavior, and still have file-mtime fallback timestamp concerns.

Production activation audit is unchanged:

- `SRUMParser.supports_manifest_protocol = False`
- `SRUMParser.manifest_ordering_contract = None`
- `WebCacheParser.supports_manifest_protocol = False`
- `WebCacheParser.manifest_ordering_contract = None`
- `PHASE1B_MANIFEST_PROTOCOL_ENABLED` remains default false.
- Generation activation remains out of scope; no `ACTIVE`, replacement,
  derivation, graph, reader, C3D2B, C3E, or Tranche D work was started.

Closure verdict:

No C3D2A candidate genuinely certified. C3D2A closure remains uncommitted, and
no push was performed.

PHASE1B_TRANCHE_C3D2A_CLOSURE_NOT_READY
