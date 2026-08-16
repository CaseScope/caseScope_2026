# Phase 1B Tranche C3C Registry / Registry.pol / JumpList Certification

Date: 2026-08-16
Version: 4.19.0
C3B checkpoint: `e574c6beb3d25eb917b0ed8db95a350c2ab6030c`
Remote baseline verified: `be175072ca716f64cba7f087e5fd1d67a29f7c04`

## Scope

Tranche C3C evaluated only:

- `RegistryParser`
- `RegistryPolParser`
- `JumpListParser`

No MFT, Prefetch, standalone LNK, Firefox JSONLZ4, SRUM, BrowserSQLite,
ActivitiesCache, WebCache, Windows Search, EventTranscript, Sdb, memory, PCAP,
derivation, graph, reader, `events_current`, replacement generation, ACTIVE
transition, C3D, C3E, or Tranche D work was started.

## Contract Verification

C3C preserves the locked Phase 1B contracts:

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

| Parser | Registered artifact type | Version before C3C | C3C status |
|---|---|---:|---|
| `RegistryParser` | `registry` | `RegistryParser-2.1.0` | NOT CERTIFIED |
| `RegistryPolParser` | `registry_pol` | `RegistryPolParser-1.0.0` | CERTIFIED as `RegistryPolParser-1.1.0` |
| `JumpListParser` | `jumplist` | `JumpListParser-2.1.0` | NOT CERTIFIED |

## RegistryParser

Status: NOT CERTIFIED

- Backend/dependency: `dissect.regf` 3.14 plus optional external decode helpers
  `/opt/casescope/bin/appcompatcacheparser` and `/opt/casescope/bin/sbecmd`.
- Fixture/corpus: no safe representative real SYSTEM, SOFTWARE, NTUSER.DAT, SAM,
  SECURITY, USRCLASS, or AMCACHE hive fixture was found in the repository.
  Existing tests use fakes/mocks and are not certification evidence.
- Source walk: current full-hive mode starts at `hive.root()`, emits a key event,
  then value events, then recursively walks child keys using `key.subkeys()`.
  Interesting-key mode opens configured key paths and recursively walks up to
  depth 3 from each matched key.
- Native identity: not assigned. Current emitted events do not carry hive cell
  offsets, key cell IDs, value cell IDs, or another proven authoritative record
  identity.
- Locator: not assigned.
- Ordering contract: not assigned.
- Frozen semantic configuration: unresolved. `extract_all` changes emitted source
  set and interesting-key mode also freezes hive-specific key lists plus depth.
  Optional hive replay and external helper availability can change emitted rows.
- Dependency/producer policy: unresolved. `dissect.regf` traversal, value
  decoding, hive replay, and helper tool output can change canonical output.
- Independent-process proof: not run because no valid representative real hive
  fixture exists and source-native traversal order was not proven.
- Legacy/managed parity: not run.
- Multi-batch retry: not run.
- Partial failure recovery: not run.
- Real PG/CH: not run.
- Performance/RSS: not measured.
- Exact reason: C3C cannot truthfully prove recursive key/value ordering,
  duplicate/default value identity, deleted/recovered behavior, unreadable key
  handling, helper-tool row order, or a strong locator without a real parser-backed
  hive fixture and a proven source-native ordering primitive from `dissect.regf`.

## RegistryPolParser

Status: CERTIFIED

- Backend/dependency: in-repository Registry.pol parser implementing the documented
  `PReg` header and `[key;value;type;size;data]` binary record format. No external
  parser backend or mock is used.
- Fixture/corpus: GENERATED VALID FIXTURE, a `Registry.pol` file under
  `C/Windows/System32/GroupPolicy/Machine/` with 8 records. It includes nested
  keys, duplicate policy value names, default value, `REG_SZ`, `REG_DWORD`,
  `REG_BINARY`, `REG_MULTI_SZ`, and `REG_QWORD`.
- Native source identity: physical byte offset of each Registry.pol record
  opener in the file body.
- Source walk: sequential byte walk from offset 8 after the `PReg` signature and
  version. Each record is decoded in physical file order using its own key, value,
  type, size, and data fields. Malformed/truncated records stop parsing at that
  physical offset with a warning; valid records before the malformed boundary keep
  their source order.
- Locator basis: authoritative parser source identifier
  `registry_pol_record_offset`, stored from the physical record offset.
- Ordering contract: `registry-pol:physical-record-offset-order:v1`.
- Frozen semantic configuration: no parser options are accepted that change
  emitted Registry.pol rows. The certified format version is 1, data size is
  bounded by the Registry.pol 65,535-byte field, and byte-read truncation is
  recorded in emitted payloads rather than silently changing semantics.
- Dependency/producer policy: frozen producer signature is
  `RegistryPolParser-1.1.0;registry_pol_format=1;record_offsets=physical`.
  It excludes runtime noise such as PID, worker host, temp path, timestamps, and
  attempt UUID.
- Canonical output hardening: `raw_json` and `extra_fields` serialize with sorted
  keys; decoded type-specific data is normalized by explicit registry type rules;
  source locator metadata is included in parser provenance.
- Independent processes: PASS with `PYTHONHASHSEED=1`, `7`, and `random`.
- Legacy/managed parity: PASS. Legacy parser rows and managed parser input rows
  matched exactly after JSON-safe serialization, excluding manifest protocol
  metadata. This is a parser semantic change from the prior one-event string scan,
  so `RegistryPolParser` version was bumped from `1.0.0` to `1.1.0`.
- Multi-batch retry: PASS at batch size 3 over 8 records, producing batch row
  counts `[3, 3, 2]`. Retry used a new attempt and reproduced identical batch IDs,
  row hashes, batch hashes, and locators.
- Partial failure recovery: PASS. An injected failure after the first DURABLE batch
  left that batch intact; retry reused the first batch manifest, continued remaining
  batches, and did not perform CaseFile-wide cleanup.
- Real PostgreSQL/ClickHouse: PASS on disposable databases. Flow exercised parser
  -> generation 1 `BUILDING_INITIAL` -> attempts -> STAGED -> real CH insert ->
  CH verification -> PG DURABLE -> shadow projection -> retry.
- Batch source isolation: PASS. Maximum `countDistinct(case_file_id)` per
  `ingest_batch_id` was `1`.
- Generation state: PASS. Generation remained `BUILDING_INITIAL`.
- Performance/RSS: generated 1,000-record fixture was 110,008 bytes, emitted
  1,000 events, parsed in 0.098325 seconds, built 100 manifest batches at batch
  size 10 in 0.356020 seconds, parser throughput 10,170.30 rows/sec, hash/manifest
  throughput 2,808.83 rows/sec, peak RSS 76,224 KB.

## JumpListParser

Status: NOT CERTIFIED

- Backend/dependency: `dissect.ole` 3.12 and `dissect.shellitem` 3.13.
- Fixture/corpus: no safe representative real or generated
  `automaticDestinations-ms` or `customDestinations-ms` fixture was found in the
  repository. Existing tests cover `DestList` byte decoding only, not full
  parser-backed OLE/LNK extraction.
- AutomaticDestinations source walk: current code lists OLE root entries with
  `ole.root.listdir()`, reads `DestList`, skips `DestList`, and parses LNK streams
  whose stream data starts with LNK magic.
- CustomDestinations source walk: current code uses the same OLE path, but C3C did
  not prove this is correct for CustomDestinations or that embedded LNK records
  share the same source-defined walk.
- Native identity: not assigned. Stream names can correspond to DestList entry IDs
  for automatic destinations, but OLE directory entry identity and physical stream
  position are not emitted or proven.
- Locator: not assigned.
- Ordering contract: not assigned.
- Frozen semantic configuration: unresolved. Automatic and Custom destinations may
  need mode-specific contracts. `DestList` handling, missing LNK streams, corrupt
  streams, and embedded LNK extraction need separate format proofs.
- Dependency/producer policy: unresolved. `dissect.ole` directory enumeration and
  `dissect.shellitem` LNK interpretation can change emitted canonical output.
- Independent-process proof: not run.
- Legacy/managed parity: not run.
- Multi-batch retry: not run.
- Partial failure recovery: not run.
- Real PG/CH: not run.
- Performance/RSS: not measured.
- Exact reason: C3C could not prove that OLE `listdir()` order is source-native,
  could not prove CustomDestinations handling separately, and had no valid
  parser-backed fixture. Standalone `LnkParser` remains not certified; JumpList is
  not silently certified through embedded LNK handling.

## Source-Ordering Proof

`RegistryPolParser` ordering is not a post-parse sort. The parser reads the file
linearly from byte offset 8, consumes one native `[key;value;type;size;data]`
record at a time, advances by that record's encoded length, and emits in the same
physical byte order. The same physical record offset is used as the certified
locator. Timestamps, row hashes, JSON text, registry key names, value names, and
filesystem enumeration are not ordering inputs.

`RegistryParser` and `JumpListParser` do not receive ordering contracts in C3C.

## Configuration Freeze

- `RegistryPolParser`: no order/emission-changing options. Format version 1 and
  physical record offset ordering are frozen in the producer signature.
- `RegistryParser.extract_all`: changes emitted source set; parser remains
  disabled.
- `RegistryParser` interesting-key lists, hive-specific lists, depth 3 walk,
  hive replay availability, and external helper availability change emitted rows;
  parser remains disabled.
- `JumpListParser`: mode-specific Automatic vs Custom semantics unresolved; parser
  remains disabled.
- `Config.PHASE1B_MANIFEST_BATCH_SIZE`: frozen in the generation contract and
  mismatch fails closed.
- `Config.PHASE1B_NORMALIZATION_VERSION`: frozen in the generation contract and
  mismatch fails closed.

## Dependency / Producer Identity

- `RegistryPolParser`: producer identity freezes only
  `RegistryPolParser-1.1.0`, `registry_pol_format=1`, and
  `record_offsets=physical`.
- `RegistryParser`: dependency policy unresolved; observed `dissect.regf=3.14`.
- `JumpListParser`: dependency policy unresolved; observed `dissect.ole=3.12` and
  `dissect.shellitem=3.13`.

## Production Activation Audit

Enabled in C3C:

- `RegistryPolParser.supports_manifest_protocol = True`
- `RegistryPolParser.manifest_ordering_contract =
  registry-pol:physical-record-offset-order:v1`

Still disabled:

- `RegistryParser.supports_manifest_protocol = False`
- `RegistryParser.manifest_ordering_contract = None`
- `JumpListParser.supports_manifest_protocol = False`
- `JumpListParser.manifest_ordering_contract = None`

Global manifest protocol remains default false.

## No-Cutover Audit

Expected and preserved:

- global flag OFF
- derivations NO
- graph NO
- readers NO
- ACTIVE NO

## Tests

Passed:

- C3C local:
  `/opt/casescope/venv/bin/python -m unittest tests.test_phase1b_tranche_c3c_registry_jumplist`
  returned 5 tests OK, 2 skipped without DB env.
- C3C real PG/CH:
  same module against disposable PG/CH returned 5 tests OK.

The final C3C regression record is in the Tranche C3C result report.

## Verdict

At least one production parser in C3C certified under the managed manifest
protocol: `RegistryPolParser`.

PHASE1B_TRANCHE_C3C_PASS
