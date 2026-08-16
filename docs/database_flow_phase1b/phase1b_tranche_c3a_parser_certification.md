# Phase 1B Tranche C3A Parser Certification

Date: 2026-08-16
Version: 4.19.0
C2 checkpoint: `353d241e44ca3717791bc2aa383d88937aaf1c2b`

## Scope

Tranche C3A evaluated only the next bounded structured-parser cohort:

- `PrefetchParser`
- `LnkParser`
- `ScheduledTaskParser`
- `FirefoxJSONLZ4Parser`

Only `ScheduledTaskParser` is certified in this tranche. `PrefetchParser`,
`LnkParser`, and `FirefoxJSONLZ4Parser` remain disabled for manifest ingest.

No registry, recursive/container, database-backed, memory, PCAP, graph,
derivation, reader-surface, replacement-generation, or `events_current` work was
started.

## Contract Verification

C3A preserves the locked Phase 1B contracts:

- `case_files.ingest_protocol_origin` semantics are unchanged.
- Existing legacy/unknown CaseFiles remain legacy.
- Only never-started CaseFiles may newly enter managed generation 1.
- Existing `BUILDING_INITIAL` managed sources remain pinned to managed recovery
  before the global feature flag is considered.
- Global `PHASE1B_MANIFEST_PROTOCOL_ENABLED` remains default false.
- Managed generation state remains `BUILDING_INITIAL`.
- No derivations, graph cutover, readers, ACTIVE transition, or replacement
  generation behavior was activated.

## Candidate Inventory

| Parser | Registered artifact type | Version before C3A | C3A status |
|---|---|---:|---|
| `PrefetchParser` | `prefetch` | `PrefetchParser-2.1.0` | NOT CERTIFIED |
| `LnkParser` | `lnk` | `LnkParser-2.1.0` | NOT CERTIFIED |
| `ScheduledTaskParser` | `scheduled_task` | `ScheduledTaskParser-1.0.1` | CERTIFIED |
| `FirefoxJSONLZ4Parser` | `firefox_session` | `FirefoxJSONLZ4Parser-1.0.0` | NOT CERTIFIED |

## PrefetchParser

Status: NOT CERTIFIED

- Fixture: none found in `tests/`, `_example_files`, or `/opt/casescope-benchmark`.
- Source walk: current code emits one event per `latest_timestamp` followed by
  `previous_timestamps`, then a triage event on parse failure.
- Locator: no authoritative source identifier or native record ID is emitted.
- Ordering contract: not assigned.
- Independent process proof: not run because no representative real or generated
  valid Prefetch source was available and the parser/library behavior was not
  proven.
- Retry proof: not run.
- Legacy/managed parity: not run.
- Real PG/CH: not run.
- Dependency policy: Dissect Prefetch semantics may materially affect timestamp
  exposure and loaded-file traversal; producer identity policy is unresolved.
- Exact reason: current C3A could not prove Dissect execution timestamp slot
  order, loaded-file canonical representation, or representative multi-run
  Prefetch behavior without a valid corpus artifact.

## LnkParser

Status: NOT CERTIFIED

- Fixture: none found in `tests/`, `_example_files`, or `/opt/casescope-benchmark`.
- Source walk: current code emits one structured event per LNK source.
- Locator: no authoritative source identifier or native record ID is emitted.
- Ordering contract: not assigned.
- Independent process proof: not run because no valid representative LNK source
  was available.
- Retry proof: not run.
- Legacy/managed parity: not run.
- Real PG/CH: not run.
- Dependency policy: Dissect shell item/LNK interpretation may affect path,
  tracker, droid, and timestamp fields; producer identity policy is unresolved.
- Exact reason: single-event ordering is trivial, but canonical representation,
  tracker/extradata traversal, and dependency effects were not proven with a
  valid parser-backed fixture.

## ScheduledTaskParser

Status: CERTIFIED

- Fixture: GENERATED VALID FIXTURE, a UTF-16 Task Scheduler XML document under a
  `C/Windows/System32/Tasks/CaseScope/` path. No parser backend was mocked.
- Source count: 1.
- Source bytes: 2,848.
- Events: 1.
- Source walk: one event per Task Scheduler XML document. Trigger and action
  arrays preserve XML document order as returned by `xml.etree.ElementTree`.
- Locator: authoritative scheduled task URI when present
  (`\CaseScope\C3A-MultiAction`); deterministic ordinal fallback otherwise.
- Ordering contract: `scheduled-task:single-xml-document:v1`.
- Parser version: `ScheduledTaskParser-1.0.1`.
- Independent processes: PASS with `PYTHONHASHSEED=1`, `7`, and `random`.
- Determinism: PASS. Event row, canonical normalized values, batch ID, row
  ordinal, row hash, batch content hash, and locator sequence matched exactly.
- Retry: PASS. New attempt UUID produced the same generation, batch ID, row hash,
  batch hash, and locator identity.
- Multi-batch: naturally impossible for one scheduled task XML source because
  the parser emits exactly one event per source. The manifest engine was tested
  with the actual one-event output at batch size 1 and 10000; both correctly
  produced one batch without changing evidence semantics.
- Legacy/managed parity: PASS. Legacy parse output and managed parse input rows
  matched exactly, ignoring manifest metadata.
- Real PostgreSQL: PASS on disposable database
  `phase1b_c3a_20260816022949`, dropped after the proof.
- Real ClickHouse: PASS on disposable database
  `phase1b_c3a_20260816022949`, dropped after the proof.
- Generation state: `BUILDING_INITIAL`.
- Attempts: first managed attempt plus retry attempt, both successful.
- Batches: one `DURABLE` batch; retry reused the same `ingest_batch_id`,
  expected row hash, and batch content hash.
- Performance: parser 4.852 ms, manifest hashing 3.775 ms, about 206 rows/sec
  for the natural one-event workload. Disposable PG/CH managed retry test ran in
  2.795 seconds including setup.
- Dependency policy: standard-library XML parsing is the semantic producer. The
  project parser version is sufficient for this contract because the emitted
  fields are explicit ElementTree document-order traversals and changing those
  semantics requires a parser version bump.

## FirefoxJSONLZ4Parser

Status: NOT CERTIFIED

- Fixture: none found in `tests/`, `_example_files`, or `/opt/casescope-benchmark`.
- Source walk: current code supports session, search engine, addon/extension,
  handler, and generic JSON modes.
- Locator: no authoritative source identifier or native record ID is emitted.
- Ordering contract: not assigned.
- Independent process proof: not run.
- Retry proof: not run.
- Legacy/managed parity: not run.
- Real PG/CH: not run.
- Dependency policy: `lz4.block` decompression is a semantic producer input if
  this parser is later certified.
- Exact reason: the class handles multiple modes with different truthful
  ordering semantics. Session arrays can use source JSON array order, but handler
  object mappings and generic JSON modes need a mode-aware contract before
  manifest activation.

## Production Activation Audit

Newly enabled parser:

- `ScheduledTaskParser.supports_manifest_protocol = True`
- `ScheduledTaskParser.manifest_ordering_contract =
  scheduled-task:single-xml-document:v1`

All other C3A candidates remain:

- `PrefetchParser.supports_manifest_protocol = False`
- `PrefetchParser.manifest_ordering_contract = None`
- `LnkParser.supports_manifest_protocol = False`
- `LnkParser.manifest_ordering_contract = None`
- `FirefoxJSONLZ4Parser.supports_manifest_protocol = False`
- `FirefoxJSONLZ4Parser.manifest_ordering_contract = None`

## Test Evidence

Passed:

- C2 checkpoint proof before commit:
  - `python -m unittest` equivalent via venv for Phase 1B A/B/C1/C2: 65 tests,
    10 skipped.
  - `py_compile` on C2 files.
  - `pyflakes` on C2 files.
  - `git diff --check`.
- C3A local:
  - `/opt/casescope/venv/bin/python -m unittest tests.test_phase1b_tranche_c3a_structured_parsers`
    returned 5 tests, 1 skipped.
  - C3A real PG/CH managed integration on disposable databases returned 1 test
    OK.
  - `py_compile` and `pyflakes` on C3A changed files.
  - `git diff --check`.

Broader requested regression slice:

- Ran 479 tests across Phase 1B, parser hardening/gap, retry/failure, ingest
  fence, ClickHouse delete/dedup, graph, privacy, and completion-related tests.
- Result: 463 passed or skipped before accounting for known/unrelated failures;
  11 skipped; 1 known unrelated diagnostic-parser failure; 4 PCAP Celery
  task-registration errors in `test_clickhouse_delete_dedup_contracts`.
- Known unrelated failure preserved:
  `test_diagnostic_log_parser_emits_clean_windows_etl_metadata` expected
  `metadata_only` and observed `parse_error`.
- PCAP errors were unrelated to C3A parser certification and occurred in task
  registration for deferred PCAP paths.

## Verdict

At least one real parser in C3A certified under the manifest protocol:
`ScheduledTaskParser`.

PHASE1B_TRANCHE_C3A_PASS
