# Phase 1B Tranche C3B MFT / USN Certification

Date: 2026-08-16
Version: 4.19.0
C3A checkpoint: `7f6f9e06f35fd422fe60af27dcf42a6ba288cc0a`
Remote baseline verified: `be175072ca716f64cba7f087e5fd1d67a29f7c04`

## Scope

Tranche C3B evaluated only:

- `MFTParser`
- `USNParser`

No Prefetch, LNK, Firefox JSONLZ4, Registry, RegistryPol, JumpList, SRUM,
BrowserSQLite, ActivitiesCache, WebCache, Windows Search, EventTranscript,
Sdb, memory, PCAP, derivation, graph, reader, `events_current`, replacement
generation, or ACTIVE-transition work was started.

## Contract Verification

C3B preserves the locked Phase 1B contracts:

- Global `PHASE1B_MANIFEST_PROTOCOL_ENABLED` remains default false.
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

| Parser | Artifact type | Version before C3B | C3B status |
|---|---|---:|---|
| `MFTParser` | `mft` | `MFTParser-2.0.0` | NOT CERTIFIED |
| `USNParser` | `usn` | `USNParser-1.1.0` | CERTIFIED as `USNParser-1.2.0` |

## MFTParser

Status: NOT CERTIFIED

- Backend/dependency: `dissect.ntfs` 3.16 via `NTFS(mft=fh).mft.segments()`.
- Fixture/corpus: no safe representative `$MFT` fixture or benchmark corpus was
  found in `tests/`, the repository, or the visible local worktree. No
  production case evidence was used.
- Source walk: current code walks `mft.segments()` and emits zero or one event
  per segment depending on attributes and per-record parse success.
- Native identity: `record.segment` is exposed as `record_id`, but sequence
  number and full file reference are not currently preserved in the emitted
  event identity.
- Locator: not assigned for managed certification.
- Ordering contract: not assigned.
- Frozen semantic configuration: unresolved because `max_entries` changes the
  emitted source set and must be frozen or disallowed before certification.
- Dependency/producer policy: unresolved. `dissect.ntfs` interpretation, MFT
  segment traversal, attribute selection, and path resolution can change
  canonical output across dependency versions.
- Independent-process proof: not run because no representative valid MFT source
  exists.
- Legacy/managed parity: not run.
- Multi-batch retry: not run.
- Partial failure recovery: not run.
- Real PG/CH: not run.
- Performance/RSS: not measured.
- Exact reason: C3B cannot truthfully prove record order, record number plus
  sequence semantics, reused/deleted record identity, multiple filename
  attribute behavior, directory/file handling, corrupt-record skipping, or
  multi-batch retry without a valid parser-backed MFT fixture.

## USNParser

Status: CERTIFIED

- Backend/dependency: `dissect.ntfs` 3.16, specifically
  `dissect.ntfs.usnjrnl.UsnJrnl` and `UsnRecord`.
- Fixture/corpus: GENERATED VALID FIXTURE, an NTFS USN_RECORD_V2 journal stream
  written as `$Extend/$UsnJrnl/$J`. No parser backend was mocked.
- Natural source identity: physical byte offset of each valid USN record in the
  journal stream. The USN value is preserved as `record_id`, but the certified
  locator uses stream offset to avoid collapsing repeated or reset USN values.
- Source walk: bounded forward byte-stream walk from the first allocated data
  offset. The parser reads each record length, skips zero pages, skips malformed
  records deterministically, aligns to the next 8-byte boundary, and yields
  records in physical journal order.
- Locator basis: authoritative parser source identifier
  `usn_journal_offset`, stored from the record's stream offset.
- Ordering contract: `usn:physical-record-offset-order:v1`.
- Frozen semantic configuration: no parser options are accepted that change
  emitted USN rows. Managed certification is explicitly `usn_companion_mft=absent`.
  If a companion `$MFT` is present in managed mode, parsing fails closed because
  companion path resolution changes canonical `target_path` values.
- Dependency/producer policy: frozen producer signature is
  `USNParser-1.2.0;dissect.ntfs=3.16;usn_companion_mft=absent;usn_record_versions=2`.
  It excludes runtime noise such as PID, worker host, temp path, timestamps, and
  attempt UUID.
- Canonical output hardening: USN `raw_json` and `extra_fields` are serialized
  with sorted keys; reason/source/attribute flags are emitted from deterministic
  enum-name order; source locator metadata is included in parser provenance.
- Independent processes: PASS with `PYTHONHASHSEED=1`, `7`, and `random`.
- Legacy/managed parity: PASS. Legacy parser rows and managed parser input rows
  matched exactly after JSON-safe serialization, excluding manifest protocol
  metadata.
- Multi-batch retry: PASS at batch size 3 over 8 records, producing batch row
  counts `[3, 3, 2]`. Retry used a new attempt and reproduced identical batch
  IDs, row hashes, batch hashes, and locators.
- Partial failure recovery: PASS. An injected failure after the first DURABLE
  batch left that batch intact; retry reused the first batch manifest, continued
  remaining batches, and did not perform CaseFile-wide cleanup.
- Real PostgreSQL/ClickHouse: PASS on disposable databases. Flow exercised
  parser -> generation 1 `BUILDING_INITIAL` -> attempts -> STAGED -> real CH
  insert -> CH verification -> PG DURABLE -> shadow projection -> retry.
- Batch source isolation: PASS. Maximum `countDistinct(case_file_id)` per
  `ingest_batch_id` was `1`.
- Generation state: PASS. Generation remained `BUILDING_INITIAL`.
- Performance/RSS: generated 1,000-record fixture was 88,000 bytes, emitted
  1,000 events, parsed in 0.148712 seconds, built 100 manifest batches at batch
  size 10 in 0.361421 seconds, parser throughput 6,724.40 rows/sec, hash/manifest
  throughput 2,766.86 rows/sec, peak RSS 76,672 KB.

## Source-Ordering Proof

USN C3B ordering is not a post-parse sort. The parser advances through the
journal stream by physical record offset, using each record's on-disk length and
alignment. That offset is the same source-native position used as the certified
locator. Timestamps, filenames, row hashes, JSON text, Python object order, and
filesystem enumeration are not ordering inputs.

Malformed records are skipped deterministically from identical bytes: invalid
lengths advance to the next USN page; unsupported/bad records with valid length
lose only that record and continue at the next aligned offset.

## Configuration Freeze

- `MFTParser.max_entries`: changes emitted source set; MFT remains disabled.
- `USNParser` companion `$MFT`: changes emitted paths; managed mode certifies
  only absent companion `$MFT` and fails closed when a companion exists.
- `USNParser` record versions: only USN v2 records are certified and included in
  the producer signature.
- `Config.PHASE1B_MANIFEST_BATCH_SIZE`: frozen in the generation contract and
  mismatch fails closed.
- `Config.PHASE1B_NORMALIZATION_VERSION`: frozen in the generation contract and
  mismatch fails closed.

## Tests

Passed:

- C3B local determinism/lint:
  `/opt/casescope/venv/bin/python -m unittest tests.test_phase1b_tranche_c3b_mft_usn`
  returned 6 tests OK, 2 skipped without DB env.
- C3B real PG/CH:
  same module as `casescope` against disposable PG/CH returned 6 tests OK.
- A/B/C1/C2/C3A/C3B regression slice:
  76 tests OK against disposable PG/CH.
- ClickHouse delete/dedup:
  35 tests OK; previously observed PCAP Celery-registration errors did not
  reproduce standalone.
- Retry/failure/ingest fence/hash:
  43 tests OK.
- Graph regression group:
  170 tests OK, 1 skipped.
- Privacy/completion group:
  83 tests OK.
- Memory hardening standalone:
  1 test OK; grouped failure was a test-stub ordering artifact.
- `py_compile`, `pyflakes`, and `git diff --check` passed for changed C3B files.

Unrelated known failures/errors:

- `test_diagnostic_log_parser_emits_clean_windows_etl_metadata` still expects
  `metadata_only` and observes `parse_error`. This was already documented in
  C3A and was not modified for C3B.
- A broad mixed parser/gap grouping produced one memory parser import error from
  test support stubs replacing `db.Model`; the same memory test passed when run
  standalone.
- The four earlier PCAP Celery-registration errors did not reproduce in the
  standalone ClickHouse delete/dedup contract run.

## Production Activation Audit

Enabled in C3B:

- `USNParser.supports_manifest_protocol = True`
- `USNParser.manifest_ordering_contract = usn:physical-record-offset-order:v1`

Still disabled:

- `MFTParser.supports_manifest_protocol = False`
- `MFTParser.manifest_ordering_contract = None`

Global manifest protocol remains default false.

## Verdict

At least one production parser in C3B certified under the managed manifest
protocol: `USNParser`.

PHASE1B_TRANCHE_C3B_PASS
