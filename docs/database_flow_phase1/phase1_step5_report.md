# Phase 1 Step 5 Report

## 1. Scope

Authorized scope was Phase 1.8 only: typed hot-field promotion for current `events` readers.

Not started: Phase 1B progressive orchestration, Phase 2 text indexes/lightweight updates, LEK, generations, manifests, watermarks, event surfaces, Qdrant migration, and overlay migration.

## 2. Candidate Decision

`KeyLength` was promoted to `key_length Nullable(UInt16)`.

All other evaluated candidates were deferred or rejected. Existing typed columns were not duplicated (`src_ip`, `workstation_name`, `auth_package`, `logon_process`, `logon_type`, actor/domain/SID columns, process/path/hash columns).

Candidate inventory artifacts:

- `docs/database_flow_phase1/phase1_step5_candidate_fields.md`
- `docs/database_flow_phase1/phase1_step5_candidate_fields.json`

## 3. Implementation

Additive schema:

- `migrations/add_events_table.py` adds `key_length Nullable(UInt16)` to fresh `events` schemas.
- `migrations/add_event_key_length_column.py` provides an idempotent `ADD COLUMN IF NOT EXISTS` migration for existing schemas.
- No backfill or destructive rewrite is performed.

Parser population:

- `parsers/evtx_parser.py` populates `key_length` from already-decoded EVTX `EventData.KeyLength`.
- `parsers/base.py` serializes the new column in ClickHouse insert order and clamps to `UInt16`.
- Malformed/out-of-range values remain `NULL`; the original value remains in `raw_json` and `search_blob`.
- `key_length` is excluded from emitted provenance serialization to keep `extra_fields` invariant.

Migrated readers:

- `utils/candidate_extractor.py`
- `models/pattern_rules.py`
- `utils/mitre_attack_sync.py`

Reader SQL uses conditional fallback:

`if(key_length IS NULL, JSONExtractString(raw_json, 'EventData', 'KeyLength') = value, key_length = typed_value)`

## 4. Semantic Parity

Artifact: `docs/database_flow_phase1/phase1_step5_semantic_parity.json`

- Events: 110,742 current = 110,742 legacy
- Detections: 7,436 current = 7,436 legacy
- ERK missing/extra: 0 / 0
- Deterministic event field differences: 0
- Incorrect cross-file attachments: 0
- Parser errors: 0
- Parser warnings: 0

IOC common-path coverage was unchanged. No IOC reader was migrated away from `raw_json` or `search_blob`.

## 5. Query Performance

Scratch benchmark rows: 550,414 EVTX rows from representative cases 10 and 33.

Exact pass-the-hash predicate returned zero rows in both measured cases, but count parity held for legacy, typed-only, and fallback shapes.

Non-zero `KeyLength=0` predicate on case 33:

- Legacy JSON median: 14.006 ms
- Typed-only new-row path median: 5.015 ms
- Conditional historical fallback median: 9.165 ms
- Count: 529 for all shapes

`EXPLAIN indexes=1` confirmed the same primary-key pruning shape for legacy and typed predicates; the benefit comes from avoiding JSON extraction on rows with populated `key_length`, not from a new index.

## 6. Ingest Regression

Artifact: `docs/database_flow_phase1/phase1_step5_ingest.json`

Approved Step 4 hybrid policy was used: eager first EVTX plus one directory group for the remaining seven files.

- Events inserted: 110,742
- ERK digest: `6ad87fe76520d18bde4cfb421bbd4fce0b410c00d60abaf642769aa303515b7c`
- Detections: 7,436
- Wall: 136.215 s
- Events/sec: 812.996
- First searchable: 18.282 s
- Peak RSS: 228.42 MB
- CPU self / children: 96.4 s / 92.385 s
- Errors: 0

This is within the accepted Step 4 performance envelope.

## 7. Storage Cost

Scratch storage comparison with `raw_json` and `search_blob` retained:

- Without `key_length`: 53,647,726 compressed bytes
- With `key_length`: 53,938,864 compressed bytes
- Delta: 291,138 bytes, 0.543%

Disposable full-corpus optimized `events` table after Step 5 ingest: 20,762,370 active bytes for 110,742 rows.

## 8. Tests

Command:

`/opt/casescope/venv/bin/python -m unittest tests.test_phase1_step5 tests.test_phase1_step1.OrjsonParityTests tests.test_phase1_step4.ParserDirectoryModeTestCase tests.test_parser_hardening.ParserHardeningTestCase`

Result: 148 tests OK.

Linter diagnostics: none for edited files.

## 9. Verdict

**STEP5_ACCEPTED**

Phase 1 implementation work complete.

Stop here for separate Phase 1 exit review.
