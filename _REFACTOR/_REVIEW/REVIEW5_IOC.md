# Review 5 — IOC Pipeline

Date: 2026-04-20

## Scope
Review the IOC extraction / normalization / merge / audit / tagging pipeline against the live repo, with emphasis on whether `utils/ioc_extractor.py` is actually thin, canonical IOC identity and dedup semantics, schema-validation ordering, defang/refang single-source-of-truth claims, whether the AI audit path is additive or authoritative, and `utils/ioc_artifact_tagger.py` correctness.

## Review Outcome
- `utils/ioc_extractor.py` is still the canonical IOC boundary, but it is not a thin facade in practice. The live module still owns the regex extractor class, alias-generation logic, import preparation, and persistence helpers in addition to orchestration.
- Schema validation ordering is correct on the semantic path: deterministic extraction runs first, raw AI payloads are validated/review-gated, then coerced into the IOC contract before normalization and merge.
- Review 5 found and fixed a real canonical-identity bug in `process_extraction_for_import()`: importer-side dedup used one flat `seen_values` set, so distinct IOC types with the same literal value could collapse before analyst review. Landed in `19b76a61`.
- Review 5 also fixed a timeline/query-consistency bug: `utils/ioc_timeline_builder.py` loaded each IOC's effective match mode, then ignored it and recomputed auto-detection when building search clauses. Landed in `19b76a61`.
- Defang/refang handling is not yet a single source of truth. The shared helper in `utils/ioc_text.py` exists, but the regex extractor and audit path still carry their own pattern tables.
- The semantic AI path is additive over deterministic extraction, but the audit path is currently authoritative over the final candidate set: validated audit deltas mutate the deterministic extraction in place before the caller receives the final payload.
- `utils/ioc_artifact_tagger.py` still stores badge labels like `Hash`, `User`, and `IP` in `events.ioc_types` rather than canonical IOC identities, so event-level tagging collapses distinct IOC types that share the same badge bucket.

## Verified Behavior
- `run_ioc_pipeline_with_provider()` still executes deterministic extraction first in both `semantic` and `audit` modes.
- `prepare_ai_extraction_payload()` still performs schema/semantic review gating after inspecting the raw AI payload and before normalized IOC merge, so the semantic path does not bypass deterministic-first ordering.
- `_ioc_records` provenance still flows through deterministic, semantic, and audit paths and is available to import-time annotation when the extraction came through the normal IOC pipeline.
- `generate_ioc_with_aliases()` still intentionally keeps file-path and command-line matching contextual by splitting a broad searchable primary value from narrower aliases.

## Findings
### 1. `CORRECTNESS` / `HIGH`
- Location: `utils/ioc_extractor.py:1628`
- Summary: importer-side dedup previously keyed on raw value alone, so two distinct IOC types with the same literal string could collapse before analyst review even though the canonical database identity is `(case_id, ioc_type, value_normalized)`.
- Proposed fix: landed in this Review by namespacing dedup keys by IOC type or raw-input field so cross-type identities survive review/import preparation while same-type duplicates still collapse. Rough effort: S. Commit: `19b76a61`

### 2. `CORRECTNESS` / `MEDIUM`
- Location: `utils/ioc_timeline_builder.py:108`, `utils/ioc_timeline_builder.py:240`
- Summary: the IOC timeline path loaded each IOC's stored effective `match_type`, then ignored it and re-ran auto-detection inside `_find_ioc_events()`, so explicit regex/token/substring settings were not honored consistently across IOC consumers.
- Proposed fix: landed in this Review by threading the stored match mode into `_find_ioc_events()` and only auto-detecting when no stored mode is available. Rough effort: S. Commit: `19b76a61`

### 3. `DRIFT` / `MEDIUM`
- Location: `utils/ioc_extractor.py:250`, `utils/ioc_extractor.py:1503`, `utils/ioc_extractor.py:1605`, `utils/ioc_extractor.py:2448`
- Summary: `utils/ioc_extractor.py` remains far more than a thin facade; it still owns the regex engine, alias generation, import preparation, and persistence logic instead of just orchestrating the extracted IOC helper modules.
- Proposed fix: continue Phase 5 decomposition by moving regex, alias/import preparation, and save helpers behind dedicated component modules while keeping `utils/ioc_extractor.py` as the stable public entry point. Rough effort: M/L.

### 4. `DUPLICATION` / `MEDIUM`
- Location: `utils/ioc_extractor.py:254`, `utils/ioc_text.py:9`, `utils/ioc_audit.py:113`
- Summary: defang/refang normalization is not yet a single source of truth. The shared helper exists, but the regex extractor and audit module still maintain separate pattern tables, so future defang updates can drift by pipeline stage.
- Proposed fix: move the regex extractor and audit stage onto the same shared normalization table used by `utils/ioc_text.py` (or an explicitly versioned shared helper) and keep only thin wrappers in callers. Rough effort: M.

### 5. `RISK` / `HIGH`
- Location: `utils/ioc_audit.py:573`, `utils/ioc_audit.py:677`, `utils/ioc_extractor.py:1292`
- Summary: the semantic IOC path is additive, but audit mode is authoritative over the returned candidate set: `apply_audit_deltas()` mutates deterministic output in place before the final extraction is returned. The validated deltas are preserved in summary metadata, but the original detector output is no longer the sole returned authority.
- Proposed fix: keep the validated delta log, but preserve the pre-audit deterministic candidate set alongside the post-audit view (or persist audit overlays separately) so downstream consumers can distinguish detector output from AI correction without reconstructing it from summary metadata. Rough effort: M.

### 6. `CORRECTNESS` / `HIGH`
- Location: `utils/ioc_artifact_tagger.py:93`, `utils/ioc_artifact_tagger.py:601`, `utils/ioc_artifact_tagger.py:624`
- Summary: artifact tagging stores shortened badge labels in `events.ioc_types` instead of canonical IOC identities, so distinct types such as `MD5 Hash` / `SHA256 Hash` or `Username` / `SID` collapse onto the same event-level marker and downstream consumers cannot recover the exact matched IOC type from the ClickHouse event row.
- Proposed fix: keep short labels only as presentation metadata and store canonical IOC type (or IOC ID/value identity) in the event tagging surface used for downstream hunt/chat/timeline consumers. Rough effort: M/L.

## Code Changes Landed During Review 5
- `utils/ioc_extractor.py`
  - made importer dedup type-aware so cross-type IOC identities survive review/import prep while same-type duplicates still collapse (`19b76a61`)
- `utils/ioc_timeline_builder.py`
  - threaded stored IOC match modes into event search so timelines honor explicit regex/token/substring settings instead of silently re-autodetecting (`19b76a61`)
- `tests/test_ioc_case_scope.py`
  - added regressions covering cross-type importer dedup semantics and stored-match-type propagation into the IOC timeline path (`19b76a61`)

## Verification Run
- `python3 -m unittest tests.test_ioc_case_scope tests.test_ioc_artifact_tagger tests.test_phase5_ioc_merge_contract tests.test_phase5_ioc_normalizer_contract tests.test_ioc_extractor_huntress_regressions`
- Result: `OK` (51 tests)

## Review 6 / 7 Hand-off
- Review 6 should treat IOC semantic extraction as deterministic-first plus additive AI repair, but treat `pipeline_mode='audit'` as an authoritative AI correction layer until an explicit overlay-preservation contract exists.
- Review 7 should assume that event-level `ioc_types` currently expose badge buckets rather than canonical IOC identity, so any route/chat/hunting surface that treats those tags as exact IOC type evidence needs direct verification.
- Review 5's two landed fixes are in `19b76a61`; no push was performed.
