# LEK Contract

Status: LOCKED for Phase 0B. This contract defines semantics only; it does not implement LEK storage or reader migration.

## Definition

`logical_event_key` (LEK) is source-independent semantic logical-event identity. It collapses only observations that are safe to treat as the same logical event while preserving all physical ERKs as provenance.

Initial representation is `lek:v1:<sha256>`.

ERK remains unchanged and remains the physical forensic identity. LEK never destroys physical provenance and never replaces ERK for custody, audit, or evidence-source support.

## Evidence Inputs

- Locked v4 plan: LEK is not mechanically derived from legacy `ARTIFACT_DEDUP_CONFIGS`.
- Current normalized event schema: `ParsedEvent` columns in `parsers/base.py`.
- ERK construction: `utils/evidence_identity.py` scopes physical identity by case/source record evidence.
- Legacy dedup recipes: `utils/event_deduplication.py::ARTIFACT_DEDUP_CONFIGS`.
- Phase 0A duplicate sample: 20,894,468 rows, 9,392,460 duplicate rows under current legacy semantics; 6,912,432 duplicate rows had different ERKs.

## Global Rules

- Status: LOCKED.
- Version: `logical_identity_version = "lek:v1"`.
- Hash input: deterministic JSON with sorted keys, ASCII output, compact separators, explicit field names, explicit null markers, and a fixed recipe name.
- Hash algorithm: SHA-256 over UTF-8 canonical JSON.
- Null handling: a locked recipe may emit a cross-source LEK only when all required fields are present after normalization. If required fields are missing, fallback is `lek:v1:erk:<sha256(ERK)>` and may not cross source boundaries.
- Timestamp precision: use `timestamp_utc` at the precision specified per recipe. Do not use localized display time.
- Source-independent requirement: `source_file`, `source_path`, `case_file_id`, `indexed_at`, parser run IDs, selector key, and ERK must not participate in a cross-source LEK recipe.
- Collision behavior: if two rows share a LEK but conflict on fields declared collision-checking fields, keep both observations, set `field_conflict = true`, expose conflicting values through provenance lookup, and emit a collision/conflict audit event in the implementation phase.
- Missing-field fallback: one logical event per ERK unless a recipe explicitly says a same-source fallback is safe. No fallback may cross source boundaries unless listed below.
- Uncertainty rule: **uncertainty => no cross-source collapse**. `logical_identity_quality = "medium"` is not permission to collapse uncertain events. A cross-source recipe may be locked only when Phase 0 evidence proves a verified native transaction/event/record identity whose semantics are appropriate for cross-export equivalence.

## Cross-Source Recipe Gate

A parser-specific cross-source LEK recipe may be locked only if all of the following are true:

1. The parser supplies a **verified native** transaction, event, or record identifier.
2. Phase 0 evidence proves that identifier's semantics are appropriate for cross-export equivalence (same logical event across independent source files/exports).
3. The identifier is not invented by CaseScope (not a line number, not a hash of mutable fields, not a grouping code, not a second-level timestamp plus endpoint tuple).

Otherwise the family is `NO_SAFE_CROSS_SOURCE_RECIPE_YET` and MUST emit an ERK-backed non-collapsing LEK.

Do not invent a native identifier.

## Artifact Family Classification

| Artifact family | Status | Recipe summary |
|---|---|---|
| `evtx` | LEK_RECIPE_LOCKED | Windows event semantic record using host/channel/provider/event/record/time identity, excluding source file. Evaluated separately. `EventRecordID` is a native EVTX record identity. |
| `firewall` | NO_SAFE_CROSS_SOURCE_RECIPE_YET | Current `FirewallLogParser` does not emit a verified native unique transaction/event/record identifier. `event_id` is absent. Action plus second-level timestamp plus endpoint tuple can collide independent flows. |
| `iis` | NO_SAFE_CROSS_SOURCE_RECIPE_YET | Current `IISLogParser` emits no `event_id` / `record_id`. W3C logs can repeat legitimate requests in the same second with the same client IP, method, path, and status. No authoritative unique event identity. |
| `sonicwall` | NO_SAFE_CROSS_SOURCE_RECIPE_YET | Current `SonicWallCSVParser` maps `ID` to `event_id`. That `ID` is a message/event-type code, not a unique transaction/record UUID. Repeated flows in the same second share the type ID. |
| `huntress` | NO_SAFE_CROSS_SOURCE_RECIPE_YET | Current `HuntressParser` sets `event_id` from ECS `event.code` / `event.action` / category+type, explicitly **not** a unique source-event UUID. Parser comments state `entity_id` is per-process and was rejected as a grouping key. No proven unique Huntress event UUID is mapped. |
| `registry` | NO_SAFE_CROSS_SOURCE_RECIPE_YET | Legacy recipe depends on `source_file` and `raw_json`; retain one LEK per ERK until registry hive/key semantics are separately measured. |
| `mft` | NO_SAFE_CROSS_SOURCE_RECIPE_YET | `record_id` is file-system/source-scoped and cannot safely cross source files without volume identity. |
| `srum` | NO_SAFE_CROSS_SOURCE_RECIPE_YET | Heavy cross-file duplicates observed, but recipe depends on `source_file` and process/time only; collision risk is not bounded. |
| `prefetch` | NO_SAFE_CROSS_SOURCE_RECIPE_YET | Needs executable path/hash/run-count semantics beyond current source-file recipe. |
| `browser` | NO_SAFE_CROSS_SOURCE_RECIPE_YET | No Phase 0A sample rows; browser database native IDs and profile scope need measurement. |
| `lnk` | NO_SAFE_CROSS_SOURCE_RECIPE_YET | Target path alone plus host is insufficient to prove same shortcut observation across sources. |
| `jumplist` | NO_SAFE_CROSS_SOURCE_RECIPE_YET | No duplicates observed in sample, but current recipe includes source file and Jump List app/session scope matters. |
| `scheduled_task` | NO_SAFE_CROSS_SOURCE_RECIPE_YET | Current sample has no eligible legacy dedup rows; task path alone is not enough. |
| `activities_cache` | NO_SAFE_CROSS_SOURCE_RECIPE_YET | No eligible duplicate evidence; app/activity IDs require measurement. |
| `webcache` | NO_SAFE_CROSS_SOURCE_RECIPE_YET | No sample rows; browser cache database scope and native IDs required. |
| `json_log` | NO_SAFE_CROSS_SOURCE_RECIPE_YET | Generic logs are source-specific unless a parser supplies an authoritative native ID. |
| `csv_log` | NO_SAFE_CROSS_SOURCE_RECIPE_YET | Generic CSV content depends on source format; current recipe uses `source_file`. |
| `firefox_session` | NO_SAFE_CROSS_SOURCE_RECIPE_YET | No sample rows; session/profile scope required. |

## Locked Recipes

### EVTX

Evaluated separately from network/EDR families. Windows EVTX `EventRecordID` is a native per-log record identifier. Combined with canonical host, channel, provider, event ID, and millisecond UTC timestamp it is the only Phase 0 family with a proven cross-source recipe.

- `logical_identity_version`: `lek:v1:evtx`.
- Canonical inputs: `case_id`, normalized `source_host`, normalized `channel`, normalized `provider`, normalized `event_id`, `record_id`, `timestamp_utc` truncated to milliseconds.
- Normalization: trim strings, map `"-"` to null, uppercase host, lowercase channel/provider only for comparison, preserve original values for display.
- Null handling: `source_host`, `event_id`, `record_id`, and `timestamp_utc` are required. If `channel` or `provider` is missing, include explicit null marker and quality becomes `medium` **for representative scoring only**; required-field absence still falls back to ERK and does not cross sources. Quality `medium` does not authorize a weaker identity recipe.
- Quality tier: `high` when host, channel, provider, event ID, record ID, and millisecond UTC timestamp are present; `medium` when optional channel/provider is missing; `erk_fallback` otherwise.
- Collision fields: `username`, `domain`, `sid`, `process_name`, `process_path`, `command_line`, `remote_host`, `workstation_name`, `payload_data1` through `payload_data6`, `raw_json`.
- Tests: cross-CaseFile same EVTX record collapses; different event IDs do not; missing record ID falls back to ERK; milliseconds are deterministic; conflicting usernames surface (CT-014, CT-015, CT-035).

## Unsupported Families

For `NO_SAFE_CROSS_SOURCE_RECIPE_YET`, including `iis`, `firewall`, `sonicwall`, and `huntress`, LEK is still emitted as a non-collapsing identity:

- Format: `lek:v1:erk:<sha256({"erk": ERK})>`.
- Quality tier: `erk_fallback`.
- Cross-source collapse: prohibited.
- Future change: requires a parser-supplied verified native identifier, a new `logical_identity_version`, Phase 0-style collision/equivalence measurements, and a decision-log entry.

Tests: two IIS requests in the same second with identical endpoint/path/status remain distinct LEKs; two firewall/SonicWall flows in the same second with identical endpoints remain distinct; two Huntress rows sharing `event.code` remain distinct (CT-034).

## Canonical Representative Contract

One LEK may have multiple ERKs. The default representative is selected by deterministic sort key, highest score first:

1. Highest `logical_identity_quality`: `high`, `medium`, `erk_fallback`.
2. Highest ERK quality: `native`, `source_identifier`, `fingerprinted`, `legacy_fallback`.
3. Highest field completeness count across display fields.
4. Highest source quality tier: native parser output, structured parser output, generic parsed output.
5. Most precise timestamp: millisecond, second, date-only, missing.
6. Newest `parser_version` by semantic comparison when parseable; otherwise lexical.
7. Earliest `timestamp_utc`.
8. Deterministic final tie-break: lexicographically smallest ERK.

Prohibited: `any()`, arbitrary first row, insertion-order selection, merge-order-dependent selection.

## Logical Surface Fields

- `observation_count`: number of published ERKs with the LEK.
- `source_count`: count of distinct `(source_ref_type, source_ref_id, source_generation)` values represented by the LEK. It indicates source diversity, not independent truth.
- `field_conflict`: true when any conflict field has more than one normalized non-null value among observations.
- Conflict normalization: compare normalized-equivalent values after trimming, null mapping, case normalization for case-insensitive fields, and timestamp precision rules. Preserve original values for provenance display.
- Provenance lookup: default timeline shows the representative; "show observations" returns every ERK, source ref, generation, original field values, and conflict values.

## Explicitly Open Items

- OPEN — ADDITIONAL MEASUREMENT REQUIRED: safe source-independent recipes for registry, MFT, SRUM, prefetch, browser, LNK, Jump List, scheduled task, Activities Cache, WebCache, JSON, CSV, Firefox session, IIS, firewall, SonicWall, and Huntress. Each requires a verified native identifier; none may be invented.
- NOT APPLICABLE: Phase 0B does not implement LEK columns, projections, or migrations.
