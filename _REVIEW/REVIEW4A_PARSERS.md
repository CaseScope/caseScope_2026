# Review 4a — Parsers

Date: 2026-04-20

## Scope
Review EVTX, dissect, Windows, and registry-related parser surfaces against the live repo; verify the `parsers/base.py` contract and provenance emission for those families; check coverage-bearing parser output against `utils/pattern_event_mappings.py`; carry forward Review 3 timezone concerns only where they still survive at the parser boundary; and land any unambiguous in-scope fixes discovered during the review.

## Review Outcome
- The base parser contract still computes `timestamp_utc` during ClickHouse row materialization, and the EVTX / dissect / Windows / registry families in this scope all route through that contract. Review 3's UTC drift therefore does **not** survive at the parser boundary for these families; it remains a consumer/query-surface problem in deterministic-core code.
- The primary EVTX path still emits the fields Review 3 made load-bearing for deterministic evaluation: `timestamp_utc`, `source_host`, `channel`, `provider`, and `raw_json.EventData.*` values used by `utils/candidate_extractor.py`.
- The EVTX fallback path does **not** honor the same parser-to-extractor contract as the primary EVTX path. It persists native pyevtx JSON directly into `raw_json`, so `EventData`-based candidate extraction can silently miss pattern fields when fallback ingestion is active.
- Parser-emitted provenance had a real contract drift: the shared provenance helper did not classify `timestamp_utc` or `timestamp_source_tz` as structural even though `ParsedEvent`'s inline fallback already did. Review 4a fixed that.
- Windows WebCache emitted two artifact subtypes (`webcache_dom_storage`, `webcache_compatibility`) that were missing from the catalog and hunting-tab mappings, which made those parsed rows drift out of the declared parser surface. Review 4a fixed that.

## Verified Behavior
- `parsers/base.py` still computes `timestamp_utc` from `timestamp` plus `timestamp_source_tz` during `to_clickhouse_row()`, and `_serialized_extra_fields()` still merges parser-emitted provenance into `extra_fields`.
- `parsers/evtx_parser.py` primary-path events still populate `event_id`, `channel`, `provider`, `record_id`, `source_host`, `src_ip`/`dst_ip` (IPv4-only), and a normalized `raw_json` payload that includes top-level `EventData`.
- `utils/candidate_extractor.py` still relies on `JSONExtractString(raw_json, 'EventData', ...)` for key Windows fields such as `IpAddress`, `TargetServerName`, `KeyLength`, `SourceImage`, `TargetImage`, and `ParentImage`, so the EVTX parser's `raw_json` shape remains load-bearing.
- `RegistryParser` still emits full-fidelity registry key/value rows with UTC FILETIME semantics, `source_host`, `reg_key`, `reg_value`, `reg_data`, and preserved raw payloads in `raw_json`; no direct pattern-mapping gap was found for the registry-specific 4a surfaces beyond the general fact that most `pattern_event_mappings` entries remain Windows Event ID driven rather than hive-native.
- `ScheduledTaskParser` still tags ambiguous task-registration timestamps with case timezone behavior, matching the parser catalog and timezone helper classification for `scheduled_task`.

## Findings
### 1. `CORRECTNESS` / `HIGH`
- Location: `parsers/evtx_parser.py:944`, `utils/candidate_extractor.py:302`
- Summary: `EvtxFallbackParser` stores native pyevtx JSON in `raw_json` instead of the normalized `EventData` envelope the primary EVTX path emits, so `JSONExtractString(raw_json, 'EventData', ...)` lookups can silently miss anchor/supporting fields when fallback ingestion is active.
- Proposed fix: normalize fallback `raw_json` onto the same `EventData` contract as `EvtxECmdParser` (or explicitly exclude fallback-ingested EVTX from deterministic correlation until that contract is met). Rough effort: M.

### 2. `CORRECTNESS` / `MEDIUM`
- Location: `parsers/evtx_parser.py:943`, `parsers/base.py:634`
- Summary: `EvtxFallbackParser` writes `src_ip=self.validate_ip(...)` into a ClickHouse IPv4 column even though the primary EVTX path already narrowed that column to IPv4-only storage with `validate_ipv4()`. IPv6 fallback rows can therefore violate the established parser/storage contract.
- Proposed fix: mirror the primary EVTX path by using `validate_ipv4()` for `src_ip` and preserving non-IPv4 addresses in string metadata instead of the typed IPv4 column. Rough effort: S.

### 3. `CORRECTNESS` / `MEDIUM`
- Location: `parsers/evtx_parser.py:318`
- Summary: Hayabusa enrichment is keyed by `RecordID` and later matches overwrite earlier ones, so multiple detections on the same record collapse to the last rule seen instead of preserving the full enrichment set.
- Proposed fix: store a list per `RecordID` (or key by a richer tuple) and merge enrichment deterministically before attaching it to the parsed event. Rough effort: S/M.

### 4. `CORRECTNESS` / `MEDIUM`
- Location: `utils/provenance.py:16`, `parsers/base.py:145`
- Summary: the shared parser provenance helper classified `timestamp_utc` and `timestamp_source_tz` as artifact-tainted even though `ParsedEvent`'s inline fallback treated them as structural/system-derived, which inflated parser-emitted provenance risk for correctly normalized timestamps.
- Proposed fix: landed in this Review by adding `timestamp_utc` and `timestamp_source_tz` to `utils.provenance.STRUCTURAL_FIELDS`. Rough effort: S. Commit: `<pending>`

### 5. `DRIFT` / `MEDIUM`
- Location: `parsers/windows_parsers.py:815`, `parsers/catalog.py:118`, `parsers/catalog.py:291`
- Summary: `WebCacheParser` emits `webcache_dom_storage` and `webcache_compatibility`, but those artifact types were missing from the parser catalog and hunting-tab mapping, leaving real parser outputs outside the declared/reachable product surface.
- Proposed fix: landed in this Review by adding both subtypes to the `webcache` parser capability and the browsers hunting-tab list. Rough effort: S. Commit: `<pending>`

### 6. `DOC` / `LOW`
- Location: `docs/PARSERS.md`
- Summary: parser documentation had drifted from code: the EVTX and Registry versions were stale, the dissect parser file list omitted USN, and the Registry `reg_data` truncation limit no longer matched the live parser.
- Proposed fix: landed in this Review by updating the documentation to the live repo state. Rough effort: S. Commit: `<pending>`

## Code Changes Landed During Review 4a
- `utils/provenance.py`
  - aligned shared parser provenance classification with the live `ParsedEvent` contract for `timestamp_utc` and `timestamp_source_tz` (`<pending>`)
- `parsers/catalog.py`
  - added `webcache_dom_storage` and `webcache_compatibility` to the catalog and browsers hunting-tab mapping so emitted WebCache rows stay on the declared product surface (`<pending>`)
- `tests/test_parser_hardening.py`
  - added focused regressions covering UTC parser provenance classification and WebCache catalog/tab consistency (`<pending>`)
- `docs/PARSERS.md`
  - refreshed stale parser versions, dissect file coverage, and Registry truncation documentation (`<pending>`)

## Verification Run
- `python3 -m unittest tests.test_parser_hardening tests.test_phase65_parser_provenance_contract`
- Result: `OK` (46 tests, 2 skipped)

## Review 4b Hand-off
- Review 4b should pick up the remaining parser families: browser, log, memory, and vendor.
- Carry forward Review 3's timezone thread only at the consumer boundary; Review 4a verified that the parsers reviewed here do populate `timestamp_utc` through the base contract.
- Treat the EVTX fallback contract mismatch as still open: the primary EVTX path remains pattern-safe, but fallback ingestion can still degrade deterministic candidate extraction and may also violate the IPv4 column contract.
