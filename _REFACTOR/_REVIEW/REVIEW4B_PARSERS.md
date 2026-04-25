# Review 4b — Parsers

Date: 2026-04-20

## Scope
Review browser, log, memory, and vendor parser surfaces against the live repo; verify the `parsers/base.py` contract and provenance emission for those families; check coverage-bearing parser output against `utils/pattern_event_mappings.py`; carry forward Review 3 and Review 4a findings only where they still survive verification at the 4b parser boundary; and land any unambiguous in-scope fixes discovered during the review.

## Review Outcome
- Browser, log, and vendor event parsers in this scope still route through `ParsedEvent`, so `timestamp_utc` is still computed at `to_clickhouse_row()` time. Review 3's UTC query-column drift therefore still does **not** survive at the parser boundary for those event families; it remains downstream consumer/query-surface work.
- The 4b log/vendor surface had a live parser/storage contract defect: multiple parsers still wrote `validate_ip()` output directly into the IPv4-only `src_ip` / `dst_ip` columns, so valid IPv6 telemetry could break ingestion or silently drift off the typed correlation surface. Review 4b fixed that in `41d9d5cb`.
- The browser SQLite family had declared-surface drift: the parser already emitted `sqlite_firefox_origin_storage`, `sqlite_firefox_cache_storage`, and `sqlite_firefox_indexeddb`, but those artifact types were missing from the parser catalog, browser hunt-tab mapping, and parser docs. Review 4b fixed that in `41d9d5cb`.
- `utils/pattern_event_mappings.py` remains Windows Event ID centric for the deterministic engine. No new 4b browser/log/vendor event-ID coverage gap was found at the parser boundary; these families are primarily hunt/chat/correlation inputs rather than current direct deterministic anchors.
- The memory family remains a real boundary exception: `parsers/memory_parser.py` does not use `BaseParser` / `ParsedEvent` and does not emit parser provenance metadata. Memory provenance is applied later by runtime presentation code rather than at ingest time.

## Verified Behavior
- Browser SQLite, Firefox JSON(LZ4), log, and vendor parsers in this scope still populate `source_host` through path- or payload-derived host extraction, and still thread parser-emitted provenance through `extra_fields` when they use `ParsedEvent`.
- Browser timestamps remain consistently UTC at ingest (`browser_*`, `firefox_*`, and Firefox storage SQLite subtypes derive UTC timestamps from WebKit/Mozilla storage or explicit UTC epoch values).
- Ambiguous log/vendor families (`iis`, `firewall`, `csv_log`, `palo_alto`, `fortigate`, `pfsense`, `cisco_asa`, `sonicwall_syslog`) still use case timezone semantics via `get_source_tz()`, while UTC-native families (`huntress`, `mde_xdr`, `suricata`, cloud-export JSON families) still stay on the UTC path.
- Review 3's load-bearing parser outputs still hold for the 4b event families that feed hunt/correlation surfaces: `timestamp_utc`, `source_host`, and where present `src_ip` / `dst_ip` remain available after row materialization.
- The memory parser writes into dedicated `memory_*` tables and updates `MemoryJob.memory_timestamp` from Volatility `windows.info` output, but it remains outside the standard event-parser contract and outside parser-emitted provenance.

## Findings
### 1. `CORRECTNESS` / `HIGH`
- Location: `parsers/log_parsers.py:154`, `parsers/log_parsers.py:303`, `parsers/log_parsers.py:651`, `parsers/log_parsers.py:1240`, `parsers/log_parsers.py:1409`, `parsers/vendor_parsers.py:176`, `parsers/vendor_parsers.py:270`, `parsers/vendor_parsers.py:397`, `parsers/vendor_parsers.py:501`
- Summary: multiple 4b log and vendor parsers still wrote generic `validate_ip()` output into the IPv4-only `src_ip` / `dst_ip` event columns, so valid IPv6 telemetry could violate the established parser/storage contract and disappear from typed correlation surfaces.
- Proposed fix: landed in this Review by adding a shared IPv4-safe normalization helper in `BaseParser`, switching the affected parsers to preserve non-IPv4 values in searchable `extra_fields`, and adding focused regression coverage. Rough effort: S/M. Commit: `41d9d5cb`

### 2. `DRIFT` / `MEDIUM`
- Location: `parsers/browser_parsers.py:1059`, `parsers/catalog.py:81`, `parsers/catalog.py:299`, `docs/PARSERS.md:407`
- Summary: the browser SQLite parser already emitted `sqlite_firefox_origin_storage`, `sqlite_firefox_cache_storage`, and `sqlite_firefox_indexeddb`, but those artifact types were missing from the declared catalog/browser-tab/docs surface, leaving real parsed rows outside the product's advertised browser family.
- Proposed fix: landed in this Review by adding the emitted Firefox storage SQLite subtypes to the browser capability, the browsers hunting-tab mapping, and the parser docs. Rough effort: S. Commit: `41d9d5cb`

### 3. `DRIFT` / `MEDIUM`
- Location: `parsers/memory_parser.py:45`, `models/memory_data.py`, `utils/forensic_chat_sources.py:339`
- Summary: the memory parser family bypasses `BaseParser` / `ParsedEvent` entirely, writes directly into `memory_*` tables, and does not emit parser provenance metadata; runtime/chat surfaces annotate memory records later instead. That leaves Review 4's parser provenance contract only partially true for the memory family.
- Proposed fix: either explicitly narrow the parser-provenance contract so memory ingest is documented as a separate pipeline, or move memory ingest onto an explicit provenance-bearing storage contract before claiming Refactor Phase 6.5 closure for that family. Rough effort: M/L.

## Code Changes Landed During Review 4b
- `parsers/base.py`
  - added `normalize_ip_for_storage()` so event parsers can preserve valid IPv6/raw IP values without writing them into IPv4-only columns (`41d9d5cb`)
- `parsers/log_parsers.py`
  - hardened IIS, firewall, Huntress, generic JSON, and generic CSV parsing to preserve non-IPv4 network values in `extra_fields` while keeping typed IP columns IPv4-safe (`41d9d5cb`)
- `parsers/vendor_parsers.py`
  - hardened MDE XDR, Palo Alto, pfSense, and Suricata parsing to preserve non-IPv4 network values without breaking the typed event schema (`41d9d5cb`)
- `parsers/catalog.py`
  - added the emitted Firefox storage SQLite artifact types to the browser catalog and browsers hunting-tab mapping (`41d9d5cb`)
- `docs/PARSERS.md`
  - documented the memory-parser exception to the standard `ParsedEvent` contract and added the Firefox storage SQLite browser subtypes (`41d9d5cb`)
- `tests/test_parser_hardening.py`
  - added focused regressions covering IPv6 preservation across 4b parser families and browser catalog coverage for Firefox storage SQLite subtypes (`41d9d5cb`)

## Verification Run
- `python3 -m unittest tests.test_parser_hardening tests.test_phase65_parser_provenance_contract`
- Result: `OK` (51 tests, 2 skipped)

## Review 5 Hand-off
- Review 5 can treat the 4b event parser families as still emitting `timestamp_utc`, `source_host`, and parser-emitted provenance at the event boundary after the IPv4-column hardening landed in `41d9d5cb`.
- The remaining open parser-boundary issue from Review 4 is now the memory family exception: provenance and contract reasoning for memory artifacts still lives partly in downstream runtime/model code, not in parser-emitted metadata.
- Review 10 should continue to own the downstream UTC query-column drift and the still-open EVTX fallback parser contract gap from Review 4a.
