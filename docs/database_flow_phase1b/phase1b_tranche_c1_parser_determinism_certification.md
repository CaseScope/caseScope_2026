# Phase 1B Tranche C1 Parser Determinism Certification

Date: 2026-08-15
Version: 4.19.0
Checkpoint baseline: Phase 1B Tranche B managed initial ingest protocol

## Scope

Tranche C1 certifies the first low-risk production parser cohort only:
IISLogParser, FirewallLogParser, HuntressParser, GenericJSONParser,
CSVLogParser, and SonicWallCSVParser.

No EVTX, structured/database/library, memory, PCAP, graph, derivation, reader,
replacement-generation, or events_current behavior is activated by this record.

## Adoption Safety

CaseFile first managed adoption is guarded by `case_files.ingest_protocol_origin`.
Existing rows are migrated to `legacy_or_unknown`. Future rows default to
`not_started`. A source can newly enter `BUILDING_INITIAL` only from
`not_started`; legacy/unknown sources stay legacy until replacement/migration
semantics are implemented later.

Existing `BUILDING_INITIAL` generations are pinned to managed recovery before
the global feature flag is considered. Parser capability removal, parser version
mismatch, or ordering-contract mismatch fails closed and cannot fall through to
legacy CaseFile-wide cleanup.

## Certification Harness

Each certified parser was tested with stable fixture paths, `case_id=77`,
`case_file_id=901`, `source_host=C1HOST`, `case_tz=America/New_York`, and
batch size 3. The harness ran independent Python processes with
`PYTHONHASHSEED=1`, `PYTHONHASHSEED=7`, and `PYTHONHASHSEED=random`.

For each parser the harness compared event count, normalized ClickHouse row
values, event sequence, batch IDs, row ordinals, row hashes, batch content
hashes, and source locator sequence. Retry tests used different
`ingest_attempt_id` values and verified that attempt identity did not alter
generation, batch, row, locator, or hash identity.

## Certified Parsers

| Parser | Version | Artifact type | Ordering contract | Locator basis | Fixtures | Independent runs | Retry | Multi-batch | Legacy/managed parity | Real PG | Real CH | Performance sample | Status |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| IISLogParser | IISLogParser-1.0.0 | iis | `iis:w3c-data-line-order:v1` | deterministic ordinal fallback over W3C data line order | W3C directives, `#Fields`, blank/comment lines, query strings, 11 data rows | 3 / seeds 1, 7, random | PASS | 4 batches at size 3 | PASS | PASS | PASS | 11-row certification fixture | CERTIFIED |
| FirewallLogParser | FirewallLogParser-1.0.0 | firewall | `firewall:physical-log-line-order:v1` | deterministic ordinal fallback over physical log line order | syslog/key=value lines, repeated timestamps, missing optional fields, duplicate source lines, 11 rows | 3 / seeds 1, 7, random | PASS | 4 batches at size 3 | PASS | PASS | PASS | 11-row certification fixture | CERTIFIED |
| HuntressParser | HuntressParser-2.2.0 | huntress | `huntress:physical-ndjson-line-order:v1` | deterministic ordinal fallback over physical NDJSON line order | realistic ECS process/parent/user/host/org NDJSON, nested structures, 11 rows | 3 / seeds 1, 7, random | PASS | 4 batches at size 3 | PASS | PASS | PASS | 11-row certification fixture | CERTIFIED |
| GenericJSONParser | GenericJSONParser-1.1.0 | json_log | `json-log:document-order:v1` | deterministic ordinal fallback over NDJSON line order or JSON array element order | JSON array document with nested process/network fields, 11 objects | 3 / seeds 1, 7, random | PASS | 4 batches at size 3 | PASS | PASS | PASS | 11-row certification fixture | CERTIFIED |
| CSVLogParser | CSVLogParser-1.0.0 | csv_log | `csv-log:csv-row-order:v1` | deterministic ordinal fallback over CSV row order | CRLF CSV, quoted commas, blank fields, escaped command text, 11 rows | 3 / seeds 1, 7, random | PASS | 4 batches at size 3 | PASS | PASS | PASS | 11-row certification fixture | CERTIFIED |
| SonicWallCSVParser | SonicWallCSVParser-1.1.0 | sonicwall | `sonicwall:csv-row-order:v1` | deterministic ordinal fallback over SonicWall CSV row order | SonicWall firewall CSV header and 11 event rows | 3 / seeds 1, 7, random | PASS | 4 batches at size 3 | PASS | PASS | PASS | 11-row certification fixture | CERTIFIED |

## Real Database Certification

The real integration test used disposable PostgreSQL and ClickHouse databases.
For each certified parser:

- Created one `CaseFile` with `ingest_protocol_origin='not_started'`.
- Parsed with the actual production parser class.
- Allocated `CASE_FILE` generation 1 as `BUILDING_INITIAL`.
- Reserved PostgreSQL STAGED manifests before ClickHouse insertion.
- Inserted managed ClickHouse rows with source generation, batch, row ordinal,
  row hash, and attempt metadata.
- Verified exact ClickHouse persisted rows.
- Marked PostgreSQL batches DURABLE only after verifier success.
- Replayed with a new ingest attempt and verified same generation, batch IDs,
  row hashes, and batch content hashes.
- Verified physical retry duplicates remain accepted only as retry-equivalent
  duplicate-identical proof.
- Verified generation remains `BUILDING_INITIAL`.

No production evidence databases or production events tables were used for
destructive certification tests.

## Parser Inventory Summary

All registered parsers started C1 with manifest support disabled. After C1,
only the six certified parsers above are enabled. Every non-C1 parser remains
disabled for manifest use and is deferred to later cohorts.

High-risk deferred groups include EVTX/external-tool parsers, structured
database/ESE/SQLite/OLE parsers, file-system traversal/library parsers, memory,
and PCAP. These require separate deterministic walk audits.
