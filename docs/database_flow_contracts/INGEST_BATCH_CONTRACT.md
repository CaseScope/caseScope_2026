# Ingest Batch Contract

Status: LOCKED for Phase 0B. No manifest tables or ingest behavior are implemented here.

## Identities

- `ingest_attempt_id`: UUID or equivalent unique execution attempt ID.
- `ingest_batch_id`: deterministic ID stable over:
  - `case_id`
  - `source_ref_type`
  - `source_ref_id`
  - `source_generation`
  - `batch_ordinal`

Canonical batch ID input:

```text
{"batching_contract_version":"ingest-batch:v1","case_id":<int>,"source_ref_type":<string>,"source_ref_id":<string>,"source_generation":<int>,"batch_ordinal":<int>}
```

`ingest_attempt_id` is never part of `ingest_batch_id`.

## Frozen Generation Batching Contract

The generation manifest freezes:

- `parser_version`
- `normalization_version`
- `batching_contract_version`
- `configured_batch_size`
- `ordering_contract`

Changing any frozen value for an already allocated generation is prohibited. If the change alters batch content or ordering, allocate a new source generation.

`ordering_contract` must name the frozen parser/source walk that assigns `ingest_row_ordinal` (for example EVTX EvtxECmd record order, IIS log line order after skipping directives, Huntress NDJSON physical line order). Retries of the same generation must reproduce the same ordinals for the same source bytes.

## Required Batch Fields

Every PostgreSQL batch records:

- `ingest_batch_id`
- `batch_ordinal`
- expected `row_count`
- `batch_content_hash`
- ordered expected `ingest_row_hash[]` or an equivalent reconstructible row-hash manifest
- `first_source_locator`
- `last_source_locator`
- `ingest_attempt_id`
- state: `STAGED` or `DURABLE`

## ClickHouse Row Verification Columns

Every future ClickHouse event row belonging to a manifest batch MUST persist:

| Column | Type / rule |
|---|---|
| `ingest_batch_id` | deterministic batch ID |
| `ingest_row_ordinal` | UInt32, **zero-based**, unique within `ingest_batch_id` |
| `ingest_row_hash` | 64-char lowercase hex SHA-256 of the canonical row payload |

These three columns are the reconstructible verification state. Parser provenance inside `extra_fields` is not sufficient.

`ingest_attempt_id` may be stored for audit. It is excluded from `ingest_row_hash`.

## ingest_row_ordinal

Locked choice: **zero-based**.

Rules:

- Unique within `ingest_batch_id`.
- Assigned by the frozen `ordering_contract` over the source walk, then sliced by frozen `configured_batch_size`.
- Ordinal 0 is the first row of that batch under the frozen order.
- Stable across retries of the same generation and batch ID.
- Not a ClickHouse insertion index, not a task attempt counter, and not a timestamp rank.

## ingest_row_hash

`ingest_row_hash = SHA-256(UTF-8 canonical JSON of the canonical row payload)`.

### Canonical row payload field allowlist

The payload is a JSON object containing **only** these keys. Keys not listed are excluded.

Identity and batch membership:

- `case_id` (integer)
- `artifact_type` (string)
- `source_ref_type` (string)
- `source_ref_id` (string)
- `source_generation` (integer)
- `ingest_batch_id` (string)
- `ingest_row_ordinal` (integer, zero-based)
- `source_file` (string)
- `source_path` (string)
- `source_host` (string)
- `case_file_id` (integer or null)

Timestamps:

- `timestamp`
- `timestamp_utc`
- `timestamp_source_tz`

Normalized event fields from `ParsedEvent.clickhouse_columns()` that are deterministic source/parser output:

- `event_id`, `channel`, `provider`, `record_id`, `level`
- `username`, `domain`, `sid`, `logon_type`, `logon_id`
- `remote_host`, `workstation_name`, `auth_package`, `logon_process`, `elevated_token`
- `process_name`, `process_path`, `process_id`, `parent_process`, `parent_pid`, `command_line`, `thread_id`, `executable_info`
- `payload_data1` through `payload_data6`
- `target_path`, `file_hash_md5`, `file_hash_sha1`, `file_hash_sha256`, `file_size`
- `src_ip`, `dst_ip`, `src_port`, `dst_port`
- `reg_key`, `reg_value`, `reg_data`
- `rule_title`, `rule_level`, `rule_file`
- `mitre_tactics`, `mitre_tags`, `mitre_attack_ids`, `mitre_attack_tactics`, `mitre_attack_sources`, `mitre_mapping_max_confidence`
- `raw_json` (canonicalized; see encoding)
- `search_blob`
- `evidence_record_key`, `evidence_identity_version`, `evidence_identity_quality`

Deterministic parser-provenance object, **not** `extra_fields` wholesale:

```json
"parser_provenance": {
  "parser_version": "<string>",
  "native_record_id_authoritative": <bool>,
  "source_record_identifier_authoritative": <bool>,
  "source_record_identifier_type": <string or null>,
  "source_record_identifier_value": <string or null>
}
```

Only those five provenance fields are permitted in identity. `field_provenance`, `emitted_provenance`, `provenance_source`, and any other `extra_fields` keys are excluded.

### Explicit exclusions

Never present in the canonical row payload:

- `indexed_at`
- `selector_key`
- `ingest_attempt_id`
- `ingest_row_hash` itself
- run IDs, task IDs, Celery IDs, worker hostnames
- mutable overlays: `analyst_*`, `noise_*`, `ioc_types`, and any later-updated overlay column not emitted by the frozen parser
- Python `repr`, `id()`, set iteration order, ClickHouse insertion byte streams
- nondeterministic `extra_fields` serialization

### Canonical encoding

- JSON object, keys sorted lexicographically, compact separators `','` and `':'`, `ensure_ascii=true`, UTF-8.
- Null: JSON `null`. ClickHouse non-nullable strings that store `''` encode as `""`, not null.
- Datetime (`timestamp`, `timestamp_utc`): UTC ISO-8601 with millisecond precision and `Z` suffix, e.g. `2024-01-02T03:04:05.123Z`. Truncate toward zero to milliseconds. No timezone offsets in the encoded value.
- `timestamp_source_tz`: IANA string or `""`.
- Integers: JSON numbers, no leading zeros, no floats.
- Strings: the exact normalized string that will be inserted.
- IP columns: canonical parser/ClickHouse string form, or JSON `null` when absent.
- Arrays: JSON arrays preserving parser order; elements encoded by the rules above.
- `raw_json`: if the value parses as a JSON object or array, re-serialize with sorted keys and the same compact ASCII rules; if it is a JSON primitive, encode that primitive; if it is not valid JSON, encode `{"$raw_text":"<utf-8 string>"}`.
- Booleans: JSON `true` / `false`.

Do not hash Python `dict` repr, unordered sets, row object memory addresses, or ClickHouse insertion byte streams.

## Batch Content Hash

`batch_content_hash` is SHA-256 over a framed concatenation of ordered row hashes. Raw hex concatenation without framing is prohibited.

Framing (binary):

```text
contract_version_bytes = UTF-8("ingest-batch:v1")
framed(row_hash) =
    0x01
    || uint8(32)
    || 32-byte SHA-256 digest of that row
    || uint32_be(ingest_row_ordinal)

batch_content_hash = SHA256(
    uint8(len(contract_version_bytes))
    || contract_version_bytes
    || 0x00
    || framed(row_hash of ordinal 0)
    || framed(row_hash of ordinal 1)
    || ...
    || framed(row_hash of ordinal row_count-1)
)
```

Row hashes appear in ascending `ingest_row_ordinal` order. Missing or out-of-order ordinals cannot produce the expected aggregate hash.

Store `batch_content_hash` as 64-char lowercase hex.

## Source Locator Contract

Locator priority per event:

1. parser-declared authoritative source record identifier;
2. native `record_id` when authoritative for the source;
3. source byte/row/line offset when parser supports it;
4. deterministic ordinal within the frozen source ordering.

`first_source_locator` and `last_source_locator` are canonical JSON objects with `type` and `value` fields. Missing locators are explicit nulls and lower confidence; they do not change batch identity.

## Commit Protocol

```text
PG reserve STAGED (batch_id, expected row_count, expected row hashes, batch_content_hash)
↓
CH insert rows carrying ingest_batch_id, ingest_row_ordinal, ingest_row_hash
↓
verify from CH: presence, ordinal set, row hashes, aggregate hash
↓
PG DURABLE
↓
publish subject to generation state
↓
queue derivations
```

Exactly-once is protocol behavior, not Celery success.

## Reconciler Proof From ClickHouse

The reconciler MUST be able to prove from CH rows for one `ingest_batch_id`:

1. expected row count after retry-equivalent collapse;
2. exact ordinal set `{0, 1, ..., expected_row_count-1}`;
3. no duplicate ordinal remaining after collapse;
4. each ordinal's `ingest_row_hash` equals the frozen expected hash;
5. recomputed `batch_content_hash` equals the frozen aggregate hash.

Query shape (normative semantics):

```sql
SELECT
    ingest_row_ordinal,
    ingest_row_hash,
    count() AS physical_copies,
    uniqExact(ingest_row_hash) AS distinct_hashes
FROM events
WHERE ingest_batch_id = {id:String}
GROUP BY ingest_row_ordinal, ingest_row_hash
```

## Reconciler Outcomes

| Condition | Proof | Outcome |
|---|---|---|
| CH absent | zero rows | Keep/recreate `STAGED`, retry same `ingest_batch_id` under new `ingest_attempt_id`. |
| CH exact | ordinals `{0..n-1}`, one hash per ordinal, hashes match, aggregate matches | Mark PG batch `DURABLE`, queue derivations if not already queued. |
| CH partial / missing ordinal | any ordinal in `{0..n-1}` absent | FAIL CLOSED for publication. Purge rows by `ingest_batch_id`, keep `STAGED`, retry same batch ID and expected hashes. |
| Extra ordinal | ordinal `< 0` or `>= n` or otherwise not in expected set | FAIL CLOSED. Purge. No retry equivalence. Alert/audit. |
| Duplicate ordinal, identical hash | same ordinal, one distinct `ingest_row_hash`, hash matches expected | Retry-equivalent physical copies. Collapse proof required: after grouping by `(ingest_batch_id, ingest_row_ordinal)` the distinct hash count is 1 and matches expected. Purge extra copies or accept collapsed proof, then DURABLE. This is the only duplicate-ordinal success path. |
| Duplicate ordinal, different hash | same ordinal, `uniqExact(ingest_row_hash) > 1` or hash ≠ expected | FAIL CLOSED. No publication. No retry equivalence. Alert/audit. Human decision. |
| Hash mismatch (ordinal present, wrong hash) | expected ordinal's hash ≠ frozen hash | FAIL CLOSED. No retry equivalence. Alert/audit. |
| Aggregate hash mismatch despite per-row match | framing/order/contract_version error | FAIL CLOSED. Treat as contract violation. |
| Crash before CH insert | CH absent | Retry. |
| Crash after CH insert | verify as above | Act per row. |
| Crash after verification before PG DURABLE | repeat verification | Mark durable only if exact or retry-equivalent collapse. |
| Crash after PG DURABLE | batch remains publishable subject to generation state | Derivation queue retried idempotently. |
| Retry under new attempt ID | same generation, batch ID, expected hashes | Must match. |

All outcomes fail closed except CH exact and explicitly proven retry-equivalent duplicate-ordinal-identical-hash state.

## Tests

- Deterministic batch ID ignores attempt ID.
- `ingest_row_ordinal` is zero-based, unique within batch, stable across retry.
- `ingest_row_hash` is stable across process restarts and dict ordering changes.
- Hash changes on row content or ordinal changes.
- `batch_content_hash` changes if framing, contract version, order, or any row hash changes.
- Partial STAGED batch is not published.
- Exact STAGED batch reconciles to DURABLE.
- Duplicate ordinal identical hash is retry-equivalent only after collapse proof (CT-030).
- Duplicate ordinal different hash fails closed (CT-031).
- Missing ordinal fails closed (CT-032).
- Extra ordinal fails closed (CT-033).
- Hash mismatch fails closed (CT-008).
- Reconciler reconstructs aggregate hash from CH `ingest_row_ordinal` + `ingest_row_hash` (CT-029).

## Explicit Open Items

- OPEN — ADDITIONAL MEASUREMENT REQUIRED: later batch-size benchmarking.
- NOT APPLICABLE: Phase 0B does not add manifest tables or ClickHouse columns.

## Implemented Extensions / Phase 2.4

Dated 2026-08-22. This addendum records current Phase 2.4B1 runtime. It does not rewrite the locked identity rules above.

- Phase 2.4 uses deterministic retry preflight against the frozen PostgreSQL manifest before a second physical INSERT.
- An existing STAGED physical batch that verifies `exact` is not reinserted. Lost-acknowledgement recovery marks that batch DURABLE.
- Current Phase 2.4 runtime requires an exact physical manifest before DURABLE. `DURABLE => EXACT PHYSICAL MANIFEST`, not exact-after-collapse.
- `duplicate_identical` remains a recognized retry-equivalence classification from `verify_ingest_batch` / D2 `classify_batch`.
- `duplicate_identical` STAGED rows are normalized/recovered before publication. They must not be marked DURABLE while extra physical copies remain.
- Current implementation uses whole-batch STAGED purge/reinsert through the accepted exclusive-fence purge helper, then one deterministic INSERT, then `exact` verification. Targeted extra-copy deletion is not used.
- Batch identity remains unchanged: deterministic `ingest_batch_id` over frozen generation/batch identity. `ingest_attempt_id` remains execution-only.
- No semantic or logical dedup, no LEK, no ReplacingMergeTree engine change, and no same-ERK / cross-source collapse. Real logical dedup remains Phase 4.
- Historical D2 evidence that accepted collapsed `duplicate_identical` as DURABLE remains historical. Current runtime does not preserve that publication action.
