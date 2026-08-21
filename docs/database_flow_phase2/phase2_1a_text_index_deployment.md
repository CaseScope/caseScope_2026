# Phase 2.1A Text Index Deployment

Production ADD of locked `idx_search_blob_text` metadata, a partition-scoped
materialization operator, and two retained-production pilots. Hunt readers
remain `search_blob ILIKE`. Bloom indexes remain. No later Phase 2.x/3+ work.

Measurement artifact: `docs/database_flow_phase2/phase2_1a_text_index_deployment.json`.

## Starting state

- origin/main and HEAD at start: `5150420c61f8c8e04c3164b6c426b74d4cebd3b9`
- Commit: Close Phase 2 entry-gate deployed schema so Gate B is actually enabled on production events
- Baseline version: 4.23.2
- This tranche version: 4.24.0
- Python: `/opt/casescope/venv/bin/python`
- Deployed ClickHouse: `26.7.3.19`

## Locked scope

Done:

- production ADD INDEX `idx_search_blob_text` (metadata only)
- `exclude_materialize_skip_indexes_on_merge = 'idx_search_blob_text'`
- reusable coverage detector (MATERIALIZED / PARTIAL / UNMATERIALIZED / UNKNOWN)
- operator `scripts/phase2_1_materialize_search_index.py` (one `--case-id` per invocation)
- disposable tool proof
- production pilots case_id 33 (A) and 10 (B)
- semantic/EXPLAIN/performance and mixed-state proof

Not done: Hunt `hasAllTokens`/`hasAnyTokens` cutover, bloom drop, full-table
MATERIALIZE, automatic remaining-partition rollout, production `command_line`
index, Phase 2.2–2.4, Phase 3+.

## Production schema preconditions

PASS. Before ADD INDEX:

- protocol columns present as Nullable with DEFAULT NULL
- `enable_block_number_column = 1`, `enable_block_offset_column = 1`
- `visible_evidence_generations` and `durable_ingest_batches` present

## Production inventory (pre-ADD)

- active parts 135 / 25 partitions / 745,463,991 rows
- compressed `bytes_on_disk` 108,493,801,090 (~101.1 GiB)
- no `idx_search_blob_text`
- blooms `idx_search_ngram` and `idx_search_token` present
- no in-progress mutations; recent MITRE UPDATEs on case 3 were already `is_done=1`

## Coverage detector

ClickHouse 26.7.3.19 does not expose a per-partition text-index byte column.
`system.data_skipping_indices.data_compressed_bytes` is table-wide.
`EXPLAIN indexes = 1` shows a `hasAllTokens(lower(search_blob), …)` scan only
while *every* queried part is unmaterialized. After any partition is
materialized, EXPLAIN can emit `__text_index_idx_search_blob_text_*` even for
still-unmaterialized partitions.

Authoritative coverage is per-part files under `system.parts.path`:

- sentinel: `skp_idx_idx_search_blob_text.idx`
- companion: `skp_idx_idx_search_blob_text.{cmrk2|cmrk4,dct.*,pst.*}`

Proven on a disposable mixed table: materialized partition A gained those
files; unmaterialized partition B did not; `hash_of_all_files` of B was
unchanged. UNKNOWN (cannot list part files) fails closed for automatic
rollout.

## Production ADD INDEX

```
/opt/casescope/venv/bin/python migrations/add_events_search_blob_text_index.py --apply-production
```

- SQL: `ALTER TABLE events ADD INDEX IF NOT EXISTS idx_search_blob_text search_blob TYPE text(tokenizer = 'splitByNonAlpha', preprocessor = lower(search_blob)) GRANULARITY 1`
- server stores GRANULARITY `100000000`
- expr `search_blob`, type matches locked tokenizer/preprocessor
- `exclude_materialize_skip_indexes_on_merge = 'idx_search_blob_text'`
- `materialize_sql` was None
- parts/rows/bytes delta 0
- fingerprints for cases 33/10/14 unchanged
- coverage remained UNMATERIALIZED (metadata only)
- blooms retained

## Operator

`scripts/phase2_1_materialize_search_index.py`

- `--status` inspects without DDL
- `--dry-run --case-id N --apply-production`
- `--case-id N --apply-production` materializes exactly that partition
- no all-partitions default
- refuses production without `--apply-production`
- refuses incompatible type/expression, missing blooms, schema drift,
  in-progress mutations, and UNKNOWN coverage
- never issues OPTIMIZE FINAL, DROP INDEX, or UPDATE

Proven ClickHouse 26.7 syntax:

```
ALTER TABLE events MATERIALIZE INDEX idx_search_blob_text IN PARTITION <case_id>
SETTINGS mutations_sync = 1
```

Unaffected parts may be renamed with a mutation suffix; their
`hash_of_all_files` / rows / file counts stay identical.

## Disposable tool proof

Live `tests/test_phase2_1a_text_index_materialization.py`: 16 passed.
Three partitions; dry-run adds no mutations; one partition materializes;
others keep file hashes; rerun is idempotent; wrong/missing index fails
closed; row counts and `hasAllTokens` result sets remain identical.

## Pilots

| Pilot | case_id | rows | parts | compressed before | why |
|---|---:|---:|---:|---:|---|
| A | 33 | 131,512 | 4 | 24,213,803 | Small but non-trivial; not 1k; not largest |
| B | 10 | 2,447,494 | 3 | 396,919,390 | Medium Windows-rich corpus; not largest (32) |

Avoided case 14 (1,341 rows) as the only proof. Avoided case 32 (174,899,397).

### Pilot A

- mutation `mutation_34667.txt` `(MATERIALIZE INDEX idx_search_blob_text IN PARTITION 33)` `is_done=1`
- elapsed 7.16s (~18.4k rows/s)
- rows/values/protocol identity unchanged; other partitions unchanged
- coverage MATERIALIZED; part bytes 24,213,803 → 28,604,100
- text-index compressed bytes after A only: 4,378,028
- rerun skipped as already materialized
- whole-token equal: Administrator, PCLAPPVM, PCL, local, VeeamVssSupport, gupdate, WinHTTP
- A-only vs ILIKE for svchost/Invoke/4688/7036/Hyper explained as true substrings (`SMSvcHost`, `invoked`, `14688`, volume GUIDs, `Hypervisor`)
- B-only empty (no token false negative)
- `EXPLAIN` uses Skip `idx_search_blob_text` and `__text_index_idx_search_blob_text_hasAllTokens_*`
- substring `vchos` / `dminis`: ILIKE hits, hasAllTokens 0 (LIKE retained)

### Pilot B

- mutation `mutation_34668.txt` IN PARTITION 10 `is_done=1`
- elapsed 8.98s (~272.5k rows/s); loadavg 0.22 → 0.70
- rows/values/protocol unchanged; other partitions unchanged
- coverage MATERIALIZED; part bytes 396,919,390 → 461,845,421
- table text-index bytes after A+B: 69,117,249
- hash SHA-256 fixture equal 1/1
- ILIKE vs hasAllTokens differences are substring or multi-separator token semantics (`WindowsPowerShell`, `administrators`, `cmd`+`exe` without `cmd.exe`, IP octets without a contiguous IP). No unexplained whole-token miss
- token `powershell` p50 9.9 ms vs ILIKE 102 ms; rare `4688` token p50 10.2 ms / 180k rows read vs ILIKE 117 ms / 1.35M rows read
- `EXPLAIN` shows Skip `idx_search_blob_text` + direct-read filter on the materialized case

## Mixed materialization

Intentional: 2 of 25 partitions materialized.

- case 33 MATERIALIZED, case 10 MATERIALIZED
- cases 16/14/32 UNMATERIALIZED (and the rest)
- unmaterialized case 16: `hasAllTokens(search_blob, 'powershell')` equals
  `hasAllTokens(lower(search_blob), 'powershell')` (19,644 ERKs) — no
  false-negative index pruning
- unmaterialized token query read ~768 MB (full partition scan); materialized
  case 10 token query read ~7 MB

## command_line

DEFER. Case 10 nonempty `command_line` 5,799 / 2,447,494 (0.24%). No production
`command_line` index created.

## Blooms / readers

- `idx_search_ngram` PRESENT
- `idx_search_token` PRESENT
- Hunt still emits `search_blob ilike`; no `hasAllTokens`/`hasAnyTokens` cutover

## Remaining rollout (not executed)

Estimate from Pilot B: ~272.5k rows/s, ~26.8 compressed index bytes/row,
~16% part-byte growth. Remaining ~742.9M rows ⇒ roughly 20 GB index and
~40–50 minutes sequential wall-clock (large partitions may be slower).

Recommended order: remaining small partitions (13, 15), then the 3–6M row
band, then 10M+, with case 32 last. One `--case-id` per invocation. UNKNOWN
or PARTIAL must not be auto-skipped as done.

## Services

Stopped before ADD INDEX: web, workers, beat. ClickHouse/PostgreSQL/Redis
left running. Restarted in order web → workers → beat after validation.

Smoke: `GET /login` HTTP 200; `/case/files`, `/case/hunting`,
`/api/hunting/events/14` redirect to login (auth wall intact). Case 14
ClickHouse hunt-equivalent: 1,341 events, `search_blob ILIKE '%sonicwall%'` = 13.
## Tests

`133 passed, 7 skipped`. F2 live publication-gate cases still require
`PHASE1B_PG_TEST_DATABASE_URL` and `PHASE1B_CH_TEST_DATABASE`. Operator live
ClickHouse tests passed. `py_compile`, `pyflakes`, and `git diff --check` passed.
